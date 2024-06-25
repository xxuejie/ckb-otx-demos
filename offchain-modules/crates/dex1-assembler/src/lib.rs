pub mod config;
pub mod schemas;

use crate::{
    config::{Config, PackedFullScript, PackedTradingPair, RunnerConfig},
    schemas::{
        basic, dex1,
        top_level::{WitnessLayout, WitnessLayoutUnion},
    },
};
use anyhow::{anyhow, bail, Result};
use ckb_hash::blake2b_256;
use ckb_sdk::{
    constants::SIGHASH_TYPE_HASH,
    rpc::ckb_indexer::SearchMode,
    traits::{
        CellCollector, CellDepResolver, CellQueryOptions, DefaultCellCollector,
        DefaultCellDepResolver, DefaultTransactionDependencyProvider, LiveCell, MaturityOption,
        SecpCkbRawKeySigner, ValueRangeOption,
    },
    tx_builder::unlock_tx,
    unlock::{ScriptUnlocker, SecpSighashUnlocker},
    CkbRpcClient, ScriptId, SECP256K1,
};
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, FeeRate, ScriptHashType, TransactionView},
    packed::{CellInput, CellOutput, OutPoint, Script, Transaction, WitnessArgs},
    prelude::*,
    H256,
};
use ethnum::U256;
use num_rational::Ratio;
use otx_traits::{Assembler, MapEmitter, ReduceEmitter, ReduceSource, Value};
use std::collections::{HashMap, HashSet};

const LIMIT_BUY: u8 = 'B' as u8;
const LIMIT_SELL: u8 = 'S' as u8;
// const MARKET_BUY: u8 = 'b' as u8;
// const MARKET_SELL: u8 = 's' as u8;

/// This is similar to ResolvedTransaction, but contains just the bit of
/// information required by Dex1. For a different OTX processor, one can
/// alter this data structure with other required values.
#[derive(Debug, Clone)]
pub struct RichOtx {
    pub tx: Transaction,
    pub inputs: Vec<(CellOutput, Bytes)>,
}

// The environment struct handles impure logic that is pending on
// actual state of the chain.
pub struct Dex1Env {
    client: CkbRpcClient,
    config: RunnerConfig,

    cell_collector: DefaultCellCollector,
    dep_resolver: DefaultCellDepResolver,
    tx_dep_provider: DefaultTransactionDependencyProvider,

    sender_script: Script,
    unlockers: HashMap<ScriptId, Box<dyn ScriptUnlocker>>,
}

pub fn build_genesis_sighash_lock(private_key: &H256) -> (secp256k1::SecretKey, Script) {
    let secret_key = secp256k1::SecretKey::from_slice(private_key.as_bytes())
        .expect("create secp256k1 secret key structure");
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &secret_key);
    let hash160 = blake2b_256(&pubkey.serialize()[..])[0..20].to_vec();
    let script = Script::new_builder()
        .code_hash(SIGHASH_TYPE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(Bytes::from(hash160).pack())
        .build();
    (secret_key, script)
}

impl Dex1Env {
    pub fn new(config: &RunnerConfig, private_key: H256) -> Self {
        let client = CkbRpcClient::new(&config.ckb_rpc);
        let dep_resolver = config.build_dep_resolver();

        let (sender_key, sender_script) = build_genesis_sighash_lock(&private_key);
        let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![sender_key]);
        let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
        let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
        let mut unlockers = HashMap::default();
        unlockers.insert(
            sighash_script_id,
            Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
        );

        Self {
            client,
            config: config.clone(),
            cell_collector: DefaultCellCollector::new(&config.ckb_rpc),
            dep_resolver,
            tx_dep_provider: DefaultTransactionDependencyProvider::new(&config.ckb_rpc, 10),
            sender_script,
            unlockers,
        }
    }

    pub fn refresh_deps(&mut self) {
        self.cell_collector = DefaultCellCollector::new(&self.config.ckb_rpc);
        self.dep_resolver = self.config.build_dep_resolver();
        self.tx_dep_provider = DefaultTransactionDependencyProvider::new(&self.config.ckb_rpc, 10);
    }

    pub fn dex1_script(&self) -> Script {
        self.config.config().dex1_deployment.script.into()
    }

    pub fn fulfill_otx(&mut self, otx: Transaction) -> Result<RichOtx> {
        let raw = otx.raw();
        let mut inputs = Vec::with_capacity(raw.inputs().len());
        for cell_input in raw.inputs().into_iter() {
            let (output, data) = if cell_input == placeholder_dex1_cell_input() {
                let cell = self.latest_dex1_cell(false)?;
                (cell.output, cell.output_data)
            } else {
                match self
                    .tx_dep_provider
                    .get_cell_with_data(&cell_input.previous_output())
                {
                    Ok((output, data)) => (output, data),
                    Err(e) => bail!("Dep provider error: {:?}", e),
                }
            };
            inputs.push((output, data));
        }
        let otx_view = otx.into_view();
        Ok(RichOtx {
            tx: otx_view.data(),
            inputs,
        })
    }

    fn latest_dex1_cell(&mut self, force_chain: bool) -> Result<LiveCell> {
        let mut query = CellQueryOptions::new_type(self.dex1_script());
        query.with_data = Some(true);
        query.script_search_mode = Some(SearchMode::Exact);

        let (mut cells, _) = match self.cell_collector.collect_live_cells(&query, false) {
            Ok(data) => data,
            Err(e) => bail!("Cell collector error: {:?}", e),
        };
        assert_eq!(cells.len(), 1, "Dex1 cell is not yet deployed!");
        let mut cell = cells.pop().unwrap();

        if force_chain {
            let tx_status = match self
                .client
                .get_transaction_status(cell.out_point.tx_hash().unpack())
            {
                Ok(status) => status.tx_status,
                Err(e) => bail!("CKB RPC error: {:?}", e),
            };
            assert_eq!(tx_status.status, ckb_jsonrpc_types::Status::Committed);
            cell.block_number = tx_status.block_number.unwrap().value();
        }

        Ok(cell)
    }

    pub fn base_tx(&mut self) -> Result<(RichOtx, u64)> {
        let cell = self.latest_dex1_cell(false)?;
        let tx = TransactionView::new_advanced_builder()
            // We will find the right input cell to use at sealing time.
            .input(placeholder_dex1_cell_input())
            .output(cell.output.into())
            .output_data(cell.output_data.pack())
            .build();

        // Leave 100 blocks as a buffer space in case the assembled tx is not submitted to
        // chain as scheduled. Though this is really a hacky solution, a proper one should be
        // to detect against expired otxs at sealing time.
        let expired_block = cell.block_number + 100;

        Ok((self.fulfill_otx(tx.data())?, expired_block))
    }

    pub fn seal_tx(&mut self, tx: &Transaction) -> Result<Transaction> {
        // For each pending tx:
        let tx = tx.clone().into_view();
        // * Find the latest dex1 cell input with its header, then update
        // current tx with latest values.
        let tx = {
            let input_position = tx
                .inputs()
                .into_iter()
                .position(|cell_input| cell_input == placeholder_dex1_cell_input())
                .expect("dex1 cell is missing!");
            let dex1_cell = self.latest_dex1_cell(true)?;

            assert!(dex1_cell.block_number > 0);
            let header = self
                .client
                .get_header_by_number(dex1_cell.block_number.into())
                .expect("rpc")
                .unwrap();

            let mut inputs: Vec<_> = tx.inputs().into_iter().collect();
            inputs[input_position] = CellInput::new_builder()
                .previous_output(dex1_cell.out_point)
                .build();

            tx.as_advanced_builder()
                .set_inputs(inputs)
                .header_dep(header.hash.pack())
                .build()
        };
        // * Add sighash cell for both providing tx fees, and sealing the whole tx
        let mut witnesses: Vec<_> = tx.witnesses().into_iter().collect();

        let mut query = CellQueryOptions::new_lock(self.sender_script.clone());
        query.secondary_script_len_range = Some(ValueRangeOption::new_exact(0));
        query.data_len_range = Some(ValueRangeOption::new_exact(0));
        query.maturity = MaturityOption::Both;
        query.min_total_capacity = Capacity::bytes(71).expect("overflow").as_u64();

        let first_input_cell_index = tx.inputs().len();
        let fee_change_output_cell_index = tx.outputs().len();
        let (live_cells, total_capacity) = self
            .cell_collector
            .collect_live_cells(&query, false)
            .expect("collect cells");
        assert!(total_capacity >= query.min_total_capacity);
        let placeholder_witness = WitnessArgs::new_builder()
            .lock(Some(Bytes::from(vec![0u8; 65])).pack())
            .build()
            .as_bytes()
            .pack();
        if witnesses[first_input_cell_index].len() > 0 {
            witnesses.insert(first_input_cell_index, placeholder_witness);
        } else {
            witnesses[first_input_cell_index] = placeholder_witness;
        }
        for i in 1..live_cells.len() {
            if witnesses[first_input_cell_index + i].len() > 0 {
                witnesses.insert(first_input_cell_index + i, Bytes::default().pack());
            }
        }

        let tx_without_deps = tx
            .as_advanced_builder()
            .set_witnesses(witnesses)
            .inputs(live_cells.iter().map(|live_cell| {
                CellInput::new_builder()
                    .previous_output(live_cell.out_point.clone())
                    .build()
            }))
            .output(
                CellOutput::new_builder()
                    .capacity(total_capacity.pack())
                    .lock(self.sender_script.clone())
                    .build(),
            )
            .output_data(Bytes::default().pack())
            .build();

        // * Fill in missing cell deps
        let mut cell_deps = HashSet::new();
        for input in tx_without_deps.inputs() {
            let (output, _) = self
                .tx_dep_provider
                .get_cell_with_data(&input.previous_output())
                .expect("fetching tx dependency");
            let cell_dep = self
                .dep_resolver
                .resolve(&output.lock())
                .expect("resolving cell dep");
            cell_deps.insert(cell_dep);

            if let Some(t) = output.type_().to_opt() {
                let cell_dep = self.dep_resolver.resolve(&t).expect("resolving cell dep");
                cell_deps.insert(cell_dep);
            }
        }
        for output in tx_without_deps.outputs() {
            if let Some(t) = output.type_().to_opt() {
                let cell_dep = self.dep_resolver.resolve(&t).expect("resolving cell dep");
                cell_deps.insert(cell_dep);
            }
        }

        let tx_before_fee = tx_without_deps
            .as_advanced_builder()
            .set_cell_deps(cell_deps.into_iter().collect())
            .build();

        let fee_rate = FeeRate::from_u64(1000);
        let fee = fee_rate
            .fee(tx_before_fee.data().as_reader().serialized_size_in_block() as u64)
            .as_u64();
        let updated_capacity = total_capacity.checked_sub(fee).expect("fee overflow");

        let mut outputs: Vec<_> = tx_before_fee.outputs().into_iter().collect();
        let updated_change_output = outputs[fee_change_output_cell_index]
            .clone()
            .as_builder()
            .capacity(updated_capacity.pack())
            .build();
        outputs[fee_change_output_cell_index] = updated_change_output;

        let locked_tx = tx_before_fee
            .as_advanced_builder()
            .set_outputs(outputs)
            .build();
        // * Sign an input cell using sighash to seal it
        let (new_tx, _) =
            unlock_tx(locked_tx, &self.tx_dep_provider, &self.unlockers).expect("unlock tx");

        // Update providers to recognize this new transaction
        let tip_block_number = self.client.get_tip_block_number().expect("rpc").value();
        self.cell_collector
            .apply_tx(new_tx.data(), tip_block_number)
            .expect("apply tx to cell collector");
        self.tx_dep_provider
            .apply_tx(new_tx.data(), tip_block_number)
            .expect("apply tx to tx dep provider");

        Ok(new_tx.data())
    }
}

#[derive(Debug, Clone)]
pub struct ParsedData {
    pub tx: RichOtx,
    pub recipient_script: Script,
    pub ask_token_script: Script,
    pub bid_token_script: Script,
    pub price: Ratio<u128>,
    pub order: dex1::Order,
    pub freestanding_cell: bool,
}

impl ParsedData {
    fn minimal_ckbytes(&self) -> u64 {
        let dummy_freestanding_cell = CellOutput::new_builder()
            .lock(
                Script::new_builder()
                    .args(Bytes::from(vec![0; 96]).pack())
                    .build(),
            )
            .type_(Some(self.bid_token_script.clone()).pack())
            .build();
        let dummy_cell_capacity = dummy_freestanding_cell
            .occupied_capacity(Capacity::bytes(16).expect("overflow"))
            .expect("overflow");
        let return_cell = CellOutput::new_builder()
            .lock(self.recipient_script.clone())
            .type_(Some(self.ask_token_script.clone()).pack())
            .build();
        let return_cell_capacity = return_cell
            .occupied_capacity(Capacity::bytes(16).expect("overflow"))
            .expect("overflow");
        dummy_cell_capacity
            .safe_add(return_cell_capacity)
            .expect("overflow")
            .as_u64()
    }
}

impl Value for ParsedData {
    fn transaction(&self) -> &Transaction {
        &self.tx.tx
    }
}

// An assembler here is pure logic for assembling transactions.
pub struct Dex1 {
    dex1_script: PackedFullScript,
    pairs: HashMap<[u8; 64], PackedTradingPair>,
}

impl Dex1 {
    pub fn new(config: &Config) -> Self {
        Self {
            dex1_script: config.dex1_deployment.clone().into(),
            pairs: config
                .pairs
                .iter()
                .map(|pair| {
                    let packed: PackedTradingPair = pair.clone().into();
                    let mut key = [0u8; 64];
                    key[0..32].copy_from_slice(&packed.first.script.calc_script_hash().raw_data());
                    key[32..64]
                        .copy_from_slice(&packed.second.script.calc_script_hash().raw_data());
                    (key, packed)
                })
                .collect(),
        }
    }

    pub fn keys(&self) -> Vec<[u8; 65]> {
        self.pairs
            .keys()
            .map(|key| {
                let mut data = [0u8; 65];
                data[0..64].copy_from_slice(key);
                data
            })
            .collect()
    }

    pub fn freestanding_lock(&self, recipient_script: &Script, order: &dex1::Order) -> Script {
        let freestanding_args = {
            let mut data = [0u8; 96];
            data[0..32].copy_from_slice(&self.dex1_script.script.args().raw_data().slice(0..32));
            data[32..64].copy_from_slice(&recipient_script.calc_script_hash().raw_data());
            data[64..96].copy_from_slice(&hash_order(order));
            Bytes::from(data.to_vec()).pack()
        };
        self.dex1_script
            .script
            .clone()
            .as_builder()
            .args(freestanding_args)
            .build()
    }
}

impl Assembler for Dex1 {
    type Otx = RichOtx;
    type BaseTx = (RichOtx, u64);
    type Key = [u8; 65];
    type Order = Ratio<u128>;
    type Value = ParsedData;
    type PostValue = Option<([u8; 65], ParsedData)>;

    fn map<E>(&self, tx: RichOtx, emitter: &mut E) -> Result<()>
    where
        E: MapEmitter<Self::Key, Self::Order, Self::Value>,
    {
        let raw = tx.tx.raw();
        if raw.cell_deps().len() > 0 {
            bail!("Invalid number of cell deps!");
        }
        if raw.header_deps().len() > 0 {
            bail!("Invalid number of header deps!");
        }
        if tx.tx.witnesses().len() != 1 {
            bail!("Invalid number of witnesses!");
        }
        let witness = tx.tx.witnesses().get(0).unwrap();
        let witness_layout = WitnessLayout::from_slice(&witness.raw_data())
            .map_err(|e| anyhow!("Error parsing witness: {:?}", e))?;
        let WitnessLayoutUnion::Otx(otx) = witness_layout.to_enum() else {
            bail!("Invalid witness layout type!");
        };
        {
            let input_cells: usize = otx.input_cells().unpack();
            let output_cells: usize = otx.output_cells().unpack();
            let cell_deps: usize = otx.cell_deps().unpack();
            let header_deps: usize = otx.header_deps().unpack();
            if raw.inputs().len() != input_cells
                || raw.outputs().len() != output_cells
                || raw.cell_deps().len() != cell_deps
                || raw.header_deps().len() != header_deps
            {
                bail!("Invalid otx format!");
            }
        }
        let dex1_script_hash = self.dex1_script.script.calc_script_hash();
        let action = otx
            .message()
            .actions()
            .into_iter()
            .find(|action| action.script_hash() == dex1_script_hash)
            .ok_or_else(|| anyhow!("Missing cobuild action for dex1!"))?;
        let dex1_action = dex1::Dex1Action::from_slice(&action.data().raw_data())
            .map_err(|e| anyhow!("Error parsing dex1 action data: {:?}", e))?;
        if dex1_action.orders().len() != 1 {
            bail!("For now, we only process otx with exact one order");
        }
        let order = dex1_action.orders().get(0).unwrap();
        let limit_order = match order.to_enum() {
            dex1::OrderUnion::LimitOrder(limit_order) => limit_order,
            // Deadline will be processed at reduce time
            dex1::OrderUnion::LimitOrderWithDeadline(o) => o.order(),
            _ => bail!("For now, we only support basic limit orders, later we shall add support for market orders"),
        };
        // Check if current trading pair is supported
        let (key, bid_token_script, ask_token_script) = {
            let buy_pair = {
                let mut pair = [0u8; 64];
                pair[0..32].copy_from_slice(&limit_order.ask_token().raw_data());
                pair[32..64].copy_from_slice(&limit_order.bid_token().raw_data());
                pair
            };
            let sell_pair = {
                let mut pair = [0u8; 64];
                pair[0..32].copy_from_slice(&limit_order.bid_token().raw_data());
                pair[32..64].copy_from_slice(&limit_order.ask_token().raw_data());
                pair
            };
            if let Some(pair_data) = self.pairs.get(&buy_pair) {
                let mut key = [LIMIT_BUY; 65];
                key[0..64].copy_from_slice(&buy_pair);
                (key, &pair_data.second, &pair_data.first)
            } else if let Some(pair_data) = self.pairs.get(&sell_pair) {
                let mut key = [LIMIT_SELL; 65];
                key[0..64].copy_from_slice(&sell_pair);
                (key, &pair_data.first, &pair_data.second)
            } else {
                bail!("Trading pair is not supported!");
            }
        };
        // Check if enough tokens are provided by the otx as claimed in bid_amount
        // Check if claimed_ckbytes can be claimed
        let bid_amount: u128 = limit_order.bid_amount().unpack();
        let ask_amount: u128 = limit_order.ask_amount().unpack();
        let claimed_ckbytes: u64 = limit_order.claimed_ckbytes().unpack();
        {
            let mut tokens: u128 = 0;
            let mut ckbytes: u64 = 0;
            for (cell_output, cell_data) in &tx.inputs {
                if cell_output
                    .type_()
                    .to_opt()
                    .map(|s| s == bid_token_script.script)
                    .unwrap_or(false)
                {
                    if cell_data.len() < 16 {
                        bail!("Invalid udt data format!");
                    }
                    let mut data = [0u8; 16];
                    data.copy_from_slice(&cell_data[0..16]);
                    let current_tokens = u128::from_le_bytes(data);
                    tokens = tokens
                        .checked_add(current_tokens)
                        .ok_or_else(|| anyhow!("overflow!"))?;
                }
                ckbytes = ckbytes
                    .checked_add(cell_output.capacity().unpack())
                    .ok_or_else(|| anyhow!("overflow!"))?;
            }
            for (i, cell_output) in raw.outputs().into_iter().enumerate() {
                if cell_output
                    .type_()
                    .to_opt()
                    .map(|s| s == bid_token_script.script)
                    .unwrap_or(false)
                {
                    let cell_data = raw.outputs_data().get(i).unwrap();
                    let mut data = [0u8; 16];
                    data.copy_from_slice(&cell_data.raw_data()[0..16]);
                    let current_tokens = u128::from_le_bytes(data);
                    tokens = tokens
                        .checked_sub(current_tokens)
                        .ok_or_else(|| anyhow!("overflow!"))?;
                }
                ckbytes = ckbytes
                    .checked_sub(cell_output.capacity().unpack())
                    .ok_or_else(|| anyhow!("overflow!"))?;
            }
            if bid_amount == 0 || bid_amount != tokens {
                bail!("Invalid bid amount!");
            }
            if claimed_ckbytes > ckbytes {
                bail!("Not enough ckbytes to claim!");
            }
        }
        // Check if recipient hash is used in current otx. Note this is a shortcut,
        // it's also possible to provide recipient script via OTX RPC.
        let Some(recipient_script) = tx
            .inputs
            .iter()
            .map(|(cell_output, _)| cell_output.lock())
            .chain(
                raw.outputs()
                    .into_iter()
                    .map(|cell_output| cell_output.lock()),
            )
            .find(|s| s.calc_script_hash() == limit_order.recipient())
        else {
            bail!("Recipient script is missing!");
        };
        // Claimed ckbytes must be enough for partial fills
        {
            let dummy_freestanding_cell = CellOutput::new_builder()
                .lock(
                    Script::new_builder()
                        .args(Bytes::from(vec![0; 96]).pack())
                        .build(),
                )
                .type_(Some(bid_token_script.script.clone()).pack())
                .build();
            let dummy_cell_capacity = dummy_freestanding_cell
                .occupied_capacity(Capacity::bytes(16).expect("overflow"))
                .expect("overflow");
            let return_cell = CellOutput::new_builder()
                .lock(recipient_script.clone())
                .type_(Some(ask_token_script.script.clone()).pack())
                .build();
            let return_cell_capacity = return_cell
                .occupied_capacity(Capacity::bytes(16).expect("overflow"))
                .expect("overflow");
            let total_capacity = dummy_cell_capacity
                .safe_add(return_cell_capacity)
                .expect("overflow");
            if total_capacity.as_u64() > claimed_ckbytes {
                bail!("Claimed ckbytes are not enough in the partial fill worse case!");
            }
        }
        // Calculate the price, now we can build parsed data
        let price = Ratio::new_raw(ask_amount, bid_amount);
        let parsed_data = ParsedData {
            tx,
            recipient_script,
            ask_token_script: ask_token_script.script.clone(),
            bid_token_script: bid_token_script.script.clone(),
            price,
            order,
            freestanding_cell: false,
        };
        // Claimed ckbytes must be enough for partial fills
        if parsed_data.minimal_ckbytes() > claimed_ckbytes {
            bail!("Claimed ckbytes are not enough in the partial fill worse case!");
        }

        log::debug!(
            "Emitting {} order of price {}, bid amount: {}, ask amount: {}",
            if key[64] == LIMIT_SELL {
                "limit sell"
            } else {
                "limit buy"
            },
            price,
            bid_amount,
            ask_amount
        );
        emitter.emit(key, price, parsed_data)
    }

    fn reduce<E, S>(
        &self,
        base_tx: (RichOtx, u64),
        key: Self::Key,
        emitter: &mut E,
        source: &S,
    ) -> Result<()>
    where
        E: ReduceEmitter<Self::Key, Self::Order, Self::Value, Self::PostValue>,
        S: ReduceSource<Self::Key, Self::Value>,
    {
        let (base_tx, expired_block_number) = base_tx;

        let dex1_cell_input = base_tx.tx.raw().inputs().get(0).unwrap();
        let dex1_cell_output = base_tx.tx.raw().outputs().get(0).unwrap();
        let dex1_cell_data = base_tx.tx.raw().outputs_data().get(0).unwrap();
        // Create iterators of buy orders & sell orders
        let limit_buy_key = {
            let mut key = key.clone();
            key[64] = LIMIT_BUY;
            key
        };
        let mut limit_buys = source.otxs(limit_buy_key);
        let limit_sell_key = {
            let mut key = key.clone();
            key[64] = LIMIT_SELL;
            key
        };
        let mut limit_sells = source.otxs(limit_sell_key);
        // For each top buy order, look for sell orders it can fulfill
        // For simplicity, we are packing at most 20 limit buy otxs here,
        // but this depends on your strategy, it can and should be altered.
        let mut fulfilled_orders: Vec<(ParsedData, dex1::LimitOrder)> = vec![];
        let mut unfinished_buy_order =
            locate_next_valid_order(&mut limit_buys, emitter, expired_block_number)?;
        let mut pending_ask_amount: u128 = match &unfinished_buy_order {
            Some((_, limit_order)) => limit_order.ask_amount().unpack(),
            // Terminate when we don't have at least one buy order.
            None => return Ok(()),
        };
        let mut unfinished_sell_order: Option<(ParsedData, dex1::LimitOrder)> = None;
        while fulfilled_orders.len() < 20 {
            // Loop invariant
            assert!(unfinished_buy_order.is_none() || unfinished_sell_order.is_none());
            let mut advanced = false;
            {
                let mut finish_buy_order = false;
                if let Some(buy_order) = &unfinished_buy_order {
                    if let Some(sell_order) =
                        locate_next_valid_order(&mut limit_sells, emitter, expired_block_number)?
                    {
                        if !matchable_order(&buy_order.0, &sell_order.0) {
                            // No more sell orders can be processed
                            break;
                        }
                        let seller_bid_amount: u128 = sell_order.1.bid_amount().unpack();
                        match pending_ask_amount.cmp(&seller_bid_amount) {
                            std::cmp::Ordering::Less => {
                                // pending_ask_amount should now hold value for the unfinished sell order.
                                pending_ask_amount = seller_bid_amount - pending_ask_amount;
                                finish_buy_order = true;
                                unfinished_sell_order = Some(sell_order);
                            }
                            std::cmp::Ordering::Equal => {
                                pending_ask_amount = 0;
                                finish_buy_order = true;
                                fulfilled_orders.push(sell_order);
                            }
                            std::cmp::Ordering::Greater => {
                                pending_ask_amount -= seller_bid_amount;
                                fulfilled_orders.push(sell_order);
                            }
                        };
                        advanced = true;
                    }
                }
                if finish_buy_order {
                    fulfilled_orders.push(unfinished_buy_order.unwrap());
                    if unfinished_sell_order.is_none() {
                        unfinished_buy_order = locate_next_valid_order(
                            &mut limit_buys,
                            emitter,
                            expired_block_number,
                        )?;
                    } else {
                        unfinished_buy_order = None;
                    }
                }
            }
            {
                let mut finish_sell_order = false;
                if let Some(sell_order) = &unfinished_sell_order {
                    if let Some(buy_order) =
                        locate_next_valid_order(&mut limit_buys, emitter, expired_block_number)?
                    {
                        if !matchable_order(&buy_order.0, &sell_order.0) {
                            // No more buy orders can be processed
                            break;
                        }
                        let buyer_bid_amount: u128 = buy_order.1.bid_amount().unpack();
                        match pending_ask_amount.cmp(&buyer_bid_amount) {
                            std::cmp::Ordering::Less => {
                                // pending_ask_amount should now hold value for the unfinished buy order.
                                pending_ask_amount = buyer_bid_amount - pending_ask_amount;
                                finish_sell_order = true;
                                unfinished_buy_order = Some(buy_order);
                            }
                            std::cmp::Ordering::Equal => {
                                pending_ask_amount = 0;
                                finish_sell_order = true;
                                fulfilled_orders.push(buy_order);
                            }
                            std::cmp::Ordering::Greater => {
                                pending_ask_amount -= buyer_bid_amount;
                                fulfilled_orders.push(buy_order);
                            }
                        }
                        advanced = true;
                    }
                }
                if finish_sell_order {
                    fulfilled_orders.push(unfinished_sell_order.unwrap());
                    if unfinished_buy_order.is_none() {
                        unfinished_sell_order = locate_next_valid_order(
                            &mut limit_sells,
                            emitter,
                            expired_block_number,
                        )?;
                    } else {
                        unfinished_sell_order = None;
                    }
                }
            }
            if !advanced {
                break;
            }
        }
        if fulfilled_orders.is_empty() {
            return Ok(());
        }
        // Create payment cells for all fulfilled orders
        let mut freestanding_orders = Vec::new();
        let mut otx_payment_cells = Vec::new();
        let mut freestanding_payment_cells = Vec::new();
        fulfilled_orders
            .iter()
            .for_each(|(parsed_data, limit_order)| {
                let cell_output = CellOutput::new_builder()
                    .lock(parsed_data.recipient_script.clone())
                    .type_(Some(parsed_data.ask_token_script.clone()).pack())
                    .capacity(limit_order.claimed_ckbytes())
                    .build();
                let cell_data = limit_order.ask_amount().raw_data().pack();

                if parsed_data.freestanding_cell {
                    freestanding_orders.push(parsed_data.order.clone());
                    freestanding_payment_cells.push((cell_output, cell_data));
                } else {
                    otx_payment_cells.push((cell_output, cell_data));
                }
            });

        // Create payment cells for partially filled order if needed
        assert!(unfinished_buy_order.is_none() || unfinished_sell_order.is_none());
        let mut post_value = None;
        if unfinished_buy_order.is_some() || unfinished_sell_order.is_some() {
            let (order, key) = if unfinished_buy_order.is_some() {
                (unfinished_buy_order.unwrap(), limit_buy_key)
            } else {
                (unfinished_sell_order.unwrap(), limit_sell_key)
            };

            // The partial order will ask +required_ask_amount+ ask token, while
            // providing +required_bid_amount+ bid token.
            let (required_bid_amount, required_ask_amount) = {
                let mut input_bid_amount: u128 = 0;
                let mut output_bid_amount: u128 = 0;
                let mut input_ask_amount: u128 = 0;
                let mut output_ask_amount: u128 = 0;

                let ask_token = order.1.ask_token();
                fulfilled_orders.iter().for_each(|(_, limit_order)| {
                    let current_bid_amount: u128 = limit_order.bid_amount().unpack();
                    let current_ask_amount: u128 = limit_order.ask_amount().unpack();

                    if limit_order.ask_token() == ask_token {
                        // Current order is of the same direction as partial order
                        input_bid_amount += current_bid_amount;
                        output_ask_amount += current_ask_amount;
                    } else {
                        input_ask_amount += current_bid_amount;
                        output_bid_amount += current_ask_amount;
                    }
                });

                assert!(output_bid_amount > input_bid_amount);
                assert!(input_ask_amount > output_ask_amount);
                (
                    (output_bid_amount - input_bid_amount),
                    (input_ask_amount - output_ask_amount),
                )
            };

            let ask_amount: u128 = order.1.ask_amount().unpack();
            let bid_amount: u128 = order.1.bid_amount().unpack();
            assert!(required_bid_amount < bid_amount);
            assert!(required_ask_amount < ask_amount);
            assert!(
                U256::from(required_ask_amount) * U256::from(bid_amount)
                    >= U256::from(required_bid_amount) * U256::from(ask_amount),
            );

            let claimed_ckbytes: u64 = order.1.claimed_ckbytes().unpack();

            // Create paid cell first, so we know how much capacity freestanding cell has
            let (paid_cell, paid_data, paid_capacity) = {
                let dummy = CellOutput::new_builder()
                    .lock(order.0.recipient_script.clone())
                    .type_(Some(order.0.ask_token_script.clone()).pack())
                    .build();
                let capacity = dummy
                    .occupied_capacity(Capacity::bytes(16).expect("overflow"))
                    .expect("overflow");
                let output = dummy
                    .as_builder()
                    .capacity(capacity.as_u64().pack())
                    .build();
                (
                    output,
                    Bytes::from(required_ask_amount.to_le_bytes().to_vec()).pack(),
                    capacity.as_u64(),
                )
            };

            let freestanding_capacity = claimed_ckbytes - paid_capacity;
            let new_ask_amount = ask_amount - required_ask_amount;
            let new_bid_amount = bid_amount - required_bid_amount;
            let new_price = Ratio::new_raw(new_ask_amount, new_bid_amount);
            let new_order = dex1::Order::new_builder()
                .set(
                    order
                        .1
                        .clone()
                        .as_builder()
                        .ask_amount(new_ask_amount.pack())
                        .bid_amount(new_bid_amount.pack())
                        .claimed_ckbytes(freestanding_capacity.pack())
                        .build(),
                )
                .build();

            // Create freestanding cell
            let (freestanding_cell, freestanding_data) = {
                (
                    CellOutput::new_builder()
                        .lock(self.freestanding_lock(&order.0.recipient_script, &new_order))
                        .type_(Some(order.0.bid_token_script.clone()).pack())
                        .capacity(freestanding_capacity.pack())
                        .build(),
                    Bytes::from((bid_amount - required_bid_amount).to_le_bytes().to_vec()).pack(),
                )
            };

            post_value = Some((
                key,
                ParsedData {
                    tx: RichOtx {
                        tx: Transaction::default(),
                        inputs: Vec::new(),
                    },
                    recipient_script: order.0.recipient_script.clone(),
                    ask_token_script: order.0.ask_token_script.clone(),
                    bid_token_script: order.0.bid_token_script.clone(),
                    price: new_price,
                    order: new_order,
                    freestanding_cell: true,
                },
            ));

            if order.0.freestanding_cell {
                freestanding_orders.push(order.0.order.clone());
                freestanding_payment_cells.push((freestanding_cell, freestanding_data));
                freestanding_payment_cells.push((paid_cell, paid_data));
            } else {
                otx_payment_cells.push((freestanding_cell, freestanding_data));
                otx_payment_cells.push((paid_cell, paid_data));
            }
            fulfilled_orders.push(order);
        }

        // Assemble the final transaction.
        let sighash_witness = {
            let orders = dex1::Orders::new_builder()
                .extend(freestanding_orders)
                .build();
            let dex1_action = dex1::Dex1Action::new_builder().orders(orders).build();
            let action = basic::Action::new_builder()
                .data(dex1_action.as_bytes().pack())
                .script_hash(self.dex1_script.script.calc_script_hash())
                .build();
            let actions = basic::ActionVec::new_builder().push(action).build();
            let message = basic::Message::new_builder().actions(actions).build();
            let sighash = basic::SighashAll::new_builder().message(message).build();
            WitnessLayout::new_builder()
                .set(sighash)
                .build()
                .as_bytes()
                .pack()
        };
        let otxstart_witness = {
            // As shown below, dex1 builds CKB transactions so that
            // OTXs are put at the very front, so OtxStart can just
            // use all default values.
            let otx_start = basic::OtxStart::new_builder().build();
            WitnessLayout::new_builder()
                .set(otx_start)
                .build()
                .as_bytes()
                .pack()
        };
        let mut cobuild_witnesses = vec![sighash_witness, otxstart_witness];
        let mut inputs = vec![];
        let mut outputs = vec![];
        let mut outputs_data = vec![];
        // Our assembler here will create tx of the following layouts:
        // * All the otx cells come at the very first
        fulfilled_orders
            .iter()
            .filter(|(parsed_data, _)| !parsed_data.freestanding_cell)
            .for_each(|(parsed_data, _)| {
                inputs.extend(parsed_data.tx.tx.raw().inputs());
                outputs.extend(parsed_data.tx.tx.raw().outputs());
                outputs_data.extend(parsed_data.tx.tx.raw().outputs_data());
                cobuild_witnesses.extend(parsed_data.tx.tx.witnesses());
            });
        // * The dex1 validating input & output cell comes next
        inputs.push(dex1_cell_input);
        outputs.push(dex1_cell_output);
        outputs_data.push(dex1_cell_data);
        // * Freestanding input cells are appended to inputs
        fulfilled_orders
            .iter()
            .filter(|(parsed_data, _)| parsed_data.freestanding_cell)
            .for_each(|(parsed_data, _)| {
                inputs.extend(parsed_data.tx.tx.raw().inputs());
            });
        // * Finally, we have a series of payment output cells
        for (output, data) in otx_payment_cells {
            outputs.push(output);
            outputs_data.push(data);
        }
        for (output, data) in freestanding_payment_cells {
            outputs.push(output);
            outputs_data.push(data);
        }
        // * The witness array will be prepended with empty values for existing
        // input & output cells, then we will insert one witness for Sighash Cobuild
        // message(for dex1 validating purpose), and then a series of otx witnesses
        let witnesses = {
            let mut w = vec![Bytes::default().pack(); std::cmp::max(outputs.len(), inputs.len())];
            w.extend(cobuild_witnesses);
            w
        };
        // The outer processor infrastructure shall take care of locating cell deps,
        // reducer here does nothing.
        // We will fill in dex1 header dep at sealing time
        let tx = TransactionView::new_advanced_builder()
            .inputs(inputs)
            .outputs(outputs)
            .outputs_data(outputs_data)
            .witnesses(witnesses)
            .build();
        emitter.emit_tx(tx.data(), post_value)
    }

    fn postprocess<E>(&self, tx: Transaction, value: Self::PostValue, emitter: &mut E) -> Result<()>
    where
        E: MapEmitter<Self::Key, Self::Order, Self::Value>,
    {
        if let Some((key, mut parsed_data)) = value {
            let tx = tx.into_view();
            let freestanding_lock =
                self.freestanding_lock(&parsed_data.recipient_script, &parsed_data.order);
            let Some(output_index) = tx
                .outputs()
                .into_iter()
                .position(|cell_output| cell_output.lock() == freestanding_lock)
            else {
                bail!(
                    "Freestanding lock is missing in transaction {:x}!",
                    tx.hash()
                );
            };
            let output = tx.outputs().get(output_index).unwrap();
            let data = tx.outputs_data().get(output_index).unwrap();
            if parsed_data.minimal_ckbytes() > output.capacity().unpack() {
                bail!(
                    "Freestanding cell in {:x} does not have enough capacity for later orders!",
                    tx.hash()
                );
            }
            parsed_data.tx = RichOtx {
                tx: TransactionView::new_advanced_builder()
                    .input(
                        CellInput::new_builder()
                            .previous_output(OutPoint::new(tx.hash(), output_index as u32))
                            .build(),
                    )
                    .build()
                    .data(),
                inputs: vec![(output, data.unpack())],
            };
            emitter.emit(key, parsed_data.price, parsed_data)
        } else {
            Ok(())
        }
    }
}

fn validate_limit_order(order: &ParsedData, expired_block_number: u64) -> Option<dex1::LimitOrder> {
    match order.order.to_enum() {
        dex1::OrderUnion::LimitOrder(o) => Some(o),
        dex1::OrderUnion::LimitOrderWithDeadline(o) => {
            let deadline: u64 = o.deadline().unpack();
            if deadline <= expired_block_number {
                Some(o.order())
            } else {
                None
            }
        }
        _ => unreachable!(),
    }
}

fn locate_next_valid_order<I, E>(
    iter: &mut I,
    emitter: &mut E,
    expired_block_number: u64,
) -> Result<Option<(ParsedData, dex1::LimitOrder)>>
where
    I: Iterator<Item = ParsedData>,
    E: ReduceEmitter<
        <Dex1 as Assembler>::Key,
        <Dex1 as Assembler>::Order,
        <Dex1 as Assembler>::Value,
        <Dex1 as Assembler>::PostValue,
    >,
{
    while let Some(parsed_data) = iter.next() {
        if let Some(limit_order) = validate_limit_order(&parsed_data, expired_block_number) {
            return Ok(Some((parsed_data, limit_order)));
        } else {
            if let Err(e) = emitter.reject_otx(parsed_data.tx.tx) {
                bail!("Reject otx encounters error: {:?}", e);
            }
        }
    }
    Ok(None)
}

fn matchable_order(buy_order: &ParsedData, sell_order: &ParsedData) -> bool {
    buy_order.price.recip() >= sell_order.price
}

fn hash_order(order: &dex1::Order) -> [u8; 32] {
    let mut blake = blake2b_ref::Blake2bBuilder::new(32)
        .personal(b"ckb-default-hash")
        .build();
    blake.update(order.as_slice());
    let mut hash = [0u8; 32];
    blake.finalize(&mut hash);
    hash
}

fn placeholder_dex1_cell_input() -> CellInput {
    CellInput::new_builder().build()
}
