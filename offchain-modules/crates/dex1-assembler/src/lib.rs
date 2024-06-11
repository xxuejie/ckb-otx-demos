pub mod config;
pub mod schemas;

use crate::{
    config::{Config, PackedFullScript, PackedTradingPair},
    schemas::{
        dex1::{Dex1Action, OrderUnion},
        top_level::{WitnessLayout, WitnessLayoutUnion},
    },
};
use anyhow::{anyhow, bail, Result};
use ckb_jsonrpc_types::{
    Either, ResponseFormat, Script as JsonScript, Status, TransactionView as JsonTransactionView,
};
use ckb_sdk::{
    rpc::ckb_indexer::{Order, ScriptType, SearchKey, SearchMode},
    CkbRpcClient,
};
use ckb_types::{
    bytes::Bytes,
    core::TransactionView,
    packed::{Byte32, CellOutput, Script, Transaction},
    prelude::*,
};
use num_rational::Ratio;
use otx_traits::{Assembler, ReduceSource, Value};
use std::collections::HashMap;

/// This is similar to ResolvedTransaction, but contains just the bit of
/// information required by Dex1. For a different OTX processor, one can
/// alter this data structure with other required values.
#[derive(Debug, Clone)]
pub struct RichOtx {
    pub tx: Transaction,
    pub inputs: Vec<(CellOutput, Bytes, Byte32)>,
}

// The environment struct handles impure logic that is pending on
// actual state of the chain.
pub struct Dex1Env {
    client: CkbRpcClient,
    dex1_script: JsonScript,
}

impl Dex1Env {
    pub fn new(client: CkbRpcClient, config: &Config) -> Self {
        Self {
            client,
            dex1_script: config.dex1_script.script.clone(),
        }
    }

    pub fn fulfill_otx(&self, otx: Transaction) -> Result<RichOtx> {
        let raw = otx.raw();
        let mut inputs = Vec::with_capacity(raw.inputs().len());
        for cell_input in raw.inputs().into_iter() {
            let outpoint = cell_input.previous_output();
            let tx_with_status = match self.client.get_transaction(outpoint.tx_hash().unpack()) {
                Ok(Some(tx_with_status)) => tx_with_status,
                Ok(None) => bail!("Unknown outpoint: {:?}", outpoint),
                Err(e) => bail!("CKB RPC error: {:?}", e),
            };
            // Maybe we will need to take inflight transactions into account here
            // as well.
            if tx_with_status.tx_status.status != Status::Committed {
                bail!("Tx not committed: {:?}", outpoint);
            }
            let previous_tx = to_tx(tx_with_status.transaction.unwrap());
            let index: usize = outpoint.index().unpack();
            inputs.push((
                previous_tx.data().raw().outputs().get(index).unwrap(),
                previous_tx
                    .data()
                    .raw()
                    .outputs_data()
                    .get(index)
                    .unwrap()
                    .unpack(),
                tx_with_status.tx_status.block_hash.unwrap().pack(),
            ));
        }
        Ok(RichOtx { tx: otx, inputs })
    }

    pub fn base_tx(&self) -> Result<RichOtx> {
        let cells = match self.client.get_cells(
            SearchKey {
                script: self.dex1_script.clone(),
                script_type: ScriptType::Type,
                script_search_mode: Some(SearchMode::Exact),
                filter: None,
                with_data: Some(false),
                group_by_transaction: None,
            },
            Order::Desc,
            2.into(),
            None,
        ) {
            Ok(cells) => cells.objects,
            Err(e) => bail!("CKB RPC error: {:?}", e),
        };
        assert_eq!(cells.len(), 1);
        let tx = to_tx(
            self.client
                .get_transaction(cells[0].out_point.tx_hash.clone())
                .expect("rpc")
                .expect("fetching tx")
                .transaction
                .expect("extracting tx"),
        );
        self.fulfill_otx(tx.data())
    }
}

fn to_tx(json: ResponseFormat<JsonTransactionView>) -> TransactionView {
    match json.inner {
        Either::Left(json_view) => {
            let tx: Transaction = json_view.inner.into();
            tx.into_view()
        }
        Either::Right(json_bytes) => Transaction::from_slice(&json_bytes.into_bytes())
            .expect("molecule parsing")
            .into_view(),
    }
}

#[derive(Debug, Clone)]
pub struct ParsedData {
    pub tx: RichOtx,
    pub recipient_script: Script,
    pub price: Ratio<u128>,
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
            dex1_script: config.dex1_script.clone().into(),
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

    pub fn keys(&self) -> Vec<([u8; 65], [u8; 65])> {
        self.pairs
            .keys()
            .map(|key| {
                let mut first = ['B' as u8; 65];
                let mut second = ['S' as u8; 65];
                first[1..65].copy_from_slice(key);
                second[1..65].copy_from_slice(key);
                (first, second)
            })
            .collect()
    }
}

impl Assembler for Dex1 {
    type Tx = RichOtx;
    type Key = [u8; 65];
    type Order = Ratio<u128>;
    type Value = ParsedData;

    fn map(&self, tx: RichOtx) -> Result<(Self::Key, Self::Order, Self::Value)> {
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
            assert_eq!(raw.inputs().len(), input_cells);
            let output_cells: usize = otx.output_cells().unpack();
            assert_eq!(raw.outputs().len(), output_cells);
            let cell_deps: usize = otx.cell_deps().unpack();
            assert_eq!(raw.cell_deps().len(), cell_deps);
            let header_deps: usize = otx.header_deps().unpack();
            assert_eq!(raw.header_deps().len(), header_deps);
        }
        let dex1_script_hash = self.dex1_script.script.calc_script_hash();
        let action = otx
            .message()
            .actions()
            .into_iter()
            .find(|action| action.script_hash() == dex1_script_hash)
            .ok_or_else(|| anyhow!("Missing cobuild action for dex1!"))?;
        let dex1_action = Dex1Action::from_slice(&action.data().raw_data())
            .map_err(|e| anyhow!("Error parsing dex1 action data: {:?}", e))?;
        if dex1_action.orders().len() != 1 {
            bail!("For now, we only process otx with exact one order");
        }
        // TODO: support more order types
        let OrderUnion::LimitOrder(order) = dex1_action.orders().get(0).unwrap().to_enum() else {
            bail!("For now, we only support basic limit orders, later we shall add support for other types");
        };
        // Check if current trading pair is supported
        let (key, bid_token_script) = {
            let buy_pair = {
                let mut pair = [0u8; 64];
                pair[0..32].copy_from_slice(&order.ask_token().raw_data());
                pair[32..64].copy_from_slice(&order.bid_token().raw_data());
                pair
            };
            let sell_pair = {
                let mut pair = [0u8; 64];
                pair[0..32].copy_from_slice(&order.bid_token().raw_data());
                pair[32..64].copy_from_slice(&order.ask_token().raw_data());
                pair
            };
            if let Some(pair_data) = self.pairs.get(&buy_pair) {
                let mut key = ['B' as u8; 65];
                key[1..65].copy_from_slice(&buy_pair);
                (key, &pair_data.second)
            } else if let Some(pair_data) = self.pairs.get(&sell_pair) {
                let mut key = ['S' as u8; 65];
                key[1..65].copy_from_slice(&sell_pair);
                (key, &pair_data.first)
            } else {
                bail!("Trading pair is not supported!");
            }
        };
        // Check if enough tokens are provided by the otx as claimed in bid_amount
        // Check if claimed_ckbytes can be claimed
        let bid_amount: u128 = order.bid_amount().unpack();
        let ask_amount: u128 = order.ask_amount().unpack();
        {
            let mut tokens: u128 = 0;
            let mut ckbytes: u64 = 0;
            for (cell_output, cell_data, _) in &tx.inputs {
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
            let claimed_ckbytes: u64 = order.claimed_ckbytes().unpack();
            if claimed_ckbytes > ckbytes {
                bail!("Not enough ckbytes to claim!");
            }
        }
        // Check if recipient hash is used in current otx. Note this is a shortcut,
        // it's also possible to provide recipient script via OTX RPC.
        let Some(recipient_script) = tx
            .inputs
            .iter()
            .map(|(cell_output, _, _)| cell_output.lock())
            .chain(
                raw.outputs()
                    .into_iter()
                    .map(|cell_output| cell_output.lock()),
            )
            .find(|s| s.calc_script_hash() == order.recipient())
        else {
            bail!("Recipient script is missing!");
        };
        // Calculate the price, then emit the otx with parsed metadata
        let price = Ratio::new_raw(ask_amount, bid_amount);
        Ok((
            key,
            price,
            ParsedData {
                tx,
                recipient_script,
                price,
            },
        ))
    }

    fn reduce<S>(
        &self,
        base_tx: Self::Tx,
        keys: Vec<Self::Key>,
        source: &S,
    ) -> Result<Vec<Transaction>>
    where
        S: ReduceSource<Self::Key, Self::Value>,
    {
        assert_eq!(keys.len(), 2);
        // Find dex1 cell from base_tx
        // Create iterators of buy orders & sell orders
        // For each top buy order, look for sell orders it can fulfill
        // Adjust for partially filled order if needed
        // TODO: find a way so reduce can accept freestanding orders as well
        // The outer processor infrastructure shall take care of locating cell deps,
        // reducer here does nothing.
        todo!()
    }
}
