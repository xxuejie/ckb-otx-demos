#[cfg(test)]
mod tests;

use chrono::prelude::*;
use ckb_jsonrpc_types::{OutPoint, OutputsValidator, Status, Transaction};
use ckb_sdk::{CkbRpcClient, RpcError};
use ckb_types::{core::TransactionView, packed, prelude::*, H256};
use clap::{arg, command, value_parser, ArgMatches};
use core::hash::Hash;
use dex1_assembler::{config::RunnerConfig, schemas::top_level, Dex1, Dex1Env};
use jsonrpc_core::Result as JsonrpcResult;
use jsonrpc_derive::rpc;
use jsonrpc_http_server::ServerBuilder;
use otx_traits::{Assembler, MapEmitter, ReduceEmitter, ReduceSource, Value};
use regex::Regex;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[rpc]
pub trait OtxRpc {
    #[rpc(name = "submit_open_transaction")]
    fn submit_open_transaction(&self, tx: Transaction) -> JsonrpcResult<()>;

    #[rpc(name = "cancel_open_transaction")]
    fn cancel_open_transaction(&self, outpoint: OutPoint) -> JsonrpcResult<()>;
}

pub struct OtxRpcImpl(Arc<Mutex<(Vec<packed::Transaction>, Vec<packed::OutPoint>)>>);
impl OtxRpc for OtxRpcImpl {
    fn submit_open_transaction(&self, tx: Transaction) -> JsonrpcResult<()> {
        self.0.lock().expect("lock").0.push(tx.into());
        Ok(())
    }

    fn cancel_open_transaction(&self, outpoint: OutPoint) -> JsonrpcResult<()> {
        self.0.lock().expect("lock").1.push(outpoint.into());
        Ok(())
    }
}

/// This is a minimal data source which:
/// 1. Works with only one assembler
/// 2. Keeps all open transactions in memory
///
/// A more mature source would be able to support more assemblers at once,
/// and also store open transactions in a persistent layer such as rocksdb.
/// But this simple one here already shows what a data source can do.
pub struct SingleInMemorySource<A: Assembler> {
    data: HashMap<A::Key, BTreeMap<A::Order, Vec<A::Value>>>,

    inflight_tx: Option<TransactionView>,
    pending_txs: VecDeque<(packed::Transaction, A::PostValue)>,
}

impl<A: Assembler> SingleInMemorySource<A> {
    pub fn pending_outpoints(&self) -> HashSet<packed::OutPoint> {
        self.pending_txs
            .iter()
            .map(|(tx, _)| tx.raw().inputs())
            .chain(self.inflight_tx.iter().map(|tx_view| tx_view.inputs()))
            .map(|inputs| {
                inputs
                    .into_iter()
                    .map(|cell_input| cell_input.previous_output())
            })
            .flatten()
            .collect()
    }

    // Count the number of otxs
    pub fn len(&self) -> usize {
        self.data
            .values()
            .map(|otxs| otxs.values().map(|values| values.len()))
            .flatten()
            .fold(0, |acc, l| acc + l)
    }

    // Given a set of already-spent outpoints, this method purges all otxs
    // that also consume such outpoints
    pub fn purge_otxs(&mut self, outpoints: &HashSet<packed::OutPoint>) {
        let before = self.len();
        for otxs in self.data.values_mut() {
            for values in otxs.values_mut() {
                values.retain(|value| !value.spent(outpoints));
            }
            otxs.retain(|_, values| !values.is_empty());
        }
        let after = self.len();
        assert!(before >= after);
        if before > after {
            log::info!("Purged {} otxs due to spent outpoints", before - after);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParsedRpcError {
    InvalidOutPoint(packed::OutPoint),
    InputCellScriptError(usize),
    OutputCellScriptError(usize),
    Other(String),
}

impl From<RpcError> for ParsedRpcError {
    fn from(e: RpcError) -> ParsedRpcError {
        let text = e.to_string();
        if let Some(caps) = Regex::new(r"TransactionScriptError.+Inputs\[([0-9]+)\]")
            .unwrap()
            .captures(&text)
        {
            ParsedRpcError::InputCellScriptError(caps.get(1).unwrap().as_str().parse().unwrap())
        } else if let Some(caps) = Regex::new(r"TransactionScriptError.+Outputs\[([0-9]+)\]")
            .unwrap()
            .captures(&text)
        {
            ParsedRpcError::OutputCellScriptError(caps.get(1).unwrap().as_str().parse().unwrap())
        } else if let Some(caps) = Regex::new(r"OutPoint\(0x([0-9a-fA-F]+)\)")
            .unwrap()
            .captures(&text)
        {
            let data = hex::decode(caps.get(1).unwrap().as_str()).expect("decode hex");
            let outpoint = packed::OutPoint::from_slice(&data).expect("parse outpoint");
            ParsedRpcError::InvalidOutPoint(outpoint)
        } else {
            ParsedRpcError::Other(text)
        }
    }
}

impl<K: Eq + Hash + Clone, O: Ord + Clone, A: Assembler<Key = K, Order = O>>
    SingleInMemorySource<A>
{
    pub fn insert_otx(&mut self, key: K, order: O, value: A::Value) {
        if !self.data.contains_key(&key) {
            self.data.insert(key.clone(), BTreeMap::default());
        }
        let otxs = self.data.get_mut(&key).unwrap();
        if !otxs.contains_key(&order) {
            otxs.insert(order.clone(), Vec::new());
        }
        otxs.get_mut(&order).unwrap().push(value);
    }
}

impl<V: Value + Clone, A: Assembler<Value = V>> ReduceSource<A::Key, A::Value>
    for SingleInMemorySource<A>
{
    fn otxs<'a>(&'a self, key: A::Key) -> impl Iterator<Item = A::Value>
    where
        V: 'a,
    {
        let pending_outpoints = self.pending_outpoints();
        self.data
            .get(&key)
            .into_iter()
            .map(|btree| btree.values())
            .flatten()
            .flatten()
            .filter(move |value| !value.spent(&pending_outpoints))
            .cloned()
    }
}

impl<A: Assembler> Default for SingleInMemorySource<A> {
    fn default() -> Self {
        Self {
            data: HashMap::new(),
            inflight_tx: None,
            pending_txs: VecDeque::new(),
        }
    }
}

pub struct MemoryEmitter<A: Assembler> {
    pub otxs: Vec<(A::Key, A::Order, A::Value)>,
    pub rejected_otxs: Vec<packed::Transaction>,
    pub txs: Vec<(packed::Transaction, A::PostValue)>,
}

impl<A: Assembler> Default for MemoryEmitter<A> {
    fn default() -> Self {
        Self {
            otxs: Vec::new(),
            rejected_otxs: Vec::new(),
            txs: Vec::new(),
        }
    }
}

impl<A: Assembler> MapEmitter<A::Key, A::Order, A::Value> for MemoryEmitter<A> {
    fn emit(&mut self, key: A::Key, order: A::Order, value: A::Value) -> anyhow::Result<()> {
        self.otxs.push((key, order, value));
        Ok(())
    }
}

impl<A: Assembler> ReduceEmitter<A::Key, A::Order, A::Value, A::PostValue> for MemoryEmitter<A> {
    fn reject_otx(&mut self, otx: packed::Transaction) -> anyhow::Result<()> {
        self.rejected_otxs.push(otx);
        Ok(())
    }

    fn emit_tx(&mut self, tx: packed::Transaction, post_value: A::PostValue) -> anyhow::Result<()> {
        self.txs.push((tx, post_value));
        Ok(())
    }
}

fn main() {
    flexi_logger::Logger::try_with_env()
        .unwrap()
        .start()
        .unwrap();

    let matches = command!()
        .arg(
            arg!(
                -f --from <WALLET> "Wallet file for from address"
            )
            .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(
                -c --config <FILE> "Config file path"
            )
            .required(true)
            .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(
                -t --txs <TXS> "Folder to save all created txs for debugging"
            )
            .value_parser(value_parser!(PathBuf)),
        )
        .get_matches();
    let config_path = matches.get_one::<PathBuf>("config").expect("config");
    log::debug!("Config file path: {:?}", config_path);

    let config: RunnerConfig =
        toml::from_str(&std::fs::read_to_string(config_path).expect("read config"))
            .expect("parse config");
    let client = CkbRpcClient::new(&config.ckb_rpc);

    let buffered_data = Arc::new(Mutex::new((Vec::new(), Vec::new())));
    let otx_rpc_impl = OtxRpcImpl(buffered_data.clone());

    let mut io = jsonrpc_core::IoHandler::new();
    io.extend_with(otx_rpc_impl.to_delegate());

    let rpc = if let Some(caps) = Regex::new(r"https?://(.+)")
        .unwrap()
        .captures(&config.otx_rpc)
    {
        caps.get(1).unwrap().as_str().to_string()
    } else {
        config.otx_rpc.clone()
    };
    log::debug!("Listening RPC address: {}", rpc);
    let server = ServerBuilder::new(io)
        .threads(3)
        .start_http(&rpc.parse().expect("parse listen address"))
        .expect("start jsonrpc server");
    log::info!("JSONRPC server started!");

    // Periodically, update open transaction list, then submit assembled
    // CKB transaction to L1 network
    thread::spawn(move || {
        let private_key = build_private_key(&matches);
        let mut dex1_env = Dex1Env::new(&config, private_key);
        let dex1 = Dex1::new(&config.config());
        let mut source: SingleInMemorySource<Dex1> = SingleInMemorySource::default();

        loop {
            // If any in-flight tx exists, we will wait till it is committed.
            // Note: this is rather inefficient solution, which works for a demo
            // but might not suit a production usage. Considering the fact that CKB
            // has a transaction proposal flow, it means that we can only submit a
            // new assembled CKB transaction roughly every minute, which means the
            // TPS counting otxs will be extremely low. There are indeed solutions
            // to this issue, but it would really depend on different cases:
            // * The ideal actor to run a cobuild OTX processor, would be CKB miners
            // or mining pools. When a mining pool integrates an OTX processor, it
            // will have better insight into the whole flow, allowing it to build more
            // assembled CKB transactions with better insight into referenced blocks.
            // * Given enough interests, there could be a mechanism, where we can
            // express the fact that multiple CKB transactions must be committed within
            // one block, or no transactions get committed. That will also provide a
            // solution to the problem.
            // * A simple solution without any assumptions also exists: instead of
            // having one dex1 cell that validates otxs, we can have multiple dex1 cells
            // sharing the exact same type script. The validating logic continues to work,
            // an actual otx does not need to care which dex1 cell will be used, and the
            // OTX processor can multiplex amongst different dex1 cells, achieving higher
            // throughput.
            let inflight_committed = source.inflight_tx.clone().map(|tx| {
                match client.get_transaction_status(tx.hash().unpack()) {
                    Ok(status) => match status.tx_status.status {
                        Status::Committed => true,
                        Status::Unknown => {
                            client
                                .send_transaction(
                                    tx.data().into(),
                                    Some(OutputsValidator::Passthrough),
                                )
                                .expect("send inflight tx error!");
                            false
                        }
                        _ => false,
                    },
                    Err(e) => {
                        log::error!("CKB RPC error: {:?}", e);
                        false
                    }
                }
            });
            match inflight_committed {
                Some(true) => {
                    let tx = source.inflight_tx.take().unwrap();
                    log::info!("TX {:x} committed to chain!", tx.hash());
                    let out_points = tx
                        .inputs()
                        .into_iter()
                        .map(|input| input.previous_output())
                        .collect();
                    // Purge otxs that have already spent outpoints
                    source.purge_otxs(&out_points);
                    // Purge pending txs that have already spent outpoints
                    if let Some(i) =
                        source.pending_txs.iter().position(|(pending_tx, _)| {
                            pending_tx.raw().inputs().into_iter().any(|cell_input| {
                                out_points.contains(&cell_input.previous_output())
                            })
                        })
                    {
                        source.pending_txs.drain(i..);
                    }
                }
                Some(false) => {
                    // In case an inflight transaction is present but not yet
                    // committed, we will wait for it, and start over.
                    thread::sleep(Duration::from_secs(5));
                    continue;
                }
                None => (),
            };

            // If a pending tx(meaning already assembled txs) is present, we will
            // try to seal it and send it over the network.
            // For now, we employ an optimistic solution to detect spent
            // outpoints: we would construct the CKB transaction assuming all
            // otxs contain valid outpoints. The processor would only trigger
            // outpoint validation checks, when a CKB nodes rejects a CKB
            // transaction due to one of the outpoint is already spent.
            // This might lead to that more transactions than necessary are
            // constructed, but the processor is just a dummy machine, it won't
            // really hurt doing retries.
            if source.inflight_tx.is_none() {
                if let Some((pending_tx, post_value)) = source.pending_txs.pop_front() {
                    let sealed_tx = dex1_env
                        .seal_tx(&pending_tx)
                        .expect("sealing tx")
                        .into_view();

                    log::info!("Sealed tx for submission: {:x}", sealed_tx.hash());
                    if let Some(txs) = matches.get_one::<PathBuf>("txs") {
                        let now: DateTime<Utc> = Utc::now();
                        let timestamp = now.format("%Y%m%d%H%M%S%.f").to_string();
                        let json_tx: Transaction = sealed_tx.data().into();

                        std::fs::write(
                            txs.join(format!("{}_{:x}.json", timestamp, sealed_tx.hash())),
                            serde_json::to_string_pretty(&json_tx).expect("json"),
                        )
                        .expect("write tx");
                    }

                    match client.send_transaction(
                        sealed_tx.data().into(),
                        Some(OutputsValidator::Passthrough),
                    ) {
                        Ok(_) => {
                            source.inflight_tx = Some(sealed_tx.clone());

                            let mut emitter: MemoryEmitter<Dex1> = MemoryEmitter::default();
                            if let Err(e) =
                                dex1.postprocess(sealed_tx.data(), post_value, &mut emitter)
                            {
                                log::warn!(
                                    "Error in postprocessor: {:?} for tx: {:x}",
                                    e,
                                    sealed_tx.hash()
                                );
                            }
                            for (key, order, value) in emitter.otxs {
                                source.insert_otx(key, order, value);
                            }
                        }
                        Err(e) => {
                            let mut defected_out_points = HashSet::new();
                            // Parse the error:
                            // * For script validation errors, we would remove the affected otxs
                            // * For double-spent errors, we would scan the transaction, and remove
                            // all spent outpoints
                            match e.into() {
                                ParsedRpcError::InvalidOutPoint(o) => {
                                    log::info!(
                            "Tx: {:x} uses a spent out point: {:?}, purge otxs that use this out point!",
                            sealed_tx.hash(),
                            o
                            );
                                    defected_out_points.insert(o);
                                }
                                ParsedRpcError::InputCellScriptError(i) => {
                                    log::info!(
                                        "Tx: {:x} has an otx with failed input cell(index: {})!",
                                        sealed_tx.hash(),
                                        i,
                                    );
                                    // For input cell it is easy, we just take the outpoint
                                    // of that input cell, and use it to purge otxs
                                    defected_out_points.insert(
                                        sealed_tx
                                            .data()
                                            .raw()
                                            .inputs()
                                            .get(i)
                                            .unwrap()
                                            .previous_output(),
                                    );
                                    break;
                                }
                                ParsedRpcError::OutputCellScriptError(i) => {
                                    log::info!(
                                        "Tx: {:x} has an otx with failed output cell(index: {})!",
                                        sealed_tx.hash(),
                                        i,
                                    );
                                    // Output cell is slightly tricky, we will need to parse
                                    // otx data to detect which otx the affected output cell
                                    // belongs, then find an outpoint from that otx to do
                                    // purging.
                                    let otx = locate_otx_in_tx(&sealed_tx.data(), i);
                                    defected_out_points.extend(
                                        otx.raw()
                                            .inputs()
                                            .into_iter()
                                            .map(|cell_input| cell_input.previous_output()),
                                    );
                                }
                                ParsedRpcError::Other(e) => panic!("CKB RPC error: {:?}", e),
                            }
                            if !defected_out_points.is_empty() {
                                source.purge_otxs(&defected_out_points);
                                // TODO: maybe some pending txs still contain useful otxs, we
                                // might want to salvage them
                                source.pending_txs.clear();
                                dex1_env.refresh_deps();
                            }
                        }
                    }
                }
            }

            // Actual processing of requests from RPC
            log::debug!("Processing otxs from RPC!");
            let (new_otxs, mut cancelling_out_points): (Vec<_>, HashSet<_>) = {
                let mut pair = buffered_data.lock().expect("lock");
                (pair.0.drain(..).collect(), pair.1.drain(..).collect())
            };
            // When new otx contains outpoints used by old otxs, we should purge old
            // otxs first.
            cancelling_out_points.extend(
                new_otxs
                    .iter()
                    .map(|otx| {
                        otx.raw()
                            .inputs()
                            .into_iter()
                            .map(|input| input.previous_output())
                    })
                    .flatten(),
            );
            source.purge_otxs(&cancelling_out_points);
            for new_otx in new_otxs {
                let rich_otx = dex1_env.fulfill_otx(new_otx).expect("fulfilling otx");
                let mut emitter: MemoryEmitter<Dex1> = MemoryEmitter::default();
                match dex1.map(rich_otx, &mut emitter) {
                    Ok(_) => {
                        for (key, order, value) in emitter.otxs {
                            source.insert_otx(key, order, value);
                        }
                    }
                    Err(e) => log::error!("Error in mapper: {:?}", e),
                }
            }

            // Assembling new CKB transactions from otxs
            let mut assembled = false;
            for key in dex1.keys() {
                let base_tx = dex1_env.base_tx().expect("creating base tx");
                let txs = {
                    let mut emitter: MemoryEmitter<Dex1> = MemoryEmitter::default();
                    match dex1.reduce(base_tx, key, &mut emitter, &source) {
                        Ok(_) => {
                            for (key, order, value) in emitter.otxs {
                                source.insert_otx(key, order, value);
                            }
                            source.purge_otxs(
                                &emitter
                                    .rejected_otxs
                                    .into_iter()
                                    .map(|otx| {
                                        otx.raw()
                                            .inputs()
                                            .into_iter()
                                            .map(|input| input.previous_output())
                                    })
                                    .flatten()
                                    .collect(),
                            );
                            emitter.txs
                        }
                        Err(e) => {
                            log::error!("Error in reducer: {:?}", e);
                            Vec::new()
                        }
                    }
                };

                assembled = assembled || (!txs.is_empty());
                source.pending_txs.extend(txs);
            }
            if !assembled {
                // In case there is no request, we will wait for a while so as not to block CPU
                thread::sleep(Duration::from_secs(10));
            }
        }
    });

    server.wait();
}

fn locate_otx_in_tx(tx: &packed::Transaction, output_index: usize) -> packed::Transaction {
    let mut first_otx = None;
    let mut input_cell = 0u32;
    let mut output_cell = 0u32;
    let mut cell_dep = 0u32;
    let mut header_dep = 0u32;

    for (i, witness) in tx.witnesses().into_iter().enumerate() {
        if let Ok(r) = top_level::WitnessLayoutReader::from_slice(&witness.raw_data()) {
            match r.to_enum() {
                top_level::WitnessLayoutUnionReader::OtxStart(o) => {
                    assert!(first_otx.is_none());
                    first_otx = Some(i + 1);
                    input_cell = o.start_input_cell().unpack();
                    output_cell = o.start_output_cell().unpack();
                    cell_dep = o.start_cell_deps().unpack();
                    header_dep = o.start_header_deps().unpack();
                }
                top_level::WitnessLayoutUnionReader::Otx(_o) => {
                    assert!(first_otx.is_none());
                    first_otx = Some(i);
                }
                _ => {}
            }
        }
    }
    let first_otx = first_otx.unwrap();
    let mut input_cell = input_cell as usize;
    let mut output_cell = output_cell as usize;
    let mut cell_dep = cell_dep as usize;
    let mut header_dep = header_dep as usize;

    for i in first_otx..tx.witnesses().len() {
        let witness = tx.witnesses().get(i).unwrap();
        let Ok(r) = top_level::WitnessLayout::from_slice(&witness.raw_data()) else {
            break;
        };
        let top_level::WitnessLayoutUnion::Otx(o) = r.to_enum() else {
            break;
        };
        let input_count: usize = o.input_cells().unpack();
        let output_count: usize = o.output_cells().unpack();
        let cell_dep_count: usize = o.cell_deps().unpack();
        let header_dep_count: usize = o.header_deps().unpack();

        let output_end = output_cell + output_count;
        if output_index >= output_cell && output_index < output_end {
            // Current OTX is the one to find
            return TransactionView::new_advanced_builder()
                .inputs(
                    tx.raw()
                        .inputs()
                        .into_iter()
                        .skip(input_cell)
                        .take(input_count),
                )
                .outputs(
                    tx.raw()
                        .outputs()
                        .into_iter()
                        .skip(output_cell)
                        .take(output_count),
                )
                .outputs_data(
                    tx.raw()
                        .outputs_data()
                        .into_iter()
                        .skip(output_cell)
                        .take(output_count),
                )
                .cell_deps(
                    tx.raw()
                        .cell_deps()
                        .into_iter()
                        .skip(cell_dep)
                        .take(cell_dep_count),
                )
                .header_deps(
                    tx.raw()
                        .header_deps()
                        .into_iter()
                        .skip(header_dep)
                        .take(header_dep_count),
                )
                .witness(witness)
                .build()
                .data();
        }

        input_cell += input_count;
        output_cell = output_end;
        cell_dep += cell_dep_count;
        header_dep += header_dep_count;
    }

    panic!("Output {} does not belong to any OTX!", output_index);
}

pub fn build_private_key(top_matches: &ArgMatches) -> H256 {
    let wallet_path = top_matches.get_one::<PathBuf>("from").unwrap();
    read_private_key(wallet_path)
}

pub fn read_private_key(path: &PathBuf) -> H256 {
    let wallet_content = std::fs::read_to_string(path)
        .expect("read wallet content")
        .trim()
        .to_string();
    // TODO: other formats might be added later, such as keystore files
    H256::from_str(&wallet_content).expect("parse raw private key")
}
