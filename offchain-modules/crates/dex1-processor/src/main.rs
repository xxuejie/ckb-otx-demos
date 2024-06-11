use ckb_jsonrpc_types::{OutPoint, OutputsValidator, Status, Transaction};
use ckb_sdk::{CkbRpcClient, RpcError};
use ckb_types::{core::TransactionView, packed, prelude::*};
use clap::{arg, command, value_parser};
use core::hash::Hash;
use dex1_assembler::{
    config::{Config as Dex1Config, FullScript},
    Dex1, Dex1Env,
};
use jsonrpc_core::Result as JsonrpcResult;
use jsonrpc_derive::rpc;
use jsonrpc_http_server::ServerBuilder;
use otx_traits::{Assembler, ReduceSource, Value};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct Config {
    pub listen_address: String,
    pub ckb_uri: String,
    pub dex1_config: Dex1Config,
    pub known_locks: Vec<FullScript>,
}

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

/// This is a minimal emitter instance which:
/// 1. Works with only one assembler
/// 2. Keeps all open transactions in memory
///
/// A more mature emitter would be able to support more assemblers at once,
/// and also store open transactions in a persistent layer such as rocksdb.
/// But this simple one here already shows what an emitter can do.
pub struct SingleInMemoryEmitter<A: Assembler> {
    data: HashMap<A::Key, BTreeMap<A::Order, Vec<A::Value>>>,
    pending_txs: Vec<TransactionView>,
}

impl<A: Assembler> SingleInMemoryEmitter<A> {
    pub fn pending_outpoints(&self) -> HashSet<packed::OutPoint> {
        self.pending_txs
            .iter()
            .map(|tx| {
                tx.data()
                    .raw()
                    .inputs()
                    .into_iter()
                    .map(|cell_input| cell_input.previous_output())
            })
            .flatten()
            .collect()
    }

    pub fn add_pending_txs(&mut self, txs: impl Iterator<Item = packed::Transaction>) {
        self.pending_txs.extend(txs.map(|tx| tx.into_view()));
    }

    // Given a set of already-spent outpoints, this method purges all otxs
    // that also consume such outpoints
    pub fn purge_otxs(&mut self, outpoints: &HashSet<packed::OutPoint>) {
        for otxs in self.data.values_mut() {
            for values in otxs.values_mut() {
                values.retain(|value| !value.spent(outpoints));
            }
            otxs.retain(|_, values| !values.is_empty());
        }
    }

    // Refresh (and possibly resend) pending transactions to CKB client.
    // This method would return true when a CKB node error is detected when
    // processing a transaction. Which might trigger regeneration of certain
    // transactions.
    pub fn refresh_pending_txs(&mut self, client: &CkbRpcClient) -> bool {
        // First of all, find and remove all committed txs
        let mut i = 0;
        while i < self.pending_txs.len() {
            let status = client
                .get_transaction_status(self.pending_txs[i].hash().unpack())
                .expect("get transaction status");
            // TODO: maybe it's worth waiting for enough confirmations before
            // removing them immediately when committed.
            if status.tx_status.status != Status::Committed {
                break;
            }
            i += 1;
        }
        if i > 0 {
            self.pending_txs.drain(0..i);
        }
        // Now repeatedly send all remaining transactions to CKB. For those
        // that have already been sent to CKB, it won't really hurt if we
        // send them again.
        let mut remove_tx_from = None;
        for (i, tx) in self.pending_txs.iter().enumerate() {
            if let Err(e) =
                client.send_transaction(tx.data().into(), Some(OutputsValidator::Passthrough))
            {
                // Parse the error:
                // * For script validation errors, we would remove the affected otxs
                // * For double-spent errors, we would scan the transaction, and remove
                // all spent outpoints
                match e.into() {
                    ParsedRpcError::InvalidOutPoint(o) => {
                        self.purge_otxs(&vec![o].into_iter().collect());
                        remove_tx_from = Some(i);
                        break;
                    }
                    ParsedRpcError::InputCellScriptError(i) => {
                        // For input cell it is easy, we just take the outpoint
                        // of that input cell, and use it to purge otxs
                        self.purge_otxs(
                            &vec![tx.data().raw().inputs().get(i).unwrap().previous_output()]
                                .into_iter()
                                .collect(),
                        );
                        remove_tx_from = Some(i);
                        break;
                    }
                    ParsedRpcError::OutputCellScriptError(i) => {
                        // Output cell is slightly tricky, we will need to parse
                        // otx data to detect which otx the affected output cell
                        // belongs, then find an outpoint from that otx to do
                        // purging.
                        todo!()
                    }
                    ParsedRpcError::Other(e) => panic!("CKB RPC error: {:?}", e),
                }
            }
        }
        if let Some(i) = remove_tx_from {
            self.pending_txs.drain(i..);
            true
        } else {
            false
        }
    }
}

pub enum ParsedRpcError {
    InvalidOutPoint(packed::OutPoint),
    InputCellScriptError(usize),
    OutputCellScriptError(usize),
    Other(String),
}

impl From<RpcError> for ParsedRpcError {
    fn from(e: RpcError) -> ParsedRpcError {
        todo!()
    }
}

impl<K: Eq + Hash + Clone, O: Ord + Clone, A: Assembler<Key = K, Order = O>>
    SingleInMemoryEmitter<A>
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
    for SingleInMemoryEmitter<A>
{
    fn otxs<'a>(&'a self, key: A::Key) -> impl Iterator<Item = A::Value>
    where
        V: 'a,
    {
        let pending_outpoints = self.pending_outpoints();
        self.data
            .get(&key)
            .unwrap()
            .values()
            .flatten()
            .filter(move |value| !value.spent(&pending_outpoints))
            .cloned()
    }
}

impl<A: Assembler> Default for SingleInMemoryEmitter<A> {
    fn default() -> Self {
        Self {
            data: HashMap::new(),
            pending_txs: Vec::new(),
        }
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
                -c --config <FILE> "Config file path"
            )
            .required(true)
            .value_parser(value_parser!(PathBuf)),
        )
        .get_matches();
    let config_path = matches.get_one::<PathBuf>("config").expect("config");
    log::debug!("Config file path: {:?}", config_path);

    let config: Config =
        toml::from_str(&std::fs::read_to_string(config_path).expect("read config"))
            .expect("parse config");
    let client = CkbRpcClient::new(&config.ckb_uri);

    let buffered_data = Arc::new(Mutex::new((Vec::new(), Vec::new())));
    let otx_rpc_impl = OtxRpcImpl(buffered_data.clone());

    let mut io = jsonrpc_core::IoHandler::new();
    io.extend_with(otx_rpc_impl.to_delegate());

    let server = ServerBuilder::new(io)
        .threads(3)
        .start_http(&config.listen_address.parse().expect("parse listen address"))
        .expect("start jsonrpc server");
    log::info!("JSONRPC server started!");

    // Periodically, update open transaction list, then submit assembled
    // CKB transaction to L1 network
    thread::spawn(move || {
        let env = Dex1Env::new(client.clone(), &config.dex1_config);
        let mut emitter: SingleInMemoryEmitter<Dex1> = SingleInMemoryEmitter::default();
        let mut last_time = SystemTime::now();
        let dex1 = Dex1::new(&config.dex1_config);

        loop {
            let now = SystemTime::now();
            let d = now.duration_since(last_time).expect("time goes backwards!");
            if let Some(sleep_time) = Duration::from_secs(10).checked_sub(d) {
                thread::sleep(sleep_time);
            }

            log::debug!("Processing otxs!");
            let (new_otxs, cancelling_out_points): (Vec<_>, HashSet<_>) = {
                let mut pair = buffered_data.lock().expect("lock");
                (pair.0.drain(..).collect(), pair.1.drain(..).collect())
            };
            emitter.refresh_pending_txs(&client);
            // For now, we employ an optimistic solution to detect spent
            // outpoints: we would construct the CKB transaction assuming all
            // otxs contain valid outpoints. The processor would only trigger
            // outpoint validation checks, when a CKB nodes rejects a CKB
            // transaction due to one of the outpoint is already spent.
            // This might lead to that more transactions than necessary are
            // constructed, but the processor is just a dummy machine, it won't
            // really hurt doing retries.
            emitter.purge_otxs(&cancelling_out_points);
            for new_otx in new_otxs {
                let rich_otx = env.fulfill_otx(new_otx).expect("fulfilling otx");
                match dex1.map(rich_otx) {
                    Ok((key, order, value)) => emitter.insert_otx(key, order, value),
                    Err(e) => log::error!("Error in mapper: {:?}", e),
                }
            }
            // Since we are taking the optimistic solution to detect spent
            // outpoints. Chances are we would need to regenerate CKB transactions
            // for a few rounds before detecting all spent outpoints. This loop
            // ensures this behavior.
            loop {
                for (first_key, second_key) in dex1.keys() {
                    let base_tx = match emitter.pending_txs.last() {
                        Some(tx) => env.fulfill_otx(tx.data()).expect("fulfilling tx"),
                        None => env.base_tx().expect("fetching base tx from chain"),
                    };
                    match dex1.reduce(base_tx, vec![first_key, second_key], &emitter) {
                        Ok(txs) => emitter.add_pending_txs(txs.into_iter()),
                        Err(e) => log::error!("Error in reducer: {:?}", e),
                    }
                }
                if !emitter.refresh_pending_txs(&client) {
                    break;
                }
            }
            last_time = SystemTime::now();
        }
    });

    server.wait();
}
