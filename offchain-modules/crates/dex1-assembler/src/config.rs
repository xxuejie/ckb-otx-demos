use ckb_jsonrpc_types::{CellDep, JsonBytes, Script};
use ckb_sdk::{traits::DefaultCellDepResolver, CkbRpcClient, ScriptId};
use ckb_types::{core::BlockView, packed, prelude::*, H256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct FullScript {
    pub script: Script,
    pub cell_dep: CellDep,
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct TradingPair {
    pub first: FullScript,
    pub second: FullScript,
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct Config {
    pub dex1_deployment: FullScript,
    pub pairs: Vec<TradingPair>,
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct TradingPairHashes {
    pub first: H256,
    pub second: H256,
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct TestUdt {
    owner_lock_hash: JsonBytes,
    name: String,
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
pub struct RunnerConfig {
    pub otx_rpc: String,
    pub ckb_rpc: String,
    pub dex1_deployment: Option<JsonBytes>,
    pub dex1_trading_pair_hashes: Vec<TradingPairHashes>,

    pub test_udts: Vec<TestUdt>,
    pub omnilock: FullScript,
    pub udt: FullScript,
    pub dex1: FullScript,
    pub always_success: FullScript,
}

#[derive(Clone, Default, PartialEq, Eq, Hash, Debug)]
pub struct PackedFullScript {
    pub script: packed::Script,
    pub cell_dep: packed::CellDep,
}

impl From<FullScript> for PackedFullScript {
    fn from(input: FullScript) -> PackedFullScript {
        PackedFullScript {
            script: input.script.into(),
            cell_dep: input.cell_dep.into(),
        }
    }
}

#[derive(Clone, Default, PartialEq, Eq, Hash, Debug)]
pub struct PackedTradingPair {
    pub first: PackedFullScript,
    pub second: PackedFullScript,
}

impl From<TradingPair> for PackedTradingPair {
    fn from(input: TradingPair) -> PackedTradingPair {
        PackedTradingPair {
            first: input.first.into(),
            second: input.second.into(),
        }
    }
}

fn replace_args(args: JsonBytes, full_script: &FullScript) -> FullScript {
    let mut full_script = full_script.clone();
    full_script.script.args = args;
    full_script
}

impl RunnerConfig {
    pub fn config(&self) -> Config {
        let known_scripts = self.known_script_map();

        let pairs = self
            .dex1_trading_pair_hashes
            .iter()
            .map(|hashes| {
                let first = known_scripts
                    .get(&hashes.first)
                    .expect("first of pair")
                    .1
                    .clone();
                let second = known_scripts
                    .get(&hashes.second)
                    .expect("second of pair")
                    .1
                    .clone();
                TradingPair { first, second }
            })
            .collect();

        Config {
            dex1_deployment: replace_args(
                self.dex1_deployment
                    .clone()
                    .expect("dex1 deployment must be present!"),
                &self.dex1,
            ),
            pairs,
        }
    }

    pub fn build_dep_resolver(&self) -> DefaultCellDepResolver {
        let client = CkbRpcClient::new(&self.ckb_rpc);
        let genesis_block = client.get_block_by_number(0.into()).expect("rpc").unwrap();
        let mut resolver = DefaultCellDepResolver::from_genesis(&BlockView::from(genesis_block))
            .expect("parse genesis block");
        for (_hash, (name, full_script)) in self.known_script_map() {
            resolver.insert(
                ScriptId::new(
                    full_script.script.code_hash,
                    full_script.script.hash_type.into(),
                ),
                full_script.cell_dep.into(),
                name,
            );
        }
        resolver
    }

    pub fn udt_map(&self) -> HashMap<H256, (String, FullScript)> {
        let mut result = HashMap::default();
        {
            let udt_script: packed::Script = self.udt.script.clone().into();
            for test_udt in self.test_udts.iter() {
                let owner_args: JsonBytes = test_udt.owner_lock_hash.clone();
                let s = udt_script
                    .clone()
                    .as_builder()
                    .args(owner_args.clone().into())
                    .build();
                result.insert(
                    s.calc_script_hash().unpack(),
                    (test_udt.name.clone(), replace_args(owner_args, &self.udt)),
                );
            }
        }
        result
    }

    pub fn known_script_map(&self) -> HashMap<H256, (String, FullScript)> {
        let mut result = HashMap::default();
        {
            let omnilock_script: packed::Script = self.omnilock.script.clone().into();
            let args = JsonBytes::from_vec(vec![0u8; 22]);
            let s = omnilock_script
                .as_builder()
                .args(args.clone().into())
                .build();
            result.insert(
                s.calc_script_hash().unpack(),
                (
                    "bare omnilock".to_string(),
                    replace_args(args, &self.omnilock),
                ),
            );
        }
        {
            let dex1_script: packed::Script = self.dex1.script.clone().into();
            let args = JsonBytes::from_vec(vec![0u8; 32]);
            let s = dex1_script.as_builder().args(args.clone().into()).build();
            result.insert(
                s.calc_script_hash().unpack(),
                ("bare dex1".to_string(), replace_args(args, &self.dex1)),
            );
        }
        {
            let always_success_script: packed::Script = self.always_success.script.clone().into();
            result.insert(
                always_success_script.calc_script_hash().unpack(),
                ("always success".to_string(), self.always_success.clone()),
            );
        }

        result.extend(self.udt_map());
        result
    }
}
