use ckb_jsonrpc_types::{CellDep, Script};
use ckb_types::packed;
use serde::{Deserialize, Serialize};

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
    pub dex1_script: FullScript,
    pub pairs: Vec<TradingPair>,
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
