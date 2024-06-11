use anyhow::Result;
use ckb_types::packed::{OutPoint, Transaction};
use core::hash::Hash;
use std::collections::HashSet;

pub trait Value {
    fn transaction(&self) -> &Transaction;

    fn spent(&self, out_points: &HashSet<OutPoint>) -> bool {
        self.transaction()
            .raw()
            .inputs()
            .into_iter()
            .any(|cell_input| out_points.contains(&cell_input.previous_output()))
    }
}

pub trait ReduceSource<K: Eq + Hash, V: Value> {
    fn otxs<'a>(&'a self, key: K) -> impl Iterator<Item = V>
    where
        V: 'a;
}

pub trait Assembler {
    type Tx;
    type Key: Eq + Hash;
    type Order: Ord;
    type Value: Value;

    fn map(&self, tx: Self::Tx) -> Result<(Self::Key, Self::Order, Self::Value)>;

    fn reduce<S>(
        &self,
        base_tx: Self::Tx,
        keys: Vec<Self::Key>,
        source: &S,
    ) -> Result<Vec<Transaction>>
    where
        S: ReduceSource<Self::Key, Self::Value>;
}
