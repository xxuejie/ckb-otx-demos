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

pub trait MapEmitter<K: Eq + Hash, O: Ord, V: Value> {
    fn emit(&mut self, key: K, order: O, value: V) -> Result<()>;
}

pub trait ReduceEmitter<K: Eq + Hash, O: Ord, V: Value, P>: MapEmitter<K, O, V> {
    fn reject_otx(&mut self, otx: Transaction) -> Result<()>;
    fn emit_tx(&mut self, tx: Transaction, value: P) -> Result<()>;
}

pub trait Assembler {
    type Otx;
    type BaseTx;
    type Key: Eq + Hash;
    type Order: Ord;
    type Value: Value;
    type PostValue;

    fn map<E>(&self, tx: Self::Otx, emitter: &mut E) -> Result<()>
    where
        E: MapEmitter<Self::Key, Self::Order, Self::Value>;

    fn reduce<E, S>(
        &self,
        base_tx: Self::BaseTx,
        key: Self::Key,
        emitter: &mut E,
        source: &S,
    ) -> Result<()>
    where
        E: ReduceEmitter<Self::Key, Self::Order, Self::Value, Self::PostValue>,
        S: ReduceSource<Self::Key, Self::Value>;

    fn postprocess<E>(
        &self,
        tx: Transaction,
        value: Self::PostValue,
        emitter: &mut E,
    ) -> Result<()>
    where
        E: MapEmitter<Self::Key, Self::Order, Self::Value>;
}
