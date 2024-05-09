#![no_std]
#![cfg_attr(not(test), no_main)]

#[cfg(test)]
extern crate alloc;

#[cfg(not(test))]
use ckb_std::default_alloc;
#[cfg(not(test))]
ckb_std::entry!(program_entry);
#[cfg(not(test))]
default_alloc!();

pub use ckb_gen_types::packed as blockchain;
#[allow(dead_code)]
mod schema;

use ckb_gen_types::prelude::Unpack;
use ckb_gen_types_cobuild::prelude::Unpack as CobuildUnpack;
use ckb_std::{ckb_constants::Source, error::SysError, high_level};
use ckb_transaction_cobuild::{fetch_message, parse_otx_structure, Error as CobuildError};
use ethnum::U256;
use molecule::prelude::Entity;

pub fn program_entry() -> i8 {
    let current_script = high_level::load_script().expect("loading script");
    if current_script.args().len() == 96 {
        // Current script is used as the lock script of an order cell, there are 2 ways
        // to unlock it:
        // 1. When the order cell is processed by the dex as a normal order;
        {
            let mut i = 0;
            loop {
                match high_level::load_cell_type(i, Source::Input) {
                    Ok(Some(t)) => {
                        if t.code_hash() == current_script.code_hash()
                            && t.hash_type() == current_script.hash_type()
                            && t.args().raw_data() == current_script.args().raw_data().slice(0..32)
                        {
                            return 0;
                        }
                    }
                    Ok(None) => (),
                    Err(SysError::IndexOutOfBound) => {
                        break;
                    }
                    Err(e) => panic!("Error reading input type: {:?}", e),
                }
                i += 1;
            }
        }
        // 2. By owner locks, in this case the original user cancels the order
        {
            let mut i = 0;
            loop {
                match high_level::load_cell_lock_hash(i, Source::Input) {
                    Ok(lock_hash) => {
                        if lock_hash == *current_script.args().raw_data().slice(32..64) {
                            return 0;
                        }
                    }
                    Err(SysError::IndexOutOfBound) => {
                        break;
                    }
                    Err(e) => panic!("Error reading input lock hash: {:?}", e),
                }
                i += 1;
            }
        }
    }
    assert_eq!(
        current_script.args().len(),
        32,
        "Current script has invalid length of args!"
    );

    // Doing this first allows us to save one extra loading of transaction structure.
    let (otx_iter, tx) = match parse_otx_structure() {
        Ok((iter, tx)) => (
            Some(iter),
            blockchain::Transaction::new_unchecked(tx.as_bytes()),
        ),
        Err(CobuildError::WrongOtxStart) => (
            None,
            high_level::load_transaction().expect("loading transaction"),
        ),
        Err(e) => panic!("Parsing otx structure error: {:?}", e),
    };
    // Input cells can only be iterated via syscalls
    let input_entity_index = {
        let mut found_index = None;
        let mut i = 0;
        loop {
            match high_level::load_cell_type(i, Source::Input) {
                Ok(Some(t)) => {
                    if t == current_script {
                        assert!(
                            found_index.is_none(),
                            "More than one input cell uses AMM entity script!"
                        );
                        found_index = Some(i);
                    }
                }
                Ok(None) => (),
                Err(SysError::IndexOutOfBound) => break,
                Err(e) => panic!("Error occurs when loading input cells: {:?}", e),
            }
            i += 1;
        }
        found_index
    };
    // For simplicity, we disallow termination
    assert!(
        tx.raw()
            .outputs()
            .into_iter()
            .filter(|cell_output| cell_output
                .type_()
                .to_opt()
                .map(|t| t == current_script)
                .unwrap_or(false))
            .count()
            == 1,
        "Only one output cell uses AMM entity type script!"
    );
    let output_entity_index = tx
        .raw()
        .outputs()
        .into_iter()
        .enumerate()
        .filter(|(_, cell_output)| {
            cell_output
                .type_()
                .to_opt()
                .map(|t| t == current_script)
                .unwrap_or(false)
        })
        .map(|(i, _)| i)
        .next()
        .unwrap();
    // Entity cell has no data
    assert!(tx
        .raw()
        .outputs_data()
        .get(output_entity_index)
        .unwrap()
        .is_empty());
    if input_entity_index.is_none() {
        // Initial creation mode
        assert!(otx_iter.is_none());

        let mut blake2b = blake2b_ref::Blake2bBuilder::new(32)
            .personal(b"ckb-default-hash")
            .build();
        blake2b.update(tx.raw().inputs().get(0).unwrap().as_slice());
        blake2b.update(&(output_entity_index as u64).to_le_bytes());
        let mut ret = [0u8; 32];
        blake2b.finalize(&mut ret);

        assert_eq!(ret, *current_script.args().raw_data().slice(0..32));
    }
    let input_entity_index = input_entity_index.unwrap();
    // No one can change the lock of entity cell
    assert_eq!(
        high_level::load_cell_lock(input_entity_index, Source::Input).expect("load entity lock"),
        tx.raw().outputs().get(output_entity_index).unwrap().lock(),
    );
    let input_entity_header = high_level::load_header(input_entity_index, Source::Input)
        .expect("load input entity header");

    let mut context = Context {
        tx,
        current_script,
        input_entity_header,
        current_input_index: input_entity_index + 1,
        current_output_index: output_entity_index + 1,
        otx_input_start: usize::max_value(),
        otx_input_end: 0,
        otx_output_start: usize::max_value(),
        otx_output_end: 0,
    };
    let current_script_hash = high_level::load_script_hash().expect("load script hash");
    if let Some(otxs) = otx_iter {
        for otx in otxs {
            let input_cells: u32 = otx.otx.input_cells().unpack();
            let output_cells: u32 = otx.otx.output_cells().unpack();

            // We will need to keep track of otx cell ranges, so as to make sure
            // Dex1 related cells are not included in any OTX
            context.otx_input_start = core::cmp::min(context.otx_input_start, otx.input_cell_start);
            context.otx_input_end = core::cmp::max(
                context.otx_input_end,
                otx.input_cell_start + input_cells as usize,
            );
            context.otx_output_start =
                core::cmp::min(context.otx_output_start, otx.output_cell_start);
            context.otx_output_end = core::cmp::max(
                context.otx_output_end,
                otx.output_cell_start + output_cells as usize,
            );

            // Now we will locate OTXs that actually contain orderbook actions
            let action = match otx
                .otx
                .message()
                .actions()
                .into_iter()
                .find(|action| action.script_hash().as_slice() == current_script_hash)
            {
                Some(action) => schema::Dex1Action::from_slice(&action.data().raw_data())
                    .expect("parsing action data"),
                None => continue,
            };

            for order in action.orders() {
                context.process(order);
            }
        }
    }

    // Freestanding cells can also provide orders
    if let Some(message) = fetch_message().expect("fetch cobuild message") {
        if let Some(action) = message
            .actions()
            .into_iter()
            .find(|action| action.script_hash().as_slice() == current_script_hash)
        {
            let action = schema::Dex1Action::from_slice(&action.data().raw_data())
                .expect("parsing action data");

            for order in action.orders() {
                let order_hash = hash_order(&order);

                let next_lock =
                    high_level::load_cell_lock(context.current_input_index, Source::Input)
                        .expect("load freestanding cell lock");
                assert_eq!(context.current_script.code_hash(), next_lock.code_hash(),);
                assert_eq!(context.current_script.hash_type(), next_lock.hash_type(),);
                assert_eq!(context.current_script.args().len(), 96,);
                assert_eq!(
                    context.current_script.args().raw_data(),
                    next_lock.args().raw_data().slice(0..32),
                );
                assert_eq!(&order_hash, &*next_lock.args().raw_data().slice(64..96));

                context.process(order);
                context.current_input_index += 1;
            }
        }
    }

    // Validate that dex1 related cells do not belong to part of OTXs
    if context.otx_input_start < context.otx_input_end {
        assert!(
            input_entity_index >= context.otx_input_end
                || context.current_input_index <= context.otx_input_start
        );
    }
    if context.otx_output_start < context.otx_output_end {
        assert!(
            output_entity_index >= context.otx_output_end
                || context.current_output_index <= context.otx_output_start
        );
    }

    0
}

struct Context {
    tx: blockchain::Transaction,
    current_script: blockchain::Script,
    input_entity_header: blockchain::Header,

    current_input_index: usize,
    current_output_index: usize,
    otx_input_start: usize,
    otx_input_end: usize,
    otx_output_start: usize,
    otx_output_end: usize,
}

impl Context {
    fn process(&mut self, order: schema::Order) {
        let order_hash = hash_order(&order);
        match order.to_enum() {
            schema::OrderUnion::LimitOrder(o) => self.validate_limit_order(o, order_hash),
            schema::OrderUnion::LimitOrderWithDeadline(o) => {
                // TODO: for now, we treat deadline as an absolute block number,
                // but it is always possible to expand this to support more variations,
                // such as epoch or full featured since value
                let deadline_block: u64 = o.deadline().unpack();
                let input_block: u64 = self.input_entity_header.raw().number().unpack();
                assert!(input_block < deadline_block);
                self.validate_limit_order(o.order(), order_hash);
            }
            schema::OrderUnion::MarketOrder(o) => {
                self.validate_market_order(o);
            }
            schema::OrderUnion::MarketOrderWithMinimumAsk(o) => {
                let ask_amount = self.validate_market_order(o.order());
                let minimum_ask: u128 = o.minimum_ask().unpack();
                assert!(ask_amount >= minimum_ask);
            }
        }
    }

    fn validate_limit_order(&mut self, order: schema::LimitOrder, order_hash: [u8; 32]) {
        let bid_amount: u128 = order.bid_amount().unpack();
        let ask_amount: u128 = order.ask_amount().unpack();

        let freestanding_args = self.freestanding_script_args(&order_hash, &order.recipient());
        // Regardless of locks, next cell must use the asked UDT token type
        assert_eq!(
            high_level::load_cell_type_hash(self.current_output_index, Source::Output)
                .expect("load pay cell type hash")
                .unwrap(),
            *order.ask_token().raw_data()
        );
        let next_lock = high_level::load_cell_lock(self.current_output_index, Source::Output)
            .expect("load pay cell lock");
        if next_lock.code_hash() == self.current_script.code_hash()
            && next_lock.hash_type() == self.current_script.hash_type()
            && *next_lock.args().raw_data() == freestanding_args
        {
            // Freestanding cell available
            let freestanding_amount = self.output_cell_udt_amount(self.current_output_index);
            if freestanding_amount < bid_amount {
                // Partial filled
                let freestanding_ckbytes = self.output_cell_ckbytes(self.current_output_index);
                assert_eq!(
                    high_level::load_cell_lock_hash(self.current_output_index + 1, Source::Output)
                        .expect("load pay cell lock hash"),
                    *order.recipient().raw_data()
                );
                assert_eq!(
                    high_level::load_cell_type_hash(self.current_output_index + 1, Source::Output)
                        .expect("load pay cell type hash")
                        .unwrap(),
                    *order.ask_token().raw_data()
                );
                let actual_bid_amount = bid_amount - freestanding_amount;
                let actual_paid_amount = self.output_cell_udt_amount(self.current_output_index + 1);
                // For simplicity I picked this formula, but you might want to tweak it.
                let required_paid_amount = (U256::from(actual_bid_amount) * U256::from(ask_amount)
                    / U256::from(bid_amount))
                .as_u128();
                assert!(actual_paid_amount >= required_paid_amount);
                let payback_ckbytes = self.output_cell_ckbytes(self.current_output_index + 1);
                assert!(
                    freestanding_ckbytes
                        .checked_add(payback_ckbytes)
                        .expect("overflow")
                        >= order.claimed_ckbytes().unpack()
                );
                self.current_output_index += 2;
            } else {
                // Fully filled freestanding cell
                // UDT amount kept in the freestanding cell has been asserted above.
                // All we need to do here is CKBytes comparison
                assert!(
                    self.output_cell_ckbytes(self.current_output_index)
                        >= order.claimed_ckbytes().unpack()
                );
                self.current_output_index += 1;
            }
        } else {
            // Properly filled cell
            assert_eq!(
                high_level::load_cell_lock_hash(self.current_output_index, Source::Output)
                    .expect("load pay cell lock hash"),
                *order.recipient().raw_data()
            );
            let actual_amount = self.output_cell_udt_amount(self.current_output_index);
            assert_eq!(actual_amount, ask_amount);
            assert!(
                self.output_cell_ckbytes(self.current_output_index)
                    >= order.claimed_ckbytes().unpack()
            );
            self.current_output_index += 1;
        }
    }

    fn validate_market_order(&mut self, order: schema::MarketOrder) -> u128 {
        // A market order must be fully fulfilled when included on chain, there is no
        // partial filling of market order.
        // TODO: anything we can do to mitigate market order censorship?
        assert_eq!(
            high_level::load_cell_type_hash(self.current_output_index, Source::Output)
                .expect("load pay cell type hash")
                .unwrap(),
            *order.ask_token().raw_data()
        );
        assert_eq!(
            high_level::load_cell_lock_hash(self.current_output_index, Source::Output)
                .expect("load pay cell lock hash"),
            *order.recipient().raw_data()
        );
        assert!(
            self.output_cell_ckbytes(self.current_output_index) >= order.claimed_ckbytes().unpack()
        );
        let actual_amount = self.output_cell_udt_amount(self.current_output_index);
        self.current_output_index += 1;
        actual_amount
    }

    fn output_cell_ckbytes(&self, index: usize) -> u64 {
        self.tx
            .raw()
            .outputs()
            .get(index)
            .unwrap()
            .capacity()
            .unpack()
    }

    fn output_cell_udt_amount(&self, index: usize) -> u128 {
        let mut data = [0u8; 16];
        let full_data = self.tx.raw().outputs_data().get(index).unwrap().raw_data();
        data.copy_from_slice(&full_data[0..16]);
        u128::from_le_bytes(data)
    }

    fn freestanding_script_args(
        &self,
        order_hash: &[u8; 32],
        recipient: &blockchain::Byte32,
    ) -> [u8; 96] {
        let mut r = [0u8; 96];
        r[0..32].copy_from_slice(&self.current_script.args().raw_data().slice(0..32));
        r[32..64].copy_from_slice(&recipient.raw_data());
        r[64..96].copy_from_slice(order_hash);
        r
    }
}

fn hash_order(order: &schema::Order) -> [u8; 32] {
    let mut blake = blake2b_ref::Blake2bBuilder::new(32)
        .personal(b"ckb-default-hash")
        .build();
    blake.update(order.as_slice());
    let mut hash = [0u8; 32];
    blake.finalize(&mut hash);
    hash
}
