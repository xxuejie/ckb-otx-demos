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
use ckb_transaction_cobuild::{parse_otx_structure, Error as CobuildError};
use ethnum::U256;
use molecule::prelude::Entity;

pub fn program_entry() -> i8 {
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
    // 1. Locate AMM entity cells, extract meta infos
    let current_script = high_level::load_script().expect("loading script");
    assert_eq!(
        current_script.args().len(),
        32,
        "Current script has invalid length of args!"
    );
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
            <= 1,
        "More than one output cell uses AMM entity type script!"
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
        .next();
    assert!(
        input_entity_index.is_some() || output_entity_index.is_some(),
        "An entity cell must exist as input or output"
    );
    if input_entity_index.is_none() {
        // Validate initial creation mode then exit
        assert!(otx_iter.is_none());
        let output_entity_index = output_entity_index.unwrap();
        let output_entity = schema::AmmEntity::from_slice(
            &tx.raw()
                .outputs_data()
                .get_unchecked(output_entity_index)
                .raw_data(),
        )
        .expect("parsing AMM output entity");
        // Validate tracked assets
        assert_eq!(
            current_script,
            tx.raw()
                .outputs()
                .get(output_entity_index + 1)
                .unwrap()
                .lock(),
        );
        assert_eq!(
            output_entity.asset1_hash().as_slice(),
            high_level::load_cell_type_hash(output_entity_index + 1, Source::Output)
                .expect("load AMM asset 1 cell type hash")
                .unwrap()
        );
        assert_eq!(
            output_entity.asset1_amount().as_slice(),
            &tx.raw()
                .outputs_data()
                .get(output_entity_index + 1)
                .unwrap()
                .raw_data()[0..16],
        );
        assert_eq!(
            current_script,
            tx.raw()
                .outputs()
                .get(output_entity_index + 2)
                .unwrap()
                .lock(),
        );
        assert_eq!(
            output_entity.asset2_hash().as_slice(),
            high_level::load_cell_type_hash(output_entity_index + 2, Source::Output)
                .expect("load AMM asset 2 cell type hash")
                .unwrap()
        );
        assert_eq!(
            output_entity.asset2_amount().as_slice(),
            &tx.raw()
                .outputs_data()
                .get(output_entity_index + 2)
                .unwrap()
                .raw_data()[0..16],
        );
        return 0;
    }
    let input_entity_index = input_entity_index.unwrap();
    let input_entity = schema::AmmEntity::from_slice(
        &high_level::load_cell_data(input_entity_index, Source::Input)
            .expect("load AMM input entity data"),
    )
    .expect("parsing AMM input entity");
    let management_lock_enabled = {
        let mut result = false;
        let mut i = 0;
        loop {
            match high_level::load_cell_lock_hash(i, Source::Input) {
                Ok(lock_hash) => {
                    if lock_hash == input_entity.management_lock().as_slice() {
                        result = true;
                        break;
                    }
                }
                Err(SysError::IndexOutOfBound) => {
                    break;
                }
                Err(e) => panic!("Error reading input lock: {:?}", e),
            }
            i += 1;
        }
        result
    };
    if output_entity_index.is_none() {
        // Validate management mode then exit
        // NOTE: ideally one would care about the on-chain tokens when an AMM entity
        // cell is destroyed, some might want to forbade this action. For simplicity
        // our contract here does not spend too much logic on this part. Though one
        // is always free to alter the behavior here.
        assert!(otx_iter.is_none());
        assert!(
            management_lock_enabled,
            "Management mode lock is required when AMM output entity is destroyed!"
        );
        return 0;
    }
    let output_entity_index = output_entity_index.unwrap();
    let output_entity = schema::AmmEntity::from_slice(
        &tx.raw()
            .outputs_data()
            .get_unchecked(output_entity_index)
            .raw_data(),
    )
    .expect("parsing AMM output entity");
    // In normal mode, both input and output AMM entities must exist
    assert_eq!(input_entity.asset1_hash(), output_entity.asset1_hash());
    assert_eq!(input_entity.asset2_hash(), output_entity.asset2_hash());
    assert_eq!(
        input_entity.management_lock(),
        output_entity.management_lock()
    );
    let target_asset1_amount = output_entity.asset1_amount().unpack();
    let target_asset2_amount = output_entity.asset2_amount().unpack();
    let mut current_total_asset1_amount = input_entity.asset1_amount().unpack();
    let mut current_total_asset2_amount = input_entity.asset2_amount().unpack();
    let mut current_input_index = input_entity_index + 1;
    let mut current_output_index = output_entity_index + 1;
    let mut otx_input_start = usize::max_value();
    let mut otx_input_end = 0;
    let mut otx_output_start = usize::max_value();
    let mut otx_output_end = 0;
    // 2. Iterate and process each OTXs that do AMM operations, updating meta infos.
    // Also validate correct tokens are transferred to each AMM OTX properly.
    if let Some(otxs) = otx_iter {
        let current_script_hash = high_level::load_script_hash().expect("load script hash");
        for otx in otxs {
            let input_cells: u32 = otx.otx.input_cells().unpack();
            let output_cells: u32 = otx.otx.output_cells().unpack();

            // We will need to keep track of otx cell ranges, so as to make sure
            // AMM entity cells are not included in any OTX
            otx_input_start = core::cmp::min(otx_input_start, otx.input_cell_start);
            otx_input_end =
                core::cmp::max(otx_input_end, otx.input_cell_start + input_cells as usize);
            otx_output_start = core::cmp::min(otx_output_start, otx.output_cell_start);
            otx_output_end = core::cmp::max(
                otx_output_end,
                otx.output_cell_start + output_cells as usize,
            );

            // Now we will locate OTXs that actually contain AMM actions
            let action = match otx
                .otx
                .message()
                .actions()
                .into_iter()
                .find(|action| action.script_hash().as_slice() == current_script_hash)
            {
                Some(action) => action,
                None => continue,
            };
            // Now current OTX does contain an AMM order, we will need to deduce 2 things from
            // current transction:
            // * The total amount of assets bidded
            // * The CKBytes set aside for returned assets
            // For this simple demo, we require that order submitter must provide enough
            // CKBytes for the returned assets, however it's up to you to adjust this logic.
            let mut otx_ckbytes: u64 = 0;
            let mut otx_asset1_amount: u128 = 0;
            let mut otx_asset2_amount: u128 = 0;
            for i in 0..input_cells {
                otx_ckbytes += high_level::load_cell_capacity(
                    otx.input_cell_start + i as usize,
                    Source::Input,
                )
                .expect("load cell capacity");

                if let Some(hash) = high_level::load_cell_type_hash(
                    otx.input_cell_start + i as usize,
                    Source::Input,
                )
                .expect("load cell type hash")
                {
                    if hash == input_entity.asset1_hash().as_slice() {
                        let amount = {
                            let mut data = [0u8; 16];
                            let full_data = high_level::load_cell_data(
                                otx.input_cell_start + i as usize,
                                Source::Input,
                            )
                            .expect("load cell data");
                            data.copy_from_slice(&full_data[0..16]);
                            u128::from_le_bytes(data)
                        };
                        otx_asset1_amount += amount;
                    } else if hash == input_entity.asset2_hash().as_slice() {
                        let amount = {
                            let mut data = [0u8; 16];
                            let full_data = high_level::load_cell_data(
                                otx.input_cell_start + i as usize,
                                Source::Input,
                            )
                            .expect("load cell data");
                            data.copy_from_slice(&full_data[0..16]);
                            u128::from_le_bytes(data)
                        };
                        otx_asset2_amount += amount;
                    }
                }
            }
            for i in 0..output_cells {
                let current_cell_ckbytes = tx
                    .raw()
                    .outputs()
                    .get(otx.input_cell_start + i as usize)
                    .unwrap()
                    .capacity()
                    .unpack();
                assert!(otx_ckbytes >= current_cell_ckbytes);
                otx_ckbytes -= current_cell_ckbytes;

                if let Some(hash) = high_level::load_cell_type_hash(
                    otx.input_cell_start + i as usize,
                    Source::Output,
                )
                .expect("load cell type hash")
                {
                    if hash == input_entity.asset1_hash().as_slice() {
                        let amount = {
                            let mut data = [0u8; 16];
                            let full_data = tx
                                .raw()
                                .outputs_data()
                                .get(otx.input_cell_start + i as usize)
                                .unwrap()
                                .raw_data();
                            data.copy_from_slice(&full_data[0..16]);
                            u128::from_le_bytes(data)
                        };
                        assert!(otx_asset1_amount >= amount);
                        otx_asset1_amount -= amount;
                    } else if hash == input_entity.asset2_hash().as_slice() {
                        let amount = {
                            let mut data = [0u8; 16];
                            let full_data = tx
                                .raw()
                                .outputs_data()
                                .get(otx.input_cell_start + i as usize)
                                .unwrap()
                                .raw_data();
                            data.copy_from_slice(&full_data[0..16]);
                            u128::from_le_bytes(data)
                        };
                        assert!(otx_asset2_amount >= amount);
                        otx_asset2_amount -= amount;
                    }
                }
            }
            assert!(
                otx_asset1_amount > 0 || otx_asset2_amount > 0,
                "There must be a bidder asset!"
            );
            assert!(
                otx_asset1_amount == 0 || otx_asset2_amount == 0,
                "Both assets cannot be present at the same time!"
            );
            // X * Y = K
            let (test_amount, test_asset_hash) = if otx_asset1_amount > 0 {
                let k = U256::from(current_total_asset1_amount)
                    * U256::from(current_total_asset2_amount);
                let new_x = U256::from(current_total_asset1_amount) + U256::from(otx_asset1_amount);
                let new_y = k / new_x;
                assert!(U256::from(otx_asset2_amount) >= new_y);
                current_total_asset1_amount = new_x.as_u128();
                current_total_asset2_amount = new_y.as_u128();
                (
                    otx_asset2_amount - new_y.as_u128(),
                    input_entity.asset2_hash(),
                )
            } else {
                let k = U256::from(current_total_asset1_amount)
                    * U256::from(current_total_asset2_amount);
                let new_y = U256::from(current_total_asset2_amount) + U256::from(otx_asset2_amount);
                let new_x = k / new_y;
                assert!(U256::from(otx_asset1_amount) >= new_x);
                current_total_asset1_amount = new_x.as_u128();
                current_total_asset2_amount = new_y.as_u128();
                (
                    otx_asset1_amount - new_x.as_u128(),
                    input_entity.asset1_hash(),
                )
            };
            // TODO: optionally, you can assert the script_info_hash included in the action.
            let order =
                schema::Order::from_slice(&action.data().raw_data()).expect("parsing order");
            let minimum_ask: u128 = order.minimum_ask().unpack();
            assert!(test_amount >= minimum_ask);
            // One new output cell must be created for current OTX order
            assert_eq!(
                otx_ckbytes,
                tx.raw()
                    .outputs()
                    .get(current_output_index)
                    .unwrap()
                    .capacity()
                    .unpack()
            );
            assert_eq!(
                order.recipient(),
                tx.raw().outputs().get(current_output_index).unwrap().lock()
            );
            assert_eq!(
                test_amount.to_le_bytes(),
                tx.raw()
                    .outputs_data()
                    .get(current_output_index)
                    .unwrap()
                    .raw_data()[0..16]
            );
            assert_eq!(
                test_asset_hash.as_slice(),
                high_level::load_cell_type_hash(current_output_index, Source::Output)
                    .expect("load cell type hash")
                    .unwrap()
            );
            current_output_index += 1;
        }

        // 3. Validate that AMM assets are updated correctly
        assert_eq!(target_asset1_amount, current_total_asset1_amount);
        assert_eq!(target_asset2_amount, current_total_asset2_amount);
    } else {
        // Management lock allows altering liquidity, though again, this is one more thing
        // that some might have different opinions and would want to remove.
        if !management_lock_enabled {
            assert_eq!(target_asset1_amount, current_total_asset1_amount);
            assert_eq!(target_asset2_amount, current_total_asset2_amount);
        }
    }
    // 4. Validate that AMM asset cells are updated correctly
    assert_eq!(
        current_script,
        high_level::load_cell_lock(current_input_index, Source::Input)
            .expect("load AMM asset 1 cell lock")
    );
    assert_eq!(
        output_entity.asset1_hash().as_slice(),
        high_level::load_cell_type_hash(current_input_index, Source::Input)
            .expect("load AMM asset 1 cell type hash")
            .unwrap()
    );
    assert_eq!(
        output_entity.asset1_amount().as_slice(),
        &high_level::load_cell_data(current_input_index, Source::Input)
            .expect("load AMM asset 1 cell data")[0..16]
    );
    assert_eq!(
        current_script,
        high_level::load_cell_lock(current_input_index + 1, Source::Input)
            .expect("load AMM asset 2 cell lock")
    );
    assert_eq!(
        output_entity.asset2_hash().as_slice(),
        high_level::load_cell_type_hash(current_input_index + 1, Source::Input)
            .expect("load AMM asset 2 cell type hash")
            .unwrap()
    );
    assert_eq!(
        output_entity.asset2_amount().as_slice(),
        &high_level::load_cell_data(current_input_index + 1, Source::Input)
            .expect("load AMM asset 2 cell data")[0..16]
    );
    current_input_index += 2;
    assert_eq!(
        current_script,
        tx.raw().outputs().get(current_output_index).unwrap().lock(),
    );
    assert_eq!(
        output_entity.asset1_hash().as_slice(),
        high_level::load_cell_type_hash(current_output_index, Source::Output)
            .expect("load AMM asset 1 cell type hash")
            .unwrap()
    );
    assert_eq!(
        output_entity.asset1_amount().as_slice(),
        &tx.raw()
            .outputs_data()
            .get(current_output_index)
            .unwrap()
            .raw_data()[0..16],
    );
    assert_eq!(
        current_script,
        tx.raw()
            .outputs()
            .get(current_output_index + 1)
            .unwrap()
            .lock(),
    );
    assert_eq!(
        output_entity.asset2_hash().as_slice(),
        high_level::load_cell_type_hash(current_output_index + 1, Source::Output)
            .expect("load AMM asset 2 cell type hash")
            .unwrap()
    );
    assert_eq!(
        output_entity.asset2_amount().as_slice(),
        &tx.raw()
            .outputs_data()
            .get(current_output_index + 1)
            .unwrap()
            .raw_data()[0..16],
    );
    current_output_index += 2;
    // 5. Validate that AMM cells do not belong to part of OTXs
    if otx_input_start < otx_input_end {
        assert!(input_entity_index >= otx_input_end || current_input_index <= otx_input_start);
    }
    if otx_output_start < otx_output_end {
        assert!(output_entity_index >= otx_output_end || current_output_index <= otx_output_start);
    }

    0
}
