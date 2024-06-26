mod utils;

use crate::utils::{
    build_config, build_genesis_sighash_lock, build_lock_from_cli, build_omnilock_lock,
    build_private_key, build_recipient_script, print_script, save_tx, to_tx, wait_for_tx,
};
use ckb_hash::{new_blake2b, Blake2bBuilder};
use ckb_jsonrpc_types::{self as ckbrpc, OutputsValidator, Status};
use ckb_sdk::{
    constants::{SIGHASH_TYPE_HASH, TYPE_ID_CODE_HASH},
    rpc::{ckb_indexer::SearchMode, CkbRpcClient},
    traits::{
        CellCollector, CellDepResolver, CellQueryOptions, DefaultCellCollector,
        DefaultCellDepResolver, DefaultHeaderDepResolver, DefaultTransactionDependencyProvider,
        MaturityOption, PrimaryScriptType, QueryOrder, SecpCkbRawKeySigner, Signer,
        ValueRangeOption,
    },
    tx_builder::{
        balance_tx_capacity, fill_placeholder_witnesses,
        transfer::CapacityTransferBuilder,
        udt::{UdtIssueBuilder, UdtTargetReceiver, UdtType},
        unlock_tx, CapacityBalancer, TransferAction, TxBuilder,
    },
    types::omni_lock::OmniLockWitnessLock,
    unlock::{
        OmniLockConfig, OmniLockScriptSigner, OmniLockUnlocker, OmniUnlockMode, ScriptUnlocker,
        SecpSighashUnlocker,
    },
    util::blake160,
    HumanCapacity, ScriptId, SECP256K1,
};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, Capacity, ScriptHashType, TransactionBuilder},
    packed::{self, CellInput, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
    H256,
};
use clap::{arg, command, value_parser, ArgAction, ArgMatches, Command};
use dex1_assembler::{
    config::FullScript,
    schemas::{basic, dex1, top_level},
};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

ckb_sdk::jsonrpc!(pub struct OtxRpcClient {
    pub fn submit_open_transaction(&self, tx: ckb_jsonrpc_types::Transaction) -> ();
    pub fn cancel_open_transaction(&self, tx: ckb_jsonrpc_types::OutPoint) -> ();
});

fn main() {
    flexi_logger::Logger::try_with_env()
        .unwrap()
        .start()
        .unwrap();

    let matches = command!()
        .arg(
            arg!(
                -f --from <FILE> "Wallet file for from address"
            )
            .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(
                -c --config <CONFIG> "Config file path"
            )
            .value_parser(value_parser!(PathBuf)),
        )
        .arg(arg!(--tx_file <TX_FILE> "TX file to write").value_parser(value_parser!(PathBuf)))
        .subcommand(
            Command::new("deploy")
                .about("deploy new script in a naive way")
                .arg(arg!(
                    -r --rpc <RPC> "CKB RPC address"
                ))
                .arg(
                    arg!(
                        -b --binary <BINARY> "Binary to deploy"
                    )
                    .required(true)
                    .value_parser(value_parser!(PathBuf)),
                ),
        )
        .subcommand(Command::new("deploy-dex1").about("Deploy a new dex1 cell"))
        .subcommand(
            Command::new("create-otx")
                .about("create and (optionally) send new otx")
                .arg(
                    arg!(--bid_token <BID_TOKEN> "Bid token script hash")
                        .required(true)
                        .value_parser(value_parser!(H256)),
                )
                .arg(
                    arg!(--bid_amount <BID_AMOUNT> "Bid amount")
                        .required(true)
                        .value_parser(value_parser!(u128)),
                )
                .arg(
                    arg!(--ask_token <ASK_TOKEN> "Ask token script hash")
                        .required(true)
                        .value_parser(value_parser!(H256)),
                )
                .arg(
                    arg!(--ask_amount <ASK_AMOUNT> "Ask amount")
                        .required(true)
                        .value_parser(value_parser!(u128)),
                )
                .arg(
                    arg!(--claimed_ckbytes <CLAIMED_CKBYTES> "Claimed ckbytes")
                        .value_parser(value_parser!(HumanCapacity)),
                )
                .arg(
                    arg!(--include_outpoint_hash <INCLUDE_OUTPOINT_HASH> "Tx hash of outpoint to include")
                        .value_parser(value_parser!(H256)),
                )
                .arg(
                    arg!(--include_outpoint_index <INCLUDE_OUTPOINT_INDEX> "Index of outpoint to include")
                        .value_parser(value_parser!(u32)),
                )
                .arg(arg!(--send "Send to CKB client").action(ArgAction::SetTrue)),
        )
        .subcommand(Command::new("cancel-otx").about("cancel an otx"))
        .subcommand(
            Command::new("explain-tx").about("provide an insight into loaded tx"),
        )
        .subcommand(
            Command::new("known-scripts").about("list all known scripts (and their hashes)"),
        )
        .subcommand(
            Command::new("script-hashes").about("script hashes related to current wallet account"),
        )
        .subcommand(
            Command::new("balance-ckb")
                .about("fetch balance of ckb")
                .arg(
                    arg!(--lock_type <LOCK_TYPE> "Lock type")
                        .value_parser(["omnilock", "genesis-sighash"]),
                ),
        )
        .subcommand(
            Command::new("balance-udt")
                .about("fetch balance of udt")
                .arg(
                    arg!(--lock_type <LOCK_TYPE> "Lock type")
                        .value_parser(["omnilock", "genesis-sighash"]),
                )
                .arg(
                    arg!(--token <TOKEN> "UDT token script hash")
                        .required(true)
                        .value_parser(value_parser!(H256)),
                ),
        )
        .subcommand(
            Command::new("transfer-ckb")
                .about("transfer ckb")
                .about("Transfer ckb from one wallet to another")
                .arg(
                    arg!(--lock_type <LOCK_TYPE> "Lock type")
                        .value_parser(["omnilock", "genesis-sighash"]),
                )
                .arg(
                    arg!(--ckbytes <CKBYTES> "Ckbytes to send")
                        .value_parser(value_parser!(HumanCapacity)),
                )
                .arg(
                    arg!(--to_lock_type <TO_LOCK_TYPE> "Recipient lock type")
                        .value_parser(["omnilock", "genesis-sighash"]),
                )
                .arg(
                    arg!(
                        --to <TO> "Wallet file to send ckbytes"
                    )
                    .required(true)
                    .value_parser(value_parser!(PathBuf)),
                ),
        )
        .subcommand(
            Command::new("issue-udt")
                .about("issue udt assuming current wallet is the owner lock")
                .arg(
                    arg!(--lock_type <LOCK_TYPE> "Lock type")
                        .value_parser(["omnilock", "genesis-sighash"]),
                )
                .arg(
                    arg!(--amount <AMOUNT> "UDT amount to issue").value_parser(value_parser!(u128)),
                )
                .arg(
                    arg!(--to_lock_type <TO_LOCK_TYPE> "Recipient lock type")
                        .value_parser(["omnilock", "genesis-sighash"]),
                )
                .arg(
                    arg!(
                        --to <TO> "Wallet file to send ckbytes"
                    )
                    .required(true)
                    .value_parser(value_parser!(PathBuf)),
                ),
        )
        .subcommand(
            Command::new("transfer-udt")
                .about("transfer udt")
                .arg(
                    arg!(--lock_type <LOCK_TYPE> "Lock type")
                        .value_parser(["omnilock", "genesis-sighash"]),
                )
                .arg(
                    arg!(--amount <AMOUNT> "UDT amount to issue").value_parser(value_parser!(u128)),
                )
                .arg(
                    arg!(--to_lock_type <TO_LOCK_TYPE> "Recipient lock type")
                        .value_parser(["omnilock", "genesis-sighash"]),
                )
                .arg(
                    arg!(
                        --to <TO> "Wallet file to send ckbytes"
                    )
                    .required(true)
                    .value_parser(value_parser!(PathBuf)),
                )
                .arg(
                    arg!(--token <TOKEN> "UDT token script hash")
                        .required(true)
                        .value_parser(value_parser!(H256)),
                ),
        )
        .get_matches();

    if let Some(command_matches) = matches.subcommand_matches("deploy") {
        deploy(&command_matches, &matches);
    } else if let Some(_command_matches) = matches.subcommand_matches("deploy-dex1") {
        deploy_dex1(&matches);
    } else if let Some(command_matches) = matches.subcommand_matches("create-otx") {
        create_otx(&command_matches, &matches);
    } else if let Some(_command_matches) = matches.subcommand_matches("cancel-otx") {
        cancel_otx(&matches);
    } else if let Some(_command_matches) = matches.subcommand_matches("explain-tx") {
        explain_tx(&matches);
    } else if let Some(_command_matches) = matches.subcommand_matches("known-scripts") {
        known_scripts(&matches);
    } else if let Some(_command_matches) = matches.subcommand_matches("script-hashes") {
        script_hashes(&matches);
    } else if let Some(command_matches) = matches.subcommand_matches("balance-ckb") {
        balance_ckb(&command_matches, &matches);
    } else if let Some(command_matches) = matches.subcommand_matches("balance-udt") {
        balance_udt(&command_matches, &matches);
    } else if let Some(command_matches) = matches.subcommand_matches("transfer-ckb") {
        transfer_ckb(&command_matches, &matches);
    } else if let Some(command_matches) = matches.subcommand_matches("issue-udt") {
        issue_udt(&command_matches, &matches);
    } else if let Some(command_matches) = matches.subcommand_matches("transfer-udt") {
        transfer_udt(&command_matches, &matches);
    }
}

fn deploy(command_matches: &ArgMatches, top_matches: &ArgMatches) {
    let private_key = build_private_key(top_matches);
    let ckb_rpc = command_matches
        .get_one::<String>("rpc")
        .expect("required rpc");
    let ckb_client = CkbRpcClient::new(&ckb_rpc);

    // Identity part
    let (sender_key, sender_script) = build_genesis_sighash_lock(&private_key);
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![sender_key]);

    // CKB SDK work
    let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
    let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
    let mut unlockers = HashMap::default();
    unlockers.insert(
        sighash_script_id,
        Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
    );
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer = CapacityBalancer::new_simple(sender_script, placeholder_witness, 1000);
    let cell_dep_resolver = {
        let genesis_block = ckb_client
            .get_block_by_number(0.into())
            .expect("rpc")
            .unwrap();
        DefaultCellDepResolver::from_genesis(&BlockView::from(genesis_block))
            .expect("parse genesis block")
    };
    let header_dep_resolver = DefaultHeaderDepResolver::new(&ckb_rpc);
    let mut cell_collector = DefaultCellCollector::new(&ckb_rpc);
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(&ckb_rpc, 10);

    // Actually building the transaction
    let binary_path = command_matches.get_one::<PathBuf>("binary").unwrap();
    let binary: Bytes = std::fs::read(&binary_path).expect("read").into();
    let output = {
        let dummy = CellOutput::new_builder()
            // TODO: tweakable locks later
            .lock(Script::default())
            .type_(
                Some(
                    Script::new_builder()
                        .code_hash(TYPE_ID_CODE_HASH.pack())
                        .hash_type(ScriptHashType::Type.into())
                        .args(vec![0; 32].pack())
                        .build(),
                )
                .pack(),
            )
            .build();

        let required_capacity = dummy
            .occupied_capacity(Capacity::bytes(binary.len()).expect("capacity overflow"))
            .expect("capacity overflow");

        dummy
            .as_builder()
            .capacity(required_capacity.pack())
            .build()
    };
    let builder = CapacityTransferBuilder::new(vec![(output, binary)]);
    let dummy_tx = builder
        .build_balanced(
            &mut cell_collector,
            &cell_dep_resolver,
            &header_dep_resolver,
            &tx_dep_provider,
            &balancer,
            &unlockers,
        )
        .expect("build tx");
    let (locked_tx, code_hash) = {
        // Update type ID args
        let type_id_args: Bytes = {
            let mut hasher = new_blake2b();
            hasher.update(dummy_tx.inputs().get(0).unwrap().as_slice());
            hasher.update(&0u64.to_le_bytes());
            let mut ret = vec![0; 32];
            hasher.finalize(&mut ret);
            ret.into()
        };
        let type_id_script = Script::new_builder()
            .code_hash(TYPE_ID_CODE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(type_id_args.pack())
            .build();
        let first_output = dummy_tx
            .outputs()
            .get(0)
            .unwrap()
            .as_builder()
            .type_(Some(type_id_script.clone()).pack())
            .build();
        let mut outputs_builder = dummy_tx.outputs().as_builder();
        outputs_builder.replace(0, first_output);
        let outputs = outputs_builder.build();

        (
            dummy_tx
                .as_advanced_builder()
                .set_outputs(outputs.into_iter().collect())
                .build(),
            type_id_script.calc_script_hash(),
        )
    };
    let (tx, still_locked_groups) =
        unlock_tx(locked_tx, &tx_dep_provider, &unlockers).expect("unlock tx");
    assert!(still_locked_groups.is_empty());

    let full_script = FullScript {
        script: ckbrpc::Script {
            code_hash: code_hash.unpack(),
            hash_type: ckbrpc::ScriptHashType::Type,
            args: ckbrpc::JsonBytes::default(),
        },
        cell_dep: ckbrpc::CellDep {
            out_point: ckbrpc::OutPoint {
                tx_hash: tx.hash().unpack(),
                index: 0.into(),
            },
            dep_type: ckbrpc::DepType::Code,
        },
    };

    println!(
        "Here are the deployment details for {}",
        binary_path.to_string_lossy()
    );
    println!("");
    print_script(&full_script, None);
    println!("");
    println!("");

    save_tx(&top_matches, &tx);

    ckb_client
        .send_transaction(tx.data().into(), Some(OutputsValidator::Passthrough))
        .expect("send tx");

    wait_for_tx(tx.hash().unpack(), &ckb_rpc);
}

fn deploy_dex1(top_matches: &ArgMatches) {
    let config = build_config(top_matches);
    let private_key = build_private_key(top_matches);
    let ckb_client = CkbRpcClient::new(&config.ckb_rpc);

    // Identity part
    let (sender_key, sender_script) = build_genesis_sighash_lock(&private_key);
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![sender_key]);

    // CKB SDK work
    let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
    let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
    let mut unlockers = HashMap::default();
    unlockers.insert(
        sighash_script_id,
        Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
    );
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer = CapacityBalancer::new_simple(sender_script, placeholder_witness, 1000);
    let cell_dep_resolver = config.build_dep_resolver();
    let header_dep_resolver = DefaultHeaderDepResolver::new(&config.ckb_rpc);
    let mut cell_collector = DefaultCellCollector::new(&config.ckb_rpc);
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(&config.ckb_rpc, 10);

    // Actually building the transaction
    let output = {
        let t: ScriptHashType = config.dex1.script.hash_type.clone().into();
        let dummy = CellOutput::new_builder()
            // TODO: tweakable locks later
            .lock(config.always_success.script.clone().into())
            .type_(
                Some(
                    Script::new_builder()
                        .code_hash(config.dex1.script.code_hash.clone().pack())
                        .hash_type(t.into())
                        .args(vec![0; 32].pack())
                        .build(),
                )
                .pack(),
            )
            .build();

        let required_capacity = dummy
            .occupied_capacity(Capacity::zero())
            .expect("capacity overflow");

        dummy
            .as_builder()
            .capacity(required_capacity.pack())
            .build()
    };
    let builder = CapacityTransferBuilder::new(vec![(output, Bytes::new())]);
    let dummy_tx = builder
        .build_balanced(
            &mut cell_collector,
            &cell_dep_resolver,
            &header_dep_resolver,
            &tx_dep_provider,
            &balancer,
            &unlockers,
        )
        .expect("build tx");
    let locked_tx = {
        // Update type ID args
        let type_id_args: Bytes = {
            let mut hasher = new_blake2b();
            hasher.update(dummy_tx.inputs().get(0).unwrap().as_slice());
            hasher.update(&0u64.to_le_bytes());
            let mut ret = vec![0; 32];
            hasher.finalize(&mut ret);
            ret.into()
        };
        let type_id_script = dummy_tx
            .outputs()
            .get(0)
            .unwrap()
            .type_()
            .to_opt()
            .unwrap()
            .as_builder()
            .args(type_id_args.pack())
            .build();
        let first_output = dummy_tx
            .outputs()
            .get(0)
            .unwrap()
            .as_builder()
            .type_(Some(type_id_script.clone()).pack())
            .build();
        let mut outputs_builder = dummy_tx.outputs().as_builder();
        outputs_builder.replace(0, first_output);
        let outputs = outputs_builder.build();

        dummy_tx
            .as_advanced_builder()
            .set_outputs(outputs.into_iter().collect())
            .build()
    };
    let (tx, still_locked_groups) =
        unlock_tx(locked_tx, &tx_dep_provider, &unlockers).expect("unlock tx");
    assert!(still_locked_groups.is_empty());

    {
        let script = tx.outputs().get(0).unwrap().type_().to_opt().unwrap();

        println!(
            "Dex1 deployment cell type script hash: {:x}",
            script.calc_script_hash()
        );
        println!("Here are the dex1 deployment script details:");
        println!("");
        println!("dex1_deployment = \"0x{:x}\"", script.args().raw_data());
        println!("");
        println!("");
    }

    save_tx(&top_matches, &tx);

    ckb_client
        .send_transaction(tx.data().into(), Some(OutputsValidator::Passthrough))
        .expect("send tx");

    wait_for_tx(tx.hash().unpack(), &config.ckb_rpc);
}

fn create_otx(command_matches: &ArgMatches, top_matches: &ArgMatches) {
    let config = build_config(top_matches);
    let private_key = build_private_key(top_matches);
    let ckb_rpc = config.ckb_rpc.clone();

    let (sender_key, sender_script) = build_omnilock_lock(&private_key, &config);

    // Assembling otx
    let mut cell_collector = DefaultCellCollector::new(&ckb_rpc);
    // OTX requires signing input cells as well
    let mut input_live_cells = vec![];
    let mut tx_builder = TransactionBuilder::default();
    let known_scripts = config.known_script_map();
    let bid_hash = command_matches.get_one::<H256>("bid_token").unwrap();
    let ask_hash = command_matches.get_one::<H256>("ask_token").unwrap();
    let bid_script: Script = known_scripts
        .get(&bid_hash)
        .expect("missing bid token script!")
        .1
        .script
        .clone()
        .into();
    let ask_script: Script = known_scripts
        .get(&ask_hash)
        .expect("missing ask token script!")
        .1
        .script
        .clone()
        .into();
    let bid_amount = *command_matches.get_one::<u128>("bid_amount").unwrap();
    let mut added_amount = 0;
    let mut added_ckbytes: u64 = 0;
    while added_amount < bid_amount {
        let (live_cells, _) = cell_collector
            .collect_live_cells(
                &CellQueryOptions {
                    primary_script: sender_script.clone(),
                    primary_type: PrimaryScriptType::Lock,
                    with_data: Some(true),
                    secondary_script: Some(bid_script.clone()),
                    secondary_script_len_range: None,
                    data_len_range: Some(ValueRangeOption { start: 16, end: 17 }),
                    capacity_range: None,
                    block_range: None,
                    order: QueryOrder::Asc,
                    limit: None,
                    maturity: MaturityOption::Both,
                    min_total_capacity: 1,
                    script_search_mode: Some(SearchMode::Exact),
                },
                true,
            )
            .expect("collect live cells error");

        for live_cell in live_cells {
            let udt_amount = {
                let mut data = [0u8; 16];
                data.copy_from_slice(&live_cell.output_data[0..16]);
                u128::from_le_bytes(data)
            };
            added_amount = added_amount.checked_add(udt_amount).expect("overflow");
            added_ckbytes = added_ckbytes
                .checked_add(live_cell.output.capacity().unpack())
                .expect("overflow");
            tx_builder = tx_builder.input(
                CellInput::new_builder()
                    .previous_output(live_cell.out_point.clone())
                    .build(),
            );
            input_live_cells.push(live_cell);
            if added_amount >= bid_amount {
                break;
            }
        }
    }
    if added_amount > bid_amount {
        // Create change UDT cell
        let dummy_output = CellOutput::new_builder()
            .lock(sender_script.clone())
            .type_(Some(bid_script.clone()).pack())
            .build();
        let required_capacity = dummy_output
            .occupied_capacity(Capacity::bytes(16).expect("overflow"))
            .expect("overflow");
        assert!(added_ckbytes >= required_capacity.as_u64());
        let output = dummy_output
            .as_builder()
            .capacity(required_capacity.pack())
            .build();
        let output_data = Bytes::from((added_amount - bid_amount).to_le_bytes().to_vec());
        tx_builder = tx_builder.output(output).output_data(output_data.pack());
        added_ckbytes -= required_capacity.as_u64();
    }
    let change_ckbytes = {
        let dummy_output = CellOutput::new_builder()
            .lock(sender_script.clone())
            .build();
        dummy_output
            .occupied_capacity(Capacity::zero())
            .expect("overflow")
            .as_u64()
    };
    let minimal_claimed_ckbytes = {
        let dummy_freestanding_cell = CellOutput::new_builder()
            .lock(
                Script::new_builder()
                    .args(Bytes::from(vec![0; 96]).pack())
                    .build(),
            )
            .type_(Some(bid_script.clone()).pack())
            .build();
        let dummy_cell_capacity = dummy_freestanding_cell
            .occupied_capacity(Capacity::bytes(16).expect("overflow"))
            .expect("overflow");
        let return_cell = CellOutput::new_builder()
            .lock(sender_script.clone())
            .type_(Some(ask_script.clone()).pack())
            .build();
        let return_cell_capacity = return_cell
            .occupied_capacity(Capacity::bytes(16).expect("overflow"))
            .expect("overflow");
        dummy_cell_capacity
            .safe_add(return_cell_capacity)
            .expect("overflow")
            .as_u64()
    };
    let claimed_ckbytes = match command_matches.get_one::<HumanCapacity>("claimed_ckbytes") {
        Some(capacity) => {
            assert!(capacity.0 >= minimal_claimed_ckbytes);
            capacity.0
        }
        None => minimal_claimed_ckbytes,
    };
    let required_ckbytes = claimed_ckbytes
        .checked_add(change_ckbytes)
        .expect("overflow");
    while added_ckbytes <= required_ckbytes {
        // Add input cells for CKBytes
        let (live_cells, _) = cell_collector
            .collect_live_cells(
                &CellQueryOptions {
                    primary_script: sender_script.clone(),
                    primary_type: PrimaryScriptType::Lock,
                    with_data: None,
                    secondary_script: None,
                    secondary_script_len_range: Some(ValueRangeOption { start: 0, end: 1 }),
                    data_len_range: Some(ValueRangeOption { start: 0, end: 1 }),
                    capacity_range: None,
                    block_range: None,
                    order: QueryOrder::Asc,
                    limit: None,
                    maturity: MaturityOption::Both,
                    min_total_capacity: required_ckbytes - added_ckbytes,
                    script_search_mode: Some(SearchMode::Exact),
                },
                true,
            )
            .expect("collect live cells error");

        for live_cell in live_cells {
            added_ckbytes = added_ckbytes
                .checked_add(live_cell.output.capacity().unpack())
                .expect("overflow");
            tx_builder = tx_builder.input(
                CellInput::new_builder()
                    .previous_output(live_cell.out_point.clone())
                    .build(),
            );
            input_live_cells.push(live_cell);
            if added_ckbytes >= required_ckbytes {
                break;
            }
        }
    }
    // Change cell
    let actual_change_ckbytes = added_ckbytes - claimed_ckbytes;
    assert!(actual_change_ckbytes >= change_ckbytes);
    tx_builder = tx_builder
        .output(
            CellOutput::new_builder()
                .lock(sender_script.clone())
                .capacity(Capacity::shannons(actual_change_ckbytes).pack())
                .build(),
        )
        .output_data(Bytes::default().pack());
    let tx = tx_builder.build();
    // Detect if we need to include any outpoint
    let tx = if let (Some(tx_hash), Some(index)) = (
        command_matches.get_one::<H256>("include_outpoint_hash"),
        command_matches.get_one::<u32>("include_outpoint_index"),
    ) {
        let out_point = OutPoint::new_builder()
            .tx_hash(tx_hash.pack())
            .index(index.pack())
            .build();
        if tx
            .inputs()
            .into_iter()
            .any(|cell_input| cell_input.previous_output() == out_point)
        {
            tx
        } else {
            let ckb_client = CkbRpcClient::new(&ckb_rpc);
            let cell_with_status = ckb_client
                .get_live_cell(out_point.clone().into(), true)
                .expect("fetching live cell");
            assert_eq!(cell_with_status.status, "live");
            let cell_info = cell_with_status.cell.unwrap();
            let output = cell_info.output;
            let data = cell_info.data.unwrap().content.into_bytes();
            tx.as_advanced_builder()
                .input(CellInput::new_builder().previous_output(out_point).build())
                .output(output.into())
                .output_data(data.pack())
                .build()
        }
    } else {
        tx
    };
    // Build witness for storing order
    let action_data = {
        let limit_order = dex1::LimitOrder::new_builder()
            .bid_token(bid_hash.pack())
            .bid_amount(bid_amount.pack())
            .ask_token(ask_hash.pack())
            .ask_amount(
                command_matches
                    .get_one::<u128>("ask_amount")
                    .unwrap()
                    .pack(),
            )
            .recipient(sender_script.calc_script_hash())
            .claimed_ckbytes(claimed_ckbytes.pack())
            .build();
        let order = dex1::Order::new_builder().set(limit_order).build();
        let orders = dex1::Orders::new_builder().push(order).build();
        let dex1_action = dex1::Dex1Action::new_builder().orders(orders).build();
        dex1_action.as_bytes()
    };
    let witness = {
        let dex1_script: Script = config.config().dex1_deployment.script.into();
        let action = basic::Action::new_builder()
            .data(action_data.pack())
            .script_hash(dex1_script.calc_script_hash())
            .build();
        let actions = basic::ActionVec::new_builder().push(action).build();
        let message = basic::Message::new_builder().actions(actions).build();
        let otx = basic::Otx::new_builder()
            .message(message)
            .input_cells((tx.inputs().len() as u32).pack())
            .output_cells((tx.outputs().len() as u32).pack())
            .build();
        top_level::WitnessLayout::new_builder()
            .set(otx)
            .build()
            .as_bytes()
    };
    let tx = tx.as_advanced_builder().witness(witness.pack()).build();

    // Sign the transaction in OTX format
    let otx_hash: H256 = {
        let witness_layout =
            top_level::WitnessLayout::from_slice(&tx.witnesses().get(0).unwrap().raw_data())
                .expect("parse witness");
        let top_level::WitnessLayoutUnion::Otx(otx) = witness_layout.to_enum() else {
            panic!("Unexpected witness layout type!");
        };

        let mut hasher = Blake2bBuilder::new(32)
            .personal(b"ckb-tcob-otxhash")
            .build();
        hasher.update(otx.message().as_slice());
        hasher.update(&(tx.inputs().len() as u32).to_le_bytes());
        for (i, cell_input) in tx.inputs().into_iter().enumerate() {
            hasher.update(cell_input.as_slice());
            hasher.update(input_live_cells[i].output.as_slice());
            hasher.update(&(input_live_cells[i].output_data.len() as u32).to_le_bytes());
            hasher.update(&input_live_cells[i].output_data);
        }
        hasher.update(&(tx.outputs().len() as u32).to_le_bytes());
        for (output, data) in tx.outputs_with_data_iter() {
            hasher.update(output.as_slice());
            hasher.update(&(data.len() as u32).to_le_bytes());
            hasher.update(&data);
        }
        hasher.update(&(tx.cell_deps().len() as u32).to_le_bytes());
        for cell_dep in tx.cell_deps() {
            hasher.update(cell_dep.as_slice());
        }
        hasher.update(&(tx.header_deps().len() as u32).to_le_bytes());
        for header_dep in tx.header_deps() {
            hasher.update(header_dep.as_slice());
        }
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);
        hash.into()
    };
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![sender_key]);
    let signature = signer
        .sign(
            &sender_script.args().raw_data()[1..21],
            otx_hash.as_bytes(),
            true,
            &tx,
        )
        .expect("signing");
    let signed_tx = {
        let seal_data = {
            let mut d = vec![0];
            let omnilock_witness_lock = OmniLockWitnessLock::new_builder()
                .signature(Some(signature).pack())
                .build();
            d.extend(omnilock_witness_lock.as_slice());
            d
        };
        let seal = basic::SealPair::new_builder()
            .script_hash(sender_script.calc_script_hash())
            .seal(seal_data.pack())
            .build();
        let seals = basic::SealPairVec::new_builder().push(seal).build();

        // unpack witness step by step, then fill in seals
        let unseal_witness_layout =
            top_level::WitnessLayout::from_slice(&tx.witnesses().get(0).unwrap().raw_data())
                .expect("parse witness");
        let top_level::WitnessLayoutUnion::Otx(unseal_otx) = unseal_witness_layout.to_enum() else {
            panic!("Unexpected witness layout type!");
        };
        let otx = unseal_otx.as_builder().seals(seals).build();
        let witness_layout = unseal_witness_layout.as_builder().set(otx).build();
        let witness = witness_layout.as_bytes();
        tx.as_advanced_builder()
            .set_witnesses(vec![witness.pack()])
            .build()
    };

    // Store and (possibly) submit the transaction
    save_tx(&top_matches, &signed_tx);

    if command_matches.get_flag("send") {
        let otx_client = OtxRpcClient::new(&config.otx_rpc);

        otx_client
            .submit_open_transaction(signed_tx.data().into())
            .expect("send otx");
    }
}

fn cancel_otx(top_matches: &ArgMatches) {
    let config = build_config(top_matches);
    let tx_path = top_matches
        .get_one::<PathBuf>("tx_file")
        .expect("tx file is required as input!");

    let tx_data = std::fs::read(tx_path).expect("read");
    let tx: ckbrpc::Transaction = serde_json::from_slice(&tx_data).expect("parse json");
    let tx: packed::Transaction = tx.into();

    let otx_client = OtxRpcClient::new(&config.otx_rpc);
    otx_client
        .cancel_open_transaction(tx.raw().inputs().get(0).unwrap().previous_output().into())
        .expect("cancel otx");
}

fn explain_tx(top_matches: &ArgMatches) {
    let config = build_config(top_matches);
    let tx_path = top_matches
        .get_one::<PathBuf>("tx_file")
        .expect("tx file is required as input!");

    let tx_data = std::fs::read(tx_path).expect("read");
    let tx: ckbrpc::Transaction = serde_json::from_slice(&tx_data).expect("parse json");
    let tx: packed::Transaction = tx.into();

    let ckb_client = CkbRpcClient::new(&config.ckb_rpc);
    let mut input_cells = vec![];
    for (i, input) in tx.raw().inputs().into_iter().enumerate() {
        let tx_with_status = ckb_client
            .get_transaction(input.previous_output().tx_hash().unpack())
            .expect("rpc")
            .expect("extract tx with status");
        assert_eq!(
            tx_with_status.tx_status.status,
            Status::Committed,
            "Output cell {} is not committed!",
            i
        );
        let tx = to_tx(tx_with_status.transaction.expect("extract tx"));

        let index: usize = input.previous_output().index().unpack();
        let output = tx.outputs().get(index).unwrap();
        let json_output: ckb_jsonrpc_types::CellOutput = output.into();
        let data = tx.outputs_data().get(index).unwrap();

        input_cells.push((json_output, data));
    }

    let json_tx: ckbrpc::Transaction = tx.clone().into();
    println!(
        "TX: {}",
        serde_json::to_string_pretty(&json_tx).expect("json")
    );

    let udt_map = config.udt_map();

    println!("");
    println!("");
    for (i, (input, data)) in input_cells.iter().enumerate() {
        println!(
            "Input cell {}: {}",
            i,
            serde_json::to_string_pretty(input).expect("json")
        );
        println!(
            "Input cell {}'s capacity: {}",
            i,
            HumanCapacity(input.capacity.value())
        );
        if let Some(t) = &input.type_ {
            let s: Script = t.clone().into();
            if let Some((udt_name, _)) = udt_map.get(&s.calc_script_hash().unpack()) {
                let amount = {
                    let mut tmp = [0u8; 16];
                    tmp.copy_from_slice(&data.raw_data()[0..16]);
                    u128::from_le_bytes(tmp)
                };
                println!(
                    "Input cell {} holds UDT: {}, amount: {}",
                    i, udt_name, amount
                );
            }
        }
        println!("");
    }

    println!("");
    for (i, output) in tx.raw().outputs().into_iter().enumerate() {
        println!(
            "Output cell {}'s capacity: {}",
            i,
            HumanCapacity(output.capacity().unpack())
        );
        if let Some(t) = output.type_().to_opt() {
            let output_data = tx.raw().outputs_data().get(i).unwrap();
            if let Some((udt_name, _)) = udt_map.get(&t.calc_script_hash().unpack()) {
                let amount = {
                    let mut tmp = [0u8; 16];
                    tmp.copy_from_slice(&output_data.raw_data()[0..16]);
                    u128::from_le_bytes(tmp)
                };
                println!(
                    "Output cell {} holds UDT: {}, amount: {}",
                    i, udt_name, amount
                );
            }
        }
        println!("");
    }

    println!("");
    let mut script_groups: HashMap<H256, Vec<String>> = HashMap::default();
    for (i, (input, _data)) in input_cells.iter().enumerate() {
        let input: CellOutput = input.clone().into();
        let entry = script_groups
            .entry(input.lock().calc_script_hash().unpack())
            .or_insert_with(|| Vec::new());
        entry.push(format!("input {}'s lock", i));

        if let Some(t) = input.type_().to_opt() {
            let entry = script_groups
                .entry(t.calc_script_hash().unpack())
                .or_insert_with(|| Vec::new());
            entry.push(format!("input {}'s type", i));
        }
    }
    for (i, output) in tx.raw().outputs().into_iter().enumerate() {
        if let Some(t) = output.type_().to_opt() {
            let entry = script_groups
                .entry(t.calc_script_hash().unpack())
                .or_insert_with(|| Vec::new());
            entry.push(format!("output {}'s type", i));
        }
    }

    let known_scripts = config.known_script_map();
    for (hash, entries) in script_groups {
        let name = known_scripts
            .get(&hash)
            .map(|(name, _)| name)
            .cloned()
            .unwrap_or("Unknown".to_string());
        println!(
            "Script {:#x}({}) covers: {}",
            hash,
            name,
            entries.join(", ")
        );
    }
}

fn known_scripts(top_matches: &ArgMatches) {
    let config = build_config(top_matches);
    let known_scripts = config.known_script_map();

    for (hash, (name, full_script)) in known_scripts {
        println!("Script: {}", name);
        println!("Hash: {:#x}", hash);
        println!("");
        print_script(&full_script, Some("  ".to_string()));
        println!("");
    }
}

fn script_hashes(top_matches: &ArgMatches) {
    let config = build_config(top_matches);
    let private_key = build_private_key(top_matches);

    let (_, secp_script) = build_genesis_sighash_lock(&private_key);
    let (_, omni_script) = build_omnilock_lock(&private_key, &config);

    let h: ScriptHashType = config.udt.script.hash_type.clone().into();
    let secp_udt_script = Script::new_builder()
        .code_hash(config.udt.script.code_hash.clone().pack())
        .hash_type(h.into())
        .args(secp_script.calc_script_hash().as_bytes().pack())
        .build();
    let omni_udt_script = Script::new_builder()
        .code_hash(config.udt.script.code_hash.clone().pack())
        .hash_type(h.into())
        .args(omni_script.calc_script_hash().as_bytes().pack())
        .build();

    println!(
        "Genesis secp256k1 sighash script hash: {:x}",
        secp_script.calc_script_hash()
    );
    println!("Omnilock script hash: {:x}", omni_script.calc_script_hash());
    println!(
        "UDT script hash when using genesis sighash script as owner: {:x}",
        secp_udt_script.calc_script_hash()
    );
    println!(
        "UDT script hash when using omnilock script as owner: {:x}",
        omni_udt_script.calc_script_hash()
    );
}

fn balance_ckb(command_matches: &ArgMatches, top_matches: &ArgMatches) {
    let config = build_config(top_matches);
    let private_key = build_private_key(top_matches);
    let ckb_rpc = config.ckb_rpc.clone();

    let (_, lock_script) = build_lock_from_cli(&private_key, &config, command_matches);
    let mut cell_collector = DefaultCellCollector::new(&ckb_rpc);
    let mut query = CellQueryOptions::new_lock(lock_script);
    query.secondary_script_len_range = Some(ValueRangeOption::new_exact(0));
    query.data_len_range = Some(ValueRangeOption::new_exact(0));
    query.maturity = MaturityOption::Both;
    query.min_total_capacity = u64::max_value();
    let (_, total_capacity) = cell_collector
        .collect_live_cells(&query, false)
        .expect("collect cells");

    println!("CKBytes balance: {}", HumanCapacity(total_capacity));
}

fn balance_udt(command_matches: &ArgMatches, top_matches: &ArgMatches) {
    let config = build_config(top_matches);
    let private_key = build_private_key(top_matches);
    let ckb_rpc = config.ckb_rpc.clone();

    let (_, lock_script) = build_lock_from_cli(&private_key, &config, command_matches);
    let known_scripts = config.known_script_map();
    let udt_hash = command_matches.get_one::<H256>("token").unwrap();
    let udt_script: Script = known_scripts
        .get(&udt_hash)
        .expect("missing udt token script")
        .1
        .script
        .clone()
        .into();

    let mut cell_collector = DefaultCellCollector::new(&ckb_rpc);
    let mut query = CellQueryOptions::new_lock(lock_script);
    query.maturity = MaturityOption::Both;
    query.min_total_capacity = u64::max_value();
    query.secondary_script = Some(udt_script);
    query.data_len_range = Some(ValueRangeOption { start: 16, end: 17 });
    let (cells, _) = cell_collector
        .collect_live_cells(&query, false)
        .expect("collect cells");
    let mut total_amount: u128 = 0;
    for cell in cells {
        let udt_amount = {
            let mut data = [0u8; 16];
            data.copy_from_slice(&cell.output_data[0..16]);
            u128::from_le_bytes(data)
        };
        total_amount = total_amount.checked_add(udt_amount).expect("overflow");
    }

    println!("UDT balance: {}", total_amount);
}

fn transfer_ckb(command_matches: &ArgMatches, top_matches: &ArgMatches) {
    let config = build_config(top_matches);
    let private_key = build_private_key(top_matches);
    let ckb_client = CkbRpcClient::new(&config.ckb_rpc);

    // Identity part
    let (secp_key, secp_script) = build_genesis_sighash_lock(&private_key);
    let secp_signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![secp_key]);
    let (omni_key, omni_script) = build_omnilock_lock(&private_key, &config);
    let omnilock_config = {
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &omni_key);
        let pubkey_hash = blake160(&pubkey.serialize());
        OmniLockConfig::new_pubkey_hash(pubkey_hash)
    };
    let omnilock_script_id = ScriptId::new(
        config.omnilock.script.code_hash.clone(),
        config.omnilock.script.hash_type.clone().into(),
    );
    let omnilock_signer = OmniLockScriptSigner::new(
        Box::new(SecpCkbRawKeySigner::new_with_secret_keys(vec![omni_key])),
        omnilock_config.clone(),
        OmniUnlockMode::Normal,
    );

    // CKB SDK work
    let mut unlockers = HashMap::default();
    unlockers.insert(
        ScriptId::new_type(SIGHASH_TYPE_HASH.clone()),
        Box::new(SecpSighashUnlocker::from(Box::new(secp_signer) as Box<_>))
            as Box<dyn ScriptUnlocker>,
    );
    unlockers.insert(
        omnilock_script_id.clone(),
        Box::new(OmniLockUnlocker::new(
            omnilock_signer,
            omnilock_config.clone(),
        )) as Box<dyn ScriptUnlocker>,
    );
    let (sender_script, placeholder_witness) = match command_matches
        .get_one::<String>("lock_type")
        .unwrap()
        .as_str()
    {
        "omnilock" => (
            omni_script,
            omnilock_config
                .placeholder_witness(OmniUnlockMode::Normal)
                .expect("omnilock placeholder witness"),
        ),
        "genesis-sighash" => (
            secp_script,
            WitnessArgs::new_builder()
                .lock(Some(Bytes::from(vec![0u8; 65])).pack())
                .build(),
        ),
        _ => unreachable!(),
    };
    let balancer = CapacityBalancer::new_simple(sender_script, placeholder_witness, 1000);
    let mut cell_dep_resolver = {
        let genesis_block = ckb_client
            .get_block_by_number(0.into())
            .expect("rpc")
            .unwrap();
        DefaultCellDepResolver::from_genesis(&BlockView::from(genesis_block))
            .expect("parse genesis block")
    };
    cell_dep_resolver.insert(
        omnilock_script_id,
        config.omnilock.cell_dep.clone().into(),
        "Omnilock".to_string(),
    );
    let header_dep_resolver = DefaultHeaderDepResolver::new(&config.ckb_rpc);
    let mut cell_collector = DefaultCellCollector::new(&config.ckb_rpc);
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(&config.ckb_rpc, 10);

    // Actually building the transaction
    let recipient_script = build_recipient_script(command_matches, &config);
    let ckbytes = command_matches
        .get_one::<HumanCapacity>("ckbytes")
        .expect("extract ckbytes")
        .0;
    let builder = CapacityTransferBuilder::new(vec![(
        CellOutput::new_builder()
            .lock(recipient_script)
            .capacity(ckbytes.pack())
            .build(),
        Bytes::new(),
    )]);
    let (tx, still_locked_groups) = builder
        .build_unlocked(
            &mut cell_collector,
            &cell_dep_resolver,
            &header_dep_resolver,
            &tx_dep_provider,
            &balancer,
            &unlockers,
        )
        .expect("build tx");
    assert!(still_locked_groups.is_empty());

    save_tx(&top_matches, &tx);

    ckb_client
        .send_transaction(tx.data().into(), Some(OutputsValidator::Passthrough))
        .expect("send tx");

    wait_for_tx(tx.hash().unpack(), &config.ckb_rpc);
}

fn issue_udt(command_matches: &ArgMatches, top_matches: &ArgMatches) {
    let config = build_config(top_matches);
    let private_key = build_private_key(top_matches);
    let ckb_client = CkbRpcClient::new(&config.ckb_rpc);

    // Identity part
    let (secp_key, secp_script) = build_genesis_sighash_lock(&private_key);
    let secp_signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![secp_key]);
    let (omni_key, omni_script) = build_omnilock_lock(&private_key, &config);
    let omnilock_config = {
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &omni_key);
        let pubkey_hash = blake160(&pubkey.serialize());
        OmniLockConfig::new_pubkey_hash(pubkey_hash)
    };
    let omnilock_script_id = ScriptId::new(
        config.omnilock.script.code_hash.clone(),
        config.omnilock.script.hash_type.clone().into(),
    );
    let omnilock_signer = OmniLockScriptSigner::new(
        Box::new(SecpCkbRawKeySigner::new_with_secret_keys(vec![omni_key])),
        omnilock_config.clone(),
        OmniUnlockMode::Normal,
    );

    // CKB SDK work
    let mut unlockers = HashMap::default();
    unlockers.insert(
        ScriptId::new_type(SIGHASH_TYPE_HASH.clone()),
        Box::new(SecpSighashUnlocker::from(Box::new(secp_signer) as Box<_>))
            as Box<dyn ScriptUnlocker>,
    );
    unlockers.insert(
        omnilock_script_id.clone(),
        Box::new(OmniLockUnlocker::new(
            omnilock_signer,
            omnilock_config.clone(),
        )) as Box<dyn ScriptUnlocker>,
    );
    let (owner_script, placeholder_witness) = match command_matches
        .get_one::<String>("lock_type")
        .unwrap()
        .as_str()
    {
        "omnilock" => (
            omni_script,
            omnilock_config
                .placeholder_witness(OmniUnlockMode::Normal)
                .expect("omnilock placeholder witness"),
        ),
        "genesis-sighash" => (
            secp_script,
            WitnessArgs::new_builder()
                .lock(Some(Bytes::from(vec![0u8; 65])).pack())
                .build(),
        ),
        _ => unreachable!(),
    };
    let balancer = CapacityBalancer::new_simple(owner_script.clone(), placeholder_witness, 1000);
    let mut cell_dep_resolver = {
        let genesis_block = ckb_client
            .get_block_by_number(0.into())
            .expect("rpc")
            .unwrap();
        DefaultCellDepResolver::from_genesis(&BlockView::from(genesis_block))
            .expect("parse genesis block")
    };
    cell_dep_resolver.insert(
        omnilock_script_id,
        config.omnilock.cell_dep.clone().into(),
        "Omnilock".to_string(),
    );
    let udt_script_id = ScriptId::new(
        config.udt.script.code_hash.clone(),
        config.udt.script.hash_type.clone().into(),
    );
    cell_dep_resolver.insert(
        udt_script_id.clone(),
        config.udt.cell_dep.clone().into(),
        "UDT".to_string(),
    );
    let header_dep_resolver = DefaultHeaderDepResolver::new(&config.ckb_rpc);
    let mut cell_collector = DefaultCellCollector::new(&config.ckb_rpc);
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(&config.ckb_rpc, 10);

    // Actually building the transaction
    let recipient_script = build_recipient_script(command_matches, &config);
    let amount = *command_matches
        .get_one::<u128>("amount")
        .expect("extract amount");
    let builder = UdtIssueBuilder {
        udt_type: UdtType::Sudt,
        script_id: udt_script_id,
        owner: owner_script.clone(),
        receivers: vec![UdtTargetReceiver::new(
            TransferAction::Create,
            recipient_script,
            amount,
        )],
    };
    let (tx, still_locked_groups) = builder
        .build_unlocked(
            &mut cell_collector,
            &cell_dep_resolver,
            &header_dep_resolver,
            &tx_dep_provider,
            &balancer,
            &unlockers,
        )
        .expect("build tx");
    assert!(still_locked_groups.is_empty());

    let new_full_script = FullScript {
        script: ckbrpc::Script {
            code_hash: config.udt.script.code_hash.clone(),
            hash_type: config.udt.script.hash_type.clone(),
            args: Bytes::from(owner_script.calc_script_hash().as_slice().to_vec())
                .pack()
                .into(),
        },
        cell_dep: config.udt.cell_dep.clone(),
    };
    let udt_script: Script = new_full_script.script.clone().into();

    let suffix = format!("{:x}", udt_script.calc_script_hash()).as_str()[56..64].to_string();
    println!(
        "Issued token script hash: {:x}",
        udt_script.calc_script_hash()
    );
    println!("Use the following line to keep token script in an environment variable:");
    println!(
        "export TOKEN_{}=\"{:x}\"",
        suffix,
        udt_script.calc_script_hash()
    );
    println!("");
    println!("Issued token script configuration:");
    println!("");
    println!("[[test_udts]]");
    println!("owner_lock_hash = \"0x{:x}\"", udt_script.args().raw_data());
    println!("name = \"Token {}\"", suffix);
    println!("");
    println!("");

    save_tx(&top_matches, &tx);

    ckb_client
        .send_transaction(tx.data().into(), Some(OutputsValidator::Passthrough))
        .expect("send tx");

    wait_for_tx(tx.hash().unpack(), &config.ckb_rpc);
}

fn transfer_udt(command_matches: &ArgMatches, top_matches: &ArgMatches) {
    let config = build_config(top_matches);
    let private_key = build_private_key(top_matches);
    let ckb_client = CkbRpcClient::new(&config.ckb_rpc);

    // Identity part
    let (secp_key, secp_script) = build_genesis_sighash_lock(&private_key);
    let secp_signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![secp_key]);
    let (omni_key, omni_script) = build_omnilock_lock(&private_key, &config);
    let omnilock_config = {
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &omni_key);
        let pubkey_hash = blake160(&pubkey.serialize());
        OmniLockConfig::new_pubkey_hash(pubkey_hash)
    };
    let omnilock_script_id = ScriptId::new(
        config.omnilock.script.code_hash.clone(),
        config.omnilock.script.hash_type.clone().into(),
    );
    let omnilock_signer = OmniLockScriptSigner::new(
        Box::new(SecpCkbRawKeySigner::new_with_secret_keys(vec![omni_key])),
        omnilock_config.clone(),
        OmniUnlockMode::Normal,
    );

    let known_scripts = config.known_script_map();
    let udt_hash = command_matches.get_one::<H256>("token").unwrap();
    let udt_full_script = known_scripts
        .get(&udt_hash)
        .expect("missing udt token script")
        .1
        .clone();
    let udt_script_id = ScriptId::new(
        udt_full_script.script.code_hash.clone().into(),
        udt_full_script.script.hash_type.clone().into(),
    );
    let udt_script: Script = udt_full_script.script.clone().into();

    // CKB SDK work
    let mut unlockers = HashMap::default();
    unlockers.insert(
        ScriptId::new_type(SIGHASH_TYPE_HASH.clone()),
        Box::new(SecpSighashUnlocker::from(Box::new(secp_signer) as Box<_>))
            as Box<dyn ScriptUnlocker>,
    );
    unlockers.insert(
        omnilock_script_id.clone(),
        Box::new(OmniLockUnlocker::new(
            omnilock_signer,
            omnilock_config.clone(),
        )) as Box<dyn ScriptUnlocker>,
    );
    let (sender_script, placeholder_witness) = match command_matches
        .get_one::<String>("lock_type")
        .unwrap()
        .as_str()
    {
        "omnilock" => (
            omni_script,
            omnilock_config
                .placeholder_witness(OmniUnlockMode::Normal)
                .expect("omnilock placeholder witness"),
        ),
        "genesis-sighash" => (
            secp_script,
            WitnessArgs::new_builder()
                .lock(Some(Bytes::from(vec![0u8; 65])).pack())
                .build(),
        ),
        _ => unreachable!(),
    };
    let balancer = CapacityBalancer::new_simple(sender_script.clone(), placeholder_witness, 1000);
    let mut cell_dep_resolver = {
        let genesis_block = ckb_client
            .get_block_by_number(0.into())
            .expect("rpc")
            .unwrap();
        DefaultCellDepResolver::from_genesis(&BlockView::from(genesis_block))
            .expect("parse genesis block")
    };
    cell_dep_resolver.insert(
        omnilock_script_id,
        config.omnilock.cell_dep.clone().into(),
        "Omnilock".to_string(),
    );
    cell_dep_resolver.insert(
        udt_script_id.clone(),
        udt_full_script.cell_dep.clone().into(),
        "UDT to transfer".to_string(),
    );
    let header_dep_resolver = DefaultHeaderDepResolver::new(&config.ckb_rpc);
    let mut cell_collector = DefaultCellCollector::new(&config.ckb_rpc);
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(&config.ckb_rpc, 10);

    // Build the base transaction
    let recipient_script = build_recipient_script(command_matches, &config);
    let required_amount = *command_matches
        .get_one::<u128>("amount")
        .expect("extract amount");
    let base_tx = {
        let query = {
            let mut query = CellQueryOptions::new_lock(sender_script.clone());
            query.secondary_script = Some(udt_script.clone());
            query.data_len_range = Some(ValueRangeOption::new_min(16));
            query
        };

        let mut cell_deps = HashSet::new();
        {
            let sender_cell_dep = cell_dep_resolver
                .resolve(&sender_script)
                .expect("resolve sender script");
            cell_deps.insert(sender_cell_dep);
            let udt_cell_dep = cell_dep_resolver
                .resolve(&udt_script)
                .expect("resolve udt script");
            cell_deps.insert(udt_cell_dep);
        }

        let recipient_cell_output = {
            let dummy = CellOutput::new_builder()
                .lock(recipient_script)
                .type_(Some(udt_script.clone()).pack())
                .build();
            let required_capacity = dummy
                .occupied_capacity(Capacity::bytes(16).expect("overflow"))
                .expect("overflow");
            dummy
                .as_builder()
                .capacity(required_capacity.pack())
                .build()
        };
        let recipient_cell_data = Bytes::from((required_amount).to_le_bytes().to_vec());
        let mut outputs = vec![recipient_cell_output];
        let mut outputs_data = vec![recipient_cell_data];

        let (cells, _) = cell_collector
            .collect_live_cells(&query, true)
            .expect("collect udt cells");
        let mut added_amount: u128 = 0;
        let mut inputs = vec![];
        for cell in cells {
            let cell_udt_amount = {
                let mut data = [0u8; 16];
                data.copy_from_slice(&cell.output_data[0..16]);
                u128::from_le_bytes(data)
            };

            inputs.push(CellInput::new(cell.out_point, 0));
            added_amount = added_amount.checked_add(cell_udt_amount).expect("overflow");

            if added_amount >= required_amount {
                break;
            }
        }
        assert!(added_amount >= required_amount);
        if added_amount > required_amount {
            let change_cell_output = {
                let dummy = CellOutput::new_builder()
                    .lock(sender_script)
                    .type_(Some(udt_script.clone()).pack())
                    .build();
                let required_capacity = dummy
                    .occupied_capacity(Capacity::bytes(16).expect("overflow"))
                    .expect("overflow");
                dummy
                    .as_builder()
                    .capacity(required_capacity.pack())
                    .build()
            };
            outputs.push(change_cell_output);
            outputs_data.push(Bytes::from(
                (added_amount - required_amount).to_le_bytes().to_vec(),
            ));
        }

        TransactionBuilder::default()
            .set_cell_deps(cell_deps.into_iter().collect())
            .inputs(inputs)
            .outputs(outputs)
            .outputs_data(
                outputs_data
                    .into_iter()
                    .map(|d| d.pack())
                    .collect::<Vec<packed::Bytes>>(),
            )
            .build()
    };
    let (filled_tx, _) =
        fill_placeholder_witnesses(base_tx, &tx_dep_provider, &unlockers).expect("fill witness");
    let balanced_tx = balance_tx_capacity(
        &filled_tx,
        &balancer,
        &mut cell_collector,
        &tx_dep_provider,
        &cell_dep_resolver,
        &header_dep_resolver,
    )
    .expect("balance tx");
    let (tx, still_locked_groups) =
        unlock_tx(balanced_tx, &tx_dep_provider, &unlockers).expect("unlock tx");
    assert!(still_locked_groups.is_empty());

    save_tx(&top_matches, &tx);

    ckb_client
        .send_transaction(tx.data().into(), Some(OutputsValidator::Passthrough))
        .expect("send tx");

    wait_for_tx(tx.hash().unpack(), &config.ckb_rpc);
}
