use ckb_hash::{blake2b_256, new_blake2b};
use ckb_jsonrpc_types::OutputsValidator;
use ckb_sdk::{
    constants::{SIGHASH_TYPE_HASH, TYPE_ID_CODE_HASH},
    rpc::CkbRpcClient,
    traits::{
        DefaultCellCollector, DefaultCellDepResolver, DefaultHeaderDepResolver,
        DefaultTransactionDependencyProvider, SecpCkbRawKeySigner,
    },
    tx_builder::{transfer::CapacityTransferBuilder, CapacityBalancer, TxBuilder},
    unlock::{ScriptUnlocker, SecpSighashUnlocker},
    ScriptId, SECP256K1,
};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, Capacity, ScriptHashType},
    packed::{CellOutput, Script, WitnessArgs},
    prelude::*,
    H256,
};
use clap::{arg, command, value_parser, ArgMatches, Command};
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;

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
            .required(true)
            .value_parser(value_parser!(PathBuf)),
        )
        .arg(arg!(
            -r --rpc <RPC> "CKB RPC address"
        ))
        .subcommand(
            Command::new("deploy")
                .about("deploy new script in a naive way")
                .arg(
                    arg!(
                        -b --binary <BINARY> "Binary to deploy"
                    )
                    .required(true)
                    .value_parser(value_parser!(PathBuf)),
                ),
        )
        .subcommand(Command::new("create-otx").about("create and (optionally) send new otx"))
        .subcommand(Command::new("explain-otx").about("explain created otx"))
        .subcommand(Command::new("update-otx").about("update created otx"))
        .subcommand(Command::new("cancel-otx").about("cancel an otx"))
        .subcommand(Command::new("balance-ckb").about("fetch balance of ckb"))
        .subcommand(Command::new("balance-udt").about("fetch balance of udt"))
        .subcommand(Command::new("transfer-ckb").about("transfer ckb"))
        .subcommand(Command::new("issue-udt").about("transfer udt"))
        .subcommand(Command::new("transfer-udt").about("transfer udt"))
        .get_matches();

    if let Some(command_matches) = matches.subcommand_matches("deploy") {
        deploy(&command_matches, &matches);
    }
}

fn deploy(command_matches: &ArgMatches, top_matches: &ArgMatches) {
    let wallet_path = top_matches.get_one::<PathBuf>("from").unwrap();
    let wallet_content = std::fs::read_to_string(wallet_path)
        .expect("read wallet content")
        .trim()
        .to_string();
    // TODO: other formats will be added later, such as keystore files
    let private_key = H256::from_str(&wallet_content).expect("parse raw private key");
    let ckb_rpc = top_matches.get_one::<String>("rpc").expect("required rpc");
    let ckb_client = CkbRpcClient::new(&ckb_rpc);

    // Identity part
    let sender_key = secp256k1::SecretKey::from_slice(private_key.as_bytes())
        .expect("create secp256k1 secret key structure");
    let sender_script = {
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
        let hash160 = blake2b_256(&pubkey.serialize()[..])[0..20].to_vec();
        Script::new_builder()
            .code_hash(SIGHASH_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(Bytes::from(hash160).pack())
            .build()
    };

    // CKB SDK work
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![sender_key]);
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
    let binary: Bytes = std::fs::read(command_matches.get_one::<PathBuf>("binary").unwrap())
        .expect("read")
        .into();
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
    let (tx, code_hash) = {
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

    println!("code_hash = \"{:#x}\"", code_hash);
    println!("hash_type = \"type\"");
    println!("out_point.tx_hash = \"{:#x}\"", tx.hash());
    println!("out_point.index = 1");
    println!("dep_type = \"code\"");

    ckb_client
        .send_transaction(tx.data().into(), Some(OutputsValidator::Passthrough))
        .expect("send tx");
}
