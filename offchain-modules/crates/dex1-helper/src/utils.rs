use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::{DepType, Either, ResponseFormat, Status};
use ckb_sdk::{constants::SIGHASH_TYPE_HASH, CkbRpcClient, SECP256K1};
use ckb_types::{
    bytes::Bytes,
    core::{ScriptHashType, TransactionView},
    packed::{Script, Transaction},
    prelude::*,
    H256,
};
use clap::ArgMatches;
use dex1_assembler::config::{FullScript, RunnerConfig};
use std::path::PathBuf;
use std::str::FromStr;

pub fn build_config(top_matches: &ArgMatches) -> RunnerConfig {
    let config_path = top_matches
        .get_one::<PathBuf>("config")
        .expect("required config file");
    toml::from_str(&std::fs::read_to_string(config_path).expect("read")).expect("parse config")
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
    // TODO: other formats will be added later, such as keystore files
    H256::from_str(&wallet_content).expect("parse raw private key")
}

pub fn build_recipient_script(command_matches: &ArgMatches, config: &RunnerConfig) -> Script {
    // NOTE: in a real setup, we would never be able to get the recipient's
    // private key, then derive public key hash like we do here. But for a
    // helper binary used for playing with the demo, doing it this way simplifies
    // the management of different wallet accounts.
    let recipient_private_key = {
        let path = command_matches.get_one::<PathBuf>("to").unwrap();
        read_private_key(path)
    };
    match command_matches
        .get_one::<String>("to_lock_type")
        .unwrap()
        .as_str()
    {
        "omnilock" => {
            let (_, s) = build_omnilock_lock(&recipient_private_key, &config);
            s
        }
        "genesis-sighash" => {
            let (_, s) = build_genesis_sighash_lock(&recipient_private_key);
            s
        }
        _ => unreachable!(),
    }
}

pub fn build_genesis_sighash_lock(private_key: &H256) -> (secp256k1::SecretKey, Script) {
    let secret_key = secp256k1::SecretKey::from_slice(private_key.as_bytes())
        .expect("create secp256k1 secret key structure");
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &secret_key);
    let hash160 = blake2b_256(&pubkey.serialize()[..])[0..20].to_vec();
    let script = Script::new_builder()
        .code_hash(SIGHASH_TYPE_HASH.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(Bytes::from(hash160).pack())
        .build();
    (secret_key, script)
}

pub fn build_omnilock_lock(
    private_key: &H256,
    config: &RunnerConfig,
) -> (secp256k1::SecretKey, Script) {
    // For simplicity, our demo here only uses omnilock with CKB's signature algorithm
    let secret_key = secp256k1::SecretKey::from_slice(private_key.as_bytes())
        .expect("create secp256k1 secret key structure");
    let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &secret_key);
    let args = {
        let mut data = vec![0; 22];
        let pubkey_hash = &blake2b_256(&pubkey.serialize()[..])[0..20];
        data[1..21].copy_from_slice(&pubkey_hash);
        data
    };
    let t: ScriptHashType = config.omnilock.script.hash_type.clone().into();
    let script = Script::new_builder()
        .code_hash(config.omnilock.script.code_hash.pack())
        .hash_type(t.into())
        .args(Bytes::from(args).pack())
        .build();
    (secret_key, script)
}

pub fn build_lock_from_cli(
    private_key: &H256,
    config: &RunnerConfig,
    matches: &ArgMatches,
) -> (secp256k1::SecretKey, Script) {
    match matches.get_one::<String>("lock_type").unwrap().as_str() {
        "omnilock" => build_omnilock_lock(private_key, config),
        "genesis-sighash" => build_genesis_sighash_lock(private_key),
        _ => unreachable!(),
    }
}

pub fn print_script(script: &FullScript, prefix: Option<String>) {
    let prefix = prefix.unwrap_or("".to_string());

    println!(
        "{}script.code_hash = \"0x{:x}\"",
        prefix, script.script.code_hash
    );
    println!(
        "{}script.hash_type = \"{}\"",
        prefix, script.script.hash_type
    );
    println!(
        "{}script.args = \"0x{:x}\"",
        prefix,
        script.script.args.clone().into_bytes()
    );
    println!(
        "{}cell_dep.out_point.tx_hash = \"{:#x}\"",
        prefix, script.cell_dep.out_point.tx_hash
    );
    println!(
        "{}cell_dep.out_point.index = \"{}\"",
        prefix, script.cell_dep.out_point.index
    );
    println!(
        "{}cell_dep.dep_type = \"{}\"",
        prefix,
        match script.cell_dep.dep_type {
            DepType::Code => "code",
            DepType::DepGroup => "dep_group",
        }
    );
}

pub fn wait_for_tx(hash: H256, ckb_rpc: &str) {
    let ckb_client = CkbRpcClient::new(ckb_rpc);
    println!("Waiting for {:#x} to be committed...", hash);

    loop {
        let status = ckb_client
            .get_transaction_status(hash.clone())
            .expect("ckb rpc");
        if status.tx_status.status == Status::Committed {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(4));
    }

    println!("Tx {:#x} is committed!", hash);
}

pub fn save_tx(matches: &ArgMatches, tx: &TransactionView) {
    if let Some(tx_file) = matches.get_one::<PathBuf>("tx_file") {
        let tx: ckb_jsonrpc_types::Transaction = tx.data().into();

        std::fs::write(tx_file, serde_json::to_string_pretty(&tx).expect("json"))
            .expect("write tx");
    }
}

pub fn to_tx(json: ResponseFormat<ckb_jsonrpc_types::TransactionView>) -> TransactionView {
    match json.inner {
        Either::Left(json_view) => {
            let tx: Transaction = json_view.inner.into();
            tx.into_view()
        }
        Either::Right(json_bytes) => Transaction::from_slice(&json_bytes.into_bytes())
            .expect("molecule parsing")
            .into_view(),
    }
}
