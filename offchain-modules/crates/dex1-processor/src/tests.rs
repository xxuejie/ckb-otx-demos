use crate::ParsedRpcError;
use ckb_script::ScriptError;
use ckb_sdk::RpcError;
use ckb_types::{
    core::error::OutPointError,
    packed::{Byte32, OutPoint},
};
use jsonrpc_core::types::error::{Error as JsonrpcError, ErrorCode};
use rand::{rngs::StdRng, thread_rng, Rng, SeedableRng};

#[test]
fn test_parse_rpc_error() {
    let seed: u64 = {
        let mut rng = thread_rng();
        rng.gen()
    };
    println!("Seed: {}", seed);
    let mut rng = StdRng::seed_from_u64(seed);

    let index1 = rng.gen();
    let error1 = RpcError::Rpc(JsonrpcError {
        code: ErrorCode::ServerError(-302),
        message: ScriptError::ValidationFailure("0xdeadbeef".to_string(), 13)
            .input_lock_script(index1)
            .to_string(),
        data: None,
    });
    assert_eq!(ParsedRpcError::InputCellScriptError(index1), error1.into());

    let index2 = rng.gen();
    let error2 = RpcError::Rpc(JsonrpcError {
        code: ErrorCode::ServerError(-302),
        message: ScriptError::ValidationFailure("0xdeadbeef".to_string(), 1)
            .input_type_script(index2)
            .to_string(),
        data: None,
    });
    assert_eq!(ParsedRpcError::InputCellScriptError(index2), error2.into());

    let index3 = rng.gen();
    let error3 = RpcError::Other(
        ScriptError::ValidationFailure("0xdeadbeef".to_string(), 8)
            .output_type_script(index3)
            .into(),
    );
    assert_eq!(ParsedRpcError::OutputCellScriptError(index3), error3.into());

    let out_point1 = {
        let mut data = [0u8; 32];
        rng.fill(&mut data);
        OutPoint::new(Byte32::new(data), rng.gen())
    };
    let error4 = RpcError::Rpc(JsonrpcError {
        code: ErrorCode::ServerError(-302),
        message: OutPointError::Dead(out_point1.clone()).to_string(),
        data: None,
    });
    assert_eq!(ParsedRpcError::InvalidOutPoint(out_point1), error4.into());

    let out_point2 = {
        let mut data = [0u8; 32];
        rng.fill(&mut data);
        OutPoint::new(Byte32::new(data), rng.gen())
    };
    let error5 = RpcError::Rpc(JsonrpcError {
        code: ErrorCode::ServerError(-302),
        message: OutPointError::Unknown(out_point2.clone()).to_string(),
        data: None,
    });
    assert_eq!(ParsedRpcError::InvalidOutPoint(out_point2), error5.into());
}
