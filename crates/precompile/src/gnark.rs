use anyhow::{anyhow, Result};
use ethabi::{encode, ethereum_types::U256, ParamType, Token};
use gnark::{gnark_groth16_verify, gnark_plonk_verify};

use crate::{
    primitives::Bytes, Precompile, PrecompileError, PrecompileErrors, PrecompileOutput,
    PrecompileResult, PrecompileWithAddress,
};

pub const VERIFY_GROTH16: PrecompileWithAddress = PrecompileWithAddress(
    crate::u64_to_address(0xff00),
    Precompile::Standard(verify_groth16),
);
pub enum ErrorCode {
    GG16VInputUnpackErr = 1000001,
    GG16VVerifyErr = 1000002,

    GPVInputUnpackErr = 1000011,
    GPVVerifyErr = 1000012,
}

pub const VERIFY_PLONK: PrecompileWithAddress = PrecompileWithAddress(
    crate::u64_to_address(0xff01),
    Precompile::Standard(verify_plonk),
);

const GAS: u64 = 7500;

fn verify_groth16(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    if gas_limit < GAS {
        return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
    }

    let (id, proof, verify_key, witness) = decode_input(input).map_err(|_| {
        PrecompileErrors::Error(PrecompileError::Other(format!(
            "{}",
            ErrorCode::GG16VInputUnpackErr as u32
        )))
    })?;

    let ret = gnark_groth16_verify(id, proof, verify_key, witness);

    if !ret {
        return Err(PrecompileErrors::Error(PrecompileError::Other(
            format!(
                "{}",
                ErrorCode::GG16VVerifyErr as u32
            )
        )))
    }

    Ok(PrecompileOutput::new(
        GAS,
        encode(&[Token::Bool(ret)]).into(),
    ))
}

fn verify_plonk(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    if gas_limit < GAS {
        return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
    }
    let (id, proof, verify_key, witness) = decode_input(input).map_err(|_| {
        PrecompileErrors::Error(PrecompileError::Other(format!(
            "{}",
            ErrorCode::GPVInputUnpackErr as u32
        )))
    })?;

    let ret = gnark_plonk_verify(id, proof, verify_key, witness);

    if !ret {
        return Err(PrecompileErrors::Error(PrecompileError::Other(
            format!(
                "{}",
                ErrorCode::GPVVerifyErr as u32
            )
        )))
    }

    Ok(PrecompileOutput::new(
        GAS,
        encode(&[Token::Bool(ret)]).into(),
    ))
}

fn decode_input(input: &Bytes) -> Result<(u16, Vec<u8>, Vec<u8>, Vec<u8>)> {
    let tokens = ethabi::decode(
        &[ParamType::Tuple(vec![
            ParamType::Uint(16),
            ParamType::Bytes,
            ParamType::Bytes,
            ParamType::Bytes,
        ])],
        &input,
    )
        .map_err(|e| anyhow!("decode input error:{e}"))?;

    let tokens = tokens
        .first()
        .cloned()
        .and_then(|token| token.into_tuple())
        .ok_or(anyhow!("format input error"))?;

    let id = tokens
        .first()
        .cloned()
        .and_then(|token| token.into_uint())
        .ok_or(anyhow!("id format error"))?;

    if id > U256::from(u16::MAX) {
        return Err(anyhow!("iid is too large"));
    }

    let id = id.as_u32() as u16;

    let proof = tokens
        .get(1)
        .cloned()
        .and_then(|token| token.into_bytes())
        .ok_or(anyhow!("proof format error"))?;

    let verify_key = tokens
        .get(2)
        .cloned()
        .and_then(|token| token.into_bytes())
        .ok_or(anyhow!("verify_key format error"))?;

    let witness = tokens
        .get(3)
        .cloned()
        .and_then(|token| token.into_bytes())
        .ok_or(anyhow!("witness format error"))?;

    Ok((id, proof, verify_key, witness))
}