use crate::primitives::Bytes;
use ethabi::{ethereum_types::U256, ParamType};
use gnark::{gnark_groth16_verify, gnark_plonk_verify};

use crate::{
    Precompile, PrecompileError, PrecompileErrors, PrecompileOutput, PrecompileResult,
    PrecompileWithAddress,
};

pub const VERIFY_GROTH16: PrecompileWithAddress = PrecompileWithAddress(
    crate::u64_to_address(0xff00),
    Precompile::Standard(verify_groth16),
);

pub const VERIFY_PLONK: PrecompileWithAddress = PrecompileWithAddress(
    crate::u64_to_address(0xff01),
    Precompile::Standard(verify_plonk),
);

const GAS: u64 = 7500;

fn verify_groth16(input: &Bytes, _gas_limit: u64) -> PrecompileResult {
    let tokens = ethabi::decode(
        &[ParamType::Tuple(vec![
            ParamType::Uint(16),
            ParamType::Bytes,
            ParamType::Bytes,
            ParamType::Bytes,
        ])],
        &input,
    )
    .map_err(|e| {
        PrecompileErrors::Error(PrecompileError::other(format!(
            "decode verify groth16 input error:{e}"
        )))
    })?;

    let tokens = tokens
        .first()
        .cloned()
        .and_then(|token| token.into_tuple())
        .ok_or(PrecompileErrors::Error(PrecompileError::other(
            "verify groth16 format error",
        )))?;

    let id = tokens
        .first()
        .cloned()
        .and_then(|token| token.into_uint())
        .ok_or(PrecompileErrors::Error(PrecompileError::other(
            "verify groth16 id format error",
        )))?;
    if id > U256::from(u16::MAX) {
        return Err(PrecompileErrors::Error(PrecompileError::other(
            "verify groth16 id format error",
        )));
    }
    let id = id.as_u32() as u16;

    let proof = tokens
        .get(1)
        .cloned()
        .and_then(|token| token.into_bytes())
        .ok_or(PrecompileErrors::Error(PrecompileError::other(
            "verify groth16 proof format error",
        )))?;
    let verify_key = tokens
        .get(2)
        .cloned()
        .and_then(|token| token.into_bytes())
        .ok_or(PrecompileErrors::Error(PrecompileError::other(
            "verify groth16 verify_key format error",
        )))?;
    let witness = tokens
        .get(3)
        .cloned()
        .and_then(|token| token.into_bytes())
        .ok_or(PrecompileErrors::Error(PrecompileError::other(
            "verify groth16 witness format error",
        )))?;

    let bytes = if gnark_groth16_verify(id, proof, verify_key, witness) {
        "y".as_bytes().to_vec()
    } else {
        "n".as_bytes().to_vec()
    };

    Ok(PrecompileOutput::new(GAS, bytes.into()))
}

fn verify_plonk(input: &Bytes, _gas_limit: u64) -> PrecompileResult {
    let tokens = ethabi::decode(
        &[ParamType::Tuple(vec![
            ParamType::Uint(16),
            ParamType::Bytes,
            ParamType::Bytes,
            ParamType::Bytes,
        ])],
        &input,
    )
    .map_err(|e| {
        PrecompileErrors::Error(PrecompileError::other(format!(
            "decode verify plonk input error:{e}"
        )))
    })?;

    let tokens = tokens
        .first()
        .cloned()
        .and_then(|token| token.into_tuple())
        .ok_or(PrecompileErrors::Error(PrecompileError::other(
            "verify plonk id format error",
        )))?;

    let id = tokens
        .first()
        .cloned()
        .and_then(|token| token.into_uint())
        .ok_or(PrecompileErrors::Error(PrecompileError::other(
            "verify plonk id format error",
        )))?;
    if id > U256::from(u16::MAX) {
        return Err(PrecompileErrors::Error(PrecompileError::other(
            "verify plonk id format error",
        )));
    }
    let id = id.as_u32() as u16;

    let proof = tokens
        .get(1)
        .cloned()
        .and_then(|token| token.into_bytes())
        .ok_or(PrecompileErrors::Error(PrecompileError::other(
            "verify plonk proof format error",
        )))?;
    let verify_key = tokens
        .get(2)
        .cloned()
        .and_then(|token| token.into_bytes())
        .ok_or(PrecompileErrors::Error(PrecompileError::other(
            "verify plonk verify_key format error",
        )))?;
    let witness = tokens
        .get(3)
        .cloned()
        .and_then(|token| token.into_bytes())
        .ok_or(PrecompileErrors::Error(PrecompileError::other(
            "verify plonk witness format error",
        )))?;

    let bytes = if gnark_plonk_verify(id, proof, verify_key, witness) {
        "y".as_bytes().to_vec()
    } else {
        "n".as_bytes().to_vec()
    };
    Ok(PrecompileOutput::new(GAS, bytes.into()))
}
