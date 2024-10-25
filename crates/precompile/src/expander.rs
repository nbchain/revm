use std::{
    fs,
    io::{Cursor, Write},
    path::PathBuf,
};

use arith::FieldSerde;
use ethabi::{ethereum_types::U256, ParamType};
use expander::{
    BN254ConfigSha2, Circuit, Config, GKRScheme, M31ExtConfigSha2, MPIConfig, Verifier,
    SENTINEL_BN254, SENTINEL_M31,
};
use flate2::write::GzDecoder;
use halo2curves::bn256::Fr;
use mersenne31::M31Ext3;
use once_cell::sync::Lazy;
use revm_primitives::{hex, Bytes};
use transcript::Proof;

use crate::{
    Precompile, PrecompileError, PrecompileErrors, PrecompileOutput, PrecompileResult,
    PrecompileWithAddress,
};

static SIDE_CHAIN_DATA_PATH: Lazy<PathBuf> =
    Lazy::new(|| std::env::var("SIDE_CHAIN_DATA_PATH").unwrap().into());
const INDEX_FILE: &str = "index";

pub const VERIFY_EXPANDER: PrecompileWithAddress = PrecompileWithAddress(
    crate::u64_to_address(0xff02),
    Precompile::Standard(verify_expander),
);

const GAS: u64 = 7500;

pub fn verify_expander(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    if gas_limit < GAS {
        return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
    }
    let input = match input[0] {
        0 => input[1..].to_vec(),
        1 => {
            let index_file = SIDE_CHAIN_DATA_PATH.join(INDEX_FILE);
            let data_height = if index_file.exists() {
                let content = fs::read_to_string(&index_file).map_err(|e| {
                    PrecompileErrors::Error(PrecompileError::other(format!(
                        "decode verify expander error:{e}"
                    )))
                })?;
                u64::from_str_radix(&content, 10).map_err(|e| {
                    PrecompileErrors::Error(PrecompileError::other(format!(
                        "decode verify expander error:{e}"
                    )))
                })?
            } else {
                0
            };

            let tokens = ethabi::decode(
                &[ParamType::Uint(256), ParamType::FixedBytes(32)],
                &input[1..],
            )
            .map_err(|e| {
                PrecompileErrors::Error(PrecompileError::other(format!(
                    "decode verify expander error:{e}"
                )))
            })?;
            let height = tokens
                .first()
                .cloned()
                .and_then(|token| token.into_uint())
                .ok_or(PrecompileErrors::Error(PrecompileError::other(
                    "verify expander id format error",
                )))?;
            if height > U256::from(data_height) {
                return Err(PrecompileErrors::Error(PrecompileError::other(format!(
                    "height > data height"
                ))));
            }
            let hash = tokens
                .last()
                .cloned()
                .and_then(|token| token.into_fixed_bytes())
                .ok_or(PrecompileErrors::Error(PrecompileError::other(
                    "verify expander id format error",
                )))?;
            let hash = hex::encode(hash);
            let data_file = SIDE_CHAIN_DATA_PATH.join(hash[0..4].to_string()).join(hash);

            let data = fs::read_to_string(data_file).map_err(|e| {
                PrecompileErrors::Error(PrecompileError::other(format!(
                    "verify expander error:{e}"
                )))
            })?;
            let data = data.strip_prefix("0x").unwrap_or(&data).trim();
            hex::decode(data).map_err(|e| {
                PrecompileErrors::Error(PrecompileError::other(format!(
                    "verify expander hex decode error:{e}"
                )))
            })?
        }
        _ => {
            return Err(PrecompileErrors::Error(PrecompileError::Other(
                String::from("data type format error"),
            )))
        }
    };

    let input = {
        let mut e = GzDecoder::new(Vec::new());
        e.write_all(&input).map_err(|e| {
            PrecompileErrors::Error(PrecompileError::other(format!(
                "verify expander gzdecode write_all error:{e}"
            )))
        })?;
        e.finish().map_err(|e| {
            PrecompileErrors::Error(PrecompileError::other(format!(
                "verify expander gzdecode finish error:{e}"
            )))
        })?
    };
    let tokens = ethabi::decode(
        &[ParamType::Tuple(vec![
            ParamType::Bytes,
            ParamType::Bytes,
            ParamType::Bytes,
        ])],
        &input,
    )
    .map_err(|e| {
        PrecompileErrors::Error(PrecompileError::other(format!(
            "decode verify expander error:{e}"
        )))
    })?;

    let tokens = tokens
        .first()
        .cloned()
        .and_then(|token| token.into_tuple())
        .ok_or(PrecompileErrors::Error(PrecompileError::other(
            "verify expander id format error",
        )))?;

    let circuit_bytes = tokens
        .first()
        .cloned()
        .and_then(|token| token.into_bytes())
        .ok_or(PrecompileErrors::Error(PrecompileError::other(
            "verify expander circuit format error",
        )))?;

    let witness_bytes = tokens
        .get(1)
        .cloned()
        .and_then(|token| token.into_bytes())
        .ok_or(PrecompileErrors::Error(PrecompileError::other(
            "verify expander witness format error",
        )))?;

    let proof_bytes = tokens
        .get(2)
        .cloned()
        .and_then(|token| token.into_bytes())
        .ok_or(PrecompileErrors::Error(PrecompileError::other(
            "verify expander proof format error",
        )))?;

    if circuit_bytes.len() < 40 {
        return Err(PrecompileErrors::Error(PrecompileError::Other(
            String::from("The circuit is not long enough"),
        )));
    }
    let field_bytes = circuit_bytes[8..8 + 32].try_into().unwrap_or_default();
    let ret = match field_bytes {
        SENTINEL_M31 => {
            let mut circuit = Circuit::<M31ExtConfigSha2>::load_circuit_bytes(circuit_bytes)
                .map_err(|e| {
                    PrecompileErrors::Error(PrecompileError::other(format!(
                        "load_circuit_bytes error:{e}"
                    )))
                })?;

            circuit.load_witness_bytes(&witness_bytes).map_err(|e| {
                PrecompileErrors::Error(PrecompileError::other(format!(
                    "load_witness_bytes error:{e}"
                )))
            })?;

            let config = Config::<M31ExtConfigSha2>::new(GKRScheme::Vanilla, MPIConfig::new());
            let verifier = Verifier::new(&config);

            let mut cursor = Cursor::new(proof_bytes);
            let proof = Proof::deserialize_from(&mut cursor).map_err(|e| {
                PrecompileErrors::Error(PrecompileError::other(format!("format proof error:{e}")))
            })?;
            let claimed_v = M31Ext3::deserialize_from(&mut cursor).map_err(|e| {
                PrecompileErrors::Error(PrecompileError::other(format!("format claimed error:{e}")))
            })?;
            verifier.verify(&mut circuit, &claimed_v, &proof)
        }
        SENTINEL_BN254 => {
            let mut circuit = Circuit::<BN254ConfigSha2>::load_circuit_bytes(circuit_bytes)
                .map_err(|e| {
                    PrecompileErrors::Error(PrecompileError::other(format!(
                        "load_circuit_bytes error:{e}"
                    )))
                })?;

            circuit.load_witness_bytes(&witness_bytes).map_err(|e| {
                PrecompileErrors::Error(PrecompileError::other(format!(
                    "load_witness_bytes error:{e}"
                )))
            })?;

            let config = Config::<BN254ConfigSha2>::new(GKRScheme::Vanilla, MPIConfig::new());
            let verifier = Verifier::new(&config);

            let mut cursor = Cursor::new(proof_bytes);
            let proof = Proof::deserialize_from(&mut cursor).map_err(|e| {
                PrecompileErrors::Error(PrecompileError::other(format!("format proof error:{e}")))
            })?;
            let claimed_v = Fr::deserialize_from(&mut cursor).map_err(|e| {
                PrecompileErrors::Error(PrecompileError::other(format!("format claimed error:{e}")))
            })?;
            verifier.verify(&mut circuit, &claimed_v, &proof)
        }
        _ => {
            return Err(PrecompileErrors::Error(PrecompileError::Other(format!(
                "Unknown field type. Field byte value: {:?}",
                field_bytes
            ))));
        }
    };

    let bytes = if ret {
        "y".as_bytes().to_vec()
    } else {
        "n".as_bytes().to_vec()
    };

    Ok(PrecompileOutput::new(GAS, bytes.into()))
}
