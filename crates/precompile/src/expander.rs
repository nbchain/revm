use std::{
    fs,
    io::{Cursor, Write},
    panic,
    path::PathBuf,
};

use anyhow::Result;
use arith::{Field, FieldSerde};
use circuit::Circuit;
use config::{
    BN254ConfigSha2, Config, GF2ExtConfigSha2, GKRConfig, GKRScheme, M31ExtConfigSha2, MPIConfig,
    SENTINEL_BN254, SENTINEL_GF2, SENTINEL_M31,
};
use ethabi::{encode, ethereum_types::U256, ParamType, Token};
use flate2::write::GzDecoder;
use gkr::Verifier;
use once_cell::sync::Lazy;
use revm_primitives::{hex, Bytes};
use transcript::Proof;

use crate::{
    Precompile, PrecompileError, PrecompileErrors, PrecompileOutput, PrecompileResult,
    PrecompileWithAddress,
};

static SIDE_CHAIN_DATA_PATH: Lazy<PathBuf> = Lazy::new(|| {
    std::env::var("SIDE_CHAIN_DATA_PATH")
        .unwrap_or("/tmp/side_chain_data".to_string())
        .into()
});
const INDEX_FILE: &str = "index";

pub const VERIFY_EXPANDER: PrecompileWithAddress = PrecompileWithAddress(
    crate::u64_to_address(0xff02),
    Precompile::Standard(verify_expander),
);

const GAS: u64 = 7500;

pub enum ErrorCode {
    EVReadIndexErr = 1000022,
    EVParseIndexErr = 1000023,
    EVUnpackInputErr = 1000024,
    EVParseInputHeightErr = 1000025,
    EVInputGreaterThanIndexHeightErr = 1000026,
    EVParseInputHashErr = 1000027,
    EVReadSideChainDataErr = 1000028,
    EVGzipDecompressErr = 1000030,
    EVInvalidInput = 1000039,
    EVOtherErr = 1000040,
}

pub fn verify_expander(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    if gas_limit < GAS {
        return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
    }
    let input = match input[0] {
        0 => input[1..].to_vec(),
        1 => {
            let input = input[1..].to_vec();
            let mut e = GzDecoder::new(Vec::new());
            e.write_all(&input).map_err(|_| {
                PrecompileErrors::Error(PrecompileError::other(format!(
                    "{}",
                    ErrorCode::EVGzipDecompressErr as u32
                )))
            })?;
            e.finish().map_err(|_| {
                PrecompileErrors::Error(PrecompileError::other(format!(
                    "{}",
                    ErrorCode::EVGzipDecompressErr as u32
                )))
            })?
        }
        2 => {
            let index_file = SIDE_CHAIN_DATA_PATH.join(INDEX_FILE);
            let data_height = if index_file.exists() {
                let content = fs::read_to_string(&index_file).map_err(|_| {
                    PrecompileErrors::Error(PrecompileError::other(format!(
                        "{}",
                        ErrorCode::EVReadIndexErr as u32
                    )))
                })?;
                u64::from_str_radix(&content, 10).map_err(|_| {
                    PrecompileErrors::Error(PrecompileError::other(format!(
                        "{}",
                        ErrorCode::EVParseIndexErr as u32
                    )))
                })?
            } else {
                0
            };

            let tokens = ethabi::decode(
                &[ParamType::Uint(256), ParamType::FixedBytes(32)],
                &input[1..],
            )
                .map_err(|_| {
                    PrecompileErrors::Error(PrecompileError::other(format!(
                        "{}",
                        ErrorCode::EVUnpackInputErr as u32
                    )))
                })?;

            let height = tokens
                .first()
                .cloned()
                .and_then(|token| token.into_uint())
                .ok_or(PrecompileErrors::Error(PrecompileError::other(format!(
                    "{}",
                    ErrorCode::EVParseInputHeightErr as u32
                ))))?;

            if height > U256::from(data_height) {
                return Err(PrecompileErrors::Error(PrecompileError::other(format!(
                    "{}",
                    ErrorCode::EVInputGreaterThanIndexHeightErr as u32
                ))));
            }

            let hash = tokens
                .last()
                .cloned()
                .and_then(|token| token.into_fixed_bytes())
                .ok_or(PrecompileErrors::Error(PrecompileError::other(format!(
                    "{}",
                    ErrorCode::EVParseInputHashErr as u32
                ))))?;

            let hash = hex::encode(hash);
            let data_file = SIDE_CHAIN_DATA_PATH.join(hash[0..4].to_string()).join(hash);

            fs::read(data_file).map_err(|_| {
                PrecompileErrors::Error(PrecompileError::other(format!(
                    "{}",
                    ErrorCode::EVReadSideChainDataErr as u32
                )))
            })?
        }
        _ => {
            return Err(PrecompileErrors::Error(PrecompileError::other(format!(
                "{}",
                ErrorCode::EVInvalidInput as u32
            ))))
        }
    };

    let tokens = ethabi::decode(
        &[ParamType::Tuple(vec![
            ParamType::Bytes,
            ParamType::Bytes,
            ParamType::Bytes,
        ])],
        &input,
    )
        .map_err(|_| {
            PrecompileErrors::Error(PrecompileError::other(format!(
                "{}",
                ErrorCode::EVOtherErr as u32
            )))
        })?;

    let tokens = tokens
        .first()
        .cloned()
        .and_then(|token| token.into_tuple())
        .ok_or(PrecompileErrors::Error(PrecompileError::other(format!(
            "{}",
            ErrorCode::EVOtherErr as u32
        ))))?;

    let circuit_bytes = tokens
        .first()
        .cloned()
        .and_then(|token| token.into_bytes())
        .ok_or(PrecompileErrors::Error(PrecompileError::other(format!(
            "{}",
            ErrorCode::EVOtherErr as u32
        ))))?;

    let witness_bytes = tokens
        .get(1)
        .cloned()
        .and_then(|token| token.into_bytes())
        .ok_or(PrecompileErrors::Error(PrecompileError::other(format!(
            "{}",
            ErrorCode::EVOtherErr as u32
        ))))?;

    let proof_bytes = tokens
        .get(2)
        .cloned()
        .and_then(|token| token.into_bytes())
        .ok_or(PrecompileErrors::Error(PrecompileError::other(format!(
            "{}",
            ErrorCode::EVOtherErr as u32
        ))))?;

    if circuit_bytes.len() < 40 {
        return Err(PrecompileErrors::Error(PrecompileError::other(format!(
            "{}",
            ErrorCode::EVOtherErr as u32
        ))));
    }
    let field_bytes = circuit_bytes[8..8 + 32].try_into().unwrap_or_default();
    let ret = panic::catch_unwind(|| match field_bytes {
        SENTINEL_M31 => run_verify::<M31ExtConfigSha2>(circuit_bytes, witness_bytes, proof_bytes),
        SENTINEL_BN254 => run_verify::<BN254ConfigSha2>(circuit_bytes, witness_bytes, proof_bytes),
        SENTINEL_GF2 => run_verify::<GF2ExtConfigSha2>(circuit_bytes, witness_bytes, proof_bytes),
        _ => {
            return Err(format!(
                "Unknown field type. Field byte value: {:?}",
                field_bytes
            ));
        }
    })
        .map_err(|_| {
            PrecompileErrors::Error(PrecompileError::other(format!(
                "{}",
                ErrorCode::EVOtherErr as u32
            )))
        })?
        .map_err(|_| {
            PrecompileErrors::Error(PrecompileError::other(format!(
                "{}",
                ErrorCode::EVOtherErr as u32
            )))
        })?;

    Ok(PrecompileOutput::new(
        GAS,
        encode(&[Token::Bool(ret)]).into(),
    ))
}

fn load_proof_and_claimed_v<F: Field + FieldSerde>(bytes: &[u8]) -> Result<(Proof, F), String> {
    let mut cursor = Cursor::new(bytes);

    let proof =
        Proof::deserialize_from(&mut cursor).map_err(|_| String::from("format proof error"))?;
    let claimed_v =
        F::deserialize_from(&mut cursor).map_err(|_| String::from("format claimed error"))?;

    Ok((proof, claimed_v))
}

fn run_verify<C: GKRConfig>(
    circuit_bytes: Vec<u8>,
    witness_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
) -> Result<bool, String> {
    let mut circuit = Circuit::<C>::load_circuit_bytes(circuit_bytes)
        .map_err(|_| String::from("format claimed error "))?;
    circuit.load_witness_bytes(&witness_bytes, false);

    let config = Config::<C>::new(GKRScheme::Vanilla, MPIConfig::new());
    let verifier = Verifier::new(&config);

    let (proof, claimed_v) =
        load_proof_and_claimed_v(&proof_bytes).expect("Unable to deserialize proof.");

    let public_input = circuit.public_input.clone();
    Ok(verifier.verify(&mut circuit, &public_input, &claimed_v, &proof))
}