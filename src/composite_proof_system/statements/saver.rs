use crate::{
    saver::{ChunkedCommGens, EncGens, SaverEk, SaverSnarkPk, SaverSnarkVk},
    utils::set_panic_hook,
};
use ark_bls12_381::Bls12_381;
use js_sys::Uint8Array;
use proof_system::prelude;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
use zeroize::Zeroize;

pub(crate) type SaverProverStmt = prelude::saver::SaverProver<Bls12_381>;
pub(crate) type SaverVerifierStmt = prelude::saver::SaverVerifier<Bls12_381>;

#[wasm_bindgen(js_name = generateSaverProverStatement)]
pub fn generate_saver_prover_statement(
    chunk_bit_size: u8,
    enc_gens: Uint8Array,
    chunked_comm_gens: Uint8Array,
    encryption_key: Uint8Array,
    snark_pk: Uint8Array,
    uncompressed_public_params: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let snark_pk = if uncompressed_public_params {
        obj_from_uint8array_uncompressed!(SaverSnarkPk, snark_pk, "SaverSnarkPk")
    } else {
        obj_from_uint8array!(SaverSnarkPk, snark_pk, false, "SaverSnarkPk")
    };
    let (enc_gens, chunked_comm_gens, ek) = parse_saver_statement_input(
        enc_gens,
        chunked_comm_gens,
        encryption_key,
        uncompressed_public_params,
    )?;
    let statement = SaverProverStmt::new_statement_from_params(
        chunk_bit_size,
        enc_gens,
        chunked_comm_gens,
        ek,
        snark_pk,
    )
    .map_err(|e| {
        JsValue::from(&format!(
            "Creating statement for SaverProver returned error: {:?}",
            e
        ))
    })?;
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "SaverProverStmt"
    ))
}

#[wasm_bindgen(js_name = generateSaverProverStatementFromParamRefs)]
pub fn generate_saver_prover_statement_from_param_refs(
    chunk_bit_size: u8,
    enc_gens: usize,
    chunked_comm_gens: usize,
    encryption_key: usize,
    snark_pk: usize,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let statement = SaverProverStmt::new_statement_from_params_ref(
        chunk_bit_size,
        enc_gens,
        chunked_comm_gens,
        encryption_key,
        snark_pk,
    );
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "SaverProverStmt"
    ))
}

#[wasm_bindgen(js_name = generateSaverVerifierStatement)]
pub fn generate_saver_verifier_statement(
    chunk_bit_size: u8,
    enc_gens: Uint8Array,
    chunked_comm_gens: Uint8Array,
    encryption_key: Uint8Array,
    snark_vk: Uint8Array,
    uncompressed_public_params: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let snark_vk = if uncompressed_public_params {
        obj_from_uint8array_uncompressed!(SaverSnarkVk, snark_vk, "SaverSnarkVk")
    } else {
        obj_from_uint8array!(SaverSnarkVk, snark_vk, false, "SaverSnarkVk")
    };
    let (enc_gens, chunked_comm_gens, ek) = parse_saver_statement_input(
        enc_gens,
        chunked_comm_gens,
        encryption_key,
        uncompressed_public_params,
    )?;
    let statement = SaverVerifierStmt::new_statement_from_params(
        chunk_bit_size,
        enc_gens,
        chunked_comm_gens,
        ek,
        snark_vk,
    )
    .map_err(|e| {
        JsValue::from(&format!(
            "Creating statement for SaverVerifier returned error: {:?}",
            e
        ))
    })?;
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "SaverVerifierStatement"
    ))
}

#[wasm_bindgen(js_name = generateSaverVerifierStatementFromParamRefs)]
pub fn generate_saver_verifier_statement_from_param_refs(
    chunk_bit_size: u8,
    enc_gens: usize,
    chunked_comm_gens: usize,
    encryption_key: usize,
    snark_vk: usize,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let statement = SaverVerifierStmt::new_statement_from_params_ref(
        chunk_bit_size,
        enc_gens,
        chunked_comm_gens,
        encryption_key,
        snark_vk,
    );
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "SaverVerifierStatement"
    ))
}

fn parse_saver_statement_input(
    enc_gens: Uint8Array,
    chunked_comm_gens: Uint8Array,
    encryption_key: Uint8Array,
    uncompressed_public_params: bool,
) -> Result<(EncGens, ChunkedCommGens, SaverEk), JsValue> {
    let (enc_gens, chunked_comm_gens, ek) = if uncompressed_public_params {
        (
            obj_from_uint8array_uncompressed!(EncGens, enc_gens, "EncryptionGenerators"),
            obj_from_uint8array_uncompressed!(
                ChunkedCommGens,
                chunked_comm_gens,
                "ChunkedCommitmentGenerators"
            ),
            obj_from_uint8array_uncompressed!(SaverEk, encryption_key, "SaverEk"),
        )
    } else {
        (
            obj_from_uint8array!(EncGens, enc_gens, false, "EncryptionGenerators"),
            obj_from_uint8array!(
                ChunkedCommGens,
                chunked_comm_gens,
                false,
                "ChunkedCommitmentGenerators"
            ),
            obj_from_uint8array!(SaverEk, encryption_key, false, "SaverEk"),
        )
    };
    Ok((enc_gens, chunked_comm_gens, ek))
}
