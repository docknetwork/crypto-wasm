use crate::{
    legosnark::{LegoProvingKey, LegoVerifyingKey},
    r1cs::gen_r1cs,
    utils::{js_array_to_fr_vec, set_panic_hook},
};
use ark_bls12_381::Bls12_381;
use js_sys::Uint8Array;
use proof_system::prelude;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

use zeroize::Zeroize;

pub(crate) type R1CSCircomProverStmt = prelude::r1cs_legogroth16::R1CSCircomProver<Bls12_381>;
pub(crate) type R1CSCircomVerifierStmt = prelude::r1cs_legogroth16::R1CSCircomVerifier<Bls12_381>;

#[wasm_bindgen(js_name = generateR1CSCircomProverStatement)]
pub fn generate_r1cs_circom_prover_statement(
    curve_name: &str,
    num_public: u32,
    num_private: u32,
    constraints: js_sys::Array,
    wasm_bytes: Uint8Array,
    snark_pk: Uint8Array,
    uncompressed_public_params: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let r = gen_r1cs(curve_name, num_public, num_private, constraints)?;
    let wasm_bytes = wasm_bytes.to_vec();
    let snark_pk = if uncompressed_public_params {
        obj_from_uint8array_uncompressed!(LegoProvingKey, snark_pk, "LegoProvingKey")
    } else {
        obj_from_uint8array!(LegoProvingKey, snark_pk, false, "LegoProvingKey")
    };
    let statement = R1CSCircomProverStmt::new_statement_from_params(r, wasm_bytes, snark_pk)
        .map_err(|e| {
            JsValue::from(&format!(
                "Creating statement for R1CSCircomProver returned error: {:?}",
                e
            ))
        })?;
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "R1CSCircomProverStmt"
    ))
}

#[wasm_bindgen(js_name = generateR1CSCircomProverStatementFromParamRefs)]
pub fn generate_r1cs_circom_prover_statement_from_param_refs(
    r1cs: usize,
    wasm_bytes: usize,
    snark_pk: usize,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let statement = R1CSCircomProverStmt::new_statement_from_params_ref(r1cs, wasm_bytes, snark_pk)
        .map_err(|e| {
            JsValue::from(&format!(
                "Creating statement for R1CSCircomProver returned error: {:?}",
                e
            ))
        })?;
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "R1CSCircomProverStmt"
    ))
}

#[wasm_bindgen(js_name = generateR1CSCircomVerifierStatement)]
pub fn generate_r1cs_circom_verifier_statement(
    public_inputs: js_sys::Array,
    snark_vk: Uint8Array,
    uncompressed_public_params: bool,
) -> Result<Uint8Array, JsValue> {
    let public_inputs = js_array_to_fr_vec(&public_inputs)?;
    set_panic_hook();
    let snark_vk = if uncompressed_public_params {
        obj_from_uint8array_uncompressed!(LegoVerifyingKey, snark_vk, "LegoVerifyingKey")
    } else {
        obj_from_uint8array!(LegoVerifyingKey, snark_vk, false, "LegoVerifyingKey")
    };
    let statement = R1CSCircomVerifierStmt::new_statement_from_params(public_inputs, snark_vk)
        .map_err(|e| {
            JsValue::from(&format!(
                "Creating statement for R1CSCircomVerifier returned error: {:?}",
                e
            ))
        })?;
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "R1CSCircomVerifierStmt"
    ))
}

#[wasm_bindgen(js_name = generateR1CSCircomVerifierStatementFromParamRefs)]
pub fn generate_r1cs_circom_verifier_statement_from_param_refs(
    public_inputs: usize,
    snark_vk: usize,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let statement = R1CSCircomVerifierStmt::new_statement_from_params_ref(public_inputs, snark_vk)
        .map_err(|e| {
            JsValue::from(&format!(
                "Creating statement for R1CSCircomVerifier returned error: {:?}",
                e
            ))
        })?;
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "R1CSCircomVerifierStmt"
    ))
}
