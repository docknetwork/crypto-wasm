use crate::{
    bound_check::{BppSetupParams, SmcParams, SmcParamsAndSk},
    legosnark::{LegoProvingKey, LegoVerifyingKey},
    utils::{is_positive_safe_integer, set_panic_hook},
    G1Affine,
};
use ark_bls12_381::Bls12_381;
use js_sys::Uint8Array;
use proof_system::prelude;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
use zeroize::Zeroize;

pub(crate) type BoundCheckLegoProverStmt =
    prelude::bound_check_legogroth16::BoundCheckLegoGroth16Prover<Bls12_381>;
pub(crate) type BoundCheckLegoVerifierStmt =
    prelude::bound_check_legogroth16::BoundCheckLegoGroth16Verifier<Bls12_381>;
pub(crate) type BoundCheckBppStmt = prelude::bound_check_bpp::BoundCheckBpp<G1Affine>;
pub(crate) type BoundCheckSmcStmt = prelude::bound_check_smc::BoundCheckSmc<Bls12_381>;

// For bound check statements using set-membership check based range proof with keyed verification
pub(crate) type BoundCheckSmcProverStmt =
    prelude::bound_check_smc_with_kv::BoundCheckSmcWithKVProver<Bls12_381>;
pub(crate) type BoundCheckSmcVerifierStmt =
    prelude::bound_check_smc_with_kv::BoundCheckSmcWithKVVerifier<Bls12_381>;

/// If `uncompressed` is true, expects the legosnark proving key to be in uncompressed form else
/// it should be compressed.
#[wasm_bindgen(js_name = generateBoundCheckLegoProverStatement)]
pub fn generate_bound_check_lego_prover_statement(
    min: js_sys::Number,
    max: js_sys::Number,
    snark_pk: Uint8Array,
    uncompressed_public_params: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let (min, max) = get_valid_min_max(min, max)?;
    let snark_pk = if uncompressed_public_params {
        obj_from_uint8array_uncompressed!(LegoProvingKey, snark_pk, "LegoProvingKey")
    } else {
        obj_from_uint8array!(LegoProvingKey, snark_pk, false, "LegoProvingKey")
    };
    let statement =
        BoundCheckLegoProverStmt::new_statement_from_params::<G1Affine>(min, max, snark_pk)
            .map_err(|e| {
                JsValue::from(&format!(
                    "Creating statement for BoundCheckLegoProver returned error: {:?}",
                    e
                ))
            })?;
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "BoundCheckLegoProverStmt"
    ))
}

#[wasm_bindgen(js_name = generateBoundCheckLegoProverStatementFromParamRefs)]
pub fn generate_bound_check_lego_prover_statement_from_param_refs(
    min: js_sys::Number,
    max: js_sys::Number,
    snark_pk: usize,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let (min, max) = get_valid_min_max(min, max)?;
    let statement =
        BoundCheckLegoProverStmt::new_statement_from_params_ref::<G1Affine>(min, max, snark_pk)
            .map_err(|e| {
                JsValue::from(&format!(
                    "Creating statement for BoundCheckLegoProver returned error: {:?}",
                    e
                ))
            })?;
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "BoundCheckLegoProverStmt"
    ))
}

/// If `uncompressed` is true, expects the legosnark verifying key to be in uncompressed form else
/// it should be compressed.
#[wasm_bindgen(js_name = generateBoundCheckLegoVerifierStatement)]
pub fn generate_bound_check_lego_verifier_statement(
    min: js_sys::Number,
    max: js_sys::Number,
    snark_vk: Uint8Array,
    uncompressed_public_params: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let (min, max) = get_valid_min_max(min, max)?;
    let snark_vk = if uncompressed_public_params {
        obj_from_uint8array_uncompressed!(LegoVerifyingKey, snark_vk, "LegoVerifyingKey")
    } else {
        obj_from_uint8array!(LegoVerifyingKey, snark_vk, false, "LegoVerifyingKey")
    };
    let statement =
        BoundCheckLegoVerifierStmt::new_statement_from_params::<G1Affine>(min, max, snark_vk)
            .map_err(|e| {
                JsValue::from(&format!(
                    "Creating statement for BoundCheckLegoVerifier returned error: {:?}",
                    e
                ))
            })?;
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "BoundCheckLegoVerifierStmt"
    ))
}

#[wasm_bindgen(js_name = generateBoundCheckLegoVerifierStatementFromParamRefs)]
pub fn generate_bound_check_lego_verifier_statement_from_param_refs(
    min: js_sys::Number,
    max: js_sys::Number,
    snark_vk: usize,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let (min, max) = get_valid_min_max(min, max)?;
    let statement =
        BoundCheckLegoVerifierStmt::new_statement_from_params_ref::<G1Affine>(min, max, snark_vk)
            .map_err(|e| {
            JsValue::from(&format!(
                "Creating statement for BoundCheckLegoVerifier returned error: {:?}",
                e
            ))
        })?;
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "BoundCheckLegoVerifierStmt"
    ))
}

#[wasm_bindgen(js_name = generateBoundCheckBppStatement)]
pub fn generate_bound_check_bpp_statement(
    min: js_sys::Number,
    max: js_sys::Number,
    params: Uint8Array,
    uncompressed_public_params: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let (min, max) = get_valid_min_max(min, max)?;
    let params = if uncompressed_public_params {
        obj_from_uint8array_uncompressed!(BppSetupParams, params, "Bulletproofs++SetupParams")
    } else {
        obj_from_uint8array!(BppSetupParams, params, false, "Bulletproofs++SetupParams")
    };
    let statement = BoundCheckBppStmt::new_statement_from_params::<Bls12_381>(min, max, params)
        .map_err(|e| {
            JsValue::from(&format!(
                "Creating statement for BoundCheckBpp returned error: {:?}",
                e
            ))
        })?;
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "BoundCheckBppStmt"
    ))
}

#[wasm_bindgen(js_name = generateBoundCheckBppStatementFromParamRefs)]
pub fn generate_bound_check_bpp_statement_from_param_refs(
    min: js_sys::Number,
    max: js_sys::Number,
    params: usize,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let (min, max) = get_valid_min_max(min, max)?;
    let statement = BoundCheckBppStmt::new_statement_from_params_ref::<Bls12_381>(min, max, params)
        .map_err(|e| {
            JsValue::from(&format!(
                "Creating statement for BoundCheckBpp returned error: {:?}",
                e
            ))
        })?;
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "BoundCheckBppStmt"
    ))
}

#[wasm_bindgen(js_name = generateBoundCheckSmcStatement)]
pub fn generate_bound_check_smc_statement(
    min: js_sys::Number,
    max: js_sys::Number,
    params: Uint8Array,
    uncompressed_params: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let (min, max) = get_valid_min_max(min, max)?;
    let params = if uncompressed_params {
        obj_from_uint8array_uncompressed!(SmcParams, params, "SmcParamsAndCommitmentKey")
    } else {
        obj_from_uint8array!(SmcParams, params, false, "SmcParamsAndCommitmentKey")
    };
    let statement = BoundCheckSmcStmt::new_statement_from_params::<G1Affine>(min, max, params)
        .map_err(|e| {
            JsValue::from(&format!(
                "Creating statement for BoundCheckSmc returned error: {:?}",
                e
            ))
        })?;
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "BoundCheckSmcStmt"
    ))
}

#[wasm_bindgen(js_name = generateBoundCheckSmcStatementFromParamRefs)]
pub fn generate_bound_check_smc_statement_from_param_refs(
    min: js_sys::Number,
    max: js_sys::Number,
    params: usize,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let (min, max) = get_valid_min_max(min, max)?;
    let statement = BoundCheckSmcStmt::new_statement_from_params_ref::<G1Affine>(min, max, params)
        .map_err(|e| {
            JsValue::from(&format!(
                "Creating statement for BoundCheckSmc returned error: {:?}",
                e
            ))
        })?;
    Ok(obj_to_uint8array_uncompressed!(&statement, "BoundCheckSmc"))
}

#[wasm_bindgen(js_name = generateBoundCheckSmcWithKVProverStatement)]
pub fn generate_bound_check_smc_with_kv_prover_statement(
    min: js_sys::Number,
    max: js_sys::Number,
    params: Uint8Array,
    uncompressed_public_params: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let (min, max) = get_valid_min_max(min, max)?;
    let params = if uncompressed_public_params {
        obj_from_uint8array_uncompressed!(SmcParams, params, "SmcParamsAndCommitmentKey")
    } else {
        obj_from_uint8array!(SmcParams, params, false, "SmcParamsAndCommitmentKey")
    };
    let statement = BoundCheckSmcProverStmt::new_statement_from_params::<G1Affine>(
        min, max, params,
    )
    .map_err(|e| {
        JsValue::from(&format!(
            "Creating statement for BoundCheckSmcProver returned error: {:?}",
            e
        ))
    })?;
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "BoundCheckSmcProverStmt"
    ))
}

#[wasm_bindgen(js_name = generateBoundCheckSmcWithKVProverStatementFromParamRefs)]
pub fn generate_bound_check_smc_with_kv_prover_statement_from_param_refs(
    min: js_sys::Number,
    max: js_sys::Number,
    params: usize,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let (min, max) = get_valid_min_max(min, max)?;
    let statement =
        BoundCheckSmcProverStmt::new_statement_from_params_ref::<G1Affine>(min, max, params)
            .map_err(|e| {
                JsValue::from(&format!(
                    "Creating statement for BoundCheckSmcProver returned error: {:?}",
                    e
                ))
            })?;
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "BoundCheckSmcProverStmt"
    ))
}

#[wasm_bindgen(js_name = generateBoundCheckSmcWithKVVerifierStatement)]
pub fn generate_bound_check_smc_with_kv_verifier_statement(
    min: js_sys::Number,
    max: js_sys::Number,
    params: Uint8Array,
    uncompressed_public_params: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let (min, max) = get_valid_min_max(min, max)?;
    let params = if uncompressed_public_params {
        obj_from_uint8array_uncompressed!(
            SmcParamsAndSk,
            params,
            "SmcParamsAndCommitmentKeyAndSecretKey"
        )
    } else {
        obj_from_uint8array!(
            SmcParamsAndSk,
            params,
            false,
            "SmcParamsAndCommitmentKeyAndSecretKey"
        )
    };
    let statement =
        BoundCheckSmcVerifierStmt::new_statement_from_params::<G1Affine>(min, max, params)
            .map_err(|e| {
                JsValue::from(&format!(
                    "Creating statement for BoundCheckSmcVerifier returned error: {:?}",
                    e
                ))
            })?;
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "BoundCheckSmcVerifierStmt"
    ))
}

#[wasm_bindgen(js_name = generateBoundCheckSmcWithKVVerifierStatementFromParamRefs)]
pub fn generate_bound_check_smc_with_kv_verifier_statement_from_param_refs(
    min: js_sys::Number,
    max: js_sys::Number,
    params: usize,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let (min, max) = get_valid_min_max(min, max)?;
    let statement =
        BoundCheckSmcVerifierStmt::new_statement_from_params_ref::<G1Affine>(min, max, params)
            .map_err(|e| {
                JsValue::from(&format!(
                    "Creating statement for BoundCheckSmcVerifier returned error: {:?}",
                    e
                ))
            })?;
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "BoundCheckSmcVerifierStmt"
    ))
}

pub fn get_valid_min_max(min: js_sys::Number, max: js_sys::Number) -> Result<(u64, u64), JsValue> {
    if !(is_positive_safe_integer(&min) && is_positive_safe_integer(&max)) {
        return Err(JsValue::from(&format!(
            "min and max should be safe positive integers but instead found {:?}, {:?}",
            min, max
        )));
    }
    let min = min.value_of() as u64;
    let max = max.value_of() as u64;
    Ok((min, max))
}
