use crate::{
    accumulator::{
        common::{deserialize_params, deserialize_public_key, AccumSk},
        vb_accumulator::{MembershipPrk, NonMembershipPrk},
    },
    utils::{g1_affine_from_uint8_array, set_panic_hook},
    G1Affine,
};
use ark_bls12_381::Bls12_381;
use js_sys::Uint8Array;
use proof_system::prelude;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
use zeroize::Zeroize;

pub(crate) type AccumMemStmt = prelude::accumulator::VBAccumulatorMembership<Bls12_381>;
pub(crate) type AccumNonMemStmt = prelude::accumulator::VBAccumulatorNonMembership<Bls12_381>;

pub(crate) type KBUniAccumMemProverStmt =
    prelude::accumulator::cdh::KBUniversalAccumulatorMembershipCDHProver<Bls12_381>;
pub(crate) type KBUniAccumMemVerifierStmt =
    prelude::accumulator::cdh::KBUniversalAccumulatorMembershipCDHVerifier<Bls12_381>;
pub(crate) type KBUniAccumNonMemProverStmt =
    prelude::accumulator::cdh::KBUniversalAccumulatorNonMembershipCDHProver<Bls12_381>;
pub(crate) type KBUniAccumNonMemVerifierStmt =
    prelude::accumulator::cdh::KBUniversalAccumulatorNonMembershipCDHVerifier<Bls12_381>;

pub(crate) type AccumMemStmtKV =
    prelude::accumulator::keyed_verification::VBAccumulatorMembershipKV<G1Affine>;
pub(crate) type AccumMemStmtKVFullVerifier =
    prelude::accumulator::keyed_verification::VBAccumulatorMembershipKVFullVerifier<G1Affine>;

pub(crate) type KBAccumMemStmtKV =
    prelude::accumulator::keyed_verification::KBUniversalAccumulatorMembershipKV<G1Affine>;
pub(crate) type KBAccumMemStmtKVFullVerifier =
    prelude::accumulator::keyed_verification::KBUniversalAccumulatorMembershipKVFullVerifier<
        G1Affine,
    >;

pub(crate) type KBAccumNonMemStmtKV =
    prelude::accumulator::keyed_verification::KBUniversalAccumulatorNonMembershipKV<G1Affine>;
pub(crate) type KBAccumNonMemStmtKVFullVerifier =
    prelude::accumulator::keyed_verification::KBUniversalAccumulatorNonMembershipKVFullVerifier<
        G1Affine,
    >;

#[wasm_bindgen(js_name = generateAccumulatorMembershipStatement)]
pub fn generate_accumulator_membership_statement(
    params: Uint8Array,
    public_key: Uint8Array,
    proving_key: Uint8Array,
    accumulated: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let pk = deserialize_public_key(public_key)?;
    let params = deserialize_params(params)?;
    let prk = obj_from_uint8array!(MembershipPrk, proving_key, false, "MembershipPrk");
    let statement = AccumMemStmt::new_statement_from_params(params, pk, prk, accumulated);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "AccumMemStatement"
    ))
}

#[wasm_bindgen(js_name = generateAccumulatorMembershipStatementFromParamRefs)]
pub fn generate_accumulator_membership_statement_from_param_refs(
    params: usize,
    public_key: usize,
    proving_key: usize,
    accumulated: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let statement =
        AccumMemStmt::new_statement_from_params_ref(params, public_key, proving_key, accumulated);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "AccumMemStatement"
    ))
}

#[wasm_bindgen(js_name = generateAccumulatorNonMembershipStatement)]
pub fn generate_accumulator_non_membership_statement(
    params: Uint8Array,
    public_key: Uint8Array,
    proving_key: Uint8Array,
    accumulated: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let pk = deserialize_public_key(public_key)?;
    let params = deserialize_params(params)?;
    let prk = obj_from_uint8array!(NonMembershipPrk, proving_key, false, "NonMembershipPrk");
    let statement = AccumNonMemStmt::new_statement_from_params(params, pk, prk, accumulated);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "AccumNonMemStatement"
    ))
}

#[wasm_bindgen(js_name = generateAccumulatorNonMembershipStatementFromParamRefs)]
pub fn generate_accumulator_non_membership_statement_from_param_refs(
    params: usize,
    public_key: usize,
    proving_key: usize,
    accumulated: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let statement = AccumNonMemStmt::new_statement_from_params_ref(
        params,
        public_key,
        proving_key,
        accumulated,
    );
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "AccumNonMemStatement"
    ))
}

#[wasm_bindgen(js_name = generateAccumulatorKVMembershipStatement)]
pub fn generate_accumulator_kv_membership_statement(
    accumulated: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let statement = AccumMemStmtKV::new::<Bls12_381>(accumulated);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "AccumMemStmtKV"
    ))
}

#[wasm_bindgen(js_name = generateAccumulatorKVFullVerifierMembershipStatement)]
pub fn generate_accumulator_kv_full_verifier_membership_statement(
    secret_key: Uint8Array,
    accumulated: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let sk = obj_from_uint8array!(AccumSk, secret_key, true, "AccumSk");
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let statement = AccumMemStmtKVFullVerifier::new::<Bls12_381>(accumulated, sk);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "AccumMemStmtKVFullVerifier"
    ))
}

#[wasm_bindgen(js_name = generateKBUniversalAccumulatorKVMembershipStatement)]
pub fn generate_kb_universal_accumulator_kv_membership_statement(
    accumulated: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let statement = KBAccumMemStmtKV::new::<Bls12_381>(accumulated);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "KBAccumMemStmtKV"
    ))
}

#[wasm_bindgen(js_name = generateKBUniversalAccumulatorKVFullVerifierMembershipStatement)]
pub fn generate_kb_universal_accumulator_kv_full_verifier_membership_statement(
    secret_key: Uint8Array,
    accumulated: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let sk = obj_from_uint8array!(AccumSk, secret_key, true, "AccumSk");
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let statement = KBAccumMemStmtKVFullVerifier::new::<Bls12_381>(accumulated, sk);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "KBAccumMemStmtKVFullVerifier"
    ))
}

#[wasm_bindgen(js_name = generateKBUniversalAccumulatorKVNonMembershipStatement)]
pub fn generate_kb_universal_accumulator_kv_non_membership_statement(
    accumulated: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let statement = KBAccumNonMemStmtKV::new::<Bls12_381>(accumulated);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "KBAccumNonMemStmtKV"
    ))
}

#[wasm_bindgen(js_name = generateKBUniversalAccumulatorKVFullVerifierNonMembershipStatement)]
pub fn generate_kb_universal_accumulator_kv_full_verifier_non_membership_statement(
    secret_key: Uint8Array,
    accumulated: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let sk = obj_from_uint8array!(AccumSk, secret_key, true, "AccumSk");
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let statement = KBAccumNonMemStmtKVFullVerifier::new::<Bls12_381>(accumulated, sk);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "KBAccumNonMemStmtKVFullVerifier"
    ))
}

#[wasm_bindgen(js_name = generateKBUniversalAccumulatorMembershipProverStatement)]
pub fn generate_kb_universal_accumulator_membership_prover_statement(
    accumulated: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let statement = KBUniAccumMemProverStmt::new(accumulated);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "KBUniAccumMemProverStmt"
    ))
}

#[wasm_bindgen(js_name = generateKBUniversalAccumulatorMembershipVerifierStatement)]
pub fn generate_kb_universal_accumulator_membership_verifier_statement(
    params: Uint8Array,
    public_key: Uint8Array,
    accumulated: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let pk = deserialize_public_key(public_key)?;
    let params = deserialize_params(params)?;
    let statement = KBUniAccumMemVerifierStmt::new_statement_from_params(params, pk, accumulated);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "KBUniAccumMemVerifierStmt"
    ))
}

#[wasm_bindgen(js_name = generateKBUniversalAccumulatorMembershipVerifierStatementFromParamRefs)]
pub fn generate_kb_universal_accumulator_membership_verifier_statement_from_param_refs(
    params: usize,
    public_key: usize,
    accumulated: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let statement =
        KBUniAccumMemVerifierStmt::new_statement_from_params_ref(params, public_key, accumulated);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "KBUniAccumMemVerifierStmt"
    ))
}

#[wasm_bindgen(js_name = generateKBUniversalAccumulatorNonMembershipProverStatement)]
pub fn generate_kb_universal_accumulator_non_membership_prover_statement(
    accumulated: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let statement = KBUniAccumNonMemProverStmt::new(accumulated);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "KBUniAccumNonMemProverStmt"
    ))
}

#[wasm_bindgen(js_name = generateKBUniversalAccumulatorNonMembershipVerifierStatement)]
pub fn generate_kb_universal_accumulator_non_membership_verifier_statement(
    params: Uint8Array,
    public_key: Uint8Array,
    accumulated: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let pk = deserialize_public_key(public_key)?;
    let params = deserialize_params(params)?;
    let statement =
        KBUniAccumNonMemVerifierStmt::new_statement_from_params(params, pk, accumulated);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "KBUniAccumNonMemVerifierStmt"
    ))
}

#[wasm_bindgen(js_name = generateKBUniversalAccumulatorNonMembershipVerifierStatementFromParamRefs)]
pub fn generate_kb_universal_accumulator_non_membership_verifier_statement_from_param_refs(
    params: usize,
    public_key: usize,
    accumulated: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let statement = KBUniAccumNonMemVerifierStmt::new_statement_from_params_ref(
        params,
        public_key,
        accumulated,
    );
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "KBUniAccumNonMemVerifierStmt"
    ))
}
