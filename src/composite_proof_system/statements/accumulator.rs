use crate::{
    accumulator::{deserialize_params, deserialize_public_key, MembershipPrk, NonMembershipPrk},
    utils::{g1_affine_from_uint8_array, set_panic_hook},
    G1Affine,
};
use ark_bls12_381::Bls12_381;
use js_sys::Uint8Array;
use proof_system::prelude;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
use zeroize::Zeroize;

pub(crate) type AccumMemStmt = prelude::accumulator::AccumulatorMembership<Bls12_381>;
pub(crate) type AccumNonMemStmt = prelude::accumulator::AccumulatorNonMembership<Bls12_381>;

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
    let statement =
        AccumMemStmt::new_statement_from_params::<G1Affine>(params, pk, prk, accumulated);
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
    let statement = AccumMemStmt::new_statement_from_params_ref::<G1Affine>(
        params,
        public_key,
        proving_key,
        accumulated,
    );
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
    let statement =
        AccumNonMemStmt::new_statement_from_params::<G1Affine>(params, pk, prk, accumulated);
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
    let statement = AccumNonMemStmt::new_statement_from_params_ref::<G1Affine>(
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
