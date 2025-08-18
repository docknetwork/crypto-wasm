use crate::utils::{
    fr_from_jsvalue, fr_from_uint8_array, fr_to_uint8_array, g1_affine_from_uint8_array,
    g1_affine_to_uint8_array, get_seeded_rng, js_array_from_frs, js_array_to_fr_vec, random_bytes,
    set_panic_hook,
};

use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use wasm_bindgen::prelude::*;

use ark_ff::One;
use blake2::Blake2b512;
use vb_accumulator::prelude::{
    Accumulator, MembershipProof, MembershipProofProtocol, MembershipProvingKey, MembershipWitness,
    NonMembershipProof, NonMembershipProofProtocol, NonMembershipProvingKey, NonMembershipWitness,
    Omega as Omega_, PositiveAccumulator, UniversalAccumulator,
};

use zeroize::Zeroize;

use crate::{
    accumulator::common::{deserialize_params, deserialize_public_key, AccumSk},
    to_verify_response, Fr,
};

pub(crate) type PositiveAccum = PositiveAccumulator<<Bls12_381 as Pairing>::G1Affine>;
pub(crate) type UniversalAccum = UniversalAccumulator<<Bls12_381 as Pairing>::G1Affine>;
pub(crate) type MembershipWit = MembershipWitness<<Bls12_381 as Pairing>::G1Affine>;
pub(crate) type NonMembershipWit = NonMembershipWitness<<Bls12_381 as Pairing>::G1Affine>;
pub(crate) type Omega = Omega_<<Bls12_381 as Pairing>::G1Affine>;
pub type MembershipPrk = MembershipProvingKey<<Bls12_381 as Pairing>::G1Affine>;
pub type NonMembershipPrk = NonMembershipProvingKey<<Bls12_381 as Pairing>::G1Affine>;
pub(crate) type MemProtocol = MembershipProofProtocol<Bls12_381>;
pub(crate) type MemProof = MembershipProof<Bls12_381>;
pub(crate) type NonMemProtocol = NonMembershipProofProtocol<Bls12_381>;
pub(crate) type NonMemProof = NonMembershipProof<Bls12_381>;

use crate::common::VerifyResponse;

/// Initialize a positive accumulator
#[wasm_bindgen(js_name = positiveAccumulatorInitialize)]
pub fn positive_accumulator_initialize(params: js_sys::Uint8Array) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let params = deserialize_params(params)?;
    let accum = PositiveAccum::initialize(&params);
    serde_wasm_bindgen::to_value(&accum).map_err(JsValue::from)
}

/// Get the accumulated value from given positive accumulator
#[wasm_bindgen(js_name = positiveAccumulatorGetAccumulated)]
pub fn positive_accumulator_get_accumulated(accum: JsValue) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let accum: PositiveAccum = serde_wasm_bindgen::from_value(accum)?;
    let a = g1_affine_to_uint8_array(accum.value())?;
    Ok(a)
}

#[wasm_bindgen(js_name = positiveAccumulatorAdd)]
pub fn positive_accumulator_add(
    existing_accum: JsValue,
    element: js_sys::Uint8Array,
    secret_key: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let accum: PositiveAccum = serde_wasm_bindgen::from_value(existing_accum)?;
    let element = fr_from_uint8_array(element, true)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;

    let new_value = accum.compute_new_post_add(&element, &sk);

    serde_wasm_bindgen::to_value(&PositiveAccum::from_value(new_value)).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = positiveAccumulatorRemove)]
pub fn positive_accumulator_remove(
    existing_accum: JsValue,
    element: js_sys::Uint8Array,
    secret_key: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let accum: PositiveAccum = serde_wasm_bindgen::from_value(existing_accum)?;
    let element = fr_from_uint8_array(element, true)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let new_value = accum.compute_new_post_remove(&element, &sk);

    serde_wasm_bindgen::to_value(&PositiveAccum::from_value(new_value)).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = positiveAccumulatorMembershipWitness)]
pub fn positive_accumulator_membership_witness(
    accum: JsValue,
    element: js_sys::Uint8Array,
    secret_key: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let accum: PositiveAccum = serde_wasm_bindgen::from_value(accum)?;
    crate::get_membership_witness!(accum, element, secret_key)
}

#[wasm_bindgen(js_name = positiveAccumulatorVerifyMembership)]
pub fn positive_accumulator_verify_membership(
    accumulated: js_sys::Uint8Array,
    element: js_sys::Uint8Array,
    witness: JsValue,
    public_key: js_sys::Uint8Array,
    params: js_sys::Uint8Array,
) -> Result<bool, JsValue> {
    set_panic_hook();
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let accum = PositiveAccum::from_accumulated(accumulated);
    crate::verify_membership!(accum, element, MembershipWit, witness, public_key, params)
}

/// Creates the initial elements that depend on the order of the curve and thus can be considered fixed.
/// This function generates them for the BLS12-381 curve *only*.
#[wasm_bindgen(js_name = universalAccumulatorFixedInitialElements)]
pub fn universal_accumulator_fixed_initial_elements() -> Result<js_sys::Array, JsValue> {
    use ark_ff::MontFp;
    let initial = vb_accumulator::initial_elements_for_bls12_381!(Fr);
    js_array_from_frs(&initial)
}

#[wasm_bindgen(js_name = universalAccumulatorComputeInitialFv)]
pub fn universal_accumulator_compute_initial_fv(
    initial_elements: js_sys::Array,
    secret_key: JsValue,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let initial_elements = js_array_to_fr_vec(&initial_elements)?;
    let f_v = UniversalAccum::compute_initial_f_V(&initial_elements, &sk);
    fr_to_uint8_array(&f_v)
}

#[wasm_bindgen(js_name = universalAccumulatorCombineMultipleInitialFv)]
pub fn universal_accumulator_combine_multiple_initial_fv(
    initial_f_vs: js_sys::Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let mut product = Fr::one();
    for f_v in initial_f_vs.values() {
        let f_v = f_v.unwrap();
        product *= fr_from_jsvalue(f_v)?;
    }
    fr_to_uint8_array(&product)
}

#[wasm_bindgen(js_name = universalAccumulatorInitialiseGivenFv)]
pub fn universal_accumulator_initialize_given_f_v(
    f_v: js_sys::Uint8Array,
    params: js_sys::Uint8Array,
    max_size: u32,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let f_v = fr_from_uint8_array(f_v, true)?;
    let params = deserialize_params(params)?;
    let accum = UniversalAccum::initialize_given_f_V(f_v, &params, max_size as u64);
    serde_wasm_bindgen::to_value(&accum).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = universalAccumulatorGetAccumulated)]
pub fn universal_accumulator_get_accumulated(
    accum: JsValue,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let accum: UniversalAccum = serde_wasm_bindgen::from_value(accum)?;
    let a = g1_affine_to_uint8_array(accum.value())?;
    Ok(a)
}

#[wasm_bindgen(js_name = universalAccumulatorAdd)]
pub fn universal_accumulator_add(
    existing_accum: JsValue,
    element: js_sys::Uint8Array,
    secret_key: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let accum: UniversalAccum = serde_wasm_bindgen::from_value(existing_accum)?;
    let element = fr_from_uint8_array(element, true)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let (f_v, v) = accum.compute_new_post_add(&element, &sk);
    serde_wasm_bindgen::to_value(&accum.get_updated(f_v, v)).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = universalAccumulatorRemove)]
pub fn universal_accumulator_remove(
    existing_accum: JsValue,
    element: js_sys::Uint8Array,
    secret_key: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let accum: UniversalAccum = serde_wasm_bindgen::from_value(existing_accum)?;
    let element = fr_from_uint8_array(element, true)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let (f_v, v) = accum.compute_new_post_remove(&element, &sk);
    serde_wasm_bindgen::to_value(&accum.get_updated(f_v, v)).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = universalAccumulatorMembershipWitness)]
pub fn universal_accumulator_membership_witness(
    accum: JsValue,
    element: js_sys::Uint8Array,
    secret_key: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let accum: UniversalAccum = serde_wasm_bindgen::from_value(accum)?;
    crate::get_membership_witness!(accum, element, secret_key)
}

#[wasm_bindgen(js_name = universalAccumulatorVerifyMembership)]
pub fn universal_accumulator_verify_membership(
    accumulated: js_sys::Uint8Array,
    member: js_sys::Uint8Array,
    witness: JsValue,
    public_key: js_sys::Uint8Array,
    params: js_sys::Uint8Array,
) -> Result<bool, JsValue> {
    set_panic_hook();
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    // Only care about accumulated
    let accum = UniversalAccum::from_accumulated(accumulated);
    crate::verify_membership!(accum, member, MembershipWit, witness, public_key, params)
}

#[wasm_bindgen(js_name = universalAccumulatorComputeD)]
pub fn universal_accumulator_compute_d(
    non_member: js_sys::Uint8Array,
    members: js_sys::Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let element = fr_from_uint8_array(non_member, true)?;
    let members = js_array_to_fr_vec(&members)?;
    let d = UniversalAccum::compute_d_given_members(&element, &members);
    let d = fr_to_uint8_array(&d)?;
    Ok(d)
}

#[wasm_bindgen(js_name = universalAccumulatorCombineMultipleD)]
pub fn universal_accumulator_combine_multiple_d(
    ds: js_sys::Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let mut product = Fr::one();
    for d in ds.values() {
        let d = d.unwrap();
        product *= fr_from_jsvalue(d)?;
    }
    let d = fr_to_uint8_array(&product)?;
    Ok(d)
}

#[wasm_bindgen(js_name = universalAccumulatorNonMembershipWitness)]
pub fn universal_accumulator_non_membership_witness(
    accum: JsValue,
    d: js_sys::Uint8Array,
    non_member: js_sys::Uint8Array,
    secret_key: JsValue,
    params: js_sys::Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let accum: UniversalAccum = serde_wasm_bindgen::from_value(accum)?;
    let element = fr_from_uint8_array(non_member, true)?;
    let d = fr_from_uint8_array(d, true)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let params = deserialize_params(params)?;
    serde_wasm_bindgen::to_value(
        &accum
            .compute_non_membership_witness_given_d(d, &element, &sk, &params)
            .map_err(|e| {
                JsValue::from(&format!(
                    "Evaluating compute_non_membership_witness_given_d returned error: {:?}",
                    e
                ))
            })?,
    )
    .map_err(JsValue::from)
}

#[wasm_bindgen(js_name = universalAccumulatorVerifyNonMembership)]
pub fn universal_accumulator_verify_non_membership(
    accumulated: js_sys::Uint8Array,
    non_member: js_sys::Uint8Array,
    witness: JsValue,
    public_key: js_sys::Uint8Array,
    params: js_sys::Uint8Array,
) -> Result<bool, JsValue> {
    set_panic_hook();
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    // Only care about accumulated
    let accum = UniversalAccum::from_accumulated(accumulated);
    let non_member = fr_from_uint8_array(non_member, true)?;
    let witness: NonMembershipWit = serde_wasm_bindgen::from_value(witness)?;
    let pk = deserialize_public_key(public_key)?;
    let params = deserialize_params(params)?;
    Ok(accum.verify_non_membership(&non_member, &witness, &pk, &params))
}

#[wasm_bindgen(js_name = positiveAccumulatorAddBatch)]
pub fn positive_accumulator_add_batch(
    existing_accum: JsValue,
    elements: js_sys::Array,
    secret_key: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let accum: PositiveAccum = serde_wasm_bindgen::from_value(existing_accum)?;
    let elems = js_array_to_fr_vec(&elements)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let new_value = accum.compute_new_post_add_batch(&elems, &sk);
    serde_wasm_bindgen::to_value(&PositiveAccum::from_value(new_value)).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = positiveAccumulatorRemoveBatch)]
pub fn positive_accumulator_remove_batch(
    existing_accum: JsValue,
    elements: js_sys::Array,
    secret_key: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let accum: PositiveAccum = serde_wasm_bindgen::from_value(existing_accum)?;
    let elems = js_array_to_fr_vec(&elements)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let new_value = accum.compute_new_post_remove_batch(&elems, &sk);
    serde_wasm_bindgen::to_value(&PositiveAccum::from_value(new_value)).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = positiveAccumulatorBatchUpdates)]
pub fn positive_accumulator_batch_updates(
    existing_accum: JsValue,
    additions: js_sys::Array,
    removals: js_sys::Array,
    secret_key: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let accum: PositiveAccum = serde_wasm_bindgen::from_value(existing_accum)?;
    let adds = js_array_to_fr_vec(&additions)?;
    let removes = js_array_to_fr_vec(&removals)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let new_value = accum.compute_new_post_batch_updates(&adds, &removes, &sk);
    serde_wasm_bindgen::to_value(&PositiveAccum::from_value(new_value)).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = positiveAccumulatorMembershipWitnessesForBatch)]
pub fn positive_accumulator_membership_witnesses_for_batch(
    accum: JsValue,
    elements: js_sys::Array,
    secret_key: JsValue,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    let accum: PositiveAccum = serde_wasm_bindgen::from_value(accum)?;
    crate::get_membership_witnesses_for_batch!(accum, elements, secret_key)
}

#[wasm_bindgen(js_name = universalAccumulatorAddBatch)]
pub fn universal_accumulator_add_batch(
    existing_accum: JsValue,
    elements: js_sys::Array,
    secret_key: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let accum: UniversalAccum = serde_wasm_bindgen::from_value(existing_accum)?;
    let elems = js_array_to_fr_vec(&elements)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let (f_v, v) = accum.compute_new_post_add_batch(&elems, &sk);
    serde_wasm_bindgen::to_value(&UniversalAccum::from_value(f_v, v, accum.max_size()))
        .map_err(JsValue::from)
}

#[wasm_bindgen(js_name = universalAccumulatorRemoveBatch)]
pub fn universal_accumulator_remove_batch(
    existing_accum: JsValue,
    elements: js_sys::Array,
    secret_key: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let accum: UniversalAccum = serde_wasm_bindgen::from_value(existing_accum)?;
    let elems = js_array_to_fr_vec(&elements)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let (f_v, v) = accum.compute_new_post_remove_batch(&elems, &sk);
    serde_wasm_bindgen::to_value(&UniversalAccum::from_value(f_v, v, accum.max_size()))
        .map_err(JsValue::from)
}

#[wasm_bindgen(js_name = universalAccumulatorBatchUpdates)]
pub fn universal_accumulator_batch_updates(
    existing_accum: JsValue,
    additions: js_sys::Array,
    removals: js_sys::Array,
    secret_key: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let accum: UniversalAccum = serde_wasm_bindgen::from_value(existing_accum)?;
    let adds = js_array_to_fr_vec(&additions)?;
    let removes = js_array_to_fr_vec(&removals)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let (f_v, v) = accum.compute_new_post_batch_updates(&adds, &removes, &sk);
    serde_wasm_bindgen::to_value(&UniversalAccum::from_value(f_v, v, accum.max_size()))
        .map_err(JsValue::from)
}

#[wasm_bindgen(js_name = universalAccumulatorMembershipWitnessesForBatch)]
pub fn universal_accumulator_membership_witnesses_for_batch(
    accum: JsValue,
    elements: js_sys::Array,
    secret_key: JsValue,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    let accum: UniversalAccum = serde_wasm_bindgen::from_value(accum)?;
    crate::get_membership_witnesses_for_batch!(accum, elements, secret_key)
}

#[wasm_bindgen(js_name = universalAccumulatorComputeDForBatch)]
pub fn universal_accumulator_compute_d_for_batch(
    non_members: js_sys::Array,
    members: js_sys::Array,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    let non_members = js_array_to_fr_vec(&non_members)?;
    let members = js_array_to_fr_vec(&members)?;
    let d = UniversalAccum::compute_d_for_batch_given_members(&non_members, &members);
    js_array_from_frs(&d)
}

#[wasm_bindgen(js_name = universalAccumulatorCombineMultipleDForBatch)]
pub fn universal_accumulator_combine_multiple_d_for_batch(
    ds: js_sys::Array,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    let mut length = None;
    let mut products = vec![];
    for d in ds.values() {
        let d = d.unwrap();
        let arr = js_sys::Array::from(&d);
        if length.is_none() {
            length = Some(arr.length());
            products = vec![Fr::one(); arr.length() as usize]
        } else if arr.length() != *length.as_ref().unwrap() {
            return Err(JsValue::from(format!(
                "All d should be equal, {}, {}",
                arr.length(),
                *length.as_ref().unwrap()
            )));
        }
        for e in arr.entries() {
            let a = js_sys::Array::from(&e.unwrap());
            let i: u32 = serde_wasm_bindgen::from_value(a.get(0)).unwrap();
            let d = fr_from_jsvalue(a.get(1))?;
            products[i as usize] *= d;
        }
    }
    js_array_from_frs(&products)
}

#[wasm_bindgen(js_name = universalAccumulatorNonMembershipWitnessesForBatch)]
pub fn universal_accumulator_non_membership_witnesses_for_batch(
    accum: JsValue,
    d: js_sys::Array,
    non_members: js_sys::Array,
    secret_key: JsValue,
    params: js_sys::Uint8Array,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    let accum: UniversalAccum = serde_wasm_bindgen::from_value(accum)?;
    let d = js_array_to_fr_vec(&d)?;
    let non_members = js_array_to_fr_vec(&non_members)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let params = deserialize_params(params)?;
    let witnesses = accum
        .compute_non_membership_witnesses_for_batch_given_d(d, &non_members, &sk, &params)
        .map_err(|e| {
            JsValue::from(&format!(
                "Evaluating compute_non_membership_witnesses_for_batch_given_d returned error: {:?}",
                e
            ))
        })?;
    let result = js_sys::Array::new();
    for witness in witnesses {
        result.push(&serde_wasm_bindgen::to_value(&witness).map_err(JsValue::from)?);
    }
    Ok(result)
}

#[wasm_bindgen(js_name = updateMembershipWitnessPostAdd)]
pub fn update_membership_witness_post_add(
    witness: JsValue,
    member: js_sys::Uint8Array,
    addition: js_sys::Uint8Array,
    old_accumulated: js_sys::Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let witness: MembershipWit = serde_wasm_bindgen::from_value(witness)?;
    crate::update_witness_post_add!(witness, member, addition, old_accumulated)
}

#[wasm_bindgen(js_name = updateMembershipWitnessPostRemove)]
pub fn update_membership_witness_post_remove(
    witness: JsValue,
    member: js_sys::Uint8Array,
    removal: js_sys::Uint8Array,
    new_accumulated: js_sys::Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let witness: MembershipWit = serde_wasm_bindgen::from_value(witness)?;
    crate::update_witness_post_remove!(witness, member, removal, new_accumulated)
}

#[wasm_bindgen(js_name = updateNonMembershipWitnessPostAdd)]
pub fn update_non_membership_witness_post_add(
    witness: JsValue,
    non_member: js_sys::Uint8Array,
    addition: js_sys::Uint8Array,
    old_accumulated: js_sys::Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let witness: NonMembershipWit = serde_wasm_bindgen::from_value(witness)?;
    crate::update_witness_post_add!(witness, non_member, addition, old_accumulated)
}

#[wasm_bindgen(js_name = updateNonMembershipWitnessPostRemove)]
pub fn update_non_membership_witness_post_remove(
    witness: JsValue,
    non_member: js_sys::Uint8Array,
    removal: js_sys::Uint8Array,
    new_accumulated: js_sys::Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let witness: NonMembershipWit = serde_wasm_bindgen::from_value(witness)?;
    crate::update_witness_post_remove!(witness, non_member, removal, new_accumulated)
}

#[wasm_bindgen(js_name = updateMembershipWitnessesPostBatchUpdates)]
pub fn update_membership_witnesses_post_batch_updates(
    witnesses: js_sys::Array,
    members: js_sys::Array,
    additions: js_sys::Array,
    removals: js_sys::Array,
    old_accumulated: js_sys::Uint8Array,
    secret_key: JsValue,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    crate::update_using_secret_key_after_batch_updates!(
        witnesses,
        members,
        additions,
        removals,
        old_accumulated,
        secret_key,
        MembershipWit
    )
}

#[wasm_bindgen(js_name = updateNonMembershipWitnessesPostBatchUpdates)]
pub fn update_non_membership_witnesses_post_batch_updates(
    witnesses: js_sys::Array,
    non_members: js_sys::Array,
    additions: js_sys::Array,
    removals: js_sys::Array,
    old_accumulated: js_sys::Uint8Array,
    secret_key: JsValue,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    crate::update_using_secret_key_after_batch_updates!(
        witnesses,
        non_members,
        additions,
        removals,
        old_accumulated,
        secret_key,
        NonMembershipWit
    )
}

#[wasm_bindgen(js_name = publicInfoForWitnessUpdate)]
pub fn public_info_for_witness_update(
    old_accumulated: js_sys::Uint8Array,
    additions: js_sys::Array,
    removals: js_sys::Array,
    secret_key: JsValue,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let existing_accumulated = g1_affine_from_uint8_array(old_accumulated)?;
    let additions = js_array_to_fr_vec(&additions)?;
    let removals = js_array_to_fr_vec(&removals)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let omega = Omega::new(&additions, &removals, &existing_accumulated, &sk);
    Ok(obj_to_uint8array!(&omega, false, "Omega"))
}

#[wasm_bindgen(js_name = updateMembershipWitnessUsingPublicInfoAfterBatchUpdate)]
pub fn update_membership_witness_using_public_info_after_batch_update(
    witness: JsValue,
    member: js_sys::Uint8Array,
    additions: js_sys::Array,
    removals: js_sys::Array,
    public_info: js_sys::Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let witness: MembershipWit = serde_wasm_bindgen::from_value(witness)?;
    crate::update_witness_single_batch!(witness, member, additions, removals, public_info)
}

#[wasm_bindgen(js_name = updateMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates)]
pub fn update_membership_witness_using_public_info_after_multiple_batch_updates(
    witness: JsValue,
    member: js_sys::Uint8Array,
    additions: js_sys::Array,
    removals: js_sys::Array,
    public_info: js_sys::Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let witness: MembershipWit = serde_wasm_bindgen::from_value(witness)?;
    crate::update_witness_multiple_batches!(witness, member, additions, removals, public_info)
}

#[wasm_bindgen(js_name = updateNonMembershipWitnessUsingPublicInfoAfterBatchUpdate)]
pub fn update_non_membership_witness_using_public_info_after_batch_update(
    witness: JsValue,
    non_member: js_sys::Uint8Array,
    additions: js_sys::Array,
    removals: js_sys::Array,
    public_info: js_sys::Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let witness: NonMembershipWit = serde_wasm_bindgen::from_value(witness)?;
    crate::update_witness_single_batch!(witness, non_member, additions, removals, public_info)
}

#[wasm_bindgen(js_name = updateNonMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates)]
pub fn update_non_membership_witness_using_public_info_after_multiple_batch_updates(
    witness: JsValue,
    non_member: js_sys::Uint8Array,
    additions: js_sys::Array,
    removals: js_sys::Array,
    public_info: js_sys::Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let witness: NonMembershipWit = serde_wasm_bindgen::from_value(witness)?;
    crate::update_witness_multiple_batches!(witness, non_member, additions, removals, public_info)
}

#[wasm_bindgen(js_name = generateMembershipProvingKey)]
pub fn generate_membership_proving_key(
    label: Option<Vec<u8>>,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let label = label.unwrap_or_else(random_bytes);
    let prk = MembershipPrk::new::<Blake2b512>(&label);
    Ok(obj_to_uint8array!(&prk, false, "MembershipProvingKey"))
}

#[wasm_bindgen(js_name = generateNonMembershipProvingKey)]
pub fn generate_non_membership_proving_key(
    label: Option<Vec<u8>>,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let label = label.unwrap_or_else(random_bytes);
    let prk = NonMembershipPrk::new::<Blake2b512>(&label);
    Ok(obj_to_uint8array!(&prk, false, "NonMembershipProvingKey"))
}

#[wasm_bindgen(js_name = accumulatorDeriveMembershipProvingKeyFromNonMembershipKey)]
pub fn accumulator_derive_membership_proving_key_from_non_membership_key(
    proving_key: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    let prk = obj_from_uint8array!(
        NonMembershipPrk,
        proving_key,
        false,
        "NonMembershipProvingKey"
    );
    let mprk = prk.derive_membership_proving_key();
    Ok(obj_to_uint8array!(&mprk, false, "MembershipProvingKey"))
}

#[wasm_bindgen(js_name = accumulatorInitializeMembershipProof)]
pub fn accumulator_initialize_membership_proof(
    member: js_sys::Uint8Array,
    blinding: js_sys::Uint8Array,
    witness: JsValue,
    public_key: js_sys::Uint8Array,
    params: js_sys::Uint8Array,
    proving_key: js_sys::Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let witness: MembershipWit = serde_wasm_bindgen::from_value(witness)?;
    let prk = obj_from_uint8array!(MembershipPrk, proving_key, false);
    crate::init_proof_protocol!(
        MemProtocol,
        witness,
        member,
        blinding,
        public_key,
        params,
        prk
    )
}

#[wasm_bindgen(js_name = accumulatorGenMembershipProof)]
pub fn accumulator_gen_membership_proof(
    protocol: JsValue,
    challenge: js_sys::Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let protocol: MemProtocol = serde_wasm_bindgen::from_value(protocol)?;
    let challenge = fr_from_uint8_array(challenge, false)?;
    serde_wasm_bindgen::to_value(&protocol.gen_proof(&challenge)).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = accumulatorVerifyMembershipProof)]
pub fn accumulator_verify_membership_proof(
    proof: JsValue,
    accumulated: js_sys::Uint8Array,
    challenge: js_sys::Uint8Array,
    public_key: js_sys::Uint8Array,
    params: js_sys::Uint8Array,
    proving_key: js_sys::Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let proof: MemProof = serde_wasm_bindgen::from_value(proof)?;
    let prk = obj_from_uint8array!(MembershipPrk, proving_key, false, "MembershipPrk");
    crate::verify_proof!(proof, accumulated, challenge, public_key, params, prk)
}

#[wasm_bindgen(js_name = accumulatorChallengeContributionFromMembershipProtocol)]
pub fn accumulator_challenge_contribution_from_membership_protocol(
    protocol: JsValue,
    accumulated: js_sys::Uint8Array,
    public_key: js_sys::Uint8Array,
    params: js_sys::Uint8Array,
    proving_key: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let protocol: MemProtocol = serde_wasm_bindgen::from_value(protocol)?;
    let prk = obj_from_uint8array!(MembershipPrk, proving_key, false, "MembershipPrk");
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let pk = deserialize_public_key(public_key)?;
    let params = deserialize_params(params)?;
    let mut bytes = vec![];
    protocol
        .challenge_contribution(&accumulated, &pk, &params, &prk, &mut bytes)
        .map_err(|e| {
            JsValue::from(&format!(
                "Evaluating challenge_contribution returned error: {:?}",
                e
            ))
        })?;
    Ok(js_sys::Uint8Array::from(bytes.as_slice()))
}

#[wasm_bindgen(js_name = accumulatorChallengeContributionFromMembershipProof)]
pub fn accumulator_challenge_contribution_from_membership_proof(
    proof: JsValue,
    accumulated: js_sys::Uint8Array,
    public_key: js_sys::Uint8Array,
    params: js_sys::Uint8Array,
    proving_key: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let proof: MemProof = serde_wasm_bindgen::from_value(proof)?;
    let prk = obj_from_uint8array!(MembershipPrk, proving_key, false, "MembershipPrk");
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let pk = deserialize_public_key(public_key)?;
    let params = deserialize_params(params)?;
    let mut bytes = vec![];
    proof
        .challenge_contribution(&accumulated, &pk, &params, &prk, &mut bytes)
        .map_err(|e| {
            JsValue::from(&format!(
                "Evaluating challenge_contribution returned error: {:?}",
                e
            ))
        })?;
    Ok(js_sys::Uint8Array::from(bytes.as_slice()))
}

#[wasm_bindgen(js_name = accumulatorInitializeNonMembershipProof)]
pub fn accumulator_initialize_non_membership_proof(
    non_member: js_sys::Uint8Array,
    blinding: js_sys::Uint8Array,
    witness: JsValue,
    public_key: js_sys::Uint8Array,
    params: js_sys::Uint8Array,
    proving_key: js_sys::Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let witness: NonMembershipWit = serde_wasm_bindgen::from_value(witness)?;
    let prk = obj_from_uint8array!(NonMembershipPrk, proving_key, false, "NonMembershipPrk");
    crate::init_proof_protocol!(
        NonMemProtocol,
        witness,
        non_member,
        blinding,
        public_key,
        params,
        prk
    )
}

#[wasm_bindgen(js_name = accumulatorGenNonMembershipProof)]
pub fn accumulator_gen_non_membership_proof(
    protocol: JsValue,
    challenge: js_sys::Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let protocol: NonMemProtocol = serde_wasm_bindgen::from_value(protocol)?;
    let challenge = fr_from_uint8_array(challenge, false)?;
    serde_wasm_bindgen::to_value(&protocol.gen_proof(&challenge)).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = accumulatorVerifyNonMembershipProof)]
pub fn accumulator_verify_non_membership_proof(
    proof: JsValue,
    accumulated: js_sys::Uint8Array,
    challenge: js_sys::Uint8Array,
    public_key: js_sys::Uint8Array,
    params: js_sys::Uint8Array,
    proving_key: js_sys::Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let proof: NonMemProof = serde_wasm_bindgen::from_value(proof)?;
    let prk = obj_from_uint8array!(NonMembershipPrk, proving_key, false, "NonMembershipPrk");
    crate::verify_proof!(proof, accumulated, challenge, public_key, params, prk)
}

#[wasm_bindgen(js_name = accumulatorChallengeContributionFromNonMembershipProtocol)]
pub fn accumulator_challenge_contribution_from_non_membership_protocol(
    protocol: JsValue,
    accumulated: js_sys::Uint8Array,
    public_key: js_sys::Uint8Array,
    params: js_sys::Uint8Array,
    proving_key: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let protocol: NonMemProtocol = serde_wasm_bindgen::from_value(protocol)?;
    let prk = obj_from_uint8array!(NonMembershipPrk, proving_key, false, "NonMembershipPrk");
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let pk = deserialize_public_key(public_key)?;
    let params = deserialize_params(params)?;
    let mut bytes = vec![];
    protocol
        .challenge_contribution(&accumulated, &pk, &params, &prk, &mut bytes)
        .map_err(|e| {
            JsValue::from(&format!(
                "Evaluating challenge_contribution returned error: {:?}",
                e
            ))
        })?;
    Ok(js_sys::Uint8Array::from(bytes.as_slice()))
}

#[wasm_bindgen(js_name = accumulatorChallengeContributionFromNonMembershipProof)]
pub fn accumulator_challenge_contribution_from_non_membership_proof(
    proof: JsValue,
    accumulated: js_sys::Uint8Array,
    public_key: js_sys::Uint8Array,
    params: js_sys::Uint8Array,
    proving_key: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let proof: NonMemProof = serde_wasm_bindgen::from_value(proof)?;
    let prk = obj_from_uint8array!(NonMembershipPrk, proving_key, false, "NonMembershipPrk");
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let pk = deserialize_public_key(public_key)?;
    let params = deserialize_params(params)?;
    let mut bytes = vec![];
    proof
        .challenge_contribution(&accumulated, &pk, &params, &prk, &mut bytes)
        .map_err(|e| {
            JsValue::from(&format!(
                "Evaluating challenge_contribution returned error: {:?}",
                e
            ))
        })?;
    Ok(js_sys::Uint8Array::from(bytes.as_slice()))
}
