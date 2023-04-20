use crate::utils::{
    fr_from_jsvalue, fr_from_uint8_array, fr_to_jsvalue, fr_to_uint8_array,
    g1_affine_from_uint8_array, g1_affine_to_uint8_array, get_seeded_rng, js_array_from_frs,
    js_array_to_fr_vec, random_bytes, set_panic_hook,
};

use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use dock_crypto_utils::concat_slices;
use wasm_bindgen::prelude::*;

use ark_ff::One;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2::Blake2b512;
use vb_accumulator::prelude::{
    Accumulator, Keypair, MembershipProof, MembershipProofProtocol, MembershipProvingKey,
    MembershipWitness, NonMembershipProof, NonMembershipProofProtocol, NonMembershipProvingKey,
    NonMembershipWitness, Omega as Omega_, PositiveAccumulator, PublicKey, SecretKey, SetupParams,
    UniversalAccumulator,
};
use zeroize::Zeroize;

use crate::Fr;

// Trying to keep types at one place so changing the curve is easier
pub(crate) type AccumSk = SecretKey<Fr>;
pub type AccumPk = PublicKey<Bls12_381>;
pub type AccumSetupParams = SetupParams<Bls12_381>;
pub(crate) type AccumKeypair = Keypair<Bls12_381>;
pub(crate) type PositiveAccum = PositiveAccumulator<Bls12_381>;
pub(crate) type UniversalAccum = UniversalAccumulator<Bls12_381>;
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

/// Generate accumulator parameters. They are needed to generate public key and initialize the accumulator.
/// Pass the `label` argument to generate parameters deterministically.
#[wasm_bindgen(js_name = generateAccumulatorParams)]
pub fn generate_accumulator_params(label: Option<Vec<u8>>) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let label = label.unwrap_or_else(random_bytes);
    let params = AccumSetupParams::new::<Blake2b512>(&label);
    Ok(obj_to_uint8array!(&params, false, "SetupParams"))
}

/// Check if parameters are valid. Before verifying witness or using for proof verification,
/// make sure the params are valid.
#[wasm_bindgen(js_name = isAccumulatorParamsValid)]
pub fn accumulator_is_params_valid(params: js_sys::Uint8Array) -> Result<bool, JsValue> {
    set_panic_hook();
    let params = deserialize_params(params)?;
    Ok(params.is_valid())
}

/// Generate secret key for the accumulator manager who updates the accumulator and creates witnesses.
/// Pass the `seed` argument to generate key deterministically.
#[wasm_bindgen(js_name = generateAccumulatorSecretKey)]
pub fn accumulator_generate_secret_key(
    seed: Option<Vec<u8>>,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let mut seed = seed.unwrap_or_else(random_bytes);
    let sk = AccumSk::generate_using_seed::<Blake2b512>(&seed);
    seed.zeroize();
    Ok(obj_to_uint8array!(&sk, true, "AccumSk"))
}

/// Generate public key from given params and secret key.
#[wasm_bindgen(js_name = generateAccumulatorPublicKey)]
pub fn accumulator_generate_public_key(
    secret_key: JsValue,
    params: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let params = deserialize_params(params)?;
    let pk = AccumKeypair::public_key_from_secret_key(&sk, &params);
    Ok(obj_to_uint8array!(&pk, false, "PublicKeyG2"))
}

/// Check if public key is valid. Before verifying witness or using for proof verification,
/// make sure the public key is valid.
#[wasm_bindgen(js_name = isAccumulatorPublicKeyValid)]
pub fn accumulator_is_pubkey_valid(public_key: js_sys::Uint8Array) -> Result<bool, JsValue> {
    set_panic_hook();
    let pk = deserialize_public_key(public_key)?;
    Ok(pk.is_valid())
}

/// Generate private and public key from given params and optional `seed`.
/// Pass the `seed` argument to generate keys deterministically.
#[wasm_bindgen(js_name = generateAccumulatorKeyPair)]
pub fn accumulator_generate_keypair(
    params: js_sys::Uint8Array,
    seed: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let params = deserialize_params(params)?;
    let seed = seed.unwrap_or(random_bytes());
    let keypair = AccumKeypair::generate_using_seed::<Blake2b512>(&seed, &params);
    serde_wasm_bindgen::to_value(&keypair).map_err(|e| JsValue::from(e))
}

/// To add arbitrary bytes as an accumulator member, they should be first converted to
/// a field element. This function will prefix the given bytes with a constant string as
/// domain separator and then generate a field element using IETF standard.
#[wasm_bindgen(js_name = accumulatorGetElementFromBytes)]
pub fn accumulator_get_element_from_bytes(bytes: Vec<u8>) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let f = fr_to_jsvalue(&encode_bytes_as_accumulator_member(&bytes))?;
    Ok(f)
}

/// Initialize a positive accumulator
#[wasm_bindgen(js_name = positiveAccumulatorInitialize)]
pub fn positive_accumulator_initialize(
    params: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let params = deserialize_params(params)?;
    let accum = PositiveAccum::initialize(&params);
    Ok(obj_to_uint8array!(&accum, false, "PositiveAccum"))
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
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let accum: PositiveAccum = serde_wasm_bindgen::from_value(existing_accum)?;
    let element = fr_from_uint8_array(element, true)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;

    let new_value = accum.compute_new_post_add(&element, &sk);

    Ok(obj_to_uint8array!(&new_value, false, "PositiveAccum"))
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
    serde_wasm_bindgen::to_value(&PositiveAccum::from_value(new_value))
        .map_err(|e| JsValue::from(e))
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
    crate::verify_membership!(accum, element, witness, public_key, params)
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
    Ok(fr_to_uint8_array(&f_v)?)
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
    Ok(fr_to_uint8_array(&product)?)
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
    serde_wasm_bindgen::to_value(&accum).map_err(|e| JsValue::from(e))
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
    serde_wasm_bindgen::to_value(&accum.get_updated(f_v, v)).map_err(|e| JsValue::from(e))
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
    serde_wasm_bindgen::to_value(&accum.get_updated(f_v, v)).map_err(|e| JsValue::from(e))
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
    crate::verify_membership!(accum, member, witness, public_key, params)
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
    .map_err(|e| JsValue::from(e))
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
    serde_wasm_bindgen::to_value(&PositiveAccum::from_value(new_value))
        .map_err(|e| JsValue::from(e))
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
    serde_wasm_bindgen::to_value(&PositiveAccum::from_value(new_value))
        .map_err(|e| JsValue::from(e))
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
    serde_wasm_bindgen::to_value(&PositiveAccum::from_value(new_value))
        .map_err(|e| JsValue::from(e))
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
        .map_err(|e| JsValue::from(e))
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
        .map_err(|e| JsValue::from(e))
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
        .map_err(|e| JsValue::from(e))
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
        .compute_non_membership_witness_for_batch_given_d(d, &non_members, &sk, &params)
        .map_err(|e| {
            JsValue::from(&format!(
                "Evaluating compute_non_membership_witness_for_batch_given_d returned error: {:?}",
                e
            ))
        })?;
    let result = js_sys::Array::new();
    for witness in witnesses {
        result.push(&serde_wasm_bindgen::to_value(&witness).map_err(|e| JsValue::from(e))?);
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
    serde_wasm_bindgen::to_value(&protocol.gen_proof(&challenge)).map_err(|e| JsValue::from(e))
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
    serde_wasm_bindgen::to_value(&protocol.gen_proof(&challenge)).map_err(|e| JsValue::from(e))
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

pub(crate) fn deserialize_params(bytes: js_sys::Uint8Array) -> Result<AccumSetupParams, JsValue> {
    CanonicalDeserialize::deserialize_compressed(&bytes.to_vec()[..]).map_err(|e| {
        JsValue::from(&format!(
            "Failed to deserialize accumulator params from bytes due to error: {:?}",
            e
        ))
    })
}

pub(crate) fn deserialize_public_key(bytes: js_sys::Uint8Array) -> Result<AccumPk, JsValue> {
    CanonicalDeserialize::deserialize_compressed(&bytes.to_vec()[..]).map_err(|e| {
        JsValue::from(&format!(
            "Failed to deserialize accumulator public key from bytes due to error: {:?}",
            e
        ))
    })
}

#[macro_use]
mod macros {
    #[macro_export]
    macro_rules! get_membership_witness {
        ($accum: ident, $element: ident, $sk: ident) => {{
            let element = fr_from_uint8_array($element, true)?;
            let sk: AccumSk = serde_wasm_bindgen::from_value($sk)?;
            let new_value = $accum.compute_membership_witness(&element, &sk);
            serde_wasm_bindgen::to_value(&new_value).map_err(|e| JsValue::from(e))
        }};
    }

    #[macro_export]
    macro_rules! get_membership_witnesses_for_batch {
        ($accum: ident, $elements: ident, $sk: ident) => {{
            let elems = js_array_to_fr_vec(&$elements)?;
            let sk: AccumSk = serde_wasm_bindgen::from_value($sk)?;
            let witnesses = $accum.compute_membership_witness_for_batch(&elems, &sk);

            let result = js_sys::Array::new();
            for witness in witnesses {
                result.push(&serde_wasm_bindgen::to_value(&witness).map_err(|e| JsValue::from(e))?);
            }
            Ok(result)
        }};
    }

    #[macro_export]
    macro_rules! verify_membership {
        ($accum: ident, $element: ident, $witness: ident, $pk: ident, $params: ident) => {{
            let element = fr_from_uint8_array($element, true)?;
            let witness: MembershipWit = serde_wasm_bindgen::from_value($witness)?;
            let pk = deserialize_public_key($pk)?;
            let params = deserialize_params($params)?;
            Ok($accum.verify_membership(&element, &witness, &pk, &params))
        }};
    }

    #[macro_export]
    macro_rules! update_witness_post_add {
        ($witness:expr, $element: ident, $addition: ident, $old_accumulated: ident) => {{
            let element = fr_from_uint8_array($element, true)?;
            let addition = fr_from_uint8_array($addition, true)?;
            let old_accumulated = g1_affine_from_uint8_array($old_accumulated)?;
            serde_wasm_bindgen::to_value(&$witness.update_after_addition(
                &element,
                &addition,
                &old_accumulated,
            ))
            .map_err(|e| JsValue::from(e))
        }};
    }

    #[macro_export]
    macro_rules! update_witness_post_remove {
        ($witness:expr, $element: ident, $removal: ident, $new_accumulated: ident) => {{
            let element = fr_from_uint8_array($element, true)?;
            let removal = fr_from_uint8_array($removal, true)?;
            let new_accumulated = g1_affine_from_uint8_array($new_accumulated)?;
            let new_wit = $witness
                .update_after_removal(&element, &removal, &new_accumulated)
                .map_err(|e| {
                    JsValue::from(&format!(
                        "Evaluating update_after_removal returned error: {:?}",
                        e
                    ))
                })?;
            serde_wasm_bindgen::to_value(&new_wit).map_err(|e| JsValue::from(e))
        }};
    }

    #[macro_export]
    macro_rules! update_witness_single_batch {
        ($witness:expr, $element: ident, $additions: ident, $removals: ident, $public_info: ident) => {{
            let element = fr_from_uint8_array($element, true)?;
            let additions = js_array_to_fr_vec(&$additions)?;
            let removals = js_array_to_fr_vec(&$removals)?;
            let public_info: Omega = CanonicalDeserialize::deserialize_compressed(&$public_info.to_vec()[..]).map_err(|e| {
                JsValue::from(&format!(
                    "Failed to deserialize public info from bytes due to error: {:?}",
                    e
                ))
            })?;
            let new_witness = $witness
                .update_using_public_info_after_batch_updates(&additions, &removals, &public_info, &element)
                .map_err(|e| {
                    JsValue::from(&format!(
                        "Evaluating update_using_public_info_after_batch_updates returned error: {:?}",
                        e
                    ))
                })?;
            serde_wasm_bindgen::to_value(&new_witness).map_err(|e| JsValue::from(e))
        }}
    }

    #[macro_export]
    macro_rules! update_witness_multiple_batches {
        ($witness:expr, $element: ident, $additions: ident, $removals: ident, $public_info: ident) => {{
            let element = fr_from_uint8_array($element, true)?;
            if $additions.length() == $removals.length() && $removals.length() == $public_info.length() {
                let size = $additions.length();
                let mut updates_and_public_info = Vec::with_capacity(size as usize);
                for i in 0..size {
                    let adds = js_array_to_fr_vec(&js_sys::Array::from(&$additions.get(i)))?;
                    let rems = js_array_to_fr_vec(&js_sys::Array::from(&$removals.get(i)))?;
                    let bytes: Vec<u8> = serde_wasm_bindgen::from_value($public_info.get(i))?;
                    let p: Omega = CanonicalDeserialize::deserialize_compressed(&bytes[..]).map_err(|e| JsValue::from(&format!(
                            "Failed to deserialize public info from bytes due to error: {:?}",
                            e
                        )))?;
                    updates_and_public_info.push((adds, rems, p));
                }
                let new_witness = $witness.update_using_public_info_after_multiple_batch_updates(updates_and_public_info.iter().map(|(a, r, p)| (a.as_slice(), r.as_slice(), p)).collect::<Vec<_>>(), &element)
                .map_err(|e| {
                    JsValue::from(&format!(
                        "Evaluating update_using_public_info_after_multiple_batch_updates returned error: {:?}",
                        e
                    ))
                })?;
                let w = serde_wasm_bindgen::to_value(&new_witness).map_err(|e| JsValue::from(e))?;
                Ok(w)
            } else {
                Err(JsValue::from(&format!(
                    "Expected same but found different lengths for additions, removals and public info: {} {} {}",
                    $additions.length(), $removals.length(), $public_info.length()
                )))
            }
        }}
    }

    #[macro_export]
    macro_rules! init_proof_protocol {
        ($protocol:ident, $witness:ident, $element: ident, $blinding: ident, $public_key: ident, $params: ident, $prk: ident) => {{
            let element = fr_from_uint8_array($element, true)?;
            let blinding = fr_from_uint8_array($blinding, true)?;
            let pk = deserialize_public_key($public_key)?;
            let params = deserialize_params($params)?;

            let mut rng = get_seeded_rng();
            let protocol = $protocol::init(
                &mut rng,
                &element,
                Some(blinding),
                &$witness,
                &pk,
                &params,
                &$prk,
            );
            serde_wasm_bindgen::to_value(&protocol).map_err(|e| JsValue::from(e))
        }};
    }

    #[macro_export]
    macro_rules! verify_proof {
        ($proof: ident, $accumulated:ident, $challenge: ident, $public_key: ident, $params: ident, $prk: ident) => {{
            let accumulated = g1_affine_from_uint8_array($accumulated)?;
            let challenge = fr_from_uint8_array($challenge, false)?;
            let pk = deserialize_public_key($public_key)?;
            let params = deserialize_params($params)?;

            match $proof.verify(&accumulated, &challenge, pk.clone(), params.clone(), &$prk) {
                Ok(_) => Ok(serde_wasm_bindgen::to_value(&VerifyResponse {
                    verified: true,
                    error: None,
                })
                .unwrap()),
                Err(e) => Ok(serde_wasm_bindgen::to_value(&VerifyResponse {
                    verified: false,
                    error: Some(format!("{:?}", e)),
                })
                .unwrap()),
            }
        }};
    }

    #[macro_export]
    macro_rules! update_using_secret_key_after_batch_updates {
        ($witnesses: ident, $elements:ident, $additions: ident, $removals: ident, $old_accumulated: ident, $secret_key: ident, $wit_type: ident) => {{
            let elements = js_array_to_fr_vec(&$elements)?;
            let additions = js_array_to_fr_vec(&$additions)?;
            let removals = js_array_to_fr_vec(&$removals)?;
            let old_accumulated = g1_affine_from_uint8_array($old_accumulated)?;
            let sk: AccumSk = serde_wasm_bindgen::from_value($secret_key)?;
            let mut wits = Vec::with_capacity($witnesses.length() as usize);
            for w in $witnesses.values() {
                wits.push(serde_wasm_bindgen::from_value::<$wit_type>(w.unwrap())?);
            }
            let new_wits = $wit_type::update_using_secret_key_after_batch_updates(
                &additions,
                &removals,
                &elements,
                &wits,
                &old_accumulated,
                &sk,
            )
            .map_err(|e| {
                JsValue::from(&format!(
                    "Evaluating update_using_secret_key_after_batch_updates returned error: {:?}",
                    e
                ))
            })?;
            let result = js_sys::Array::new();
            for w in new_wits {
                result.push(&serde_wasm_bindgen::to_value(&w).map_err(|e| JsValue::from(e))?);
            }
            Ok(result)
        }}
    }
}

pub fn encode_bytes_as_accumulator_member(bytes: &[u8]) -> Fr {
    dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr::<Fr, Blake2b512>(
        &concat_slices!(bytes, b"Accumulator element"),
    )
}
