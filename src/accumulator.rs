use crate::utils::{
    encode_bytes_as_accumulator_member, fr_from_jsvalue, fr_to_jsvalue, g1_affine_from_jsvalue,
    g1_affine_to_jsvalue, get_seeded_rng, js_array_from_frs, js_array_to_fr_vec,
    js_array_to_g1_affine_vec, random_bytes, set_panic_hook,
};

use ark_bls12_381::Bls12_381;
use ark_ec::PairingEngine;
use serde_wasm_bindgen::*;
use wasm_bindgen::prelude::*;

use vb_accumulator::prelude::{
    Accumulator, Keypair, MembershipProof, MembershipProofProtocol, MembershipProvingKey,
    MembershipWitness, NonMembershipProof, NonMembershipProofProtocol, NonMembershipProvingKey,
    NonMembershipWitness, Omega as Omega_, PositiveAccumulator, PublicKey, SecretKey, SetupParams,
    UniversalAccumulator,
};

use crate::Fr;
use ark_ff::One;
use blake2::Blake2b;

pub(crate) type AccumSk = SecretKey<Fr>;
pub(crate) type AccumPk = PublicKey<<Bls12_381 as PairingEngine>::G2Affine>;
pub(crate) type AccumSetupParams = SetupParams<Bls12_381>;
pub(crate) type AccumKeypair = Keypair<Bls12_381>;
pub(crate) type PositiveAccum = PositiveAccumulator<Bls12_381>;
pub(crate) type UniversalAccum = UniversalAccumulator<Bls12_381>;
pub(crate) type MembershipWit = MembershipWitness<<Bls12_381 as PairingEngine>::G1Affine>;
pub(crate) type NonMembershipWit = NonMembershipWitness<<Bls12_381 as PairingEngine>::G1Affine>;
pub(crate) type Omega = Omega_<<Bls12_381 as PairingEngine>::G1Affine>;
pub(crate) type MembershipPrk = MembershipProvingKey<<Bls12_381 as PairingEngine>::G1Affine>;
pub(crate) type NonMembershipPrk = NonMembershipProvingKey<<Bls12_381 as PairingEngine>::G1Affine>;
pub(crate) type MemProtocol = MembershipProofProtocol<Bls12_381>;
pub(crate) type MemProof = MembershipProof<Bls12_381>;
pub(crate) type NonMemProtocol = NonMembershipProofProtocol<Bls12_381>;
pub(crate) type NonMemProof = NonMembershipProof<Bls12_381>;

use crate::common::VerifyResponse;

#[wasm_bindgen(js_name = generateAccumulatorParams)]
pub async fn generate_accumulator_params(
    label: Option<Vec<u8>>,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let label = label.unwrap_or_else(|| random_bytes());
    let params = AccumSetupParams::new::<Blake2b>(&label);
    serde_wasm_bindgen::to_value(&params)
}

#[wasm_bindgen(js_name = isAccumulatorParamsValid)]
pub async fn accumulator_is_params_valid(
    params: JsValue,
) -> Result<bool, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let params: AccumSetupParams = serde_wasm_bindgen::from_value(params)?;
    Ok(params.is_valid())
}

#[wasm_bindgen(js_name = generateAccumulatorSecretKey)]
pub async fn accumulator_generate_secret_key(
    seed: Option<Vec<u8>>,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let seed = seed.unwrap_or_else(|| random_bytes());
    let sk = AccumSk::generate_using_seed::<Blake2b>(&seed);
    serde_wasm_bindgen::to_value(&sk)
}

#[wasm_bindgen(js_name = generateAccumulatorPublicKey)]
pub async fn accumulator_generate_public_key(
    secret_key: JsValue,
    params: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let params: AccumSetupParams = serde_wasm_bindgen::from_value(params)?;
    serde_wasm_bindgen::to_value(&AccumKeypair::public_key_from_secret_key(&sk, &params))
}

#[wasm_bindgen(js_name = isAccumulatorPublicKeyValid)]
pub async fn accumulator_is_pubkey_valid(
    public_key: JsValue,
) -> Result<bool, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let pk: AccumPk = serde_wasm_bindgen::from_value(public_key)?;
    Ok(pk.is_valid())
}

#[wasm_bindgen(js_name = generateAccumulatorKeyPair)]
pub async fn accumulator_generate_keypair(
    params: JsValue,
    seed: Option<Vec<u8>>,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let params: AccumSetupParams = serde_wasm_bindgen::from_value(params)?;
    let seed = seed.unwrap_or(random_bytes());
    let keypair = AccumKeypair::generate_using_seed::<Blake2b>(&seed, &params);
    serde_wasm_bindgen::to_value(&keypair)
}

#[wasm_bindgen(js_name = accumulatorGetElementFromBytes)]
pub async fn accumulator_get_element_from_bytes(
    bytes: Vec<u8>,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let f = fr_to_jsvalue(&encode_bytes_as_accumulator_member(&bytes))?;
    Ok(f)
}

#[wasm_bindgen(js_name = positiveAccumulatorInitialize)]
pub async fn positive_accumulator_initialize(
    params: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let params: AccumSetupParams = serde_wasm_bindgen::from_value(params)?;
    let accum = PositiveAccum::initialize(&params);
    serde_wasm_bindgen::to_value(&accum)
}

#[wasm_bindgen(js_name = positiveAccumulatorGetAccumulated)]
pub async fn positive_accumulator_get_accumulated(
    accum: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let accum: PositiveAccum = serde_wasm_bindgen::from_value(accum)?;
    let a = g1_affine_to_jsvalue(accum.value())?;
    Ok(a)
}

#[wasm_bindgen(js_name = positiveAccumulatorAdd)]
pub async fn positive_accumulator_add(
    existing_accum: JsValue,
    element: JsValue,
    secret_key: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let accum: PositiveAccum = serde_wasm_bindgen::from_value(existing_accum)?;
    let element = fr_from_jsvalue(element)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;

    let new_value = accum.compute_new_post_add(&element, &sk);

    serde_wasm_bindgen::to_value(&PositiveAccum::from_value(new_value))
}

#[wasm_bindgen(js_name = positiveAccumulatorRemove)]
pub async fn positive_accumulator_remove(
    existing_accum: JsValue,
    element: JsValue,
    secret_key: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let accum: PositiveAccum = serde_wasm_bindgen::from_value(existing_accum)?;
    let element = fr_from_jsvalue(element)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let new_value = accum.compute_new_post_remove(&element, &sk);
    serde_wasm_bindgen::to_value(&PositiveAccum::from_value(new_value))
}

#[wasm_bindgen(js_name = positiveAccumulatorMembershipWitness)]
pub async fn positive_accumulator_membership_witness(
    accum: JsValue,
    element: JsValue,
    secret_key: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let accum: PositiveAccum = serde_wasm_bindgen::from_value(accum)?;
    get_membership_witness(&accum, element, secret_key)
}

#[wasm_bindgen(js_name = positiveAccumulatorVerifyMembership)]
pub async fn positive_accumulator_verify_membership(
    accum: JsValue,
    element: JsValue,
    witness: JsValue,
    public_key: JsValue,
    params: JsValue,
) -> Result<bool, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let accum: PositiveAccum = serde_wasm_bindgen::from_value(accum)?;
    verify_membership(&accum, element, witness, public_key, params)
}

#[wasm_bindgen(js_name = universalAccumulatorComputeInitialFv)]
pub async fn universal_accumulator_compute_initial_fv(
    initial_elements: js_sys::Array,
    secret_key: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let initial_elements = js_array_to_fr_vec(&initial_elements)?;
    let f_v = UniversalAccum::compute_initial_f_V(&initial_elements, &sk);
    let f_v = fr_to_jsvalue(&f_v)?;
    Ok(f_v)
}

#[wasm_bindgen(js_name = universalAccumulatorCombineMultipleInitialFv)]
pub async fn universal_accumulator_combine_multiple_initial_fv(
    initial_f_vs: js_sys::Array,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let mut product = Fr::one();
    for f_v in initial_f_vs.values() {
        let f_v = f_v.unwrap();
        product *= fr_from_jsvalue(f_v)?;
    }
    let f_v = fr_to_jsvalue(&product)?;
    Ok(f_v)
}

#[wasm_bindgen(js_name = universalAccumulatorInitialiseGivenFv)]
pub async fn universal_accumulator_initialize_given_f_v(
    f_v: JsValue,
    params: JsValue,
    max_size: u32,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let f_v = fr_from_jsvalue(f_v)?;
    let params: AccumSetupParams = serde_wasm_bindgen::from_value(params)?;
    let accum = UniversalAccum::initialize_given_f_V(f_v, &params, max_size as u64);
    serde_wasm_bindgen::to_value(&accum)
}

#[wasm_bindgen(js_name = universalAccumulatorGetAccumulated)]
pub async fn universal_accumulator_get_accumulated(
    accum: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let accum: UniversalAccum = serde_wasm_bindgen::from_value(accum)?;
    let a = g1_affine_to_jsvalue(accum.value())?;
    Ok(a)
}

#[wasm_bindgen(js_name = universalAccumulatorAdd)]
pub async fn universal_accumulator_add(
    existing_accum: JsValue,
    element: JsValue,
    secret_key: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let accum: UniversalAccum = serde_wasm_bindgen::from_value(existing_accum)?;
    let element = fr_from_jsvalue(element)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let (f_v, v) = accum.compute_new_post_add(&element, &sk);
    serde_wasm_bindgen::to_value(&accum.get_updated(f_v, v))
}

#[wasm_bindgen(js_name = universalAccumulatorRemove)]
pub async fn universal_accumulator_remove(
    existing_accum: JsValue,
    element: JsValue,
    secret_key: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let accum: UniversalAccum = serde_wasm_bindgen::from_value(existing_accum)?;
    let element = fr_from_jsvalue(element)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let (f_v, v) = accum.compute_new_post_remove(&element, &sk);
    serde_wasm_bindgen::to_value(&accum.get_updated(f_v, v))
}

#[wasm_bindgen(js_name = universalAccumulatorMembershipWitness)]
pub async fn universal_accumulator_membership_witness(
    accum: JsValue,
    element: JsValue,
    secret_key: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let accum: UniversalAccum = serde_wasm_bindgen::from_value(accum)?;
    get_membership_witness(&accum, element, secret_key)
}

#[wasm_bindgen(js_name = universalAccumulatorVerifyMembership)]
pub async fn universal_accumulator_verify_membership(
    accum: JsValue,
    member: JsValue,
    witness: JsValue,
    public_key: JsValue,
    params: JsValue,
) -> Result<bool, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let accum: UniversalAccum = serde_wasm_bindgen::from_value(accum)?;
    verify_membership(&accum, member, witness, public_key, params)
}

#[wasm_bindgen(js_name = universalAccumulatorComputeD)]
pub async fn universal_accumulator_compute_d(
    non_member: JsValue,
    members: js_sys::Array,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let element = fr_from_jsvalue(non_member)?;
    let members = js_array_to_fr_vec(&members)?;
    let d = UniversalAccum::compute_d_given_members(&element, &members);
    let d = fr_to_jsvalue(&d)?;
    Ok(d)
}

#[wasm_bindgen(js_name = universalAccumulatorCombineMultipleD)]
pub async fn universal_accumulator_combine_multiple_d(
    ds: js_sys::Array,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let mut product = Fr::one();
    for d in ds.values() {
        let d = d.unwrap();
        product *= fr_from_jsvalue(d)?;
    }
    let d = fr_to_jsvalue(&product)?;
    Ok(d)
}

#[wasm_bindgen(js_name = universalAccumulatorNonMembershipWitness)]
pub async fn universal_accumulator_non_membership_witness(
    accum: JsValue,
    d: JsValue,
    non_member: JsValue,
    secret_key: JsValue,
    params: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let accum: UniversalAccum = serde_wasm_bindgen::from_value(accum)?;
    let element = fr_from_jsvalue(non_member)?;
    let d = fr_from_jsvalue(d)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let params: AccumSetupParams = serde_wasm_bindgen::from_value(params)?;
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
}

#[wasm_bindgen(js_name = universalAccumulatorVerifyNonMembership)]
pub async fn universal_accumulator_verify_non_membership(
    accum: JsValue,
    non_member: JsValue,
    witness: JsValue,
    public_key: JsValue,
    params: JsValue,
) -> Result<bool, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let accum: UniversalAccum = serde_wasm_bindgen::from_value(accum)?;
    let non_member = fr_from_jsvalue(non_member)?;
    let witness: NonMembershipWit = serde_wasm_bindgen::from_value(witness)?;
    let pk: AccumPk = serde_wasm_bindgen::from_value(public_key)?;
    let params: AccumSetupParams = serde_wasm_bindgen::from_value(params)?;
    Ok(accum.verify_non_membership(&non_member, &witness, &pk, &params))
}

#[wasm_bindgen(js_name = positiveAccumulatorAddBatch)]
pub async fn positive_accumulator_add_batch(
    existing_accum: JsValue,
    elements: js_sys::Array,
    secret_key: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let accum: PositiveAccum = serde_wasm_bindgen::from_value(existing_accum)?;
    let elems = js_array_to_fr_vec(&elements)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let new_value = accum.compute_new_post_add_batch(&elems, &sk);
    serde_wasm_bindgen::to_value(&PositiveAccum::from_value(new_value))
}

#[wasm_bindgen(js_name = positiveAccumulatorRemoveBatch)]
pub async fn positive_accumulator_remove_batch(
    existing_accum: JsValue,
    elements: js_sys::Array,
    secret_key: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let accum: PositiveAccum = serde_wasm_bindgen::from_value(existing_accum)?;
    let elems = js_array_to_fr_vec(&elements)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let new_value = accum.compute_new_post_remove_batch(&elems, &sk);
    serde_wasm_bindgen::to_value(&PositiveAccum::from_value(new_value))
}

#[wasm_bindgen(js_name = positiveAccumulatorBatchUpdates)]
pub async fn positive_accumulator_batch_updates(
    existing_accum: JsValue,
    additions: js_sys::Array,
    removals: js_sys::Array,
    secret_key: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let accum: PositiveAccum = serde_wasm_bindgen::from_value(existing_accum)?;
    let adds = js_array_to_fr_vec(&additions)?;
    let removes = js_array_to_fr_vec(&removals)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let new_value = accum.compute_new_post_batch_updates(&adds, &removes, &sk);
    serde_wasm_bindgen::to_value(&PositiveAccum::from_value(new_value))
}

#[wasm_bindgen(js_name = positiveAccumulatorMembershipWitnessesForBatch)]
pub async fn positive_accumulator_membership_witnesses_for_batch(
    accum: JsValue,
    elements: js_sys::Array,
    secret_key: JsValue,
) -> Result<js_sys::Array, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let accum: PositiveAccum = serde_wasm_bindgen::from_value(accum)?;

    get_membership_witnesses_for_batch(&accum, elements, secret_key)
}

#[wasm_bindgen(js_name = universalAccumulatorAddBatch)]
pub async fn universal_accumulator_add_batch(
    existing_accum: JsValue,
    elements: js_sys::Array,
    secret_key: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let accum: UniversalAccum = serde_wasm_bindgen::from_value(existing_accum)?;
    let elems = js_array_to_fr_vec(&elements)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let (f_v, v) = accum.compute_new_post_add_batch(&elems, &sk);
    serde_wasm_bindgen::to_value(&UniversalAccum::from_value(f_v, v, accum.max_size()))
}

#[wasm_bindgen(js_name = universalAccumulatorRemoveBatch)]
pub async fn universal_accumulator_remove_batch(
    existing_accum: JsValue,
    elements: js_sys::Array,
    secret_key: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let accum: UniversalAccum = serde_wasm_bindgen::from_value(existing_accum)?;
    let elems = js_array_to_fr_vec(&elements)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let (f_v, v) = accum.compute_new_post_remove_batch(&elems, &sk);
    serde_wasm_bindgen::to_value(&UniversalAccum::from_value(f_v, v, accum.max_size()))
}

#[wasm_bindgen(js_name = universalAccumulatorBatchUpdates)]
pub async fn universal_accumulator_batch_updates(
    existing_accum: JsValue,
    additions: js_sys::Array,
    removals: js_sys::Array,
    secret_key: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let accum: UniversalAccum = serde_wasm_bindgen::from_value(existing_accum)?;
    let adds = js_array_to_fr_vec(&additions)?;
    let removes = js_array_to_fr_vec(&removals)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let (f_v, v) = accum.compute_new_post_batch_updates(&adds, &removes, &sk);
    serde_wasm_bindgen::to_value(&UniversalAccum::from_value(f_v, v, accum.max_size()))
}

#[wasm_bindgen(js_name = universalAccumulatorMembershipWitnessesForBatch)]
pub async fn universal_accumulator_membership_witnesses_for_batch(
    accum: JsValue,
    elements: js_sys::Array,
    secret_key: JsValue,
) -> Result<js_sys::Array, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let accum: UniversalAccum = serde_wasm_bindgen::from_value(accum)?;
    get_membership_witnesses_for_batch(&accum, elements, secret_key)
}

#[wasm_bindgen(js_name = universalAccumulatorComputeDForBatch)]
pub async fn universal_accumulator_compute_d_for_batch(
    non_members: js_sys::Array,
    members: js_sys::Array,
) -> Result<js_sys::Array, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let non_members = js_array_to_fr_vec(&non_members)?;
    let members = js_array_to_fr_vec(&members)?;
    let d = UniversalAccum::compute_d_for_batch_given_members(&non_members, &members);
    js_array_from_frs(&d)
}

#[wasm_bindgen(js_name = universalAccumulatorCombineMultipleDForBatch)]
pub async fn universal_accumulator_combine_multiple_d_for_batch(
    ds: js_sys::Array,
) -> Result<js_sys::Array, serde_wasm_bindgen::Error> {
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
            return Err(Error::from(JsValue::from(format!(
                "All d should be equal, {}, {}",
                arr.length(),
                *length.as_ref().unwrap()
            ))));
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
pub async fn universal_accumulator_non_membership_witnesses_for_batch(
    accum: JsValue,
    d: js_sys::Array,
    non_members: js_sys::Array,
    secret_key: JsValue,
    params: JsValue,
) -> Result<js_sys::Array, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let accum: UniversalAccum = serde_wasm_bindgen::from_value(accum)?;
    let d = js_array_to_fr_vec(&d)?;
    let non_members = js_array_to_fr_vec(&non_members)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let params: AccumSetupParams = serde_wasm_bindgen::from_value(params)?;
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
        result.push(&serde_wasm_bindgen::to_value(&witness)?);
    }
    Ok(result)
}

#[wasm_bindgen(js_name = updateMembershipWitnessPostAdd)]
pub async fn update_membership_witness_post_add(
    witness: JsValue,
    member: JsValue,
    addition: JsValue,
    old_accumulated: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let witness: MembershipWit = serde_wasm_bindgen::from_value(witness)?;
    crate::update_witness_post_add!(witness, member, addition, old_accumulated)
}

#[wasm_bindgen(js_name = updateMembershipWitnessPostRemove)]
pub async fn update_membership_witness_post_remove(
    witness: JsValue,
    member: JsValue,
    removal: JsValue,
    new_accumulated: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let witness: MembershipWit = serde_wasm_bindgen::from_value(witness)?;
    crate::update_witness_post_remove!(witness, member, removal, new_accumulated)
}

#[wasm_bindgen(js_name = updateNonMembershipWitnessPostAdd)]
pub async fn update_non_membership_witness_post_add(
    witness: JsValue,
    non_member: JsValue,
    addition: JsValue,
    old_accumulated: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let witness: NonMembershipWit = serde_wasm_bindgen::from_value(witness)?;
    crate::update_witness_post_add!(witness, non_member, addition, old_accumulated)
}

#[wasm_bindgen(js_name = updateNonMembershipWitnessPostRemove)]
pub async fn update_non_membership_witness_post_remove(
    witness: JsValue,
    non_member: JsValue,
    removal: JsValue,
    new_accumulated: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let witness: NonMembershipWit = serde_wasm_bindgen::from_value(witness)?;
    crate::update_witness_post_remove!(witness, non_member, removal, new_accumulated)
}

#[wasm_bindgen(js_name = publicInfoForWitnessUpdate)]
pub async fn public_info_for_witness_update(
    old_accumulated: JsValue,
    additions: js_sys::Array,
    removals: js_sys::Array,
    secret_key: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let existing_accumulated = g1_affine_from_jsvalue(old_accumulated)?;
    let additions = js_array_to_fr_vec(&additions)?;
    let removals = js_array_to_fr_vec(&removals)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let omega = Omega::new(&additions, &removals, &existing_accumulated, &sk);
    serde_wasm_bindgen::to_value(&omega)
}

#[wasm_bindgen(js_name = updateMembershipWitnessUsingPublicInfoAfterBatchUpdate)]
pub async fn update_membership_witness_using_public_info_after_batch_update(
    witness: JsValue,
    member: JsValue,
    additions: js_sys::Array,
    removals: js_sys::Array,
    public_info: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let witness: MembershipWit = serde_wasm_bindgen::from_value(witness)?;
    crate::update_witness_single_batch!(witness, member, additions, removals, public_info)
}

#[wasm_bindgen(js_name = updateMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates)]
pub async fn update_membership_witness_using_public_info_after_multiple_batch_updates(
    witness: JsValue,
    member: JsValue,
    additions: js_sys::Array,
    removals: js_sys::Array,
    public_info: js_sys::Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let witness: MembershipWit = serde_wasm_bindgen::from_value(witness)?;
    crate::update_witness_multiple_batches!(witness, member, additions, removals, public_info)
}

#[wasm_bindgen(js_name = updateNonMembershipWitnessUsingPublicInfoAfterBatchUpdate)]
pub async fn update_non_membership_witness_using_public_info_after_batch_update(
    witness: JsValue,
    non_member: JsValue,
    additions: js_sys::Array,
    removals: js_sys::Array,
    public_info: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let witness: NonMembershipWit = serde_wasm_bindgen::from_value(witness)?;
    crate::update_witness_single_batch!(witness, non_member, additions, removals, public_info)
}

#[wasm_bindgen(js_name = updateNonMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates)]
pub async fn update_non_membership_witness_using_public_info_after_multiple_batch_updates(
    witness: JsValue,
    non_member: JsValue,
    additions: js_sys::Array,
    removals: js_sys::Array,
    public_info: js_sys::Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let witness: NonMembershipWit = serde_wasm_bindgen::from_value(witness)?;
    crate::update_witness_multiple_batches!(witness, non_member, additions, removals, public_info)
}

#[wasm_bindgen(js_name = generateMembershipProvingKey)]
pub async fn generate_membership_proving_key(
    label: Option<Vec<u8>>,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let label = label.unwrap_or_else(|| random_bytes());
    let prk = MembershipPrk::new::<Blake2b>(&label);
    serde_wasm_bindgen::to_value(&prk)
}

#[wasm_bindgen(js_name = generateNonMembershipProvingKey)]
pub async fn generate_non_membership_proving_key(
    label: Option<Vec<u8>>,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let label = label.unwrap_or_else(|| random_bytes());
    let prk = NonMembershipPrk::new::<Blake2b>(&label);
    serde_wasm_bindgen::to_value(&prk)
}

#[wasm_bindgen(js_name = accumulatorDeriveMembershipProvingKeyFromNonMembershipKey)]
pub async fn accumulator_derive_membership_proving_key_from_non_membership_key(
    proving_key: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    let prk: NonMembershipPrk = serde_wasm_bindgen::from_value(proving_key)?;
    serde_wasm_bindgen::to_value(&prk.derive_membership_proving_key())
}

#[wasm_bindgen(js_name = accumulatorInitializeMembershipProof)]
pub async fn accumulator_initialize_membership_proof(
    member: JsValue,
    blinding: JsValue,
    witness: JsValue,
    public_key: JsValue,
    params: JsValue,
    proving_key: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();

    let witness: MembershipWit = serde_wasm_bindgen::from_value(witness)?;
    let prk: MembershipPrk = serde_wasm_bindgen::from_value(proving_key)?;
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
pub async fn accumulator_gen_membership_proof(
    protocol: JsValue,
    challenge: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let protocol: MemProtocol = serde_wasm_bindgen::from_value(protocol)?;
    let challenge = fr_from_jsvalue(challenge)?;
    serde_wasm_bindgen::to_value(&protocol.gen_proof(&challenge))
}

#[wasm_bindgen(js_name = accumulatorVerifyMembershipProof)]
pub async fn accumulator_verify_membership_proof(
    proof: JsValue,
    accumulated: JsValue,
    challenge: JsValue,
    public_key: JsValue,
    params: JsValue,
    proving_key: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let proof: MemProof = serde_wasm_bindgen::from_value(proof)?;
    let prk: MembershipPrk = serde_wasm_bindgen::from_value(proving_key)?;
    crate::verify_proof!(proof, accumulated, challenge, public_key, params, prk)
}

#[wasm_bindgen(js_name = accumulatorChallengeContributionFromMembershipProtocol)]
pub async fn accumulator_challenge_contribution_from_membership_protocol(
    protocol: JsValue,
    accumulated: JsValue,
    public_key: JsValue,
    params: JsValue,
    proving_key: JsValue,
) -> Result<js_sys::Uint8Array, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let protocol: MemProtocol = serde_wasm_bindgen::from_value(protocol)?;
    let prk: MembershipPrk = serde_wasm_bindgen::from_value(proving_key)?;
    let accumulated = g1_affine_from_jsvalue(accumulated)?;
    let pk: AccumPk = serde_wasm_bindgen::from_value(public_key)?;
    let params: AccumSetupParams = serde_wasm_bindgen::from_value(params)?;
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
pub async fn accumulator_challenge_contribution_from_membership_proof(
    proof: JsValue,
    accumulated: JsValue,
    public_key: JsValue,
    params: JsValue,
    proving_key: JsValue,
) -> Result<js_sys::Uint8Array, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let proof: MemProof = serde_wasm_bindgen::from_value(proof)?;
    let prk: MembershipPrk = serde_wasm_bindgen::from_value(proving_key)?;
    let accumulated = g1_affine_from_jsvalue(accumulated)?;
    let pk: AccumPk = serde_wasm_bindgen::from_value(public_key)?;
    let params: AccumSetupParams = serde_wasm_bindgen::from_value(params)?;
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
pub async fn accumulator_initialize_non_membership_proof(
    non_member: JsValue,
    blinding: JsValue,
    witness: JsValue,
    public_key: JsValue,
    params: JsValue,
    proving_key: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();

    let witness: NonMembershipWit = serde_wasm_bindgen::from_value(witness)?;
    let prk: NonMembershipPrk = serde_wasm_bindgen::from_value(proving_key)?;
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
pub async fn accumulator_gen_non_membership_proof(
    protocol: JsValue,
    challenge: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let protocol: NonMemProtocol = serde_wasm_bindgen::from_value(protocol)?;
    let challenge = fr_from_jsvalue(challenge)?;
    serde_wasm_bindgen::to_value(&protocol.gen_proof(&challenge))
}

#[wasm_bindgen(js_name = accumulatorVerifyNonMembershipProof)]
pub async fn accumulator_verify_non_membership_proof(
    proof: JsValue,
    accumulated: JsValue,
    challenge: JsValue,
    public_key: JsValue,
    params: JsValue,
    proving_key: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let proof: NonMemProof = serde_wasm_bindgen::from_value(proof)?;
    let prk: NonMembershipPrk = serde_wasm_bindgen::from_value(proving_key)?;
    crate::verify_proof!(proof, accumulated, challenge, public_key, params, prk)
}

#[wasm_bindgen(js_name = accumulatorChallengeContributionFromNonMembershipProtocol)]
pub async fn accumulator_challenge_contribution_from_non_membership_protocol(
    protocol: JsValue,
    accumulated: JsValue,
    public_key: JsValue,
    params: JsValue,
    proving_key: JsValue,
) -> Result<js_sys::Uint8Array, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let protocol: NonMemProtocol = serde_wasm_bindgen::from_value(protocol)?;
    let prk: NonMembershipPrk = serde_wasm_bindgen::from_value(proving_key)?;
    let accumulated = g1_affine_from_jsvalue(accumulated)?;
    let pk: AccumPk = serde_wasm_bindgen::from_value(public_key)?;
    let params: AccumSetupParams = serde_wasm_bindgen::from_value(params)?;
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
pub async fn accumulator_challenge_contribution_from_non_membership_proof(
    proof: JsValue,
    accumulated: JsValue,
    public_key: JsValue,
    params: JsValue,
    proving_key: JsValue,
) -> Result<js_sys::Uint8Array, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let proof: NonMemProof = serde_wasm_bindgen::from_value(proof)?;
    let prk: NonMembershipPrk = serde_wasm_bindgen::from_value(proving_key)?;
    let accumulated = g1_affine_from_jsvalue(accumulated)?;
    let pk: AccumPk = serde_wasm_bindgen::from_value(public_key)?;
    let params: AccumSetupParams = serde_wasm_bindgen::from_value(params)?;
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

fn get_membership_witness(
    accum: &dyn Accumulator<Bls12_381>,
    element: JsValue,
    sk: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    let element = fr_from_jsvalue(element)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(sk)?;
    let new_value = accum.compute_membership_witness(&element, &sk);
    serde_wasm_bindgen::to_value(&new_value)
}

fn get_membership_witnesses_for_batch(
    accum: &dyn Accumulator<Bls12_381>,
    elements: js_sys::Array,
    sk: JsValue,
) -> Result<js_sys::Array, serde_wasm_bindgen::Error> {
    let elems = js_array_to_fr_vec(&elements)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(sk)?;

    let witnesses = accum.compute_membership_witness_for_batch(&elems, &sk);

    let result = js_sys::Array::new();
    for witness in witnesses {
        result.push(&serde_wasm_bindgen::to_value(&witness)?);
    }
    Ok(result)
}

fn verify_membership(
    accum: &dyn Accumulator<Bls12_381>,
    element: JsValue,
    witness: JsValue,
    pk: JsValue,
    params: JsValue,
) -> Result<bool, serde_wasm_bindgen::Error> {
    let element = fr_from_jsvalue(element)?;
    let witness: MembershipWit = serde_wasm_bindgen::from_value(witness)?;
    let pk: AccumPk = serde_wasm_bindgen::from_value(pk)?;
    let params: AccumSetupParams = serde_wasm_bindgen::from_value(params)?;
    Ok(accum.verify_membership(&element, &witness, &pk, &params))
}

#[macro_use]
mod macros {
    #[macro_export]
    macro_rules! update_witness_post_add {
        ($witness:expr, $element: ident, $addition: ident, $old_accumulated: ident) => {{
            let element = fr_from_jsvalue($element)?;
            let addition = fr_from_jsvalue($addition)?;
            let old_accumulated = g1_affine_from_jsvalue($old_accumulated)?;
            serde_wasm_bindgen::to_value(&$witness.update_after_addition(
                &element,
                &addition,
                &old_accumulated,
            ))
        }};
    }

    #[macro_export]
    macro_rules! update_witness_post_remove {
        ($witness:expr, $element: ident, $removal: ident, $new_accumulated: ident) => {{
            let element = fr_from_jsvalue($element)?;
            let removal = fr_from_jsvalue($removal)?;
            let new_accumulated = g1_affine_from_jsvalue($new_accumulated)?;
            let new_wit = $witness
                .update_after_removal(&element, &removal, &new_accumulated)
                .map_err(|e| {
                    JsValue::from(&format!(
                        "Evaluating update_after_removal returned error: {:?}",
                        e
                    ))
                })?;
            serde_wasm_bindgen::to_value(&new_wit)
        }};
    }

    #[macro_export]
    macro_rules! update_witness_single_batch {
        ($witness:expr, $element: ident, $additions: ident, $removals: ident, $public_info: ident) => {{
            let element = fr_from_jsvalue($element)?;
            let additions = js_array_to_fr_vec(&$additions)?;
            let removals = js_array_to_fr_vec(&$removals)?;
            let public_info: Omega = serde_wasm_bindgen::from_value($public_info)?;
            let new_witness = $witness
                .update_using_public_info_after_batch_updates(&additions, &removals, &public_info, &element)
                .map_err(|e| {
                    JsValue::from(&format!(
                        "Evaluating update_using_public_info_after_batch_updates returned error: {:?}",
                        e
                    ))
                })?;
            serde_wasm_bindgen::to_value(&new_witness)
        }}
    }

    #[macro_export]
    macro_rules! update_witness_multiple_batches {
        ($witness:expr, $element: ident, $additions: ident, $removals: ident, $public_info: ident) => {{
            let element = fr_from_jsvalue($element)?;
            if $additions.length() == $removals.length() && $removals.length() == $public_info.length() {
                let size = $additions.length();
                let mut updates_and_public_info = Vec::with_capacity(size as usize);
                for i in 0..size {
                    let adds = js_array_to_fr_vec(&js_sys::Array::from(&$additions.get(i)))?;
                    let rems = js_array_to_fr_vec(&js_sys::Array::from(&$removals.get(i)))?;
                    let p = Omega::from(js_array_to_g1_affine_vec(&js_sys::Array::from(
                        &$public_info.get(i),
                    ))?);
                    updates_and_public_info.push((adds, rems, p));
                }
                let new_witness = $witness.update_using_public_info_after_multiple_batch_updates(updates_and_public_info.iter().map(|(a, r, p)| (a.as_slice(), r.as_slice(), p)).collect::<Vec<_>>(), &element)
                .map_err(|e| {
                    JsValue::from(&format!(
                        "Evaluating update_using_public_info_after_multiple_batch_updates returned error: {:?}",
                        e
                    ))
                })?;
                let w = serde_wasm_bindgen::to_value(&new_witness)?;
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
            let element = fr_from_jsvalue($element)?;
            let blinding = fr_from_jsvalue($blinding)?;
            let pk: AccumPk = serde_wasm_bindgen::from_value($public_key)?;
            let params: AccumSetupParams = serde_wasm_bindgen::from_value($params)?;

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
            serde_wasm_bindgen::to_value(&protocol)
        }};
    }

    #[macro_export]
    macro_rules! verify_proof {
        ($proof: ident, $accumulated:ident, $challenge: ident, $public_key: ident, $params: ident, $prk: ident) => {{
            let accumulated = g1_affine_from_jsvalue($accumulated)?;
            let challenge = fr_from_jsvalue($challenge)?;
            let pk: AccumPk = serde_wasm_bindgen::from_value($public_key)?;
            let params: AccumSetupParams = serde_wasm_bindgen::from_value($params)?;

            match $proof.verify(&accumulated, &challenge, &pk, &params, &$prk) {
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
}
