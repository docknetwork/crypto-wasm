use crate::{
    accumulator::{
        common::{deserialize_params, deserialize_public_key, AccumSk},
        vb_accumulator::Omega,
    },
    utils::{fr_from_uint8_array, js_array_to_fr_vec, set_panic_hook},
};
use ark_bls12_381::{Bls12_381, G1Affine};
use ark_ec::pairing::Pairing;
use ark_serialize::CanonicalDeserialize;
use js_sys::Uint8Array;
use vb_accumulator::kb_universal_accumulator::{
    witness::{
        KBUniversalAccumulatorMembershipWitness, KBUniversalAccumulatorNonMembershipWitness,
    },
    KBUniversalAccumulator,
};
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
use zeroize::Zeroize;

pub(crate) type KBUniversalAccum = KBUniversalAccumulator<G1Affine>;
pub(crate) type KBUniMembershipWit =
    KBUniversalAccumulatorMembershipWitness<<Bls12_381 as Pairing>::G1Affine>;
pub(crate) type KBUniNonMembershipWit =
    KBUniversalAccumulatorNonMembershipWitness<<Bls12_381 as Pairing>::G1Affine>;

#[wasm_bindgen(js_name = kbUniversalAccumulatorInitialise)]
pub fn kb_universal_accumulator_initialize(
    domain: js_sys::Array,
    secret_key: JsValue,
    params: Uint8Array,
) -> Result<JsValue, JsValue> {
    let domain = js_array_to_fr_vec(&domain)?;
    let secret_key: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let params = deserialize_params(params)?;
    let accum = KBUniversalAccum::initialize_empty(&params);
    let (mem, non_mem) = accum.compute_extended(&domain, &secret_key);
    let new = KBUniversalAccum::from_accumulated(mem, non_mem);
    serde_wasm_bindgen::to_value(&new).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = kbUniversalAccumulatorComputeExtended)]
pub fn kb_universal_accumulator_compute_extended(
    old_accum: JsValue,
    new_elements: js_sys::Array,
    secret_key: JsValue,
) -> Result<JsValue, JsValue> {
    let accum: KBUniversalAccum = serde_wasm_bindgen::from_value(old_accum)?;
    let new_elements = js_array_to_fr_vec(&new_elements)?;
    let secret_key: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let (mem, non_mem) = accum.compute_extended(&new_elements, &secret_key);
    let new = KBUniversalAccum::from_accumulated(mem, non_mem);
    serde_wasm_bindgen::to_value(&new).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = kbUniversalAccumulatorAdd)]
pub fn kb_universal_accumulator_add(
    old_accum: JsValue,
    element: Uint8Array,
    secret_key: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let accum: KBUniversalAccum = serde_wasm_bindgen::from_value(old_accum)?;
    let element = fr_from_uint8_array(element, true)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let (mem, non_mem) = accum.compute_new_post_add(&element, &sk);
    let new = KBUniversalAccum::from_accumulated(mem, non_mem);
    serde_wasm_bindgen::to_value(&new).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = kbUniversalAccumulatorRemove)]
pub fn kb_universal_accumulator_remove(
    old_accum: JsValue,
    element: Uint8Array,
    secret_key: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let accum: KBUniversalAccum = serde_wasm_bindgen::from_value(old_accum)?;
    let element = fr_from_uint8_array(element, true)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let (mem, non_mem) = accum.compute_new_post_remove(&element, &sk);
    let new = KBUniversalAccum::from_accumulated(mem, non_mem);
    serde_wasm_bindgen::to_value(&new).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = kbUniversalAccumulatorMembershipWitness)]
pub fn kb_universal_accumulator_membership_witness(
    accum: JsValue,
    element: Uint8Array,
    secret_key: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let accum: KBUniversalAccum = serde_wasm_bindgen::from_value(accum)?;
    crate::get_membership_witness!(accum, element, secret_key)
}

#[wasm_bindgen(js_name = kbUniversalAccumulatorVerifyMembership)]
pub fn kb_universal_accumulator_verify_membership(
    accum: JsValue,
    member: Uint8Array,
    witness: JsValue,
    public_key: Uint8Array,
    params: Uint8Array,
) -> Result<bool, JsValue> {
    set_panic_hook();
    let accum: KBUniversalAccum = serde_wasm_bindgen::from_value(accum)?;
    crate::verify_membership!(
        accum,
        member,
        KBUniMembershipWit,
        witness,
        public_key,
        params
    )
}

#[wasm_bindgen(js_name = kbUniversalAccumulatorNonMembershipWitness)]
pub fn kb_universal_accumulator_non_membership_witness(
    accum: JsValue,
    non_member: Uint8Array,
    secret_key: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let accum: KBUniversalAccum = serde_wasm_bindgen::from_value(accum)?;
    let element = fr_from_uint8_array(non_member, true)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let new_value = accum.compute_non_membership_witness(&element, &sk);
    serde_wasm_bindgen::to_value(&new_value).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = kbUniversalAccumulatorVerifyNonMembership)]
pub fn universal_accumulator_verify_non_membership(
    accum: JsValue,
    non_member: Uint8Array,
    witness: JsValue,
    public_key: Uint8Array,
    params: Uint8Array,
) -> Result<bool, JsValue> {
    set_panic_hook();
    let accum: KBUniversalAccum = serde_wasm_bindgen::from_value(accum)?;
    let non_member = fr_from_uint8_array(non_member, true)?;
    let witness: KBUniNonMembershipWit = serde_wasm_bindgen::from_value(witness)?;
    let pk = deserialize_public_key(public_key)?;
    let params = deserialize_params(params)?;
    Ok(accum.verify_non_membership(&non_member, &witness, &pk, &params))
}

#[wasm_bindgen(js_name = kbUniversalAccumulatorAddBatch)]
pub fn kb_universal_accumulator_add_batch(
    existing_accum: JsValue,
    elements: js_sys::Array,
    secret_key: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let accum: KBUniversalAccum = serde_wasm_bindgen::from_value(existing_accum)?;
    let elems = js_array_to_fr_vec(&elements)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let (mem, non_mem) = accum.compute_new_post_add_batch(&elems, &sk);
    let new = KBUniversalAccum::from_accumulated(mem, non_mem);
    serde_wasm_bindgen::to_value(&new).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = kbUniversalAccumulatorRemoveBatch)]
pub fn kb_universal_accumulator_remove_batch(
    existing_accum: JsValue,
    elements: js_sys::Array,
    secret_key: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let accum: KBUniversalAccum = serde_wasm_bindgen::from_value(existing_accum)?;
    let elems = js_array_to_fr_vec(&elements)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let (mem, non_mem) = accum.compute_new_post_remove_batch(&elems, &sk);
    let new = KBUniversalAccum::from_accumulated(mem, non_mem);
    serde_wasm_bindgen::to_value(&new).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = kbUniversalAccumulatorBatchUpdates)]
pub fn kb_universal_accumulator_batch_updates(
    existing_accum: JsValue,
    additions: js_sys::Array,
    removals: js_sys::Array,
    secret_key: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let accum: KBUniversalAccum = serde_wasm_bindgen::from_value(existing_accum)?;
    let adds = js_array_to_fr_vec(&additions)?;
    let removes = js_array_to_fr_vec(&removals)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let (mem, non_mem) = accum.compute_new_post_batch_updates(&adds, &removes, &sk);
    let new = KBUniversalAccum::from_accumulated(mem, non_mem);
    serde_wasm_bindgen::to_value(&new).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = kbUniversalAccumulatorMembershipWitnessesForBatch)]
pub fn kb_universal_accumulator_membership_witnesses_for_batch(
    accum: JsValue,
    elements: js_sys::Array,
    secret_key: JsValue,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    let accum: KBUniversalAccum = serde_wasm_bindgen::from_value(accum)?;
    crate::get_membership_witnesses_for_batch!(accum, elements, secret_key)
}

#[wasm_bindgen(js_name = kbUniversalAccumulatorNonMembershipWitnessesForBatch)]
pub fn kb_universal_accumulator_non_membership_witnesses_for_batch(
    accum: JsValue,
    non_members: js_sys::Array,
    secret_key: JsValue,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    let accum: KBUniversalAccum = serde_wasm_bindgen::from_value(accum)?;
    let non_members = js_array_to_fr_vec(&non_members)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let witnesses = accum.compute_non_membership_witnesses_for_batch(&non_members, &sk);
    let result = js_sys::Array::new();
    for witness in witnesses {
        result.push(&serde_wasm_bindgen::to_value(&witness).map_err(JsValue::from)?);
    }
    Ok(result)
}

#[wasm_bindgen(js_name = kbUniversalUpdateMembershipWitnessPostAdd)]
pub fn kb_universal_update_membership_witness_post_add(
    witness: JsValue,
    member: Uint8Array,
    addition: Uint8Array,
    old_accum: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let witness: KBUniMembershipWit = serde_wasm_bindgen::from_value(witness)?;
    let member = fr_from_uint8_array(member, true)?;
    let addition = fr_from_uint8_array(addition, true)?;
    let accum: KBUniversalAccum = serde_wasm_bindgen::from_value(old_accum)?;
    let new = accum.update_mem_wit_on_addition(&witness, &member, &addition);
    serde_wasm_bindgen::to_value(&new).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = kbUniversalUpdateMembershipWitnessPostRemove)]
pub fn kb_universal_update_membership_witness_post_remove(
    witness: JsValue,
    member: Uint8Array,
    removal: Uint8Array,
    new_accum: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let witness: KBUniMembershipWit = serde_wasm_bindgen::from_value(witness)?;
    let member = fr_from_uint8_array(member, true)?;
    let removal = fr_from_uint8_array(removal, true)?;
    let accum: KBUniversalAccum = serde_wasm_bindgen::from_value(new_accum)?;
    let new = accum
        .update_mem_wit_on_removal(&witness, &member, &removal)
        .map_err(|e| {
            JsValue::from(&format!(
                "Evaluating update_mem_wit_on_removal returned error: {:?}",
                e
            ))
        })?;
    serde_wasm_bindgen::to_value(&new).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = kbUniversalUpdateNonMembershipWitnessPostAdd)]
pub fn kb_universal_update_non_membership_witness_post_add(
    witness: JsValue,
    non_member: Uint8Array,
    addition: Uint8Array,
    new_accum: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let witness: KBUniNonMembershipWit = serde_wasm_bindgen::from_value(witness)?;
    let non_member = fr_from_uint8_array(non_member, true)?;
    let addition = fr_from_uint8_array(addition, true)?;
    let accum: KBUniversalAccum = serde_wasm_bindgen::from_value(new_accum)?;
    let new = accum
        .update_non_mem_wit_on_addition(&witness, &non_member, &addition)
        .map_err(|e| {
            JsValue::from(&format!(
                "Evaluating update_non_mem_wit_on_addition returned error: {:?}",
                e
            ))
        })?;
    serde_wasm_bindgen::to_value(&new).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = kbUniversalUpdateNonMembershipWitnessPostRemove)]
pub fn kb_universal_update_non_membership_witness_post_remove(
    witness: JsValue,
    non_member: Uint8Array,
    removal: Uint8Array,
    old_accum: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let witness: KBUniNonMembershipWit = serde_wasm_bindgen::from_value(witness)?;
    let non_member = fr_from_uint8_array(non_member, true)?;
    let removal = fr_from_uint8_array(removal, true)?;
    let accum: KBUniversalAccum = serde_wasm_bindgen::from_value(old_accum)?;
    let new = accum.update_non_mem_wit_on_removal(&witness, &non_member, &removal);
    serde_wasm_bindgen::to_value(&new).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = kbUpdateMembershipWitnessesPostBatchUpdates)]
pub fn kb_universal_update_membership_witnesses_post_batch_updates(
    witnesses: js_sys::Array,
    members: js_sys::Array,
    additions: js_sys::Array,
    removals: js_sys::Array,
    old_accum: JsValue,
    secret_key: JsValue,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    let members = js_array_to_fr_vec(&members)?;
    let additions = js_array_to_fr_vec(&additions)?;
    let removals = js_array_to_fr_vec(&removals)?;
    let accum: KBUniversalAccum = serde_wasm_bindgen::from_value(old_accum)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let mut wits = Vec::with_capacity(witnesses.length() as usize);
    for w in witnesses.values() {
        wits.push(serde_wasm_bindgen::from_value::<KBUniMembershipWit>(
            w.unwrap(),
        )?);
    }
    let new_wits = accum
        .update_mem_wit_using_secret_key_on_batch_updates(
            &additions, &removals, &members, &wits, &sk,
        )
        .map_err(|e| {
            JsValue::from(&format!(
                "Evaluating update_mem_wit_using_secret_key_on_batch_updates returned error: {:?}",
                e
            ))
        })?;
    let result = js_sys::Array::new();
    for w in new_wits {
        result.push(&serde_wasm_bindgen::to_value(&w).map_err(JsValue::from)?);
    }
    Ok(result)
}

#[wasm_bindgen(js_name = kbUpdateNonMembershipWitnessesPostBatchUpdates)]
pub fn kb_universal_update_non_membership_witnesses_post_batch_updates(
    witnesses: js_sys::Array,
    non_members: js_sys::Array,
    additions: js_sys::Array,
    removals: js_sys::Array,
    old_accum: JsValue,
    secret_key: JsValue,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    let non_members = js_array_to_fr_vec(&non_members)?;
    let additions = js_array_to_fr_vec(&additions)?;
    let removals = js_array_to_fr_vec(&removals)?;
    let accum: KBUniversalAccum = serde_wasm_bindgen::from_value(old_accum)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let mut wits = Vec::with_capacity(witnesses.length() as usize);
    for w in witnesses.values() {
        wits.push(serde_wasm_bindgen::from_value::<KBUniNonMembershipWit>(
            w.unwrap(),
        )?);
    }
    let new_wits = accum.update_non_mem_wit_using_secret_key_on_batch_updates(
        &additions,
        &removals,
        &non_members,
        &wits,
        &sk,
    )
        .map_err(|e| {
            JsValue::from(&format!(
                "Evaluating update_non_mem_wit_using_secret_key_on_batch_updates returned error: {:?}",
                e
            ))
        })?;
    let result = js_sys::Array::new();
    for w in new_wits {
        result.push(&serde_wasm_bindgen::to_value(&w).map_err(JsValue::from)?);
    }
    Ok(result)
}

#[wasm_bindgen(js_name = kbUpdateBothWitnessesPostBatchUpdates)]
pub fn kb_universal_update_both_witnesses_post_batch_updates(
    mem_witnesses: js_sys::Array,
    members: js_sys::Array,
    non_mem_witnesses: js_sys::Array,
    non_members: js_sys::Array,
    additions: js_sys::Array,
    removals: js_sys::Array,
    old_accum: JsValue,
    secret_key: JsValue,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    let members = js_array_to_fr_vec(&members)?;
    let non_members = js_array_to_fr_vec(&non_members)?;
    let additions = js_array_to_fr_vec(&additions)?;
    let removals = js_array_to_fr_vec(&removals)?;
    let accum: KBUniversalAccum = serde_wasm_bindgen::from_value(old_accum)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let mut mem_wits = Vec::with_capacity(mem_witnesses.length() as usize);
    for w in mem_witnesses.values() {
        mem_wits.push(serde_wasm_bindgen::from_value::<KBUniMembershipWit>(
            w.unwrap(),
        )?);
    }
    let mut non_mem_wits = Vec::with_capacity(non_mem_witnesses.length() as usize);
    for w in non_mem_witnesses.values() {
        non_mem_wits.push(serde_wasm_bindgen::from_value::<KBUniNonMembershipWit>(
            w.unwrap(),
        )?);
    }
    let (new_mem_wits, new_non_mem_wits) = accum
        .update_both_wit_using_secret_key_on_batch_updates(
            &additions,
            &removals,
            &members,
            &mem_wits,
            &non_members,
            &non_mem_wits,
            &sk,
        )
        .map_err(|e| {
            JsValue::from(&format!(
                "Evaluating update_both_wit_using_secret_key_on_batch_updates returned error: {:?}",
                e
            ))
        })?;
    let result = js_sys::Array::new();
    let mem_wit_arr = js_sys::Array::new();
    let non_mem_wit_arr = js_sys::Array::new();
    for w in new_mem_wits {
        mem_wit_arr.push(&serde_wasm_bindgen::to_value(&w).map_err(JsValue::from)?);
    }
    for w in new_non_mem_wits {
        non_mem_wit_arr.push(&serde_wasm_bindgen::to_value(&w).map_err(JsValue::from)?);
    }
    result.push(&mem_wit_arr);
    result.push(&non_mem_wit_arr);
    Ok(result)
}

#[wasm_bindgen(js_name = publicInfoForKBUniversalMemWitnessUpdate)]
pub fn public_info_for_kb_universal_mem_witness_update(
    old_accum: JsValue,
    additions: js_sys::Array,
    removals: js_sys::Array,
    secret_key: JsValue,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let accum: KBUniversalAccum = serde_wasm_bindgen::from_value(old_accum)?;
    let additions = js_array_to_fr_vec(&additions)?;
    let removals = js_array_to_fr_vec(&removals)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let omega = accum.generate_omega_for_membership_witnesses(&additions, &removals, &sk);
    Ok(obj_to_uint8array!(&omega, false, "Omega"))
}

#[wasm_bindgen(js_name = publicInfoForKBUniversalNonMemWitnessUpdate)]
pub fn public_info_for_kb_universal_non_mem_witness_update(
    old_accum: JsValue,
    additions: js_sys::Array,
    removals: js_sys::Array,
    secret_key: JsValue,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let accum: KBUniversalAccum = serde_wasm_bindgen::from_value(old_accum)?;
    let additions = js_array_to_fr_vec(&additions)?;
    let removals = js_array_to_fr_vec(&removals)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let omega = accum.generate_omega_for_non_membership_witnesses(&additions, &removals, &sk);
    Ok(obj_to_uint8array!(&omega, false, "Omega"))
}

#[wasm_bindgen(js_name = publicInfoForBothKBUniversalWitnessUpdate)]
pub fn public_info_for_both_kb_universal_witness_update(
    old_accum: JsValue,
    additions: js_sys::Array,
    removals: js_sys::Array,
    secret_key: JsValue,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    let accum: KBUniversalAccum = serde_wasm_bindgen::from_value(old_accum)?;
    let additions = js_array_to_fr_vec(&additions)?;
    let removals = js_array_to_fr_vec(&removals)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let (omega_mem, omega_non_mem) =
        accum.generate_omega_for_both_witnesses(&additions, &removals, &sk);
    let result = js_sys::Array::new();
    result.push(&obj_to_uint8array!(&omega_mem, false, "Omega").into());
    result.push(&obj_to_uint8array!(&omega_non_mem, false, "Omega").into());
    Ok(result)
}

#[wasm_bindgen(js_name = updateKBUniversalMembershipWitnessUsingPublicInfoAfterBatchUpdate)]
pub fn update_kb_universal_membership_witness_using_public_info_after_batch_update(
    witness: JsValue,
    member: Uint8Array,
    additions: js_sys::Array,
    removals: js_sys::Array,
    public_info: Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let witness: KBUniMembershipWit = serde_wasm_bindgen::from_value(witness)?;
    crate::update_witness_single_batch!(witness, member, additions, removals, public_info)
}

#[wasm_bindgen(js_name = updateKBUniversalMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates)]
pub fn update_kb_universal_membership_witness_using_public_info_after_multiple_batch_updates(
    witness: JsValue,
    member: Uint8Array,
    additions: js_sys::Array,
    removals: js_sys::Array,
    public_info: js_sys::Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let witness: KBUniMembershipWit = serde_wasm_bindgen::from_value(witness)?;
    crate::update_witness_multiple_batches!(witness, member, additions, removals, public_info)
}

#[wasm_bindgen(js_name = updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterBatchUpdate)]
pub fn update_kb_universal_non_membership_witness_using_public_info_after_batch_update(
    witness: JsValue,
    non_member: Uint8Array,
    additions: js_sys::Array,
    removals: js_sys::Array,
    public_info: Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let witness: KBUniNonMembershipWit = serde_wasm_bindgen::from_value(witness)?;
    crate::update_witness_single_batch!(witness, non_member, additions, removals, public_info)
}

#[wasm_bindgen(js_name = updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates)]
pub fn update_kb_universal_non_membership_witness_using_public_info_after_multiple_batch_updates(
    witness: JsValue,
    non_member: Uint8Array,
    additions: js_sys::Array,
    removals: js_sys::Array,
    public_info: js_sys::Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let witness: KBUniNonMembershipWit = serde_wasm_bindgen::from_value(witness)?;
    crate::update_witness_multiple_batches!(witness, non_member, additions, removals, public_info)
}

#[wasm_bindgen(js_name = kbUpdateNonMembershipWitnessesPostDomainExtension)]
pub fn kb_universal_update_non_membership_witnesses_post_domain_extension(
    witnesses: js_sys::Array,
    non_members: js_sys::Array,
    new_elements: js_sys::Array,
    old_accum: JsValue,
    secret_key: JsValue,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    let non_members = js_array_to_fr_vec(&non_members)?;
    let new_elements = js_array_to_fr_vec(&new_elements)?;
    let accum: KBUniversalAccum = serde_wasm_bindgen::from_value(old_accum)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let mut wits = Vec::with_capacity(witnesses.length() as usize);
    for w in witnesses.values() {
        wits.push(serde_wasm_bindgen::from_value::<KBUniNonMembershipWit>(
            w.unwrap(),
        )?);
    }
    let new_wits = accum.update_non_mem_wit_using_secret_key_on_domain_extension(
        &new_elements,
        &non_members,
        &wits,
        &sk,
    )
        .map_err(|e| {
            JsValue::from(&format!(
                "Evaluating update_non_mem_wit_using_secret_key_on_domain_extension returned error: {:?}",
                e
            ))
        })?;
    let result = js_sys::Array::new();
    for w in new_wits {
        result.push(&serde_wasm_bindgen::to_value(&w).map_err(JsValue::from)?);
    }
    Ok(result)
}

#[wasm_bindgen(js_name = publicInfoForKBUniversalNonMemWitnessUpdateOnDomainExtension)]
pub fn public_info_for_kb_universal_non_mem_witness_update_on_domain_extension(
    old_accum: JsValue,
    new_elements: js_sys::Array,
    secret_key: JsValue,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let accum: KBUniversalAccum = serde_wasm_bindgen::from_value(old_accum)?;
    let new_elements = js_array_to_fr_vec(&new_elements)?;
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let omega =
        accum.generate_omega_for_non_membership_witnesses_on_domain_extension(&new_elements, &sk);
    Ok(obj_to_uint8array!(&omega, false, "Omega"))
}

#[wasm_bindgen(js_name = updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterDomainExtension)]
pub fn update_kb_universal_non_membership_witness_using_public_info_after_domain_extension(
    witness: JsValue,
    non_member: Uint8Array,
    new_elements: js_sys::Array,
    public_info: Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let witness: KBUniNonMembershipWit = serde_wasm_bindgen::from_value(witness)?;
    let non_member = fr_from_uint8_array(non_member, true)?;
    let new_elements = js_array_to_fr_vec(&new_elements)?;
    let public_info: Omega =
        CanonicalDeserialize::deserialize_compressed(&public_info.to_vec()[..]).map_err(|e| {
            JsValue::from(&format!(
                "Failed to deserialize public info from bytes due to error: {:?}",
                e
            ))
        })?;
    let new_witness = witness
        .update_using_public_info_after_domain_extension(&new_elements, &public_info, &non_member)
        .map_err(|e| {
            JsValue::from(&format!(
                "Evaluating update_using_public_info_after_domain_extension returned error: {:?}",
                e
            ))
        })?;
    serde_wasm_bindgen::to_value(&new_witness).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterMultipleDomainExtensions)]
pub fn update_kb_universal_non_membership_witness_using_public_info_after_multiple_domain_extensions(
    witness: JsValue,
    non_member: Uint8Array,
    new_elements: js_sys::Array,
    public_info: js_sys::Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let witness: KBUniNonMembershipWit = serde_wasm_bindgen::from_value(witness)?;
    let non_member = fr_from_uint8_array(non_member, true)?;
    if new_elements.length() == public_info.length() {
        let size = new_elements.length();
        let mut updates_and_public_info = Vec::with_capacity(size as usize);
        for i in 0..size {
            let new = js_array_to_fr_vec(&js_sys::Array::from(&new_elements.get(i)))?;
            let bytes: Vec<u8> = serde_wasm_bindgen::from_value(public_info.get(i))?;
            let p: Omega =
                CanonicalDeserialize::deserialize_compressed(&bytes[..]).map_err(|e| {
                    JsValue::from(&format!(
                        "Failed to deserialize public info from bytes due to error: {:?}",
                        e
                    ))
                })?;
            updates_and_public_info.push((new, p));
        }
        let new_witness = witness.update_using_public_info_after_multiple_domain_extensions(updates_and_public_info.iter().map(|(a, p)| (a.as_slice(), p)).collect::<Vec<_>>(), &non_member)
            .map_err(|e| {
                JsValue::from(&format!(
                    "Evaluating update_using_public_info_after_multiple_domain_extensions returned error: {:?}",
                    e
                ))
            })?;
        let w = serde_wasm_bindgen::to_value(&new_witness).map_err(JsValue::from)?;
        Ok(w)
    } else {
        Err(JsValue::from(&format!(
            "Expected same but found different lengths for elements and public info: {} {}",
            new_elements.length(),
            public_info.length()
        )))
    }
}
