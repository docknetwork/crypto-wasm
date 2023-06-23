use crate::{
    utils::{
        g1_affine_from_uint8_array, g1_affine_to_uint8_array, g2_affine_from_uint8_array,
        g2_affine_to_uint8_array, get_seeded_rng, random_bytes, set_panic_hook,
    },
    Fr, G1Affine, G2Affine,
};
use ark_bls12_381::Bls12_381;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::ops::Mul;
use blake2::Blake2b512;
use js_sys::{Array, Uint8Array};
use secret_sharing_and_dkg::{
    common::{ParticipantId, PublicKeyBase, Share, ShareId},
    feldman_dvss_dkg::reconstruct_threshold_public_key,
    frost_dkg::{Round1Msg, Round1State, Round2State},
};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

type PublicKeyBaseG1 = PublicKeyBase<G1Affine>;
type PublicKeyBaseG2 = PublicKeyBase<G2Affine>;
type Round1StateG1 = Round1State<G1Affine>;
type Round1StateG2 = Round1State<G2Affine>;
type Round1MsgG1 = Round1Msg<G1Affine>;
type Round1MsgG2 = Round1Msg<G2Affine>;
type Round2StateG1 = Round2State<G1Affine>;
type Round2StateG2 = Round2State<G2Affine>;

macro_rules! start_round1 {
    ($participant_id: ident, $threshold: ident, $total: ident, $schnorr_proof_ctx: ident, $pk_base: ident, $pk_base_type: ident) => {{
        set_panic_hook();
        let mut rng = get_seeded_rng();
        let pk_base = obj_from_uint8array!($pk_base_type, $pk_base, false);
        let (state, msg) = Round1State::start_with_random_secret::<_, Blake2b512>(
            &mut rng,
            $participant_id,
            $threshold,
            $total,
            &$schnorr_proof_ctx,
            &pk_base.0,
        )
        .map_err(|e| {
            JsValue::from(&format!(
                "Starting Round1 of Frost keygen returned error: {:?}",
                e
            ))
        })?;
        let r = Array::new();
        let state = obj_to_uint8array!(&state, true, "FrostRound1State");
        let msg = obj_to_uint8array!(&msg, false, "FrostRound1Message");
        r.push(&state);
        r.push(&msg);
        Ok(r)
    }};
}

macro_rules! receive_round1 {
    ($round_state: ident, $msg: ident, $schnorr_proof_ctx: ident, $pk_base: ident, $pk_base_type: ident, $round_state_type: ident, $round_msg_type: ident) => {{
        set_panic_hook();
        let mut round_state = obj_from_uint8array!($round_state_type, $round_state, true);
        let msg = obj_from_uint8array!($round_msg_type, $msg, false);
        let pk_base = obj_from_uint8array!($pk_base_type, $pk_base, false);
        round_state
            .add_received_message::<Blake2b512>(msg, &$schnorr_proof_ctx, &pk_base.0)
            .map_err(|e| {
                JsValue::from(&format!(
                    "Processing Round1 message of Frost keygen returned error: {:?}",
                    e
                ))
            })?;
        Ok(obj_to_uint8array!(&round_state, true, "FrostRound1State"))
    }};
}

macro_rules! finish_round1 {
    ($round_state: ident, $round_state_type: ident) => {{
        set_panic_hook();
        let round_state = obj_from_uint8array!($round_state_type, $round_state, true);
        let (round2_state, shares) = round_state.finish().map_err(|e| {
            JsValue::from(&format!(
                "Processing Round1 message of Frost keygen returned error: {:?}",
                e
            ))
        })?;
        let round2_state = obj_to_uint8array!(&round2_state, true, "FrostRound2State");
        let shares_array = Array::new();
        for s in shares.0 {
            let s = obj_to_uint8array!(&s, true, "FrostKeyShare");
            shares_array.push(&s);
        }
        let r = Array::new();
        r.push(&round2_state);
        r.push(&shares_array);
        Ok(r)
    }};
}

macro_rules! receive_round2 {
    ($round_state: ident, $sender_id: ident, $share: ident, $pk_base: ident, $pk_base_type: ident, $round_state_type: ident) => {{
        set_panic_hook();
        let mut round_state = obj_from_uint8array!($round_state_type, $round_state, true);
        let share = obj_from_uint8array!(Share<Fr>, $share, false);
        let pk_base = obj_from_uint8array!($pk_base_type, $pk_base, false);
        round_state
            .add_received_share($sender_id, share, &pk_base.0)
            .map_err(|e| {
                JsValue::from(&format!(
                    "Processing Round2 message of Frost keygen returned error: {:?}",
                    e
                ))
            })?;
        Ok(obj_to_uint8array!(&round_state, true, "FrostRound2State"))
    }};
}

macro_rules! finish_round2 {
    ($round_state: ident, $pk_base: ident, $pk_base_type: ident, $round_state_type: ident) => {{
        set_panic_hook();
        let round_state = obj_from_uint8array!($round_state_type, $round_state, true);
        let pk_base = obj_from_uint8array!($pk_base_type, $pk_base, false);
        let (share, pk, tpk) = round_state.finish(&pk_base.0).map_err(|e| {
            JsValue::from(&format!(
                "Processing Round1 message of Frost keygen returned error: {:?}",
                e
            ))
        })?;
        let r = Array::new();
        let share = obj_to_uint8array!(&share.share, true, "SecretKeyShare");
        let pk = obj_to_uint8array!(&pk, false, "PublicKey");
        let tpk = obj_to_uint8array!(&tpk, false, "ThresholdPublicKey");
        r.push(&share);
        r.push(&pk);
        r.push(&tpk);
        Ok(r)
    }};
}

macro_rules! gen_tpk {
    ($pubkeys: ident, $threshold: ident, $pk_cons: ident) => {{
        set_panic_hook();
        let mut pk_with_ids = Vec::with_capacity($pubkeys.length() as usize);
        for pk_id in $pubkeys.values() {
            let pk_id = pk_id.unwrap();
            let arr = js_sys::Array::from(&pk_id);
            if arr.length() != 2 {
                return Err(JsValue::from(&format!(
                    "Each item should be of length 2 but found of length {:?}",
                    arr.length()
                )));
            }
            let i =
                arr.get(0).as_f64().ok_or_else(|| {
                    JsValue::from("The 1st element of item should have been a number")
                })? as ShareId;
            let pk_bytes = Uint8Array::new(&arr.get(1));
            let pk = $pk_cons(pk_bytes)?;
            pk_with_ids.push((i, pk));
        }
        let tpk = reconstruct_threshold_public_key(pk_with_ids, $threshold).map_err(|e| {
            JsValue::from(&format!(
                "Reconstructing threshold public key returned error: {:?}",
                e
            ))
        })?;
        Ok(obj_to_uint8array!(&tpk, false, "ThresholdPublicKey"))
    }};
}

#[wasm_bindgen(js_name = generateRandomPublicKeyBaseInG1)]
pub fn generate_random_public_key_base_in_g1(seed: Option<Vec<u8>>) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let label = seed.unwrap_or_else(random_bytes);
    Ok(obj_to_uint8array!(
        &PublicKeyBaseG1::new::<Blake2b512>(&label),
        false,
        "PublicKeyBaseG1"
    ))
}

#[wasm_bindgen(js_name = generateRandomPublicKeyBaseInG2)]
pub fn generate_random_public_key_base_in_g2(seed: Option<Vec<u8>>) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let label = seed.unwrap_or_else(random_bytes);
    Ok(obj_to_uint8array!(
        &PublicKeyBaseG2::new::<Blake2b512>(&label),
        false,
        "PublicKeyBaseG2"
    ))
}

#[wasm_bindgen(js_name = generateKeyBaseFromGivenG1Point)]
pub fn generate_key_base_from_given_g1_point(point: Uint8Array) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let point = g1_affine_from_uint8_array(point)?;
    let pk_base = PublicKeyBase::<G1Affine>(point);
    Ok(obj_to_uint8array!(&pk_base, false, "PublicKeyBaseG1"))
}

#[wasm_bindgen(js_name = generateKeyBaseFromGivenG2Point)]
pub fn generate_key_base_from_given_g2_point(point: Uint8Array) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let point = g2_affine_from_uint8_array(point)?;
    let pk_base = PublicKeyBase::<G2Affine>(point);
    Ok(obj_to_uint8array!(&pk_base, false, "PublicKeyBaseG2"))
}

#[wasm_bindgen(js_name = frostKeygenG1StartRound1)]
pub fn frost_keygen_g1_start_round_1(
    participant_id: ParticipantId,
    threshold: ShareId,
    total: ShareId,
    schnorr_proof_ctx: Vec<u8>,
    pk_base: Uint8Array,
) -> Result<Array, JsValue> {
    start_round1!(
        participant_id,
        threshold,
        total,
        schnorr_proof_ctx,
        pk_base,
        PublicKeyBaseG1
    )
}

#[wasm_bindgen(js_name = frostKeygenG2StartRound1)]
pub fn frost_keygen_g2_start_round_1(
    participant_id: ParticipantId,
    threshold: ShareId,
    total: ShareId,
    schnorr_proof_ctx: Vec<u8>,
    pk_base: Uint8Array,
) -> Result<Array, JsValue> {
    start_round1!(
        participant_id,
        threshold,
        total,
        schnorr_proof_ctx,
        pk_base,
        PublicKeyBaseG2
    )
}

#[wasm_bindgen(js_name = frostKeygenG1Round1ProcessReceivedMessage)]
pub fn frost_keygen_g1_round_1_process_received_message(
    round_state: Uint8Array,
    msg: Uint8Array,
    schnorr_proof_ctx: Vec<u8>,
    pk_base: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    receive_round1!(
        round_state,
        msg,
        schnorr_proof_ctx,
        pk_base,
        PublicKeyBaseG1,
        Round1StateG1,
        Round1MsgG1
    )
}

#[wasm_bindgen(js_name = frostKeygenG2Round1ProcessReceivedMessage)]
pub fn frost_keygen_g2_round_1_process_received_message(
    round_state: Uint8Array,
    msg: Uint8Array,
    schnorr_proof_ctx: Vec<u8>,
    pk_base: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    receive_round1!(
        round_state,
        msg,
        schnorr_proof_ctx,
        pk_base,
        PublicKeyBaseG2,
        Round1StateG2,
        Round1MsgG2
    )
}

#[wasm_bindgen(js_name = frostKeygenG1Round1Finish)]
pub fn frost_keygen_g1_round_1_finish(round_state: Uint8Array) -> Result<Array, JsValue> {
    finish_round1!(round_state, Round1StateG1)
}

#[wasm_bindgen(js_name = frostKeygenG2Round1Finish)]
pub fn frost_keygen_g2_round_1_finish(round_state: Uint8Array) -> Result<Array, JsValue> {
    finish_round1!(round_state, Round1StateG2)
}

#[wasm_bindgen(js_name = frostKeygenG1Round2ProcessReceivedMessage)]
pub fn frost_keygen_g1_round_2_process_received_message(
    round_state: Uint8Array,
    sender_id: ParticipantId,
    share: Uint8Array,
    pk_base: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    receive_round2!(
        round_state,
        sender_id,
        share,
        pk_base,
        PublicKeyBaseG1,
        Round2StateG1
    )
}

#[wasm_bindgen(js_name = frostKeygenG2Round2ProcessReceivedMessage)]
pub fn frost_keygen_g2_round_2_process_received_message(
    round_state: Uint8Array,
    sender_id: ParticipantId,
    share: Uint8Array,
    pk_base: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    receive_round2!(
        round_state,
        sender_id,
        share,
        pk_base,
        PublicKeyBaseG2,
        Round2StateG2
    )
}

#[wasm_bindgen(js_name = frostKeygenG1Round2Finish)]
pub fn frost_keygen_g1_round_2_finish(
    round_state: Uint8Array,
    pk_base: Uint8Array,
) -> Result<Array, JsValue> {
    finish_round2!(round_state, pk_base, PublicKeyBaseG1, Round2StateG1)
}

#[wasm_bindgen(js_name = frostKeygenG2Round2Finish)]
pub fn frost_keygen_g2_round_2_finish(
    round_state: Uint8Array,
    pk_base: Uint8Array,
) -> Result<Array, JsValue> {
    finish_round2!(round_state, pk_base, PublicKeyBaseG2, Round2StateG2)
}

#[wasm_bindgen(js_name = frostKeygenG1PubkeyFromSecretKey)]
pub fn frost_keygen_g1_pubkey_from_secret_key(
    secret: Uint8Array,
    pk_base: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let secret = obj_from_uint8array!(Fr, secret, true);
    let pk_base = obj_from_uint8array!(PublicKeyBaseG1, pk_base, false);
    g1_affine_to_uint8_array(&pk_base.0.mul(secret).into_affine())
}

#[wasm_bindgen(js_name = frostKeygenG2PubkeyFromSecretKey)]
pub fn frost_keygen_g2_pubkey_from_secret_key(
    secret: Uint8Array,
    pk_base: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let secret = obj_from_uint8array!(Fr, secret, true);
    let pk_base = obj_from_uint8array!(PublicKeyBaseG2, pk_base, false);
    g2_affine_to_uint8_array(&pk_base.0.mul(secret).into_affine())
}

#[wasm_bindgen(js_name = frostKeygenG1ThresholdPubkeyFromPubkeys)]
pub fn frost_keygen_g1_threshold_pubkey_from_pubkeys(
    pubkeys: Array,
    threshold: ShareId,
) -> Result<Uint8Array, JsValue> {
    gen_tpk!(pubkeys, threshold, g1_affine_from_uint8_array)
}

#[wasm_bindgen(js_name = frostKeygenG2ThresholdPubkeyFromPubkeys)]
pub fn frost_keygen_g2_threshold_pubkey_from_pubkeys(
    pubkeys: Array,
    threshold: ShareId,
) -> Result<Uint8Array, JsValue> {
    gen_tpk!(pubkeys, threshold, g2_affine_from_uint8_array)
}
