use crate::{
    threshold_sig::{BASE_OT_KEY_SIZE, KAPPA, STATISTICAL_SECURITY_PARAMETER},
    utils::{get_seeded_rng, js_array_to_iter, js_set_to_btree_set, set_panic_hook},
    G1Affine,
};
use blake2::Blake2b512;
use js_sys::{Array, Map, Set, Uint8Array};
use oblivious_transfer_protocols::{
    base_ot::simplest_ot::{Challenges, HashedKey, ReceiverPubKeys, Responses},
    ot_based_multiplication::{
        base_ot_multi_party_pairwise::{BaseOTOutput, Participant, SenderPubKeyAndProof},
        dkls18_mul_2p::MultiplicationOTEParams,
    },
    ParticipantId,
};
use secret_sharing_and_dkg::common::PublicKeyBase;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;
use sha3::Shake256;

fn parse_pk_base(pk_base: Uint8Array) -> Result<G1Affine, JsValue> {
    let pk_base = obj_from_uint8array!(PublicKeyBase<G1Affine>, pk_base, false);
    Ok(pk_base.0)
}

#[wasm_bindgen(js_name = startBaseOTPhase)]
pub fn start_base_ot_phase(
    participant_id: ParticipantId,
    others: Set,
    pk_base: Uint8Array,
    num_base_ot: Option<u16>,
) -> Result<Array, JsValue> {
    set_panic_hook();
    let mut rng = get_seeded_rng();
    let num_base_ot = num_base_ot.unwrap_or_else(|| {
        let ote_params = MultiplicationOTEParams::<KAPPA, STATISTICAL_SECURITY_PARAMETER> {};
        ote_params.num_base_ot()
    });
    let others = js_set_to_btree_set(&others);
    let (base_ot, sender_pk_and_proof) = Participant::init::<_, Blake2b512>(
        &mut rng,
        participant_id,
        others,
        num_base_ot,
        &parse_pk_base(pk_base)?,
    )
    .map_err(|e| JsValue::from(&format!("Starting Base OT returned error: {:?}", e)))?;
    let r = Array::new();
    let base_ot = obj_to_uint8array!(&base_ot, true, "BaseOTPhase");
    let messages_to_send = Map::new();
    for (i, pk_proof) in sender_pk_and_proof {
        let pk_proof = obj_to_uint8array!(&pk_proof, false, "SenderPubKeyAndProof");
        messages_to_send.set(&JsValue::from(i as u32), &pk_proof);
    }
    r.push(&base_ot);
    r.push(&messages_to_send);
    Ok(r)
}

#[wasm_bindgen(js_name = baseOTPhaseProcessSenderPubkey)]
pub fn base_ot_phase_process_sender_pubkey(
    base_ot_phase: Uint8Array,
    sender_id: ParticipantId,
    pub_key_proof: Uint8Array,
    pk_base: Uint8Array,
) -> Result<Array, JsValue> {
    set_panic_hook();
    let mut rng = get_seeded_rng();
    let mut base_ot = obj_from_uint8array!(Participant<G1Affine>, base_ot_phase, true);
    let pub_key_proof = obj_from_uint8array!(SenderPubKeyAndProof<G1Affine>, pub_key_proof, false);
    let recv_pk = base_ot
        .receive_sender_pubkey::<_, Blake2b512, Shake256, BASE_OT_KEY_SIZE>(
            &mut rng,
            sender_id,
            pub_key_proof,
            &parse_pk_base(pk_base)?,
        )
        .map_err(|e| {
            JsValue::from(&format!(
                "Processing Base OT sender's public key returned error: {:?}",
                e
            ))
        })?;
    let r = Array::new();
    let base_ot = obj_to_uint8array!(&base_ot, true, "BaseOTPhase");
    let recv_pk = obj_to_uint8array!(&recv_pk, true, "ReceiverPubkeys");
    r.push(&base_ot);
    r.push(&recv_pk);
    Ok(r)
}

#[wasm_bindgen(js_name = baseOTPhaseProcessReceiverPubkey)]
pub fn base_ot_phase_process_receiver_pubkey(
    base_ot_phase: Uint8Array,
    receiver_id: ParticipantId,
    public_key: Uint8Array,
) -> Result<Array, JsValue> {
    set_panic_hook();
    let mut base_ot = obj_from_uint8array!(Participant<G1Affine>, base_ot_phase, true);
    let pk = obj_from_uint8array!(ReceiverPubKeys<G1Affine>, public_key, false);
    let challenges = base_ot
        .receive_receiver_pubkey::<Blake2b512, Shake256, BASE_OT_KEY_SIZE>(receiver_id, pk)
        .map_err(|e| {
            JsValue::from(&format!(
                "Processing Base OT sender's public key returned error: {:?}",
                e
            ))
        })?;
    let r = Array::new();
    let base_ot = obj_to_uint8array!(&base_ot, true, "BaseOTPhase");
    let challenges = obj_to_uint8array!(&challenges, true, "BaseOTPhaseChallenges");
    r.push(&base_ot);
    r.push(&challenges);
    Ok(r)
}

#[wasm_bindgen(js_name = baseOTPhaseProcessChallenges)]
pub fn base_ot_phase_process_receiver_challenges(
    base_ot_phase: Uint8Array,
    sender_id: ParticipantId,
    challenges: Uint8Array,
) -> Result<Array, JsValue> {
    set_panic_hook();
    let mut base_ot = obj_from_uint8array!(Participant<G1Affine>, base_ot_phase, true);
    let challenges = obj_from_uint8array!(Challenges, challenges, false);
    let resp = base_ot
        .receive_challenges::<Blake2b512>(sender_id, challenges)
        .map_err(|e| {
            JsValue::from(&format!(
                "Processing Base OT sender's challenges returned error: {:?}",
                e
            ))
        })?;
    let r = Array::new();
    let base_ot = obj_to_uint8array!(&base_ot, true, "BaseOTPhase");
    let resp = obj_to_uint8array!(&resp, true, "BaseOTPhaseResponses");
    r.push(&base_ot);
    r.push(&resp);
    Ok(r)
}

#[wasm_bindgen(js_name = baseOTPhaseProcessResponses)]
pub fn base_ot_phase_process_sender_responses(
    base_ot_phase: Uint8Array,
    sender_id: ParticipantId,
    responses: Uint8Array,
) -> Result<Array, JsValue> {
    set_panic_hook();
    let mut base_ot = obj_from_uint8array!(Participant<G1Affine>, base_ot_phase, true);
    let responses = obj_from_uint8array!(Responses, responses, false);
    let hk = base_ot
        .receive_responses(sender_id, responses)
        .map_err(|e| {
            JsValue::from(&format!(
                "Processing Base OT receiver's responses returned error: {:?}",
                e
            ))
        })?;
    let r = Array::new();
    let base_ot = obj_to_uint8array!(&base_ot, true, "BaseOTPhase");
    let hk = obj_to_uint8array!(&hk, true, "BaseOTPhaseHashedKeys");
    r.push(&base_ot);
    r.push(&hk);
    Ok(r)
}

#[wasm_bindgen(js_name = baseOTPhaseProcessHashedKeys)]
pub fn base_ot_phase_process_hashed_keys(
    base_ot_phase: Uint8Array,
    sender_id: ParticipantId,
    hashed_keys: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let mut base_ot = obj_from_uint8array!(Participant<G1Affine>, base_ot_phase, true);
    let hk = obj_from_uint8array!(Vec<(HashedKey, HashedKey)>, hashed_keys, false);
    base_ot.receive_hashed_keys::<Blake2b512>(sender_id, hk).map_err(|e| {
        JsValue::from(&format!(
            "Processing Base OT receiver's responses returned error: {:?}",
            e
        ))
    })?;
    let base_ot = obj_to_uint8array!(&base_ot, true, "BaseOTPhase");
    Ok(base_ot)
}

#[wasm_bindgen(js_name = baseOTPhaseFinish)]
pub fn base_ot_phase_finish(base_ot_phase: Uint8Array) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let base_ot = obj_from_uint8array!(Participant<G1Affine>, base_ot_phase, true);
    let out = base_ot.finish();
    let out = obj_to_uint8array!(&out, true, "BaseOTOutput");
    Ok(out)
}

/// Check if base OT outputs are correct. Useful in debugging, won't be possible in practice as each party keeps it OT output to itself
#[wasm_bindgen(js_name = baseOTOutputCheck)]
pub fn base_ot_output_check(base_ot_outputs: Array) -> Result<(), JsValue> {
    set_panic_hook();
    let outs = js_array_to_iter(&base_ot_outputs).collect::<Result<Vec<BaseOTOutput>, _>>()?;

    for base_ot in &outs {
        for (other, sender_keys) in &base_ot.sender_keys {
            let (choices, receiver_keys) =
                outs[*other as usize - 1].receiver.get(&base_ot.id).unwrap();
            if receiver_keys.len() != sender_keys.len() {
                return Err(JsValue::from(&format!(
                    "Receiver keys count {} different from sender key count {}",
                    receiver_keys.len(),
                    sender_keys.len()
                )));
            }
            for i in 0..sender_keys.len() {
                if choices[i] {
                    if sender_keys.0[i].1 != receiver_keys.0[i] {
                        return Err(JsValue::from(&format!(
                            "Sender key not equal to receiver at index {}",
                            i
                        )));
                    }
                } else {
                    if sender_keys.0[i].0 != receiver_keys.0[i] {
                        return Err(JsValue::from(&format!(
                            "Sender key not equal to receiver at index {}",
                            i
                        )));
                    }
                }
            }
        }
    }
    Ok(())
}
