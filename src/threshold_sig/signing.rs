use crate::{
    bbs::BBSSigParams,
    bbs_plus::BBSPlusSigParamsG1,
    threshold_sig::{KAPPA, SALT_SIZE, STATISTICAL_SECURITY_PARAMETER},
    utils::{
        encode_messages_as_js_array_to_fr_vec_in_constant_time, fr_from_uint8_array,
        get_seeded_rng, js_array_to_iter, js_set_to_btree_set, set_panic_hook,
    },
    Fr,
};
use blake2::Blake2b512;
use sha3::Shake256;
use ark_bls12_381::Bls12_381;
use bbs_plus::threshold::{
    multiplication_phase::{Phase2, Phase2Output},
    randomness_generation_phase::Phase1,
    threshold_bbs::{BBSSignatureShare, Phase1Output as BbsPhase1Output},
    threshold_bbs_plus::{BBSPlusSignatureShare, Phase1Output as BbsPlusPhase1Output},
};
use js_sys::{Array, Map, Set, Uint8Array};
use oblivious_transfer_protocols::{
    cointoss::Commitments,
    ot_based_multiplication::{
        base_ot_multi_party_pairwise::BaseOTOutput,
        batch_mul_multi_party::{Message1, Message2},
        dkls18_mul_2p::MultiplicationOTEParams,
        dkls19_batch_mul_2p::GadgetVector,
    },
};
use secret_sharing_and_dkg::common::ParticipantId;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

macro_rules! start_phase1 {
    ($sig_batch_size: ident, $participant_id: ident, $others: ident, $protocol_id: ident, $fn_name: ident, $sig_name: expr) => {{
        set_panic_hook();
        let mut rng = get_seeded_rng();
        let others = js_set_to_btree_set(&$others);
        let (phase1, comm, comm_zero) = Phase1::<Fr, SALT_SIZE>::$fn_name::<_, Blake2b512>(
            &mut rng,
            $sig_batch_size,
            $participant_id,
            others,
            $protocol_id.clone(),
        )
        .map_err(|e| JsValue::from(&format!("Starting Phase1 returned error: {:?}", e)))?;
        let r = Array::new();
        let phase1 = obj_to_uint8array!(&phase1, true, $sig_name);
        let comm = obj_to_uint8array!(&comm, false, "Commitments");
        let comm_zero_to_send = Map::new();
        for (i, comm) in comm_zero {
            let comm = obj_to_uint8array!(&comm, false, "Commitments");
            comm_zero_to_send.set(&JsValue::from(i as u32), &comm);
        }
        r.push(&phase1);
        r.push(&comm);
        r.push(&comm_zero_to_send);
        Ok(r)
    }};
}

macro_rules! finish_phase1 {
    ($phase1: ident, $secret_key: ident, $fn_name: ident, $sig_name: expr) => {{
        set_panic_hook();
        let phase1 = obj_from_uint8array!(Phase1<Fr, SALT_SIZE>, $phase1, true);
        let secret_key = fr_from_uint8_array($secret_key, true)?;
        let out = phase1
            .$fn_name::<Blake2b512>(&secret_key)
            .map_err(|e| JsValue::from(&format!("Finishing Phase1 returned error: {:?}", e)))?;
        let out = obj_to_uint8array!(&out, true, $sig_name);
        Ok(out)
    }}
}

macro_rules! start_phase2 {
    ($participant_id: ident, $others: ident, $phase1_output: ident, $base_ot_output: ident, $gadget_vector: ident, $phase1_output_type: ident) => {{
        set_panic_hook();
    let mut rng = get_seeded_rng();
    let others = js_set_to_btree_set(&$others);
    let phase1_output = obj_from_uint8array!($phase1_output_type<Fr>, $phase1_output, true, "Phase1Output");
    let base_ot_output = obj_from_uint8array!(BaseOTOutput, $base_ot_output, true, "BaseOTOutput");
    let gadget_vector = obj_from_uint8array!(GadgetVector<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>, $gadget_vector, false, "GadgetVector");
    let ote_params = MultiplicationOTEParams::<KAPPA, STATISTICAL_SECURITY_PARAMETER> {};

    let (phase2, msgs) = Phase2::init::<_, Shake256>(
        &mut rng,
        $participant_id,
        phase1_output.masked_signing_key_shares,
        phase1_output.masked_rs,
        base_ot_output,
        others,
        ote_params,
        &gadget_vector,
    )
    .map_err(|e| JsValue::from(&format!("Starting Phase2 returned error: {:?}", e)))?;
    let r = Array::new();
    let phase2 = obj_to_uint8array!(&phase2, true, "Phase2");
    let msgs_to_send = Map::new();
    for (i, msg) in msgs {
        let msg = obj_to_uint8array!(&msg, false, "Message1");
        msgs_to_send.set(&JsValue::from(i as u32), &msg);
    }
    r.push(&phase2);
    r.push(&msgs_to_send);
    Ok(r)
    }}
}

macro_rules! create_signature_share {
    ($messages: ident, $index_in_output: ident, $phase1_output: ident, $phase2_output: ident, $params: ident, $encode_messages: ident, $params_type: ident, $phase1_output_type: ident, $share_type: ident, $sig_name: expr) => {{
        set_panic_hook();
        let params: $params_type = serde_wasm_bindgen::from_value($params)?;
        let messages =
            encode_messages_as_js_array_to_fr_vec_in_constant_time(&$messages, $encode_messages)?;
        let phase1_output = obj_from_uint8array!($phase1_output_type<Fr>, $phase1_output, true);
        let phase2_output = obj_from_uint8array!(Phase2Output<Fr>, $phase2_output, true);
        let share = $share_type::new(
            &messages,
            $index_in_output,
            &phase1_output,
            &phase2_output,
            &params,
        )
        .map_err(|e| JsValue::from(&format!("Creating signature share returned error: {:?}", e)))?;
        let share = obj_to_uint8array!(&share, true, $sig_name);
        Ok(share)
    }};
}

macro_rules! aggregate_signature_shares {
    ($shares: ident, $sig_share_type: ident) => {{
        set_panic_hook();
        let shares =
            js_array_to_iter(&$shares).collect::<Result<Vec<$sig_share_type<Bls12_381>>, _>>()?;
        let sig = $sig_share_type::aggregate(shares).map_err(|e| {
            JsValue::from(&format!(
                "Creating signature from shares returned error: {:?}",
                e
            ))
        })?;
        let sig = obj_to_uint8array!(&sig, true, "Signature");
        Ok(sig)
    }};
}

#[wasm_bindgen(js_name = thresholdBbsPlusStartPhase1)]
pub fn threshold_bbs_plus_start_phase_1(
    sig_batch_size: u32,
    participant_id: ParticipantId,
    others: Set,
    protocol_id: Vec<u8>,
) -> Result<Array, JsValue> {
    start_phase1!(
        sig_batch_size,
        participant_id,
        others,
        protocol_id,
        init_for_bbs_plus,
        "ThresholdBbsPlusPhase1"
    )
}

#[wasm_bindgen(js_name = thresholdBbsPlusPhase1ProcessCommitments)]
pub fn threshold_bbs_plus_phase_1_process_commitments(
    phase1: Uint8Array,
    sender_id: ParticipantId,
    commitments: Uint8Array,
    commitments_zero_share: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    process_commitments(phase1, sender_id, commitments, commitments_zero_share)
}

#[wasm_bindgen(js_name = thresholdBbsPlusPhase1GetSharesForOther)]
pub fn threshold_bbs_plus_phase_1_get_shares_for_other(
    phase1: Uint8Array,
    other_id: ParticipantId,
) -> Result<Array, JsValue> {
    get_shares_for_other(phase1, other_id)
}

#[wasm_bindgen(js_name = thresholdBbsPlusPhase1GetSharesForOthers)]
pub fn threshold_bbs_plus_phase_1_get_shares_for_others(
    phase1: Uint8Array,
    other_ids: Vec<ParticipantId>,
) -> Result<Array, JsValue> {
    get_shares_for_others(phase1, other_ids)
}

#[wasm_bindgen(js_name = thresholdBbsPlusPhase1ProcessShares)]
pub fn threshold_bbs_plus_phase_1_process_shares(
    phase1: Uint8Array,
    sender_id: ParticipantId,
    shares: Uint8Array,
    zero_shares: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    process_shares(phase1, sender_id, shares, zero_shares)
}

#[wasm_bindgen(js_name = thresholdBbsPlusPhase1Finish)]
pub fn threshold_bbs_plus_phase_1_finish(
    phase1: Uint8Array,
    secret_key: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    finish_phase1!(
        phase1,
        secret_key,
        finish_for_bbs_plus,
        "ThresholdBbsPlusPhase1Output"
    )
}

#[wasm_bindgen(js_name = thresholdBbsPlusPhase2Start)]
pub fn threshold_bbs_plus_phase_2_start(
    participant_id: ParticipantId,
    others: Set,
    phase1_output: Uint8Array,
    base_ot_output: Uint8Array,
    gadget_vector: Uint8Array,
) -> Result<Array, JsValue> {
    start_phase2!(
        participant_id,
        others,
        phase1_output,
        base_ot_output,
        gadget_vector,
        BbsPlusPhase1Output
    )
}

#[wasm_bindgen(js_name = thresholdBbsPlusPhase2ReceiveMessage1)]
pub fn threshold_bbs_plus_phase_2_receive_message_1(
    phase2: Uint8Array,
    sender_id: ParticipantId,
    message: Uint8Array,
    gadget_vector: Uint8Array,
) -> Result<Array, JsValue> {
    receive_message_1(phase2, sender_id, message, gadget_vector)
}

#[wasm_bindgen(js_name = thresholdBbsPlusPhase2ReceiveMessage2)]
pub fn threshold_bbs_plus_phase_2_receive_message_2(
    phase2: Uint8Array,
    sender_id: ParticipantId,
    message: Uint8Array,
    gadget_vector: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    receive_message_2(phase2, sender_id, message, gadget_vector)
}

#[wasm_bindgen(js_name = thresholdBbsPlusPhase2Finish)]
pub fn threshold_bbs_plus_phase_2_finish(phase2: Uint8Array) -> Result<Uint8Array, JsValue> {
    phase_2_finish(phase2)
}

#[wasm_bindgen(js_name = thresholdBbsPlusCreateSignatureShare)]
pub fn threshold_bbs_plus_create_signature_share(
    messages: Array,
    index_in_output: usize,
    phase1_output: Uint8Array,
    phase2_output: Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    create_signature_share!(
        messages,
        index_in_output,
        phase1_output,
        phase2_output,
        params,
        encode_messages,
        BBSPlusSigParamsG1,
        BbsPlusPhase1Output,
        BBSPlusSignatureShare,
        "BbsPlusSignatureShare"
    )
}

#[wasm_bindgen(js_name = thresholdBbsPlusAggregateSignatureShares)]
pub fn threshold_bbs_plus_aggregate_signature_shares(shares: Array) -> Result<Uint8Array, JsValue> {
    aggregate_signature_shares!(shares, BBSPlusSignatureShare)
}

// Following are for BBS

#[wasm_bindgen(js_name = thresholdBbsStartPhase1)]
pub fn threshold_bbs_start_phase_1(
    sig_batch_size: u32,
    participant_id: ParticipantId,
    others: Set,
    protocol_id: Vec<u8>,
) -> Result<Array, JsValue> {
    start_phase1!(
        sig_batch_size,
        participant_id,
        others,
        protocol_id,
        init_for_bbs,
        "ThresholdBbsPhase1"
    )
}

#[wasm_bindgen(js_name = thresholdBbsPhase1ProcessCommitments)]
pub fn threshold_bbs_phase_1_process_commitments(
    phase1: Uint8Array,
    sender_id: ParticipantId,
    commitments: Uint8Array,
    commitments_zero_share: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    process_commitments(phase1, sender_id, commitments, commitments_zero_share)
}

#[wasm_bindgen(js_name = thresholdBbsPhase1GetSharesForOther)]
pub fn threshold_bbs_phase_1_get_shares_for_other(
    phase1: Uint8Array,
    other_id: ParticipantId,
) -> Result<Array, JsValue> {
    get_shares_for_other(phase1, other_id)
}

#[wasm_bindgen(js_name = thresholdBbsPhase1GetSharesForOthers)]
pub fn threshold_bbs_phase_1_get_shares_for_others(
    phase1: Uint8Array,
    other_ids: Vec<ParticipantId>,
) -> Result<Array, JsValue> {
    get_shares_for_others(phase1, other_ids)
}

#[wasm_bindgen(js_name = thresholdBbsPhase1ProcessShares)]
pub fn threshold_bbs_phase_1_process_shares(
    phase1: Uint8Array,
    sender_id: ParticipantId,
    shares: Uint8Array,
    zero_shares: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    process_shares(phase1, sender_id, shares, zero_shares)
}

#[wasm_bindgen(js_name = thresholdBbsPhase1Finish)]
pub fn threshold_bbs_phase_1_finish(
    phase1: Uint8Array,
    secret_key: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    finish_phase1!(
        phase1,
        secret_key,
        finish_for_bbs,
        "ThresholdBbsPhase1Output"
    )
}

#[wasm_bindgen(js_name = thresholdBbsPhase2Start)]
pub fn threshold_bbs_phase_2_start(
    participant_id: ParticipantId,
    others: Set,
    phase1_output: Uint8Array,
    base_ot_output: Uint8Array,
    gadget_vector: Uint8Array,
) -> Result<Array, JsValue> {
    start_phase2!(
        participant_id,
        others,
        phase1_output,
        base_ot_output,
        gadget_vector,
        BbsPhase1Output
    )
}

#[wasm_bindgen(js_name = thresholdBbsPhase2ReceiveMessage1)]
pub fn threshold_bbs_phase_2_receive_message_1(
    phase2: Uint8Array,
    sender_id: ParticipantId,
    message: Uint8Array,
    gadget_vector: Uint8Array,
) -> Result<Array, JsValue> {
    receive_message_1(phase2, sender_id, message, gadget_vector)
}

#[wasm_bindgen(js_name = thresholdBbsPhase2ReceiveMessage2)]
pub fn threshold_bbs_phase_2_receive_message_2(
    phase2: Uint8Array,
    sender_id: ParticipantId,
    message: Uint8Array,
    gadget_vector: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    receive_message_2(phase2, sender_id, message, gadget_vector)
}

#[wasm_bindgen(js_name = thresholdBbsPhase2Finish)]
pub fn threshold_bbs_phase_2_finish(phase2: Uint8Array) -> Result<Uint8Array, JsValue> {
    phase_2_finish(phase2)
}

#[wasm_bindgen(js_name = thresholdBbsCreateSignatureShare)]
pub fn threshold_bbs_create_signature_share(
    messages: Array,
    index_in_output: usize,
    phase1_output: Uint8Array,
    phase2_output: Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    create_signature_share!(
        messages,
        index_in_output,
        phase1_output,
        phase2_output,
        params,
        encode_messages,
        BBSSigParams,
        BbsPhase1Output,
        BBSSignatureShare,
        "BbsSignatureShare"
    )
}

#[wasm_bindgen(js_name = thresholdBbsAggregateSignatureShares)]
pub fn threshold_bbs_aggregate_signature_shares(shares: Array) -> Result<Uint8Array, JsValue> {
    aggregate_signature_shares!(shares, BBSSignatureShare)
}

fn process_commitments(
    phase1: Uint8Array,
    sender_id: ParticipantId,
    commitments: Uint8Array,
    commitments_zero_share: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let mut phase1 = obj_from_uint8array!(Phase1<Fr, SALT_SIZE>, phase1, true);
    let commitments = obj_from_uint8array!(Commitments, commitments, false);
    let commitments_zero_share = obj_from_uint8array!(Commitments, commitments_zero_share, false);
    phase1
        .receive_commitment(sender_id, commitments, commitments_zero_share)
        .map_err(|e| {
            JsValue::from(&format!(
                "Processing commitments in Phase1 returned error: {:?}",
                e
            ))
        })?;
    let phase1 = obj_to_uint8array!(&phase1, true, "Phase1");
    Ok(phase1)
}

fn get_shares_for_other(phase1: Uint8Array, other_id: ParticipantId) -> Result<Array, JsValue> {
    set_panic_hook();
    let phase1 = obj_from_uint8array!(Phase1<Fr, SALT_SIZE>, phase1, true);
    let share = obj_to_uint8array!(&phase1.get_comm_shares_and_salts(), false, "Phase1Share");
    let zero_share = obj_to_uint8array!(
        &phase1.get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(&other_id),
        false,
        "Phase1ZeroShare"
    );
    let r = Array::new();
    r.push(&share);
    r.push(&zero_share);
    Ok(r)
}

fn get_shares_for_others(
    phase1: Uint8Array,
    other_ids: Vec<ParticipantId>,
) -> Result<Array, JsValue> {
    set_panic_hook();
    let phase1 = obj_from_uint8array!(Phase1<Fr, SALT_SIZE>, phase1, true);
    let r = Array::new();
    for i in other_ids {
        let t = Array::new();
        let share = obj_to_uint8array!(&phase1.get_comm_shares_and_salts(), false, "Phase1Share");
        let zero_share = obj_to_uint8array!(
            &phase1.get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(&i),
            false,
            "Phase1ZeroShare"
        );
        t.push(&share);
        t.push(&zero_share);
        r.push(&t);
    }
    Ok(r)
}

fn process_shares(
    phase1: Uint8Array,
    sender_id: ParticipantId,
    shares: Uint8Array,
    zero_shares: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let mut phase1 = obj_from_uint8array!(Phase1<Fr, SALT_SIZE>, phase1, true);
    let shares = obj_from_uint8array!(Vec<(Fr, [u8; SALT_SIZE])>, shares, false);
    let zero_shares = obj_from_uint8array!(Vec<(Fr, [u8; SALT_SIZE])>, zero_shares, false);
    phase1
        .receive_shares::<Blake2b512>(sender_id, shares, zero_shares)
        .map_err(|e| {
            JsValue::from(&format!(
                "Processing shares in Phase1 returned error: {:?}",
                e
            ))
        })?;
    let phase1 = obj_to_uint8array!(&phase1, true, "Phase1");
    Ok(phase1)
}

fn receive_message_1(
    phase2: Uint8Array,
    sender_id: ParticipantId,
    message: Uint8Array,
    gadget_vector: Uint8Array,
) -> Result<Array, JsValue> {
    set_panic_hook();
    let mut phase2 =
        obj_from_uint8array!(Phase2<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>, phase2, true);
    let message = obj_from_uint8array!(Message1<Fr>, message, false, "Phase2 Message1");
    let gadget_vector = obj_from_uint8array!(GadgetVector<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>, gadget_vector, false);
    let m2 = phase2
        .receive_message1::<Blake2b512, Shake256>(sender_id, message, &gadget_vector)
        .map_err(|e| {
            JsValue::from(&format!(
                "Receiving Message1 in Phase2 returned error: {:?}",
                e
            ))
        })?;
    let r = Array::new();
    let phase2 = obj_to_uint8array!(&phase2, true, "Phase2");
    let m2 = obj_to_uint8array!(&m2, false, "Phase2 Message2");
    r.push(&phase2);
    r.push(&m2);
    Ok(r)
}

fn receive_message_2(
    phase2: Uint8Array,
    sender_id: ParticipantId,
    message: Uint8Array,
    gadget_vector: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let mut phase2 =
        obj_from_uint8array!(Phase2<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>, phase2, true);
    let message = obj_from_uint8array!(Message2<Fr>, message, false, "Phase2 Message2");
    let gadget_vector = obj_from_uint8array!(GadgetVector<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>, gadget_vector, false);
    phase2
        .receive_message2::<Blake2b512>(sender_id, message, &gadget_vector)
        .map_err(|e| {
            JsValue::from(&format!(
                "Receiving Message2 in Phase2 returned error: {:?}",
                e
            ))
        })?;
    let phase2 = obj_to_uint8array!(&phase2, true, "Phase2");
    Ok(phase2)
}

fn phase_2_finish(phase2: Uint8Array) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let phase2 =
        obj_from_uint8array!(Phase2<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>, phase2, true);
    let out = phase2.finish();
    let out = obj_to_uint8array!(&out, true, "Phase2Output");
    Ok(out)
}
