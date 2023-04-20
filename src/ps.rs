use crate::utils::{
    fr_from_uint8_array, fr_to_jsvalue, fr_to_uint8_array, g1_affine_from_uint8_array,
    g1_affine_to_jsvalue, g1_affine_to_uint8_array, g2_affine_from_uint8_array,
    g2_affine_to_jsvalue, g2_affine_to_uint8_array, get_seeded_rng,
    js_array_of_bytearrays_to_vector_of_bytevectors, random_bytes, set_panic_hook,
};

use crate::common::VerifyResponse;
use crate::utils::g1_affine_from_jsvalue;
use crate::{Fr, G1Affine, G2Affine};
use ark_bls12_381::Bls12_381;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::collections::{BTreeMap, BTreeSet};
use blake2::Blake2b512;
use coconut_crypto::{proof, setup, signature};
use coconut_crypto::{CommitMessage, CommitmentOrMessage, MessageCommitment};
use dock_crypto_utils::concat_slices;
use dock_crypto_utils::hashing_utils::affine_group_elem_from_try_and_incr;
use js_sys::Uint8Array;
use serde::Deserialize;
use serde_wasm_bindgen::from_value;
use serde_wasm_bindgen::to_value;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

pub type PsSecretKey = setup::SecretKey<Fr>;
pub type BlindSignature = signature::BlindSignature<Bls12_381>;
pub type PsPublicKey = setup::PublicKey<Bls12_381>;
pub type SignatureParams = setup::SignatureParams<Bls12_381>;
pub(crate) type Signature = signature::Signature<Bls12_381>;
pub(crate) type PoKOfSigProtocol = proof::SignaturePoKGenerator<Bls12_381>;
pub(crate) type PoKOfMessagesProtocol = proof::MessagesPoKGenerator<Bls12_381>;
pub(crate) type PoKOfSignatureProof = proof::SignaturePoK<Bls12_381>;
pub(crate) type PoKOfMessagesProof = proof::MessagesPoK<Bls12_381>;

#[wasm_bindgen(js_name = psIsSignatureParamsValid)]
pub fn ps_is_params_valid(params: JsValue) -> Result<bool, JsValue> {
    set_panic_hook();
    let params: SignatureParams = from_value(params)?;
    Ok(params.valid())
}

#[wasm_bindgen(js_name = psSignatureParamsMaxSupportedMsgs)]
pub fn ps_params_max_supported_msgs(params: JsValue) -> Result<usize, JsValue> {
    set_panic_hook();
    let params: SignatureParams = from_value(params)?;
    Ok(params.supported_message_count())
}

#[wasm_bindgen(js_name = psGenerateSignatureParams)]
pub fn ps_generate_params(
    message_count: usize,
    label: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let label = label.unwrap_or_else(random_bytes);
    let params = SignatureParams::new::<Blake2b512>(&label, message_count);

    to_value(&params).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = psSignatureParamsToBytes)]
pub fn ps_params_to_bytes(params: JsValue) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let params: SignatureParams = from_value(params)?;
    Ok(obj_to_uint8array!(&params, false, "SignatureParams"))
}

#[wasm_bindgen(js_name = psGenerateSigningKey)]
pub fn ps_generate_secret_key(
    message_count: usize,
    seed: Option<Vec<u8>>,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let seed = seed.unwrap_or_else(random_bytes);
    let sk = PsSecretKey::from_seed::<Blake2b512>(&seed, message_count);
    Ok(obj_to_uint8array!(&sk, true, "PsSecretKey"))
}

#[wasm_bindgen(js_name = psGeneratePublicKey)]
pub fn ps_generate_public_key(
    secret_key: js_sys::Uint8Array,
    params: JsValue,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let sk = obj_from_uint8array!(PsSecretKey, secret_key, true, "PsSecretKey");
    let params: SignatureParams = from_value(params)?;
    let pk = PsPublicKey::new(&sk, &params);

    Ok(obj_to_uint8array!(&pk, false, "PsPublicKey"))
}

#[wasm_bindgen(js_name = psIsPublicKeyValid)]
pub fn ps_is_pubkey_valid(public_key: js_sys::Uint8Array) -> Result<bool, JsValue> {
    set_panic_hook();
    let pk = obj_from_uint8array!(PsPublicKey, public_key, false, "PsPublicKey");
    Ok(pk.valid())
}

/*#[wasm_bindgen(js_name = psGetBasesForCommitment)]
pub fn ps_get_bases_for_commitment(
    params: JsValue,
    indices_to_commit: js_sys::Array,
) -> Result<js_sys::Array, JsValue> {
    let params: SignatureParams = from_value(params)?;
    let bases = js_sys::Array::new();
    bases.push(&g1_affine_to_jsvalue(&params.h_0)?);
    for i in indices_to_commit.values() {
        let index: usize = from_value(i.unwrap())?;
        if index >= params.supported_message_count() {
            return Err(JsValue::from(&format!(
                "Invalid index {:?} to get signature param",
                index
            ))
            .into());
        }
        bases.push(&g1_affine_to_jsvalue(&params.h[index])?);
    }
    Ok(bases)
}*/

#[wasm_bindgen(js_name = psEncodeMessageForSigning)]
pub fn ps_encode_message_for_signing(message: Vec<u8>) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let fr = encode_message_for_signing(&message);
    Ok(fr_to_uint8_array(&fr)?)
}

#[wasm_bindgen(js_name = psEncodeMessagesForSigning)]
pub fn ps_encode_messages_for_signing(
    messages: js_sys::Array,
    indices_to_encode: js_sys::Array,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    let encoded = js_sys::Array::new();
    for i in indices_to_encode.values() {
        let index: u32 = from_value(i.unwrap())?;
        if index >= messages.length() {
            return Err(JsValue::from(&format!("Invalid index {:?} to get message", index)).into());
        }
        let msg: Vec<u8> = from_value(messages.get(index))?;
        let fr = encode_message_for_signing(&msg);
        encoded.push(&fr_to_jsvalue(&fr)?);
    }

    Ok(encoded)
}

#[wasm_bindgen(js_name = psMessageCommitment)]
pub fn ps_message_commitment(
    blinding: js_sys::Uint8Array,
    message: js_sys::Uint8Array,
    h: JsValue,
    params: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let blinding = fr_from_uint8_array(blinding, true)?;
    let message = fr_from_uint8_array(message, true)?;
    let params: SignatureParams = from_value(params)?;
    let h = g1_affine_from_jsvalue(h)?;

    to_value(&MessageCommitment::<Bls12_381>::new(
        &params.g, &blinding, &h, &message,
    ))
    .map_err(Into::into)
}

#[wasm_bindgen(js_name = psSign)]
pub fn ps_sign(
    messages: js_sys::Array,
    secret_key: js_sys::Uint8Array,
    params: JsValue,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();

    let sk = obj_from_uint8array!(PsSecretKey, secret_key, true, "PsSecretKey");
    let params: SignatureParams = from_value(params)?;
    let messages = encode_messages_as_js_array_to_fr_vec(&messages, false)?;

    let mut rng = get_seeded_rng();
    match Signature::new(&mut rng, &messages, &sk, &params) {
        Ok(sig) => Ok(obj_to_uint8array!(&sig, true, "Signature")),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = psBlindSign)]
pub fn ps_blind_sign(
    messages: JsValue,
    secret_key: js_sys::Uint8Array,
    h: JsValue,
) -> Result<js_sys::Uint8Array, JsValue> {
    use dock_crypto_utils::serde_utils::ArkObjectBytes;
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;
    set_panic_hook();

    let messages = js_sys::try_iter(&messages)?
        .unwrap()
        .into_iter()
        .map(Result::unwrap)
        .map(|js_msg| -> CommitmentOrMessage<Bls12_381> { from_value(js_msg).unwrap() });

    let sk = obj_from_uint8array!(PsSecretKey, secret_key, true, "PsSecretKey");
    let h = g1_affine_from_jsvalue(h)?;

    BlindSignature::new(messages, &sk, &h)
        .map_err(debug_to_js_value)
        .and_then(|sig| Ok(obj_to_uint8array!(&sig, true, "BlindSignature")))
}

#[wasm_bindgen(js_name = psUnblindSignature)]
pub fn ps_unblind_sig(
    blind_signature: js_sys::Uint8Array,
    indexed_blindings: js_sys::Map,
    public_key: Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();

    let signature = obj_from_uint8array!(BlindSignature, blind_signature, false);
    let indexed_blindings = encode_messages_as_js_map_to_fr_btreemap(&indexed_blindings, false)?;
    let pk = obj_from_uint8array!(PsPublicKey, public_key, false, "PsPublicKey");

    Ok(obj_to_uint8array!(
        &signature
            .unblind(
                indexed_blindings
                    .iter()
                    .map(|(&idx, message)| (idx, message)),
                &pk
            )
            .map_err(debug_to_js_value)?,
        true,
        "Signature"
    ))
}

#[wasm_bindgen(js_name = psVerify)]
pub fn ps_verify(
    messages: js_sys::Array,
    signature: js_sys::Uint8Array,
    public_key: js_sys::Uint8Array,
    params: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let signature = obj_from_uint8array!(Signature, signature, true);
    let pk = obj_from_uint8array!(PsPublicKey, public_key, false, "PsPublicKey");
    let params: SignatureParams = from_value(params)?;
    let messages = encode_messages_as_js_array_to_fr_vec(&messages, false)?;

    match signature.verify(&messages, &pk, &params) {
        Ok(_) => Ok(to_value(&VerifyResponse {
            verified: true,
            error: None,
        })
        .unwrap()),
        Err(e) => Ok(to_value(&VerifyResponse {
            verified: false,
            error: Some(format!("{:?}", e)),
        })
        .unwrap()),
    }
}

#[wasm_bindgen(js_name = psInitializeProofOfKnowledgeOfSignature)]
pub fn ps_initialize_proof_of_knowledge_of_signature(
    signature: js_sys::Uint8Array,
    params: JsValue,
    public_key: js_sys::Uint8Array,
    messages: JsValue,
) -> Result<JsValue, JsValue> {
    use ark_ff::PrimeField;
    set_panic_hook();

    let signature = obj_from_uint8array!(Signature, signature, true);
    let params: SignatureParams = from_value(params)?;
    let pk = obj_from_uint8array!(PsPublicKey, public_key, false, "PsPublicKey");
    let messages = js_sys::try_iter(&messages)?
        .unwrap()
        .into_iter()
        .map(Result::unwrap)
        .map(|js_msg| from_value::<CommitMessage<Fr>>(js_msg).unwrap());

    let mut rng = get_seeded_rng();

    PoKOfSigProtocol::init(&mut rng, messages, &signature, &pk, &params)
        .map_err(debug_to_js_value)
        .and_then(|protocol| to_value(&protocol).map_err(debug_to_js_value))
}

#[wasm_bindgen(js_name = psInitializeProofOfKnowledgeOfMessages)]
pub fn ps_initialize_proof_of_knowledge_of_messagese(
    messages: JsValue,
    params: JsValue,
    h: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let messages = js_sys::try_iter(&messages)?
        .unwrap()
        .into_iter()
        .map(Result::unwrap)
        .map(|js_msg| from_value::<CommitMessage<Fr>>(js_msg).unwrap());
    let params: SignatureParams = from_value(params)?;
    let h = g1_affine_from_jsvalue(h)?;

    let mut rng = get_seeded_rng();

    PoKOfMessagesProtocol::init(&mut rng, messages, &params, &h)
        .map_err(debug_to_js_value)
        .and_then(|protocol| to_value(&protocol).map_err(debug_to_js_value))
}

fn debug_to_js_value<V: core::fmt::Debug>(value: V) -> JsValue {
    JsValue::from(&format!("{:?}", value))
}

#[wasm_bindgen(js_name = psGenProofOfKnowledgeOfSignature)]
pub fn ps_gen_sig_proof(
    protocol: JsValue,
    challenge: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let protocol: PoKOfSigProtocol = from_value(protocol)?;
    let challenge = fr_from_uint8_array(challenge, false)?;
    match protocol.gen_proof(&challenge) {
        Ok(proof) => Ok(obj_to_uint8array!(&proof, false, "PoKOfSignatureProof")),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = psGenProofOfKnowledgeOfMessages)]
pub fn ps_gen_messages_proof(
    protocol: JsValue,
    challenge: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let protocol: PoKOfMessagesProtocol = from_value(protocol)?;
    let challenge = fr_from_uint8_array(challenge, false)?;

    match protocol.gen_proof(&challenge) {
        Ok(proof) => Ok(obj_to_uint8array!(&proof, false, "PoKOfMessagesProof")),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = psVerifySignaturePoK)]
pub fn ps_verify_signature_proof(
    proof: js_sys::Uint8Array,
    revealed_msgs: js_sys::Map,
    challenge: js_sys::Uint8Array,
    public_key: js_sys::Uint8Array,
    params: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let proof: PoKOfSignatureProof = obj_from_uint8array!(PoKOfSignatureProof, proof, false);
    let params: SignatureParams = from_value(params)?;
    let public_key = obj_from_uint8array!(PsPublicKey, public_key, false, "PsPublicKey");
    let challenge = fr_from_uint8_array(challenge, false)?;

    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, false)?;

    match proof.verify(
        &challenge,
        msgs.iter().map(|(&idx, msg)| (idx, msg)),
        &public_key,
        &params,
    ) {
        Ok(_) => Ok(to_value(&VerifyResponse {
            verified: true,
            error: None,
        })
        .unwrap()),
        Err(e) => Ok(to_value(&VerifyResponse {
            verified: false,
            error: Some(format!("{:?}", e)),
        })
        .unwrap()),
    }
}

#[wasm_bindgen(js_name = psVerifyMessagesPoK)]
pub fn ps_verify_messages_proof(
    proof: js_sys::Uint8Array,
    revealed_indices: js_sys::Set,
    challenge: js_sys::Uint8Array,
    params: JsValue,
    h: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let proof: PoKOfMessagesProof = obj_from_uint8array!(PoKOfMessagesProof, proof, false);
    let challenge = fr_from_uint8_array(challenge, false)?;
    let revealed_indices: BTreeSet<usize> = revealed_indices
        .values()
        .into_iter()
        .map(|i| serde_wasm_bindgen::from_value(i.unwrap()).unwrap())
        .collect();
    let params: SignatureParams = from_value(params)?;
    let h = g1_affine_from_jsvalue(h)?;

    match proof.verify(&challenge, revealed_indices, &params, &h) {
        Ok(_) => Ok(to_value(&VerifyResponse {
            verified: true,
            error: None,
        })
        .unwrap()),
        Err(e) => Ok(to_value(&VerifyResponse {
            verified: false,
            error: Some(format!("{:?}", e)),
        })
        .unwrap()),
    }
}

#[wasm_bindgen(js_name = psChallengeSignaturePoKContributionFromProtocol)]
pub fn ps_challenge_signature_pok_contribution_from_protocol(
    protocol: JsValue,
    public_key: Uint8Array,
    params: JsValue,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();

    let protocol: PoKOfSigProtocol = from_value(protocol)?;
    let pk = obj_from_uint8array!(PsPublicKey, public_key, false, "PsPublicKey");
    let params: SignatureParams = from_value(params)?;
    let mut bytes = vec![];

    protocol
        .challenge_contribution(&mut bytes, &pk, &params)
        .map_err(|e| {
            JsValue::from(&format!(
                "Evaluating challenge_contribution returned error: {:?}",
                e
            ))
        })?;
    Ok(js_sys::Uint8Array::from(bytes.as_slice()))
}

#[wasm_bindgen(js_name = psChallengeMessagesPoKContributionFromProtocol)]
pub fn ps_challenge_messages_pok_contribution_from_protocol(
    protocol: JsValue,
    params: JsValue,
    h: JsValue,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();

    let protocol: PoKOfMessagesProtocol = from_value(protocol)?;
    let params: SignatureParams = from_value(params)?;
    let h = g1_affine_from_jsvalue(h)?;
    let mut bytes = vec![];

    protocol
        .challenge_contribution(&mut bytes, &params, &h)
        .map_err(|e| {
            JsValue::from(&format!(
                "Evaluating challenge_contribution returned error: {:?}",
                e
            ))
        })?;
    Ok(js_sys::Uint8Array::from(bytes.as_slice()))
}

#[wasm_bindgen(js_name = psChallengeSignaturePoKContributionFromProof)]
pub fn ps_challenge_signature_pok_contribution_from_proof(
    proof: js_sys::Uint8Array,
    public_key: js_sys::Uint8Array,
    params: JsValue,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();

    let proof: PoKOfSignatureProof = obj_from_uint8array!(PoKOfSignatureProof, proof, false);
    let pk = obj_from_uint8array!(PsPublicKey, public_key, false, "PsPublicKey");
    let params: SignatureParams = from_value(params)?;

    let mut bytes = vec![];
    proof
        .challenge_contribution(&mut bytes, &pk, &params)
        .map_err(|e| {
            JsValue::from(&format!(
                "Evaluating challenge_contribution returned error: {:?}",
                e
            ))
        })?;

    Ok(js_sys::Uint8Array::from(bytes.as_slice()))
}

#[wasm_bindgen(js_name = psChallengeMessagesPoKContributionFromProof)]
pub fn ps_challenge_messages_pok_contribution_from_proof(
    proof: js_sys::Uint8Array,
    params: JsValue,
    h: JsValue,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();

    let proof: PoKOfMessagesProof = obj_from_uint8array!(PoKOfMessagesProof, proof, false);
    let params: SignatureParams = from_value(params)?;
    let h = g1_affine_from_jsvalue(h)?;

    let mut bytes = vec![];
    proof
        .challenge_contribution(&mut bytes, &params, &h)
        .map_err(|e| {
            JsValue::from(&format!(
                "Evaluating challenge_contribution returned error: {:?}",
                e
            ))
        })?;

    Ok(js_sys::Uint8Array::from(bytes.as_slice()))
}

#[wasm_bindgen(js_name = psSignatureParamsFromBytes)]
pub fn ps_signature_params_from_bytes(bytes: js_sys::Uint8Array) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let params = obj_from_uint8array!(SignatureParams, bytes, false, "SignatureParams");
    serde_wasm_bindgen::to_value(&params).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = psAdaptSignatureParamsForMsgCount)]
pub fn adapt_sig_params_for_msg_count(
    params: JsValue,
    generating_label: js_sys::Uint8Array,
    new_count: usize,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    crate::adapt_params!(
        params,
        generating_label,
        new_count,
        SignatureParams,
        G1Affine
    )
}

pub fn messages_as_bytes_to_fr_vec(
    messages_as_bytes: &[Vec<u8>],
    encode_messages: bool,
) -> Result<Vec<Fr>, JsValue> {
    messages_as_bytes
        .into_iter()
        .map(|msg| {
            if encode_messages {
                Ok(encode_message_for_signing(msg))
            } else {
                Fr::deserialize_compressed(msg.as_slice()).map_err(|e| {
                    JsValue::from(&format!("Cannot deserialize to Fr due to error: {:?}", e))
                })
            }
        })
        .collect()
}

pub fn encode_messages_as_js_array_to_fr_vec(
    messages: &js_sys::Array,
    encode_messages: bool,
) -> Result<Vec<Fr>, JsValue> {
    let messages_as_bytes = js_array_of_bytearrays_to_vector_of_bytevectors(messages)?;
    messages_as_bytes_to_fr_vec(&messages_as_bytes, encode_messages)
}

pub fn encode_messages_as_js_map_to_fr_btreemap(
    messages: &js_sys::Map,
    encode_messages: bool,
) -> Result<BTreeMap<usize, Fr>, JsValue> {
    messages
        .entries()
        .into_iter()
        .map(|raw_msg_arr| {
            let arr = js_sys::Array::from(&raw_msg_arr?);
            let idx: usize = from_value(arr.get(0))?;
            let msg_bytes: Vec<u8> = from_value(arr.get(1))?;

            let msg = if encode_messages {
                encode_message_for_signing(&msg_bytes)
            } else {
                Fr::deserialize_compressed(&msg_bytes[..]).map_err(|e| {
                    JsValue::from(&format!(
                        "Cannot deserialize to `ScalarField` due to error: {:?}",
                        e
                    ))
                })?
            };

            Ok((idx, msg))
        })
        .collect()
}

/// This is to convert a message to field element. This encoding needs to be collision resistant but
/// not preimage-resistant and thus use of hash function is not necessary. However, the encoding must
/// be constant time
pub fn encode_message_for_signing(msg: &[u8]) -> Fr {
    dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr::<Fr, Blake2b512>(
        &concat_slices!(msg, b"PS message"),
    )
}
