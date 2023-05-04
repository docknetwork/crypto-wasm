use crate::utils::{
    fr_from_uint8_array, fr_to_jsvalue, fr_to_uint8_array, get_seeded_rng, random_bytes,
    set_panic_hook, encode_message_for_signing
};

use crate::common::VerifyResponse;
use crate::{Fr, G1Affine};
use ark_bls12_381::Bls12_381;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::collections::{BTreeMap, BTreeSet};
use blake2::Blake2b512;
use coconut_crypto::keygen::common::Threshold;
use coconut_crypto::keygen::shamir_ss;
use coconut_crypto::{proof, setup, signature};
use coconut_crypto::{CommitMessage, CommitmentOrMessage, MessageCommitment};
use dock_crypto_utils::concat_slices;
use dock_crypto_utils::hashing_utils::affine_group_elem_from_try_and_incr;
use js_sys::Uint8Array;
use serde_wasm_bindgen::from_value;
use serde_wasm_bindgen::to_value;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

pub type PSSecretKey = setup::SecretKey<Fr>;
pub type PSBlindSignature = signature::BlindSignature<Bls12_381>;
pub type PSPublicKey = setup::PublicKey<Bls12_381>;
pub type PSSignatureParams = setup::SignatureParams<Bls12_381>;
pub type PSAggregatedSignature = signature::AggregatedSignature<Bls12_381>;
pub(crate) type PSSignature = signature::Signature<Bls12_381>;
pub(crate) type PSPoKOfSigProtocol = proof::SignaturePoKGenerator<Bls12_381>;
pub(crate) type PSPoKOfMessagesProtocol = proof::MessagesPoKGenerator<Bls12_381>;
pub(crate) type PSPoKOfSignatureProof = proof::SignaturePoK<Bls12_381>;
pub(crate) type PSPoKOfMessagesProof = proof::MessagesPoK<Bls12_381>;

macro_rules! adapt_key_for_less_messages {
    ($key: ident: $key_type: ident for $new_count: ident using $pop_element: expr) => {{
        let mut $key = obj_from_uint8array!($key_type, $key, true, stringify!($key_type));
        let current_count = $key.supported_message_count();

        if current_count >= $new_count {
            for _ in 0..(current_count - $new_count) {
                $pop_element;
            }
        } else if current_count < $new_count {
            return Ok(None);
        }

        Ok(Some(obj_to_uint8array!(&$key, true, stringify!($key_type))))
    }};
}

macro_rules! adapt_key_for_more_messages {
    ($key: ident: $key_type: ident for $new_count: ident using $add_element: expr) => {{
        let mut $key = obj_from_uint8array!($key_type, $key, true, stringify!($key_type));
        let current_count = $key.supported_message_count();

        if current_count <= $new_count {
            for i in current_count..$new_count {
                $add_element(i);
            }
        } else if current_count > $new_count {
            return Ok(None);
        }

        Ok(Some(obj_to_uint8array!(&$key, true, stringify!($key_type))))
    }};
}

#[wasm_bindgen(js_name = psIsSignatureParamsValid)]
pub fn ps_is_params_valid(params: JsValue) -> Result<bool, JsValue> {
    set_panic_hook();
    let params: PSSignatureParams = from_value(params)?;
    Ok(params.valid())
}

#[wasm_bindgen(js_name = psSignatureParamsMaxSupportedMsgs)]
pub fn ps_params_max_supported_msgs(params: JsValue) -> Result<usize, JsValue> {
    set_panic_hook();
    let params: PSSignatureParams = from_value(params)?;
    Ok(params.supported_message_count())
}

#[wasm_bindgen(js_name = psSigningKeyMaxSupportedMsgs)]
pub fn ps_secret_key_supported_msgs(secret_key: Uint8Array) -> Result<usize, JsValue> {
    set_panic_hook();
    let sk = obj_from_uint8array!(PSSecretKey, secret_key, true, "PSSecretKey");

    Ok(sk.supported_message_count())
}

#[wasm_bindgen(js_name = psPublicKeyMaxSupportedMsgs)]
pub fn ps_public_key_supported_msgs(public_key: Uint8Array) -> Result<usize, JsValue> {
    set_panic_hook();
    let public_key = obj_from_uint8array!(PSPublicKey, public_key, false, "PSPublicKey");

    Ok(public_key.supported_message_count())
}

#[wasm_bindgen(js_name = psGenerateSignatureParams)]
pub fn ps_generate_params(
    message_count: usize,
    label: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let label = label.unwrap_or_else(random_bytes);
    let params = PSSignatureParams::new::<Blake2b512>(&label, message_count);

    to_value(&params).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = psSignatureParamsToBytes)]
pub fn ps_signature_params_to_bytes(params: JsValue) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let params: PSSignatureParams = from_value(params)?;
    Ok(obj_to_uint8array!(&params, false, "PSSignatureParams"))
}

#[wasm_bindgen(js_name = psGenerateSigningKey)]
pub fn ps_generate_secret_key(
    message_count: usize,
    seed: Option<Vec<u8>>,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let seed = seed.unwrap_or_else(random_bytes);
    let sk = PSSecretKey::from_seed::<Blake2b512>(&seed, message_count);
    Ok(obj_to_uint8array!(&sk, true, "PSSecretKey"))
}

#[wasm_bindgen(js_name = psGeneratePublicKey)]
pub fn ps_generate_public_key(
    secret_key: js_sys::Uint8Array,
    params: JsValue,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let sk = obj_from_uint8array!(PSSecretKey, secret_key, true, "PSSecretKey");
    let params: PSSignatureParams = from_value(params)?;
    let pk = PSPublicKey::new(&sk, &params);

    Ok(obj_to_uint8array!(&pk, false, "PSPublicKey"))
}

#[wasm_bindgen(js_name = psAdaptSecretKeyForLessMessages)]
pub fn ps_adapt_secret_key_for_less_messages(
    secret_key: js_sys::Uint8Array,
    message_count: usize,
) -> Result<Option<js_sys::Uint8Array>, JsValue> {
    adapt_key_for_less_messages! { secret_key: PSSecretKey for message_count using secret_key.y.pop() }
}

#[wasm_bindgen(js_name = psAdaptPublicKeyForLessMessages)]
pub fn ps_adapt_public_key_for_less_messages(
    public_key: js_sys::Uint8Array,
    message_count: usize,
) -> Result<Option<js_sys::Uint8Array>, JsValue> {
    adapt_key_for_less_messages! { public_key: PSPublicKey for message_count using { public_key.beta.pop(); public_key.beta_tilde.pop(); } }
}

#[wasm_bindgen(js_name = psAdaptSecretKeyForMoreMessages)]
pub fn ps_adapt_secret_key_for_more_messages(
    secret_key: js_sys::Uint8Array,
    seed: Vec<u8>,
    message_count: usize,
) -> Result<Option<js_sys::Uint8Array>, JsValue> {
    use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
    let hasher = <DefaultFieldHasher<Blake2b512> as HashToField<Fr>>::new(PSSecretKey::Y_SALT);

    adapt_key_for_more_messages! {
        secret_key: PSSecretKey for message_count using
        |i: usize| secret_key.y.push(hasher.hash_to_field(&concat_slices!(seed, i.to_le_bytes()), 1).pop().unwrap())
    }
}

#[wasm_bindgen(js_name = psBlindedMessage)]
pub fn ps_blinded_message(commitment: JsValue) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let commitment: MessageCommitment<Bls12_381> = from_value(commitment)?;

    to_value(&CommitmentOrMessage::BlindedMessage(commitment)).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = psRevealedMessage)]
pub fn ps_revealed_message(message: js_sys::Uint8Array) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let message = obj_from_uint8array!(Fr, message, true, "Fr");

    to_value(&CommitmentOrMessage::<Bls12_381>::RevealedMessage(message)).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = psBlindMessageRandomly)]
pub fn ps_blind_message_randomly(message: js_sys::Uint8Array) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let message = obj_from_uint8array!(Fr, message, true, "Fr");

    to_value(&CommitMessage::<Fr>::BlindMessageRandomly(message)).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = psRevealMessage)]
pub fn ps_reveal_message() -> Result<JsValue, JsValue> {
    set_panic_hook();

    to_value(&CommitMessage::<Fr>::RevealMessage).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = psBlindMessageWithConcreteBlinding)]
pub fn ps_blind_message_with_concrete_blinding(
    message: js_sys::Uint8Array,
    blinding: js_sys::Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let message = obj_from_uint8array!(Fr, message, true, "Fr");
    let blinding = obj_from_uint8array!(Fr, blinding, true, "Fr");

    to_value(&CommitMessage::<Fr>::BlindMessageWithConcreteBlinding { message, blinding })
        .map_err(JsValue::from)
}

#[wasm_bindgen(js_name = psIsPublicKeyValid)]
pub fn ps_is_pubkey_valid(public_key: js_sys::Uint8Array) -> Result<bool, JsValue> {
    set_panic_hook();
    let pk = obj_from_uint8array!(PSPublicKey, public_key, false, "PSPublicKey");
    Ok(pk.valid())
}

#[wasm_bindgen(js_name = psEncodeMessageForSigning)]
pub fn ps_encode_message_for_signing(message: Vec<u8>) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let fr = encode_message_for_signing(&message);
    fr_to_uint8_array(&fr)
}

#[wasm_bindgen(js_name = psEncodeMessagesForSigning)]
pub fn ps_encode_messages_for_signing(
    messages: js_sys::Array,
    indices_to_encode: Option<js_sys::Array>,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    let encoded = js_sys::Array::new();
    if let Some(indices_to_encode) = indices_to_encode {
        for i in indices_to_encode.values() {
            let index: u32 = from_value(i.unwrap())?;
            if index >= messages.length() {
                return Err(JsValue::from(&format!(
                    "Invalid index {:?} to get message",
                    index
                )));
            }
            let msg: Vec<u8> = from_value(messages.get(index))?;
            let fr = encode_message_for_signing(&msg);
            encoded.push(&fr_to_jsvalue(&fr)?);
        }
    } else {
        for value in messages.values() {
            let msg: Vec<u8> = from_value(value?)?;
            let fr = encode_message_for_signing(&msg);

            encoded.push(&fr_to_jsvalue(&fr)?);
        }
    }

    Ok(encoded)
}

#[wasm_bindgen(js_name = psMessageCommitment)]
pub fn ps_message_commitment(
    blinding: js_sys::Uint8Array,
    message: js_sys::Uint8Array,
    h: js_sys::Uint8Array,
    params: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let blinding = fr_from_uint8_array(blinding, true)?;
    let message = fr_from_uint8_array(message, true)?;
    let params: PSSignatureParams = from_value(params)?;
    let h = obj_from_uint8array!(G1Affine, h, false);

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

    let sk = obj_from_uint8array!(PSSecretKey, secret_key, true, "PSSecretKey");
    let params: PSSignatureParams = from_value(params)?;
    let messages: Vec<_> = js_array_to_iter(&messages).collect::<Result<_, _>>()?;

    let mut rng = get_seeded_rng();
    PSSignature::new(&mut rng, &messages, &sk, &params)
        .map_err(debug_to_js_value)
        .and_then(|sig| Ok(obj_to_uint8array!(&sig, true, "PSSignature")))
}

#[wasm_bindgen(js_name = psBlindSign)]
pub fn ps_blind_sign(
    messages: JsValue,
    secret_key: js_sys::Uint8Array,
    h: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();

    let messages = js_sys::try_iter(&messages)?
        .unwrap()
        .map(Result::unwrap)
        .map(|js_msg| -> CommitmentOrMessage<Bls12_381> { from_value(js_msg).unwrap() });

    let sk = obj_from_uint8array!(PSSecretKey, secret_key, true, "PSSecretKey");
    let h = obj_from_uint8array!(G1Affine, h, false);

    PSBlindSignature::new(messages, &sk, &h)
        .map_err(debug_to_js_value)
        .and_then(|sig| Ok(obj_to_uint8array!(&sig, true, "PSBlindSignature")))
}

#[wasm_bindgen(js_name = psUnblindSignature)]
pub fn ps_unblind_sig(
    blind_signature: js_sys::Uint8Array,
    indexed_blindings: js_sys::Map,
    public_key: Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();

    let signature = obj_from_uint8array!(PSBlindSignature, blind_signature, false);
    let indexed_blindings: BTreeMap<_, _> =
        js_map_to_iter(&indexed_blindings).collect::<Result<_, _>>()?;
    let sorted_indexed_blindigns = indexed_blindings
        .iter()
        .map(|(&idx, message)| (idx, message));
    let pk = obj_from_uint8array!(PSPublicKey, public_key, false, "PSPublicKey");

    Ok(obj_to_uint8array!(
        &signature
            .unblind(sorted_indexed_blindigns, &pk)
            .map_err(debug_to_js_value)?,
        true,
        "PSSignature"
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
    let signature = obj_from_uint8array!(PSSignature, signature, true);
    let pk = obj_from_uint8array!(PSPublicKey, public_key, false, "PSPublicKey");
    let params: PSSignatureParams = from_value(params)?;
    let messages: Vec<_> = js_array_to_iter(&messages).collect::<Result<_, _>>()?;

    signature
        .verify(&messages, &pk, &params)
        .map(|_| {
            to_value(&VerifyResponse {
                verified: true,
                error: None,
            })
            .unwrap()
        })
        .map_err(|err| {
            to_value(&VerifyResponse {
                verified: false,
                error: Some(format!("{:?}", err)),
            })
            .unwrap()
        })
}

#[wasm_bindgen(js_name = psInitializeSignaturePoK)]
pub fn ps_initialize_signature_pok(
    signature: js_sys::Uint8Array,
    params: JsValue,
    public_key: js_sys::Uint8Array,
    messages: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let signature = obj_from_uint8array!(PSSignature, signature, true);
    let params: PSSignatureParams = from_value(params)?;
    let pk = obj_from_uint8array!(PSPublicKey, public_key, false, "PSPublicKey");
    let messages = js_sys::try_iter(&messages)?
        .unwrap()
        .map(Result::unwrap)
        .map(|js_msg| from_value::<CommitMessage<Fr>>(js_msg).unwrap());

    let mut rng = get_seeded_rng();

    PSPoKOfSigProtocol::init(&mut rng, messages, &signature, &pk, &params)
        .map_err(debug_to_js_value)
        .and_then(|protocol| to_value(&protocol).map_err(Into::into))
}

#[wasm_bindgen(js_name = psInitializeMessagesPoK)]
pub fn ps_initialize_messages_pok(
    messages: JsValue,
    params: JsValue,
    h: js_sys::Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let messages = js_sys::try_iter(&messages)?
        .unwrap()
        .map(Result::unwrap)
        .map(|js_msg| from_value::<CommitMessage<Fr>>(js_msg).unwrap());
    let params: PSSignatureParams = from_value(params)?;
    let h = obj_from_uint8array!(G1Affine, h, false);

    let mut rng = get_seeded_rng();

    PSPoKOfMessagesProtocol::init(&mut rng, messages, &params, &h)
        .map_err(debug_to_js_value)
        .and_then(|protocol| to_value(&protocol).map_err(Into::into))
}

#[wasm_bindgen(js_name = psGenSignaturePoK)]
pub fn ps_gen_sig_proof(
    protocol: JsValue,
    challenge: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let protocol: PSPoKOfSigProtocol = from_value(protocol)?;
    let challenge = fr_from_uint8_array(challenge, false)?;

    protocol
        .gen_proof(&challenge)
        .map_err(debug_to_js_value)
        .and_then(|proof| Ok(obj_to_uint8array!(&proof, false, "PSPoKOfSignatureProof")))
}

#[wasm_bindgen(js_name = psGenMessagesPoK)]
pub fn ps_gen_messages_proof(
    protocol: JsValue,
    challenge: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let protocol: PSPoKOfMessagesProtocol = from_value(protocol)?;
    let challenge = fr_from_uint8_array(challenge, false)?;

    protocol
        .gen_proof(&challenge)
        .map_err(debug_to_js_value)
        .and_then(|proof| Ok(obj_to_uint8array!(&proof, false, "PSPoKOfMessagesProof")))
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

    let proof: PSPoKOfSignatureProof = obj_from_uint8array!(PSPoKOfSignatureProof, proof, false);
    let params: PSSignatureParams = from_value(params)?;
    let public_key = obj_from_uint8array!(PSPublicKey, public_key, false, "PSPublicKey");
    let challenge = fr_from_uint8_array(challenge, false)?;

    let msgs: BTreeMap<_, _> = js_map_to_iter(&revealed_msgs).collect::<Result<_, _>>()?;
    let msgs_iter = msgs.iter().map(|(&idx, msg)| (idx, msg));

    proof
        .verify(&challenge, msgs_iter, &public_key, &params)
        .map(|_| {
            to_value(&VerifyResponse {
                verified: true,
                error: None,
            })
            .unwrap()
        })
        .map_err(|err| {
            to_value(&VerifyResponse {
                verified: false,
                error: Some(format!("{:?}", err)),
            })
            .unwrap()
        })
}

#[wasm_bindgen(js_name = psVerifyMessagesPoK)]
pub fn ps_verify_messages_proof(
    proof: js_sys::Uint8Array,
    revealed_indices: js_sys::Set,
    challenge: js_sys::Uint8Array,
    params: JsValue,
    h: js_sys::Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let proof: PSPoKOfMessagesProof = obj_from_uint8array!(PSPoKOfMessagesProof, proof, false);
    let challenge = fr_from_uint8_array(challenge, false)?;
    let revealed_indices: BTreeSet<usize> = revealed_indices
        .values()
        .into_iter()
        .map(|i| serde_wasm_bindgen::from_value(i.unwrap()).unwrap())
        .collect();
    let params: PSSignatureParams = from_value(params)?;
    let h = obj_from_uint8array!(G1Affine, h, false);

    proof
        .verify(&challenge, revealed_indices, &params, &h)
        .map(|_| {
            to_value(&VerifyResponse {
                verified: true,
                error: None,
            })
            .unwrap()
        })
        .map_err(|err| {
            to_value(&VerifyResponse {
                verified: false,
                error: Some(format!("{:?}", err)),
            })
            .unwrap()
        })
}

#[wasm_bindgen(js_name = psChallengeSignaturePoKContributionFromProtocol)]
pub fn ps_challenge_signature_pok_contribution_from_protocol(
    protocol: JsValue,
    public_key: Uint8Array,
    params: JsValue,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();

    let protocol: PSPoKOfSigProtocol = from_value(protocol)?;
    let pk = obj_from_uint8array!(PSPublicKey, public_key, false, "PSPublicKey");
    let params: PSSignatureParams = from_value(params)?;
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
    h: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();

    let protocol: PSPoKOfMessagesProtocol = from_value(protocol)?;
    let params: PSSignatureParams = from_value(params)?;
    let h = obj_from_uint8array!(G1Affine, h, false);
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

    let proof: PSPoKOfSignatureProof = obj_from_uint8array!(PSPoKOfSignatureProof, proof, false);
    let pk = obj_from_uint8array!(PSPublicKey, public_key, false, "PSPublicKey");
    let params: PSSignatureParams = from_value(params)?;

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
    h: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();

    let proof: PSPoKOfMessagesProof = obj_from_uint8array!(PSPoKOfMessagesProof, proof, false);
    let params: PSSignatureParams = from_value(params)?;
    let h = obj_from_uint8array!(G1Affine, h, false);

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
    let params = obj_from_uint8array!(PSSignatureParams, bytes, false, "PSSignatureParams");
    to_value(&params).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = psAggregateSignatures)]
pub fn ps_aggregate_signatures(
    participant_signatures: js_sys::Map,
    h: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();

    let sorted_participant_signatures: BTreeMap<_, _> = js_map_to_iter(&participant_signatures)
        .map(|part_sig| {
            part_sig.and_then(|(participant, signature)| {
                participant
                    .try_into()
                    .map_err(|_| "Invalid participant id".into())
                    .map(|participant| (participant, signature))
            })
        })
        .collect::<Result<_, _>>()?;
    let sorted_participant_signatures_iter = sorted_participant_signatures
        .iter()
        .map(|(&participant, signature)| (participant, signature));
    let h = obj_from_uint8array!(G1Affine, h, false);
    let aggregated = PSAggregatedSignature::new(sorted_participant_signatures_iter, &h)
        .map_err(debug_to_js_value)?;

    Ok(obj_to_uint8array!(
        &aggregated,
        true,
        "PSAggregatedSignature"
    ))
}

#[wasm_bindgen(js_name = psShamirDeal)]
pub fn ps_shamir_deal(
    message_count: usize,
    threshold: u16,
    total: u16,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let threshold = Threshold::new(threshold, total).ok_or("Invalid threshold")?;
    let mut rng = get_seeded_rng();
    let keys =
        shamir_ss::deal::<_, Fr>(&mut rng, message_count, threshold).map_err(debug_to_js_value)?;

    to_value(&keys).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = psAdaptSignatureParamsForMsgCount)]
pub fn ps_adapt_sig_params_for_msg_count(
    params: JsValue,
    generating_label: js_sys::Uint8Array,
    new_count: usize,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    crate::adapt_params!(
        params,
        generating_label,
        new_count,
        PSSignatureParams,
        G1Affine
    )
}

pub fn js_array_to_iter<Item: CanonicalDeserialize>(
    messages: &js_sys::Array,
) -> impl Iterator<Item = Result<Item, JsValue>> {
    messages.values().into_iter().map(|raw| {
        Item::deserialize_compressed(js_sys::Uint8Array::new(&raw.unwrap()).to_vec().as_slice())
            .map_err(debug_to_js_value)
    })
}

pub fn js_map_to_iter<Item: CanonicalDeserialize>(
    messages: &js_sys::Map,
) -> impl Iterator<Item = Result<(usize, Item), JsValue>> {
    messages.entries().into_iter().map(|raw_msg_arr| {
        let arr = js_sys::Array::from(&raw_msg_arr?);
        let idx: usize = from_value(arr.get(0))?;
        let msg_bytes: Vec<u8> = from_value(arr.get(1))?;

        let msg = Item::deserialize_compressed(&msg_bytes[..]).map_err(|e| {
            JsValue::from(&format!(
                "Cannot deserialize to `ScalarField` due to error: {:?}",
                e
            ))
        })?;

        Ok((idx, msg))
    })
}

fn debug_to_js_value<V: core::fmt::Debug>(value: V) -> JsValue {
    JsValue::from(&format!("{:?}", value))
}
