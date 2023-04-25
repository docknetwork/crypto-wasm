use crate::utils::{
    fr_from_uint8_array, fr_to_jsvalue, fr_to_uint8_array, get_seeded_rng, random_bytes,
    set_panic_hook,
};

use crate::common::VerifyResponse;
use crate::{Fr, G1Affine};
use ark_bls12_381::Bls12_381;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::collections::{BTreeMap, BTreeSet};
use blake2::Blake2b512;
use coconut_crypto::{proof, setup, signature};
use coconut_crypto::{CommitMessage, CommitmentOrMessage, MessageCommitment};
use dock_crypto_utils::concat_slices;
use dock_crypto_utils::hashing_utils::affine_group_elem_from_try_and_incr;
use js_sys::Uint8Array;
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
pub fn ps_signature_params_to_bytes(params: JsValue) -> Result<js_sys::Uint8Array, JsValue> {
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
    let pk = obj_from_uint8array!(PsPublicKey, public_key, false, "PsPublicKey");
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
    let params: SignatureParams = from_value(params)?;
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

    let sk = obj_from_uint8array!(PsSecretKey, secret_key, true, "PsSecretKey");
    let params: SignatureParams = from_value(params)?;
    let messages: Vec<_> = js_array_to_iter(&messages).collect::<Result<_, _>>()?;

    let mut rng = get_seeded_rng();
    Signature::new(&mut rng, &messages, &sk, &params)
        .map_err(debug_to_js_value)
        .and_then(|sig| Ok(obj_to_uint8array!(&sig, true, "Signature")))
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

    let sk = obj_from_uint8array!(PsSecretKey, secret_key, true, "PsSecretKey");
    let h = obj_from_uint8array!(G1Affine, h, false);

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
    let indexed_blindings: BTreeMap<_, _> =
        js_map_to_iter(&indexed_blindings).collect::<Result<_, _>>()?;
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

    let signature = obj_from_uint8array!(Signature, signature, true);
    let params: SignatureParams = from_value(params)?;
    let pk = obj_from_uint8array!(PsPublicKey, public_key, false, "PsPublicKey");
    let messages = js_sys::try_iter(&messages)?
        .unwrap()
        .map(Result::unwrap)
        .map(|js_msg| from_value::<CommitMessage<Fr>>(js_msg).unwrap());

    let mut rng = get_seeded_rng();

    PoKOfSigProtocol::init(&mut rng, messages, &signature, &pk, &params)
        .map_err(debug_to_js_value)
        .and_then(|protocol| to_value(&protocol).map_err(Into::into))
}

#[wasm_bindgen(js_name = psInitializeMessagesPoK)]
pub fn ps_initialize_messagese_pok(
    messages: JsValue,
    params: JsValue,
    h: js_sys::Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let messages = js_sys::try_iter(&messages)?
        .unwrap()
        .map(Result::unwrap)
        .map(|js_msg| from_value::<CommitMessage<Fr>>(js_msg).unwrap());
    let params: SignatureParams = from_value(params)?;
    let h = obj_from_uint8array!(G1Affine, h, false);

    let mut rng = get_seeded_rng();

    PoKOfMessagesProtocol::init(&mut rng, messages, &params, &h)
        .map_err(debug_to_js_value)
        .and_then(|protocol| to_value(&protocol).map_err(Into::into))
}

fn debug_to_js_value<V: core::fmt::Debug>(value: V) -> JsValue {
    JsValue::from(&format!("{:?}", value))
}

#[wasm_bindgen(js_name = psGenSignaturePoK)]
pub fn ps_gen_sig_proof(
    protocol: JsValue,
    challenge: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let protocol: PoKOfSigProtocol = from_value(protocol)?;
    let challenge = fr_from_uint8_array(challenge, false)?;

    protocol
        .gen_proof(&challenge)
        .map_err(debug_to_js_value)
        .and_then(|proof| Ok(obj_to_uint8array!(&proof, false, "PoKOfSignatureProof")))
}

#[wasm_bindgen(js_name = psGenMessagesPoK)]
pub fn ps_gen_messages_proof(
    protocol: JsValue,
    challenge: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let protocol: PoKOfMessagesProtocol = from_value(protocol)?;
    let challenge = fr_from_uint8_array(challenge, false)?;

    protocol
        .gen_proof(&challenge)
        .map_err(debug_to_js_value)
        .and_then(|proof| Ok(obj_to_uint8array!(&proof, false, "PoKOfMessagesProof")))
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

    let proof: PoKOfMessagesProof = obj_from_uint8array!(PoKOfMessagesProof, proof, false);
    let challenge = fr_from_uint8_array(challenge, false)?;
    let revealed_indices: BTreeSet<usize> = revealed_indices
        .values()
        .into_iter()
        .map(|i| serde_wasm_bindgen::from_value(i.unwrap()).unwrap())
        .collect();
    let params: SignatureParams = from_value(params)?;
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
    h: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();

    let protocol: PoKOfMessagesProtocol = from_value(protocol)?;
    let params: SignatureParams = from_value(params)?;
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
    h: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();

    let proof: PoKOfMessagesProof = obj_from_uint8array!(PoKOfMessagesProof, proof, false);
    let params: SignatureParams = from_value(params)?;
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
    let params = obj_from_uint8array!(SignatureParams, bytes, false, "SignatureParams");
    serde_wasm_bindgen::to_value(&params).map_err(JsValue::from)
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
        SignatureParams,
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

/// This is to convert a message to field element. This encoding needs to be collision resistant but
/// not preimage-resistant and thus use of hash function is not necessary. However, the encoding must
/// be constant time
pub fn encode_message_for_signing(msg: &[u8]) -> Fr {
    dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr::<Fr, Blake2b512>(
        &concat_slices!(msg, b"PS message"),
    )
}
