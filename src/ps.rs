use crate::utils::{
    fr_from_uint8_array, fr_to_jsvalue, fr_to_uint8_array, g1_affine_from_uint8_array,
    g1_affine_to_jsvalue, g1_affine_to_uint8_array, g2_affine_from_uint8_array,
    g2_affine_to_jsvalue, g2_affine_to_uint8_array, get_seeded_rng,
    js_array_of_bytearrays_to_vector_of_bytevectors, random_bytes, set_panic_hook,
};

use coconut_crypto::{CommitMessage, CommitmentOrMessage, MessageCommitment};
use serde::Deserialize;
use serde_wasm_bindgen::from_value;
use wasm_bindgen::prelude::*;
use crate::utils::g1_affine_from_jsvalue;
use crate::common::VerifyResponse;
use crate::{Fr, G1Affine, G2Affine};
use ark_bls12_381::Bls12_381;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::collections::{BTreeMap, BTreeSet};
use blake2::Blake2b512;
use coconut_crypto::{proof, setup, signature};
use dock_crypto_utils::concat_slices;
use dock_crypto_utils::hashing_utils::affine_group_elem_from_try_and_incr;
use serde_wasm_bindgen::to_value;
use zeroize::Zeroize;

pub type PsSecretKey = setup::SecretKey<Fr>;
pub type BlindSignature = signature::BlindSignature<Bls12_381>;
pub type PsPublicKey = setup::PublicKey<Bls12_381>;
pub type SignatureParams = setup::SignatureParams<Bls12_381>;
pub(crate) type Signature = signature::Signature<Bls12_381>;
pub(crate) type PoKOfSigProtocol = proof::SignaturePoKGenerator<Bls12_381>;
pub(crate) type PoKOfSigProof = proof::SignaturePoK<Bls12_381>;

#[wasm_bindgen(js_name = isSignatureParamsValid)]
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

#[wasm_bindgen(js_name = generateSignatureParams)]
pub fn ps_generate_params(
    message_count: usize,
    label: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let label = label.unwrap_or_else(|| random_bytes());
    let params = SignatureParams::new::<Blake2b512>(&label, message_count);
    to_value(&params).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = psSignatureParamsToBytes)]
pub fn ps_params_to_bytes(params: JsValue) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let params: SignatureParams = from_value(params)?;
    Ok(obj_to_uint8array!(&params, false, "SignatureParams"))
}

#[wasm_bindgen(js_name = generatePSSigningKey)]
pub fn ps_generate_secret_key(
    seed: Option<Vec<u8>>,
    message_count: usize,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let seed = seed.unwrap_or_else(|| random_bytes());
    let sk = PsSecretKey::from_seed::<Blake2b512>(&seed, message_count);
    Ok(obj_to_uint8array!(&sk, true, "PsSecretKey"))
}

#[wasm_bindgen(js_name = generatePSPublicKey)]
pub fn ps_generate_public_key(
    secret_key: js_sys::Uint8Array,
    params: JsValue,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let sk = obj_from_uint8array!(PsSecretKey, secret_key, true, "PsSecretKey");
    let params: SignatureParams = from_value(params)?;
    let pk = PsPublicKey::new(&sk, &params);
    Ok(obj_to_uint8array!(&pk, false, "PublicKey"))
}

#[wasm_bindgen(js_name = isPSPublicKeyValid)]
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
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();

    let blinding = fr_from_uint8_array(blinding, false)?;
    let message = fr_from_uint8_array(message, false)?;
    let params: SignatureParams = from_value(params)?;
    let h = g1_affine_from_jsvalue(h)?;

    g1_affine_to_uint8_array(&MessageCommitment::<Bls12_381>::new(&params.g, &blinding, &h, &message))
}

#[wasm_bindgen(js_name = psSign)]
pub fn ps_sign(
    messages: js_sys::Array,
    secret_key: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();

    let sk = obj_from_uint8array!(PsSecretKey, secret_key, true, "PsSecretKey");
    let params: SignatureParams = from_value(params)?;
    let messages = encode_messages_as_js_array_to_fr_vec(&messages, encode_messages)?;

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
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    use dock_crypto_utils::serde_utils::ArkObjectBytes;
    use serde_with::serde_as;
    use serde::{Serialize, Deserialize};
    set_panic_hook();

    /// Each message can be either revealed or blinded into the commitment.
    #[serde_as]
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub enum OwnedCommitmentOrMessage {
        /// Message blinded into the commitment.
        BlindedMessage(MessageCommitment<Bls12_381>),
        /// Revealed message.
        RevealedMessage(#[serde_as(as = "ArkObjectBytes")] Fr),
    }

    impl<'a> From<&'a OwnedCommitmentOrMessage> for CommitmentOrMessage<'a, Bls12_381> {
        fn from(com_or_msg: &'a OwnedCommitmentOrMessage) -> Self {
            match com_or_msg {
                OwnedCommitmentOrMessage::BlindedMessage(msg) => CommitmentOrMessage::BlindedMessage(msg),
                OwnedCommitmentOrMessage::RevealedMessage(msg) => CommitmentOrMessage::RevealedMessage(msg)
            }
        }
    }

    let messages: Vec<_> = js_sys::try_iter(&messages)?
        .unwrap()
        .into_iter()
        .map(Result::unwrap)
        .map(|js_msg| from_value::<OwnedCommitmentOrMessage>(js_msg).unwrap())
        .collect();

    let sk = obj_from_uint8array!(PsSecretKey, secret_key, true, "PsSecretKey");
    let h = g1_affine_from_jsvalue(h)?;

    let mut rng = get_seeded_rng();

    BlindSignature::new(messages.iter(), &sk, &h)
        .map_err(debug_to_js_value)
        .and_then(|sig| Ok(obj_to_uint8array!(&sig, true, "BlindSignature")))
}

#[wasm_bindgen(js_name = psUnblindSignature)]
pub fn ps_unblind_sig(
    blind_signature: js_sys::Uint8Array,
    indexed_blindings: js_sys::Map,
    pk: JsValue,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();

    let signature = obj_from_uint8array!(BlindSignature, blind_signature, true);
    let indexed_blindings = encode_messages_as_js_map_to_fr_btreemap(&indexed_blindings, false)?;
    let pk = from_value(pk)?;

    Ok(obj_to_uint8array!(
        &signature.unblind(
            indexed_blindings
                .iter()
                .map(|(&idx, message)| (idx, message)),
            &pk
        ).map_err(debug_to_js_value)?,
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
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let signature = obj_from_uint8array!(Signature, signature, true);
    let pk = obj_from_uint8array!(PsPublicKey, public_key, false, "PsPublicKey");
    let params: SignatureParams = from_value(params)?;
    let messages = encode_messages_as_js_array_to_fr_vec(&messages, encode_messages)?;

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
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    use ark_ff::PrimeField;
    use serde::{Deserialize, Serialize};
    set_panic_hook();

    let signature = obj_from_uint8array!(Signature, signature, true);
    let params: SignatureParams = from_value(params)?;
    let pk = obj_from_uint8array!(PsPublicKey, public_key, false, "PsPublicKey");
    let messages = js_sys::try_iter(&messages)?
        .unwrap()
        .into_iter()
        .map(Result::unwrap)
        .map(|js_msg| from_value::<CommitMessage<Fr, Fr>>(js_msg).unwrap());

    let mut rng = get_seeded_rng();

    PoKOfSigProtocol::init(&mut rng, messages, &signature, &pk, &params)
        .map_err(debug_to_js_value)
        .and_then(|protocol| to_value(&protocol).map_err(debug_to_js_value))
}

fn debug_to_js_value<V: core::fmt::Debug>(value: V) -> JsValue {
    JsValue::from(&format!("{:?}", value))
}

#[wasm_bindgen(js_name = psGenProofOfKnowledgeOfSignature)]
pub fn ps_gen_proof(
    protocol: JsValue,
    challenge: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let protocol: PoKOfSigProtocol = from_value(protocol)?;
    let challenge = fr_from_uint8_array(challenge, false)?;
    match protocol.gen_proof(&challenge) {
        Ok(proof) => Ok(obj_to_uint8array!(&proof, false, "PoKOfSigProof")),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = psVerifyProofOfKnowledgeOfSignature)]
pub fn ps_verify_proof(
    proof: js_sys::Uint8Array,
    revealed_msgs: js_sys::Map,
    challenge: js_sys::Uint8Array,
    public_key: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    // let proof: PoKOfSigProof = from_value(proof)?;
    let proof: PoKOfSigProof = obj_from_uint8array!(PoKOfSigProof, proof, false);
    let params: SignatureParams = from_value(params)?;
    let public_key = obj_from_uint8array!(PsPublicKey, public_key, false, "PsPublicKey");
    let challenge = fr_from_uint8_array(challenge, false)?;

    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;

    match proof.verify(&challenge, msgs.iter().map(|(&idx, msg)| (idx, msg)), &public_key, &params) {
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

#[wasm_bindgen(js_name = psChallengeContributionFromProtocol)]
pub fn ps_challenge_contribution_from_protocol(
    protocol: JsValue,
    pk: JsValue,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();

    let protocol: PoKOfSigProtocol = from_value(protocol)?;
    let pk: PsPublicKey = from_value(pk)?;
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

#[wasm_bindgen(js_name = psChallengeContributionFromProof)]
pub fn ps_challenge_contribution_from_proof(
    proof: js_sys::Uint8Array,
    public_key: js_sys::Uint8Array,
    revealed_msgs: js_sys::Map,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();

    let proof: PoKOfSigProof = obj_from_uint8array!(PoKOfSigProof, proof, false);
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
    let mut result = vec![];
    for m in messages_as_bytes {
        result.push({
            if encode_messages {
                encode_message_for_signing(m)
            } else {
                Fr::deserialize_compressed(m.as_slice()).map_err(|e| {
                    JsValue::from(&format!("Cannot deserialize to Fr due to error: {:?}", e))
                })?
            }
        });
    }
    Ok(result)
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
        &concat_slices!(msg, b"PS+ message"),
    )
}
