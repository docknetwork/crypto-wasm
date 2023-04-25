use crate::utils::{
    fr_from_uint8_array, fr_to_jsvalue, fr_to_uint8_array, g1_affine_from_uint8_array,
    g1_affine_to_jsvalue, g1_affine_to_uint8_array, g2_affine_from_uint8_array,
    g2_affine_to_jsvalue, g2_affine_to_uint8_array, get_seeded_rng,
    js_array_of_bytearrays_to_vector_of_bytevectors, random_bytes, set_panic_hook,
};

use bbs_plus::proof::MessageOrBlinding;
use bbs_plus::setup::MultiMessageSignatureParams;
use wasm_bindgen::prelude::*;

use crate::common::VerifyResponse;
use crate::{Fr, G1Affine, G2Affine};
use ark_bls12_381::Bls12_381;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::collections::{BTreeMap, BTreeSet};
use bbs_plus::prelude::{
    KeypairG1, KeypairG2, PoKOfSignatureG1Proof, PoKOfSignatureG1Protocol, PublicKeyG1,
    PublicKeyG2, SecretKey, SignatureG1, SignatureG2, SignatureParamsG1, SignatureParamsG2,
};
use blake2::Blake2b512;
use dock_crypto_utils::concat_slices;
use dock_crypto_utils::hashing_utils::affine_group_elem_from_try_and_incr;
use zeroize::Zeroize;

pub type BBSPlusSigningKey = SecretKey<Fr>;
pub type BBSPlusSigParamsG1 = SignatureParamsG1<Bls12_381>;
pub type BBSPlusSigParamsG2 = SignatureParamsG2<Bls12_381>;
pub type BBSPlusPublicKeyG1 = PublicKeyG1<Bls12_381>;
pub type BBSPlusPublicKeyG2 = PublicKeyG2<Bls12_381>;
pub(crate) type BBSPlusSigG1 = SignatureG1<Bls12_381>;
pub(crate) type BBSPlusSigG2 = SignatureG2<Bls12_381>;
pub(crate) type BBSPlusPoKOfSigProtocol = PoKOfSignatureG1Protocol<Bls12_381>;
pub(crate) type BBSPlusPoKOfSigProof = PoKOfSignatureG1Proof<Bls12_381>;

#[wasm_bindgen(js_name = bbsPlusGenerateSignatureParamsG1)]
pub fn bbs_plus_generate_g1_params(
    message_count: usize,
    label: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let label = label.unwrap_or_else(random_bytes);
    let params = BBSPlusSigParamsG1::new::<Blake2b512>(&label, message_count);
    serde_wasm_bindgen::to_value(&params).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = bbsPlusIsSignatureParamsG1Valid)]
pub fn bbs_plus_is_params_g1_valid(params: JsValue) -> Result<bool, JsValue> {
    set_panic_hook();
    let params: BBSPlusSigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    Ok(params.is_valid())
}

#[wasm_bindgen(js_name = bbsPlusSignatureParamsG1MaxSupportedMsgs)]
pub fn bbs_plus_params_g1_max_supported_msgs(params: JsValue) -> Result<usize, JsValue> {
    set_panic_hook();
    let params: BBSPlusSigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    Ok(params.supported_message_count())
}

#[wasm_bindgen(js_name = bbsPlusGenerateSignatureParamsG2)]
pub fn bbs_plus_generate_g2_params(
    message_count: usize,
    label: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let label = label.unwrap_or_else(random_bytes);
    let params = BBSPlusSigParamsG2::new::<Blake2b512>(&label, message_count);
    serde_wasm_bindgen::to_value(&params).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = bbsPlusIsSignatureParamsG2Valid)]
pub fn bbs_plus_is_params_g2_valid(params: JsValue) -> Result<bool, JsValue> {
    set_panic_hook();
    let params: BBSPlusSigParamsG2 = serde_wasm_bindgen::from_value(params)?;
    Ok(params.is_valid())
}

#[wasm_bindgen(js_name = bbsPlusSignatureParamsG2MaxSupportedMsgs)]
pub fn bbs_plus_params_g2_max_supported_msgs(params: JsValue) -> Result<usize, JsValue> {
    set_panic_hook();
    let params: BBSPlusSigParamsG2 = serde_wasm_bindgen::from_value(params)?;
    Ok(params.supported_message_count())
}

#[wasm_bindgen(js_name = bbsPlusSignatureParamsG1ToBytes)]
pub fn bbs_plus_params_g1_to_bytes(params: JsValue) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let params: BBSPlusSigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    Ok(obj_to_uint8array!(&params, false, "BBSPlusSigParamsG1"))
}

#[wasm_bindgen(js_name = bbsPlusSignatureParamsG1FromBytes)]
pub fn bbs_plus_params_g1_from_bytes(bytes: js_sys::Uint8Array) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let params = obj_from_uint8array!(BBSPlusSigParamsG1, bytes, false, "BBSPlusSigParamsG1");
    serde_wasm_bindgen::to_value(&params).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = bbsPlusSignatureParamsG2ToBytes)]
pub fn bbs_plus_params_g2_to_bytes(params: JsValue) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let params: BBSPlusSigParamsG2 = serde_wasm_bindgen::from_value(params)?;
    Ok(obj_to_uint8array!(&params, false, "BBSPlusSigParamsG2"))
}

#[wasm_bindgen(js_name = bbsPlusSignatureParamsG2FromBytes)]
pub fn bbs_plus_params_g2_from_bytes(bytes: js_sys::Uint8Array) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let params = obj_from_uint8array!(BBSPlusSigParamsG2, bytes, false, "BBSPlusSigParamsG2");
    serde_wasm_bindgen::to_value(&params).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = bbsPlusGenerateSigningKey)]
pub fn bbs_plus_generate_secret_key(seed: Option<Vec<u8>>) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let seed = seed.unwrap_or_else(random_bytes);
    let sk = BBSPlusSigningKey::generate_using_seed::<Blake2b512>(&seed);
    Ok(obj_to_uint8array!(&sk, true, "BBSPlusSigningKey"))
}

#[wasm_bindgen(js_name = bbsPlusGeneratePublicKeyG1)]
pub fn bbs_plus_generate_public_key_g1(
    secret_key: js_sys::Uint8Array,
    params: JsValue,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let sk = obj_from_uint8array!(BBSPlusSigningKey, secret_key, true, "BBSPlusSigningKey");
    let params: BBSPlusSigParamsG2 = serde_wasm_bindgen::from_value(params)?;
    let pk = BBSPlusPublicKeyG1::generate_using_secret_key(&sk, &params);
    Ok(obj_to_uint8array!(&pk, false, "BBSPlusPublicKeyG1"))
}

#[wasm_bindgen(js_name = bbsPlusIsPublicKeyG1Valid)]
pub fn bbs_plus_is_pubkey_g1_valid(public_key: js_sys::Uint8Array) -> Result<bool, JsValue> {
    set_panic_hook();
    let pk = obj_from_uint8array!(BBSPlusPublicKeyG1, public_key, false, "BBSPlusPublicKeyG1");
    Ok(pk.is_valid())
}

#[wasm_bindgen(js_name = bbsPlusGeneratePublicKeyG2)]
pub fn bbs_plus_generate_public_key_g2(
    secret_key: js_sys::Uint8Array,
    params: JsValue,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let sk = obj_from_uint8array!(BBSPlusSigningKey, secret_key, true, "BBSPlusSigningKey");
    let params: BBSPlusSigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let pk = BBSPlusPublicKeyG2::generate_using_secret_key(&sk, &params);
    Ok(obj_to_uint8array!(&pk, false, "BBSPlusPublicKeyG2"))
}

#[wasm_bindgen(js_name = bbsPlusIsPublicKeyG2Valid)]
pub fn bbs_plus_is_pubkey_g2_valid(public_key: js_sys::Uint8Array) -> Result<bool, JsValue> {
    set_panic_hook();
    let pk = obj_from_uint8array!(BBSPlusPublicKeyG2, public_key, false, "BBSPlusPublicKeyG2");
    Ok(pk.is_valid())
}

#[wasm_bindgen(js_name = bbsPlusGenerateKeyPairG1)]
pub fn bbs_plus_generate_g1_keypair(
    params: JsValue,
    seed: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let params: BBSPlusSigParamsG2 = serde_wasm_bindgen::from_value(params)?;
    let mut seed = seed.unwrap_or_else(random_bytes);
    let keypair = KeypairG1::generate_using_seed::<Blake2b512>(&seed, &params);
    seed.zeroize();
    serde_wasm_bindgen::to_value(&keypair).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = bbsPlusGenerateKeyPairG2)]
pub fn bbs_plus_generate_g2_keypair(
    params: JsValue,
    seed: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let params: BBSPlusSigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let mut seed = seed.unwrap_or_else(random_bytes);
    let keypair = KeypairG2::generate_using_seed::<Blake2b512>(&seed, &params);
    seed.zeroize();
    serde_wasm_bindgen::to_value(&keypair).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = bbsPlusGetBasesForCommitmentG1)]
pub fn bbs_plus_get_bases_for_commitment_g1(
    params: JsValue,
    indices_to_commit: js_sys::Array,
) -> Result<js_sys::Array, JsValue> {
    let params: BBSPlusSigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let bases = js_sys::Array::new();
    bases.push(&g1_affine_to_jsvalue(&params.h_0)?);
    for i in indices_to_commit.values() {
        let index: usize = serde_wasm_bindgen::from_value(i.unwrap())?;
        if index >= params.supported_message_count() {
            return Err(JsValue::from(&format!(
                "Invalid index {:?} to get signature param",
                index
            )));
        }
        bases.push(&g1_affine_to_jsvalue(&params.h[index])?);
    }
    Ok(bases)
}

#[wasm_bindgen(js_name = bbsPlusGetBasesForCommitmentG2)]
pub fn bbs_plus_get_bases_for_commitment_g2(
    params: JsValue,
    indices_to_commit: js_sys::Array,
) -> Result<js_sys::Array, JsValue> {
    let params: BBSPlusSigParamsG2 = serde_wasm_bindgen::from_value(params)?;
    let bases = js_sys::Array::new();
    bases.push(&g2_affine_to_jsvalue(&params.h_0)?);
    for i in indices_to_commit.values() {
        let index: usize = serde_wasm_bindgen::from_value(i.unwrap())?;
        if index >= params.supported_message_count() {
            return Err(JsValue::from(&format!(
                "Invalid index {:?} to get signature param",
                index
            )));
        }
        bases.push(&g2_affine_to_jsvalue(&params.h[index])?);
    }
    Ok(bases)
}

#[wasm_bindgen(js_name = bbsPlusEncodeMessageForSigning)]
pub fn bbs_plus_encode_message_for_signing(
    message: Vec<u8>,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let fr = encode_message_for_signing(&message);
    fr_to_uint8_array(&fr)
}

#[wasm_bindgen(js_name = bbsPlusEncodeMessagesForSigning)]
pub fn bbs_plus_encode_messages_for_signing(
    messages: js_sys::Array,
    indices_to_encode: js_sys::Array,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    let encoded = js_sys::Array::new();
    for i in indices_to_encode.values() {
        let index: u32 = serde_wasm_bindgen::from_value(i.unwrap())?;
        if index >= messages.length() {
            return Err(JsValue::from(&format!(
                "Invalid index {:?} to get message",
                index
            )));
        }
        let msg: Vec<u8> = serde_wasm_bindgen::from_value(messages.get(index))?;
        let fr = encode_message_for_signing(&msg);
        encoded.push(&fr_to_jsvalue(&fr)?);
    }
    Ok(encoded)
}

#[wasm_bindgen(js_name = bbsPlusCommitMsgsInG1)]
pub fn bbs_plus_commit_to_message_in_g1(
    messages_to_commit: js_sys::Map,
    blinding: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&messages_to_commit, encode_messages)?;
    let msgs_ref = msgs
        .iter()
        .map(|(i, m)| (*i, m))
        .collect::<BTreeMap<_, _>>();

    let params: BBSPlusSigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let blinding = fr_from_uint8_array(blinding, true)?;
    match params.commit_to_messages(msgs_ref, &blinding) {
        Ok(comm) => g1_affine_to_uint8_array(&comm),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsPlusCommitMsgsInG2)]
pub fn bbs_plus_commit_to_message_in_g2(
    messages_to_commit: js_sys::Map,
    blinding: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();

    let msgs = encode_messages_as_js_map_to_fr_btreemap(&messages_to_commit, encode_messages)?;
    let msgs_ref = msgs
        .iter()
        .map(|(i, m)| (*i, m))
        .collect::<BTreeMap<_, _>>();

    let params: BBSPlusSigParamsG2 = serde_wasm_bindgen::from_value(params)?;
    let blinding = fr_from_uint8_array(blinding, true)?;
    match params.commit_to_messages(msgs_ref, &blinding) {
        Ok(comm) => g2_affine_to_uint8_array(&comm),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsPlusSignG1)]
pub fn bbs_plus_sign_g1(
    messages: js_sys::Array,
    secret_key: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let sk = obj_from_uint8array!(BBSPlusSigningKey, secret_key, true, "BBSPlusSigningKey");
    let params: BBSPlusSigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let messages = encode_messages_as_js_array_to_fr_vec(&messages, encode_messages)?;

    let mut rng = get_seeded_rng();
    match BBSPlusSigG1::new(&mut rng, &messages, &sk, &params) {
        Ok(sig) => Ok(obj_to_uint8array!(&sig, true, "BBSPlusSigG1")),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsPlusBlindSignG1)]
pub fn bbs_plus_blind_sign_g1(
    commitment: js_sys::Uint8Array,
    uncommitted_messages: js_sys::Map,
    secret_key: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let commitment = g1_affine_from_uint8_array(commitment)?;
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&uncommitted_messages, encode_messages)?;
    let msgs_ref = msgs
        .iter()
        .map(|(i, m)| (*i, m))
        .collect::<BTreeMap<_, _>>();
    let sk = obj_from_uint8array!(BBSPlusSigningKey, secret_key, true, "BBSPlusSigningKey");
    let params: BBSPlusSigParamsG1 = serde_wasm_bindgen::from_value(params)?;

    let mut rng = get_seeded_rng();
    match BBSPlusSigG1::new_with_committed_messages(&mut rng, &commitment, msgs_ref, &sk, &params) {
        Ok(sig) => Ok(obj_to_uint8array!(&sig, true, "BBSPlusSigG1")),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsPlusUnblindSigG1)]
pub fn bbs_plus_unblind_sig_g1(
    blind_signature: js_sys::Uint8Array,
    blinding: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let signature = obj_from_uint8array!(BBSPlusSigG1, blind_signature, true);
    let blinding = fr_from_uint8_array(blinding, true)?;
    Ok(obj_to_uint8array!(
        &signature.unblind(&blinding),
        true,
        "BBSPlusSigG1"
    ))
}

#[wasm_bindgen(js_name = bbsPlusVerifyG1)]
pub fn bbs_plus_verify_g1(
    messages: js_sys::Array,
    signature: js_sys::Uint8Array,
    public_key: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    // let signature: SigG1 = serde_wasm_bindgen::from_value(signature)?;
    let signature = obj_from_uint8array!(BBSPlusSigG1, signature, true);
    let pk = obj_from_uint8array!(BBSPlusPublicKeyG2, public_key, false, "BBSPlusPublicKeyG2");
    let params: BBSPlusSigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let messages = encode_messages_as_js_array_to_fr_vec(&messages, encode_messages)?;

    match signature.verify(messages.as_slice(), pk, params) {
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
}

#[wasm_bindgen(js_name = bbsPlusSignG2)]
pub fn bbs_plus_sign_g2(
    messages: js_sys::Array,
    secret_key: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let sk = obj_from_uint8array!(BBSPlusSigningKey, secret_key, true, "BBSPlusSigningKey");
    let params: BBSPlusSigParamsG2 = serde_wasm_bindgen::from_value(params)?;
    let messages = encode_messages_as_js_array_to_fr_vec(&messages, encode_messages)?;

    let mut rng = get_seeded_rng();
    match BBSPlusSigG2::new(&mut rng, &messages, &sk, &params) {
        // Ok(sig) => Ok(serde_wasm_bindgen::to_value(&sig).map_err(|e| JsValue::from(e)).unwrap()),
        Ok(sig) => Ok(obj_to_uint8array!(&sig, true, "BBSPlusSigG2")),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsPlusBlindSignG2)]
pub fn bbs_plus_blind_sign_g2(
    commitment: js_sys::Uint8Array,
    uncommitted_messages: js_sys::Map,
    secret_key: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let commitment = g2_affine_from_uint8_array(commitment)?;
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&uncommitted_messages, encode_messages)?;
    let msgs_ref = msgs
        .iter()
        .map(|(i, m)| (*i, m))
        .collect::<BTreeMap<_, _>>();
    let sk = obj_from_uint8array!(BBSPlusSigningKey, secret_key, true, "BBSPlusSigningKey");
    let params: BBSPlusSigParamsG2 = serde_wasm_bindgen::from_value(params)?;

    let mut rng = get_seeded_rng();
    match BBSPlusSigG2::new_with_committed_messages(&mut rng, &commitment, msgs_ref, &sk, &params) {
        // Ok(sig) => Ok(serde_wasm_bindgen::to_value(&sig).map_err(|e| JsValue::from(e)).unwrap()),
        Ok(sig) => Ok(obj_to_uint8array!(&sig, true, "BBSPlusSigG2")),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsPlusUnblindSigG2)]
pub fn bbs_plus_unblind_sig_g2(
    blind_signature: js_sys::Uint8Array,
    blinding: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    // let signature: SigG2 = serde_wasm_bindgen::from_value(blind_signature)?;
    let signature = obj_from_uint8array!(BBSPlusSigG2, blind_signature, true);
    let blinding = fr_from_uint8_array(blinding, true)?;
    // serde_wasm_bindgen::to_value(&signature.unblind(&blinding).map_err(|e| JsValue::from(e)))
    Ok(obj_to_uint8array!(
        &signature.unblind(&blinding),
        true,
        "BBSPlusSigG2"
    ))
}

#[wasm_bindgen(js_name = bbsPlusVerifyG2)]
pub fn bbs_plus_verify_g2(
    messages: js_sys::Array,
    signature: js_sys::Uint8Array,
    public_key: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    // let signature: SigG2 = serde_wasm_bindgen::from_value(signature)?;
    let signature = obj_from_uint8array!(BBSPlusSigG2, signature, true);
    let pk = obj_from_uint8array!(BBSPlusPublicKeyG1, public_key, false, "BBSPlusPublicKeyG1");
    let params: BBSPlusSigParamsG2 = serde_wasm_bindgen::from_value(params)?;
    let messages = encode_messages_as_js_array_to_fr_vec(&messages, encode_messages)?;

    match signature.verify(messages.as_slice(), &pk, &params) {
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
}

#[wasm_bindgen(js_name = bbsPlusInitializeProofOfKnowledgeOfSignature)]
pub fn bbs_plus_initialize_proof_of_knowledge_of_signature(
    signature: js_sys::Uint8Array,
    params: JsValue,
    messages: js_sys::Array,
    blindings: js_sys::Map,
    revealed_indices: js_sys::Set,
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let signature = obj_from_uint8array!(BBSPlusSigG1, signature, true);
    let params: BBSPlusSigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    // TODO: Avoid this hack of passing false, create separate method to parse
    let mut blindings = encode_messages_as_js_map_to_fr_btreemap(&blindings, false)?;
    let messages = encode_messages_as_js_array_to_fr_vec(&messages, encode_messages)?;
    let revealed_indices: BTreeSet<usize> = revealed_indices
        .values()
        .into_iter()
        .map(|i| serde_wasm_bindgen::from_value(i.unwrap()).unwrap())
        .collect();

    // TODO!
    let mut rng = get_seeded_rng();
    match BBSPlusPoKOfSigProtocol::init(
        &mut rng,
        &signature,
        &params,
        messages.iter().enumerate().map(|(idx, message)| {
            if revealed_indices.contains(&idx) {
                MessageOrBlinding::RevealMessage(message)
            } else if let Some(blinding) = blindings.remove(&idx) {
                MessageOrBlinding::BlindMessageWithConcreteBlinding { message, blinding }
            } else {
                MessageOrBlinding::BlindMessageRandomly(message)
            }
        }),
    ) {
        Ok(sig) => Ok(serde_wasm_bindgen::to_value(&sig)
            .map_err(JsValue::from)
            .unwrap()),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsPlusGenProofOfKnowledgeOfSignature)]
pub fn bbs_plus_gen_proof(
    protocol: JsValue,
    challenge: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let protocol: BBSPlusPoKOfSigProtocol = serde_wasm_bindgen::from_value(protocol)?;
    let challenge = fr_from_uint8_array(challenge, false)?;
    match protocol.gen_proof(&challenge) {
        // Ok(proof) => Ok(serde_wasm_bindgen::to_value(&proof).map_err(|e| JsValue::from(e)).unwrap()),
        Ok(proof) => Ok(obj_to_uint8array!(&proof, false, "BBS+ProofG1")),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsPlusVerifyProofOfKnowledgeOfSignature)]
pub fn bbs_plus_verify_proof(
    proof: js_sys::Uint8Array,
    revealed_msgs: js_sys::Map,
    challenge: js_sys::Uint8Array,
    public_key: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    // let proof: PoKOfSigProof = serde_wasm_bindgen::from_value(proof)?;
    let proof: BBSPlusPoKOfSigProof = obj_from_uint8array!(BBSPlusPoKOfSigProof, proof, false);
    let params: BBSPlusSigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let public_key =
        obj_from_uint8array!(BBSPlusPublicKeyG2, public_key, false, "BBSPlusPublicKeyG2");
    let challenge = fr_from_uint8_array(challenge, false)?;

    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;

    match proof.verify(&msgs, &challenge, public_key, params) {
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
}

#[wasm_bindgen(js_name = bbsPlusChallengeContributionFromProtocol)]
pub fn bbs_plus_challenge_contribution_from_protocol(
    protocol: JsValue,
    revealed_msgs: js_sys::Map,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let protocol: BBSPlusPoKOfSigProtocol = serde_wasm_bindgen::from_value(protocol)?;
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;
    let params: BBSPlusSigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let mut bytes = vec![];
    protocol
        .challenge_contribution(&msgs, &params, &mut bytes)
        .map_err(|e| {
            JsValue::from(&format!(
                "Evaluating challenge_contribution returned error: {:?}",
                e
            ))
        })?;
    Ok(js_sys::Uint8Array::from(bytes.as_slice()))
}

#[wasm_bindgen(js_name = bbsPlusChallengeContributionFromProof)]
pub fn bbs_plus_challenge_contribution_from_proof(
    proof: js_sys::Uint8Array,
    revealed_msgs: js_sys::Map,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    // let proof: PoKOfSigProof = serde_wasm_bindgen::from_value(proof)?;
    let proof: BBSPlusPoKOfSigProof = obj_from_uint8array!(BBSPlusPoKOfSigProof, proof, false);
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;
    let params: BBSPlusSigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let mut bytes = vec![];
    proof
        .challenge_contribution(&msgs, &params, &mut bytes)
        .map_err(|e| {
            JsValue::from(&format!(
                "Evaluating challenge_contribution returned error: {:?}",
                e
            ))
        })?;
    Ok(js_sys::Uint8Array::from(bytes.as_slice()))
}

#[wasm_bindgen(js_name = bbsPlusAdaptSigParamsG1ForMsgCount)]
pub fn bbs_plus_adapt_sig_params_g1_for_msg_count(
    params: JsValue,
    generating_label: js_sys::Uint8Array,
    new_count: usize,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    crate::adapt_params!(
        params,
        generating_label,
        new_count,
        BBSPlusSigParamsG1,
        G1Affine
    )
}

#[wasm_bindgen(js_name = bbsPlusAdaptSigParamsG2ForMsgCount)]
pub fn bbs_plus_adapt_sig_params_g2_for_msg_count(
    params: JsValue,
    generating_label: js_sys::Uint8Array,
    new_count: usize,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    crate::adapt_params!(
        params,
        generating_label,
        new_count,
        BBSPlusSigParamsG2,
        G2Affine
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
    let mut msgs = BTreeMap::new();
    for e in messages.entries() {
        let arr = js_sys::Array::from(&e.unwrap());
        let index: usize = serde_wasm_bindgen::from_value(arr.get(0))?;
        let msg: Vec<u8> = serde_wasm_bindgen::from_value(arr.get(1))?;
        let m = if encode_messages {
            encode_message_for_signing(&msg)
        } else {
            Fr::deserialize_compressed(msg.as_slice()).map_err(|e| {
                JsValue::from(&format!("Cannot deserialize to Fr due to error: {:?}", e))
            })?
        };
        msgs.insert(index, m);
    }
    Ok(msgs)
}

/// This is to convert a message to field element. This encoding needs to be collision resistant but
/// not preimage-resistant and thus use of hash function is not necessary. However, the encoding must
/// be constant time
pub fn encode_message_for_signing(msg: &[u8]) -> Fr {
    dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr::<Fr, Blake2b512>(
        &concat_slices!(msg, b"BBS+ message"),
    )
}
