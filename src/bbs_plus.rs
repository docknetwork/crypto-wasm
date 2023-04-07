use crate::utils::{
    fr_from_uint8_array, fr_to_jsvalue, fr_to_uint8_array, g1_affine_from_uint8_array,
    g1_affine_to_jsvalue, g1_affine_to_uint8_array, g2_affine_from_uint8_array,
    g2_affine_to_jsvalue, g2_affine_to_uint8_array, get_seeded_rng,
    js_array_of_bytearrays_to_vector_of_bytevectors, random_bytes, set_panic_hook,
};

use bbs_plus::proof::MessageOrBlinding;
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

pub type BBSPlusSk = SecretKey<Fr>;
pub type SigParamsG1 = SignatureParamsG1<Bls12_381>;
pub type SigParamsG2 = SignatureParamsG2<Bls12_381>;
pub type BBSPlusPkG1 = PublicKeyG1<Bls12_381>;
pub type BBSPlusPkG2 = PublicKeyG2<Bls12_381>;
pub(crate) type SigG1 = SignatureG1<Bls12_381>;
pub(crate) type SigG2 = SignatureG2<Bls12_381>;
pub(crate) type PoKOfSigProtocol = PoKOfSignatureG1Protocol<Bls12_381>;
pub(crate) type PoKOfSigProof = PoKOfSignatureG1Proof<Bls12_381>;

#[wasm_bindgen(js_name = generateSignatureParamsG1)]
pub fn bbs_generate_g1_params(
    message_count: usize,
    label: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let label = label.unwrap_or_else(|| random_bytes());
    let params = SigParamsG1::new::<Blake2b512>(&label, message_count);
    serde_wasm_bindgen::to_value(&params).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = isSignatureParamsG1Valid)]
pub fn bbs_is_params_g1_valid(params: JsValue) -> Result<bool, JsValue> {
    set_panic_hook();
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    Ok(params.is_valid())
}

#[wasm_bindgen(js_name = bbsSignatureParamsG1MaxSupportedMsgs)]
pub fn bbs_params_g1_max_supported_msgs(params: JsValue) -> Result<usize, JsValue> {
    set_panic_hook();
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    Ok(params.supported_message_count())
}

#[wasm_bindgen(js_name = generateSignatureParamsG2)]
pub fn bbs_generate_g2_params(
    message_count: usize,
    label: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let label = label.unwrap_or_else(|| random_bytes());
    let params = SigParamsG2::new::<Blake2b512>(&label, message_count);
    serde_wasm_bindgen::to_value(&params).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = isSignatureParamsG2Valid)]
pub fn bbs_is_params_g2_valid(params: JsValue) -> Result<bool, JsValue> {
    set_panic_hook();
    let params: SigParamsG2 = serde_wasm_bindgen::from_value(params)?;
    Ok(params.is_valid())
}

#[wasm_bindgen(js_name = bbsSignatureParamsG2MaxSupportedMsgs)]
pub fn bbs_params_g2_max_supported_msgs(params: JsValue) -> Result<usize, JsValue> {
    set_panic_hook();
    let params: SigParamsG2 = serde_wasm_bindgen::from_value(params)?;
    Ok(params.supported_message_count())
}

#[wasm_bindgen(js_name = bbsSignatureParamsG1ToBytes)]
pub fn bbs_params_g1_to_bytes(params: JsValue) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    Ok(obj_to_uint8array!(&params, false, "SigParamsG1"))
}

#[wasm_bindgen(js_name = bbsSignatureParamsG1FromBytes)]
pub fn bbs_params_g1_from_bytes(bytes: js_sys::Uint8Array) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let params = obj_from_uint8array!(SigParamsG1, bytes, false, "SigParamsG1");
    serde_wasm_bindgen::to_value(&params).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = bbsSignatureParamsG2ToBytes)]
pub fn bbs_params_g2_to_bytes(params: JsValue) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let params: SigParamsG2 = serde_wasm_bindgen::from_value(params)?;
    Ok(obj_to_uint8array!(&params, false, "SigParamsG2"))
}

#[wasm_bindgen(js_name = bbsSignatureParamsG2FromBytes)]
pub fn bbs_params_g2_from_bytes(bytes: js_sys::Uint8Array) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let params = obj_from_uint8array!(SigParamsG2, bytes, false, "SigParamsG2");
    serde_wasm_bindgen::to_value(&params).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = generateBBSSigningKey)]
pub fn bbs_generate_secret_key(seed: Option<Vec<u8>>) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let seed = seed.unwrap_or_else(|| random_bytes());
    let sk = BBSPlusSk::generate_using_seed::<Blake2b512>(&seed);
    Ok(obj_to_uint8array!(&sk, true, "BBSPlusSk"))
}

#[wasm_bindgen(js_name = generateBBSPublicKeyG1)]
pub fn bbs_generate_public_key_g1(
    secret_key: js_sys::Uint8Array,
    params: JsValue,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let sk = obj_from_uint8array!(BBSPlusSk, secret_key, true, "BBSPlusSk");
    let params: SigParamsG2 = serde_wasm_bindgen::from_value(params)?;
    let pk = BBSPlusPkG1::generate_using_secret_key(&sk, &params);
    Ok(obj_to_uint8array!(&pk, false, "PublicKeyG1"))
}

#[wasm_bindgen(js_name = isBBSPublicKeyG1Valid)]
pub fn bbs_is_pubkey_g1_valid(public_key: js_sys::Uint8Array) -> Result<bool, JsValue> {
    set_panic_hook();
    let pk = obj_from_uint8array!(BBSPlusPkG1, public_key, false, "BBSPlusPkG1");
    Ok(pk.is_valid())
}

#[wasm_bindgen(js_name = generateBBSPublicKeyG2)]
pub fn bbs_generate_public_key_g2(
    secret_key: js_sys::Uint8Array,
    params: JsValue,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let sk = obj_from_uint8array!(BBSPlusSk, secret_key, true, "BBSPlusSk");
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let pk = BBSPlusPkG2::generate_using_secret_key(&sk, &params);
    Ok(obj_to_uint8array!(&pk, false, "PublicKeyG2"))
}

#[wasm_bindgen(js_name = isBBSPublicKeyG2Valid)]
pub fn bbs_is_pubkey_g2_valid(public_key: js_sys::Uint8Array) -> Result<bool, JsValue> {
    set_panic_hook();
    let pk = obj_from_uint8array!(BBSPlusPkG2, public_key, false, "BBSPlusPkG2");
    Ok(pk.is_valid())
}

#[wasm_bindgen(js_name = generateBBSKeyPairG1)]
pub fn bbs_generate_g1_keypair(params: JsValue, seed: Option<Vec<u8>>) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let params: SigParamsG2 = serde_wasm_bindgen::from_value(params)?;
    let mut seed = seed.unwrap_or(random_bytes());
    let keypair = KeypairG1::generate_using_seed::<Blake2b512>(&seed, &params);
    seed.zeroize();
    serde_wasm_bindgen::to_value(&keypair).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = generateBBSKeyPairG2)]
pub fn bbs_generate_g2_keypair(params: JsValue, seed: Option<Vec<u8>>) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let mut seed = seed.unwrap_or(random_bytes());
    let keypair = KeypairG2::generate_using_seed::<Blake2b512>(&seed, &params);
    seed.zeroize();
    serde_wasm_bindgen::to_value(&keypair).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = bbsGetBasesForCommitmentG1)]
pub fn bbs_get_bases_for_commitment_g1(
    params: JsValue,
    indices_to_commit: js_sys::Array,
) -> Result<js_sys::Array, JsValue> {
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let bases = js_sys::Array::new();
    bases.push(&g1_affine_to_jsvalue(&params.h_0)?);
    for i in indices_to_commit.values() {
        let index: usize = serde_wasm_bindgen::from_value(i.unwrap())?;
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
}

#[wasm_bindgen(js_name = bbsGetBasesForCommitmentG2)]
pub fn bbs_get_bases_for_commitment_g2(
    params: JsValue,
    indices_to_commit: js_sys::Array,
) -> Result<js_sys::Array, JsValue> {
    let params: SigParamsG2 = serde_wasm_bindgen::from_value(params)?;
    let bases = js_sys::Array::new();
    bases.push(&g2_affine_to_jsvalue(&params.h_0)?);
    for i in indices_to_commit.values() {
        let index: usize = serde_wasm_bindgen::from_value(i.unwrap())?;
        if index >= params.supported_message_count() {
            return Err(JsValue::from(&format!(
                "Invalid index {:?} to get signature param",
                index
            ))
            .into());
        }
        bases.push(&g2_affine_to_jsvalue(&params.h[index])?);
    }
    Ok(bases)
}

#[wasm_bindgen(js_name = bbsEncodeMessageForSigning)]
pub fn bbs_encode_message_for_signing(message: Vec<u8>) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let fr = encode_message_for_signing(&message);
    Ok(fr_to_uint8_array(&fr)?)
}

#[wasm_bindgen(js_name = bbsEncodeMessagesForSigning)]
pub fn bbs_encode_messages_for_signing(
    messages: js_sys::Array,
    indices_to_encode: js_sys::Array,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    let encoded = js_sys::Array::new();
    for i in indices_to_encode.values() {
        let index: u32 = serde_wasm_bindgen::from_value(i.unwrap())?;
        if index >= messages.length() {
            return Err(JsValue::from(&format!("Invalid index {:?} to get message", index)).into());
        }
        let msg: Vec<u8> = serde_wasm_bindgen::from_value(messages.get(index))?;
        let fr = encode_message_for_signing(&msg);
        encoded.push(&fr_to_jsvalue(&fr)?);
    }
    Ok(encoded)
}

#[wasm_bindgen(js_name = bbsCommitMsgsInG1)]
pub fn bbs_commit_to_message_in_g1(
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

    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let blinding = fr_from_uint8_array(blinding, true)?;
    match params.commit_to_messages(msgs_ref, &blinding) {
        Ok(comm) => g1_affine_to_uint8_array(&comm),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsCommitMsgsInG2)]
pub fn bbs_commit_to_message_in_g2(
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

    let params: SigParamsG2 = serde_wasm_bindgen::from_value(params)?;
    let blinding = fr_from_uint8_array(blinding, true)?;
    match params.commit_to_messages(msgs_ref, &blinding) {
        Ok(comm) => g2_affine_to_uint8_array(&comm),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsSignG1)]
pub fn bbs_sign_g1(
    messages: js_sys::Array,
    secret_key: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let sk = obj_from_uint8array!(BBSPlusSk, secret_key, true, "BBSPlusSk");
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let messages = encode_messages_as_js_array_to_fr_vec(&messages, encode_messages)?;

    let mut rng = get_seeded_rng();
    match SigG1::new(&mut rng, &messages, &sk, &params) {
        // Ok(sig) => Ok(serde_wasm_bindgen::to_value(&sig).map_err(|e| JsValue::from(e)).unwrap()),
        Ok(sig) => Ok(obj_to_uint8array!(&sig, true, "SigG1")),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsBlindSignG1)]
pub fn bbs_blind_sign_g1(
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
    let sk = obj_from_uint8array!(BBSPlusSk, secret_key, true, "BBSPlusSk");
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;

    let mut rng = get_seeded_rng();
    match SigG1::new_with_committed_messages(&mut rng, &commitment, msgs_ref, &sk, &params) {
        // Ok(sig) => Ok(serde_wasm_bindgen::to_value(&sig).map_err(|e| JsValue::from(e)).unwrap()),
        Ok(sig) => Ok(obj_to_uint8array!(&sig, true, "SigG1")),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsUnblindSigG1)]
pub fn bbs_unblind_sig_g1(
    blind_signature: js_sys::Uint8Array,
    blinding: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    // let signature: SigG1 = serde_wasm_bindgen::from_value(blind_signature)?;
    let signature = obj_from_uint8array!(SigG1, blind_signature, true);
    let blinding = fr_from_uint8_array(blinding, true)?;
    // serde_wasm_bindgen::to_value(&signature.unblind(&blinding).map_err(|e| JsValue::from(e)))
    Ok(obj_to_uint8array!(
        &signature.unblind(&blinding),
        true,
        "SigG1"
    ))
}

#[wasm_bindgen(js_name = bbsVerifyG1)]
pub fn bbs_verify_g1(
    messages: js_sys::Array,
    signature: js_sys::Uint8Array,
    public_key: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    // let signature: SigG1 = serde_wasm_bindgen::from_value(signature)?;
    let signature = obj_from_uint8array!(SigG1, signature, true);
    let pk = obj_from_uint8array!(BBSPlusPkG2, public_key, false, "BBSPlusPkG2");
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let messages = encode_messages_as_js_array_to_fr_vec(&messages, encode_messages)?;

    match signature.verify(messages.as_slice(), pk.clone(), params.clone()) {
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

#[wasm_bindgen(js_name = bbsSignG2)]
pub fn bbs_sign_g2(
    messages: js_sys::Array,
    secret_key: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let sk = obj_from_uint8array!(BBSPlusSk, secret_key, true, "BBSPlusSk");
    let params: SigParamsG2 = serde_wasm_bindgen::from_value(params)?;
    let messages = encode_messages_as_js_array_to_fr_vec(&messages, encode_messages)?;

    let mut rng = get_seeded_rng();
    match SigG2::new(&mut rng, &messages, &sk, &params) {
        // Ok(sig) => Ok(serde_wasm_bindgen::to_value(&sig).map_err(|e| JsValue::from(e)).unwrap()),
        Ok(sig) => Ok(obj_to_uint8array!(&sig, true, "SigG2")),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsBlindSignG2)]
pub fn bbs_blind_sign_g2(
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
    let sk = obj_from_uint8array!(BBSPlusSk, secret_key, true, "BBSPlusSk");
    let params: SigParamsG2 = serde_wasm_bindgen::from_value(params)?;

    let mut rng = get_seeded_rng();
    match SigG2::new_with_committed_messages(&mut rng, &commitment, msgs_ref, &sk, &params) {
        // Ok(sig) => Ok(serde_wasm_bindgen::to_value(&sig).map_err(|e| JsValue::from(e)).unwrap()),
        Ok(sig) => Ok(obj_to_uint8array!(&sig, true, "SigG2")),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsUnblindSigG2)]
pub fn bbs_unblind_sig_g2(
    blind_signature: js_sys::Uint8Array,
    blinding: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    // let signature: SigG2 = serde_wasm_bindgen::from_value(blind_signature)?;
    let signature = obj_from_uint8array!(SigG2, blind_signature, true);
    let blinding = fr_from_uint8_array(blinding, true)?;
    // serde_wasm_bindgen::to_value(&signature.unblind(&blinding).map_err(|e| JsValue::from(e)))
    Ok(obj_to_uint8array!(
        &signature.unblind(&blinding),
        true,
        "SigG2"
    ))
}

#[wasm_bindgen(js_name = bbsVerifyG2)]
pub fn bbs_verify_g2(
    messages: js_sys::Array,
    signature: js_sys::Uint8Array,
    public_key: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    // let signature: SigG2 = serde_wasm_bindgen::from_value(signature)?;
    let signature = obj_from_uint8array!(SigG2, signature, true);
    let pk = obj_from_uint8array!(BBSPlusPkG1, public_key, false, "BBSPlusPkG1");
    let params: SigParamsG2 = serde_wasm_bindgen::from_value(params)?;
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

#[wasm_bindgen(js_name = bbsInitializeProofOfKnowledgeOfSignature)]
pub fn bbs_initialize_proof_of_knowledge_of_signature(
    signature: js_sys::Uint8Array,
    params: JsValue,
    messages: js_sys::Array,
    blindings: js_sys::Map,
    revealed_indices: js_sys::Set,
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    // let signature: SigG1 = serde_wasm_bindgen::from_value(signature)?;
    let signature = obj_from_uint8array!(SigG1, signature, true);
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    // TODO: Avoid this hack of passing false, create separate method to parse
    let mut blindings = encode_messages_as_js_map_to_fr_btreemap(&blindings, false)?;
    let messages = encode_messages_as_js_array_to_fr_vec(&messages, encode_messages)?;

    let mut indices = BTreeSet::new();
    for i in revealed_indices.values() {
        let index: usize = serde_wasm_bindgen::from_value(i.unwrap()).unwrap();
        indices.insert(index);
    }
    // TODO!
    let mut rng = get_seeded_rng();
    match PoKOfSigProtocol::init(
        &mut rng,
        &signature,
        &params,
        messages.iter().enumerate().map(|(idx, message)| {
            if indices.contains(&idx) {
                MessageOrBlinding::RevealMessage(message)
            } else if let Some(blinding) = blindings.remove(&idx) {
                MessageOrBlinding::BlindMessageWithConcreteBlinding { message, blinding }
            } else {
                MessageOrBlinding::BlindMessageRandomly(message)
            }
        }),
    ) {
        Ok(sig) => Ok(serde_wasm_bindgen::to_value(&sig)
            .map_err(|e| JsValue::from(e))
            .unwrap()),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsGenProofOfKnowledgeOfSignature)]
pub fn bbs_gen_proof(
    protocol: JsValue,
    challenge: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let protocol: PoKOfSigProtocol = serde_wasm_bindgen::from_value(protocol)?;
    let challenge = fr_from_uint8_array(challenge, false)?;
    match protocol.gen_proof(&challenge) {
        // Ok(proof) => Ok(serde_wasm_bindgen::to_value(&proof).map_err(|e| JsValue::from(e)).unwrap()),
        Ok(proof) => Ok(obj_to_uint8array!(&proof, false, "BBS+ProofG1")),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsVerifyProofOfKnowledgeOfSignature)]
pub fn bbs_verify_proof(
    proof: js_sys::Uint8Array,
    revealed_msgs: js_sys::Map,
    challenge: js_sys::Uint8Array,
    public_key: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    // let proof: PoKOfSigProof = serde_wasm_bindgen::from_value(proof)?;
    let proof: PoKOfSigProof = obj_from_uint8array!(PoKOfSigProof, proof, false);
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let public_key = obj_from_uint8array!(BBSPlusPkG2, public_key, false, "BBSPlusPkG2");
    let challenge = fr_from_uint8_array(challenge, false)?;

    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;

    match proof.verify(&msgs, &challenge, public_key.clone(), params.clone()) {
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

#[wasm_bindgen(js_name = bbsChallengeContributionFromProtocol)]
pub fn bbs_challenge_contribution_from_protocol(
    protocol: JsValue,
    revealed_msgs: js_sys::Map,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let protocol: PoKOfSigProtocol = serde_wasm_bindgen::from_value(protocol)?;
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
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

#[wasm_bindgen(js_name = bbsChallengeContributionFromProof)]
pub fn bbs_challenge_contribution_from_proof(
    proof: js_sys::Uint8Array,
    revealed_msgs: js_sys::Map,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    // let proof: PoKOfSigProof = serde_wasm_bindgen::from_value(proof)?;
    let proof: PoKOfSigProof = obj_from_uint8array!(PoKOfSigProof, proof, false);
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
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

#[wasm_bindgen(js_name = bbsAdaptSigParamsG1ForMsgCount)]
pub fn adapt_sig_params_g1_for_msg_count(
    params: JsValue,
    generating_label: js_sys::Uint8Array,
    new_count: usize,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    crate::adapt_params!(params, generating_label, new_count, SigParamsG1, G1Affine)
}

#[wasm_bindgen(js_name = bbsAdaptSigParamsG2ForMsgCount)]
pub fn adapt_sig_params_g2_for_msg_count(
    params: JsValue,
    generating_label: js_sys::Uint8Array,
    new_count: usize,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    crate::adapt_params!(params, generating_label, new_count, SigParamsG2, G2Affine)
}

#[macro_use]
mod macros {
    #[macro_export]
    macro_rules! adapt_params {
        ($params:ident, $generating_label: ident, $new_count: ident, $sig_type: ident, $sig_group: ident) => {{
            let mut params: $sig_type = serde_wasm_bindgen::from_value($params)?;
            let current_count = params.supported_message_count();
            if current_count > $new_count {
                for _ in 0..(current_count - $new_count) {
                    params.h.pop();
                }
            } else if current_count < $new_count {
                let generating_label = $generating_label.to_vec();
                for i in current_count + 1..=$new_count {
                    let h = affine_group_elem_from_try_and_incr::<$sig_group, Blake2b512>(
                        &concat_slices!(&generating_label, b" : h_", i.to_be_bytes()),
                    );
                    params.h.push(h);
                }
            }
            serde_wasm_bindgen::to_value(&params).map_err(|e| JsValue::from(e))
        }};
    }
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
