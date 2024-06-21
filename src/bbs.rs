use crate::utils::{
    encode_messages_as_js_array_to_fr_vec_in_constant_time,
    encode_messages_as_js_map_to_fr_btreemap_in_constant_time, fr_from_uint8_array,
    g1_affine_from_uint8_array, g1_affine_to_jsvalue, g1_affine_to_uint8_array, get_seeded_rng,
    js_set_to_btree_set, random_bytes, set_panic_hook,
};

use wasm_bindgen::prelude::*;

use crate::{
    blind_sign, challenge_contribution_from_proof, challenge_contribution_from_protocol,
    common::VerifyResponse,
    init_pok, sign, to_verify_response,
    utils::{encode_messages_as_js_array_to_fr_vec, encode_messages_as_js_map_to_fr_btreemap},
    verify, verify_pok, Fr, G1Affine,
};
use ark_bls12_381::Bls12_381;
use ark_std::collections::BTreeMap;
use bbs_plus::prelude::{
    KeypairG2, PoKOfSignature23G1Proof, PoKOfSignature23G1Protocol, PublicKeyG2, SecretKey,
    Signature23G1, SignatureParams23G1,
};
use blake2::Blake2b512;
use dock_crypto_utils::{
    concat_slices,
    hashing_utils::affine_group_elem_from_try_and_incr,
    signature::{MessageOrBlinding, MultiMessageSignatureParams},
};
use zeroize::Zeroize;

pub type BBSSecretKey = SecretKey<Fr>;
pub type BBSSigParams = SignatureParams23G1<Bls12_381>;
pub type BBSPublicKey = PublicKeyG2<Bls12_381>;
pub(crate) type BBSSignature = Signature23G1<Bls12_381>;
pub(crate) type BBSPoKOfSigProtocol = PoKOfSignature23G1Protocol<Bls12_381>;
pub(crate) type BBSPoKOfSigProof = PoKOfSignature23G1Proof<Bls12_381>;

pub(crate) type BBSPoKOfSigProtocolNew =
    bbs_plus::proof_23_ietf::PoKOfSignature23G1Protocol<Bls12_381>;
pub(crate) type BBSPoKOfSigProofNew = bbs_plus::proof_23_ietf::PoKOfSignature23G1Proof<Bls12_381>;

#[wasm_bindgen(js_name = bbsGenerateSignatureParams)]
pub fn bbs_generate_params(message_count: u32, label: Option<Vec<u8>>) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let label = label.unwrap_or_else(random_bytes);
    let params = BBSSigParams::new::<Blake2b512>(&label, message_count);
    serde_wasm_bindgen::to_value(&params).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = bbsIsSignatureParamsValid)]
pub fn bbs_is_params_valid(params: JsValue) -> Result<bool, JsValue> {
    set_panic_hook();
    let params: BBSSigParams = serde_wasm_bindgen::from_value(params)?;
    Ok(params.is_valid())
}

#[wasm_bindgen(js_name = bbsSignatureParamsMaxSupportedMsgs)]
pub fn bbs_params_max_supported_msgs(params: JsValue) -> Result<usize, JsValue> {
    set_panic_hook();
    let params: BBSSigParams = serde_wasm_bindgen::from_value(params)?;
    Ok(params.supported_message_count())
}

#[wasm_bindgen(js_name = bbsSignatureParamsToBytes)]
pub fn bbs_params_to_bytes(params: JsValue) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let params: BBSSigParams = serde_wasm_bindgen::from_value(params)?;
    Ok(obj_to_uint8array!(&params, false, "BBSSigParams"))
}

#[wasm_bindgen(js_name = bbsSignatureParamsFromBytes)]
pub fn bbs_params_from_bytes(bytes: js_sys::Uint8Array) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let params = obj_from_uint8array!(BBSSigParams, bytes, false, "BBSSigParams");
    serde_wasm_bindgen::to_value(&params).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = bbsGenerateSigningKey)]
pub fn bbs_generate_secret_key(seed: Option<Vec<u8>>) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let seed = seed.unwrap_or_else(random_bytes);
    let sk = BBSSecretKey::generate_using_seed::<Blake2b512>(&seed);
    Ok(obj_to_uint8array!(&sk, true, "BBSSecretKey"))
}

#[wasm_bindgen(js_name = bbsGeneratePublicKey)]
pub fn bbs_generate_public_key(
    secret_key: js_sys::Uint8Array,
    params: JsValue,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let sk = obj_from_uint8array!(BBSSecretKey, secret_key, true, "BBSSecretKey");
    let params: BBSSigParams = serde_wasm_bindgen::from_value(params)?;
    let pk = BBSPublicKey::generate_using_secret_key_and_bbs23_params(&sk, &params);
    Ok(obj_to_uint8array!(&pk, false, "BBSPublicKey"))
}

#[wasm_bindgen(js_name = bbsIsPublicKeyValid)]
pub fn bbs_is_pubkey_valid(public_key: js_sys::Uint8Array) -> Result<bool, JsValue> {
    set_panic_hook();
    let pk = obj_from_uint8array!(BBSPublicKey, public_key, false, "BBSPublicKey");
    Ok(pk.is_valid())
}

#[wasm_bindgen(js_name = bbsGenerateKeyPair)]
pub fn bbs_generate_keypair(params: JsValue, seed: Option<Vec<u8>>) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let params: BBSSigParams = serde_wasm_bindgen::from_value(params)?;
    let mut seed = seed.unwrap_or_else(random_bytes);
    let keypair = KeypairG2::generate_using_seed_and_bbs23_params::<Blake2b512>(&seed, &params);
    seed.zeroize();
    serde_wasm_bindgen::to_value(&keypair).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = bbsGetBasesForCommitment)]
pub fn bbs_get_bases_for_commitment(
    params: JsValue,
    indices_to_commit: js_sys::Array,
) -> Result<js_sys::Array, JsValue> {
    let params: BBSSigParams = serde_wasm_bindgen::from_value(params)?;
    let bases = js_sys::Array::new();

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

#[wasm_bindgen(js_name = bbsCommitMsgs)]
pub fn bbs_commit_to_message(
    messages_to_commit: js_sys::Map,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&messages_to_commit, encode_messages)?;
    let msgs_ref = msgs
        .iter()
        .map(|(i, m)| (*i, m))
        .collect::<BTreeMap<_, _>>();

    let params: BBSSigParams = serde_wasm_bindgen::from_value(params)?;
    match params.commit_to_messages(msgs_ref) {
        Ok(comm) => g1_affine_to_uint8_array(&comm),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsCommitMsgsConstantTime)]
pub fn bbs_commit_to_message_constant_time(
    messages_to_commit: js_sys::Map,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let msgs = encode_messages_as_js_map_to_fr_btreemap_in_constant_time(
        &messages_to_commit,
        encode_messages,
    )?;
    let msgs_ref = msgs
        .iter()
        .map(|(i, m)| (*i, m))
        .collect::<BTreeMap<_, _>>();

    let params: BBSSigParams = serde_wasm_bindgen::from_value(params)?;
    match params.commit_to_messages(msgs_ref) {
        Ok(comm) => g1_affine_to_uint8_array(&comm),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsSign)]
pub fn bbs_sign(
    messages: js_sys::Array,
    secret_key: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    sign!(
        messages,
        secret_key,
        params,
        encode_messages,
        BBSSecretKey,
        "BBSSecretKey",
        BBSSigParams,
        BBSSignature,
        "BBSSignature",
        encode_messages_as_js_array_to_fr_vec
    )
}

#[wasm_bindgen(js_name = bbsSignConstantTime)]
pub fn bbs_sign_constant_time(
    messages: js_sys::Array,
    secret_key: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    sign!(
        messages,
        secret_key,
        params,
        encode_messages,
        BBSSecretKey,
        "BBSSecretKey",
        BBSSigParams,
        BBSSignature,
        "BBSSignature",
        encode_messages_as_js_array_to_fr_vec_in_constant_time
    )
}

#[wasm_bindgen(js_name = bbsBlindSign)]
pub fn bbs_blind_sign(
    commitment: js_sys::Uint8Array,
    uncommitted_messages: js_sys::Map,
    secret_key: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    blind_sign!(
        commitment,
        uncommitted_messages,
        secret_key,
        params,
        encode_messages,
        BBSSecretKey,
        "BBSSecretKey",
        BBSSigParams,
        BBSSignature,
        "BBSSignature",
        encode_messages_as_js_map_to_fr_btreemap,
        g1_affine_from_uint8_array
    )
}

#[wasm_bindgen(js_name = bbsBlindSignConstantTime)]
pub fn bbs_blind_sign_constant_time(
    commitment: js_sys::Uint8Array,
    uncommitted_messages: js_sys::Map,
    secret_key: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    blind_sign!(
        commitment,
        uncommitted_messages,
        secret_key,
        params,
        encode_messages,
        BBSSecretKey,
        "BBSSecretKey",
        BBSSigParams,
        BBSSignature,
        "BBSSignature",
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time,
        g1_affine_from_uint8_array
    )
}

#[wasm_bindgen(js_name = bbsVerify)]
pub fn bbs_verify(
    messages: js_sys::Array,
    signature: js_sys::Uint8Array,
    public_key: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    verify!(
        messages,
        signature,
        public_key,
        params,
        encode_messages,
        BBSSignature,
        "BBSSignature",
        BBSPublicKey,
        "BBSPublicKey",
        BBSSigParams,
        encode_messages_as_js_array_to_fr_vec
    )
}

#[wasm_bindgen(js_name = bbsVerifyConstantTime)]
pub fn bbs_verify_constant_time(
    messages: js_sys::Array,
    signature: js_sys::Uint8Array,
    public_key: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    verify!(
        messages,
        signature,
        public_key,
        params,
        encode_messages,
        BBSSignature,
        "BBSSignature",
        BBSPublicKey,
        "BBSPublicKey",
        BBSSigParams,
        encode_messages_as_js_array_to_fr_vec_in_constant_time
    )
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
    init_pok!(
        signature,
        params,
        messages,
        blindings,
        revealed_indices,
        encode_messages,
        BBSSignature,
        BBSSigParams,
        BBSPoKOfSigProtocol,
        encode_messages_as_js_array_to_fr_vec
    )
}

#[wasm_bindgen(js_name = bbsInitializeProofOfKnowledgeOfSignatureNew)]
pub fn bbs_initialize_proof_of_knowledge_of_signature_new(
    signature: js_sys::Uint8Array,
    params: JsValue,
    messages: js_sys::Array,
    blindings: js_sys::Map,
    revealed_indices: js_sys::Set,
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    init_pok!(
        signature,
        params,
        messages,
        blindings,
        revealed_indices,
        encode_messages,
        BBSSignature,
        BBSSigParams,
        BBSPoKOfSigProtocolNew,
        encode_messages_as_js_array_to_fr_vec_in_constant_time
    )
}

#[wasm_bindgen(js_name = bbsInitializeProofOfKnowledgeOfSignatureConstantTime)]
pub fn bbs_initialize_proof_of_knowledge_of_signature_constant_time(
    signature: js_sys::Uint8Array,
    params: JsValue,
    messages: js_sys::Array,
    blindings: js_sys::Map,
    revealed_indices: js_sys::Set,
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    init_pok!(
        signature,
        params,
        messages,
        blindings,
        revealed_indices,
        encode_messages,
        BBSSignature,
        BBSSigParams,
        BBSPoKOfSigProtocol,
        encode_messages_as_js_array_to_fr_vec_in_constant_time
    )
}

#[wasm_bindgen(js_name = bbsGenProofOfKnowledgeOfSignature)]
pub fn bbs_gen_proof(
    protocol: JsValue,
    challenge: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let protocol: BBSPoKOfSigProtocol = serde_wasm_bindgen::from_value(protocol)?;
    let challenge = fr_from_uint8_array(challenge, false)?;
    match protocol.gen_proof(&challenge) {
        Ok(proof) => Ok(obj_to_uint8array!(&proof, false, "BBSProof")),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsGenProofOfKnowledgeOfSignatureNew)]
pub fn bbs_gen_proof_new(
    protocol: JsValue,
    challenge: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let protocol: BBSPoKOfSigProtocolNew = serde_wasm_bindgen::from_value(protocol)?;
    let challenge = fr_from_uint8_array(challenge, false)?;
    match protocol.gen_proof(&challenge) {
        Ok(proof) => Ok(obj_to_uint8array!(&proof, false, "BBSProofNew")),
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
    verify_pok!(
        proof,
        revealed_msgs,
        challenge,
        public_key,
        params,
        encode_messages,
        BBSPoKOfSigProof,
        BBSSigParams,
        BBSPublicKey,
        "BBSPublicKey",
        encode_messages_as_js_map_to_fr_btreemap
    )
}

#[wasm_bindgen(js_name = bbsVerifyProofOfKnowledgeOfSignatureNew)]
pub fn bbs_verify_proof_new(
    proof: js_sys::Uint8Array,
    revealed_msgs: js_sys::Map,
    challenge: js_sys::Uint8Array,
    public_key: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    verify_pok!(
        proof,
        revealed_msgs,
        challenge,
        public_key,
        params,
        encode_messages,
        BBSPoKOfSigProofNew,
        BBSSigParams,
        BBSPublicKey,
        "BBSPublicKey",
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time
    )
}

#[wasm_bindgen(js_name = bbsVerifyProofOfKnowledgeOfSignatureConstantTime)]
pub fn bbs_verify_proof_constant_time(
    proof: js_sys::Uint8Array,
    revealed_msgs: js_sys::Map,
    challenge: js_sys::Uint8Array,
    public_key: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    verify_pok!(
        proof,
        revealed_msgs,
        challenge,
        public_key,
        params,
        encode_messages,
        BBSPoKOfSigProof,
        BBSSigParams,
        BBSPublicKey,
        "BBSPublicKey",
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time
    )
}

#[wasm_bindgen(js_name = bbsChallengeContributionFromProtocol)]
pub fn bbs_challenge_contribution_from_protocol(
    protocol: JsValue,
    revealed_msgs: js_sys::Map,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    challenge_contribution_from_protocol!(
        protocol,
        revealed_msgs,
        params,
        encode_messages,
        BBSPoKOfSigProtocol,
        BBSSigParams,
        encode_messages_as_js_map_to_fr_btreemap
    )
}

#[wasm_bindgen(js_name = bbsChallengeContributionFromProtocolNew)]
pub fn bbs_challenge_contribution_from_protocol_new(
    protocol: JsValue,
    revealed_msgs: js_sys::Map,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    challenge_contribution_from_protocol!(
        protocol,
        revealed_msgs,
        params,
        encode_messages,
        BBSPoKOfSigProtocolNew,
        BBSSigParams,
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time
    )
}

#[wasm_bindgen(js_name = bbsChallengeContributionFromProtocolConstantTime)]
pub fn bbs_challenge_contribution_from_protocol_constant_time(
    protocol: JsValue,
    revealed_msgs: js_sys::Map,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    challenge_contribution_from_protocol!(
        protocol,
        revealed_msgs,
        params,
        encode_messages,
        BBSPoKOfSigProtocol,
        BBSSigParams,
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time
    )
}

#[wasm_bindgen(js_name = bbsChallengeContributionFromProof)]
pub fn bbs_challenge_contribution_from_proof(
    proof: js_sys::Uint8Array,
    revealed_msgs: js_sys::Map,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    challenge_contribution_from_proof!(
        proof,
        revealed_msgs,
        params,
        encode_messages,
        BBSPoKOfSigProof,
        BBSSigParams,
        encode_messages_as_js_map_to_fr_btreemap
    )
}

#[wasm_bindgen(js_name = bbsChallengeContributionFromProofNew)]
pub fn bbs_challenge_contribution_from_proof_new(
    proof: js_sys::Uint8Array,
    revealed_msgs: js_sys::Map,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    challenge_contribution_from_proof!(
        proof,
        revealed_msgs,
        params,
        encode_messages,
        BBSPoKOfSigProofNew,
        BBSSigParams,
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time
    )
}

#[wasm_bindgen(js_name = bbsChallengeContributionFromProofConstantTime)]
pub fn bbs_challenge_contribution_from_proof_constant_time(
    proof: js_sys::Uint8Array,
    revealed_msgs: js_sys::Map,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    challenge_contribution_from_proof!(
        proof,
        revealed_msgs,
        params,
        encode_messages,
        BBSPoKOfSigProof,
        BBSSigParams,
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time
    )
}

#[wasm_bindgen(js_name = bbsAdaptSigParamsForMsgCount)]
pub fn bbs_adapt_sig_params_for_msg_count(
    params: JsValue,
    generating_label: js_sys::Uint8Array,
    new_count: usize,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    crate::adapt_params!(
        params,
        generating_label,
        b"h_",
        h,
        new_count,
        BBSSigParams,
        G1Affine
    )
}
