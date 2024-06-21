use crate::utils::{
    fr_from_uint8_array, g1_affine_from_uint8_array, g1_affine_to_jsvalue,
    g1_affine_to_uint8_array, g2_affine_from_uint8_array, g2_affine_to_jsvalue,
    g2_affine_to_uint8_array, get_seeded_rng, js_set_to_btree_set, random_bytes, set_panic_hook,
};

use wasm_bindgen::prelude::*;

use crate::{
    common::VerifyResponse,
    to_verify_response,
    utils::{
        encode_messages_as_js_array_to_fr_vec,
        encode_messages_as_js_array_to_fr_vec_in_constant_time,
        encode_messages_as_js_map_to_fr_btreemap,
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time,
    },
    Fr, G1Affine, G2Affine,
};
use ark_bls12_381::Bls12_381;
use ark_std::collections::BTreeMap;
use bbs_plus::prelude::{
    KeypairG1, KeypairG2, PoKOfSignatureG1Proof, PoKOfSignatureG1Protocol, PublicKeyG1,
    PublicKeyG2, SecretKey, SignatureG1, SignatureG2, SignatureParamsG1, SignatureParamsG2,
};
use blake2::Blake2b512;
use dock_crypto_utils::{
    concat_slices,
    hashing_utils::affine_group_elem_from_try_and_incr,
    signature::{MessageOrBlinding, MultiMessageSignatureParams},
};
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

#[macro_export]
macro_rules! sign {
    ($messages: ident, $sk: ident, $sig_params: ident, $encode_messages: ident, $sk_type: ident, $sk_str: expr, $sig_params_type: ident, $sig: ident, $sig_str: expr, $fn_name: ident) => {{
        set_panic_hook();
        let sk = obj_from_uint8array!($sk_type, $sk, true, $sk_str);
        let params: $sig_params_type = serde_wasm_bindgen::from_value($sig_params)?;
        let messages = $fn_name(&$messages, $encode_messages)?;

        let mut rng = get_seeded_rng();
        match $sig::new(&mut rng, &messages, &sk, &params) {
            Ok(sig) => Ok(obj_to_uint8array!(&sig, true, $sig_str)),
            Err(e) => Err(JsValue::from(&format!("{:?}", e))),
        }
    }};
}

#[macro_export]
macro_rules! verify {
    ($messages: ident, $sig: ident, $pk: ident, $sig_params: ident, $encode_messages: ident, $sig_type: ident, $sig_str: expr, $pk_type: ident, $pk_str: expr, $sig_params_type: ident, $fn_name: ident) => {{
        set_panic_hook();
        let signature = obj_from_uint8array!($sig_type, $sig, true, $sig_str);
        let pk = obj_from_uint8array!($pk_type, $pk, false, $pk_str);
        let params: $sig_params_type = serde_wasm_bindgen::from_value($sig_params)?;
        let messages = $fn_name(&$messages, $encode_messages)?;
        to_verify_response!(signature.verify(messages.as_slice(), pk, params))
    }};
}

#[macro_export]
macro_rules! blind_sign {
    ($commitment: ident, $uncommitted_messages: ident, $sk: ident, $sig_params: ident, $encode_messages: ident, $sk_type: ident, $sk_str: expr, $sig_params_type: ident, $sig: ident, $sig_str: expr, $enc_fn_name: ident, $dec_fn_name: ident) => {{
        set_panic_hook();
        let commitment = $dec_fn_name($commitment)?;
        let msgs = $enc_fn_name(&$uncommitted_messages, $encode_messages)?;
        let msgs_ref = msgs
            .iter()
            .map(|(i, m)| (*i, m))
            .collect::<BTreeMap<_, _>>();
        let sk = obj_from_uint8array!($sk_type, $sk, true, $sk_str);
        let params: $sig_params_type = serde_wasm_bindgen::from_value($sig_params)?;

        let mut rng = get_seeded_rng();
        match $sig::new_with_committed_messages(&mut rng, &commitment, msgs_ref, &sk, &params) {
            Ok(sig) => Ok(obj_to_uint8array!(&sig, true, $sig_str)),
            Err(e) => Err(JsValue::from(&format!("{:?}", e))),
        }
    }};
}

#[macro_export]
macro_rules! init_pok {
    ($sig: ident, $params: ident, $messages: ident, $blindings: ident, $revealed_indices: ident, $encode_messages: ident, $sig_type: ident, $params_type: ident, $protocol: ident, $fn_name: ident) => {{
        set_panic_hook();
        let signature = obj_from_uint8array!($sig_type, $sig, true);
        let params: $params_type = serde_wasm_bindgen::from_value($params)?;
        // TODO: Avoid this hack of passing false, create separate method to parse
        let mut blindings = encode_messages_as_js_map_to_fr_btreemap(&$blindings, false)?;
        let messages = $fn_name(&$messages, $encode_messages)?;
        let revealed_indices = js_set_to_btree_set::<usize>(&$revealed_indices);
        let msg_iter = messages.iter().enumerate().map(|(idx, message)| {
            if revealed_indices.contains(&idx) {
                MessageOrBlinding::RevealMessage(message)
            } else if let Some(blinding) = blindings.remove(&idx) {
                MessageOrBlinding::BlindMessageWithConcreteBlinding { message, blinding }
            } else {
                MessageOrBlinding::BlindMessageRandomly(message)
            }
        });

        let mut rng = get_seeded_rng();
        match $protocol::init(&mut rng, &signature, &params, msg_iter) {
            Ok(sig) => Ok(serde_wasm_bindgen::to_value(&sig)
                .map_err(JsValue::from)
                .unwrap()),
            Err(e) => Err(JsValue::from(&format!("{:?}", e))),
        }
    }};
}

#[macro_export]
macro_rules! verify_pok {
    ($proof: ident, $revealed_msgs: ident, $challenge: ident, $pk: ident, $params: ident, $encode_messages: ident, $proof_type: ident, $params_type: ident, $pk_type: ident, $pk_str: expr, $fn_name: ident) => {{
        set_panic_hook();
        let proof: $proof_type = obj_from_uint8array!($proof_type, $proof, false);
        let params: $params_type = serde_wasm_bindgen::from_value($params)?;
        let public_key = obj_from_uint8array!($pk_type, $pk, false, $pk_str);
        let challenge = fr_from_uint8_array($challenge, false)?;

        let msgs = $fn_name(&$revealed_msgs, $encode_messages)?;

        to_verify_response!(proof.verify(&msgs, &challenge, public_key, params))
    }};
}

#[macro_export]
macro_rules! challenge_contribution_from_protocol {
    ($protocol: ident, $revealed_msgs: ident, $params: ident, $encode_messages: ident, $protocol_type: ident, $params_type: ident, $fn_name: ident) => {{
        set_panic_hook();
        let protocol: $protocol_type = serde_wasm_bindgen::from_value($protocol)?;
        let msgs = $fn_name(&$revealed_msgs, $encode_messages)?;
        let params: $params_type = serde_wasm_bindgen::from_value($params)?;
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
    }};
}

#[macro_export]
macro_rules! challenge_contribution_from_proof {
    ($proof: ident, $revealed_msgs: ident, $params: ident, $encode_messages: ident, $proof_type: ident, $params_type: ident, $fn_name: ident) => {{
        set_panic_hook();
        let proof: $proof_type = obj_from_uint8array!($proof_type, $proof, false);
        let msgs = $fn_name(&$revealed_msgs, $encode_messages)?;
        let params: $params_type = serde_wasm_bindgen::from_value($params)?;
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
    }};
}

#[macro_export]
macro_rules! commit_to_messages {
    ($messages_to_commit: ident, $blinding: ident, $sig_params: ident, $encode_messages: ident, $sig_params_type: ident, $enc_fn_name: ident, $dec_fn_name: ident) => {{
        set_panic_hook();
        let msgs = $enc_fn_name(&$messages_to_commit, $encode_messages)?;
        let msgs_ref = msgs
            .iter()
            .map(|(i, m)| (*i, m))
            .collect::<BTreeMap<_, _>>();

        let params: $sig_params_type = serde_wasm_bindgen::from_value($sig_params)?;
        let blinding = fr_from_uint8_array($blinding, true)?;
        match params.commit_to_messages(msgs_ref, &blinding) {
            Ok(comm) => $dec_fn_name(&comm),
            Err(e) => Err(JsValue::from(&format!("{:?}", e))),
        }
    }};
}

#[wasm_bindgen(js_name = bbsPlusGenerateSignatureParamsG1)]
pub fn bbs_plus_generate_g1_params(
    message_count: u32,
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
    message_count: u32,
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

#[wasm_bindgen(js_name = bbsPlusCommitMsgsInG1)]
pub fn bbs_plus_commit_to_message_in_g1(
    messages_to_commit: js_sys::Map,
    blinding: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    commit_to_messages!(
        messages_to_commit,
        blinding,
        params,
        encode_messages,
        BBSPlusSigParamsG1,
        encode_messages_as_js_map_to_fr_btreemap,
        g1_affine_to_uint8_array
    )
}

#[wasm_bindgen(js_name = bbsPlusCommitMsgsInG1ConstantTime)]
pub fn bbs_plus_commit_to_message_in_g1_constant_time(
    messages_to_commit: js_sys::Map,
    blinding: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    commit_to_messages!(
        messages_to_commit,
        blinding,
        params,
        encode_messages,
        BBSPlusSigParamsG1,
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time,
        g1_affine_to_uint8_array
    )
}

#[wasm_bindgen(js_name = bbsPlusCommitMsgsInG2)]
pub fn bbs_plus_commit_to_message_in_g2(
    messages_to_commit: js_sys::Map,
    blinding: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    commit_to_messages!(
        messages_to_commit,
        blinding,
        params,
        encode_messages,
        BBSPlusSigParamsG2,
        encode_messages_as_js_map_to_fr_btreemap,
        g2_affine_to_uint8_array
    )
}

#[wasm_bindgen(js_name = bbsPlusCommitMsgsInG2ConstantTime)]
pub fn bbs_plus_commit_to_message_in_g2_constant_time(
    messages_to_commit: js_sys::Map,
    blinding: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    commit_to_messages!(
        messages_to_commit,
        blinding,
        params,
        encode_messages,
        BBSPlusSigParamsG2,
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time,
        g2_affine_to_uint8_array
    )
}

#[wasm_bindgen(js_name = bbsPlusSignG1)]
pub fn bbs_plus_sign_g1(
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
        BBSPlusSigningKey,
        "BBSPlusSigningKey",
        BBSPlusSigParamsG1,
        BBSPlusSigG1,
        "BBSPlusSigG1",
        encode_messages_as_js_array_to_fr_vec
    )
}

#[wasm_bindgen(js_name = bbsPlusSignG1ConstantTime)]
pub fn bbs_plus_sign_g1_constant_time(
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
        BBSPlusSigningKey,
        "BBSPlusSigningKey",
        BBSPlusSigParamsG1,
        BBSPlusSigG1,
        "BBSPlusSigG1",
        encode_messages_as_js_array_to_fr_vec_in_constant_time
    )
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
    blind_sign!(
        commitment,
        uncommitted_messages,
        secret_key,
        params,
        encode_messages,
        BBSPlusSigningKey,
        "BBSPlusSigningKey",
        BBSPlusSigParamsG1,
        BBSPlusSigG1,
        "BBSPlusSigG1",
        encode_messages_as_js_map_to_fr_btreemap,
        g1_affine_from_uint8_array
    )
}

#[wasm_bindgen(js_name = bbsPlusBlindSignG1ConstantTime)]
pub fn bbs_plus_blind_sign_g1_constant_time(
    commitment: js_sys::Uint8Array,
    uncommitted_messages: js_sys::Map,
    secret_key: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    blind_sign!(
        commitment,
        uncommitted_messages,
        secret_key,
        params,
        encode_messages,
        BBSPlusSigningKey,
        "BBSPlusSigningKey",
        BBSPlusSigParamsG1,
        BBSPlusSigG1,
        "BBSPlusSigG1",
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time,
        g1_affine_from_uint8_array
    )
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
    verify!(
        messages,
        signature,
        public_key,
        params,
        encode_messages,
        BBSPlusSigG1,
        "BBSPlusSigG1",
        BBSPlusPublicKeyG2,
        "BBSPlusPublicKeyG2",
        BBSPlusSigParamsG1,
        encode_messages_as_js_array_to_fr_vec
    )
}

#[wasm_bindgen(js_name = bbsPlusVerifyG1ConstantTime)]
pub fn bbs_plus_verify_g1_constant_time(
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
        BBSPlusSigG1,
        "BBSPlusSigG1",
        BBSPlusPublicKeyG2,
        "BBSPlusPublicKeyG2",
        BBSPlusSigParamsG1,
        encode_messages_as_js_array_to_fr_vec_in_constant_time
    )
}

#[wasm_bindgen(js_name = bbsPlusSignG2)]
pub fn bbs_plus_sign_g2(
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
        BBSPlusSigningKey,
        "BBSPlusSigningKey",
        BBSPlusSigParamsG2,
        BBSPlusSigG2,
        "BBSPlusSigG2",
        encode_messages_as_js_array_to_fr_vec
    )
}

#[wasm_bindgen(js_name = bbsPlusSignG2ConstantTime)]
pub fn bbs_plus_sign_g2_constant_time(
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
        BBSPlusSigningKey,
        "BBSPlusSigningKey",
        BBSPlusSigParamsG2,
        BBSPlusSigG2,
        "BBSPlusSigG2",
        encode_messages_as_js_array_to_fr_vec_in_constant_time
    )
}

#[wasm_bindgen(js_name = bbsPlusBlindSignG2)]
pub fn bbs_plus_blind_sign_g2(
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
        BBSPlusSigningKey,
        "BBSPlusSigningKey",
        BBSPlusSigParamsG2,
        BBSPlusSigG2,
        "BBSPlusSigG2",
        encode_messages_as_js_map_to_fr_btreemap,
        g2_affine_from_uint8_array
    )
}

#[wasm_bindgen(js_name = bbsPlusBlindSignG2ConstantTime)]
pub fn bbs_plus_blind_sign_g2_constant_time(
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
        BBSPlusSigningKey,
        "BBSPlusSigningKey",
        BBSPlusSigParamsG2,
        BBSPlusSigG2,
        "BBSPlusSigG2",
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time,
        g2_affine_from_uint8_array
    )
}

#[wasm_bindgen(js_name = bbsPlusUnblindSigG2)]
pub fn bbs_plus_unblind_sig_g2(
    blind_signature: js_sys::Uint8Array,
    blinding: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let signature = obj_from_uint8array!(BBSPlusSigG2, blind_signature, true);
    let blinding = fr_from_uint8_array(blinding, true)?;
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

    let signature = obj_from_uint8array!(BBSPlusSigG2, signature, true);
    let pk = obj_from_uint8array!(BBSPlusPublicKeyG1, public_key, false, "BBSPlusPublicKeyG1");
    let params: BBSPlusSigParamsG2 = serde_wasm_bindgen::from_value(params)?;
    let messages = encode_messages_as_js_array_to_fr_vec(&messages, encode_messages)?;
    to_verify_response!(signature.verify(messages.as_slice(), &pk, &params))
}

#[wasm_bindgen(js_name = bbsPlusVerifyG2ConstantTime)]
pub fn bbs_plus_verify_g2_constant_time(
    messages: js_sys::Array,
    signature: js_sys::Uint8Array,
    public_key: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let signature = obj_from_uint8array!(BBSPlusSigG2, signature, true);
    let pk = obj_from_uint8array!(BBSPlusPublicKeyG1, public_key, false, "BBSPlusPublicKeyG1");
    let params: BBSPlusSigParamsG2 = serde_wasm_bindgen::from_value(params)?;
    let messages =
        encode_messages_as_js_array_to_fr_vec_in_constant_time(&messages, encode_messages)?;
    to_verify_response!(signature.verify(messages.as_slice(), &pk, &params))
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
    init_pok!(
        signature,
        params,
        messages,
        blindings,
        revealed_indices,
        encode_messages,
        BBSPlusSigG1,
        BBSPlusSigParamsG1,
        BBSPlusPoKOfSigProtocol,
        encode_messages_as_js_array_to_fr_vec
    )
}

#[wasm_bindgen(js_name = bbsPlusInitializeProofOfKnowledgeOfSignatureConstantTime)]
pub fn bbs_plus_initialize_proof_of_knowledge_of_signature_constant_time(
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
        BBSPlusSigG1,
        BBSPlusSigParamsG1,
        BBSPlusPoKOfSigProtocol,
        encode_messages_as_js_array_to_fr_vec_in_constant_time
    )
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
    verify_pok!(
        proof,
        revealed_msgs,
        challenge,
        public_key,
        params,
        encode_messages,
        BBSPlusPoKOfSigProof,
        BBSPlusSigParamsG1,
        BBSPlusPublicKeyG2,
        "BBSPlusPublicKeyG2",
        encode_messages_as_js_map_to_fr_btreemap
    )
}

#[wasm_bindgen(js_name = bbsPlusVerifyProofOfKnowledgeOfSignatureConstantTime)]
pub fn bbs_plus_verify_proof_constant_time(
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
        BBSPlusPoKOfSigProof,
        BBSPlusSigParamsG1,
        BBSPlusPublicKeyG2,
        "BBSPlusPublicKeyG2",
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time
    )
}

#[wasm_bindgen(js_name = bbsPlusChallengeContributionFromProtocol)]
pub fn bbs_plus_challenge_contribution_from_protocol(
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
        BBSPlusPoKOfSigProtocol,
        BBSPlusSigParamsG1,
        encode_messages_as_js_map_to_fr_btreemap
    )
}

#[wasm_bindgen(js_name = bbsPlusChallengeContributionFromProtocolConstantTime)]
pub fn bbs_plus_challenge_contribution_from_protocol_constant_time(
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
        BBSPlusPoKOfSigProtocol,
        BBSPlusSigParamsG1,
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time
    )
}

#[wasm_bindgen(js_name = bbsPlusChallengeContributionFromProof)]
pub fn bbs_plus_challenge_contribution_from_proof(
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
        BBSPlusPoKOfSigProof,
        BBSPlusSigParamsG1,
        encode_messages_as_js_map_to_fr_btreemap
    )
}

#[wasm_bindgen(js_name = bbsPlusChallengeContributionFromProofConstantTime)]
pub fn bbs_plus_challenge_contribution_from_proof_constant_time(
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
        BBSPlusPoKOfSigProof,
        BBSPlusSigParamsG1,
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time
    )
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
        b"h_",
        h,
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
        b"h_",
        h,
        new_count,
        BBSPlusSigParamsG2,
        G2Affine
    )
}
