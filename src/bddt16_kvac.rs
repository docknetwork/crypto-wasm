use crate::{
    common::VerifyResponse,
    to_verify_response,
    utils::{
        encode_messages_as_js_array_to_fr_vec, encode_messages_as_js_map_to_fr_btreemap,
        fr_from_uint8_array, g1_affine_from_uint8_array, g1_affine_to_jsvalue,
        g1_affine_to_uint8_array, get_seeded_rng, random_bytes, set_panic_hook,
    },
    Fr, G1Affine,
};
use blake2::Blake2b512;
use dock_crypto_utils::{
    concat_slices, hashing_utils::affine_group_elem_from_try_and_incr,
    signature::MultiMessageSignatureParams,
};
use kvac::bddt_2016::{
    mac::MAC,
    setup::{MACParams, SecretKey},
};
use std::collections::BTreeMap;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
use zeroize::Zeroize;

pub type BDDT16MACParams = MACParams<G1Affine>;
pub type BDDT16MACSecretKey = SecretKey<Fr>;
pub type BDDT16MAC = MAC<G1Affine>;

#[wasm_bindgen(js_name = bddt16GenerateMacParams)]
pub fn bddt16_generate_mac_params(
    message_count: u32,
    label: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let label = label.unwrap_or_else(random_bytes);
    let params = BDDT16MACParams::new::<Blake2b512>(&label, message_count);
    serde_wasm_bindgen::to_value(&params).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = bddt16IsMacParamsValid)]
pub fn bddt16_is_mac_params_valid(params: JsValue) -> Result<bool, JsValue> {
    set_panic_hook();
    let params: BDDT16MACParams = serde_wasm_bindgen::from_value(params)?;
    Ok(params.is_valid())
}

#[wasm_bindgen(js_name = bddt16MacParamsMaxSupportedMsgs)]
pub fn bddt16_mac_params_max_supported_msgs(params: JsValue) -> Result<usize, JsValue> {
    set_panic_hook();
    let params: BDDT16MACParams = serde_wasm_bindgen::from_value(params)?;
    Ok(params.supported_message_count())
}

#[wasm_bindgen(js_name = bddt16MacParamsToBytes)]
pub fn bddt16_mac_params_to_bytes(params: JsValue) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let params: BDDT16MACParams = serde_wasm_bindgen::from_value(params)?;
    Ok(obj_to_uint8array!(&params, false, "BDDT16MACParams"))
}

#[wasm_bindgen(js_name = bddt16MacParamsFromBytes)]
pub fn bddt16_mac_params_from_bytes(bytes: js_sys::Uint8Array) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let params = obj_from_uint8array!(BDDT16MACParams, bytes, false, "BDDT16MACParams");
    serde_wasm_bindgen::to_value(&params).map_err(JsValue::from)
}

#[wasm_bindgen(js_name = bddt16MacAdaptParamsForMsgCount)]
pub fn bddt16_mac_adapt_params_for_msg_count(
    params: JsValue,
    generating_label: js_sys::Uint8Array,
    new_count: usize,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    crate::adapt_params!(
        params,
        generating_label,
        b"g_",
        g_vec,
        new_count,
        BDDT16MACParams,
        G1Affine
    )
}

#[wasm_bindgen(js_name = bddt16MacGenerateSecretKey)]
pub fn bddt16_mac_generate_secret_key(
    seed: Option<Vec<u8>>,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let seed = seed.unwrap_or_else(random_bytes);
    let sk = BDDT16MACSecretKey::generate_using_seed::<Blake2b512>(&seed);
    Ok(obj_to_uint8array!(&sk, true, "BDDT16MACSecretKey"))
}

#[wasm_bindgen(js_name = bddt16MacGetBasesForCommitment)]
pub fn bddt16_mac_get_bases_for_commitment(
    params: JsValue,
    indices_to_commit: js_sys::Array,
) -> Result<js_sys::Array, JsValue> {
    let params: BDDT16MACParams = serde_wasm_bindgen::from_value(params)?;
    let bases = js_sys::Array::new();
    bases.push(&g1_affine_to_jsvalue(&params.g)?);

    for i in indices_to_commit.values() {
        let index: usize = serde_wasm_bindgen::from_value(i.unwrap())?;
        if index >= params.supported_message_count() {
            return Err(JsValue::from(&format!(
                "Invalid index {:?} to get signature param",
                index
            )));
        }
        bases.push(&g1_affine_to_jsvalue(&params.g_vec[index])?);
    }
    Ok(bases)
}

#[wasm_bindgen(js_name = bddt16MacCommitMsgs)]
pub fn bddt16_mac_commit_to_message(
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

    let params: BDDT16MACParams = serde_wasm_bindgen::from_value(params)?;
    let blinding = fr_from_uint8_array(blinding, true)?;
    match params.commit_to_messages(msgs_ref, &blinding) {
        Ok(comm) => g1_affine_to_uint8_array(&comm),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bddt16MacGenerate)]
pub fn bddt16_mac_generate(
    messages: js_sys::Array,
    secret_key: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let sk = obj_from_uint8array!(BDDT16MACSecretKey, secret_key, true, "BDDT16MACSecretKey");
    let params: BDDT16MACParams = serde_wasm_bindgen::from_value(params)?;
    let messages = encode_messages_as_js_array_to_fr_vec(&messages, encode_messages)?;

    let mut rng = get_seeded_rng();
    match BDDT16MAC::new(&mut rng, &messages, &sk, &params) {
        Ok(mac) => Ok(obj_to_uint8array!(&mac, true, "BDDT16MAC")),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bddt16BlindMacGenerate)]
pub fn bddt16_blind_mac_generate(
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
    let sk = obj_from_uint8array!(BDDT16MACSecretKey, secret_key, true, "BDDT16MACSecretKey");
    let params: BDDT16MACParams = serde_wasm_bindgen::from_value(params)?;

    let mut rng = get_seeded_rng();
    match BDDT16MAC::new_with_committed_messages(&mut rng, &commitment, msgs_ref, &sk, &params) {
        Ok(sig) => Ok(obj_to_uint8array!(&sig, true, "BDDT16MAC")),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bddt16UnblindMac)]
pub fn bddt16_unblind_mac(
    blind_mac: js_sys::Uint8Array,
    blinding: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let mac = obj_from_uint8array!(BDDT16MAC, blind_mac, true);
    let blinding = fr_from_uint8_array(blinding, true)?;
    Ok(obj_to_uint8array!(
        &mac.unblind(&blinding),
        true,
        "BDDT16MAC"
    ))
}

#[wasm_bindgen(js_name = bddt16MacVerify)]
pub fn bddt16_mac_verify(
    messages: js_sys::Array,
    mac: js_sys::Uint8Array,
    secret_key: js_sys::Uint8Array,
    params: JsValue,
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let mac = obj_from_uint8array!(BDDT16MAC, mac, true);
    let sk = obj_from_uint8array!(BDDT16MACSecretKey, secret_key, true, "BDDT16MACSecretKey");
    let params: BDDT16MACParams = serde_wasm_bindgen::from_value(params)?;
    let messages = encode_messages_as_js_array_to_fr_vec(&messages, encode_messages)?;
    to_verify_response!(mac.verify(messages.as_slice(), &sk, &params))
}
