use crate::{
    bbs::{BBSPublicKey, BBSSigParams},
    bbs_plus::{BBSPlusPublicKeyG2, BBSPlusSigParamsG1},
    bddt16_kvac::{BDDT16MACParams, BDDT16MACSecretKey},
    ps::{PSPublicKey, PSSignatureParams},
    utils::{encode_messages_as_js_map_to_fr_btreemap, set_panic_hook},
    G1Affine,
};
use ark_bls12_381::Bls12_381;
use js_sys::Uint8Array;
use proof_system::prelude;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
use zeroize::Zeroize;

pub(crate) type PoKBBSSigProverStmt = prelude::bbs_23::PoKBBSSignature23G1Prover<Bls12_381>;
pub(crate) type PoKBBSSigVerifierStmt = prelude::bbs_23::PoKBBSSignature23G1Verifier<Bls12_381>;
pub(crate) type PoKBBSPlusSigProverStmt = prelude::bbs_plus::PoKBBSSignatureG1Prover<Bls12_381>;
pub(crate) type PoKBBSPlusSigVerifierStmt = prelude::bbs_plus::PoKBBSSignatureG1Verifier<Bls12_381>;
pub(crate) type PoKPSSigStmt = prelude::ps_signature::PoKPSSignatureStatement<Bls12_381>;

pub(crate) type PoKOfMACStmt = prelude::bddt16_kvac::PoKOfMAC<G1Affine>;
pub(crate) type PoKOfMACFullVerifierStmt = prelude::bddt16_kvac::PoKOfMACFullVerifier<G1Affine>;

#[wasm_bindgen(js_name = generatePoKBBSSignatureProverStatement)]
pub fn generate_pok_bbs_sig_prover_statement(
    params: JsValue,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let params: BBSSigParams = serde_wasm_bindgen::from_value(params)?;
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;
    let statement = PoKBBSSigProverStmt::new_statement_from_params(params, msgs);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "PoKBBSSigProverStmt"
    ))
}

#[wasm_bindgen(js_name = generatePoKBBSSignatureVerifierStatement)]
pub fn generate_pok_bbs_sig_verifier_statement(
    params: JsValue,
    public_key: Uint8Array,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let params: BBSSigParams = serde_wasm_bindgen::from_value(params)?;
    let pk = obj_from_uint8array!(BBSPublicKey, public_key, false, "BBSPublicKey");
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;
    let statement = PoKBBSSigVerifierStmt::new_statement_from_params(params, pk, msgs);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "PoKBBSSigVerifierStmt"
    ))
}

#[wasm_bindgen(js_name = generatePoKBBSPlusSignatureProverStatement)]
pub fn generate_pok_bbs_plus_sig_prover_statement(
    params: JsValue,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let params: BBSPlusSigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;
    let statement = PoKBBSPlusSigProverStmt::new_statement_from_params(params, msgs);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "PoKBBSPlusSigProverStmt"
    ))
}

#[wasm_bindgen(js_name = generatePoKBBSPlusSignatureVerifierStatement)]
pub fn generate_pok_bbs_plus_sig_verifier_statement(
    params: JsValue,
    public_key: Uint8Array,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let params: BBSPlusSigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let pk = obj_from_uint8array!(BBSPlusPublicKeyG2, public_key, false, "BBSPlusPublicKeyG2");
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;
    let statement = PoKBBSPlusSigVerifierStmt::new_statement_from_params(params, pk, msgs);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "PoKBBSPlusSigVerifierStmt"
    ))
}

#[wasm_bindgen(js_name = generatePoKPSSignatureStatement)]
pub fn generate_pok_ps_sig_statement(
    params: JsValue,
    public_key: Uint8Array,
    revealed_msgs: js_sys::Map,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let params: PSSignatureParams = serde_wasm_bindgen::from_value(params)?;
    let pk = obj_from_uint8array!(PSPublicKey, public_key, false, "BBSPlusPublicKeyG2");
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, false)?;
    let statement = PoKPSSigStmt::new_statement_from_params(params, pk, msgs);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "PokPSStatement"
    ))
}

#[wasm_bindgen(js_name = generatePoKBBSSignatureProverStatementFromParamRefs)]
pub fn generate_pok_bbs_sig_prover_statement_from_param_refs(
    params: usize,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;
    let statement = PoKBBSSigProverStmt::new_statement_from_params_ref(params, msgs);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "PoKBBSSigProverStmt"
    ))
}

#[wasm_bindgen(js_name = generatePoKBBSSignatureVerifierStatementFromParamRefs)]
pub fn generate_pok_bbs_sig_verifier_statement_from_param_refs(
    params: usize,
    public_key: usize,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;
    let statement = PoKBBSSigVerifierStmt::new_statement_from_params_ref(params, public_key, msgs);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "PoKBBSSigVerifierStmt"
    ))
}

#[wasm_bindgen(js_name = generatePoKBBSPlusSignatureProverStatementFromParamRefs)]
pub fn generate_pok_bbs_plus_sig_prover_statement_from_param_refs(
    params: usize,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;
    let statement = PoKBBSPlusSigProverStmt::new_statement_from_params_ref(params, msgs);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "PoKBBSPlusSigProverStmt"
    ))
}

#[wasm_bindgen(js_name = generatePoKBBSPlusSignatureVerifierStatementFromParamRefs)]
pub fn generate_pok_bbs_plus_sig_verifier_statement_from_param_refs(
    params: usize,
    public_key: usize,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;
    let statement =
        PoKBBSPlusSigVerifierStmt::new_statement_from_params_ref(params, public_key, msgs);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "PoKBBSPlusSigVerifierStmt"
    ))
}

#[wasm_bindgen(js_name = generatePoKPSSignatureStatementFromParamRefs)]
pub fn generate_pok_ps_sig_statement_from_param_refs(
    params: usize,
    public_key: usize,
    revealed_msgs: js_sys::Map,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, false)?;
    let statement = PoKPSSigStmt::new_statement_from_params_ref(params, public_key, msgs);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "PokPSStatement"
    ))
}

#[wasm_bindgen(js_name = generatePoKBDDT16MacStatement)]
pub fn generate_pok_bddt16_mac_statement(
    params: JsValue,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let params: BDDT16MACParams = serde_wasm_bindgen::from_value(params)?;
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;
    let statement = PoKOfMACStmt::new_statement_from_params::<Bls12_381>(params, msgs);
    Ok(obj_to_uint8array_uncompressed!(&statement, "PoKOfMACStmt"))
}

#[wasm_bindgen(js_name = generatePoKBDDT16MacStatementFromParamRefs)]
pub fn generate_pok_bddt16_mac_statement_from_param_refs(
    params: usize,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;
    let statement = PoKOfMACStmt::new_statement_from_params_ref::<Bls12_381>(params, msgs);
    Ok(obj_to_uint8array_uncompressed!(&statement, "PoKOfMACStmt"))
}

#[wasm_bindgen(js_name = generatePoKBDDT16MacFullVerifierStatement)]
pub fn generate_pok_bddt16_mac_full_verifier_statement(
    params: JsValue,
    secret_key: Uint8Array,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let params: BDDT16MACParams = serde_wasm_bindgen::from_value(params)?;
    let sk = obj_from_uint8array!(BDDT16MACSecretKey, secret_key, true, "BDDT16MACSecretKey");
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;
    let statement =
        PoKOfMACFullVerifierStmt::new_statement_from_params::<Bls12_381>(sk, params, msgs);
    Ok(obj_to_uint8array_uncompressed!(&statement, "PoKOfMACStmt"))
}

#[wasm_bindgen(js_name = generatePoKBDDT16MacFullVerifierStatementFromParamRefs)]
pub fn generate_pok_bddt16_mac_full_verifier_statement_from_param_refs(
    params: usize,
    secret_key: Uint8Array,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let sk = obj_from_uint8array!(BDDT16MACSecretKey, secret_key, true, "BDDT16MACSecretKey");
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;
    let statement =
        PoKOfMACFullVerifierStmt::new_statement_from_params_ref::<Bls12_381>(sk, params, msgs);
    Ok(obj_to_uint8array_uncompressed!(&statement, "PoKOfMACStmt"))
}
