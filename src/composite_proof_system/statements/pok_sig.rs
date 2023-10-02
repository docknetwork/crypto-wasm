use crate::{
    bbs::{BBSPublicKey, BBSSigParams},
    bbs_plus::{BBSPlusPublicKeyG2, BBSPlusSigParamsG1},
    ps::{PSPublicKey, PSSignatureParams},
    utils::{encode_messages_as_js_map_to_fr_btreemap, set_panic_hook},
    G1Affine,
};
use ark_bls12_381::Bls12_381;
use js_sys::Uint8Array;
use proof_system::prelude;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
use zeroize::Zeroize;

pub(crate) type PoKBBSSigStmt = prelude::bbs_23::PoKBBSSignature23G1<Bls12_381>;
pub(crate) type PoKBBSPlusSigStmt = prelude::bbs_plus::PoKBBSSignatureG1<Bls12_381>;
pub(crate) type PoKPSSigStmt = prelude::ps_signature::PoKPSSignatureStatement<Bls12_381>;

#[wasm_bindgen(js_name = generatePoKBBSSignatureStatement)]
pub fn generate_pok_bbs_sig_statement(
    params: JsValue,
    public_key: Uint8Array,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let params: BBSSigParams = serde_wasm_bindgen::from_value(params)?;
    let pk = obj_from_uint8array!(BBSPublicKey, public_key, false, "BBSPublicKey");
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;
    let statement = PoKBBSSigStmt::new_statement_from_params::<G1Affine>(params, pk, msgs);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "PoKBBSSignature23G1"
    ))
}

#[wasm_bindgen(js_name = generatePoKBBSPlusSignatureStatement)]
pub fn generate_pok_bbs_plus_sig_statement(
    params: JsValue,
    public_key: Uint8Array,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let params: BBSPlusSigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let pk = obj_from_uint8array!(BBSPlusPublicKeyG2, public_key, false, "BBSPlusPublicKeyG2");
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;
    let statement = PoKBBSPlusSigStmt::new_statement_from_params::<G1Affine>(params, pk, msgs);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "PoKBBSSignatureG1"
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
    let statement = PoKPSSigStmt::new_statement_from_params::<G1Affine>(params, pk, msgs);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "PokPSStatement"
    ))
}

#[wasm_bindgen(js_name = generatePoKBBSSignatureStatementFromParamRefs)]
pub fn generate_pok_bbs_sig_statement_from_param_refs(
    params: usize,
    public_key: usize,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;
    let statement =
        PoKBBSSigStmt::new_statement_from_params_ref::<G1Affine>(params, public_key, msgs);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "PoKBBSSignature23G1"
    ))
}

#[wasm_bindgen(js_name = generatePoKBBSPlusSignatureStatementFromParamRefs)]
pub fn generate_pok_bbs_plus_sig_statement_from_param_refs(
    params: usize,
    public_key: usize,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;
    let statement =
        PoKBBSPlusSigStmt::new_statement_from_params_ref::<G1Affine>(params, public_key, msgs);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "PoKBBSSignatureG1"
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
    let statement =
        PoKPSSigStmt::new_statement_from_params_ref::<G1Affine>(params, public_key, msgs);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "PokPSStatement"
    ))
}
