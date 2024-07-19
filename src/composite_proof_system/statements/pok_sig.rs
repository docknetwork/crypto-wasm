use crate::{
    bbs::{BBSPublicKey, BBSSigParams},
    bbs_plus::{BBSPlusPublicKeyG2, BBSPlusSigParamsG1},
    bddt16_kvac::{BDDT16MACParams, BDDT16MACSecretKey},
    ps::{PSPublicKey, PSSignatureParams},
    utils::{
        encode_messages_as_js_map_to_fr_btreemap,
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time, set_panic_hook,
    },
    G1Affine,
};
use ark_bls12_381::Bls12_381;
use js_sys::Uint8Array;
use proof_system::prelude;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
use zeroize::Zeroize;

pub(crate) type PoKBBSSigProverStmt = prelude::bbs_23::PoKBBSSignature23G1Prover<Bls12_381>;
pub(crate) type PoKBBSSigVerifierStmt = prelude::bbs_23::PoKBBSSignature23G1Verifier<Bls12_381>;
pub(crate) type PoKBBSSigProverStmtNew =
    prelude::bbs_23_ietf::PoKBBSSignature23IETFG1Prover<Bls12_381>;
pub(crate) type PoKBBSSigVerifierStmtNew =
    prelude::bbs_23_ietf::PoKBBSSignature23IETFG1Verifier<Bls12_381>;
pub(crate) type PoKBBSPlusSigProverStmt = prelude::bbs_plus::PoKBBSSignatureG1Prover<Bls12_381>;
pub(crate) type PoKBBSPlusSigVerifierStmt = prelude::bbs_plus::PoKBBSSignatureG1Verifier<Bls12_381>;
pub(crate) type PoKPSSigStmt = prelude::ps_signature::PoKPSSignatureStatement<Bls12_381>;

pub(crate) type PoKOfMACStmt = prelude::bbdt16_kvac::PoKOfMAC<G1Affine>;
pub(crate) type PoKOfMACFullVerifierStmt = prelude::bbdt16_kvac::PoKOfMACFullVerifier<G1Affine>;

macro_rules! pok_prover {
    ($params: ident, $revealed_msgs: ident, $encode_messages: ident, $sig_params_type: ident, $stmt: path, $stmt_str: expr, $fn_name: ident) => {{
        set_panic_hook();
        let params: $sig_params_type = serde_wasm_bindgen::from_value($params)?;
        let msgs = $fn_name(&$revealed_msgs, $encode_messages)?;
        let statement = $stmt(params, msgs);
        Ok(obj_to_uint8array_uncompressed!(&statement, $stmt_str))
    }};
}

macro_rules! pok_verifier {
    ($params: ident, $pk: ident, $revealed_msgs: ident, $encode_messages: ident, $sig_params_type: ident, $pk_type: ident, $pk_str: expr, $stmt: ident, $stmt_str: expr, $fn_name: ident) => {{
        set_panic_hook();
        let params: $sig_params_type = serde_wasm_bindgen::from_value($params)?;
        let pk = obj_from_uint8array!($pk_type, $pk, false, $pk_str);
        let msgs = $fn_name(&$revealed_msgs, $encode_messages)?;
        let statement = $stmt::new_statement_from_params(params, pk, msgs);
        Ok(obj_to_uint8array_uncompressed!(&statement, $stmt_str))
    }};
}

macro_rules! pok_prover_params_ref {
    ($params: ident, $revealed_msgs: ident, $encode_messages: ident, $stmt: path, $stmt_str: expr, $fn_name: ident) => {{
        set_panic_hook();
        let msgs = $fn_name(&$revealed_msgs, $encode_messages)?;
        let statement = $stmt($params, msgs);
        Ok(obj_to_uint8array_uncompressed!(&statement, $stmt_str))
    }};
}

macro_rules! pok_verifier_params_ref {
    ($params: ident, $public_key: ident, $revealed_msgs: ident, $encode_messages: ident, $stmt: ident, $stmt_str: expr, $fn_name: ident) => {{
        set_panic_hook();
        let msgs = $fn_name(&$revealed_msgs, $encode_messages)?;
        let statement = $stmt::new_statement_from_params_ref($params, $public_key, msgs);
        Ok(obj_to_uint8array_uncompressed!(&statement, $stmt_str))
    }};
}

#[wasm_bindgen(js_name = generatePoKBBSSignatureProverStatement)]
pub fn generate_pok_bbs_sig_prover_statement(
    params: JsValue,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    pok_prover!(
        params,
        revealed_msgs,
        encode_messages,
        BBSSigParams,
        PoKBBSSigProverStmt::new_statement_from_params,
        "PoKBBSSigProverStmt",
        encode_messages_as_js_map_to_fr_btreemap
    )
}

#[wasm_bindgen(js_name = generatePoKBBSSignatureProverStatementNew)]
pub fn generate_pok_bbs_sig_prover_statement_new(
    params: JsValue,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    pok_prover!(
        params,
        revealed_msgs,
        encode_messages,
        BBSSigParams,
        PoKBBSSigProverStmtNew::new_statement_from_params,
        "PoKBBSSigProverStmtNew",
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time
    )
}

#[wasm_bindgen(js_name = generatePoKBBSSignatureProverStatementConstantTime)]
pub fn generate_pok_bbs_sig_prover_statement_constant_time(
    params: JsValue,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    pok_prover!(
        params,
        revealed_msgs,
        encode_messages,
        BBSSigParams,
        PoKBBSSigProverStmt::new_statement_from_params,
        "PoKBBSSigProverStmt",
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time
    )
}

#[wasm_bindgen(js_name = generatePoKBBSSignatureVerifierStatement)]
pub fn generate_pok_bbs_sig_verifier_statement(
    params: JsValue,
    public_key: Uint8Array,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    pok_verifier!(
        params,
        public_key,
        revealed_msgs,
        encode_messages,
        BBSSigParams,
        BBSPublicKey,
        "BBSPublicKey",
        PoKBBSSigVerifierStmt,
        "PoKBBSSigVerifierStmt",
        encode_messages_as_js_map_to_fr_btreemap
    )
}

#[wasm_bindgen(js_name = generatePoKBBSSignatureVerifierStatementNew)]
pub fn generate_pok_bbs_sig_verifier_statement_new(
    params: JsValue,
    public_key: Uint8Array,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    pok_verifier!(
        params,
        public_key,
        revealed_msgs,
        encode_messages,
        BBSSigParams,
        BBSPublicKey,
        "BBSPublicKey",
        PoKBBSSigVerifierStmtNew,
        "PoKBBSSigVerifierStmtNew",
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time
    )
}

#[wasm_bindgen(js_name = generatePoKBBSSignatureVerifierStatementConstantTime)]
pub fn generate_pok_bbs_sig_verifier_statement_constant_time(
    params: JsValue,
    public_key: Uint8Array,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    pok_verifier!(
        params,
        public_key,
        revealed_msgs,
        encode_messages,
        BBSSigParams,
        BBSPublicKey,
        "BBSPublicKey",
        PoKBBSSigVerifierStmt,
        "PoKBBSSigVerifierStmt",
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time
    )
}

#[wasm_bindgen(js_name = generatePoKBBSPlusSignatureProverStatement)]
pub fn generate_pok_bbs_plus_sig_prover_statement(
    params: JsValue,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    pok_prover!(
        params,
        revealed_msgs,
        encode_messages,
        BBSPlusSigParamsG1,
        PoKBBSPlusSigProverStmt::new_statement_from_params,
        "PoKBBSPlusSigProverStmt",
        encode_messages_as_js_map_to_fr_btreemap
    )
}

#[wasm_bindgen(js_name = generatePoKBBSPlusSignatureProverStatementConstantTime)]
pub fn generate_pok_bbs_plus_sig_prover_statement_constant_time(
    params: JsValue,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    pok_prover!(
        params,
        revealed_msgs,
        encode_messages,
        BBSPlusSigParamsG1,
        PoKBBSPlusSigProverStmt::new_statement_from_params,
        "PoKBBSPlusSigProverStmt",
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time
    )
}

#[wasm_bindgen(js_name = generatePoKBBSPlusSignatureVerifierStatement)]
pub fn generate_pok_bbs_plus_sig_verifier_statement(
    params: JsValue,
    public_key: Uint8Array,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    pok_verifier!(
        params,
        public_key,
        revealed_msgs,
        encode_messages,
        BBSPlusSigParamsG1,
        BBSPlusPublicKeyG2,
        "BBSPlusPublicKeyG2",
        PoKBBSPlusSigVerifierStmt,
        "PoKBBSPlusSigVerifierStmt",
        encode_messages_as_js_map_to_fr_btreemap
    )
}

#[wasm_bindgen(js_name = generatePoKBBSPlusSignatureVerifierStatementConstantTime)]
pub fn generate_pok_bbs_plus_sig_verifier_statement_constant_time(
    params: JsValue,
    public_key: Uint8Array,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    pok_verifier!(
        params,
        public_key,
        revealed_msgs,
        encode_messages,
        BBSPlusSigParamsG1,
        BBSPlusPublicKeyG2,
        "BBSPlusPublicKeyG2",
        PoKBBSPlusSigVerifierStmt,
        "PoKBBSPlusSigVerifierStmt",
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time
    )
}

#[wasm_bindgen(js_name = generatePoKPSSignatureStatement)]
pub fn generate_pok_ps_sig_statement(
    params: JsValue,
    public_key: Uint8Array,
    revealed_msgs: js_sys::Map,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let params: PSSignatureParams = serde_wasm_bindgen::from_value(params)?;
    let pk = obj_from_uint8array!(PSPublicKey, public_key, false, "PSPublicKey");
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, false)?;
    let statement = PoKPSSigStmt::new_statement_from_params(params, pk, msgs);
    Ok(obj_to_uint8array_uncompressed!(
        &statement,
        "PokPSStatement"
    ))
}

#[wasm_bindgen(js_name = generatePoKPSSignatureStatementConstantTime)]
pub fn generate_pok_ps_sig_statement_constant_time(
    params: JsValue,
    public_key: Uint8Array,
    revealed_msgs: js_sys::Map,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let params: PSSignatureParams = serde_wasm_bindgen::from_value(params)?;
    let pk = obj_from_uint8array!(PSPublicKey, public_key, false, "PSPublicKey");
    let msgs = encode_messages_as_js_map_to_fr_btreemap_in_constant_time(&revealed_msgs, false)?;
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
    pok_prover_params_ref!(
        params,
        revealed_msgs,
        encode_messages,
        PoKBBSSigProverStmt::new_statement_from_params_ref,
        "PoKBBSSigProverStmt",
        encode_messages_as_js_map_to_fr_btreemap
    )
}

#[wasm_bindgen(js_name = generatePoKBBSSignatureProverStatementFromParamRefsNew)]
pub fn generate_pok_bbs_sig_prover_statement_from_param_refs_new(
    params: usize,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    pok_prover_params_ref!(
        params,
        revealed_msgs,
        encode_messages,
        PoKBBSSigProverStmtNew::new_statement_from_params_ref,
        "PoKBBSSigProverStmtNew",
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time
    )
}

#[wasm_bindgen(js_name = generatePoKBBSSignatureProverStatementFromParamRefsConstantTime)]
pub fn generate_pok_bbs_sig_prover_statement_from_param_refs_constant_time(
    params: usize,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    pok_prover_params_ref!(
        params,
        revealed_msgs,
        encode_messages,
        PoKBBSSigProverStmt::new_statement_from_params_ref,
        "PoKBBSSigProverStmt",
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time
    )
}

#[wasm_bindgen(js_name = generatePoKBBSSignatureVerifierStatementFromParamRefs)]
pub fn generate_pok_bbs_sig_verifier_statement_from_param_refs(
    params: usize,
    public_key: usize,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    pok_verifier_params_ref!(
        params,
        public_key,
        revealed_msgs,
        encode_messages,
        PoKBBSSigVerifierStmt,
        "PoKBBSSigVerifierStmt",
        encode_messages_as_js_map_to_fr_btreemap
    )
}

#[wasm_bindgen(js_name = generatePoKBBSSignatureVerifierStatementFromParamRefsNew)]
pub fn generate_pok_bbs_sig_verifier_statement_from_param_refs_new(
    params: usize,
    public_key: usize,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    pok_verifier_params_ref!(
        params,
        public_key,
        revealed_msgs,
        encode_messages,
        PoKBBSSigVerifierStmtNew,
        "PoKBBSSigVerifierStmtNew",
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time
    )
}

#[wasm_bindgen(js_name = generatePoKBBSSignatureVerifierStatementFromParamRefsConstantTime)]
pub fn generate_pok_bbs_sig_verifier_statement_from_param_refs_constant_time(
    params: usize,
    public_key: usize,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    pok_verifier_params_ref!(
        params,
        public_key,
        revealed_msgs,
        encode_messages,
        PoKBBSSigVerifierStmt,
        "PoKBBSSigVerifierStmt",
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time
    )
}

#[wasm_bindgen(js_name = generatePoKBBSPlusSignatureProverStatementFromParamRefs)]
pub fn generate_pok_bbs_plus_sig_prover_statement_from_param_refs(
    params: usize,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    pok_prover_params_ref!(
        params,
        revealed_msgs,
        encode_messages,
        PoKBBSPlusSigProverStmt::new_statement_from_params_ref,
        "PoKBBSPlusSigProverStmt",
        encode_messages_as_js_map_to_fr_btreemap
    )
}

#[wasm_bindgen(js_name = generatePoKBBSPlusSignatureProverStatementFromParamRefsConstantTime)]
pub fn generate_pok_bbs_plus_sig_prover_statement_from_param_refs_constant_time(
    params: usize,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    pok_prover_params_ref!(
        params,
        revealed_msgs,
        encode_messages,
        PoKBBSPlusSigProverStmt::new_statement_from_params_ref,
        "PoKBBSPlusSigProverStmt",
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time
    )
}

#[wasm_bindgen(js_name = generatePoKBBSPlusSignatureVerifierStatementFromParamRefs)]
pub fn generate_pok_bbs_plus_sig_verifier_statement_from_param_refs(
    params: usize,
    public_key: usize,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    pok_verifier_params_ref!(
        params,
        public_key,
        revealed_msgs,
        encode_messages,
        PoKBBSPlusSigVerifierStmt,
        "PoKBBSPlusSigVerifierStmt",
        encode_messages_as_js_map_to_fr_btreemap
    )
}

#[wasm_bindgen(js_name = generatePoKBBSPlusSignatureVerifierStatementFromParamRefsConstantTime)]
pub fn generate_pok_bbs_plus_sig_verifier_statement_from_param_refs_constant_time(
    params: usize,
    public_key: usize,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    pok_verifier_params_ref!(
        params,
        public_key,
        revealed_msgs,
        encode_messages,
        PoKBBSPlusSigVerifierStmt,
        "PoKBBSPlusSigVerifierStmt",
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time
    )
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

#[wasm_bindgen(js_name = generatePoKPSSignatureStatementFromParamRefsConstantTime)]
pub fn generate_pok_ps_sig_statement_from_param_refs_constant_time(
    params: usize,
    public_key: usize,
    revealed_msgs: js_sys::Map,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let msgs = encode_messages_as_js_map_to_fr_btreemap_in_constant_time(&revealed_msgs, false)?;
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
    pok_prover!(
        params,
        revealed_msgs,
        encode_messages,
        BDDT16MACParams,
        PoKOfMACStmt::new_statement_from_params::<Bls12_381>,
        "PoKOfMACStmt",
        encode_messages_as_js_map_to_fr_btreemap
    )
}

#[wasm_bindgen(js_name = generatePoKBDDT16MacStatementConstantTime)]
pub fn generate_pok_bddt16_mac_statement_constant_time(
    params: JsValue,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    pok_prover!(
        params,
        revealed_msgs,
        encode_messages,
        BDDT16MACParams,
        PoKOfMACStmt::new_statement_from_params::<Bls12_381>,
        "PoKOfMACStmt",
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time
    )
}

#[wasm_bindgen(js_name = generatePoKBDDT16MacStatementFromParamRefs)]
pub fn generate_pok_bddt16_mac_statement_from_param_refs(
    params: usize,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    pok_prover_params_ref!(
        params,
        revealed_msgs,
        encode_messages,
        PoKOfMACStmt::new_statement_from_params_ref::<Bls12_381>,
        "PoKOfMACStmt",
        encode_messages_as_js_map_to_fr_btreemap
    )
}

#[wasm_bindgen(js_name = generatePoKBDDT16MacStatementFromParamRefsConstantTime)]
pub fn generate_pok_bddt16_mac_statement_from_param_refs_constant_time(
    params: usize,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    pok_prover_params_ref!(
        params,
        revealed_msgs,
        encode_messages,
        PoKOfMACStmt::new_statement_from_params_ref::<Bls12_381>,
        "PoKOfMACStmt",
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time
    )
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

#[wasm_bindgen(js_name = generatePoKBDDT16MacFullVerifierStatementConstantTime)]
pub fn generate_pok_bddt16_mac_full_verifier_statement_constant_time(
    params: JsValue,
    secret_key: Uint8Array,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let params: BDDT16MACParams = serde_wasm_bindgen::from_value(params)?;
    let sk = obj_from_uint8array!(BDDT16MACSecretKey, secret_key, true, "BDDT16MACSecretKey");
    let msgs =
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time(&revealed_msgs, encode_messages)?;
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

#[wasm_bindgen(js_name = generatePoKBDDT16MacFullVerifierStatementFromParamRefsConstantTime)]
pub fn generate_pok_bddt16_mac_full_verifier_statement_from_param_refs_constant_time(
    params: usize,
    secret_key: Uint8Array,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let sk = obj_from_uint8array!(BDDT16MACSecretKey, secret_key, true, "BDDT16MACSecretKey");
    let msgs =
        encode_messages_as_js_map_to_fr_btreemap_in_constant_time(&revealed_msgs, encode_messages)?;
    let statement =
        PoKOfMACFullVerifierStmt::new_statement_from_params_ref::<Bls12_381>(sk, params, msgs);
    Ok(obj_to_uint8array_uncompressed!(&statement, "PoKOfMACStmt"))
}
