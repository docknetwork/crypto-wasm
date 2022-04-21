use ark_bls12_381::Bls12_381;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use proof_system::setup_params::SetupParams;
use wasm_bindgen::prelude::*;

use crate::accumulator::{AccumPk, AccumSetupParams, MembershipPrk, NonMembershipPrk};
use crate::bbs_plus::{BBSPlusPkG2, SigParamsG1};
use crate::legosnark::{LegoProvingKey, LegoVerifyingKey};
use crate::saver::{ChunkedCommGens, EncGens, SaverEk, SaverSnarkPk, SaverSnarkVk};
use crate::utils::{js_array_to_g1_affine_vec, js_array_to_g2_affine_vec, set_panic_hook};
use crate::{G1Affine, G2Affine};

#[wasm_bindgen(js_name = generateSetupParamForBBSSignatureParametersG1)]
pub fn generate_setup_param_for_bbs_sig_params_g1(
    params: JsValue,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    Ok(obj_to_uint8array_unchecked!(&SetupParams::<
        Bls12_381,
        G1Affine,
    >::BBSPlusSignatureParams(
        params
    )))
}

#[wasm_bindgen(js_name = generateSetupParamForBBSPublicKeyG2)]
pub fn generate_setup_param_for_bbs_public_key_g2(
    public_key: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let pk = obj_from_uint8array!(BBSPlusPkG2, public_key, "BBSPlusPkG2");
    Ok(obj_to_uint8array_unchecked!(&SetupParams::<
        Bls12_381,
        G2Affine,
    >::BBSPlusPublicKey(pk)))
}

#[wasm_bindgen(js_name = generateSetupParamForVbAccumulatorParams)]
pub fn generate_setup_param_for_vb_accumulator_params(
    params: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let params = obj_from_uint8array!(AccumSetupParams, params, "AccumSetupParams");
    Ok(obj_to_uint8array_unchecked!(&SetupParams::<
        Bls12_381,
        G1Affine,
    >::VbAccumulatorParams(
        params
    )))
}

#[wasm_bindgen(js_name = generateSetupParamForVbAccumulatorPublicKey)]
pub fn generate_setup_param_for_vb_accumulator_public_key(
    public_key: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let pk = obj_from_uint8array!(AccumPk, public_key, "AccumPk");
    Ok(obj_to_uint8array_unchecked!(&SetupParams::<
        Bls12_381,
        G2Affine,
    >::VbAccumulatorPublicKey(
        pk
    )))
}

#[wasm_bindgen(js_name = generateSetupParamForVbAccumulatorMemProvingKey)]
pub fn generate_setup_param_for_vb_accumulator_mem_proving_key(
    key: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let k = obj_from_uint8array!(MembershipPrk, key, "MembershipPrk");
    Ok(obj_to_uint8array_unchecked!(&SetupParams::<
        Bls12_381,
        G1Affine,
    >::VbAccumulatorMemProvingKey(
        k
    )))
}

#[wasm_bindgen(js_name = generateSetupParamForVbAccumulatorNonMemProvingKey)]
pub fn generate_setup_param_for_vb_accumulator_non_mem_proving_key(
    key: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let k = obj_from_uint8array!(NonMembershipPrk, key, "NonMembershipPrk");
    Ok(obj_to_uint8array_unchecked!(&SetupParams::<
        Bls12_381,
        G1Affine,
    >::VbAccumulatorNonMemProvingKey(
        k
    )))
}

#[wasm_bindgen(js_name = generateSetupParamForPedersenCommitmentKeyG1)]
pub fn generate_setup_param_for_pedersen_commitment_key_g1(
    commitment_key: js_sys::Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let k = js_array_to_g1_affine_vec(&commitment_key)?;
    Ok(obj_to_uint8array_unchecked!(&SetupParams::<
        Bls12_381,
        G1Affine,
    >::PedersenCommitmentKey(
        k
    )))
}

#[wasm_bindgen(js_name = generateSetupParamForPedersenCommitmentKeyG2)]
pub fn generate_setup_param_for_pedersen_commitment_key_g2(
    commitment_key: js_sys::Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let k = js_array_to_g2_affine_vec(&commitment_key)?;
    Ok(obj_to_uint8array_unchecked!(&SetupParams::<
        Bls12_381,
        G2Affine,
    >::PedersenCommitmentKey(
        k
    )))
}

#[wasm_bindgen(js_name = generateSetupParamForSaverEncryptionGens)]
pub fn generate_setup_param_for_saver_encryption_gens(
    enc_gens: js_sys::Uint8Array,
    uncompressed: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let enc_gens = if uncompressed {
        obj_from_uint8array_unchecked!(EncGens, enc_gens, "SaverEncryptionGens")
    } else {
        obj_from_uint8array!(EncGens, enc_gens, "SaverEncryptionGens")
    };
    Ok(obj_to_uint8array_unchecked!(&SetupParams::<
        Bls12_381,
        G1Affine,
    >::SaverEncryptionGens(
        enc_gens
    )))
}

#[wasm_bindgen(js_name = generateSetupParamForSaverCommitmentGens)]
pub fn generate_setup_param_for_saver_commitment_gens(
    comm_gens: js_sys::Uint8Array,
    uncompressed: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let comm_gens = if uncompressed {
        obj_from_uint8array_unchecked!(ChunkedCommGens, comm_gens, "SaverCommitmentGens")
    } else {
        obj_from_uint8array!(ChunkedCommGens, comm_gens, "SaverCommitmentGens")
    };
    Ok(obj_to_uint8array_unchecked!(&SetupParams::<
        Bls12_381,
        G1Affine,
    >::SaverCommitmentGens(
        comm_gens
    )))
}

#[wasm_bindgen(js_name = generateSetupParamForSaverEncryptionKey)]
pub fn generate_setup_param_for_saver_encryption_key(
    key: js_sys::Uint8Array,
    uncompressed: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let key = if uncompressed {
        obj_from_uint8array_unchecked!(SaverEk, key, "SaverEncryptionKey")
    } else {
        obj_from_uint8array!(SaverEk, key, "SaverEncryptionKey")
    };
    Ok(obj_to_uint8array_unchecked!(&SetupParams::<
        Bls12_381,
        G1Affine,
    >::SaverEncryptionKey(key)))
}

#[wasm_bindgen(js_name = generateSetupParamForSaverProvingKey)]
pub fn generate_setup_param_for_saver_proving_key(
    key: js_sys::Uint8Array,
    uncompressed: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let key = if uncompressed {
        obj_from_uint8array_unchecked!(SaverSnarkPk, key, "SaverProvingKey")
    } else {
        obj_from_uint8array!(SaverSnarkPk, key, "SaverProvingKey")
    };
    Ok(obj_to_uint8array_unchecked!(&SetupParams::<
        Bls12_381,
        G1Affine,
    >::SaverProvingKey(key)))
}

#[wasm_bindgen(js_name = generateSetupParamForSaverVerifyingKey)]
pub fn generate_setup_param_for_saver_verifying_key(
    key: js_sys::Uint8Array,
    uncompressed: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let key = if uncompressed {
        obj_from_uint8array_unchecked!(SaverSnarkVk, key, "SaverVerifyingKey")
    } else {
        obj_from_uint8array!(SaverSnarkVk, key, "SaverVerifyingKey")
    };
    Ok(obj_to_uint8array_unchecked!(&SetupParams::<
        Bls12_381,
        G1Affine,
    >::SaverVerifyingKey(key)))
}

#[wasm_bindgen(js_name = generateSetupParamForLegoProvingKey)]
pub fn generate_setup_param_for_lego_proving_key(
    key: js_sys::Uint8Array,
    uncompressed: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let key = if uncompressed {
        obj_from_uint8array_unchecked!(LegoProvingKey, key, "LegoSnarkProvingKey")
    } else {
        obj_from_uint8array!(LegoProvingKey, key, "LegoSnarkProvingKey")
    };
    Ok(obj_to_uint8array_unchecked!(&SetupParams::<
        Bls12_381,
        G1Affine,
    >::LegoSnarkProvingKey(
        key
    )))
}

#[wasm_bindgen(js_name = generateSetupParamForLegoVerifyingKey)]
pub fn generate_setup_param_for_lego_verifying_key(
    key: js_sys::Uint8Array,
    uncompressed: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let key = if uncompressed {
        obj_from_uint8array_unchecked!(LegoVerifyingKey, key, "LegoSnarkVerifyingKey")
    } else {
        obj_from_uint8array!(LegoVerifyingKey, key, "LegoSnarkVerifyingKey")
    };
    Ok(obj_to_uint8array_unchecked!(&SetupParams::<
        Bls12_381,
        G1Affine,
    >::LegoSnarkVerifyingKey(
        key
    )))
}