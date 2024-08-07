use ark_bls12_381::Bls12_381;
use dock_crypto_utils::commitment::PedersenCommitmentKey;
use proof_system::setup_params::SetupParams;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use crate::{
    accumulator::{
        common::{AccumPk, AccumSetupParams},
        vb_accumulator::{MembershipPrk, NonMembershipPrk},
    },
    bbs::BBSSigParams,
    bbs_plus::{BBSPlusPublicKeyG2, BBSPlusSigParamsG1},
    bddt16_kvac::BDDT16MACParams,
    bound_check::{BppSetupParams, SmcParams, SmcParamsAndSk},
    legosnark::{LegoProvingKey, LegoVerifyingKey},
    ps::{PSPublicKey, PSSignatureParams},
    r1cs::gen_r1cs,
    saver::{ChunkedCommGens, EncGens, SaverEk, SaverSnarkPk, SaverSnarkVk},
    utils::{
        js_array_to_fr_vec, js_array_to_g1_affine_vec, js_array_to_g2_affine_vec, set_panic_hook,
    },
    G1Affine,
};

// All `SetupParams`s are returned in their uncompressed form as they are generated by the same party using
// them unlike signature params, public keys, proofs, etc

#[wasm_bindgen(js_name = generateSetupParamForBBSPlusSignatureParametersG1)]
pub fn generate_setup_param_for_bbs_plus_sig_params_g1(
    params: JsValue,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let params: BBSPlusSigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    Ok(obj_to_uint8array_uncompressed!(
        &SetupParams::<Bls12_381>::BBSPlusSignatureParams(params)
    ))
}

#[wasm_bindgen(js_name = generateSetupParamForBBSPlusPublicKeyG2)]
pub fn generate_setup_param_for_bbs_plus_public_key(
    public_key: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let pk = obj_from_uint8array!(BBSPlusPublicKeyG2, public_key, false, "BBSPlusPublicKeyG2");
    Ok(obj_to_uint8array_uncompressed!(
        &SetupParams::<Bls12_381>::BBSPlusPublicKey(pk)
    ))
}

#[wasm_bindgen(js_name = generateSetupParamForPSPublicKey)]
pub fn generate_setup_param_for_ps_public_key(
    public_key: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let pk = obj_from_uint8array!(PSPublicKey, public_key, false, "PSPublicKey");
    Ok(obj_to_uint8array_uncompressed!(
        &SetupParams::<Bls12_381>::PSSignaturePublicKey(pk)
    ))
}

#[wasm_bindgen(js_name = generateSetupParamForBBSSignatureParameters)]
pub fn generate_setup_param_for_bbs_sig_params(
    params: JsValue,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let params: BBSSigParams = serde_wasm_bindgen::from_value(params)?;

    Ok(obj_to_uint8array_uncompressed!(
        &SetupParams::<Bls12_381>::BBSSignatureParams23(params)
    ))
}

#[wasm_bindgen(js_name = generateSetupParamForPSSignatureParameters)]
pub fn generate_setup_param_for_ps_sig_params(
    params: JsValue,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let params: PSSignatureParams = serde_wasm_bindgen::from_value(params)?;

    Ok(obj_to_uint8array_uncompressed!(
        &SetupParams::<Bls12_381>::PSSignatureParams(params)
    ))
}

#[wasm_bindgen(js_name = generateSetupParamForVbAccumulatorParams)]
pub fn generate_setup_param_for_vb_accumulator_params(
    params: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let params = obj_from_uint8array!(AccumSetupParams, params, false, "AccumSetupParams");
    Ok(obj_to_uint8array_uncompressed!(
        &SetupParams::<Bls12_381>::VbAccumulatorParams(params)
    ))
}

#[wasm_bindgen(js_name = generateSetupParamForVbAccumulatorPublicKey)]
pub fn generate_setup_param_for_vb_accumulator_public_key(
    public_key: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let pk = obj_from_uint8array!(AccumPk, public_key, false, "AccumPk");
    Ok(obj_to_uint8array_uncompressed!(
        &SetupParams::<Bls12_381>::VbAccumulatorPublicKey(pk)
    ))
}

#[wasm_bindgen(js_name = generateSetupParamForVbAccumulatorMemProvingKey)]
pub fn generate_setup_param_for_vb_accumulator_mem_proving_key(
    key: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let k = obj_from_uint8array!(MembershipPrk, key, false, "MembershipPrk");
    Ok(obj_to_uint8array_uncompressed!(
        &SetupParams::<Bls12_381>::VbAccumulatorMemProvingKey(k)
    ))
}

#[wasm_bindgen(js_name = generateSetupParamForVbAccumulatorNonMemProvingKey)]
pub fn generate_setup_param_for_vb_accumulator_non_mem_proving_key(
    key: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let k = obj_from_uint8array!(NonMembershipPrk, key, false, "NonMembershipPrk");
    Ok(obj_to_uint8array_uncompressed!(
        &SetupParams::<Bls12_381>::VbAccumulatorNonMemProvingKey(k)
    ))
}

#[wasm_bindgen(js_name = generateSetupParamForPedersenCommitmentKeyG1)]
pub fn generate_setup_param_for_pedersen_commitment_key_g1(
    commitment_key: js_sys::Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let k = js_array_to_g1_affine_vec(&commitment_key)?;
    Ok(obj_to_uint8array_uncompressed!(
        &SetupParams::<Bls12_381>::PedersenCommitmentKey(k)
    ))
}

#[wasm_bindgen(js_name = generateSetupParamForPedersenCommitmentKeyG2)]
pub fn generate_setup_param_for_pedersen_commitment_key_g2(
    commitment_key: js_sys::Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let k = js_array_to_g2_affine_vec(&commitment_key)?;
    Ok(obj_to_uint8array_uncompressed!(
        &SetupParams::<Bls12_381>::PedersenCommitmentKeyG2(k)
    ))
}

/// If `uncompressed` is true, expects the encryption generators to be in uncompressed form else
/// they should be compressed.
#[wasm_bindgen(js_name = generateSetupParamForSaverEncryptionGens)]
pub fn generate_setup_param_for_saver_encryption_gens(
    enc_gens: js_sys::Uint8Array,
    uncompressed: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let enc_gens = if uncompressed {
        obj_from_uint8array_uncompressed!(EncGens, enc_gens, "SaverEncryptionGens")
    } else {
        obj_from_uint8array!(EncGens, enc_gens, false, "SaverEncryptionGens")
    };
    Ok(obj_to_uint8array_uncompressed!(
        &SetupParams::<Bls12_381>::SaverEncryptionGens(enc_gens)
    ))
}

/// If `uncompressed` is true, expects the commitment generators to be in uncompressed form else
/// they should be compressed.
#[wasm_bindgen(js_name = generateSetupParamForSaverCommitmentGens)]
pub fn generate_setup_param_for_saver_commitment_gens(
    comm_gens: js_sys::Uint8Array,
    uncompressed: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let comm_gens = if uncompressed {
        obj_from_uint8array_uncompressed!(ChunkedCommGens, comm_gens, "SaverCommitmentGens")
    } else {
        obj_from_uint8array!(ChunkedCommGens, comm_gens, false, "SaverCommitmentGens")
    };
    Ok(obj_to_uint8array_uncompressed!(
        &SetupParams::<Bls12_381>::SaverCommitmentGens(comm_gens)
    ))
}

/// If `uncompressed` is true, expects the encryption key to be in uncompressed form else
/// it should be compressed.
#[wasm_bindgen(js_name = generateSetupParamForSaverEncryptionKey)]
pub fn generate_setup_param_for_saver_encryption_key(
    key: js_sys::Uint8Array,
    uncompressed: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let key = if uncompressed {
        obj_from_uint8array_uncompressed!(SaverEk, key, "SaverEncryptionKey")
    } else {
        obj_from_uint8array!(SaverEk, key, false, "SaverEncryptionKey")
    };
    Ok(obj_to_uint8array_uncompressed!(
        &SetupParams::<Bls12_381>::SaverEncryptionKey(key)
    ))
}

/// If `uncompressed` is true, expects the snark proving key to be in uncompressed form else
/// it should be compressed.
#[wasm_bindgen(js_name = generateSetupParamForSaverProvingKey)]
pub fn generate_setup_param_for_saver_proving_key(
    key: js_sys::Uint8Array,
    uncompressed: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let key = if uncompressed {
        obj_from_uint8array_uncompressed!(SaverSnarkPk, key, "SaverProvingKey")
    } else {
        obj_from_uint8array!(SaverSnarkPk, key, false, "SaverProvingKey")
    };
    Ok(obj_to_uint8array_uncompressed!(
        &SetupParams::<Bls12_381>::SaverProvingKey(key)
    ))
}

/// If `uncompressed` is true, expects the snark verifying key to be in uncompressed form else
/// it should be compressed.
#[wasm_bindgen(js_name = generateSetupParamForSaverVerifyingKey)]
pub fn generate_setup_param_for_saver_verifying_key(
    key: js_sys::Uint8Array,
    uncompressed: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let key = if uncompressed {
        obj_from_uint8array_uncompressed!(SaverSnarkVk, key, "SaverVerifyingKey")
    } else {
        obj_from_uint8array!(SaverSnarkVk, key, false, "SaverVerifyingKey")
    };
    Ok(obj_to_uint8array_uncompressed!(
        &SetupParams::<Bls12_381>::SaverVerifyingKey(key)
    ))
}

/// If `uncompressed` is true, expects the legosnark proving key to be in uncompressed form else
/// it should be compressed.
#[wasm_bindgen(js_name = generateSetupParamForLegoProvingKey)]
pub fn generate_setup_param_for_lego_proving_key(
    key: js_sys::Uint8Array,
    uncompressed: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let key = if uncompressed {
        obj_from_uint8array_uncompressed!(LegoProvingKey, key, "LegoSnarkProvingKey")
    } else {
        obj_from_uint8array!(LegoProvingKey, key, false, "LegoSnarkProvingKey")
    };
    Ok(obj_to_uint8array_uncompressed!(
        &SetupParams::<Bls12_381>::LegoSnarkProvingKey(key)
    ))
}

/// If `uncompressed` is true, expects the legosnark verifying key to be in uncompressed form else
/// it should be compressed.
#[wasm_bindgen(js_name = generateSetupParamForLegoVerifyingKey)]
pub fn generate_setup_param_for_lego_verifying_key(
    key: js_sys::Uint8Array,
    uncompressed: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let key = if uncompressed {
        obj_from_uint8array_uncompressed!(LegoVerifyingKey, key, "LegoSnarkVerifyingKey")
    } else {
        obj_from_uint8array!(LegoVerifyingKey, key, false, "LegoSnarkVerifyingKey")
    };
    Ok(obj_to_uint8array_uncompressed!(
        &SetupParams::<Bls12_381>::LegoSnarkVerifyingKey(key)
    ))
}

#[wasm_bindgen(js_name = generateSetupParamForR1CS)]
pub fn generate_setup_param_for_r1cs(
    curve_name: &str,
    num_public: u32,
    num_private: u32,
    constraints: js_sys::Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    let r = gen_r1cs(curve_name, num_public, num_private, constraints)?;
    Ok(obj_to_uint8array_uncompressed!(
        &SetupParams::<Bls12_381>::R1CS(r)
    ))
}

#[wasm_bindgen(js_name = generateSetupParamForBytes)]
pub fn generate_setup_param_for_bytes(
    bytes: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    Ok(obj_to_uint8array_uncompressed!(
        &SetupParams::<Bls12_381>::Bytes(bytes.to_vec())
    ))
}

#[wasm_bindgen(js_name = generateSetupParamForFieldElemVec)]
pub fn generate_setup_param_for_field_elem_vec(
    arr: js_sys::Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    Ok(obj_to_uint8array_uncompressed!(
        &SetupParams::<Bls12_381>::FieldElemVec(js_array_to_fr_vec(&arr)?)
    ))
}

#[wasm_bindgen(js_name = generateSetupParamForBppParams)]
pub fn generate_setup_param_for_bpp_params(
    params: js_sys::Uint8Array,
    uncompressed: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let params = if uncompressed {
        obj_from_uint8array_uncompressed!(BppSetupParams, params, "Bulletproofs++SetupParams")
    } else {
        obj_from_uint8array!(BppSetupParams, params, false, "Bulletproofs++SetupParams")
    };
    Ok(obj_to_uint8array_uncompressed!(
        &SetupParams::<Bls12_381>::BppSetupParams(params)
    ))
}

#[wasm_bindgen(js_name = generateSetupParamForSmcParams)]
pub fn generate_setup_param_for_smc_params(
    params: js_sys::Uint8Array,
    uncompressed: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let params = if uncompressed {
        obj_from_uint8array_uncompressed!(SmcParams, params, "SmcParamsAndCommitmentKey")
    } else {
        obj_from_uint8array!(SmcParams, params, false, "SmcParamsAndCommitmentKey")
    };
    Ok(obj_to_uint8array_uncompressed!(
        &SetupParams::<Bls12_381>::SmcParamsAndCommKey(params)
    ))
}

#[wasm_bindgen(js_name = generateSetupParamForSmcParamsAndSk)]
pub fn generate_setup_param_for_smc_params_and_sk(
    params: js_sys::Uint8Array,
    uncompressed: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let params = if uncompressed {
        obj_from_uint8array_uncompressed!(
            SmcParamsAndSk,
            params,
            "SmcParamsAndCommitmentKeyAndSecretKey"
        )
    } else {
        obj_from_uint8array!(
            SmcParamsAndSk,
            params,
            false,
            "SmcParamsAndCommitmentKeyAndSecretKey"
        )
    };
    Ok(obj_to_uint8array_uncompressed!(
        &SetupParams::<Bls12_381>::SmcParamsAndCommKeyAndSk(params)
    ))
}

#[wasm_bindgen(js_name = generateSetupParamForCommitmentKey)]
pub fn generate_setup_param_for_commitment_key(
    comm_key: js_sys::Uint8Array,
    uncompressed: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let comm_key = if uncompressed {
        obj_from_uint8array_uncompressed!(
            PedersenCommitmentKey<G1Affine>,
            comm_key,
            "CommitmentKey"
        )
    } else {
        obj_from_uint8array!(
            PedersenCommitmentKey<G1Affine>,
            comm_key,
            false,
            "CommitmentKey"
        )
    };
    Ok(obj_to_uint8array_uncompressed!(
        &SetupParams::<Bls12_381>::CommitmentKey(comm_key)
    ))
}

#[wasm_bindgen(js_name = generateSetupParamForBDDT16MacParameters)]
pub fn generate_setup_param_for_bddt16_mac_params(
    params: JsValue,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let params: BDDT16MACParams = serde_wasm_bindgen::from_value(params)?;
    Ok(obj_to_uint8array_uncompressed!(
        &SetupParams::<Bls12_381>::BBDT16MACParams(params)
    ))
}
