use ark_bls12_381::Bls12_381;
use blake2::Blake2b512;
use bulletproofs_plus_plus::prelude::SetupParams;
use js_sys::Uint8Array;
use proof_system::prelude::{
    bound_check_smc::SmcParamsAndCommitmentKey, // ← plain
    bound_check_smc_with_kv::{
        SmcParamsKVAndCommitmentKey, // ← NEW
        SmcParamsKVAndCommitmentKeyAndSecretKey,
    },
    generate_snark_srs_bound_check,
};

use crate::{
    utils::{get_seeded_rng, set_panic_hook},
    G1Affine,
};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

pub(crate) type BppSetupParams = SetupParams<G1Affine>;
pub(crate) type SmcParams = SmcParamsAndCommitmentKey<Bls12_381>;
pub(crate) type SmcParamsKV = SmcParamsKVAndCommitmentKey<G1Affine>;
pub(crate) type SmcParamsAndSk = SmcParamsKVAndCommitmentKeyAndSecretKey<G1Affine>;

/// Setup snark for proving bounds and generate compressed or uncompressed SNARK proving key
#[wasm_bindgen(js_name = boundCheckSnarkSetup)]
pub fn bound_check_snark_setup(return_uncompressed: bool) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let mut rng = get_seeded_rng();
    let snark_pk = generate_snark_srs_bound_check::<Bls12_381, _>(&mut rng).map_err(|e| {
        JsValue::from(&format!(
            "SNARK setup for bound check returned error: {:?}",
            e
        ))
    })?;
    Ok(if return_uncompressed {
        obj_to_uint8array_uncompressed!(&snark_pk, "LegoProvingKey")
    } else {
        obj_to_uint8array!(&snark_pk, false, "LegoProvingKey")
    })
}

/// Create setup params for Bulletproofs++ range proofs
#[wasm_bindgen(js_name = boundCheckBppSetup)]
pub fn bound_check_bpp_setup(
    label: Vec<u8>,
    base: u16,
    value_bit_size: u16,
    return_uncompressed: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let bpp_setup_params = BppSetupParams::new_for_arbitrary_range_proof::<Blake2b512>(
        &label,
        base,
        value_bit_size,
        1,
    );
    Ok(if return_uncompressed {
        obj_to_uint8array_uncompressed!(&bpp_setup_params, "Bulletproofs++SetupParams")
    } else {
        obj_to_uint8array!(&bpp_setup_params, false, "Bulletproofs++SetupParams")
    })
}

/// Create setup params for set-membership check based range proofs
#[wasm_bindgen(js_name = boundCheckSmcSetup)]
pub fn bound_check_smc_setup(
    label: Vec<u8>,
    base: u16,
    return_uncompressed: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let mut rng = get_seeded_rng();
    let (smc_setup_params, _) = SmcParams::new::<_, Blake2b512>(&mut rng, &label, base);
    smc_setup_params
        .verify()
        .map_err(|e| JsValue::from(&format!("Param validation failed with error: {:?}", e)))?;
    Ok(if return_uncompressed {
        obj_to_uint8array_uncompressed!(&smc_setup_params, "SmcParamsAndCommitmentKey")
    } else {
        obj_to_uint8array!(&smc_setup_params, false, "SmcParamsAndCommitmentKey")
    })
}

/// Create setup params for set-membership check based range proofs supporting keyed-verification
#[wasm_bindgen(js_name = boundCheckSmcWithKVSetup)]
pub fn bound_check_smc_with_kv_setup(
    label: Vec<u8>,
    base: u16,
    return_uncompressed: bool,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    let mut rng = get_seeded_rng();
    let (smc_setup_params, sk) = SmcParamsKV::new::<_, Blake2b512>(&mut rng, &label, base);
    let setup = js_sys::Array::new();
    let smc_params = if return_uncompressed {
        obj_to_uint8array_uncompressed!(&smc_setup_params, "SmcParamsAndCommitmentKey")
    } else {
        obj_to_uint8array!(&smc_setup_params, false, "SmcParamsAndCommitmentKey")
    };
    let smc_setup_params_with_sk = SmcParamsAndSk {
        params_and_comm_key: smc_setup_params,
        sk,
    };
    let smc_params_with_sk = if return_uncompressed {
        obj_to_uint8array_uncompressed!(
            &smc_setup_params_with_sk,
            "SmcParamsAndCommitmentKeyAndSecretKey"
        )
    } else {
        obj_to_uint8array!(
            &smc_setup_params_with_sk,
            false,
            "SmcParamsAndCommitmentKeyAndSecretKey"
        )
    };
    setup.push(&smc_params);
    setup.push(&smc_params_with_sk);
    Ok(setup)
}

/// Decompress EC points in Bulletproofs++ setup
#[wasm_bindgen(js_name = decompressBppParams)]
pub fn decompress_bpp_params(params: Uint8Array) -> Result<Uint8Array, JsValue> {
    let params = obj_from_uint8array!(BppSetupParams, params, false, "Bulletproofs++SetupParams");
    Ok(obj_to_uint8array_uncompressed!(
        &params,
        "Bulletproofs++SetupParams"
    ))
}

/// Decompress EC points in set-membership based range proof
#[wasm_bindgen(js_name = decompressSmcParams)]
pub fn decompress_smc_params(params: Uint8Array) -> Result<Uint8Array, JsValue> {
    let params = obj_from_uint8array!(SmcParams, params, false, "SmcParamsAndCommitmentKey");
    Ok(obj_to_uint8array_uncompressed!(
        &params,
        "SmcParamsAndCommitmentKey"
    ))
}

#[wasm_bindgen(js_name = decompressSmcParamsAndSk)]
pub fn decompress_smc_params_and_sk(params: Uint8Array) -> Result<Uint8Array, JsValue> {
    let params = obj_from_uint8array!(
        SmcParamsAndSk,
        params,
        false,
        "SmcParamsAndCommitmentKeyAndSecretKey"
    );
    Ok(obj_to_uint8array_uncompressed!(
        &params,
        "SmcParamsAndCommitmentKeyAndSecretKey"
    ))
}
