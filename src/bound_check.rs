use crate::Fr;
use ark_bls12_381::Bls12_381;
use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use proof_system::prelude::bound_check::generate_snark_srs_bound_check;
use proof_system::statement::LegoProvingKey;

use crate::utils::{get_seeded_rng, set_panic_hook};
use serde_wasm_bindgen::*;
use wasm_bindgen::prelude::*;

pub(crate) type BoundCheckSnarkPk = LegoProvingKey<Bls12_381>;

#[wasm_bindgen(js_name = boundCheckSnarkSetup)]
pub fn bound_check_snark_setup() -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let mut rng = get_seeded_rng();
    let snark_pk = generate_snark_srs_bound_check::<Bls12_381, _>(&mut rng).map_err(|e| {
        JsValue::from(&format!(
            "SNARK setup for bound check returned error: {:?}",
            e
        ))
    })?;
    Ok(obj_to_uint8array!(&snark_pk, "BoundCheckSnarkPk"))
}

#[wasm_bindgen(js_name = boundCheckDecompressSnarkPk)]
pub fn bound_check_decompress_snark_pk(
    snark_pk: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    let snark_pk = obj_from_uint8array!(BoundCheckSnarkPk, snark_pk, "BoundCheckSnarkPk");
    Ok(obj_to_uint8array_unchecked!(&snark_pk, "BoundCheckSnarkPk"))
}

/// Return the uncompressed SNARK verification key from compressed proving key
#[wasm_bindgen(js_name = boundCheckGetSnarkVkFromPk)]
pub fn bound_check_snark_vk_from_pk(
    snark_pk: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    let snark_pk = obj_from_uint8array!(BoundCheckSnarkPk, snark_pk, "BoundCheckSnarkPk");
    Ok(obj_to_uint8array_unchecked!(
        &snark_pk.vk,
        "BoundCheckSnarkVk"
    ))
}
