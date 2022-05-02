use ark_bls12_381::Bls12_381;
use ark_serialize::CanonicalSerialize;
use proof_system::prelude::generate_snark_srs_bound_check;

use crate::utils::{get_seeded_rng, set_panic_hook};
use wasm_bindgen::prelude::*;

/// Setup snark and generate compressed or uncompressed SNARK proving key
#[wasm_bindgen(js_name = boundCheckSnarkSetup)]
pub fn bound_check_snark_setup(return_uncompressed: bool) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let mut rng = get_seeded_rng();
    let snark_pk = generate_snark_srs_bound_check::<Bls12_381, _>(&mut rng).map_err(|e| {
        JsValue::from(&format!(
            "SNARK setup for bound check returned error: {:?}",
            e
        ))
    })?;
    Ok(if return_uncompressed {
        obj_to_uint8array_unchecked!(&snark_pk, "LegoProvingKey")
    } else {
        obj_to_uint8array!(&snark_pk, "LegoProvingKey")
    })
}
