use ark_bls12_381::Bls12_381;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use proof_system::prelude::bound_check_legogroth16::{ProvingKey, VerifyingKey};

pub(crate) type LegoProvingKey = ProvingKey<Bls12_381>;
pub(crate) type LegoVerifyingKey = VerifyingKey<Bls12_381>;

/// Takes a compressed proving key for Legosnark and return the uncompressed proving key
#[wasm_bindgen(js_name = legosnarkDecompressPk)]
pub fn legosnark_decompress_pk(
    snark_pk: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    let snark_pk = obj_from_uint8array!(LegoProvingKey, snark_pk, false, "LegoProvingKey");
    Ok(obj_to_uint8array_unchecked!(&snark_pk, "LegoProvingKey"))
}

/// Return the compressed or uncompressed SNARK verification key from compressed proving key
#[wasm_bindgen(js_name = legosnarkVkFromPk)]
pub fn legosnark_vk_from_pk(
    snark_pk: js_sys::Uint8Array,
    return_uncompressed: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    let snark_pk = obj_from_uint8array!(LegoProvingKey, snark_pk, false, "LegoProvingKey");
    Ok(if return_uncompressed {
        obj_to_uint8array_unchecked!(&snark_pk.vk, "LegoVerifyingKey")
    } else {
        obj_to_uint8array!(&snark_pk.vk, false, "LegoVerifyingKey")
    })
}

/// Takes a compressed verifying key for Legosnark and return the uncompressed verifying key
#[wasm_bindgen(js_name = legosnarkDecompressVk)]
pub fn legosnark_decompress_vk(
    snark_vk: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    let snark_vk = obj_from_uint8array!(LegoVerifyingKey, snark_vk, false, "LegoVerifyingKey");
    Ok(obj_to_uint8array_unchecked!(&snark_vk, "LegoVerifyingKey"))
}
