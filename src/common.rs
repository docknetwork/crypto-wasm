use crate::utils::{fr_to_jsvalue, random_bytes, set_panic_hook};
use crate::Fr;
use blake2::Blake2b;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = generateRandomFieldElement)]
pub async fn generate_random_field_element(seed: Option<Vec<u8>>) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let seed = seed.unwrap_or_else(|| random_bytes());
    fr_to_jsvalue(&dock_crypto_utils::hashing_utils::field_elem_from_seed::<
        Fr,
        Blake2b,
    >(&seed, &[]))
}
