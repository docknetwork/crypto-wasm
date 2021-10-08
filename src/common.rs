use crate::utils::{
    field_element_from_u32, fr_from_jsvalue, fr_to_jsvalue, g1_affine_to_jsvalue,
    g2_affine_to_jsvalue, get_seeded_rng, random_bytes, set_panic_hook,
};
use crate::{Fr, G1Proj, G2Proj};
use ark_ec::ProjectiveCurve;
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use blake2::Blake2b;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = generateRandomG1Element)]
pub async fn generate_random_g1_element() -> Result<JsValue, JsValue> {
    set_panic_hook();
    let mut rng = get_seeded_rng();
    let g = G1Proj::rand(&mut rng).into_affine();
    g1_affine_to_jsvalue(&g)
}

#[wasm_bindgen(js_name = generateRandomG2Element)]
pub async fn generate_random_g2_element() -> Result<JsValue, JsValue> {
    set_panic_hook();
    let mut rng = get_seeded_rng();
    let g = G2Proj::rand(&mut rng).into_affine();
    g2_affine_to_jsvalue(&g)
}

#[wasm_bindgen(js_name = generateRandomFieldElement)]
pub async fn generate_random_field_element(seed: Option<Vec<u8>>) -> Result<JsValue, JsValue> {
    set_panic_hook();
    fr_to_jsvalue(&random_ff(seed))
}

#[wasm_bindgen(js_name = generateFieldElementFromNumber)]
pub async fn field_element_from_number(number: u32) -> JsValue {
    set_panic_hook();
    fr_to_jsvalue(&field_element_from_u32(number)).unwrap()
}

#[wasm_bindgen(js_name = generateChallengeFromBytes)]
pub async fn generate_challenge_from_bytes(bytes: Vec<u8>) -> JsValue {
    set_panic_hook();
    fr_jsvalue_from_bytes(&bytes)
}

#[wasm_bindgen(js_name = generateFieldElementFromBytes)]
pub async fn generate_field_element_from_bytes(bytes: Vec<u8>) -> JsValue {
    set_panic_hook();
    fr_jsvalue_from_bytes(&bytes)
}

#[wasm_bindgen(js_name = fieldElementAsBytes)]
pub async fn field_element_as_bytes(
    element: JsValue,
) -> Result<js_sys::Uint8Array, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let f = fr_from_jsvalue(element)?;
    let mut bytes = vec![];
    f.serialize(&mut bytes).map_err(|e| {
        JsValue::from(&format!(
            "Serializing field element to bytes returned error: {:?}",
            e
        ))
    })?;
    Ok(js_sys::Uint8Array::from(bytes.as_slice()))
}

fn fr_jsvalue_from_bytes(bytes: &[u8]) -> JsValue {
    let f = dock_crypto_utils::hashing_utils::field_elem_from_seed::<Fr, Blake2b>(&bytes, &[]);
    fr_to_jsvalue(&f).unwrap()
}

pub fn random_ff(seed: Option<Vec<u8>>) -> Fr {
    let seed = seed.unwrap_or_else(|| random_bytes());
    dock_crypto_utils::hashing_utils::field_elem_from_seed::<Fr, Blake2b>(&seed, &[])
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VerifyResponse {
    pub verified: bool,
    pub error: Option<String>,
}

impl VerifyResponse {
    pub fn validate(&self) {
        assert!(self.verified);
        assert!(self.error.is_none());
    }
}
