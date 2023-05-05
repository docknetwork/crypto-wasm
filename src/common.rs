use crate::{
    utils::{
        self, field_element_from_u64, fr_from_uint8_array, fr_to_jsvalue, fr_to_uint8_array,
        g1_affine_to_uint8_array, g2_affine_to_uint8_array, is_positive_safe_integer,
        js_array_to_fr_vec, js_array_to_g1_affine_vec, js_array_to_g2_affine_vec, random_bytes,
        set_panic_hook,
    },
    Fr, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_serialize::CanonicalSerialize;
use blake2::Blake2b512;
use serde::{Deserialize, Serialize};
use serde_json::from_value;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = encodeMessageForSigning)]
pub fn encode_message_for_signing(message: Vec<u8>) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let fr = utils::encode_message_for_signing(&message);
    fr_to_uint8_array(&fr)
}

#[wasm_bindgen(js_name = encodeMessagesForSigning)]
pub fn encode_messages_for_signing(
    messages: js_sys::Array,
    indices_to_encode: Option<js_sys::Array>,
) -> Result<js_sys::Array, JsValue> {
    use serde_wasm_bindgen::from_value;

    set_panic_hook();
    let encoded = js_sys::Array::new();

    if let Some(indices_to_encode) = indices_to_encode {
        for i in indices_to_encode.values() {
            let index: u32 = from_value(i.unwrap())?;
            if index >= messages.length() {
                return Err(JsValue::from(&format!(
                    "Invalid index {:?} to get message",
                    index
                )));
            }
            let msg: Vec<u8> = from_value(messages.get(index))?;
            let fr = utils::encode_message_for_signing(&msg);
            encoded.push(&fr_to_jsvalue(&fr)?);
        }
    } else {
        for value in messages.values() {
            let msg: Vec<u8> = from_value(value?)?;
            let fr = utils::encode_message_for_signing(&msg);

            encoded.push(&fr_to_jsvalue(&fr)?);
        }
    }

    Ok(encoded)
}

#[wasm_bindgen(js_name = generateRandomG1Element)]
pub fn generate_random_g1_element(seed: Option<Vec<u8>>) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let g = random_g1(seed);
    g1_affine_to_uint8_array(&g)
}

#[wasm_bindgen(js_name = generateRandomG2Element)]
pub fn generate_random_g2_element(seed: Option<Vec<u8>>) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let g = random_g2(seed);
    g2_affine_to_uint8_array(&g)
}

#[wasm_bindgen(js_name = generateRandomFieldElement)]
pub fn generate_random_field_element(seed: Option<Vec<u8>>) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let f = random_ff(seed);
    fr_to_uint8_array(&f)
}

#[wasm_bindgen(js_name = generateFieldElementFromNumber)]
pub fn field_element_from_number(number: js_sys::Number) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    if !is_positive_safe_integer(&number) {
        return Err(JsValue::from(&format!(
            "number should be a safe positive integers but instead found {:?}",
            number
        )));
    }
    fr_to_uint8_array(&field_element_from_u64(number.value_of() as u64))
}

#[wasm_bindgen(js_name = generateChallengeFromBytes)]
pub fn generate_challenge_from_bytes(bytes: Vec<u8>) -> js_sys::Uint8Array {
    set_panic_hook();
    fr_uin8_array_from_bytes_hash(&bytes)
}

/// Hashes given bytes to get the field element thus can accept arbitrary sized bytearray.
#[wasm_bindgen(js_name = generateFieldElementFromBytes)]
pub fn generate_field_element_from_bytes(bytes: Vec<u8>) -> js_sys::Uint8Array {
    set_panic_hook();
    fr_uin8_array_from_bytes_hash(&bytes)
}

#[wasm_bindgen(js_name = fieldElementAsBytes)]
pub fn field_element_as_bytes(
    element: js_sys::Uint8Array,
    element_is_secret: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let f = fr_from_uint8_array(element, element_is_secret)?;
    let mut bytes = vec![];
    f.serialize_compressed(&mut bytes).map_err(|e| {
        JsValue::from(&format!(
            "Serializing field element to bytes returned error: {:?}",
            e
        ))
    })?;
    Ok(js_sys::Uint8Array::from(bytes.as_slice()))
}

/// Create a Pedersen commitment in group G1
#[wasm_bindgen(js_name = pedersenCommitmentG1)]
pub fn pedersen_commitment_g1(
    bases: js_sys::Array,
    messages: js_sys::Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let bases = js_array_to_g1_affine_vec(&bases)?;
    let messages = js_array_to_fr_vec(&messages)?;
    let comm = G1Projective::msm_unchecked(&bases, &messages).into_affine();
    g1_affine_to_uint8_array(&comm)
}

/// Create a Pedersen commitment in group G2
#[wasm_bindgen(js_name = pedersenCommitmentG2)]
pub fn pedersen_commitment_g2(
    bases: js_sys::Array,
    messages: js_sys::Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let bases = js_array_to_g2_affine_vec(&bases)?;
    let messages = js_array_to_fr_vec(&messages)?;
    let comm = G2Projective::msm_unchecked(&bases, &messages).into_affine();
    g2_affine_to_uint8_array(&comm)
}

fn fr_uin8_array_from_bytes_hash(bytes: &[u8]) -> js_sys::Uint8Array {
    let f = dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr::<Fr, Blake2b512>(bytes);
    fr_to_uint8_array(&f).unwrap()
}

pub fn random_ff(seed: Option<Vec<u8>>) -> Fr {
    let seed = seed.unwrap_or_else(random_bytes);
    dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr::<Fr, Blake2b512>(&seed)
}

pub fn random_g1(seed: Option<Vec<u8>>) -> G1Affine {
    let seed = seed.unwrap_or_else(random_bytes);
    dock_crypto_utils::hashing_utils::affine_group_elem_from_try_and_incr::<G1Affine, Blake2b512>(
        &seed,
    )
}

pub fn random_g2(seed: Option<Vec<u8>>) -> G2Affine {
    let seed = seed.unwrap_or_else(random_bytes);
    dock_crypto_utils::hashing_utils::affine_group_elem_from_try_and_incr::<G2Affine, Blake2b512>(
        &seed,
    )
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

#[macro_export]
macro_rules! adapt_params {
    ($params:ident, $generating_label: ident, $new_count: ident, $sig_type: ident, $sig_group: ident) => {{
        let mut params: $sig_type = serde_wasm_bindgen::from_value($params)?;
        let current_count = params.supported_message_count();
        if current_count > $new_count {
            for _ in 0..(current_count - $new_count) {
                params.h.pop();
            }
        } else if current_count < $new_count {
            let generating_label = $generating_label.to_vec();
            for i in current_count + 1..=$new_count {
                let h = affine_group_elem_from_try_and_incr::<$sig_group, Blake2b512>(
                    &concat_slices!(&generating_label, b" : h_", i.to_le_bytes()),
                );
                params.h.push(h);
            }
        }
        serde_wasm_bindgen::to_value(&params).map_err(|e| JsValue::from(e))
    }};
}
