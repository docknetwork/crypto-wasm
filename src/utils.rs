/*
 * Copyright 2020 - MATTR Limited
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::{Fr, G1Affine, G2Affine};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::collections::BTreeMap;
use ark_std::rand::prelude::{RngCore, SeedableRng, StdRng};
use blake2::Blake2b;
use wasm_bindgen::prelude::*;

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    {
        console_error_panic_hook::set_once();
    }
}

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(s: &str);
    // The `console.log` is quite polymorphic, so we can bind it with multiple
    // signatures. Note that we need to use `js_name` to ensure we always call
    // `log` in JS.
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    pub fn log_u32(a: u32);
    // Multiple arguments too!
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    pub fn log_many(a: &str, b: &str);
}

#[macro_export]
macro_rules! console_log {
    // Note that this is using the `log` function
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

pub fn fr_to_jsvalue(elem: &Fr) -> Result<JsValue, JsValue> {
    let mut bytes = vec![];
    elem.serialize(&mut bytes).map_err(|e| {
        JsValue::from(&format!(
            "Cannot serialize {:?} Fr due to error: {:?}",
            elem, e
        ))
    })?;
    // Following unwrap won't fail as its serializing only bytes
    Ok(serde_wasm_bindgen::to_value(&bytes).unwrap())
}

pub fn fr_from_jsvalue(value: JsValue) -> Result<Fr, JsValue> {
    let bytes: Vec<u8> = serde_wasm_bindgen::from_value(value)?;
    let elem = Fr::deserialize(&bytes[..]).map_err(|e| {
        JsValue::from(&format!(
            "Cannot deserialize {:?} to Fr due to error: {:?}",
            bytes, e
        ))
    })?;
    Ok(elem)
}

pub fn fr_to_uint8_array(elem: &Fr) -> Result<js_sys::Uint8Array, JsValue> {
    let mut bytes = vec![];
    elem.serialize(&mut bytes).map_err(|e| {
        JsValue::from(&format!(
            "Cannot serialize {:?} Fr due to error: {:?}",
            elem, e
        ))
    })?;
    Ok(js_sys::Uint8Array::from(bytes.as_slice()))
}

pub fn fr_from_uint8_array(value: js_sys::Uint8Array) -> Result<Fr, JsValue> {
    // TODO: Is there a better way to get byte slice from `value` without creating a Vec
    let bytes: Vec<u8> = value.to_vec();
    let elem = Fr::deserialize(&bytes[..]).map_err(|e| {
        JsValue::from(&format!(
            "Cannot deserialize {:?} to Fr due to error: {:?}",
            bytes, e
        ))
    })?;
    Ok(elem)
}

pub fn frs_from_jsvalue(value: JsValue) -> Result<Vec<Fr>, JsValue> {
    let bytes: Vec<u8> = serde_wasm_bindgen::from_value(value)?;
    let elem = <Vec<Fr>>::deserialize(&bytes[..]).map_err(|e| {
        JsValue::from(&format!(
            "Cannot deserialize to Fr vector due to error: {:?}",
            e
        ))
    })?;
    Ok(elem)
}

pub fn frs_to_jsvalue(elems: &[Fr]) -> Result<JsValue, JsValue> {
    let mut bytes = vec![];
    elems
        .serialize(&mut bytes)
        .map_err(|e| JsValue::from(&format!("Cannot serialize Fr vector due to error: {:?}", e)))?;
    // Following unwrap won't fail as its serializing only bytes
    Ok(serde_wasm_bindgen::to_value(&bytes).unwrap())
}

pub fn g1_affine_to_jsvalue(elem: &G1Affine) -> Result<JsValue, JsValue> {
    let mut bytes = vec![];
    elem.serialize(&mut bytes)
        .map_err(|e| JsValue::from(&format!("Cannot serialize G1Affine due to error: {:?}", e)))?;
    // Following unwrap won't fail as its serializing only bytes
    Ok(serde_wasm_bindgen::to_value(&bytes).unwrap())
}

pub fn g1_affine_from_jsvalue(value: JsValue) -> Result<G1Affine, JsValue> {
    let bytes: Vec<u8> = serde_wasm_bindgen::from_value(value)?;
    let elem = G1Affine::deserialize(&bytes[..]).map_err(|e| {
        JsValue::from(&format!(
            "Cannot deserialize to G1Affine due to error: {:?}",
            e
        ))
    })?;
    Ok(elem)
}

pub fn g1_affine_to_uint8_array(elem: &G1Affine) -> Result<js_sys::Uint8Array, JsValue> {
    let mut bytes = vec![];
    elem.serialize(&mut bytes)
        .map_err(|e| JsValue::from(&format!("Cannot serialize G1Affine due to error: {:?}", e)))?;
    Ok(js_sys::Uint8Array::from(bytes.as_slice()))
}

pub fn g1_affine_from_uint8_array(value: js_sys::Uint8Array) -> Result<G1Affine, JsValue> {
    // TODO: Is there a better way to get byte slice from `value` without creating a Vec
    let bytes: Vec<u8> = value.to_vec();
    let elem = G1Affine::deserialize(&bytes[..]).map_err(|e| {
        JsValue::from(&format!(
            "Cannot deserialize to G1Affine due to error: {:?}",
            e
        ))
    })?;
    Ok(elem)
}

pub fn g2_affine_to_jsvalue(elem: &G2Affine) -> Result<JsValue, JsValue> {
    let mut bytes = vec![];
    elem.serialize(&mut bytes)
        .map_err(|e| JsValue::from(&format!("Cannot serialize G2Affine due to error: {:?}", e)))?;
    // Following unwrap won't fail as its serializing only bytes
    Ok(serde_wasm_bindgen::to_value(&bytes).unwrap())
}

pub fn g2_affine_from_jsvalue(value: JsValue) -> Result<G2Affine, JsValue> {
    let bytes: Vec<u8> = serde_wasm_bindgen::from_value(value)?;
    let elem = G2Affine::deserialize(&bytes[..]).map_err(|e| {
        JsValue::from(&format!(
            "Cannot deserialize to G2Affine due to error: {:?}",
            e
        ))
    })?;
    Ok(elem)
}

pub fn g2_affine_to_uint8_array(elem: &G2Affine) -> Result<js_sys::Uint8Array, JsValue> {
    let mut bytes = vec![];
    elem.serialize(&mut bytes)
        .map_err(|e| JsValue::from(&format!("Cannot serialize G2Affine due to error: {:?}", e)))?;
    Ok(js_sys::Uint8Array::from(bytes.as_slice()))
}

pub fn g2_affine_from_uint8_array(value: js_sys::Uint8Array) -> Result<G2Affine, JsValue> {
    let bytes: Vec<u8> = value.to_vec();
    let elem = G2Affine::deserialize(&bytes[..]).map_err(|e| {
        JsValue::from(&format!(
            "Cannot deserialize to G2Affine due to error: {:?}",
            e
        ))
    })?;
    Ok(elem)
}

pub fn message_bytes_to_messages(
    messages_as_bytes: &[Vec<u8>],
    encode_messages: bool,
) -> Result<Vec<Fr>, JsValue> {
    let mut result = vec![];
    for m in messages_as_bytes {
        result.push({
            if encode_messages {
                encode_message_for_signing(m)
            } else {
                Fr::deserialize(m.as_slice()).map_err(|e| {
                    JsValue::from(&format!("Cannot deserialize to Fr due to error: {:?}", e))
                })?
            }
        });
    }
    Ok(result)
}

pub fn msgs_bytes_map_to_fr_btreemap(
    messages: &js_sys::Map,
    encode_messages: bool,
) -> Result<BTreeMap<usize, Fr>, serde_wasm_bindgen::Error> {
    let mut msgs = BTreeMap::new();
    for e in messages.entries() {
        let arr = js_sys::Array::from(&e.unwrap());
        let index: usize = serde_wasm_bindgen::from_value(arr.get(0))?;
        let msg: Vec<u8> = serde_wasm_bindgen::from_value(arr.get(1))?;
        let m = if encode_messages {
            encode_message_for_signing(&msg)
        } else {
            Fr::deserialize(msg.as_slice()).map_err(|e| {
                JsValue::from(&format!("Cannot deserialize to Fr due to error: {:?}", e))
            })?
        };
        msgs.insert(index, m);
    }
    Ok(msgs)
}

pub fn js_array_to_fr_vec(array: &js_sys::Array) -> Result<Vec<Fr>, serde_wasm_bindgen::Error> {
    let mut frs = Vec::with_capacity(array.length() as usize);
    for a in array.values() {
        frs.push(fr_from_jsvalue(a.unwrap())?);
    }
    Ok(frs)
}

pub fn js_array_from_frs(frs: &[Fr]) -> Result<js_sys::Array, serde_wasm_bindgen::Error> {
    let array = js_sys::Array::new();
    for fr in frs {
        array.push(&fr_to_jsvalue(fr)?);
    }
    Ok(array)
}

pub fn js_array_to_g1_affine_vec(
    array: &js_sys::Array,
) -> Result<Vec<G1Affine>, serde_wasm_bindgen::Error> {
    let mut g1s = Vec::with_capacity(array.length() as usize);
    for a in array.values() {
        g1s.push(g1_affine_from_jsvalue(a.unwrap())?);
    }
    Ok(g1s)
}

pub fn js_array_to_g2_affine_vec(
    array: &js_sys::Array,
) -> Result<Vec<G2Affine>, serde_wasm_bindgen::Error> {
    let mut g2s = Vec::with_capacity(array.length() as usize);
    for a in array.values() {
        g2s.push(g2_affine_from_jsvalue(a.unwrap())?);
    }
    Ok(g2s)
}

/// This is to convert a message to field element. This encoding needs to be collision resistant but
/// not preimage-resistant and thus use of hash function is not necessary. However, the encoding must
/// be constant time
pub fn encode_message_for_signing(msg: &[u8]) -> Fr {
    dock_crypto_utils::hashing_utils::field_elem_from_seed::<Fr, Blake2b>(
        msg,
        "BBS+ message".as_bytes(),
    )
}

pub fn field_element_from_u32(number: u32) -> Fr {
    // Using BigInteger256 is fine as Bls12-381 curve
    Fr::from_repr(ark_ff::BigInteger256::from(number as u64)).unwrap()
}

pub fn encode_bytes_as_accumulator_member(bytes: &[u8]) -> Fr {
    dock_crypto_utils::hashing_utils::field_elem_from_seed::<Fr, Blake2b>(
        bytes,
        "Accumulator element".as_bytes(),
    )
}

pub fn get_seeded_rng() -> StdRng {
    let mut buf = [0u8; 32];
    use rand::thread_rng;
    use rand::RngCore as RngCoreOld;
    let mut rng = thread_rng();
    rng.fill_bytes(&mut buf);
    // getrandom is using node-js crypto module which doesn't work when building for target web. It
    // works for `wasm-pack test` with chrome in headless and normal mode
    // getrandom::getrandom(&mut buf).unwrap();
    StdRng::from_seed(buf)
}

pub fn random_bytes() -> Vec<u8> {
    let mut rng = get_seeded_rng();
    let mut s = vec![0u8; 32];
    rng.fill_bytes(s.as_mut_slice());
    s
}

#[macro_export]
macro_rules! obj_to_uint8array {
    ($obj:expr) => {{
        let mut serz = vec![];
        CanonicalSerialize::serialize($obj, &mut serz).map_err(|e| {
            JsValue::from(format!(
                "Failed to serialize to bytes due to error: {:?}",
                e
            ))
        })?;
        js_sys::Uint8Array::from(serz.as_slice())
    }};

    ($obj:expr, $obj_name:expr) => {{
        let mut serz = vec![];
        CanonicalSerialize::serialize($obj, &mut serz).map_err(|e| {
            JsValue::from(format!(
                "Failed to serialize a {} to bytes due to error: {:?}",
                $obj_name, e
            ))
        })?;
        js_sys::Uint8Array::from(serz.as_slice())
    }};
}

#[macro_export]
macro_rules! obj_from_uint8array {
    ($obj_type:ty, $uint8array:expr) => {{
        let serz = $uint8array.to_vec();
        let deserz: $obj_type = CanonicalDeserialize::deserialize(&serz[..]).map_err(|e| {
            JsValue::from(format!(
                "Failed to deserialize from bytes due to error: {:?}",
                e
            ))
        })?;
        deserz
    }};

    ($obj_type:ty, $uint8array:expr, $obj_name:expr) => {{
        let serz = $uint8array.to_vec();
        let deserz: $obj_type = CanonicalDeserialize::deserialize(&serz[..]).map_err(|e| {
            JsValue::from(format!(
                "Failed to deserialize a {} from bytes due to error: {:?}",
                $obj_name, e
            ))
        })?;
        deserz
    }};
}

#[macro_export]
macro_rules! obj_to_uint8array_unchecked {
    ($obj:expr) => {{
        let mut serz = vec![];
        CanonicalSerialize::serialize_unchecked($obj, &mut serz).map_err(|e| {
            JsValue::from(format!(
                "Failed to serialize to bytes due to error: {:?}",
                e
            ))
        })?;
        js_sys::Uint8Array::from(serz.as_slice())
    }};

    ($obj:expr, $obj_name:expr) => {{
        let mut serz = vec![];
        CanonicalSerialize::serialize_unchecked($obj, &mut serz).map_err(|e| {
            JsValue::from(format!(
                "Failed to serialize a {} to bytes due to error: {:?}",
                $obj_name, e
            ))
        })?;
        js_sys::Uint8Array::from(serz.as_slice())
    }};
}

#[macro_export]
macro_rules! obj_from_uint8array_unchecked {
    ($obj_type:ty, $uint8array:expr) => {{
        let serz = $uint8array.to_vec();
        let deserz: $obj_type =
            CanonicalDeserialize::deserialize_unchecked(&serz[..]).map_err(|e| {
                JsValue::from(format!(
                    "Failed to deserialize from bytes due to error: {:?}",
                    e
                ))
            })?;
        deserz
    }};

    ($obj_type:ty, $uint8array:expr, $obj_name:expr) => {{
        let serz = $uint8array.to_vec();
        let deserz: $obj_type =
            CanonicalDeserialize::deserialize_unchecked(&serz[..]).map_err(|e| {
                JsValue::from(format!(
                    "Failed to deserialize a {} from bytes due to error: {:?}",
                    $obj_name, e
                ))
            })?;
        deserz
    }};
}

#[cfg(test)]
mod tests {
    #![cfg(target_arch = "wasm32")]
    extern crate wasm_bindgen_test;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    use super::*;
    use ark_bls12_381::{G1Projective, G2Projective};
    use ark_ec::ProjectiveCurve;
    use ark_std::UniformRand;
    use blake2::Blake2b;

    #[wasm_bindgen_test]
    pub fn to_and_from_js_value() {
        let seed = random_bytes();
        let f = dock_crypto_utils::hashing_utils::field_elem_from_seed::<Fr, Blake2b>(&seed, &[]);
        let jf = fr_to_jsvalue(&f).unwrap();
        assert_eq!(f, fr_from_jsvalue(jf).unwrap());

        let f = vec![
            dock_crypto_utils::hashing_utils::field_elem_from_seed::<Fr, Blake2b>(
                &random_bytes(),
                &[],
            ),
            dock_crypto_utils::hashing_utils::field_elem_from_seed::<Fr, Blake2b>(
                &random_bytes(),
                &[],
            ),
            dock_crypto_utils::hashing_utils::field_elem_from_seed::<Fr, Blake2b>(
                &random_bytes(),
                &[],
            ),
            dock_crypto_utils::hashing_utils::field_elem_from_seed::<Fr, Blake2b>(
                &random_bytes(),
                &[],
            ),
        ];
        let jf = frs_to_jsvalue(&f).unwrap();
        assert_eq!(f, frs_from_jsvalue(jf).unwrap());

        let mut rng = get_seeded_rng();
        let g1 = G1Projective::rand(&mut rng).into_affine();
        let jg1 = g1_affine_to_jsvalue(&g1).unwrap();
        assert_eq!(g1, g1_affine_from_jsvalue(jg1).unwrap());

        let mut rng = get_seeded_rng();
        let g2 = G2Projective::rand(&mut rng).into_affine();
        let jg2 = g2_affine_to_jsvalue(&g2).unwrap();
        assert_eq!(g2, g2_affine_from_jsvalue(jg2).unwrap());
    }

    #[wasm_bindgen_test]
    pub fn fr_map() {
        let map = js_sys::Map::new();
        let f1 = dock_crypto_utils::hashing_utils::field_elem_from_seed::<Fr, Blake2b>(
            &random_bytes(),
            &[],
        );
        let f2 = dock_crypto_utils::hashing_utils::field_elem_from_seed::<Fr, Blake2b>(
            &random_bytes(),
            &[],
        );
        let f3 = dock_crypto_utils::hashing_utils::field_elem_from_seed::<Fr, Blake2b>(
            &random_bytes(),
            &[],
        );
        map.set(&JsValue::from(1), &fr_to_jsvalue(&f1).unwrap());
        map.set(&JsValue::from(2), &fr_to_jsvalue(&f2).unwrap());
        map.set(&JsValue::from(3), &fr_to_jsvalue(&f3).unwrap());

        let fr_map = msgs_bytes_map_to_fr_btreemap(&map, false).unwrap();

        assert_eq!(f1, *fr_map.get(&1).unwrap());
        assert_eq!(f2, *fr_map.get(&2).unwrap());
        assert_eq!(f3, *fr_map.get(&3).unwrap());
    }
}
