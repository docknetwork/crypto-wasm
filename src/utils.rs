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
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::BTreeMap,
    rand::prelude::{RngCore, SeedableRng, StdRng},
};
use blake2::Blake2b512;
use dock_crypto_utils::concat_slices;
use serde_wasm_bindgen::from_value;
use std::collections::BTreeSet;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

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
    elem.serialize_compressed(&mut bytes).map_err(|e| {
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
    let elem = Fr::deserialize_compressed(&bytes[..]).map_err(|e| {
        JsValue::from(&format!(
            "Cannot deserialize {:?} to Fr due to error: {:?}",
            bytes, e
        ))
    })?;
    Ok(elem)
}

pub fn fr_to_uint8_array(elem: &Fr) -> Result<js_sys::Uint8Array, JsValue> {
    let mut bytes = vec![];
    elem.serialize_compressed(&mut bytes).map_err(|e| {
        JsValue::from(&format!(
            "Cannot serialize {:?} Fr due to error: {:?}",
            elem, e
        ))
    })?;
    Ok(js_sys::Uint8Array::from(bytes.as_slice()))
}

/// If `value_is_secret` is true, the temporary bytearrary created from `value` is zeroized.
/// `value` is never modified as this might not be expected by the calling JS code.
pub fn fr_from_uint8_array(
    value: js_sys::Uint8Array,
    value_is_secret: bool,
) -> Result<Fr, JsValue> {
    // TODO: Is there a better way to get byte slice from `value` without creating a Vec?
    // Looking at https://github.com/rustwasm/wasm-bindgen/issues/5 and other links from this page,
    // this isn't easily doable
    let mut bytes: Vec<u8> = value.to_vec();
    let elem = Fr::deserialize_compressed(&bytes[..]).map_err(|e| {
        JsValue::from(&format!(
            "Cannot deserialize {:?} to Fr due to error: {:?}",
            bytes, e
        ))
    })?;
    if value_is_secret {
        bytes.zeroize();
    }
    Ok(elem)
}

pub fn frs_from_jsvalue(value: JsValue) -> Result<Vec<Fr>, JsValue> {
    let bytes: Vec<u8> = serde_wasm_bindgen::from_value(value)?;
    let elem = <Vec<Fr>>::deserialize_compressed(&bytes[..]).map_err(|e| {
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
        .serialize_compressed(&mut bytes)
        .map_err(|e| JsValue::from(&format!("Cannot serialize Fr vector due to error: {:?}", e)))?;
    // Following unwrap won't fail as its serializing only bytes
    Ok(serde_wasm_bindgen::to_value(&bytes).unwrap())
}

pub fn g1_affine_to_jsvalue(elem: &G1Affine) -> Result<JsValue, JsValue> {
    let mut bytes = vec![];
    elem.serialize_compressed(&mut bytes)
        .map_err(|e| JsValue::from(&format!("Cannot serialize G1Affine due to error: {:?}", e)))?;
    // Following unwrap won't fail as its serializing only bytes
    Ok(serde_wasm_bindgen::to_value(&bytes).unwrap())
}

pub fn g1_affine_from_jsvalue(value: JsValue) -> Result<G1Affine, JsValue> {
    let bytes: Vec<u8> = serde_wasm_bindgen::from_value(value)?;
    let elem = G1Affine::deserialize_compressed(&bytes[..]).map_err(|e| {
        JsValue::from(&format!(
            "Cannot deserialize to G1Affine due to error: {:?}",
            e
        ))
    })?;
    Ok(elem)
}

pub fn g1_affine_to_uint8_array(elem: &G1Affine) -> Result<js_sys::Uint8Array, JsValue> {
    let mut bytes = vec![];
    elem.serialize_compressed(&mut bytes)
        .map_err(|e| JsValue::from(&format!("Cannot serialize G1Affine due to error: {:?}", e)))?;
    Ok(js_sys::Uint8Array::from(bytes.as_slice()))
}

pub fn g1_affine_from_uint8_array(value: js_sys::Uint8Array) -> Result<G1Affine, JsValue> {
    // TODO: Is there a better way to get byte slice from `value` without creating a Vec
    let bytes: Vec<u8> = value.to_vec();
    let elem = G1Affine::deserialize_compressed(&bytes[..]).map_err(|e| {
        JsValue::from(&format!(
            "Cannot deserialize to G1Affine due to error: {:?}",
            e
        ))
    })?;
    Ok(elem)
}

pub fn g2_affine_to_jsvalue(elem: &G2Affine) -> Result<JsValue, JsValue> {
    let mut bytes = vec![];
    elem.serialize_compressed(&mut bytes)
        .map_err(|e| JsValue::from(&format!("Cannot serialize G2Affine due to error: {:?}", e)))?;
    // Following unwrap won't fail as its serializing only bytes
    Ok(serde_wasm_bindgen::to_value(&bytes).unwrap())
}

pub fn g2_affine_from_jsvalue(value: JsValue) -> Result<G2Affine, JsValue> {
    let bytes: Vec<u8> = serde_wasm_bindgen::from_value(value)?;
    let elem = G2Affine::deserialize_compressed(&bytes[..]).map_err(|e| {
        JsValue::from(&format!(
            "Cannot deserialize to G2Affine due to error: {:?}",
            e
        ))
    })?;
    Ok(elem)
}

pub fn g2_affine_to_uint8_array(elem: &G2Affine) -> Result<js_sys::Uint8Array, JsValue> {
    let mut bytes = vec![];
    elem.serialize_compressed(&mut bytes)
        .map_err(|e| JsValue::from(&format!("Cannot serialize G2Affine due to error: {:?}", e)))?;
    Ok(js_sys::Uint8Array::from(bytes.as_slice()))
}

pub fn g2_affine_from_uint8_array(value: js_sys::Uint8Array) -> Result<G2Affine, JsValue> {
    let bytes: Vec<u8> = value.to_vec();
    let elem = G2Affine::deserialize_compressed(&bytes[..]).map_err(|e| {
        JsValue::from(&format!(
            "Cannot deserialize to G2Affine due to error: {:?}",
            e
        ))
    })?;
    Ok(elem)
}

pub fn js_array_to_fr_vec(array: &js_sys::Array) -> Result<Vec<Fr>, JsValue> {
    let mut frs = Vec::with_capacity(array.length() as usize);
    for a in array.values() {
        frs.push(fr_from_jsvalue(a.unwrap())?);
    }
    Ok(frs)
}

/// This is to convert a message to field element. This encoding needs to be collision resistant but
/// not preimage-resistant and thus use of hash function is not necessary. However, the encoding must
/// be constant time
pub fn encode_message_for_signing(msg: &[u8]) -> Fr {
    dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr::<Fr, Blake2b512>(
        &concat_slices!(msg, b"message to sign"),
    )
}

pub fn messages_as_bytes_to_fr_vec(
    messages_as_bytes: &[Vec<u8>],
    encode_messages: bool,
) -> Result<Vec<Fr>, JsValue> {
    let mut result = vec![];
    for m in messages_as_bytes {
        result.push({
            if encode_messages {
                encode_message_for_signing(m)
            } else {
                Fr::deserialize_compressed(m.as_slice()).map_err(|e| {
                    JsValue::from(&format!("Cannot deserialize to Fr due to error: {:?}", e))
                })?
            }
        });
    }
    Ok(result)
}

pub fn encode_messages_as_js_array_to_fr_vec(
    messages: &js_sys::Array,
    encode_messages: bool,
) -> Result<Vec<Fr>, JsValue> {
    let messages_as_bytes = js_array_of_bytearrays_to_vector_of_bytevectors(messages)?;
    messages_as_bytes_to_fr_vec(&messages_as_bytes, encode_messages)
}

pub fn encode_messages_as_js_map_to_fr_btreemap(
    messages: &js_sys::Map,
    encode_messages: bool,
) -> Result<BTreeMap<usize, Fr>, JsValue> {
    let mut msgs = BTreeMap::new();
    for e in messages.entries() {
        let arr = js_sys::Array::from(&e.unwrap());
        let index: usize = serde_wasm_bindgen::from_value(arr.get(0))?;
        let msg: Vec<u8> = serde_wasm_bindgen::from_value(arr.get(1))?;
        let m = if encode_messages {
            encode_message_for_signing(&msg)
        } else {
            Fr::deserialize_compressed(msg.as_slice()).map_err(|e| {
                JsValue::from(&format!("Cannot deserialize to Fr due to error: {:?}", e))
            })?
        };
        msgs.insert(index, m);
    }
    Ok(msgs)
}

pub fn js_array_from_frs(frs: &[Fr]) -> Result<js_sys::Array, JsValue> {
    let array = js_sys::Array::new();
    for fr in frs {
        array.push(&fr_to_jsvalue(fr)?);
    }
    Ok(array)
}

pub fn js_array_of_bytearrays_to_vector_of_bytevectors(
    array: &js_sys::Array,
) -> Result<Vec<Vec<u8>>, JsValue> {
    let mut r = Vec::with_capacity(array.length() as usize);
    for a in array.values() {
        let b = js_sys::Uint8Array::new(&a.unwrap());
        r.push(b.to_vec());
    }
    Ok(r)
}

pub fn js_array_of_bytearrays_from_vector_of_bytevectors(
    vector: &Vec<Vec<u8>>,
) -> Result<js_sys::Array, JsValue> {
    let r = js_sys::Array::new_with_length(vector.len() as u32);
    for (i, v) in vector.iter().enumerate() {
        let b = js_sys::Uint8Array::from(v.as_slice());
        r.set(i as u32, JsValue::from(b));
    }
    Ok(r)
}

pub fn js_array_to_g1_affine_vec(array: &js_sys::Array) -> Result<Vec<G1Affine>, JsValue> {
    let mut g1s = Vec::with_capacity(array.length() as usize);
    for a in array.values() {
        g1s.push(g1_affine_from_jsvalue(a.unwrap())?);
    }
    Ok(g1s)
}

pub fn js_array_to_g2_affine_vec(array: &js_sys::Array) -> Result<Vec<G2Affine>, JsValue> {
    let mut g2s = Vec::with_capacity(array.length() as usize);
    for a in array.values() {
        g2s.push(g2_affine_from_jsvalue(a.unwrap())?);
    }
    Ok(g2s)
}

pub fn field_element_from_u32(number: u32) -> Fr {
    // Using BigInteger256 is fine as Bls12-381 curve
    Fr::from(number as u64)
}

pub fn field_element_from_u64(number: u64) -> Fr {
    // Using BigInteger256 is fine as Bls12-381 curve
    Fr::from(number)
}

pub fn zeroize_uint8array(value: js_sys::Uint8Array) {
    value.fill(0, 0, value.length());
}

pub fn get_seeded_rng() -> StdRng {
    let mut buf = [0u8; 32];
    use rand::{thread_rng, RngCore as RngCoreOld};
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

pub fn is_positive_safe_integer(num: &js_sys::Number) -> bool {
    js_sys::Number::is_safe_integer(num) && num >= &js_sys::Number::from(0)
}

pub fn js_set_to_btree_set<T: Ord + serde::de::DeserializeOwned>(
    js_set: &js_sys::Set,
) -> BTreeSet<T> {
    let set: BTreeSet<T> = js_set
        .values()
        .into_iter()
        .map(|i| serde_wasm_bindgen::from_value(i.unwrap()).unwrap())
        .collect();
    set
}

#[macro_export]
macro_rules! obj_to_uint8array {
    ($obj:expr, $value_is_secret: expr) => {{
        let mut serz = vec![];
        CanonicalSerialize::serialize_compressed($obj, &mut serz).map_err(|e| {
            JsValue::from(format!(
                "Failed to serialize to bytes due to error: {:?}",
                e
            ))
        })?;
        let s = js_sys::Uint8Array::from(serz.as_slice());
        if $value_is_secret {
            serz.zeroize();
        }
        s
    }};

    ($obj:expr, $value_is_secret: expr, $obj_name:expr) => {{
        let mut serz = vec![];
        CanonicalSerialize::serialize_compressed($obj, &mut serz).map_err(|e| {
            JsValue::from(format!(
                "Failed to serialize a {} to bytes due to error: {:?}",
                $obj_name, e
            ))
        })?;
        let s = js_sys::Uint8Array::from(serz.as_slice());
        if $value_is_secret {
            serz.zeroize();
        }
        s
    }};
}

#[macro_export]
macro_rules! obj_from_uint8array {
    ($obj_type:ty, $uint8array:expr, $value_is_secret: expr) => {{
        let mut serz = $uint8array.to_vec();
        let deserz: $obj_type =
            CanonicalDeserialize::deserialize_compressed(&serz[..]).map_err(|e| {
                JsValue::from(format!(
                    "Failed to deserialize from bytes due to error: {:?}",
                    e
                ))
            })?;
        if $value_is_secret {
            serz.zeroize();
        }
        deserz
    }};

    ($obj_type:ty, $uint8array:expr, $value_is_secret: expr, $obj_name:expr) => {{
        let mut serz = $uint8array.to_vec();
        let deserz: $obj_type =
            CanonicalDeserialize::deserialize_compressed(&serz[..]).map_err(|e| {
                JsValue::from(format!(
                    "Failed to deserialize a {} from bytes due to error: {:?}",
                    $obj_name, e
                ))
            })?;
        if $value_is_secret {
            serz.zeroize();
        }
        deserz
    }};
}

#[macro_export]
macro_rules! obj_to_uint8array_uncompressed {
    ($obj:expr) => {{
        let mut serz = vec![];
        CanonicalSerialize::serialize_uncompressed($obj, &mut serz).map_err(|e| {
            JsValue::from(format!(
                "Failed to serialize to bytes due to error: {:?}",
                e
            ))
        })?;
        js_sys::Uint8Array::from(serz.as_slice())
    }};

    ($obj:expr, $obj_name:expr) => {{
        let mut serz = vec![];
        CanonicalSerialize::serialize_uncompressed($obj, &mut serz).map_err(|e| {
            JsValue::from(format!(
                "Failed to serialize a {} to bytes due to error: {:?}",
                $obj_name, e
            ))
        })?;
        js_sys::Uint8Array::from(serz.as_slice())
    }};
}

#[macro_export]
macro_rules! obj_from_uint8array_uncompressed {
    ($obj_type:ty, $uint8array:expr) => {{
        let serz = $uint8array.to_vec();
        let deserz: $obj_type =
            CanonicalDeserialize::deserialize_uncompressed(&serz[..]).map_err(|e| {
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
            CanonicalDeserialize::deserialize_uncompressed(&serz[..]).map_err(|e| {
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
    use ark_ec::CurveGroup;
    use ark_std::UniformRand;
    use blake2::Blake2b512;

    #[wasm_bindgen_test]
    pub fn to_and_from_js_value() {
        let seed = random_bytes();
        let f =
            dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr::<Fr, Blake2b512>(&seed);
        let jf = fr_to_jsvalue(&f).unwrap();
        assert_eq!(f, fr_from_jsvalue(jf).unwrap());

        let f = vec![
            dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr::<Fr, Blake2b512>(
                &random_bytes(),
            ),
            dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr::<Fr, Blake2b512>(
                &random_bytes(),
            ),
            dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr::<Fr, Blake2b512>(
                &random_bytes(),
            ),
            dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr::<Fr, Blake2b512>(
                &random_bytes(),
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
        let f1 = dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr::<Fr, Blake2b512>(
            &random_bytes(),
        );
        let f2 = dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr::<Fr, Blake2b512>(
            &random_bytes(),
        );
        let f3 = dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr::<Fr, Blake2b512>(
            &random_bytes(),
        );
        map.set(&JsValue::from(1), &fr_to_jsvalue(&f1).unwrap());
        map.set(&JsValue::from(2), &fr_to_jsvalue(&f2).unwrap());
        map.set(&JsValue::from(3), &fr_to_jsvalue(&f3).unwrap());

        let fr_map = encode_messages_as_js_map_to_fr_btreemap(&map, false).unwrap();

        assert_eq!(f1, *fr_map.get(&1).unwrap());
        assert_eq!(f2, *fr_map.get(&2).unwrap());
        assert_eq!(f3, *fr_map.get(&3).unwrap());
    }
}

pub fn js_array_to_iter<Item: CanonicalDeserialize>(
    messages: &js_sys::Array,
) -> impl Iterator<Item = Result<Item, JsValue>> {
    messages.values().into_iter().map(|raw| {
        Item::deserialize_compressed(js_sys::Uint8Array::new(&raw.unwrap()).to_vec().as_slice())
            .map_err(debug_to_js_value)
    })
}

pub fn js_map_to_iter<Item: CanonicalDeserialize>(
    messages: &js_sys::Map,
) -> impl Iterator<Item = Result<(usize, Item), JsValue>> {
    messages.entries().into_iter().map(|raw_msg_arr| {
        let arr = js_sys::Array::from(&raw_msg_arr?);
        let idx: usize = from_value(arr.get(0))?;
        let msg_bytes: Vec<u8> = from_value(arr.get(1))?;

        let msg = Item::deserialize_compressed(&msg_bytes[..]).map_err(|e| {
            JsValue::from(&format!(
                "Cannot deserialize to `ScalarField` due to error: {:?}",
                e
            ))
        })?;

        Ok((idx, msg))
    })
}

pub fn debug_to_js_value<V: core::fmt::Debug>(value: V) -> JsValue {
    JsValue::from(&format!("{:?}", value))
}
