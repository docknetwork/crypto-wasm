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

use crate::Fr;
use ark_bls12_381::Bls12_381;
use ark_ec::PairingEngine;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::collections::BTreeMap;
use ark_std::rand::prelude::{RngCore, SeedableRng, StdRng};
use blake2::Blake2b;
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::*;
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

pub fn fr_to_jsvalue(elem: &<Bls12_381 as PairingEngine>::Fr) -> Result<JsValue, JsValue> {
    let mut bytes = vec![];
    elem.serialize(&mut bytes)
        .map_err(|e| JsValue::from(&format!("Cannot serialize Fr due to error: {:?}", e)))?;
    // Following unwrap won't fail as its serializing only bytes
    Ok(serde_wasm_bindgen::to_value(&bytes).unwrap())
}

pub fn fr_from_jsvalue(value: JsValue) -> Result<<Bls12_381 as PairingEngine>::Fr, JsValue> {
    let bytes: Vec<u8> = serde_wasm_bindgen::from_value(value)?;
    let elem = <Bls12_381 as PairingEngine>::Fr::deserialize(&bytes[..])
        .map_err(|e| JsValue::from(&format!("Cannot deserialize to Fr due to error: {:?}", e)))?;
    Ok(elem)
}

pub fn g1_affine_to_jsvalue(
    elem: &<Bls12_381 as PairingEngine>::G1Affine,
) -> Result<JsValue, JsValue> {
    let mut bytes = vec![];
    elem.serialize(&mut bytes)
        .map_err(|e| JsValue::from(&format!("Cannot serialize G1Affine due to error: {:?}", e)))?;
    // Following unwrap won't fail as its serializing only bytes
    Ok(serde_wasm_bindgen::to_value(&bytes).unwrap())
}

pub fn g1_affine_from_jsvalue(
    value: JsValue,
) -> Result<<Bls12_381 as PairingEngine>::G1Affine, JsValue> {
    let bytes: Vec<u8> = serde_wasm_bindgen::from_value(value)?;
    let elem = <Bls12_381 as PairingEngine>::G1Affine::deserialize(&bytes[..]).map_err(|e| {
        JsValue::from(&format!(
            "Cannot deserialize to G1Affine due to error: {:?}",
            e
        ))
    })?;
    Ok(elem)
}

pub fn g2_affine_to_jsvalue(
    elem: &<Bls12_381 as PairingEngine>::G2Affine,
) -> Result<JsValue, JsValue> {
    let mut bytes = vec![];
    elem.serialize(&mut bytes)
        .map_err(|e| JsValue::from(&format!("Cannot serialize G2Affine due to error: {:?}", e)))?;
    // Following unwrap won't fail as its serializing only bytes
    Ok(serde_wasm_bindgen::to_value(&bytes).unwrap())
}

pub fn g2_affine_from_jsvalue(
    value: JsValue,
) -> Result<<Bls12_381 as PairingEngine>::G2Affine, JsValue> {
    let bytes: Vec<u8> = serde_wasm_bindgen::from_value(value)?;
    let elem = <Bls12_381 as PairingEngine>::G2Affine::deserialize(&bytes[..]).map_err(|e| {
        JsValue::from(&format!(
            "Cannot deserialize to G2Affine due to error: {:?}",
            e
        ))
    })?;
    Ok(elem)
}

pub fn message_bytes_to_messages(messages_as_bytes: &[Vec<u8>], encode_messages: bool) -> Vec<Fr> {
    messages_as_bytes
        .iter()
        .map(|m| {
            if encode_messages {
                encode_message_for_signing(m)
            } else {
                Fr::from_be_bytes_mod_order(m)
            }
        })
        .collect::<Vec<_>>()
}

pub fn msgs_bytes_map_to_fr_btreemap(
    messages: &js_sys::Map,
    encode_messages: bool,
) -> Result<BTreeMap<usize, Fr>, serde_wasm_bindgen::Error> {
    let mut msgs = BTreeMap::new();
    /*let mut msgs_vec = Vec::new();
    messages.for_each(&mut |m, i| {
        msgs_vec.push((i,m))
    });*/
    for e in messages.entries() {
        let arr = js_sys::Array::from(&e.unwrap());
        let index: usize = serde_wasm_bindgen::from_value(arr.get(0))?;
        let msg: Vec<u8> = serde_wasm_bindgen::from_value(arr.get(1))?;
        msgs.insert(
            index,
            if encode_messages {
                encode_message_for_signing(&msg)
            } else {
                Fr::from_be_bytes_mod_order(&msg)
            },
        );
    }
    Ok(msgs)
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

pub fn get_seeded_rng() -> StdRng {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).unwrap();
    StdRng::from_seed(buf)
}

pub fn random_bytes() -> Vec<u8> {
    let mut rng = get_seeded_rng();
    let mut s = vec![0u8, 32];
    rng.fill_bytes(s.as_mut_slice());
    s
}
