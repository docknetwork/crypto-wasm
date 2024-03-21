use crate::{
    utils::{fr_to_jsvalue, random_bytes, set_panic_hook},
    Fr,
};
use ark_bls12_381::Bls12_381;
use ark_serialize::CanonicalDeserialize;
use blake2::Blake2b512;
use dock_crypto_utils::concat_slices;
use vb_accumulator::prelude::{Keypair, PublicKey, SecretKey, SetupParams};
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
use zeroize::Zeroize;

// Trying to keep types at one place so changing the curve is easier
pub(crate) type AccumSk = SecretKey<Fr>;
pub type AccumPk = PublicKey<Bls12_381>;
pub type AccumSetupParams = SetupParams<Bls12_381>;
pub(crate) type AccumKeypair = Keypair<Bls12_381>;

/// Generate accumulator parameters. They are needed to generate public key and initialize the accumulator.
/// Pass the `label` argument to generate parameters deterministically.
#[wasm_bindgen(js_name = generateAccumulatorParams)]
pub fn generate_accumulator_params(label: Option<Vec<u8>>) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let label = label.unwrap_or_else(random_bytes);
    let params = AccumSetupParams::new::<Blake2b512>(&label);
    Ok(obj_to_uint8array!(&params, false, "SetupParams"))
}

/// Check if parameters are valid. Before verifying witness or using for proof verification,
/// make sure the params are valid.
#[wasm_bindgen(js_name = isAccumulatorParamsValid)]
pub fn accumulator_is_params_valid(params: js_sys::Uint8Array) -> Result<bool, JsValue> {
    set_panic_hook();
    let params = deserialize_params(params)?;
    Ok(params.is_valid())
}

/// Generate secret key for the accumulator manager who updates the accumulator and creates witnesses.
/// Pass the `seed` argument to generate key deterministically.
#[wasm_bindgen(js_name = generateAccumulatorSecretKey)]
pub fn accumulator_generate_secret_key(seed: Option<Vec<u8>>) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let mut seed = seed.unwrap_or_else(random_bytes);
    let sk = AccumSk::generate_using_seed::<Blake2b512>(&seed);
    seed.zeroize();

    serde_wasm_bindgen::to_value(&sk).map_err(JsValue::from)
}

/// Generate public key from given params and secret key.
#[wasm_bindgen(js_name = generateAccumulatorPublicKey)]
pub fn accumulator_generate_public_key(
    secret_key: JsValue,
    params: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let params = deserialize_params(params)?;
    let pk = AccumKeypair::public_key_from_secret_key(&sk, &params);
    Ok(obj_to_uint8array!(&pk, false, "PublicKeyG2"))
}

/// Check if public key is valid. Before verifying witness or using for proof verification,
/// make sure the public key is valid.
#[wasm_bindgen(js_name = isAccumulatorPublicKeyValid)]
pub fn accumulator_is_pubkey_valid(public_key: js_sys::Uint8Array) -> Result<bool, JsValue> {
    set_panic_hook();
    let pk = deserialize_public_key(public_key)?;
    Ok(pk.is_valid())
}

/// Generate private and public key from given params and optional `seed`.
/// Pass the `seed` argument to generate keys deterministically.
#[wasm_bindgen(js_name = generateAccumulatorKeyPair)]
pub fn accumulator_generate_keypair(
    params: js_sys::Uint8Array,
    seed: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let params = deserialize_params(params)?;
    let seed = seed.unwrap_or(random_bytes());
    let keypair = AccumKeypair::generate_using_seed::<Blake2b512>(&seed, &params);
    serde_wasm_bindgen::to_value(&keypair).map_err(JsValue::from)
}

/// To add arbitrary bytes as an accumulator member, they should be first converted to
/// a field element. This function will prefix the given bytes with a constant string as
/// domain separator and then generate a field element using IETF standard.
#[wasm_bindgen(js_name = accumulatorGetElementFromBytes)]
pub fn accumulator_get_element_from_bytes(bytes: Vec<u8>) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let f = fr_to_jsvalue(&encode_bytes_as_accumulator_member(&bytes))?;
    Ok(f)
}

pub(crate) fn deserialize_params(bytes: js_sys::Uint8Array) -> Result<AccumSetupParams, JsValue> {
    CanonicalDeserialize::deserialize_compressed(&bytes.to_vec()[..]).map_err(|e| {
        JsValue::from(&format!(
            "Failed to deserialize accumulator params from bytes due to error: {:?}",
            e
        ))
    })
}

pub(crate) fn deserialize_public_key(bytes: js_sys::Uint8Array) -> Result<AccumPk, JsValue> {
    CanonicalDeserialize::deserialize_compressed(&bytes.to_vec()[..]).map_err(|e| {
        JsValue::from(&format!(
            "Failed to deserialize accumulator public key from bytes due to error: {:?}",
            e
        ))
    })
}

pub fn encode_bytes_as_accumulator_member(bytes: &[u8]) -> Fr {
    dock_crypto_utils::hashing_utils::field_elem_from_try_and_incr::<Fr, Blake2b512>(
        &concat_slices!(bytes, b"Accumulator element"),
    )
}

#[macro_use]
mod macros {
    #[macro_export]
    macro_rules! get_membership_witness {
        ($accum: ident, $element: ident, $sk: ident) => {{
            let element = fr_from_uint8_array($element, true)?;
            let sk: AccumSk = serde_wasm_bindgen::from_value($sk)?;
            let new_value = $accum.compute_membership_witness(&element, &sk);
            serde_wasm_bindgen::to_value(&new_value).map_err(JsValue::from)
        }};
    }

    #[macro_export]
    macro_rules! get_membership_witnesses_for_batch {
        ($accum: ident, $elements: ident, $sk: ident) => {{
            let elems = js_array_to_fr_vec(&$elements)?;
            let sk: AccumSk = serde_wasm_bindgen::from_value($sk)?;
            let witnesses = $accum.compute_membership_witnesses_for_batch(&elems, &sk);

            let result = js_sys::Array::new();
            for witness in witnesses {
                result.push(&serde_wasm_bindgen::to_value(&witness).map_err(JsValue::from)?);
            }
            Ok(result)
        }};
    }

    #[macro_export]
    macro_rules! verify_membership {
        ($accum: ident, $element: ident, $witness_type: ident, $witness: ident, $pk: ident, $params: ident) => {{
            let element = fr_from_uint8_array($element, true)?;
            let witness: $witness_type = serde_wasm_bindgen::from_value($witness)?;
            let pk = deserialize_public_key($pk)?;
            let params = deserialize_params($params)?;
            Ok($accum.verify_membership(&element, &witness, &pk, &params))
        }};
    }

    #[macro_export]
    macro_rules! update_witness_post_add {
        ($witness:expr, $element: ident, $addition: ident, $old_accumulated: ident) => {{
            let element = fr_from_uint8_array($element, true)?;
            let addition = fr_from_uint8_array($addition, true)?;
            let old_accumulated = g1_affine_from_uint8_array($old_accumulated)?;
            serde_wasm_bindgen::to_value(&$witness.update_after_addition(
                &element,
                &addition,
                &old_accumulated,
            ))
            .map_err(JsValue::from)
        }};
    }

    #[macro_export]
    macro_rules! update_witness_post_remove {
        ($witness:expr, $element: ident, $removal: ident, $new_accumulated: ident) => {{
            let element = fr_from_uint8_array($element, true)?;
            let removal = fr_from_uint8_array($removal, true)?;
            let new_accumulated = g1_affine_from_uint8_array($new_accumulated)?;
            let new_wit = $witness
                .update_after_removal(&element, &removal, &new_accumulated)
                .map_err(|e| {
                    JsValue::from(&format!(
                        "Evaluating update_after_removal returned error: {:?}",
                        e
                    ))
                })?;
            serde_wasm_bindgen::to_value(&new_wit).map_err(JsValue::from)
        }};
    }

    #[macro_export]
    macro_rules! update_witness_single_batch {
        ($witness:expr, $element: ident, $additions: ident, $removals: ident, $public_info: ident) => {{
            let element = fr_from_uint8_array($element, true)?;
            let additions = js_array_to_fr_vec(&$additions)?;
            let removals = js_array_to_fr_vec(&$removals)?;
            let public_info: Omega = ark_serialize::CanonicalDeserialize::deserialize_compressed(&$public_info.to_vec()[..]).map_err(|e| {
                JsValue::from(&format!(
                    "Failed to deserialize public info from bytes due to error: {:?}",
                    e
                ))
            })?;
            let new_witness = $witness
                .update_using_public_info_after_batch_updates(&additions, &removals, &public_info, &element)
                .map_err(|e| {
                    JsValue::from(&format!(
                        "Evaluating update_using_public_info_after_batch_updates returned error: {:?}",
                        e
                    ))
                })?;
            serde_wasm_bindgen::to_value(&new_witness).map_err(JsValue::from)
        }}
    }

    #[macro_export]
    macro_rules! update_witness_multiple_batches {
        ($witness:expr, $element: ident, $additions: ident, $removals: ident, $public_info: ident) => {{
            let element = fr_from_uint8_array($element, true)?;
            if $additions.length() == $removals.length() && $removals.length() == $public_info.length() {
                let size = $additions.length();
                let mut updates_and_public_info = Vec::with_capacity(size as usize);
                for i in 0..size {
                    let adds = js_array_to_fr_vec(&js_sys::Array::from(&$additions.get(i)))?;
                    let rems = js_array_to_fr_vec(&js_sys::Array::from(&$removals.get(i)))?;
                    let bytes: Vec<u8> = serde_wasm_bindgen::from_value($public_info.get(i))?;
                    let p: Omega = ark_serialize::CanonicalDeserialize::deserialize_compressed(&bytes[..]).map_err(|e| JsValue::from(&format!(
                            "Failed to deserialize public info from bytes due to error: {:?}",
                            e
                        )))?;
                    updates_and_public_info.push((adds, rems, p));
                }
                let new_witness = $witness.update_using_public_info_after_multiple_batch_updates(updates_and_public_info.iter().map(|(a, r, p)| (a.as_slice(), r.as_slice(), p)).collect::<Vec<_>>(), &element)
                .map_err(|e| {
                    JsValue::from(&format!(
                        "Evaluating update_using_public_info_after_multiple_batch_updates returned error: {:?}",
                        e
                    ))
                })?;
                let w = serde_wasm_bindgen::to_value(&new_witness).map_err(JsValue::from)?;
                Ok(w)
            } else {
                Err(JsValue::from(&format!(
                    "Expected same but found different lengths for additions, removals and public info: {} {} {}",
                    $additions.length(), $removals.length(), $public_info.length()
                )))
            }
        }}
    }

    #[macro_export]
    macro_rules! init_proof_protocol {
        ($protocol:ident, $witness:ident, $element: ident, $blinding: ident, $public_key: ident, $params: ident, $prk: ident) => {{
            let element = fr_from_uint8_array($element, true)?;
            let blinding = fr_from_uint8_array($blinding, true)?;
            let pk = deserialize_public_key($public_key)?;
            let params = deserialize_params($params)?;

            let mut rng = get_seeded_rng();
            let protocol = $protocol::init(
                &mut rng,
                element,
                Some(blinding),
                &$witness,
                &pk,
                &params,
                &$prk,
            );
            serde_wasm_bindgen::to_value(&protocol).map_err(JsValue::from)
        }};
    }

    #[macro_export]
    macro_rules! verify_proof {
        ($proof: ident, $accumulated:ident, $challenge: ident, $public_key: ident, $params: ident, $prk: ident) => {{
            let accumulated = g1_affine_from_uint8_array($accumulated)?;
            let challenge = fr_from_uint8_array($challenge, false)?;
            let pk = deserialize_public_key($public_key)?;
            let params = deserialize_params($params)?;
            to_verify_response!($proof.verify(
                &accumulated,
                &challenge,
                pk.clone(),
                params.clone(),
                &$prk
            ))
        }};
    }

    #[macro_export]
    macro_rules! update_using_secret_key_after_batch_updates {
        ($witnesses: ident, $elements:ident, $additions: ident, $removals: ident, $old_accumulated: ident, $secret_key: ident, $wit_type: ident) => {{
            let elements = js_array_to_fr_vec(&$elements)?;
            let additions = js_array_to_fr_vec(&$additions)?;
            let removals = js_array_to_fr_vec(&$removals)?;
            let old_accumulated = g1_affine_from_uint8_array($old_accumulated)?;
            let sk: AccumSk = serde_wasm_bindgen::from_value($secret_key)?;
            let mut wits = Vec::with_capacity($witnesses.length() as usize);
            for w in $witnesses.values() {
                wits.push(serde_wasm_bindgen::from_value::<$wit_type>(w.unwrap())?);
            }
            let new_wits = $wit_type::update_using_secret_key_after_batch_updates(
                &additions,
                &removals,
                &elements,
                &wits,
                &old_accumulated,
                &sk,
            )
            .map_err(|e| {
                JsValue::from(&format!(
                    "Evaluating update_using_secret_key_after_batch_updates returned error: {:?}",
                    e
                ))
            })?;
            let result = js_sys::Array::new();
            for w in new_wits {
                result.push(&serde_wasm_bindgen::to_value(&w).map_err(JsValue::from)?);
            }
            Ok(result)
        }}
    }
}
