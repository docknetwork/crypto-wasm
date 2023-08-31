#![cfg(target_arch = "wasm32")]
extern crate alloc;
extern crate wasm_bindgen_test;

use alloc::collections::BTreeMap;
use dock_crypto_wasm::common::generate_random_g1_element;
use js_sys::Uint8Array;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

use dock_crypto_wasm::{
    common::{
        encode_message_for_signing, encode_messages_for_signing, field_element_as_bytes,
        field_element_from_number, generate_challenge_from_bytes, generate_random_field_element,
        VerifyResponse,
    },
    ps::*,
    utils::js_array_of_bytearrays_from_vector_of_bytevectors,
};

wasm_bindgen_test_configure!(run_in_browser);

fn ps_setup(message_count: u32) -> (JsValue, Uint8Array, Uint8Array) {
    let label = b"test-g1".to_vec();
    let params = ps_generate_params(message_count, Some(label)).unwrap();

    let seed = vec![0, 1, 2, 5, 10, 13];
    let sk = ps_generate_secret_key(message_count, Some(seed)).unwrap();
    let pk = ps_generate_public_key(sk.clone(), params.clone()).unwrap();

    (params, sk, pk)
}

macro_rules! check_sig_ver {
    ($ps_sign: ident, $ps_verify: ident, $messages_as_jsvalue: ident, $sk: ident, $pk: ident, $params: ident) => {
        let sig = $ps_sign($messages_as_jsvalue.clone(), $sk.clone(), $params.clone()).unwrap();
        let result = $ps_verify(
            $messages_as_jsvalue.clone(),
            sig,
            $pk.clone(),
            $params.clone(),
        )
        .unwrap();
        let r: VerifyResponse = serde_wasm_bindgen::from_value(result).unwrap();
        r.validate();
    };
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn ps_params_and_keygen() {
    let message_count = 5;
    let label = b"test-g1".to_vec();
    let params = ps_generate_params(message_count, Some(label)).unwrap();
    assert!(ps_is_params_valid(params.clone()).unwrap());
    assert_eq!(ps_params_max_supported_msgs(params.clone()).unwrap(), 5);

    assert!(ps_is_params_valid(params.clone()).unwrap());
    assert_eq!(ps_params_max_supported_msgs(params.clone()).unwrap(), 5);

    let seed = vec![0, 1, 2, 5, 10, 13];

    let sk = ps_generate_secret_key(message_count, Some(seed.clone())).unwrap();
    let sk_1 = ps_generate_secret_key(message_count, Some(seed)).unwrap();
    assert_eq!(sk.to_vec(), sk_1.to_vec());
    assert_eq!(
        ps_secret_key_supported_msgs(sk.clone()).unwrap(),
        message_count as usize
    );

    let pk = ps_generate_public_key(sk, params.clone()).unwrap();
    assert!(ps_is_pubkey_valid(pk.clone()).unwrap());
    assert_eq!(
        ps_public_key_supported_msgs(pk).unwrap(),
        message_count as usize
    );

    let bytes = ps_signature_params_to_bytes(params.clone()).unwrap();
    let desez_params = ps_signature_params_from_bytes(bytes).unwrap();
    assert!(ps_is_params_valid(desez_params.clone()).unwrap());
    let params_1: PSSignatureParams = serde_wasm_bindgen::from_value(params.clone()).unwrap();
    let params_2: PSSignatureParams = serde_wasm_bindgen::from_value(desez_params).unwrap();
    assert_eq!(params_1, params_2);

    let bytes = ps_signature_params_to_bytes(params.clone()).unwrap();
    let desez_params = ps_signature_params_from_bytes(bytes).unwrap();
    assert!(ps_is_params_valid(desez_params.clone()).unwrap());
    let params_1: PSSignatureParams = serde_wasm_bindgen::from_value(params).unwrap();
    let params_2: PSSignatureParams = serde_wasm_bindgen::from_value(desez_params).unwrap();
    assert_eq!(params_1, params_2);
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn ps_sign_verify() {
    let messages = vec![
        b"Message1".to_vec(),
        b"Message2".to_vec(),
        b"Message3".to_vec(),
        b"Message4".to_vec(),
    ];
    let message_count = messages.len() as u32;

    let (params, sk, pk) = ps_setup(message_count);

    let mut msgs = vec![];
    for i in 1..=message_count {
        if i == 1 {
            // Msg is an integer
            let bytes = field_element_as_bytes(
                field_element_from_number(js_sys::Number::from(1)).unwrap(),
                true,
            )
            .unwrap()
            .to_vec();
            msgs.push(bytes);
        } else {
            // Messages are encoded from text
            let m = format!("Message{}", i).as_bytes().to_vec();
            let bytes = encode_message_for_signing(m).unwrap();
            msgs.push(bytes.to_vec());
        }
    }
    let messages_as_array = encode_messages_for_signing(
        js_array_of_bytearrays_from_vector_of_bytevectors(&msgs).unwrap(),
        None,
    )
    .unwrap();

    check_sig_ver!(ps_sign, ps_verify, messages_as_array, sk, pk, params);
    check_sig_ver!(ps_sign, ps_verify, messages_as_array, sk, pk, params);
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn ps_blind_sign_test() {
    let messages = vec![
        b"Message1".to_vec(),
        b"Message2".to_vec(),
        b"Message3".to_vec(),
        b"Message4".to_vec(),
        b"Message5".to_vec(),
    ];
    let message_count = messages.len() as u32;
    let messages_as_array = encode_messages_for_signing(
        js_array_of_bytearrays_from_vector_of_bytevectors(&messages).unwrap(),
        None,
    )
    .unwrap();
    let (params, sk, pk) = ps_setup(message_count);

    let h = generate_random_g1_element(None).unwrap();
    // Prover commits to message indices 1 and 4
    let committed_indices = [1, 4];
    let blindings: BTreeMap<_, _> = committed_indices
        .iter()
        .copied()
        .map(|idx| (idx, generate_random_field_element(None).unwrap()))
        .collect();
    let msgs: js_sys::Array = messages_as_array
        .iter()
        .enumerate()
        .map(|(idx, msg)| {
            if committed_indices.contains(&idx) {
                let blinding = blindings.get(&idx).unwrap().clone();

                ps_blinded_message(
                    ps_message_commitment(
                        msg.into(),
                        blinding,
                        h.clone(),
                        js_sys::Reflect::get(&params, &"g".into()).unwrap().into(),
                    )
                    .unwrap(),
                )
                .unwrap()
            } else {
                ps_revealed_message(msg.into()).unwrap()
            }
        })
        .collect();

    assert_eq!(committed_indices.len(), committed_indices.len());

    let blind_sig = ps_blind_sign(msgs.into(), sk, h).unwrap();
    let sig = ps_unblind_sig(
        blind_sig,
        blindings
            .into_iter()
            .fold(js_sys::Map::new(), |map, (idx, msg)| {
                map.set(&JsValue::from(idx as u32), &JsValue::from(msg));
                map
            }),
        pk.clone(),
    )
    .unwrap();
    let result = ps_verify(messages_as_array, sig, pk, params).unwrap();
    let r: VerifyResponse = serde_wasm_bindgen::from_value(result).unwrap();
    assert!(r.verified);
    assert!(r.error.is_none());
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn ps_proof_of_knowledge() {
    let message_count = 6;

    let mut messages = vec![];
    for i in 1..=message_count {
        if i == 1 {
            // Msg is an integer
            let bytes = field_element_as_bytes(
                field_element_from_number(js_sys::Number::from(1)).unwrap(),
                true,
            )
            .unwrap()
            .to_vec();
            messages.push(bytes);
        } else {
            // Messages are encoded from text
            let m = format!("Message{}", i).as_bytes().to_vec();
            let bytes = encode_message_for_signing(m).unwrap();
            messages.push(bytes.to_vec());
        }
    }
    // Prover reveals message indices 0 and 2 and supplies blindings for message indices 1, 4 and 5
    let messages_as_array = encode_messages_for_signing(
        js_array_of_bytearrays_from_vector_of_bytevectors(&messages).unwrap(),
        None,
    )
    .unwrap();
    let blindings_for = [1, 3, 4, 5];
    let blindings = js_sys::Map::new();
    let revealed = js_sys::Set::new(&JsValue::undefined());
    let revealed_msgs = js_sys::Map::new();
    for i in 0..messages.len() {
        if blindings_for.contains(&i) {
            blindings.set(
                &JsValue::from(i as u32),
                &generate_random_field_element(None).unwrap(),
            );
        }
        if !blindings_for.contains(&i) {
            revealed.add(&JsValue::from(i as u32));
            revealed_msgs.set(&JsValue::from(i as u32), &messages_as_array.get(i as u32));
        }
    }

    let msgs: js_sys::Array = messages_as_array
        .iter()
        .enumerate()
        .map(|(idx, msg)| {
            if !blindings_for.contains(&idx) {
                ps_reveal_message().unwrap()
            } else {
                let blinding = blindings.get(&JsValue::from(idx as u32));

                ps_blind_message_with_concrete_blinding(msg.into(), blinding.into()).unwrap()
            }
        })
        .collect();

    let (params, sk, pk) = ps_setup(messages.len() as u32);

    let sig = ps_sign(messages_as_array.clone(), sk, params.clone()).unwrap();

    let result = ps_verify(messages_as_array, sig.clone(), pk.clone(), params.clone()).unwrap();

    let r: VerifyResponse = serde_wasm_bindgen::from_value(result).unwrap();
    assert!(r.verified);
    assert!(r.error.is_none());

    let protocol =
        ps_initialize_signature_pok(sig, params.clone(), pk.clone(), msgs.into()).unwrap();

    let prover_bytes = ps_challenge_signature_pok_contribution_from_protocol(
        protocol.clone(),
        pk.clone(),
        params.clone(),
    )
    .unwrap();
    let prover_challenge = generate_challenge_from_bytes(prover_bytes.to_vec());

    let proof = ps_gen_sig_proof(protocol, prover_challenge.clone()).unwrap();

    let verifier_bytes = ps_challenge_signature_pok_contribution_from_proof(
        proof.clone(),
        pk.clone(),
        params.clone(),
    )
    .unwrap();
    let verifier_challenge = generate_challenge_from_bytes(verifier_bytes.to_vec());

    assert_eq!(prover_challenge.to_vec(), verifier_challenge.to_vec());

    let result =
        ps_verify_signature_proof(proof, revealed_msgs, verifier_challenge, pk, params).unwrap();
    let r: VerifyResponse = serde_wasm_bindgen::from_value(result).unwrap();
    r.validate();
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn ps_extend_params() {
    let message_count = 1;

    let label = b"test-g1".to_vec();

    let params = ps_generate_params(message_count, Some(label.clone())).unwrap();

    assert_eq!(
        ps_params_max_supported_msgs(params.clone()).unwrap(),
        message_count as usize
    );
    assert_eq!(
        ps_params_max_supported_msgs(params.clone()).unwrap(),
        message_count as usize
    );

    let new_message_count = 5;

    let params_1 = ps_adapt_sig_params_for_msg_count(
        params.clone(),
        js_sys::Uint8Array::from(label.as_slice()),
        new_message_count,
    )
    .unwrap();

    assert_eq!(
        ps_params_max_supported_msgs(params_1.clone()).unwrap(),
        new_message_count
    );
    assert_eq!(
        ps_params_max_supported_msgs(params_1.clone()).unwrap(),
        new_message_count
    );

    assert_eq!(
        serde_wasm_bindgen::from_value::<PSSignatureParams>(params.clone())
            .unwrap()
            .h[0],
        serde_wasm_bindgen::from_value::<PSSignatureParams>(params_1.clone())
            .unwrap()
            .h[0],
    );
    assert_eq!(
        serde_wasm_bindgen::from_value::<PSSignatureParams>(params)
            .unwrap()
            .h[0],
        serde_wasm_bindgen::from_value::<PSSignatureParams>(params_1.clone())
            .unwrap()
            .h[0],
    );

    let new_message_count = 2;

    let params_2 = ps_adapt_sig_params_for_msg_count(
        params_1.clone(),
        js_sys::Uint8Array::from(label.as_slice()),
        new_message_count,
    )
    .unwrap();

    assert_eq!(
        ps_params_max_supported_msgs(params_2.clone()).unwrap(),
        new_message_count
    );
    assert_eq!(
        ps_params_max_supported_msgs(params_2.clone()).unwrap(),
        new_message_count
    );

    assert_eq!(
        serde_wasm_bindgen::from_value::<PSSignatureParams>(params_1.clone())
            .unwrap()
            .h[0],
        serde_wasm_bindgen::from_value::<PSSignatureParams>(params_2.clone())
            .unwrap()
            .h[0],
    );
    assert_eq!(
        serde_wasm_bindgen::from_value::<PSSignatureParams>(params_1.clone())
            .unwrap()
            .h[1],
        serde_wasm_bindgen::from_value::<PSSignatureParams>(params_2.clone())
            .unwrap()
            .h[1],
    );
    assert_eq!(
        serde_wasm_bindgen::from_value::<PSSignatureParams>(params_1.clone())
            .unwrap()
            .h[0],
        serde_wasm_bindgen::from_value::<PSSignatureParams>(params_2.clone())
            .unwrap()
            .h[0],
    );
    assert_eq!(
        serde_wasm_bindgen::from_value::<PSSignatureParams>(params_1.clone())
            .unwrap()
            .h[1],
        serde_wasm_bindgen::from_value::<PSSignatureParams>(params_2)
            .unwrap()
            .h[1],
    );

    let messages = vec![
        b"Message1".to_vec(),
        b"Message2".to_vec(),
        b"Message3".to_vec(),
        b"Message4".to_vec(),
        b"Message5".to_vec(),
    ];
    let messages_as_array = encode_messages_for_signing(
        js_array_of_bytearrays_from_vector_of_bytevectors(&messages).unwrap(),
        None,
    )
    .unwrap();

    let sk = ps_generate_secret_key(messages.len() as u32, None).unwrap();

    let pk = ps_generate_public_key(sk.clone(), params_1.clone()).unwrap();

    check_sig_ver!(ps_sign, ps_verify, messages_as_array, sk, pk, params_1);

    check_sig_ver!(ps_sign, ps_verify, messages_as_array, sk, pk, params_1);
}
