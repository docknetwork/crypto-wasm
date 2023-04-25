#![cfg(target_arch = "wasm32")]
extern crate wasm_bindgen_test;

use js_sys::Uint8Array;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

use dock_crypto_wasm::bbs::*;
use dock_crypto_wasm::common::{
    field_element_as_bytes, field_element_from_number, generate_challenge_from_bytes,
    generate_random_field_element, VerifyResponse,
};
use dock_crypto_wasm::utils::js_array_of_bytearrays_from_vector_of_bytevectors;

wasm_bindgen_test_configure!(run_in_browser);

fn js_value_to_bytes(js_value: JsValue) -> Vec<u8> {
    serde_wasm_bindgen::from_value::<Vec<u8>>(js_value).unwrap()
}

fn bbs_setup(message_count: usize) -> (JsValue, Uint8Array, Uint8Array) {
    let label = b"test-g1".to_vec();
    let params = bbs_generate_params(message_count, Some(label)).unwrap();

    let seed = vec![0, 1, 2, 5, 10, 13];

    let sk = bbs_generate_secret_key(Some(seed.clone())).unwrap();

    let pk = bbs_generate_public_key(sk.clone(), params.clone()).unwrap();

    (params, sk, pk)
}

macro_rules! check_sig_ver {
    ($bbs_sign: ident, $bbs_verify: ident, $messages_as_jsvalue: ident, $sk: ident, $pk: ident, $params: ident, $encode: ident) => {
        let sig = $bbs_sign(
            $messages_as_jsvalue.clone(),
            $sk.clone(),
            $params.clone(),
            $encode,
        )
        .unwrap();
        let result = $bbs_verify(
            $messages_as_jsvalue.clone(),
            sig,
            $pk.clone(),
            $params.clone(),
            $encode,
        )
        .unwrap();
        let r: VerifyResponse = serde_wasm_bindgen::from_value(result).unwrap();
        r.validate();
    };
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn bbs_params_and_keygen() {
    let message_count = 5;
    let label = b"test-g1".to_vec();
    let params = bbs_generate_params(message_count, Some(label)).unwrap();
    assert!(bbs_is_params_valid(params.clone()).unwrap());
    assert_eq!(bbs_params_max_supported_msgs(params.clone()).unwrap(), 5);

    let seed = vec![0, 1, 2, 5, 10, 13];

    let keypair = bbs_generate_keypair(params.clone(), Some(seed.clone())).unwrap();

    let keypair_obj = js_sys::Object::try_from(&keypair).unwrap();

    let keys = js_sys::Object::keys(&keypair_obj);
    assert_eq!(keys.get(0), "secret_key");
    assert_eq!(keys.get(1), "public_key");

    let sk = bbs_generate_secret_key(Some(seed.clone())).unwrap();
    let sk_1 = bbs_generate_secret_key(Some(seed)).unwrap();
    assert_eq!(sk.to_vec(), sk_1.to_vec());

    let pk = bbs_generate_public_key(sk.clone(), params.clone()).unwrap();
    assert!(bbs_is_pubkey_valid(pk.clone()).unwrap());

    let values_obj = js_sys::Object::values(&keypair_obj);
    assert_eq!(js_value_to_bytes(values_obj.get(0)), sk.to_vec());
    assert_eq!(js_value_to_bytes(values_obj.get(1)), pk.to_vec());

    let bytes = bbs_params_to_bytes(params.clone()).unwrap();
    let desez_params = bbs_params_from_bytes(bytes).unwrap();
    assert!(bbs_is_params_valid(desez_params.clone()).unwrap());
    let params_1: BBSSigParams = serde_wasm_bindgen::from_value(params).unwrap();
    let params_2: BBSSigParams = serde_wasm_bindgen::from_value(desez_params).unwrap();
    assert_eq!(params_1, params_2);
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn bbs_sign_verify() {
    let messages = vec![
        b"Message1".to_vec(),
        b"Message2".to_vec(),
        b"Message3".to_vec(),
        b"Message4".to_vec(),
    ];
    let message_count = messages.len();
    let messages_as_array = js_array_of_bytearrays_from_vector_of_bytevectors(&messages).unwrap();

    let (params, sk, pk) = bbs_setup(message_count);

    check_sig_ver!(
        bbs_sign,
        bbs_verify,
        messages_as_array,
        sk,
        pk,
        params,
        true
    );

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
            let bytes = bbs_encode_message_for_signing(m).unwrap();
            msgs.push(bytes.to_vec());
        }
    }
    let messages_as_array = js_array_of_bytearrays_from_vector_of_bytevectors(&msgs).unwrap();

    check_sig_ver!(
        bbs_sign,
        bbs_verify,
        messages_as_array,
        sk,
        pk,
        params,
        false
    );
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn bbs_blind_sign_test() {
    let messages = vec![
        b"Message1".to_vec(),
        b"Message2".to_vec(),
        b"Message3".to_vec(),
        b"Message4".to_vec(),
        b"Message5".to_vec(),
    ];
    let message_count = messages.len();
    let messages_as_array = js_array_of_bytearrays_from_vector_of_bytevectors(&messages).unwrap();
    let (params, sk, pk) = bbs_setup(message_count);

    // Prover commits to message indices 1 and 4
    let committed_indices = [1, 4];
    let msgs_to_commit = js_sys::Map::new();
    let msgs_to_not_commit = js_sys::Map::new();
    for i in 0..message_count {
        if committed_indices.contains(&i) {
            msgs_to_commit.set(
                &JsValue::from(i as u32),
                &serde_wasm_bindgen::to_value(&messages[i]).unwrap(),
            );
        } else {
            msgs_to_not_commit.set(
                &JsValue::from(i as u32),
                &serde_wasm_bindgen::to_value(&messages[i]).unwrap(),
            );
        }
    }

    assert_eq!(msgs_to_commit.size() as usize, committed_indices.len());
    assert_eq!(
        msgs_to_not_commit.size() as usize,
        message_count - committed_indices.len()
    );

    let blinding = generate_random_field_element(None).unwrap();

    let commitment = bbs_commit_to_message(
        msgs_to_commit.clone(),
        blinding.clone(),
        params.clone(),
        true,
    )
    .unwrap();
    let sig = bbs_blind_sign(
        commitment,
        msgs_to_not_commit.clone(),
        sk.clone(),
        params.clone(),
        true,
    )
    .unwrap();
    let result = bbs_verify(messages_as_array.clone(), sig, pk, params, true).unwrap();
    let r: VerifyResponse = serde_wasm_bindgen::from_value(result).unwrap();
    assert!(r.verified);
    assert!(r.error.is_none());
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn bbs_proof_of_knowledge() {
    macro_rules! check {
        ($messages: ident, $messages_as_jsvalue: ident, $encode: ident) => {
            let (params, sk, pk) = bbs_setup($messages.len());

            let sig = bbs_sign(
                $messages_as_jsvalue.clone(),
                sk.clone(),
                params.clone(),
                $encode,
            ).unwrap();
            let result = bbs_verify(
                $messages_as_jsvalue.clone(),
                sig.clone(),
                pk.clone(),
                params.clone(),
                $encode,
            ).unwrap();
            let r: VerifyResponse = serde_wasm_bindgen::from_value(result).unwrap();
            assert!(r.verified);
            assert!(r.error.is_none());

            // Prover reveals message indices 0 and 2 and supplies blindings for message indices 1, 4 and 5
            let revealed_indices = [0, 2];
            let blindings_for = [1, 4, 5];
            let blindings = js_sys::Map::new();
            let revealed = js_sys::Set::new(&JsValue::undefined());
            let revealed_msgs = js_sys::Map::new();
            for i in 0..$messages.len() {
                if blindings_for.contains(&i) {
                    blindings.set(
                        &JsValue::from(i as u32),
                        &generate_random_field_element(None).unwrap(),
                    );
                }
                if revealed_indices.contains(&i) {
                    revealed.add(&JsValue::from(i as u32));
                    revealed_msgs.set(
                        &JsValue::from(i as u32),
                        &serde_wasm_bindgen::to_value(&$messages[i]).unwrap(),
                    );
                }
            }

            let protocol = bbs_initialize_proof_of_knowledge_of_signature(
                sig,
                params.clone(),
                $messages_as_jsvalue,
                blindings,
                revealed,
                $encode,
            ).unwrap();

            let prover_bytes = bbs_challenge_contribution_from_protocol(
                protocol.clone(),
                revealed_msgs.clone(),
                params.clone(),
                $encode,
            ).unwrap();
            let prover_challenge = generate_challenge_from_bytes(prover_bytes.to_vec());

            let proof = bbs_gen_proof(protocol, prover_challenge.clone()).unwrap();

            let verifier_bytes = bbs_challenge_contribution_from_proof(
                proof.clone(),
                revealed_msgs.clone(),
                params.clone(),
                $encode,
            ).unwrap();
            let verifier_challenge = generate_challenge_from_bytes(verifier_bytes.to_vec());

            assert_eq!(
                prover_challenge.to_vec(),
                verifier_challenge.to_vec()
            );

            let result = bbs_verify_proof(proof, revealed_msgs, verifier_challenge, pk, params, $encode).unwrap();
            let r: VerifyResponse = serde_wasm_bindgen::from_value(result).unwrap();
            r.validate();
        };
    }

    let message_count = 6;

    let messages = vec![
        b"Message1".to_vec(),
        b"Message2".to_vec(),
        b"Message3".to_vec(),
        b"Message4".to_vec(),
        b"Message5".to_vec(),
        b"Message6".to_vec(),
    ];
    let messages_as_array = js_array_of_bytearrays_from_vector_of_bytevectors(&messages).unwrap();

    check!(messages, messages_as_array, true);

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
            let bytes = bbs_encode_message_for_signing(m).unwrap();
            messages.push(bytes.to_vec());
        }
    }
    let messages_as_array = js_array_of_bytearrays_from_vector_of_bytevectors(&messages).unwrap();

    check!(messages, messages_as_array, false);
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn bbs_extend_params() {
    let message_count = 1;

    let label = b"test-g1".to_vec();

    let params = bbs_generate_params(message_count, Some(label.clone())).unwrap();

    assert_eq!(
        bbs_params_max_supported_msgs(params.clone()).unwrap(),
        message_count
    );

    let new_message_count = 5;

    let params_1 = bbs_adapt_sig_params_for_msg_count(
        params.clone(),
        js_sys::Uint8Array::from(label.as_slice()),
        new_message_count,
    )
    .unwrap();

    assert_eq!(
        bbs_params_max_supported_msgs(params_1.clone()).unwrap(),
        new_message_count
    );

    assert_eq!(
        serde_wasm_bindgen::from_value::<BBSSigParams>(params.clone())
            .unwrap()
            .h[0],
        serde_wasm_bindgen::from_value::<BBSSigParams>(params_1.clone())
            .unwrap()
            .h[0],
    );

    let new_message_count = 2;

    let params_2 = bbs_adapt_sig_params_for_msg_count(
        params_1.clone(),
        js_sys::Uint8Array::from(label.as_slice()),
        new_message_count,
    )
    .unwrap();

    assert_eq!(
        bbs_params_max_supported_msgs(params_2.clone()).unwrap(),
        new_message_count
    );

    assert_eq!(
        serde_wasm_bindgen::from_value::<BBSSigParams>(params_1.clone())
            .unwrap()
            .h[0],
        serde_wasm_bindgen::from_value::<BBSSigParams>(params_2.clone())
            .unwrap()
            .h[0],
    );
    assert_eq!(
        serde_wasm_bindgen::from_value::<BBSSigParams>(params_1.clone())
            .unwrap()
            .h[1],
        serde_wasm_bindgen::from_value::<BBSSigParams>(params_2.clone())
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
    let messages_as_array = js_array_of_bytearrays_from_vector_of_bytevectors(&messages).unwrap();

    let sk = bbs_generate_secret_key(None).unwrap();

    let pk = bbs_generate_public_key(sk.clone(), params_1.clone()).unwrap();

    check_sig_ver!(
        bbs_sign,
        bbs_verify,
        messages_as_array,
        sk,
        pk,
        params_1,
        true
    );
}
