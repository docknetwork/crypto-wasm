#![cfg(target_arch = "wasm32")]
extern crate wasm_bindgen_test;

use wasm::common::{
    field_element_as_bytes, field_element_from_number, generate_challenge_from_bytes,
    generate_random_field_element, VerifyResponse,
};
use wasm::bbs_plus::*;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

fn js_value_to_bytes(js_value: JsValue) -> Vec<u8> {
    serde_wasm_bindgen::from_value::<Vec<u8>>(js_value).unwrap()
}

async fn bbs_setup(message_count: usize) -> (JsValue, JsValue, JsValue, JsValue, JsValue) {
    let label_g1 = b"test-g1".to_vec();
    let label_g2 = b"test-g2".to_vec();
    let params_g1 = bbs_generate_g1_params(message_count, Some(label_g1))
        .await
        .unwrap();
    let params_g2 = bbs_generate_g2_params(message_count, Some(label_g2))
        .await
        .unwrap();

    let seed = vec![0, 1, 2, 5, 10, 13];

    let sk = bbs_generate_secret_key(Some(seed.clone())).await.unwrap();

    let pk_g1 = bbs_generate_public_key_g1(sk.clone(), params_g2.clone())
        .await
        .unwrap();
    let pk_g2 = bbs_generate_public_key_g2(sk.clone(), params_g1.clone())
        .await
        .unwrap();

    (params_g1, params_g2, sk, pk_g1, pk_g2)
}

macro_rules! check_sig_ver {
    ($bbs_sign: ident, $bbs_verify: ident, $messages_as_jsvalue: ident, $sk: ident, $pk: ident, $params: ident, $encode: ident) => {
        let sig = $bbs_sign(
            $messages_as_jsvalue.clone(),
            $sk.clone(),
            $params.clone(),
            $encode,
        )
        .await
        .unwrap();
        let result = $bbs_verify(
            $messages_as_jsvalue.clone(),
            sig,
            $pk.clone(),
            $params.clone(),
            $encode,
        )
        .await
        .unwrap();
        let r: VerifyResponse = serde_wasm_bindgen::from_value(result).unwrap();
        r.validate();
    };
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub async fn bbs_params_and_keygen() {
    let message_count = 5;
    let label_g1 = b"test-g1".to_vec();
    let label_g2 = b"test-g2".to_vec();
    let params_g1 = bbs_generate_g1_params(message_count, Some(label_g1))
        .await
        .unwrap();
    assert!(bbs_is_params_g1_valid(params_g1.clone()).await.unwrap());
    assert_eq!(
        bbs_params_g1_max_supported_msgs(params_g1.clone())
            .await
            .unwrap(),
        5
    );

    let params_g2 = bbs_generate_g2_params(message_count, Some(label_g2))
        .await
        .unwrap();
    assert!(bbs_is_params_g2_valid(params_g2.clone()).await.unwrap());
    assert_eq!(
        bbs_params_g2_max_supported_msgs(params_g2.clone())
            .await
            .unwrap(),
        5
    );

    let seed = vec![0, 1, 2, 5, 10, 13];

    let keypair_g1 = bbs_generate_g1_keypair(params_g2.clone(), Some(seed.clone()))
        .await
        .unwrap();
    let keypair_g2 = bbs_generate_g2_keypair(params_g1.clone(), Some(seed.clone()))
        .await
        .unwrap();

    let keypair_g1_obj = js_sys::Object::try_from(&keypair_g1).unwrap();
    let keypair_g2_obj = js_sys::Object::try_from(&keypair_g2).unwrap();

    let keys = js_sys::Object::keys(&keypair_g1_obj);
    assert_eq!(keys.get(0), "secret_key");
    assert_eq!(keys.get(1), "public_key");

    let keys = js_sys::Object::keys(&keypair_g2_obj);
    assert_eq!(keys.get(0), "secret_key");
    assert_eq!(keys.get(1), "public_key");

    let sk = bbs_generate_secret_key(Some(seed.clone())).await.unwrap();
    let sk_1 = bbs_generate_secret_key(Some(seed)).await.unwrap();
    assert_eq!(js_value_to_bytes(sk.clone()), js_value_to_bytes(sk_1));

    let pk_g1 = bbs_generate_public_key_g1(sk.clone(), params_g2.clone())
        .await
        .unwrap();
    assert!(bbs_is_pubkey_g1_valid(pk_g1.clone()).await.unwrap());
    let pk_g2 = bbs_generate_public_key_g2(sk.clone(), params_g1.clone())
        .await
        .unwrap();
    assert!(bbs_is_pubkey_g2_valid(pk_g2.clone()).await.unwrap());

    let values_g1_obj = js_sys::Object::values(&keypair_g1_obj);
    // assert_eq!(values_g1_obj.get(0), pk_g1);
    // assert_eq!(values_g1_obj.get(1), sk);
    assert_eq!(
        js_value_to_bytes(values_g1_obj.get(0)),
        js_value_to_bytes(sk.clone())
    );
    assert_eq!(
        js_value_to_bytes(values_g1_obj.get(1)),
        js_value_to_bytes(pk_g1.clone())
    );

    let values_g2_obj = js_sys::Object::values(&keypair_g2_obj);
    assert_eq!(
        js_value_to_bytes(values_g2_obj.get(0)),
        js_value_to_bytes(sk.clone())
    );
    assert_eq!(
        js_value_to_bytes(values_g2_obj.get(1)),
        js_value_to_bytes(pk_g2.clone())
    );
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub async fn bbs_sign_verify() {
    let messages = vec![
        b"Message1".to_vec(),
        b"Message2".to_vec(),
        b"Message3".to_vec(),
        b"Message4".to_vec(),
    ];
    let message_count = messages.len();
    let messages_as_jsvalue = serde_wasm_bindgen::to_value(&messages).unwrap();

    let (params_g1, params_g2, sk, pk_g1, pk_g2) = bbs_setup(message_count).await;

    check_sig_ver!(
        bbs_sign_g1,
        bbs_verify_g1,
        messages_as_jsvalue,
        sk,
        pk_g2,
        params_g1,
        true
    );
    check_sig_ver!(
        bbs_sign_g2,
        bbs_verify_g2,
        messages_as_jsvalue,
        sk,
        pk_g1,
        params_g2,
        true
    );

    let mut msgs = vec![];
    for i in 1..=message_count {
        if i == 1 {
            // Msg is an integer
            let bytes = field_element_as_bytes(field_element_from_number(1).await)
                .await
                .unwrap()
                .to_vec();
            msgs.push(bytes);
        } else {
            // Messages are encoded from text
            let m = format!("Message{}", i).as_bytes().to_vec();
            let encoded = bbs_encode_message_for_signing(m).await.unwrap();
            let bytes: Vec<u8> = serde_wasm_bindgen::from_value(encoded).unwrap();
            msgs.push(bytes);
        }
    }
    let messages_as_jsvalue = serde_wasm_bindgen::to_value(&msgs).unwrap();

    check_sig_ver!(
        bbs_sign_g1,
        bbs_verify_g1,
        messages_as_jsvalue,
        sk,
        pk_g2,
        params_g1,
        false
    );
    check_sig_ver!(
        bbs_sign_g2,
        bbs_verify_g2,
        messages_as_jsvalue,
        sk,
        pk_g1,
        params_g2,
        false
    );
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub async fn bbs_blind_sign() {
    let messages = vec![
        b"Message1".to_vec(),
        b"Message2".to_vec(),
        b"Message3".to_vec(),
        b"Message4".to_vec(),
        b"Message5".to_vec(),
    ];
    let message_count = messages.len();
    let messages_as_jsvalue = serde_wasm_bindgen::to_value(&messages).unwrap();
    let (params_g1, params_g2, sk, pk_g1, pk_g2) = bbs_setup(message_count).await;

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

    let blinding = generate_random_field_element(None).await.unwrap();

    let commitment_g1 = bbs_commit_to_message_in_g1(
        msgs_to_commit.clone(),
        blinding.clone(),
        params_g1.clone(),
        true,
    )
    .await
    .unwrap();
    let blind_sig_g1 = bbs_blind_sign_g1(
        commitment_g1,
        msgs_to_not_commit.clone(),
        sk.clone(),
        params_g1.clone(),
        true,
    )
    .await
    .unwrap();
    let sig_g1 = bbs_unblind_sig_g1(blind_sig_g1, blinding.clone())
        .await
        .unwrap();
    let result = bbs_verify_g1(messages_as_jsvalue.clone(), sig_g1, pk_g2, params_g1, true)
        .await
        .unwrap();
    let r: VerifyResponse = serde_wasm_bindgen::from_value(result).unwrap();
    assert!(r.verified);
    assert!(r.error.is_none());

    let commitment_g2 = bbs_commit_to_message_in_g2(
        msgs_to_commit.clone(),
        blinding.clone(),
        params_g2.clone(),
        true,
    )
    .await
    .unwrap();
    let blind_sig_g2 = bbs_blind_sign_g2(
        commitment_g2,
        msgs_to_not_commit.clone(),
        sk.clone(),
        params_g2.clone(),
        true,
    )
    .await
    .unwrap();
    let sig_g2 = bbs_unblind_sig_g2(blind_sig_g2, blinding.clone())
        .await
        .unwrap();
    let result = bbs_verify_g2(messages_as_jsvalue, sig_g2, pk_g1, params_g2, true)
        .await
        .unwrap();
    let r: VerifyResponse = serde_wasm_bindgen::from_value(result).unwrap();
    assert!(r.verified);
    assert!(r.error.is_none());
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub async fn bbs_proof_of_knowledge() {
    macro_rules! check {
        ($messages: ident, $messages_as_jsvalue: ident, $encode: ident) => {
            let (params, _, sk, _, pk) = bbs_setup($messages.len()).await;

            let sig = bbs_sign_g1(
                $messages_as_jsvalue.clone(),
                sk.clone(),
                params.clone(),
                $encode,
            )
            .await
            .unwrap();
            let result = bbs_verify_g1(
                $messages_as_jsvalue.clone(),
                sig.clone(),
                pk.clone(),
                params.clone(),
                $encode,
            )
            .await
            .unwrap();
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
                        &generate_random_field_element(None).await.unwrap(),
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
            )
            .await
            .unwrap();

            let prover_bytes = bbs_challenge_contribution_from_protocol(
                protocol.clone(),
                revealed_msgs.clone(),
                params.clone(),
                $encode,
            )
            .await
            .unwrap();
            let prover_challenge = generate_challenge_from_bytes(prover_bytes.to_vec()).await;

            let proof = bbs_gen_proof(protocol, prover_challenge.clone())
                .await
                .unwrap();

            let verifier_bytes = bbs_challenge_contribution_from_proof(
                proof.clone(),
                revealed_msgs.clone(),
                params.clone(),
                $encode,
            )
            .await
            .unwrap();
            let verifier_challenge = generate_challenge_from_bytes(verifier_bytes.to_vec()).await;

            assert_eq!(
                js_value_to_bytes(prover_challenge),
                js_value_to_bytes(verifier_challenge.clone())
            );

            let result = bbs_verify_proof(proof, revealed_msgs, verifier_challenge, pk, params, $encode)
                .await
                .unwrap();
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
    let messages_as_jsvalue = serde_wasm_bindgen::to_value(&messages).unwrap();

    check!(messages, messages_as_jsvalue, true);

    let mut messages = vec![];
    for i in 1..=message_count {
        if i == 1 {
            // Msg is an integer
            let bytes = field_element_as_bytes(field_element_from_number(1).await)
                .await
                .unwrap()
                .to_vec();
            messages.push(bytes);
        } else {
            // Messages are encoded from text
            let m = format!("Message{}", i).as_bytes().to_vec();
            let encoded = bbs_encode_message_for_signing(m).await.unwrap();
            let bytes: Vec<u8> = serde_wasm_bindgen::from_value(encoded).unwrap();
            messages.push(bytes);
        }
    }
    let messages_as_jsvalue = serde_wasm_bindgen::to_value(&messages).unwrap();

    check!(messages, messages_as_jsvalue, false);
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub async fn bbs_extend_params() {
    let message_count = 1;

    let label_g1 = b"test-g1".to_vec();
    let label_g2 = b"test-g2".to_vec();

    let params_g1 = bbs_generate_g1_params(message_count, Some(label_g1.clone()))
        .await
        .unwrap();
    let params_g2 = bbs_generate_g2_params(message_count, Some(label_g2.clone()))
        .await
        .unwrap();

    assert_eq!(
        bbs_params_g1_max_supported_msgs(params_g1.clone())
            .await
            .unwrap(),
        message_count as u32
    );
    assert_eq!(
        bbs_params_g2_max_supported_msgs(params_g2.clone())
            .await
            .unwrap(),
        message_count as u32
    );

    let new_message_count = 5;

    let params_g1_1 = extend_sig_params_g1_for_msg_count(
        params_g1.clone(),
        js_sys::Uint8Array::from(label_g1.as_slice()),
        new_message_count,
    )
    .await
    .unwrap();
    let params_g2_1 = extend_sig_params_g2_for_msg_count(
        params_g2.clone(),
        js_sys::Uint8Array::from(label_g2.as_slice()),
        new_message_count,
    )
    .await
    .unwrap();

    assert_eq!(
        bbs_params_g1_max_supported_msgs(params_g1_1.clone())
            .await
            .unwrap(),
        new_message_count as u32
    );
    assert_eq!(
        bbs_params_g2_max_supported_msgs(params_g2_1.clone())
            .await
            .unwrap(),
        new_message_count as u32
    );

    assert_eq!(
        serde_wasm_bindgen::from_value::<SigParamsG1>(params_g1.clone())
            .unwrap()
            .h[0],
        serde_wasm_bindgen::from_value::<SigParamsG1>(params_g1_1.clone())
            .unwrap()
            .h[0],
    );
    assert_eq!(
        serde_wasm_bindgen::from_value::<SigParamsG2>(params_g2.clone())
            .unwrap()
            .h[0],
        serde_wasm_bindgen::from_value::<SigParamsG2>(params_g2_1.clone())
            .unwrap()
            .h[0],
    );

    let new_message_count = 2;

    let params_g1_2 = extend_sig_params_g1_for_msg_count(
        params_g1_1.clone(),
        js_sys::Uint8Array::from(label_g1.as_slice()),
        new_message_count,
    )
    .await
    .unwrap();
    let params_g2_2 = extend_sig_params_g2_for_msg_count(
        params_g2_1.clone(),
        js_sys::Uint8Array::from(label_g2.as_slice()),
        new_message_count,
    )
    .await
    .unwrap();

    assert_eq!(
        bbs_params_g1_max_supported_msgs(params_g1_2.clone())
            .await
            .unwrap(),
        new_message_count as u32
    );
    assert_eq!(
        bbs_params_g2_max_supported_msgs(params_g2_2.clone())
            .await
            .unwrap(),
        new_message_count as u32
    );

    assert_eq!(
        serde_wasm_bindgen::from_value::<SigParamsG1>(params_g1_1.clone())
            .unwrap()
            .h[0],
        serde_wasm_bindgen::from_value::<SigParamsG1>(params_g1_2.clone())
            .unwrap()
            .h[0],
    );
    assert_eq!(
        serde_wasm_bindgen::from_value::<SigParamsG1>(params_g1_1.clone())
            .unwrap()
            .h[1],
        serde_wasm_bindgen::from_value::<SigParamsG1>(params_g1_2.clone())
            .unwrap()
            .h[1],
    );
    assert_eq!(
        serde_wasm_bindgen::from_value::<SigParamsG2>(params_g2_1.clone())
            .unwrap()
            .h[0],
        serde_wasm_bindgen::from_value::<SigParamsG2>(params_g2_2.clone())
            .unwrap()
            .h[0],
    );
    assert_eq!(
        serde_wasm_bindgen::from_value::<SigParamsG2>(params_g2_1.clone())
            .unwrap()
            .h[1],
        serde_wasm_bindgen::from_value::<SigParamsG2>(params_g2_2.clone())
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
    let messages_as_jsvalue = serde_wasm_bindgen::to_value(&messages).unwrap();

    let sk = bbs_generate_secret_key(None).await.unwrap();

    let pk_g1 = bbs_generate_public_key_g1(sk.clone(), params_g2_1.clone())
        .await
        .unwrap();
    let pk_g2 = bbs_generate_public_key_g2(sk.clone(), params_g1_1.clone())
        .await
        .unwrap();

    check_sig_ver!(
        bbs_sign_g1,
        bbs_verify_g1,
        messages_as_jsvalue,
        sk,
        pk_g2,
        params_g1_1,
        true
    );

    check_sig_ver!(
        bbs_sign_g2,
        bbs_verify_g2,
        messages_as_jsvalue,
        sk,
        pk_g1,
        params_g2_1,
        true
    );
}
