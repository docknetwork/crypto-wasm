#![cfg(target_arch = "wasm32")]
extern crate wasm_bindgen_test;

use ark_std::{collections::BTreeSet, vec};
use wasm_bindgen_test::*;
use web_sys::console;

use dock_crypto_wasm::{
    bbs_plus::bbs_plus_sign_g1,
    bound_check::*,
    common::{encode_message_for_signing, VerifyResponse},
    composite_proof_system::{
        generate_bound_check_witness, generate_composite_proof_g1_with_deconstructed_proof_spec,
        generate_pok_bbs_plus_sig_witness, verify_composite_proof_g1_with_deconstructed_proof_spec,
    },
    utils::{
        field_element_from_u32, fr_to_uint8_array,
        js_array_of_bytearrays_from_vector_of_bytevectors, random_bytes,
    },
};

mod common;
use common::{bbs_params_and_keys, get_revealed_unrevealed, get_witness_equality_statement};
use dock_crypto_wasm::{
    composite_proof_system::statements::{
        bound_check::get_valid_min_max, generate_bound_check_lego_prover_statement,
        generate_bound_check_lego_verifier_statement, generate_pok_bbs_plus_sig_verifier_statement,
    },
    legosnark::{legosnark_decompress_pk, legosnark_vk_from_pk},
};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
pub fn min_max_values() {
    assert!(get_valid_min_max(js_sys::Number::from(-1i32), js_sys::Number::from(120i32)).is_err());
    assert!(get_valid_min_max(js_sys::Number::from(100i32), js_sys::Number::from(-5i32)).is_err());
    assert!(
        get_valid_min_max(js_sys::Number::from(100.1f32), js_sys::Number::from(200i32)).is_err()
    );
    assert!(
        get_valid_min_max(js_sys::Number::from(100i32), js_sys::Number::from(200.3f32)).is_err()
    );
    assert!(get_valid_min_max(
        js_sys::Number::from(100.1f32),
        js_sys::Number::from(200.3f32)
    )
    .is_err());

    for (i, j) in [
        (100, 500),
        (250000000, 60000000),
        (4294967300, 4294967306),
        (1641067913601, 1641087913601),
    ] {
        let (min, max) = get_valid_min_max(
            js_sys::Number::from(i as f64),
            js_sys::Number::from(j as f64),
        )
        .unwrap();
        assert_eq!((min, max), (i, j));
    }
}

#[wasm_bindgen_test]
pub fn bbs_sig_and_bound_check_message() {
    let msg_count = 5;
    let (params, sk, pk) = bbs_params_and_keys(msg_count as u32);
    let mut encoded_msgs = vec![];

    let bounded_msg_idx = 3usize;

    let min = js_sys::Number::from(100);
    let msg = 105;
    let max = js_sys::Number::from(120);
    for i in 0..msg_count {
        let byte_array = if i == bounded_msg_idx {
            fr_to_uint8_array(&field_element_from_u32(msg)).unwrap()
        } else {
            let m = random_bytes();
            encode_message_for_signing(m).unwrap()
        };
        encoded_msgs.push(byte_array.to_vec());
    }

    let messages_as_array =
        js_array_of_bytearrays_from_vector_of_bytevectors(&encoded_msgs).unwrap();
    let sig = bbs_plus_sign_g1(messages_as_array, sk, params.clone(), false).unwrap();
    let mut revealed_indices = BTreeSet::new();
    revealed_indices.insert(0);
    let (revealed_msgs, unrevealed_msgs) =
        get_revealed_unrevealed(&encoded_msgs, &revealed_indices);

    console::time_with_label("setup");
    let snark_pk = bound_check_snark_setup(false).unwrap();
    console::time_end_with_label("setup");

    console::time_with_label("extract vk");
    let snark_vk_decom = legosnark_vk_from_pk(snark_pk.clone(), true).unwrap();
    console::time_end_with_label("extract vk");

    console::time_with_label("pk decompresssion");
    let snark_pk_decom = legosnark_decompress_pk(snark_pk).unwrap();
    console::time_end_with_label("pk decompresssion");

    // Create statements
    let stmt_1 =
        generate_pok_bbs_plus_sig_verifier_statement(params, pk, revealed_msgs, false).unwrap();
    console::time_with_label("bound check prover stmt");
    let prover_stmt_2 =
        generate_bound_check_lego_prover_statement(min.clone(), max.clone(), snark_pk_decom, true)
            .unwrap();
    console::time_end_with_label("bound check verifier stmt");

    let prover_statements = js_sys::Array::new();
    prover_statements.push(&stmt_1);
    prover_statements.push(&prover_stmt_2);

    let meta_statements = js_sys::Array::new();
    // statement 0's `bounded_msg_idx`th index = statement 1st's 0th index
    let meta_statement = get_witness_equality_statement(vec![(0, bounded_msg_idx as u32), (1, 0)]);
    meta_statements.push(&meta_statement);

    let context = Some("test-context".as_bytes().to_vec());

    let witness_1 = generate_pok_bbs_plus_sig_witness(sig, unrevealed_msgs, false).unwrap();
    let witness_2 = generate_bound_check_witness(js_sys::Uint8Array::from(
        encoded_msgs[bounded_msg_idx].as_slice(),
    ))
    .unwrap();
    let witnesses = js_sys::Array::new();
    witnesses.push(&witness_1);
    witnesses.push(&witness_2);

    let nonce = Some("test-nonce".as_bytes().to_vec());

    console::time_with_label("proof gen");
    let proof = generate_composite_proof_g1_with_deconstructed_proof_spec(
        prover_statements,
        meta_statements.clone(),
        js_sys::Array::new(),
        witnesses,
        context.clone(),
        nonce.clone(),
    )
    .unwrap();
    console::time_end_with_label("proof gen");

    console::time_with_label("bound check verifier stmt");
    let verifier_stmt_2 =
        generate_bound_check_lego_verifier_statement(min, max, snark_vk_decom, true).unwrap();
    console::time_end_with_label("bound check verifier stmt");

    let verifier_statements = js_sys::Array::new();
    verifier_statements.push(&stmt_1);
    verifier_statements.push(&verifier_stmt_2);

    console::time_with_label("proof ver");
    let result = verify_composite_proof_g1_with_deconstructed_proof_spec(
        proof,
        verifier_statements,
        meta_statements,
        js_sys::Array::new(),
        context,
        nonce,
    )
    .unwrap();
    console::time_end_with_label("proof ver");
    let r: VerifyResponse = serde_wasm_bindgen::from_value(result).unwrap();
    r.validate();
}
