#![cfg(target_arch = "wasm32")]
extern crate wasm_bindgen_test;

use ark_bls12_381::Bls12_381;
use ark_ec::PairingEngine;
use ark_std::{collections::BTreeSet, vec};
use proof_system::{statement, witness};
use wasm_bindgen_test::*;
use web_sys::console;

use wasm::bbs_plus::{bbs_encode_message_for_signing, bbs_sign_g1};
use wasm::bound_check::*;
use wasm::common::{field_element_from_number, VerifyResponse};
use wasm::proof_system::{
    generate_bound_check_lego_statement, generate_bound_check_witness,
    generate_composite_proof_g1_with_deconstructed_proof_spec, generate_pok_bbs_sig_statement,
    generate_pok_bbs_sig_witness, verify_composite_proof_g1_with_deconstructed_proof_spec,
};
use wasm::utils::{field_element_from_u32, fr_to_jsvalue, random_bytes};

mod common;
use common::{bbs_params_and_keys, get_revealed_unrevealed, get_witness_equality_statement};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
pub fn bbs_sig_and_bound_check_message() {
    let msg_count = 5;
    let (params, sk, pk) = bbs_params_and_keys(msg_count);
    let mut encoded_msgs = vec![];

    let bounded_msg_idx = 3usize;

    let min = field_element_from_number(100);
    let msg = 105;
    let max = field_element_from_number(120);
    for i in 0..msg_count {
        let encoded = if i == bounded_msg_idx {
            fr_to_jsvalue(&field_element_from_u32(msg)).unwrap()
        } else {
            let m = random_bytes();
            bbs_encode_message_for_signing(m).unwrap()
        };
        let bytes: Vec<u8> = serde_wasm_bindgen::from_value(encoded).unwrap();
        encoded_msgs.push(bytes);
    }

    let msgs_jsvalue = serde_wasm_bindgen::to_value(&encoded_msgs).unwrap();
    let sig = bbs_sign_g1(msgs_jsvalue.clone(), sk.clone(), params.clone(), false).unwrap();
    let mut revealed_indices = BTreeSet::new();
    // revealed_indices.insert(0);
    let (revealed_msgs, unrevealed_msgs) =
        get_revealed_unrevealed(&encoded_msgs, &revealed_indices);

    console::time_with_label("setup");
    let snark_pk = bound_check_snark_setup().unwrap();
    console::time_end_with_label("setup");

    console::time_with_label("decompresssion");
    let snark_pk_decom = bound_check_decompress_snark_pk(snark_pk.clone()).unwrap();
    console::time_end_with_label("decompresssion");

    // Create statements
    let stmt_1 =
        generate_pok_bbs_sig_statement(params.clone(), pk.clone(), revealed_msgs.clone(), false)
            .unwrap();
    console::time_with_label("bound check stmt");
    let stmt_2 =
        generate_bound_check_lego_statement(min, max, snark_pk_decom.clone(), true).unwrap();
    console::time_end_with_label("bound check stmt");

    let statements = js_sys::Array::new();
    statements.push(&stmt_1);
    statements.push(&stmt_2);

    let meta_statements = js_sys::Array::new();
    // statement 0's `bounded_msg_idx`th index = statement 1st's 0th index
    let meta_statement = get_witness_equality_statement(vec![(0, bounded_msg_idx as u32), (1, 0)]);
    meta_statements.push(&meta_statement);

    let context = Some("test-context".as_bytes().to_vec());

    let witness_1 = generate_pok_bbs_sig_witness(sig, unrevealed_msgs.clone(), false).unwrap();
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
        statements.clone(),
        meta_statements.clone(),
        witnesses,
        context.clone(),
        nonce.clone(),
    )
    .unwrap();
    console::time_end_with_label("proof gen");

    console::time_with_label("proof ver");
    let result = verify_composite_proof_g1_with_deconstructed_proof_spec(
        proof.clone(),
        statements.clone(),
        meta_statements.clone(),
        context.clone(),
        nonce,
    )
    .unwrap();
    console::time_end_with_label("proof ver");
    let r: VerifyResponse = serde_wasm_bindgen::from_value(result).unwrap();
    r.validate();
}
