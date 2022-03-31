#![cfg(target_arch = "wasm32")]
extern crate wasm_bindgen_test;

use ark_bls12_381::Bls12_381;
use ark_ec::PairingEngine;
use ark_std::{collections::BTreeSet, vec};
use proof_system::{statement, witness};
use wasm_bindgen_test::*;
use web_sys::console;

use wasm::bbs_plus::{
    bbs_encode_message_for_signing, bbs_encode_messages_for_signing, bbs_generate_g1_params,
    bbs_generate_public_key_g2, bbs_generate_secret_key, bbs_sign_g1, bbs_verify_g1,
};
use wasm::common::VerifyResponse;
use wasm::proof_system::{
    generate_composite_proof_g1, generate_composite_proof_g1_with_deconstructed_proof_spec,
    generate_pok_bbs_sig_statement, generate_pok_bbs_sig_witness, generate_proof_spec_g1,
    generate_saver_statement, generate_saver_witness, saver_get_ciphertext_from_proof,
    verify_composite_proof_g1, verify_composite_proof_g1_with_deconstructed_proof_spec,
};
use wasm::saver::*;
use wasm::utils::random_bytes;

mod common;
use common::{bbs_params_and_keys, get_revealed_unrevealed, get_witness_equality_statement};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
pub fn bbs_sig_and_verifiable_encryption() {
    let msg_count = 5;
    let (params, sk, pk) = bbs_params_and_keys(msg_count);
    let mut encoded_msgs = vec![];

    for _ in 0..msg_count {
        let m = random_bytes();
        let encoded = bbs_encode_message_for_signing(m).unwrap();
        let bytes: Vec<u8> = serde_wasm_bindgen::from_value(encoded).unwrap();
        encoded_msgs.push(bytes);
    }

    let enc_msg_idx = 2usize;

    let msgs_jsvalue = serde_wasm_bindgen::to_value(&encoded_msgs).unwrap();
    let sig = bbs_sign_g1(msgs_jsvalue.clone(), sk.clone(), params.clone(), false).unwrap();
    let mut revealed_indices = BTreeSet::new();
    revealed_indices.insert(0);
    let (revealed_msgs, unrevealed_msgs) =
        get_revealed_unrevealed(&encoded_msgs, &revealed_indices);

    let chunk_bit_size = 8;
    let enc_gens = saver_generate_encryption_generators(None).unwrap();
    let comm_gens = saver_generate_chunked_commitment_generators(None).unwrap();

    console::time_with_label("setup");
    let setup_arr = saver_decryptor_setup(chunk_bit_size, enc_gens.clone()).unwrap();
    console::time_end_with_label("setup");
    let snark_pk = js_sys::Uint8Array::new(&setup_arr.get(0));
    let sk = js_sys::Uint8Array::new(&setup_arr.get(1));
    let ek = js_sys::Uint8Array::new(&setup_arr.get(2));
    let dk = js_sys::Uint8Array::new(&setup_arr.get(3));

    console::time_with_label("decompresssion");
    let enc_gens_decom = saver_decompress_encryption_generators(enc_gens.clone()).unwrap();
    let comm_gens_decom =
        saver_decompress_chunked_commitment_generators(comm_gens.clone()).unwrap();
    let ek_decom = saver_decompress_encryption_key(ek.clone()).unwrap();
    let dk_decom = saver_decompress_decryption_key(dk.clone()).unwrap();
    let snark_pk_decom = saver_decompress_snark_pk(snark_pk.clone()).unwrap();
    console::time_end_with_label("decompresssion");

    // Create statements
    let stmt_1 =
        generate_pok_bbs_sig_statement(params.clone(), pk.clone(), revealed_msgs.clone(), false)
            .unwrap();
    console::time_with_label("saver stmt");
    let stmt_2 = generate_saver_statement(
        chunk_bit_size,
        enc_gens_decom.clone(),
        comm_gens_decom.clone(),
        ek_decom.clone(),
        snark_pk_decom.clone(),
        true,
    )
    .unwrap();
    console::time_end_with_label("saver stmt");

    let statements = js_sys::Array::new();
    statements.push(&stmt_1);
    statements.push(&stmt_2);

    let meta_statements = js_sys::Array::new();
    // statement 0's 2nd index = statement 1st's 0th dex
    let meta_statement = get_witness_equality_statement(vec![(0, enc_msg_idx as u32), (1, 0)]);
    meta_statements.push(&meta_statement);

    let context = Some("test-context".as_bytes().to_vec());

    let witness_1 = generate_pok_bbs_sig_witness(sig, unrevealed_msgs.clone(), false).unwrap();
    let witness_2 = generate_saver_witness(js_sys::Uint8Array::from(
        encoded_msgs[enc_msg_idx].as_slice(),
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
        context.clone(),
        witnesses,
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

    let ct = saver_get_ciphertext_from_proof(proof, 1).unwrap();
    console::time_with_label("decrypt");
    let dec_arr = saver_decrypt_ciphertext_using_snark_pk(
        ct.clone(),
        sk.clone(),
        dk_decom.clone(),
        snark_pk_decom.clone(),
        chunk_bit_size,
        true,
    )
    .unwrap();
    console::time_end_with_label("decrypt");

    let decrypted_message = js_sys::Uint8Array::new(&dec_arr.get(0));
    let nu = js_sys::Uint8Array::new(&dec_arr.get(1));

    console::time_with_label("verify decrypttion");
    let result = saver_verify_decryption_using_snark_pk(
        ct,
        decrypted_message.clone(),
        nu,
        dk_decom,
        snark_pk_decom,
        enc_gens_decom,
        chunk_bit_size,
        true,
    )
    .unwrap();
    console::time_end_with_label("verify decrypttion");
    let r: VerifyResponse = serde_wasm_bindgen::from_value(result).unwrap();
    r.validate();
    assert_eq!(decrypted_message.to_vec(), encoded_msgs[enc_msg_idx]);
}
