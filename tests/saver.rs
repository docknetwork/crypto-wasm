#![cfg(target_arch = "wasm32")]
extern crate wasm_bindgen_test;

use ark_std::{collections::BTreeSet, vec};
use wasm_bindgen_test::*;
use web_sys::console;

use dock_crypto_wasm::bbs_plus::{bbs_encode_message_for_signing, bbs_sign_g1};
use dock_crypto_wasm::common::VerifyResponse;
use dock_crypto_wasm::composite_proof_system::{
    generate_composite_proof_g1_with_deconstructed_proof_spec, generate_pok_bbs_plus_sig_witness,
    generate_saver_witness, saver_get_ciphertext_from_proof,
    verify_composite_proof_g1_with_deconstructed_proof_spec,
};
use dock_crypto_wasm::saver::*;
use dock_crypto_wasm::utils::{js_array_of_bytearrays_from_vector_of_bytevectors, random_bytes};

mod common;
use common::{bbs_params_and_keys, get_revealed_unrevealed, get_witness_equality_statement};
use dock_crypto_wasm::composite_proof_system::statement::{
    generate_pok_bbs_plus_sig_statement, generate_saver_prover_statement,
    generate_saver_verifier_statement,
};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
pub fn bbs_sig_and_verifiable_encryption() {
    let msg_count = 5;
    let (params, sk, pk) = bbs_params_and_keys(msg_count);
    let mut encoded_msgs = vec![];

    for _ in 0..msg_count {
        let m = random_bytes();
        let bytes = bbs_encode_message_for_signing(m).unwrap();
        encoded_msgs.push(bytes.to_vec());
    }

    let messages_as_array =
        js_array_of_bytearrays_from_vector_of_bytevectors(&encoded_msgs).unwrap();
    let enc_msg_idx = 2usize;

    let sig = bbs_sign_g1(messages_as_array.clone(), sk.clone(), params.clone(), false).unwrap();
    let mut revealed_indices = BTreeSet::new();
    revealed_indices.insert(0);
    let (revealed_msgs, unrevealed_msgs) =
        get_revealed_unrevealed(&encoded_msgs, &revealed_indices);

    let chunk_bit_size = 16;
    let enc_gens = saver_generate_encryption_generators(None).unwrap();
    let comm_gens = saver_generate_chunked_commitment_generators(None).unwrap();

    console::time_with_label("setup");
    let setup_arr = saver_decryptor_setup(chunk_bit_size, enc_gens.clone(), false).unwrap();
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
    let stmt_1 = generate_pok_bbs_plus_sig_statement(
        params.clone(),
        pk.clone(),
        revealed_msgs.clone(),
        false,
    )
    .unwrap();
    console::time_with_label("saver stmt");
    let prover_stmt_2 = generate_saver_prover_statement(
        chunk_bit_size,
        enc_gens_decom.clone(),
        comm_gens_decom.clone(),
        ek_decom.clone(),
        snark_pk_decom.clone(),
        true,
    )
    .unwrap();
    console::time_end_with_label("saver stmt");

    let prover_statements = js_sys::Array::new();
    prover_statements.push(&stmt_1);
    prover_statements.push(&prover_stmt_2);

    let meta_statements = js_sys::Array::new();
    // statement 0's `enc_msg_idx`th index = statement 1st's 0th index
    let meta_statement = get_witness_equality_statement(vec![(0, enc_msg_idx as u32), (1, 0)]);
    meta_statements.push(&meta_statement);

    let context = Some("test-context".as_bytes().to_vec());

    let witness_1 = generate_pok_bbs_plus_sig_witness(sig, unrevealed_msgs.clone(), false).unwrap();
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
        prover_statements.clone(),
        meta_statements.clone(),
        js_sys::Array::new(),
        witnesses,
        context.clone(),
        nonce.clone(),
    )
    .unwrap();
    console::time_end_with_label("proof gen");

    let snark_vk_decom = saver_get_snark_vk_from_pk(snark_pk.clone(), true).unwrap();
    let verifier_stmt_2 = generate_saver_verifier_statement(
        chunk_bit_size,
        enc_gens_decom.clone(),
        comm_gens_decom.clone(),
        ek_decom.clone(),
        snark_vk_decom.clone(),
        true,
    )
    .unwrap();
    console::time_end_with_label("saver stmt");

    let verifier_statements = js_sys::Array::new();
    verifier_statements.push(&stmt_1);
    verifier_statements.push(&verifier_stmt_2);

    console::time_with_label("proof ver");
    let result = verify_composite_proof_g1_with_deconstructed_proof_spec(
        proof.clone(),
        verifier_statements.clone(),
        meta_statements.clone(),
        js_sys::Array::new(),
        context.clone(),
        nonce,
    )
    .unwrap();
    console::time_end_with_label("proof ver");
    let r: VerifyResponse = serde_wasm_bindgen::from_value(result).unwrap();
    r.validate();

    // Verifier extracts ciphertext from proof
    let ct = saver_get_ciphertext_from_proof(proof, 1).unwrap();

    // Decryptor decrypts the ciphertext
    console::time_with_label("decrypt with pk");
    let dec_arr = saver_decrypt_ciphertext_using_snark_pk(
        ct.clone(),
        sk.clone(),
        dk_decom.clone(),
        snark_pk_decom.clone(),
        chunk_bit_size,
        true,
    )
    .unwrap();
    console::time_end_with_label("decrypt with pk");

    console::time_with_label("decrypt with vk");
    let dec_arr_1 = saver_decrypt_ciphertext_using_snark_vk(
        ct.clone(),
        sk.clone(),
        dk_decom.clone(),
        snark_vk_decom.clone(),
        chunk_bit_size,
        true,
    )
    .unwrap();
    console::time_end_with_label("decrypt with vk");

    let decrypted_message = js_sys::Uint8Array::new(&dec_arr.get(0));
    let nu = js_sys::Uint8Array::new(&dec_arr.get(1));

    // Verifier checks that decrypted message was encrypted in the ciphertext
    console::time_with_label("verify decryption using pk");
    let result = saver_verify_decryption_using_snark_pk(
        ct.clone(),
        decrypted_message.clone(),
        nu,
        dk_decom.clone(),
        snark_pk_decom,
        enc_gens_decom.clone(),
        chunk_bit_size,
        true,
    )
    .unwrap();
    console::time_end_with_label("verify decryption using pk");
    let r: VerifyResponse = serde_wasm_bindgen::from_value(result).unwrap();
    r.validate();
    assert_eq!(decrypted_message.to_vec(), encoded_msgs[enc_msg_idx]);

    let decrypted_message_1 = js_sys::Uint8Array::new(&dec_arr_1.get(0));
    let nu_1 = js_sys::Uint8Array::new(&dec_arr_1.get(1));

    // Verifier checks that decrypted message was encrypted in the ciphertext
    console::time_with_label("verify decryption using vk");
    let result = saver_verify_decryption_using_snark_vk(
        ct,
        decrypted_message_1.clone(),
        nu_1,
        dk_decom,
        snark_vk_decom,
        enc_gens_decom,
        chunk_bit_size,
        true,
    )
    .unwrap();
    console::time_end_with_label("verify decryption using vk");
    let r: VerifyResponse = serde_wasm_bindgen::from_value(result).unwrap();
    r.validate();
    assert_eq!(decrypted_message_1.to_vec(), encoded_msgs[enc_msg_idx]);
}
