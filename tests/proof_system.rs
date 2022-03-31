#![cfg(target_arch = "wasm32")]
extern crate wasm_bindgen_test;

use web_sys::console;

use ark_bls12_381::Bls12_381;
use ark_ec::PairingEngine;
use ark_serialize::CanonicalDeserialize;
use ark_std::collections::BTreeSet;
use proof_system::{statement, witness};
use wasm::accumulator::{
    accumulator_derive_membership_proving_key_from_non_membership_key,
    accumulator_generate_public_key, accumulator_generate_secret_key, generate_accumulator_params,
    generate_non_membership_proving_key, positive_accumulator_add,
    positive_accumulator_get_accumulated, positive_accumulator_initialize,
    positive_accumulator_membership_witness, universal_accumulator_add,
    universal_accumulator_compute_d, universal_accumulator_compute_initial_fv,
    universal_accumulator_fixed_initial_elements, universal_accumulator_get_accumulated,
    universal_accumulator_initialize_given_f_v, universal_accumulator_membership_witness,
    universal_accumulator_non_membership_witness,
};
use wasm::bbs_plus::{
    bbs_blind_sign_g1, bbs_commit_to_message_in_g1, bbs_encode_message_for_signing,
    bbs_encode_messages_for_signing, bbs_generate_g1_params, bbs_generate_public_key_g2,
    bbs_generate_secret_key, bbs_get_bases_for_commitment_g1, bbs_sign_g1, bbs_unblind_sig_g1,
    bbs_verify_g1,
};
use wasm::common::{
    field_element_as_bytes, field_element_from_number, generate_field_element_from_bytes,
    generate_random_field_element, generate_random_g1_element, generate_random_g2_element,
    pedersen_commitment_g1, pedersen_commitment_g2, random_ff, VerifyResponse,
};
use wasm::proof_system::{
    generate_accumulator_membership_statement, generate_accumulator_membership_witness,
    generate_accumulator_non_membership_statement, generate_accumulator_non_membership_witness,
    generate_composite_proof_g1, generate_composite_proof_g2,
    generate_pedersen_commitment_g1_statement, generate_pedersen_commitment_g2_statement,
    generate_pedersen_commitment_witness, generate_pok_bbs_sig_statement,
    generate_pok_bbs_sig_witness, generate_proof_spec_g1, generate_proof_spec_g2,
    generate_witness_equality_meta_statement, verify_composite_proof_g1, verify_composite_proof_g2,
    Witness,
};
use wasm::utils::{
    fr_from_jsvalue, js_array_from_frs, msgs_bytes_map_to_fr_btreemap, random_bytes,
};
mod common;
use common::{
    accum_params_and_keys, bbs_params_and_keys, gen_msgs, get_revealed_unrevealed,
    get_universal_accum, get_witness_equality_statement,
};
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

fn test_bbs_statement(stmt_j: js_sys::Uint8Array, revealed_msgs: js_sys::Map) {
    let s = js_sys::Uint8Array::new(&stmt_j);
    let serz = s.to_vec();
    let stmt: statement::Statement<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine> =
        CanonicalDeserialize::deserialize_unchecked(&serz[..]).unwrap();
    match stmt {
        statement::Statement::PoKBBSSignatureG1(s) => {
            assert_eq!(s.revealed_messages.len() as u32, revealed_msgs.size());
            for (i, m) in s.revealed_messages.iter() {
                assert_eq!(
                    *m,
                    fr_from_jsvalue(revealed_msgs.get(&JsValue::from(*i as u32))).unwrap()
                );
            }
        }
        _ => assert!(false),
    }
}

fn test_bbs_witness(wit_j: JsValue, unrevealed_msgs: js_sys::Map) {
    let wit: Witness = serde_wasm_bindgen::from_value(wit_j).unwrap();
    match wit {
        witness::Witness::PoKBBSSignatureG1(s) => {
            assert_eq!(s.unrevealed_messages.len() as u32, unrevealed_msgs.size());
            for (i, m) in s.unrevealed_messages.iter() {
                assert_eq!(
                    *m,
                    fr_from_jsvalue(unrevealed_msgs.get(&JsValue::from(*i as u32))).unwrap()
                );
            }
        }
        _ => assert!(false),
    }
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn three_bbs_sigs_and_msg_equality() {
    let msg_count_1 = 5;
    let (params_1, sk_1, pk_1) = bbs_params_and_keys(msg_count_1);
    let msgs_1 = gen_msgs(msg_count_1);

    let msg_count_2 = 6;
    let (params_2, sk_2, pk_2) = bbs_params_and_keys(msg_count_2);
    let mut msgs_2 = gen_msgs(msg_count_2);

    let msg_count_3 = 7;
    let (params_3, sk_3, pk_3) = bbs_params_and_keys(msg_count_3);
    let mut msgs_3 = gen_msgs(msg_count_3);

    // Message at index 2 in msgs_1 is equal to index 3 in msgs_2
    msgs_2[3] = msgs_1[2].clone();
    // Message at index 2 in msgs_1 is equal to index 3 in msgs_3
    msgs_3[3] = msgs_1[2].clone();

    let msgs_1_jsvalue = serde_wasm_bindgen::to_value(&msgs_1).unwrap();
    let msgs_2_jsvalue = serde_wasm_bindgen::to_value(&msgs_2).unwrap();
    let msgs_3_jsvalue = serde_wasm_bindgen::to_value(&msgs_3).unwrap();
    let sig_1 = bbs_sign_g1(msgs_1_jsvalue.clone(), sk_1.clone(), params_1.clone(), true).unwrap();
    let sig_2 = bbs_sign_g1(msgs_2_jsvalue.clone(), sk_2.clone(), params_2.clone(), true).unwrap();
    let sig_3 = bbs_sign_g1(msgs_3_jsvalue.clone(), sk_3.clone(), params_3.clone(), true).unwrap();

    // Prepare revealed messages for the proof of knowledge of 1st signature
    let mut revealed_indices_1 = BTreeSet::new();
    revealed_indices_1.insert(0);
    let (revealed_msgs_1, unrevealed_msgs_1) =
        get_revealed_unrevealed(&msgs_1, &revealed_indices_1);

    // Prepare revealed messages for the proof of knowledge of 2nd signature
    let mut revealed_indices_2 = BTreeSet::new();
    revealed_indices_2.insert(1);
    let (revealed_msgs_2, unrevealed_msgs_2) =
        get_revealed_unrevealed(&msgs_2, &revealed_indices_2);
    let (revealed_msgs_3, unrevealed_msgs_3) = get_revealed_unrevealed(&msgs_3, &BTreeSet::new());

    // Create statements
    let stmt_1 = generate_pok_bbs_sig_statement(
        params_1.clone(),
        pk_1.clone(),
        revealed_msgs_1.clone(),
        true,
    )
    .unwrap();
    let stmt_2 = generate_pok_bbs_sig_statement(
        params_2.clone(),
        pk_2.clone(),
        revealed_msgs_2.clone(),
        true,
    )
    .unwrap();
    let stmt_3 = generate_pok_bbs_sig_statement(
        params_3.clone(),
        pk_3.clone(),
        revealed_msgs_3.clone(),
        true,
    )
    .unwrap();

    let meta_statements = js_sys::Array::new();

    // Create equality meta-statement, statement 0's 2nd index = statement 1st's 3rd index = statement 2nd's 3rd index
    let meta_statement = get_witness_equality_statement(vec![(0, 2), (1, 3), (2, 3)]);
    meta_statements.push(&meta_statement);

    let statements = js_sys::Array::new();
    statements.push(&stmt_1);
    statements.push(&stmt_2);
    statements.push(&stmt_3);

    let context = Some("test-context".as_bytes().to_vec());

    let proof_spec = generate_proof_spec_g1(statements, meta_statements, context).unwrap();

    let witness_1 = generate_pok_bbs_sig_witness(sig_1, unrevealed_msgs_1, true).unwrap();
    let witness_2 = generate_pok_bbs_sig_witness(sig_2, unrevealed_msgs_2, true).unwrap();
    let witness_3 = generate_pok_bbs_sig_witness(sig_3, unrevealed_msgs_3, true).unwrap();

    let witnesses = js_sys::Array::new();
    witnesses.push(&witness_1);
    witnesses.push(&witness_2);
    witnesses.push(&witness_3);

    let nonce = Some("test-nonce".as_bytes().to_vec());

    console::time_with_label("proof gen");
    let proof = generate_composite_proof_g1(proof_spec.clone(), witnesses, nonce.clone()).unwrap();
    console::time_end_with_label("proof gen");

    console::time_with_label("proof ver");
    let result = verify_composite_proof_g1(proof, proof_spec, nonce).unwrap();
    console::time_end_with_label("proof ver");
    let r: VerifyResponse = serde_wasm_bindgen::from_value(result).unwrap();
    r.validate();
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn bbs_sig_and_accumulator() {
    let member_1 = field_element_as_bytes(field_element_from_number(5)).unwrap();
    let member_2 = field_element_as_bytes(field_element_from_number(10)).unwrap();
    let member_3 = field_element_as_bytes(generate_field_element_from_bytes(
        "user_1232".as_bytes().to_vec(),
    ))
    .unwrap();

    let msg_count_1 = 5;
    let (params_1, sk_1, pk_1) = bbs_params_and_keys(msg_count_1);
    let mut msgs_1 = vec![];
    for _ in 0..msg_count_1 - 2 {
        let m = random_bytes();
        let encoded = bbs_encode_message_for_signing(m).unwrap();
        let bytes: Vec<u8> = serde_wasm_bindgen::from_value(encoded).unwrap();
        msgs_1.push(bytes);
    }

    msgs_1.push(member_1.to_vec());
    msgs_1.push(member_2.to_vec());

    let msgs_1_jsvalue = serde_wasm_bindgen::to_value(&msgs_1).unwrap();
    let sig_1 = bbs_sign_g1(
        msgs_1_jsvalue.clone(),
        sk_1.clone(),
        params_1.clone(),
        false,
    )
    .unwrap();

    let msg_count_2 = 6;
    let (params_2, sk_2, pk_2) = bbs_params_and_keys(msg_count_2);
    let mut msgs_2 = vec![];
    for _ in 0..msg_count_2 - 2 {
        let m = random_bytes();
        let encoded = bbs_encode_message_for_signing(m).unwrap();
        let bytes: Vec<u8> = serde_wasm_bindgen::from_value(encoded).unwrap();
        msgs_2.push(bytes);
    }

    // Message at index 2 in msgs_1 is equal to index 3 in msgs_2
    msgs_2[3] = msgs_1[2].clone();
    assert_eq!(msgs_2[3], msgs_1[2]);
    // msgs_1 has member_1 at index 3 and msgs_2 has member_1 at index 4
    msgs_2.push(member_1.to_vec());
    msgs_2.push(member_3.to_vec());

    assert_eq!(msgs_2[4], msgs_1[3]);

    assert_eq!(msgs_1[3], member_1.to_vec());
    assert_eq!(msgs_1[4], member_2.to_vec());
    assert_eq!(msgs_2[4], member_1.to_vec());
    assert_eq!(msgs_2[5], member_3.to_vec());

    let msgs_2_jsvalue = serde_wasm_bindgen::to_value(&msgs_2).unwrap();
    let sig_2 = bbs_sign_g1(
        msgs_2_jsvalue.clone(),
        sk_2.clone(),
        params_2.clone(),
        false,
    )
    .unwrap();

    // Prepare revealed messages for the proof of knowledge of 1st signature
    let mut revealed_indices_1 = BTreeSet::new();
    revealed_indices_1.insert(0);
    let (revealed_msgs_1, unrevealed_msgs_1) =
        get_revealed_unrevealed(&msgs_1, &revealed_indices_1);

    // Prepare revealed messages for the proof of knowledge of 2nd signature
    let mut revealed_indices_2 = BTreeSet::new();
    revealed_indices_2.insert(1);
    let (revealed_msgs_2, unrevealed_msgs_2) =
        get_revealed_unrevealed(&msgs_2, &revealed_indices_2);

    let (accum_params, accum_sk, accum_pk) = accum_params_and_keys();
    let non_mem_prk = generate_non_membership_proving_key(None).unwrap();
    let mem_prk =
        accumulator_derive_membership_proving_key_from_non_membership_key(non_mem_prk.clone())
            .unwrap();

    let mut pos_accumulator = positive_accumulator_initialize(accum_params.clone()).unwrap();

    let max_size = 10;
    let mut uni_accumulator = get_universal_accum(accum_sk.clone(), accum_params.clone(), max_size);

    let non_member = generate_random_field_element(None).unwrap();

    pos_accumulator =
        positive_accumulator_add(pos_accumulator, member_1.clone(), accum_sk.clone()).unwrap();
    pos_accumulator =
        positive_accumulator_add(pos_accumulator, member_2.clone(), accum_sk.clone()).unwrap();
    pos_accumulator =
        positive_accumulator_add(pos_accumulator, member_3.clone(), accum_sk.clone()).unwrap();
    let pos_witness_1 = positive_accumulator_membership_witness(
        pos_accumulator.clone(),
        member_1.clone(),
        accum_sk.clone(),
    )
    .unwrap();
    let pos_witness_2 = positive_accumulator_membership_witness(
        pos_accumulator.clone(),
        member_2.clone(),
        accum_sk.clone(),
    )
    .unwrap();
    let pos_witness_3 = positive_accumulator_membership_witness(
        pos_accumulator.clone(),
        member_3.clone(),
        accum_sk.clone(),
    )
    .unwrap();

    uni_accumulator =
        universal_accumulator_add(uni_accumulator, member_1.clone(), accum_sk.clone()).unwrap();
    uni_accumulator =
        universal_accumulator_add(uni_accumulator, member_2.clone(), accum_sk.clone()).unwrap();
    uni_accumulator =
        universal_accumulator_add(uni_accumulator, member_3.clone(), accum_sk.clone()).unwrap();
    let uni_witness_1 = universal_accumulator_membership_witness(
        uni_accumulator.clone(),
        member_1.clone(),
        accum_sk.clone(),
    )
    .unwrap();
    let uni_witness_2 = universal_accumulator_membership_witness(
        uni_accumulator.clone(),
        member_2.clone(),
        accum_sk.clone(),
    )
    .unwrap();
    let uni_witness_3 = universal_accumulator_membership_witness(
        uni_accumulator.clone(),
        member_3.clone(),
        accum_sk.clone(),
    )
    .unwrap();

    let members = js_sys::Array::new();
    members.push(&member_1);
    members.push(&member_2);
    members.push(&member_3);

    let d = universal_accumulator_compute_d(non_member.clone(), members).unwrap();
    let nm_witness = universal_accumulator_non_membership_witness(
        uni_accumulator.clone(),
        d,
        non_member.clone(),
        accum_sk.clone(),
        accum_params.clone(),
    )
    .unwrap();

    let pos_accumulated = positive_accumulator_get_accumulated(pos_accumulator.clone()).unwrap();
    let uni_accumulated = universal_accumulator_get_accumulated(uni_accumulator.clone()).unwrap();

    // Create statements
    let stmt_1 = generate_pok_bbs_sig_statement(
        params_1.clone(),
        pk_1.clone(),
        revealed_msgs_1.clone(),
        false,
    )
    .unwrap();
    let stmt_2 = generate_pok_bbs_sig_statement(
        params_2.clone(),
        pk_2.clone(),
        revealed_msgs_2.clone(),
        false,
    )
    .unwrap();
    // Membership of member_1 in positive accumulator
    let stmt_3 = generate_accumulator_membership_statement(
        accum_params.clone(),
        accum_pk.clone(),
        mem_prk.clone(),
        pos_accumulated.clone(),
    )
    .unwrap();
    // Membership of member_2 in positive accumulator
    let stmt_4 = generate_accumulator_membership_statement(
        accum_params.clone(),
        accum_pk.clone(),
        mem_prk.clone(),
        pos_accumulated.clone(),
    )
    .unwrap();
    // Membership of member_3 in positive accumulator
    let stmt_5 = generate_accumulator_membership_statement(
        accum_params.clone(),
        accum_pk.clone(),
        mem_prk.clone(),
        pos_accumulated.clone(),
    )
    .unwrap();
    // Membership of member_1 in universal accumulator
    let stmt_6 = generate_accumulator_membership_statement(
        accum_params.clone(),
        accum_pk.clone(),
        mem_prk.clone(),
        uni_accumulated.clone(),
    )
    .unwrap();
    // Membership of member_2 in universal accumulator
    let stmt_7 = generate_accumulator_membership_statement(
        accum_params.clone(),
        accum_pk.clone(),
        mem_prk.clone(),
        uni_accumulated.clone(),
    )
    .unwrap();
    // Membership of member_3 in universal accumulator
    let stmt_8 = generate_accumulator_membership_statement(
        accum_params.clone(),
        accum_pk.clone(),
        mem_prk.clone(),
        uni_accumulated.clone(),
    )
    .unwrap();
    let stmt_9 = generate_accumulator_non_membership_statement(
        accum_params.clone(),
        accum_pk.clone(),
        non_mem_prk.clone(),
        uni_accumulated.clone(),
    )
    .unwrap();

    let meta_statements = js_sys::Array::new();

    // statement 0's 2nd index = statement 1st's 3rd index
    let meta_statement = get_witness_equality_statement(vec![(0, 2), (1, 3)]);
    meta_statements.push(&meta_statement);

    // statement 0's 3nd index = statement 1st's 4th index = statement 2nd's 0th index = statement 5th's 0th index
    let meta_statement = get_witness_equality_statement(vec![(0, 3), (1, 4), (2, 0), (5, 0)]);
    meta_statements.push(&meta_statement);

    let meta_statement = get_witness_equality_statement(vec![(2, 0), (5, 0)]);
    meta_statements.push(&meta_statement);

    let meta_statement = get_witness_equality_statement(vec![(3, 0), (6, 0)]);
    meta_statements.push(&meta_statement);

    let meta_statement = get_witness_equality_statement(vec![(4, 0), (7, 0)]);
    meta_statements.push(&meta_statement);

    let statements = js_sys::Array::new();
    statements.push(&stmt_1);
    statements.push(&stmt_2);
    statements.push(&stmt_3);
    statements.push(&stmt_4);
    statements.push(&stmt_5);
    statements.push(&stmt_6);
    statements.push(&stmt_7);
    statements.push(&stmt_8);
    statements.push(&stmt_9);

    meta_statements.push(&meta_statement);

    let context = Some("test-context".as_bytes().to_vec());

    let proof_spec = generate_proof_spec_g1(statements, meta_statements, context).unwrap();

    let witness_1 = generate_pok_bbs_sig_witness(sig_1, unrevealed_msgs_1.clone(), false).unwrap();
    let witness_2 = generate_pok_bbs_sig_witness(sig_2, unrevealed_msgs_2.clone(), false).unwrap();
    let witness_3 =
        generate_accumulator_membership_witness(member_1.clone(), pos_witness_1.clone()).unwrap();
    let witness_4 =
        generate_accumulator_membership_witness(member_2.clone(), pos_witness_2.clone()).unwrap();
    let witness_5 =
        generate_accumulator_membership_witness(member_3.clone(), pos_witness_3.clone()).unwrap();
    let witness_6 =
        generate_accumulator_membership_witness(member_1, uni_witness_1.clone()).unwrap();
    let witness_7 =
        generate_accumulator_membership_witness(member_2, uni_witness_2.clone()).unwrap();
    let witness_8 =
        generate_accumulator_membership_witness(member_3, uni_witness_3.clone()).unwrap();
    let witness_9 =
        generate_accumulator_non_membership_witness(non_member, nm_witness.clone()).unwrap();

    let witnesses = js_sys::Array::new();
    witnesses.push(&witness_1);
    witnesses.push(&witness_2);
    witnesses.push(&witness_3);
    witnesses.push(&witness_4);
    witnesses.push(&witness_5);
    witnesses.push(&witness_6);
    witnesses.push(&witness_7);
    witnesses.push(&witness_8);
    witnesses.push(&witness_9);

    let msgs = msgs_bytes_map_to_fr_btreemap(&revealed_msgs_1, false).unwrap();
    assert_eq!(msgs.len(), 1);

    test_bbs_statement(stmt_1.clone(), revealed_msgs_1.clone());
    test_bbs_statement(stmt_2.clone(), revealed_msgs_2.clone());
    test_bbs_witness(witness_1.clone(), unrevealed_msgs_1.clone());
    test_bbs_witness(witness_2.clone(), unrevealed_msgs_2.clone());

    let nonce = Some("test-nonce".as_bytes().to_vec());

    let proof = generate_composite_proof_g1(proof_spec.clone(), witnesses, nonce.clone()).unwrap();

    let result = verify_composite_proof_g1(proof, proof_spec, nonce).unwrap();
    let r: VerifyResponse = serde_wasm_bindgen::from_value(result).unwrap();
    r.validate();
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn request_blind_bbs_sig() {
    let msg_count_1 = 5;
    let (params_1, sk_1, pk_1) = bbs_params_and_keys(msg_count_1);
    let msgs_1 = gen_msgs(msg_count_1);

    let msg_count_2 = 6;
    let (params_2, sk_2, pk_2) = bbs_params_and_keys(msg_count_2);
    let mut msgs_2 = gen_msgs(msg_count_2);

    // One message is equal
    msgs_2[5] = msgs_1[4].clone();

    let msgs_1_jsvalue = serde_wasm_bindgen::to_value(&msgs_1).unwrap();
    let sig_1 = bbs_sign_g1(msgs_1_jsvalue.clone(), sk_1.clone(), params_1.clone(), true).unwrap();

    let msgs_2_jsvalue = serde_wasm_bindgen::to_value(&msgs_2).unwrap();

    let mut revealed_indices = BTreeSet::new();
    revealed_indices.insert(0);
    let (revealed_msgs_1, unrevealed_msgs_1) = get_revealed_unrevealed(&msgs_1, &revealed_indices);

    let committed_indices = vec![0, 1, 5];
    let indices_to_commit = js_sys::Set::new(&JsValue::undefined());
    let indices_to_commit_arr = js_sys::Array::new();
    let msgs_to_commit = js_sys::Map::new();
    let msgs_to_not_commit = js_sys::Map::new();
    for i in 0..msg_count_2 {
        if committed_indices.contains(&i) {
            indices_to_commit.add(&JsValue::from(i as u32));
            indices_to_commit_arr.push(&JsValue::from(i as u32));
            msgs_to_commit.set(
                &JsValue::from(i as u32),
                &serde_wasm_bindgen::to_value(&msgs_2[i]).unwrap(),
            );
        } else {
            msgs_to_not_commit.set(
                &JsValue::from(i as u32),
                &serde_wasm_bindgen::to_value(&msgs_2[i]).unwrap(),
            );
        }
    }
    let blinding = generate_random_field_element(None).unwrap();

    let commitment = bbs_commit_to_message_in_g1(
        msgs_to_commit.clone(),
        blinding.clone(),
        params_2.clone(),
        true,
    )
    .unwrap();

    let statements = js_sys::Array::new();
    let stmt_1 = generate_pok_bbs_sig_statement(
        params_1.clone(),
        pk_1.clone(),
        revealed_msgs_1.clone(),
        true,
    )
    .unwrap();
    statements.push(&stmt_1);

    let bases =
        bbs_get_bases_for_commitment_g1(params_2.clone(), indices_to_commit_arr.clone()).unwrap();
    let stmt_2 = generate_pedersen_commitment_g1_statement(bases, commitment.clone()).unwrap();
    statements.push(&stmt_2);

    let meta_statements = js_sys::Array::new();
    let meta_statement = get_witness_equality_statement(vec![(0, 4), (1, 3)]);
    meta_statements.push(&meta_statement);

    let context = Some("test-context".as_bytes().to_vec());

    let proof_spec = generate_proof_spec_g1(statements, meta_statements, context).unwrap();

    let witness_1 = generate_pok_bbs_sig_witness(sig_1, unrevealed_msgs_1, true).unwrap();

    let wits =
        bbs_encode_messages_for_signing(msgs_2_jsvalue.clone(), indices_to_commit.clone()).unwrap();
    wits.unshift(&blinding);
    let witness_2 = generate_pedersen_commitment_witness(wits).unwrap();

    let witnesses = js_sys::Array::new();
    witnesses.push(&witness_1);
    witnesses.push(&witness_2);

    let nonce = Some("test-nonce".as_bytes().to_vec());
    let proof = generate_composite_proof_g1(proof_spec.clone(), witnesses, nonce.clone()).unwrap();
    let result = verify_composite_proof_g1(proof, proof_spec, nonce).unwrap();
    let r: VerifyResponse = serde_wasm_bindgen::from_value(result).unwrap();
    r.validate();

    let blinded_sig =
        bbs_blind_sign_g1(commitment, msgs_to_not_commit, sk_2, params_2.clone(), true).unwrap();
    let sig_2 = bbs_unblind_sig_g1(blinded_sig, blinding).unwrap();

    let result = bbs_verify_g1(msgs_2_jsvalue, sig_2, pk_2, params_2, true).unwrap();
    let r: VerifyResponse = serde_wasm_bindgen::from_value(result).unwrap();
    r.validate();
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn pedersen_commitment_opening_equality() {
    let m_1 = generate_random_field_element(None).unwrap();
    let m_2 = generate_random_field_element(None).unwrap();
    let m_3 = generate_random_field_element(None).unwrap();

    let msgs_1 = js_sys::Array::new();
    msgs_1.push(&m_1);
    msgs_1.push(&m_2);

    let msgs_2 = js_sys::Array::new();
    msgs_2.push(&m_1);
    msgs_2.push(&m_2);
    msgs_2.push(&m_3);

    let bases_1 = js_sys::Array::new();
    bases_1.push(&generate_random_g1_element().unwrap());
    bases_1.push(&generate_random_g1_element().unwrap());

    let comm_1 = pedersen_commitment_g1(bases_1.clone(), msgs_1.clone()).unwrap();

    let bases_2 = js_sys::Array::new();
    bases_2.push(&generate_random_g1_element().unwrap());
    bases_2.push(&generate_random_g1_element().unwrap());
    bases_2.push(&generate_random_g1_element().unwrap());

    let comm_2 = pedersen_commitment_g1(bases_2.clone(), msgs_2.clone()).unwrap();

    let statements = js_sys::Array::new();
    let stmt_1 = generate_pedersen_commitment_g1_statement(bases_1, comm_1.clone()).unwrap();
    let stmt_2 = generate_pedersen_commitment_g1_statement(bases_2, comm_2.clone()).unwrap();
    statements.push(&stmt_1);
    statements.push(&stmt_2);

    let meta_statements = js_sys::Array::new();
    meta_statements.push(&get_witness_equality_statement(vec![(0, 0), (1, 0)]));
    meta_statements.push(&get_witness_equality_statement(vec![(0, 1), (1, 1)]));

    let proof_spec = generate_proof_spec_g1(statements, meta_statements, None).unwrap();

    let witnesses = js_sys::Array::new();
    witnesses.push(&generate_pedersen_commitment_witness(msgs_1.clone()).unwrap());
    witnesses.push(&generate_pedersen_commitment_witness(msgs_2.clone()).unwrap());

    let proof = generate_composite_proof_g1(proof_spec.clone(), witnesses, None).unwrap();
    let result = verify_composite_proof_g1(proof, proof_spec, None).unwrap();
    let r: VerifyResponse = serde_wasm_bindgen::from_value(result).unwrap();
    r.validate();

    let bases_1 = js_sys::Array::new();
    bases_1.push(&generate_random_g2_element().unwrap());
    bases_1.push(&generate_random_g2_element().unwrap());

    let comm_1 = pedersen_commitment_g2(bases_1.clone(), msgs_1.clone()).unwrap();

    let bases_2 = js_sys::Array::new();
    bases_2.push(&generate_random_g2_element().unwrap());
    bases_2.push(&generate_random_g2_element().unwrap());
    bases_2.push(&generate_random_g2_element().unwrap());

    let comm_2 = pedersen_commitment_g2(bases_2.clone(), msgs_2.clone()).unwrap();

    let statements = js_sys::Array::new();
    let stmt_1 = generate_pedersen_commitment_g2_statement(bases_1, comm_1.clone()).unwrap();
    let stmt_2 = generate_pedersen_commitment_g2_statement(bases_2, comm_2.clone()).unwrap();
    statements.push(&stmt_1);
    statements.push(&stmt_2);

    let meta_statements = js_sys::Array::new();
    meta_statements.push(&get_witness_equality_statement(vec![(0, 0), (1, 0)]));
    meta_statements.push(&get_witness_equality_statement(vec![(0, 1), (1, 1)]));

    let proof_spec = generate_proof_spec_g2(statements, meta_statements, None).unwrap();

    let witnesses = js_sys::Array::new();
    witnesses.push(&generate_pedersen_commitment_witness(msgs_1.clone()).unwrap());
    witnesses.push(&generate_pedersen_commitment_witness(msgs_2.clone()).unwrap());

    let proof = generate_composite_proof_g2(proof_spec.clone(), witnesses, None).unwrap();
    let result = verify_composite_proof_g2(proof, proof_spec, None).unwrap();
    let r: VerifyResponse = serde_wasm_bindgen::from_value(result).unwrap();
    r.validate();
}
