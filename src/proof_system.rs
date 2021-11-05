use serde_wasm_bindgen::*;
use wasm_bindgen::prelude::*;

use crate::accumulator::{
    deserialize_params, deserialize_public_key, MembershipPrk, MembershipWit, NonMembershipPrk,
    NonMembershipWit,
};
use crate::bbs_plus::{BBSPlusPkG2, SigG1, SigParamsG1};
use crate::common::VerifyResponse;
use crate::utils::{
    fr_from_uint8_array, g1_affine_from_uint8_array, g2_affine_from_uint8_array, get_seeded_rng,
    js_array_to_fr_vec, js_array_to_g1_affine_vec, js_array_to_g2_affine_vec,
    msgs_bytes_map_to_fr_btreemap, set_panic_hook,
};
use crate::{Fr, G1Affine};
use ark_bls12_381::Bls12_381;
use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::collections::BTreeSet;
use blake2::Blake2b;
use proof_system::proof;
use proof_system::statement;
use proof_system::witness;

pub(crate) type PoKBBSSigStmt = statement::PoKBBSSignatureG1<Bls12_381>;
pub(crate) type AccumMemStmt = statement::AccumulatorMembership<Bls12_381>;
pub(crate) type AccumNonMemStmt = statement::AccumulatorNonMembership<Bls12_381>;
pub(crate) type PedCommG1Stmt =
    statement::PedersenCommitment<<Bls12_381 as PairingEngine>::G1Affine>;
pub(crate) type PedCommG2Stmt =
    statement::PedersenCommitment<<Bls12_381 as PairingEngine>::G2Affine>;
pub(crate) type PoKBBSSigWit = witness::PoKBBSSignatureG1<Bls12_381>;
pub(crate) type AccumMemWit = witness::Membership<Bls12_381>;
pub(crate) type AccumNonMemWit = witness::NonMembership<Bls12_381>;
pub(crate) type ProofSpec = proof::ProofSpec<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>;
pub(crate) type ProofG1 = proof::Proof<Bls12_381, G1Affine, Fr, Blake2b>;

#[wasm_bindgen(js_name = generatePoKBBSSignatureStatement)]
pub fn generate_pok_bbs_sig_statement(
    params: JsValue,
    public_key: JsValue,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let pk: BBSPlusPkG2 = serde_wasm_bindgen::from_value(public_key)?;
    let msgs = msgs_bytes_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;
    let statement = PoKBBSSigStmt::new_as_statement::<G1Affine>(params, pk, msgs);
    serde_wasm_bindgen::to_value(&statement).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = generateAccumulatorMembershipStatement)]
pub fn generate_accumulator_membership_statement(
    params: js_sys::Uint8Array,
    public_key: js_sys::Uint8Array,
    proving_key: JsValue,
    accumulated: js_sys::Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let pk = deserialize_public_key(public_key)?;
    let params = deserialize_params(params)?;
    let prk: MembershipPrk = serde_wasm_bindgen::from_value(proving_key)?;
    let statement = AccumMemStmt::new_as_statement::<G1Affine>(params, pk, prk, accumulated);
    serde_wasm_bindgen::to_value(&statement).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = generateAccumulatorNonMembershipStatement)]
pub fn generate_accumulator_non_membership_statement(
    params: js_sys::Uint8Array,
    public_key: js_sys::Uint8Array,
    proving_key: JsValue,
    accumulated: js_sys::Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let pk = deserialize_public_key(public_key)?;
    let params = deserialize_params(params)?;
    let prk: NonMembershipPrk = serde_wasm_bindgen::from_value(proving_key)?;
    let statement = AccumNonMemStmt::new_as_statement::<G1Affine>(params, pk, prk, accumulated);
    serde_wasm_bindgen::to_value(&statement).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = generatePedersenCommitmentG1Statement)]
pub fn generate_pedersen_commitment_g1_statement(
    bases: js_sys::Array,
    commitment: js_sys::Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let bases = js_array_to_g1_affine_vec(&bases)?;
    let commitment = g1_affine_from_uint8_array(commitment)?;
    let statement = PedCommG1Stmt::new_as_statement::<Bls12_381>(bases, commitment);
    serde_wasm_bindgen::to_value(&statement).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = generatePedersenCommitmentG2Statement)]
pub fn generate_pedersen_commitment_g2_statement(
    bases: js_sys::Array,
    commitment: js_sys::Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let bases = js_array_to_g2_affine_vec(&bases)?;
    let commitment = g2_affine_from_uint8_array(commitment)?;
    let statement = PedCommG2Stmt::new_as_statement::<Bls12_381>(bases, commitment);
    serde_wasm_bindgen::to_value(&statement).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = generateWitnessEqualityMetaStatement)]
pub fn generate_witness_equality_meta_statement(equality: js_sys::Set) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let mut set = BTreeSet::new();
    for wr in equality.values() {
        let wr = wr.unwrap();
        let arr_2 = js_sys::Array::from(&wr);
        if arr_2.length() != 2 {
            return Err(JsValue::from("Each equality should be a 2 element array"));
        }
        let i: u32 = serde_wasm_bindgen::from_value(arr_2.get(0)).unwrap();
        let j: u32 = serde_wasm_bindgen::from_value(arr_2.get(1)).unwrap();
        set.insert((i as usize, j as usize));
    }
    serde_wasm_bindgen::to_value(&statement::MetaStatement::WitnessEquality(
        statement::EqualWitnesses(set),
    ))
    .map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = generatePoKBBSSignatureWitness)]
pub fn generate_pok_bbs_sig_witness(
    signature: js_sys::Uint8Array,
    unrevealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    // let signature: SigG1 = serde_wasm_bindgen::from_value(signature)?;
    let signature = obj_from_uint8array!(SigG1, signature);
    let msgs = msgs_bytes_map_to_fr_btreemap(&unrevealed_msgs, encode_messages)?;
    let witness = PoKBBSSigWit::new_as_witness(signature, msgs);
    serde_wasm_bindgen::to_value(&witness).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = generateAccumulatorMembershipWitness)]
pub fn generate_accumulator_membership_witness(
    element: js_sys::Uint8Array,
    accum_witness: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let element = fr_from_uint8_array(element)?;
    let accum_witness: MembershipWit = serde_wasm_bindgen::from_value(accum_witness)?;
    let witness = AccumMemWit::new_as_witness(element, accum_witness);
    serde_wasm_bindgen::to_value(&witness).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = generateAccumulatorNonMembershipWitness)]
pub fn generate_accumulator_non_membership_witness(
    element: js_sys::Uint8Array,
    accum_witness: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let element = fr_from_uint8_array(element)?;
    let accum_witness: NonMembershipWit = serde_wasm_bindgen::from_value(accum_witness)?;
    let witness = AccumNonMemWit::new_as_witness(element, accum_witness);
    serde_wasm_bindgen::to_value(&witness).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = generatePedersenCommitmentWitness)]
pub fn generate_pedersen_commitment_witness(elements: js_sys::Array) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let elements = js_array_to_fr_vec(&elements)?;
    let witness = witness::Witness::<Bls12_381>::PedersenCommitment(elements);
    serde_wasm_bindgen::to_value(&witness).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = generateProofSpec)]
pub fn generate_proof_spec(
    statements: js_sys::Array,
    meta_statements: js_sys::Array,
    context: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let mut meta_stmts: statement::MetaStatements = statement::MetaStatements::new();
    for ms in meta_statements.values() {
        let meta_stmt: statement::MetaStatement = serde_wasm_bindgen::from_value(ms.unwrap())?;
        meta_stmts.add(meta_stmt);
    }

    let mut stmts: statement::Statements<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine> =
        statement::Statements::new();
    for s in statements.values() {
        let stmt: statement::Statement<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine> =
            serde_wasm_bindgen::from_value(s.unwrap())?;
        stmts.add(stmt);
    }

    let proof_spec = ProofSpec::new_with_statements_and_meta_statements(stmts, meta_stmts, context);
    serde_wasm_bindgen::to_value(&proof_spec).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = getProofSpecAsJson)]
pub fn get_proof_spec_as_json(proof_spec: JsValue) -> Result<js_sys::JsString, JsValue> {
    set_panic_hook();
    let proof_spec: ProofSpec = serde_wasm_bindgen::from_value(proof_spec)?;
    let ser = serde_json::to_string(&proof_spec).unwrap();
    Ok(js_sys::JsString::from(ser))
}

#[wasm_bindgen(js_name = getProofSpecFromJson)]
pub fn get_proof_spec_from_json(proof_spec: js_sys::JsString) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let proof_spec: ProofSpec = serde_json::from_str(&String::from(proof_spec)).unwrap();
    serde_wasm_bindgen::to_value(&proof_spec).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = generateCompositeProof)]
pub fn generate_composite_proof(
    proof_spec: JsValue,
    witnesses: js_sys::Array,
    nonce: Option<Vec<u8>>,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let proof_spec: ProofSpec = serde_wasm_bindgen::from_value(proof_spec)?;
    let mut wits: witness::Witnesses<Bls12_381> = witness::Witnesses::new();
    for w in witnesses.values() {
        let wit: witness::Witness<Bls12_381> = serde_wasm_bindgen::from_value(w.unwrap())?;
        wits.add(wit);
    }
    let mut rng = get_seeded_rng();
    let proof = ProofG1::new(&mut rng, proof_spec, wits, nonce)
        .map_err(|e| JsValue::from(&format!("Generating proof returned error: {:?}", e)))?;
    // serde_wasm_bindgen::to_value(&proof).map_err(|e| JsValue::from(e))
    Ok(obj_to_uint8array!(&proof))
}

#[wasm_bindgen(js_name = verifyCompositeProof)]
pub fn verify_composite_proof(
    proof: js_sys::Uint8Array,
    proof_spec: JsValue,
    nonce: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    // let proof: ProofG1 = serde_wasm_bindgen::from_value(proof)?;
    let proof = obj_from_uint8array!(ProofG1, proof);
    let proof_spec: ProofSpec = serde_wasm_bindgen::from_value(proof_spec)?;
    match proof.verify(proof_spec, nonce) {
        Ok(_) => Ok(serde_wasm_bindgen::to_value(&VerifyResponse {
            verified: true,
            error: None,
        })
        .unwrap()),
        Err(e) => Ok(serde_wasm_bindgen::to_value(&VerifyResponse {
            verified: false,
            error: Some(format!("Verifying proof returned error {:?}", e)),
        })
        .unwrap()),
    }
}
