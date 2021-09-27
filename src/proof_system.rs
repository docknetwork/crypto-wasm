use serde_wasm_bindgen::*;
use wasm_bindgen::prelude::*;

use crate::accumulator::{
    AccumPk, AccumSetupParams, MembershipPrk, MembershipWit, NonMembershipPrk, NonMembershipWit,
};
use crate::common::VerifyResponse;
use crate::dock_bbs_plus::{BBSPlusPkG2, SigG1, SigParamsG1};
use crate::utils::{fr_from_jsvalue, g1_affine_from_jsvalue, g2_affine_from_jsvalue, get_seeded_rng, js_array_to_fr_vec, js_array_to_g1_affine_vec, js_array_to_g2_affine_vec, msgs_bytes_map_to_fr_btreemap, set_panic_hook};
use crate::{Fr, G1Affine};
use ark_bls12_381::Bls12_381;
use ark_ec::PairingEngine;
use ark_std::collections::BTreeSet;
use blake2::Blake2b;
use proof_system::proof;
use proof_system::statement;
use proof_system::witness;

pub(crate) type PoKBBSSigStmt = statement::PoKBBSSignatureG1<Bls12_381>;
pub(crate) type AccumMemStmt = statement::AccumulatorMembership<Bls12_381>;
pub(crate) type AccumNonMemStmt = statement::AccumulatorNonMembership<Bls12_381>;
pub(crate) type PedCommG1Stmt = statement::PedersenCommitment<<Bls12_381 as PairingEngine>::G1Affine>;
pub(crate) type PedCommG2Stmt = statement::PedersenCommitment<<Bls12_381 as PairingEngine>::G2Affine>;
pub(crate) type PoKBBSSigWit = witness::PoKBBSSignatureG1<Bls12_381>;
pub(crate) type AccumMemWit = witness::Membership<Bls12_381>;
pub(crate) type AccumNonMemWit = witness::NonMembership<Bls12_381>;
pub(crate) type ProofSpec = proof::ProofSpec<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>;
pub(crate) type ProofG1 = proof::Proof<Bls12_381, G1Affine, Fr, Blake2b>;

#[wasm_bindgen(js_name = generatePoKBBSSignatureStatement)]
pub async fn generate_pok_bbs_sig_statement(
    params: JsValue,
    public_key: JsValue,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let pk: BBSPlusPkG2 = serde_wasm_bindgen::from_value(public_key)?;
    let msgs = msgs_bytes_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;
    let statement = PoKBBSSigStmt::new_as_statement::<G1Affine>(params, pk, msgs);
    serde_wasm_bindgen::to_value(&statement)
}

#[wasm_bindgen(js_name = generateAccumulatorMembershipStatement)]
pub async fn generate_accumulator_membership_statement(
    params: JsValue,
    public_key: JsValue,
    proving_key: JsValue,
    accumulated: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let accumulated = g1_affine_from_jsvalue(accumulated)?;
    let pk: AccumPk = serde_wasm_bindgen::from_value(public_key)?;
    let params: AccumSetupParams = serde_wasm_bindgen::from_value(params)?;
    let prk: MembershipPrk = serde_wasm_bindgen::from_value(proving_key)?;
    let statement = AccumMemStmt::new_as_statement::<G1Affine>(params, pk, prk, accumulated);
    serde_wasm_bindgen::to_value(&statement)
}

#[wasm_bindgen(js_name = generateAccumulatorNonMembershipStatement)]
pub async fn generate_accumulator_non_membership_statement(
    params: JsValue,
    public_key: JsValue,
    proving_key: JsValue,
    accumulated: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let accumulated = g1_affine_from_jsvalue(accumulated)?;
    let pk: AccumPk = serde_wasm_bindgen::from_value(public_key)?;
    let params: AccumSetupParams = serde_wasm_bindgen::from_value(params)?;
    let prk: NonMembershipPrk = serde_wasm_bindgen::from_value(proving_key)?;
    let statement = AccumNonMemStmt::new_as_statement::<G1Affine>(params, pk, prk, accumulated);
    serde_wasm_bindgen::to_value(&statement)
}

#[wasm_bindgen(js_name = generatePedersenCommitmentG1Statement)]
pub async fn generate_pedersen_commitment_g1_statement(
    bases: js_sys::Array,
    commitment: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let bases = js_array_to_g1_affine_vec(&bases)?;
    let commitment = g1_affine_from_jsvalue(commitment)?;
    let statement = PedCommG1Stmt::new_as_statement::<Bls12_381>(bases, commitment);
    serde_wasm_bindgen::to_value(&statement)
}

#[wasm_bindgen(js_name = generatePedersenCommitmentG2Statement)]
pub async fn generate_pedersen_commitment_g2_statement(
    bases: js_sys::Array,
    commitment: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let bases = js_array_to_g2_affine_vec(&bases)?;
    let commitment = g2_affine_from_jsvalue(commitment)?;
    let statement = PedCommG2Stmt::new_as_statement::<Bls12_381>(bases, commitment);
    serde_wasm_bindgen::to_value(&statement)
}

#[wasm_bindgen(js_name = generateWitnessEqualityMetaStatement)]
pub async fn generate_witness_equality_meta_statement(
    equality: js_sys::Set,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let mut set = BTreeSet::new();
    for wr in equality.values() {
        let wr = wr.unwrap();
        let arr_2 = js_sys::Array::from(&wr);
        if arr_2.length() != 2 {
            return Err(serde_wasm_bindgen::Error::new(
                "Each equality should be a 2 element array",
            ));
        }
        let i: u32 = serde_wasm_bindgen::from_value(arr_2.get(0)).unwrap();
        let j: u32 = serde_wasm_bindgen::from_value(arr_2.get(1)).unwrap();
        set.insert((i as usize, j as usize));
    }
    serde_wasm_bindgen::to_value(&statement::MetaStatement::WitnessEquality(
        statement::EqualWitnesses(set),
    ))
}

#[wasm_bindgen(js_name = generatePoKBBSSignatureWitness)]
pub async fn generate_pok_bbs_sig_witness(
    signature: JsValue,
    unrevealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let signature: SigG1 = serde_wasm_bindgen::from_value(signature)?;
    let msgs = msgs_bytes_map_to_fr_btreemap(&unrevealed_msgs, encode_messages)?;
    let witness = PoKBBSSigWit::new_as_witness(signature, msgs);
    serde_wasm_bindgen::to_value(&witness)
}

#[wasm_bindgen(js_name = generateAccumulatorMembershipWitness)]
pub async fn generate_accumulator_membership_witness(
    element: JsValue,
    accum_witness: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let element = fr_from_jsvalue(element)?;
    let accum_witness: MembershipWit = serde_wasm_bindgen::from_value(accum_witness)?;
    let witness = AccumMemWit::new_as_witness(element, accum_witness);
    serde_wasm_bindgen::to_value(&witness)
}

#[wasm_bindgen(js_name = generateAccumulatorNonMembershipWitness)]
pub async fn generate_accumulator_non_membership_witness(
    element: JsValue,
    accum_witness: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let element = fr_from_jsvalue(element)?;
    let accum_witness: NonMembershipWit = serde_wasm_bindgen::from_value(accum_witness)?;
    let witness = AccumNonMemWit::new_as_witness(element, accum_witness);
    serde_wasm_bindgen::to_value(&witness)
}

#[wasm_bindgen(js_name = generatePedersenCommitmentWitness)]
pub async fn generate_pedersen_commitment_witness(
    elements: js_sys::Array,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let elements = js_array_to_fr_vec(&elements)?;
    let witness = witness::Witness::<Bls12_381>::PedersenCommitment(elements);
    serde_wasm_bindgen::to_value(&witness)
}

#[wasm_bindgen(js_name = generateProofSpec)]
pub async fn generate_proof_spec(
    statements: js_sys::Array,
    meta_statements: js_sys::Array,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
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

    let proof_spec = ProofSpec::new_with_statements_and_meta_statements(stmts, meta_stmts);
    serde_wasm_bindgen::to_value(&proof_spec)
}

#[wasm_bindgen(js_name = generateProof)]
pub async fn generate_proof(
    proof_spec: JsValue,
    witnesses: js_sys::Array,
    context: Option<Vec<u8>>,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let proof_spec: ProofSpec = serde_wasm_bindgen::from_value(proof_spec)?;
    let mut wits: witness::Witnesses<Bls12_381> = witness::Witnesses::new();
    for w in witnesses.values() {
        let wit: witness::Witness<Bls12_381> = serde_wasm_bindgen::from_value(w.unwrap())?;
        wits.add(wit);
    }
    let context = context.unwrap_or(vec![]);
    let mut rng = get_seeded_rng();
    let proof = ProofG1::new(&mut rng, proof_spec, wits, &context)
        .map_err(|e| JsValue::from(&format!("Generating proof returned error: {:?}", e)))?;
    serde_wasm_bindgen::to_value(&proof)
}

#[wasm_bindgen(js_name = verifyProof)]
pub async fn verify_proof(
    proof: JsValue,
    proof_spec: JsValue,
    context: Option<Vec<u8>>,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let proof: ProofG1 = serde_wasm_bindgen::from_value(proof)?;
    let proof_spec: ProofSpec = serde_wasm_bindgen::from_value(proof_spec)?;
    let context = context.unwrap_or(vec![]);
    match proof.verify(proof_spec, &context) {
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
