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
use crate::{Fr, G1Affine, G2Affine};
use ark_bls12_381::Bls12_381;
use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::collections::BTreeSet;
use blake2::Blake2b;
use proof_system::prelude::{EqualWitnesses, MetaStatement, MetaStatements};
use proof_system::proof;
use proof_system::statement;
use proof_system::witness;

use crate::saver::{ChunkedCommGens, EncGens, SaverEk, SaverSnarkPk};
pub(crate) type PoKBBSSigStmt = statement::PoKBBSSignatureG1<Bls12_381>;
pub(crate) type AccumMemStmt = statement::AccumulatorMembership<Bls12_381>;
pub(crate) type AccumNonMemStmt = statement::AccumulatorNonMembership<Bls12_381>;
pub(crate) type PedCommG1Stmt =
    statement::PedersenCommitment<<Bls12_381 as PairingEngine>::G1Affine>;
pub(crate) type PedCommG2Stmt =
    statement::PedersenCommitment<<Bls12_381 as PairingEngine>::G2Affine>;
pub(crate) type SaverStmt = statement::Saver<Bls12_381>;
pub type Witness = witness::Witness<Bls12_381>;
pub type Witnesses = witness::Witnesses<Bls12_381>;
pub(crate) type PoKBBSSigWit = witness::PoKBBSSignatureG1<Bls12_381>;
pub(crate) type AccumMemWit = witness::Membership<Bls12_381>;
pub(crate) type AccumNonMemWit = witness::NonMembership<Bls12_381>;
pub(crate) type ProofSpecG1 =
    proof_system::prelude::ProofSpec<Bls12_381, <Bls12_381 as PairingEngine>::G1Affine>;
pub(crate) type ProofSpecG2 =
    proof_system::prelude::ProofSpec<Bls12_381, <Bls12_381 as PairingEngine>::G2Affine>;
pub(crate) type ProofG1 = proof::Proof<Bls12_381, G1Affine, Fr, Blake2b>;
pub(crate) type ProofG2 = proof::Proof<Bls12_381, G2Affine, Fr, Blake2b>;
pub(crate) type StatementProofG1 = proof_system::prelude::StatementProof<Bls12_381, G1Affine>;

macro_rules! gen_proof_spec {
    ($group: ident, $proof_spec: ident, $statements: ident, $meta_statements: ident, $context: ident) => {{
        set_panic_hook();
        let mut meta_stmts = MetaStatements::new();
        for ms in $meta_statements.values() {
            let meta_stmt: MetaStatement = serde_wasm_bindgen::from_value(ms.unwrap())?;
            meta_stmts.add(meta_stmt);
        }

        let mut stmts: statement::Statements<Bls12_381, <Bls12_381 as PairingEngine>::$group> =
            statement::Statements::new();
        for s in $statements.values() {
            let stmt: statement::Statement<Bls12_381, <Bls12_381 as PairingEngine>::$group> =
                serde_wasm_bindgen::from_value(s.unwrap())?;
            stmts.add(stmt);
        }

        let proof_spec =
            $proof_spec::new_with_statements_and_meta_statements(stmts, meta_stmts, $context);
        serde_wasm_bindgen::to_value(&proof_spec).map_err(|e| JsValue::from(e))
    }};
}

macro_rules! gen_proof {
    ($proof_spec_typ: ident, $proof_spec: ident, $witnesses: ident, $proof_typ: ident, $proof_typ_name: expr, $nonce: ident) => {{
        set_panic_hook();
        let proof_spec: $proof_spec_typ = serde_wasm_bindgen::from_value($proof_spec)?;
        let mut wits: Witnesses = witness::Witnesses::new();
        for w in $witnesses.values() {
            let wit: Witness = serde_wasm_bindgen::from_value(w.unwrap())?;
            wits.add(wit);
        }
        let mut rng = get_seeded_rng();
        let proof = $proof_typ::new(&mut rng, proof_spec, wits, $nonce)
            .map_err(|e| JsValue::from(&format!("Generating proof returned error: {:?}", e)))?;
        Ok(obj_to_uint8array!(&proof, $proof_typ_name))
    }};
}

macro_rules! verify_proof {
    ($proof_spec_typ: ident, $proof_spec: ident, $proof: ident, $proof_typ: ident, $nonce: ident) => {{
        set_panic_hook();
        let proof = obj_from_uint8array!($proof_typ, $proof);
        let proof_spec: $proof_spec_typ = serde_wasm_bindgen::from_value($proof_spec)?;
        match proof.verify(proof_spec, $nonce) {
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
    }};
}

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
    proving_key: js_sys::Uint8Array,
    accumulated: js_sys::Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let pk = deserialize_public_key(public_key)?;
    let params = deserialize_params(params)?;
    let prk = obj_from_uint8array!(MembershipPrk, proving_key, "MembershipPrk");
    let statement = AccumMemStmt::new_as_statement::<G1Affine>(params, pk, prk, accumulated);
    serde_wasm_bindgen::to_value(&statement).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = generateAccumulatorNonMembershipStatement)]
pub fn generate_accumulator_non_membership_statement(
    params: js_sys::Uint8Array,
    public_key: js_sys::Uint8Array,
    proving_key: js_sys::Uint8Array,
    accumulated: js_sys::Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let pk = deserialize_public_key(public_key)?;
    let params = deserialize_params(params)?;
    let prk = obj_from_uint8array!(NonMembershipPrk, proving_key, "NonMembershipPrk");
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
    serde_wasm_bindgen::to_value(&MetaStatement::WitnessEquality(EqualWitnesses(set)))
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
    let witness = Witness::PedersenCommitment(elements);
    serde_wasm_bindgen::to_value(&witness).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = generateProofSpecG1)]
pub fn generate_proof_spec_g1(
    statements: js_sys::Array,
    meta_statements: js_sys::Array,
    context: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    gen_proof_spec!(G1Affine, ProofSpecG1, statements, meta_statements, context)
}

#[wasm_bindgen(js_name = generateProofSpecG2)]
pub fn generate_proof_spec_g2(
    statements: js_sys::Array,
    meta_statements: js_sys::Array,
    context: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    gen_proof_spec!(G2Affine, ProofSpecG2, statements, meta_statements, context)
}

#[wasm_bindgen(js_name = getProofSpecAsJson)]
pub fn get_proof_spec_as_json(proof_spec: JsValue) -> Result<js_sys::JsString, JsValue> {
    set_panic_hook();
    let proof_spec: ProofSpecG1 = serde_wasm_bindgen::from_value(proof_spec)?;
    let ser = serde_json::to_string(&proof_spec).unwrap();
    Ok(js_sys::JsString::from(ser))
}

#[wasm_bindgen(js_name = getProofSpecFromJson)]
pub fn get_proof_spec_from_json(proof_spec: js_sys::JsString) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let proof_spec: ProofSpecG1 = serde_json::from_str(&String::from(proof_spec)).unwrap();
    serde_wasm_bindgen::to_value(&proof_spec).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = generateCompositeProofG1)]
pub fn generate_composite_proof_g1(
    proof_spec: JsValue,
    witnesses: js_sys::Array,
    nonce: Option<Vec<u8>>,
) -> Result<js_sys::Uint8Array, JsValue> {
    gen_proof!(
        ProofSpecG1,
        proof_spec,
        witnesses,
        ProofG1,
        "ProofG1",
        nonce
    )
}

#[wasm_bindgen(js_name = generateCompositeProofG2)]
pub fn generate_composite_proof_g2(
    proof_spec: JsValue,
    witnesses: js_sys::Array,
    nonce: Option<Vec<u8>>,
) -> Result<js_sys::Uint8Array, JsValue> {
    gen_proof!(
        ProofSpecG2,
        proof_spec,
        witnesses,
        ProofG2,
        "ProofG2",
        nonce
    )
}

#[wasm_bindgen(js_name = verifyCompositeProofG1)]
pub fn verify_composite_proof_g1(
    proof: js_sys::Uint8Array,
    proof_spec: JsValue,
    nonce: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    verify_proof!(ProofSpecG1, proof_spec, proof, ProofG1, nonce)
}

#[wasm_bindgen(js_name = verifyCompositeProofG2)]
pub fn verify_composite_proof_g2(
    proof: js_sys::Uint8Array,
    proof_spec: JsValue,
    nonce: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    verify_proof!(ProofSpecG2, proof_spec, proof, ProofG2, nonce)
}

#[wasm_bindgen(js_name = generateSaverStatement)]
pub fn generate_saver_statement(
    chunk_bit_size: u8,
    enc_gens: js_sys::Uint8Array,
    chunked_comm_gens: js_sys::Uint8Array,
    encryption_key: js_sys::Uint8Array,
    snark_pk: js_sys::Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let enc_gens = obj_from_uint8array!(EncGens, enc_gens, "EncryptionGenerators");
    let chunked_comm_gens = obj_from_uint8array!(
        ChunkedCommGens,
        chunked_comm_gens,
        "ChunkedCommitmentGenerators"
    );
    let ek = obj_from_uint8array!(SaverEk, encryption_key, "SaverEk");
    let snark_pk = obj_from_uint8array!(SaverSnarkPk, snark_pk, "SaverSnarkPk");
    let statement = SaverStmt::new_as_statement::<G1Affine>(
        chunk_bit_size,
        enc_gens,
        chunked_comm_gens,
        ek,
        snark_pk,
    )
    .map_err(|e| {
        JsValue::from(&format!(
            "Creating statement for SAVER returned error: {:?}",
            e
        ))
    })?;
    serde_wasm_bindgen::to_value(&statement).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = generateSaverWitness)]
pub fn generate_saver_witness(message: js_sys::Uint8Array) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let message = fr_from_uint8_array(message)?;
    let witness = Witness::Saver(message);
    serde_wasm_bindgen::to_value(&witness).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = saverGetCiphertextFromProof)]
pub fn saver_get_ciphertext_from_proof(
    proof: js_sys::Uint8Array,
    statement_index: usize,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let proof = obj_from_uint8array!(ProofG1, proof);
    let statement_proof = proof
        .statement_proof(statement_index)
        .map_err(|_| JsValue::from(&format!("Did not find StatementProof at the given index")))?;
    if let StatementProofG1::Saver(s) = statement_proof {
        Ok(obj_to_uint8array!(&s.ciphertext, "SaverCiphertext"))
    } else {
        Err(JsValue::from(&format!("StatementProof wasn't for Saver")))
    }
}
