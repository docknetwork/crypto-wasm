pub mod setup_params;
pub mod statement;

use wasm_bindgen::prelude::*;

use crate::accumulator::{MembershipWit, NonMembershipWit};
use crate::bbs_plus::{encode_messages_as_js_map_to_fr_btreemap, SigG1 as BBSPlusSigG1};
use crate::common::VerifyResponse;
use crate::ps::Signature as PSSignature;
use crate::utils::{fr_from_uint8_array, get_seeded_rng, js_array_to_fr_vec, set_panic_hook};
use crate::{Fr, G1Affine};
use ark_bls12_381::Bls12_381;
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2::Blake2b512;
use js_sys::Uint8Array;
use proof_system::prelude::{
    MetaStatement, MetaStatements, R1CSCircomWitness, SetupParams, Statement, Statements,
};
use proof_system::proof;
use proof_system::witness;
use zeroize::Zeroize;

pub type Witness = witness::Witness<Bls12_381>;
pub type Witnesses = witness::Witnesses<Bls12_381>;
pub(crate) type PoKBbsPlusSigWit = witness::PoKBBSSignatureG1<Bls12_381>;
pub(crate) type PokPSSigWit = witness::PoKPSSignature<Bls12_381>;
pub(crate) type AccumMemWit = witness::Membership<Bls12_381>;
pub(crate) type AccumNonMemWit = witness::NonMembership<Bls12_381>;
pub(crate) type ProofSpec<G> = proof_system::proof_spec::ProofSpec<Bls12_381, G>;
pub(crate) type Proof<G> = proof::Proof<Bls12_381, G>;
pub(crate) type ProofG1 = proof::Proof<Bls12_381, G1Affine>;
pub(crate) type StatementProofG1 = proof_system::prelude::StatementProof<Bls12_381, G1Affine>;

#[wasm_bindgen(js_name = generatePoKBBSPlusSignatureWitness)]
pub fn generate_pok_bbs_plus_sig_witness(
    signature: Uint8Array,
    unrevealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let signature = obj_from_uint8array!(BBSPlusSigG1, signature, true);
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&unrevealed_msgs, encode_messages)?;
    let witness = PoKBbsPlusSigWit::new_as_witness(signature, msgs);
    serde_wasm_bindgen::to_value(&witness).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = generatePoKPSSignatureWitness)]
pub fn generate_pok_ps_sig_witness(
    signature: Uint8Array,
    unrevealed_msgs: js_sys::Map,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let signature = obj_from_uint8array!(PSSignature, signature, true);
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&unrevealed_msgs, false)?;
    let witness = PokPSSigWit::new_as_witness(signature, msgs);

    serde_wasm_bindgen::to_value(&witness).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = generateAccumulatorMembershipWitness)]
pub fn generate_accumulator_membership_witness(
    element: Uint8Array,
    accum_witness: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let element = fr_from_uint8_array(element, true)?;
    let accum_witness: MembershipWit = serde_wasm_bindgen::from_value(accum_witness)?;
    let witness = AccumMemWit::new_as_witness(element, accum_witness);
    serde_wasm_bindgen::to_value(&witness).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = generateAccumulatorNonMembershipWitness)]
pub fn generate_accumulator_non_membership_witness(
    element: Uint8Array,
    accum_witness: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let element = fr_from_uint8_array(element, true)?;
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
    setup_params: js_sys::Array,
    context: Option<Vec<u8>>,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    gen_proof_spec::<<Bls12_381 as Pairing>::G1Affine>(
        statements,
        meta_statements,
        setup_params,
        context,
    )
}

#[wasm_bindgen(js_name = isProofSpecG1Valid)]
pub fn is_proof_spec_g1_valid(proof_spec: Uint8Array) -> Result<bool, JsValue> {
    set_panic_hook();
    let proof_spec = obj_from_uint8array_unchecked!(
        ProofSpec::<<Bls12_381 as Pairing>::G1Affine>,
        proof_spec,
        "ProofSpecG1"
    );
    Ok(true)
}

#[wasm_bindgen(js_name = generateProofSpecG2)]
pub fn generate_proof_spec_g2(
    statements: js_sys::Array,
    meta_statements: js_sys::Array,
    setup_params: js_sys::Array,
    context: Option<Vec<u8>>,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    gen_proof_spec::<<Bls12_381 as Pairing>::G2Affine>(
        statements,
        meta_statements,
        setup_params,
        context,
    )
}

#[wasm_bindgen(js_name = isProofSpecG2Valid)]
pub fn is_proof_spec_g2_valid(proof_spec: Uint8Array) -> Result<bool, JsValue> {
    set_panic_hook();
    let proof_spec = obj_from_uint8array_unchecked!(
        ProofSpec::<<Bls12_381 as Pairing>::G2Affine>,
        proof_spec,
        "ProofSpecG2"
    );
    Ok(true)
}

#[wasm_bindgen(js_name = generateCompositeProofG1)]
pub fn generate_composite_proof_g1(
    proof_spec: Uint8Array,
    witnesses: js_sys::Array,
    nonce: Option<Vec<u8>>,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    gen_proof::<<Bls12_381 as Pairing>::G1Affine>(proof_spec, witnesses, nonce)
}

#[wasm_bindgen(js_name = generateCompositeProofG2)]
pub fn generate_composite_proof_g2(
    proof_spec: Uint8Array,
    witnesses: js_sys::Array,
    nonce: Option<Vec<u8>>,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    gen_proof::<<Bls12_381 as Pairing>::G2Affine>(proof_spec, witnesses, nonce)
}

/// Same as `generate_composite_proof_g1` but takes the statements, meta-statements, setup params, context and nonce
/// separately rather than in a `ProofSpec`. Use this to save the serialization and deserialization cost of
/// creating a `ProofSpec`.
#[wasm_bindgen(js_name = generateCompositeProofG1WithDeconstructedProofSpec)]
pub fn generate_composite_proof_g1_with_deconstructed_proof_spec(
    statements: js_sys::Array,
    meta_statements: js_sys::Array,
    setup_params: js_sys::Array,
    witnesses: js_sys::Array,
    context: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
) -> Result<Uint8Array, JsValue> {
    let (statements, meta_statements, setup_params) =
        parse_statements_meta_statements_and_setup_params(
            statements,
            meta_statements,
            setup_params,
        )?;
    let proof_spec = ProofSpec::<<Bls12_381 as Pairing>::G1Affine>::new(
        statements,
        meta_statements,
        setup_params,
        context,
    );
    gen_proof_given_proof_spec_obj::<<Bls12_381 as Pairing>::G1Affine>(proof_spec, witnesses, nonce)
}

#[wasm_bindgen(js_name = verifyCompositeProofG1)]
pub fn verify_composite_proof_g1(
    proof: Uint8Array,
    proof_spec: Uint8Array,
    nonce: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    verify_proof::<<Bls12_381 as Pairing>::G1Affine>(proof_spec, proof, nonce)
}

#[wasm_bindgen(js_name = verifyCompositeProofG2)]
pub fn verify_composite_proof_g2(
    proof: Uint8Array,
    proof_spec: Uint8Array,
    nonce: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    verify_proof::<<Bls12_381 as Pairing>::G2Affine>(proof_spec, proof, nonce)
}

/// Same as `verify_composite_proof_g1` but takes the statements, meta-statements, setup params, context and nonce
/// separately rather than in a `ProofSpec`. Use this to save the serialization and deserialization cost of
/// creating a `ProofSpec`.
#[wasm_bindgen(js_name = verifyCompositeProofG1WithDeconstructedProofSpec)]
pub fn verify_composite_proof_g1_with_deconstructed_proof_spec(
    proof: Uint8Array,
    statements: js_sys::Array,
    meta_statements: js_sys::Array,
    setup_params: js_sys::Array,
    context: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    let (statements, meta_statements, setup_params) =
        parse_statements_meta_statements_and_setup_params(
            statements,
            meta_statements,
            setup_params,
        )?;
    let proof_spec = ProofSpec::<<Bls12_381 as Pairing>::G1Affine>::new(
        statements,
        meta_statements,
        setup_params,
        context,
    );
    verify_proof_given_proof_spec_obj::<<Bls12_381 as Pairing>::G1Affine>(proof_spec, proof, nonce)
}

#[wasm_bindgen(js_name = generateSaverWitness)]
pub fn generate_saver_witness(message: Uint8Array) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let message = fr_from_uint8_array(message, true)?;
    let witness = Witness::Saver(message);
    serde_wasm_bindgen::to_value(&witness).map_err(|e| JsValue::from(e))
}

/// From the composite proof, get the ciphertext for the statement at index `statement_index`
#[wasm_bindgen(js_name = saverGetCiphertextFromProof)]
pub fn saver_get_ciphertext_from_proof(
    proof: Uint8Array,
    statement_index: usize,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let proof = obj_from_uint8array!(ProofG1, proof, false);
    get_ciphertext_from_proof(&proof, statement_index)
}

/// From the composite proof, get the ciphertext for the statement indices `statement_indices`
#[wasm_bindgen(js_name = saverGetCiphertextsFromProof)]
pub fn saver_get_ciphertexts_from_proof(
    proof: Uint8Array,
    statement_indices: Vec<usize>,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    let proof = obj_from_uint8array!(ProofG1, proof, false);
    let statement_proofs = js_sys::Array::new();
    for i in statement_indices {
        statement_proofs.push(&JsValue::from(get_ciphertext_from_proof(&proof, i)?));
    }
    Ok(statement_proofs)
}

#[wasm_bindgen(js_name = generateBoundCheckWitness)]
pub fn generate_bound_check_witness(message: Uint8Array) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let message = fr_from_uint8_array(message, true)?;
    let witness = Witness::BoundCheckLegoGroth16(message);
    serde_wasm_bindgen::to_value(&witness).map_err(|e| JsValue::from(e))
}

#[wasm_bindgen(js_name = generateR1CSCircomWitness)]
pub fn generate_r1cs_circom_witness(
    input_wires: js_sys::Map,
    privates: js_sys::Array,
    publics: js_sys::Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let mut r1cs_wit = R1CSCircomWitness::<Bls12_381>::new();
    for p in privates.values() {
        let name_as_js_val = p.unwrap();
        let vals = js_sys::Array::from(&input_wires.get(&name_as_js_val));
        let name: String = serde_wasm_bindgen::from_value(name_as_js_val)?;
        r1cs_wit.set_private(name, js_array_to_fr_vec(&vals)?);
    }
    for p in publics.values() {
        let name_as_js_val = p.unwrap();
        let vals = js_sys::Array::from(&input_wires.get(&name_as_js_val));
        let name: String = serde_wasm_bindgen::from_value(name_as_js_val)?;
        r1cs_wit.set_public(name, js_array_to_fr_vec(&vals)?);
    }
    let witness = Witness::R1CSLegoGroth16(r1cs_wit);
    serde_wasm_bindgen::to_value(&witness).map_err(|e| JsValue::from(e))
}

pub fn parse_statements_meta_statements_and_setup_params<G: AffineRepr>(
    statements: js_sys::Array,
    meta_statements: js_sys::Array,
    setup_params: js_sys::Array,
) -> Result<
    (
        Statements<Bls12_381, G>,
        MetaStatements,
        Vec<SetupParams<Bls12_381, G>>,
    ),
    JsValue,
> {
    let mut meta_stmts = MetaStatements::new();
    for ms in meta_statements.values() {
        let meta_stmt: MetaStatement = serde_wasm_bindgen::from_value(ms.unwrap())?;
        meta_stmts.add(meta_stmt);
    }
    let mut stmts = Statements::<Bls12_381, G>::new();
    for s in statements.values() {
        let s = Uint8Array::new(&s.unwrap());
        let stmt = obj_from_uint8array_unchecked!(Statement<Bls12_381, G>, &s, "Statement");
        stmts.add(stmt);
    }

    let mut s_params = Vec::<SetupParams<Bls12_381, G>>::new();
    for s in setup_params.values() {
        let s = Uint8Array::new(&s.unwrap());
        let s = obj_from_uint8array_unchecked!(SetupParams<Bls12_381, G>, &s, "SetupParams");
        s_params.push(s);
    }

    Ok((stmts, meta_stmts, s_params))
}

fn gen_proof_spec<G: AffineRepr>(
    statements: js_sys::Array,
    meta_statements: js_sys::Array,
    setup_params: js_sys::Array,
    context: Option<Vec<u8>>,
) -> Result<Uint8Array, JsValue> {
    let (stmts, meta_stmts, setup_params) = parse_statements_meta_statements_and_setup_params(
        statements,
        meta_statements,
        setup_params,
    )?;
    let proof_spec = ProofSpec::<G>::new(stmts, meta_stmts, setup_params, context);
    Ok(obj_to_uint8array_unchecked!(&proof_spec, "ProofSpec"))
}

fn gen_proof<G: AffineRepr<ScalarField = Fr>>(
    proof_spec: Uint8Array,
    witnesses: js_sys::Array,
    nonce: Option<Vec<u8>>,
) -> Result<Uint8Array, JsValue> {
    let proof_spec = obj_from_uint8array_unchecked!(ProofSpec::<G>, proof_spec, "ProofSpec");
    gen_proof_given_proof_spec_obj::<G>(proof_spec, witnesses, nonce)
}

fn verify_proof<G: AffineRepr<ScalarField = Fr>>(
    proof_spec: Uint8Array,
    proof: Uint8Array,
    nonce: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    let proof_spec = obj_from_uint8array_unchecked!(ProofSpec::<G>, proof_spec, "ProofSpec");
    verify_proof_given_proof_spec_obj::<G>(proof_spec, proof, nonce)
}

fn gen_proof_given_proof_spec_obj<G: AffineRepr<ScalarField = Fr>>(
    proof_spec: ProofSpec<G>,
    witnesses: js_sys::Array,
    nonce: Option<Vec<u8>>,
) -> Result<Uint8Array, JsValue> {
    let mut wits: Witnesses = witness::Witnesses::new();
    for w in witnesses.values() {
        let wit: Witness = serde_wasm_bindgen::from_value(w.unwrap())?;
        wits.add(wit);
    }
    let mut rng = get_seeded_rng();
    let proof =
        Proof::<G>::new::<_, Blake2b512>(&mut rng, proof_spec, wits, nonce, Default::default())
            .map_err(|e| JsValue::from(&format!("Generating proof returned error: {:?}", e)))?;
    Ok(obj_to_uint8array!(&proof, false, "Proof"))
}

fn verify_proof_given_proof_spec_obj<G: AffineRepr<ScalarField = Fr>>(
    proof_spec: ProofSpec<G>,
    proof: Uint8Array,
    nonce: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    let proof = obj_from_uint8array!(Proof<G>, proof, false);
    let mut rng = get_seeded_rng();
    match proof.verify::<_, Blake2b512>(&mut rng, proof_spec, nonce, Default::default()) {
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

fn get_ciphertext_from_proof(
    proof: &ProofG1,
    statement_index: usize,
) -> Result<Uint8Array, JsValue> {
    let statement_proof = proof.statement_proof(statement_index).map_err(|_| {
        JsValue::from(&format!(
            "Did not find StatementProof at the given index {}",
            statement_index
        ))
    })?;
    if let StatementProofG1::Saver(s) = statement_proof {
        Ok(obj_to_uint8array!(&s.ciphertext, false, "SaverCiphertext"))
    } else {
        Err(JsValue::from(&format!(
            "StatementProof at index {} wasn't for Saver",
            statement_index
        )))
    }
}
