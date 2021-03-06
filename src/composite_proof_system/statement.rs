use ark_bls12_381::Bls12_381;
use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::collections::BTreeSet;
use js_sys::Uint8Array;
use proof_system::prelude::{EqualWitnesses, MetaStatement};
use proof_system::statement;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use crate::accumulator::{
    deserialize_params, deserialize_public_key, MembershipPrk, NonMembershipPrk,
};
use crate::bbs_plus::{encode_messages_as_js_map_to_fr_btreemap, BBSPlusPkG2, SigParamsG1};
use crate::legosnark::{LegoProvingKey, LegoVerifyingKey};
use crate::saver::{ChunkedCommGens, EncGens, SaverEk, SaverSnarkPk, SaverSnarkVk};
use crate::utils::{
    g1_affine_from_uint8_array, g2_affine_from_uint8_array, is_positive_safe_integer,
    js_array_to_g1_affine_vec, js_array_to_g2_affine_vec, set_panic_hook,
};
use crate::G1Affine;

pub(crate) type PoKBBSSigStmt = statement::bbs_plus::PoKBBSSignatureG1<Bls12_381>;
pub(crate) type AccumMemStmt = statement::accumulator::AccumulatorMembership<Bls12_381>;
pub(crate) type AccumNonMemStmt = statement::accumulator::AccumulatorNonMembership<Bls12_381>;
pub(crate) type PedCommG1Stmt =
    statement::ped_comm::PedersenCommitment<<Bls12_381 as PairingEngine>::G1Affine>;
pub(crate) type PedCommG2Stmt =
    statement::ped_comm::PedersenCommitment<<Bls12_381 as PairingEngine>::G2Affine>;
pub(crate) type SaverProverStmt = statement::saver::SaverProver<Bls12_381>;
pub(crate) type SaverVerifierStmt = statement::saver::SaverVerifier<Bls12_381>;
pub(crate) type BoundCheckLegoProverStmt =
    statement::bound_check_legogroth16::BoundCheckLegoGroth16Prover<Bls12_381>;
pub(crate) type BoundCheckLegoVerifierStmt =
    statement::bound_check_legogroth16::BoundCheckLegoGroth16Verifier<Bls12_381>;

// All `Statement`s are returned in their uncompressed form as they are generated by the same party using
// them unlike signature params, public keys, proofs, etc

#[wasm_bindgen(js_name = generatePoKBBSSignatureStatement)]
pub fn generate_pok_bbs_sig_statement(
    params: JsValue,
    public_key: Uint8Array,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let pk = obj_from_uint8array!(BBSPlusPkG2, public_key, false, "BBSPlusPkG2");
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;
    let statement = PoKBBSSigStmt::new_statement_from_params::<G1Affine>(params, pk, msgs);
    Ok(obj_to_uint8array_unchecked!(&statement, "PokBBSStatement"))
}

#[wasm_bindgen(js_name = generatePoKBBSSignatureStatementFromParamRefs)]
pub fn generate_pok_bbs_sig_statement_from_param_refs(
    params: usize,
    public_key: usize,
    revealed_msgs: js_sys::Map,
    encode_messages: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let msgs = encode_messages_as_js_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;
    let statement =
        PoKBBSSigStmt::new_statement_from_params_ref::<G1Affine>(params, public_key, msgs);
    Ok(obj_to_uint8array_unchecked!(&statement, "PokBBSStatement"))
}

#[wasm_bindgen(js_name = generateAccumulatorMembershipStatement)]
pub fn generate_accumulator_membership_statement(
    params: Uint8Array,
    public_key: Uint8Array,
    proving_key: Uint8Array,
    accumulated: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let pk = deserialize_public_key(public_key)?;
    let params = deserialize_params(params)?;
    let prk = obj_from_uint8array!(MembershipPrk, proving_key, false, "MembershipPrk");
    let statement =
        AccumMemStmt::new_statement_from_params::<G1Affine>(params, pk, prk, accumulated);
    Ok(obj_to_uint8array_unchecked!(
        &statement,
        "AccumMemStatement"
    ))
}

#[wasm_bindgen(js_name = generateAccumulatorMembershipStatementFromParamRefs)]
pub fn generate_accumulator_membership_statement_from_param_refs(
    params: usize,
    public_key: usize,
    proving_key: usize,
    accumulated: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let statement = AccumMemStmt::new_statement_from_params_ref::<G1Affine>(
        params,
        public_key,
        proving_key,
        accumulated,
    );
    Ok(obj_to_uint8array_unchecked!(
        &statement,
        "AccumMemStatement"
    ))
}

#[wasm_bindgen(js_name = generateAccumulatorNonMembershipStatement)]
pub fn generate_accumulator_non_membership_statement(
    params: Uint8Array,
    public_key: Uint8Array,
    proving_key: Uint8Array,
    accumulated: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let pk = deserialize_public_key(public_key)?;
    let params = deserialize_params(params)?;
    let prk = obj_from_uint8array!(NonMembershipPrk, proving_key, false, "NonMembershipPrk");
    let statement =
        AccumNonMemStmt::new_statement_from_params::<G1Affine>(params, pk, prk, accumulated);
    Ok(obj_to_uint8array_unchecked!(
        &statement,
        "AccumNonMemStatement"
    ))
}

#[wasm_bindgen(js_name = generateAccumulatorNonMembershipStatementFromParamRefs)]
pub fn generate_accumulator_non_membership_statement_from_param_refs(
    params: usize,
    public_key: usize,
    proving_key: usize,
    accumulated: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let accumulated = g1_affine_from_uint8_array(accumulated)?;
    let statement = AccumNonMemStmt::new_statement_from_params_ref::<G1Affine>(
        params,
        public_key,
        proving_key,
        accumulated,
    );
    Ok(obj_to_uint8array_unchecked!(
        &statement,
        "AccumNonMemStatement"
    ))
}

#[wasm_bindgen(js_name = generatePedersenCommitmentG1Statement)]
pub fn generate_pedersen_commitment_g1_statement(
    commitment_key: js_sys::Array,
    commitment: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let commitment_key = js_array_to_g1_affine_vec(&commitment_key)?;
    let commitment = g1_affine_from_uint8_array(commitment)?;
    let statement =
        PedCommG1Stmt::new_statement_from_params::<Bls12_381>(commitment_key, commitment);
    Ok(obj_to_uint8array_unchecked!(&statement, "PedCommG1Stmt"))
}

#[wasm_bindgen(js_name = generatePedersenCommitmentG1StatementFromParamRefs)]
pub fn generate_pedersen_commitment_g1_statement_from_param_refs(
    commitment_key: usize,
    commitment: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let commitment = g1_affine_from_uint8_array(commitment)?;
    let statement =
        PedCommG1Stmt::new_statement_from_params_refs::<Bls12_381>(commitment_key, commitment);
    Ok(obj_to_uint8array_unchecked!(&statement, "PedCommG1Stmt"))
}

#[wasm_bindgen(js_name = generatePedersenCommitmentG2Statement)]
pub fn generate_pedersen_commitment_g2_statement(
    commitment_key: js_sys::Array,
    commitment: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let commitment_key = js_array_to_g2_affine_vec(&commitment_key)?;
    let commitment = g2_affine_from_uint8_array(commitment)?;
    let statement =
        PedCommG2Stmt::new_statement_from_params::<Bls12_381>(commitment_key, commitment);
    Ok(obj_to_uint8array_unchecked!(&statement, "PedCommG2Stmt"))
}

#[wasm_bindgen(js_name = generatePedersenCommitmentG2StatementFromParamRefs)]
pub fn generate_pedersen_commitment_g2_statement_from_param_refs(
    commitment_key: usize,
    commitment: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let commitment = g2_affine_from_uint8_array(commitment)?;
    let statement =
        PedCommG2Stmt::new_statement_from_params_refs::<Bls12_381>(commitment_key, commitment);
    Ok(obj_to_uint8array_unchecked!(&statement, "PedCommG2Stmt"))
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

#[wasm_bindgen(js_name = generateSaverProverStatement)]
pub fn generate_saver_prover_statement(
    chunk_bit_size: u8,
    enc_gens: Uint8Array,
    chunked_comm_gens: Uint8Array,
    encryption_key: Uint8Array,
    snark_pk: Uint8Array,
    uncompressed_public_params: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let snark_pk = if uncompressed_public_params {
        obj_from_uint8array_unchecked!(SaverSnarkPk, snark_pk, "SaverSnarkPk")
    } else {
        obj_from_uint8array!(SaverSnarkPk, snark_pk, false, "SaverSnarkPk")
    };
    let (enc_gens, chunked_comm_gens, ek) = parse_saver_statement_input(
        enc_gens,
        chunked_comm_gens,
        encryption_key,
        uncompressed_public_params,
    )?;
    let statement = SaverProverStmt::new_statement_from_params::<G1Affine>(
        chunk_bit_size,
        enc_gens,
        chunked_comm_gens,
        ek,
        snark_pk,
    )
    .map_err(|e| {
        JsValue::from(&format!(
            "Creating statement for SaverProver returned error: {:?}",
            e
        ))
    })?;
    Ok(obj_to_uint8array_unchecked!(&statement, "SaverProverStmt"))
}

#[wasm_bindgen(js_name = generateSaverProverStatementFromParamRefs)]
pub fn generate_saver_prover_statement_from_param_refs(
    chunk_bit_size: u8,
    enc_gens: usize,
    chunked_comm_gens: usize,
    encryption_key: usize,
    snark_pk: usize,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let statement = SaverProverStmt::new_statement_from_params_ref::<G1Affine>(
        chunk_bit_size,
        enc_gens,
        chunked_comm_gens,
        encryption_key,
        snark_pk,
    );
    Ok(obj_to_uint8array_unchecked!(&statement, "SaverProverStmt"))
}

#[wasm_bindgen(js_name = generateSaverVerifierStatement)]
pub fn generate_saver_verifier_statement(
    chunk_bit_size: u8,
    enc_gens: Uint8Array,
    chunked_comm_gens: Uint8Array,
    encryption_key: Uint8Array,
    snark_vk: Uint8Array,
    uncompressed_public_params: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let snark_vk = if uncompressed_public_params {
        obj_from_uint8array_unchecked!(SaverSnarkVk, snark_vk, "SaverSnarkVk")
    } else {
        obj_from_uint8array!(SaverSnarkVk, snark_vk, false, "SaverSnarkVk")
    };
    let (enc_gens, chunked_comm_gens, ek) = parse_saver_statement_input(
        enc_gens,
        chunked_comm_gens,
        encryption_key,
        uncompressed_public_params,
    )?;
    let statement = SaverVerifierStmt::new_statement_from_params::<G1Affine>(
        chunk_bit_size,
        enc_gens,
        chunked_comm_gens,
        ek,
        snark_vk,
    )
    .map_err(|e| {
        JsValue::from(&format!(
            "Creating statement for SaverVerifier returned error: {:?}",
            e
        ))
    })?;
    Ok(obj_to_uint8array_unchecked!(
        &statement,
        "SaverVerifierStatement"
    ))
}

#[wasm_bindgen(js_name = generateSaverVerifierStatementFromParamRefs)]
pub fn generate_saver_verifier_statement_from_param_refs(
    chunk_bit_size: u8,
    enc_gens: usize,
    chunked_comm_gens: usize,
    encryption_key: usize,
    snark_vk: usize,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let statement = SaverVerifierStmt::new_statement_from_params_ref::<G1Affine>(
        chunk_bit_size,
        enc_gens,
        chunked_comm_gens,
        encryption_key,
        snark_vk,
    );
    Ok(obj_to_uint8array_unchecked!(
        &statement,
        "SaverVerifierStatement"
    ))
}

/// If `uncompressed` is true, expects the legosnark proving key to be in uncompressed form else
/// it should be compressed.
#[wasm_bindgen(js_name = generateBoundCheckLegoProverStatement)]
pub fn generate_bound_check_lego_prover_statement(
    min: js_sys::Number,
    max: js_sys::Number,
    snark_pk: Uint8Array,
    uncompressed_public_params: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let (min, max) = get_valid_min_max(min, max)?;
    let snark_pk = if uncompressed_public_params {
        obj_from_uint8array_unchecked!(LegoProvingKey, snark_pk, "LegoProvingKey")
    } else {
        obj_from_uint8array!(LegoProvingKey, snark_pk, false, "LegoProvingKey")
    };
    let statement =
        BoundCheckLegoProverStmt::new_statement_from_params::<G1Affine>(min, max, snark_pk)
            .map_err(|e| {
                JsValue::from(&format!(
                    "Creating statement for BoundCheckLegoProver returned error: {:?}",
                    e
                ))
            })?;
    Ok(obj_to_uint8array_unchecked!(
        &statement,
        "BoundCheckLegoProverStmt"
    ))
}

#[wasm_bindgen(js_name = generateBoundCheckLegoProverStatementFromParamRefs)]
pub fn generate_bound_check_lego_prover_statement_from_param_refs(
    min: js_sys::Number,
    max: js_sys::Number,
    snark_pk: usize,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let (min, max) = get_valid_min_max(min, max)?;
    let statement =
        BoundCheckLegoProverStmt::new_statement_from_params_ref::<G1Affine>(min, max, snark_pk)
            .map_err(|e| {
                JsValue::from(&format!(
                    "Creating statement for BoundCheckLegoProver returned error: {:?}",
                    e
                ))
            })?;
    Ok(obj_to_uint8array_unchecked!(
        &statement,
        "BoundCheckLegoProverStmt"
    ))
}

/// If `uncompressed` is true, expects the legosnark verifying key to be in uncompressed form else
/// it should be compressed.
#[wasm_bindgen(js_name = generateBoundCheckLegoVerifierStatement)]
pub fn generate_bound_check_lego_verifier_statement(
    min: js_sys::Number,
    max: js_sys::Number,
    snark_vk: Uint8Array,
    uncompressed_public_params: bool,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let (min, max) = get_valid_min_max(min, max)?;
    let snark_vk = if uncompressed_public_params {
        obj_from_uint8array_unchecked!(LegoVerifyingKey, snark_vk, "LegoVerifyingKey")
    } else {
        obj_from_uint8array!(LegoVerifyingKey, snark_vk, false, "LegoVerifyingKey")
    };
    let statement =
        BoundCheckLegoVerifierStmt::new_statement_from_params::<G1Affine>(min, max, snark_vk)
            .map_err(|e| {
                JsValue::from(&format!(
                    "Creating statement for BoundCheckLegoVerifier returned error: {:?}",
                    e
                ))
            })?;
    Ok(obj_to_uint8array_unchecked!(
        &statement,
        "BoundCheckLegoVerifierStmt"
    ))
}

#[wasm_bindgen(js_name = generateBoundCheckLegoVerifierStatementFromParamRefs)]
pub fn generate_bound_check_lego_verifier_statement_from_param_refs(
    min: js_sys::Number,
    max: js_sys::Number,
    snark_vk: usize,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let (min, max) = get_valid_min_max(min, max)?;
    let statement =
        BoundCheckLegoVerifierStmt::new_statement_from_params_ref::<G1Affine>(min, max, snark_vk)
            .map_err(|e| {
            JsValue::from(&format!(
                "Creating statement for BoundCheckLegoVerifier returned error: {:?}",
                e
            ))
        })?;
    Ok(obj_to_uint8array_unchecked!(
        &statement,
        "BoundCheckLegoVerifierStmt"
    ))
}

fn parse_saver_statement_input(
    enc_gens: Uint8Array,
    chunked_comm_gens: Uint8Array,
    encryption_key: Uint8Array,
    uncompressed_public_params: bool,
) -> Result<(EncGens, ChunkedCommGens, SaverEk), JsValue> {
    let (enc_gens, chunked_comm_gens, ek) = if uncompressed_public_params {
        (
            obj_from_uint8array_unchecked!(EncGens, enc_gens, "EncryptionGenerators"),
            obj_from_uint8array_unchecked!(
                ChunkedCommGens,
                chunked_comm_gens,
                "ChunkedCommitmentGenerators"
            ),
            obj_from_uint8array_unchecked!(SaverEk, encryption_key, "SaverEk"),
        )
    } else {
        (
            obj_from_uint8array!(EncGens, enc_gens, false, "EncryptionGenerators"),
            obj_from_uint8array!(
                ChunkedCommGens,
                chunked_comm_gens,
                false,
                "ChunkedCommitmentGenerators"
            ),
            obj_from_uint8array!(SaverEk, encryption_key, false, "SaverEk"),
        )
    };
    Ok((enc_gens, chunked_comm_gens, ek))
}

pub fn get_valid_min_max(min: js_sys::Number, max: js_sys::Number) -> Result<(u64, u64), JsValue> {
    if !(is_positive_safe_integer(&min) && is_positive_safe_integer(&max)) {
        return Err(JsValue::from(&format!(
            "min and max should be safe positive integers but instead found {:?}, {:?}",
            min, max
        )));
    }
    let min = min.value_of() as u64;
    let max = max.value_of() as u64;
    Ok((min, max))
}
