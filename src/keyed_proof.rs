use crate::{
    accumulator::common::AccumSk,
    bddt16_kvac::{BDDT16MACParams, BDDT16MACPublicKeyG1, BDDT16MACSecretKey},
    common::VerifyResponse,
    composite_proof_system::Proof,
    to_verify_response,
    utils::{get_seeded_rng, set_panic_hook},
    G1Affine,
};
use blake2::Blake2b512;
use js_sys::Uint8Array;
use kvac::bddt_2016::keyed_proof::{
    KeyedProof as BDDT16Kp, ProofOfInvalidityOfKeyedProof as BDDT16Pivkp,
    ProofOfValidityOfKeyedProof as BDDT16Pvkp,
};
use proof_system::prelude::StatementProof;
use vb_accumulator::{
    kb_universal_accumulator::proofs_keyed_verification::{
        KBUniversalAccumulatorKeyedMembershipProof as KBUniMemKp, KBUniversalAccumulatorProofOfValidityOfKeyedMembershipProof as KBUniMemPvkp,
        KBUniversalAccumulatorProofOfInvalidityOfKeyedMembershipProof as KBUniMemPivkp,
        KBUniversalAccumulatorKeyedNonMembershipProof as KBUniNonMemKp, KBUniversalAccumulatorProofOfValidityOfKeyedNonMembershipProof as KBUniNonMemPvkp,
        KBUniversalAccumulatorProofOfInvalidityOfKeyedNonMembershipProof as KBUniNonMemPivkp
    },
    proofs_keyed_verification::{
        KeyedMembershipProof as VBMemKp, ProofOfValidityOfKeyedMembershipProof as VbMemPvkp, ProofOfInvalidityOfKeyedMembershipProof as VbMemPivkp
    },
};
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
use zeroize::Zeroize;
use crate::accumulator::common::{AccumPkKV, AccumSetupParamsKV};

#[wasm_bindgen(js_name = getAllKeyedSubproofsFromProof)]
pub fn get_all_keyed_subproofs_from_proof(proof: Uint8Array) -> Result<js_sys::Map, JsValue> {
    set_panic_hook();
    let proof = obj_from_uint8array!(Proof, proof, false);
    let r = js_sys::Map::new();
    for (i, s) in proof.statement_proofs.into_iter().enumerate() {
        match s {
            StatementProof::PoKOfBDDT16MAC(p) => {
                let dp = p.to_keyed_proof();
                let val = js_sys::Array::new();
                val.push(&JsValue::from(0_u32));
                val.push(&JsValue::from(obj_to_uint8array!(&dp, false)));
                r.set(&JsValue::from(i as u32), &val);
            }
            StatementProof::VBAccumulatorMembershipKV(p) => {
                let dp = p.to_keyed_proof();
                let val = js_sys::Array::new();
                val.push(&JsValue::from(1_u32));
                val.push(&JsValue::from(obj_to_uint8array!(&dp, false)));
                r.set(&JsValue::from(i as u32), &val);
            }
            StatementProof::KBUniversalAccumulatorMembershipKV(p) => {
                let dp = p.to_keyed_proof();
                let val = js_sys::Array::new();
                val.push(&JsValue::from(2_u32));
                val.push(&JsValue::from(obj_to_uint8array!(&dp, false)));
                r.set(&JsValue::from(i as u32), &val);
            }
            StatementProof::KBUniversalAccumulatorNonMembershipKV(p) => {
                let dp = p.to_keyed_proof();
                let val = js_sys::Array::new();
                val.push(&JsValue::from(3_u32));
                val.push(&JsValue::from(obj_to_uint8array!(&dp, false)));
                r.set(&JsValue::from(i as u32), &val);
            }
            _ => (),
        }
    }
    Ok(r)
}

#[wasm_bindgen(js_name = verifyBDDT16KeyedProof)]
pub fn verify_bddt16_keyed_proof(
    proof: Uint8Array,
    secret_key: Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let proof = obj_from_uint8array!(BDDT16Kp<G1Affine>, proof, false, "BDDT16KeyedProof");
    let sk = obj_from_uint8array!(BDDT16MACSecretKey, secret_key, true, "BDDT16MACSecretKey");
    to_verify_response!(proof.verify(sk.as_ref()))
}

#[wasm_bindgen(js_name = proofOfValidityOfBDDT16KeyedProof)]
pub fn proof_of_validity_of_bddt16_keyed_proof(
    proof: Uint8Array,
    secret_key: Uint8Array,
    public_key: Uint8Array,
    params: JsValue,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let proof = obj_from_uint8array!(BDDT16Kp<G1Affine>, proof, false, "BDDT16KeyedProof");
    let sk = obj_from_uint8array!(BDDT16MACSecretKey, secret_key, true, "BDDT16MACSecretKey");
    let pk = obj_from_uint8array!(
        BDDT16MACPublicKeyG1,
        public_key,
        false,
        "BDDT16MACPublicKeyG1"
    );
    let params: BDDT16MACParams = serde_wasm_bindgen::from_value(params)?;
    let mut rng = get_seeded_rng();
    let p = proof.create_proof_of_validity::<_, Blake2b512>(&mut rng, sk.0, &pk.0, &params.g_0);
    Ok(obj_to_uint8array!(
        &p,
        false,
        "ProofOfValidityOfBDDT16KeyedProof"
    ))
}

#[wasm_bindgen(js_name = verifyProofOfValidityOfBDDT16KeyedProof)]
pub fn verify_proof_of_validity_of_bddt16_keyed_proof(
    proof_of_validity: Uint8Array,
    keyed_proof: Uint8Array,
    public_key: Uint8Array,
    params: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let proof_of_validity = obj_from_uint8array!(
        BDDT16Pvkp<G1Affine>,
        proof_of_validity,
        false,
        "BDDT16ProofOfValidityOfKeyedProof"
    );
    let keyed_proof =
        obj_from_uint8array!(BDDT16Kp<G1Affine>, keyed_proof, false, "BDDT16KeyedProof");
    let pk = obj_from_uint8array!(
        BDDT16MACPublicKeyG1,
        public_key,
        false,
        "BDDT16MACPublicKeyG1"
    );
    let params: BDDT16MACParams = serde_wasm_bindgen::from_value(params)?;
    to_verify_response!(proof_of_validity.verify::<Blake2b512>(&keyed_proof, &pk.0, &params.g_0))
}

#[wasm_bindgen(js_name = proofOfInvalidityOfBDDT16KeyedProof)]
pub fn proof_of_invalidity_of_bddt16_keyed_proof(
    proof: Uint8Array,
    secret_key: Uint8Array,
    public_key: Uint8Array,
    params: JsValue,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let proof = obj_from_uint8array!(BDDT16Kp<G1Affine>, proof, false, "BDDT16KeyedProof");
    let sk = obj_from_uint8array!(BDDT16MACSecretKey, secret_key, true, "BDDT16MACSecretKey");
    let pk = obj_from_uint8array!(
        BDDT16MACPublicKeyG1,
        public_key,
        false,
        "BDDT16MACPublicKeyG1"
    );
    let params: BDDT16MACParams = serde_wasm_bindgen::from_value(params)?;
    let mut rng = get_seeded_rng();
    match proof.create_proof_of_invalidity::<_, Blake2b512>(&mut rng, sk.0, &pk.0, &params.g_0) {
        Ok(p) => Ok(obj_to_uint8array!(
            &p,
            false,
            "ProofOfInvalidityOfBDDT16KeyedProof"
        )),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = verifyProofOfInvalidityOfBDDT16KeyedProof)]
pub fn verify_proof_of_invalidity_of_bddt16_keyed_proof(
    proof_of_invalidity: Uint8Array,
    keyed_proof: Uint8Array,
    public_key: Uint8Array,
    params: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let proof_of_invalidity = obj_from_uint8array!(
        BDDT16Pivkp<G1Affine>,
        proof_of_invalidity,
        false,
        "BDDT16ProofOfInvalidityOfKeyedProof"
    );
    let keyed_proof =
        obj_from_uint8array!(BDDT16Kp<G1Affine>, keyed_proof, false, "BDDT16KeyedProof");
    let pk = obj_from_uint8array!(
        BDDT16MACPublicKeyG1,
        public_key,
        false,
        "BDDT16MACPublicKeyG1"
    );
    let params: BDDT16MACParams = serde_wasm_bindgen::from_value(params)?;
    to_verify_response!(proof_of_invalidity.verify::<Blake2b512>(&keyed_proof, &pk.0, &params.g_0))
}

#[wasm_bindgen(js_name = verifyVBAccumMembershipKeyedProof)]
pub fn verify_vb_accum_membership_keyed_proof(
    proof: Uint8Array,
    secret_key: Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let proof = obj_from_uint8array!(VBMemKp<G1Affine>, proof, false, "VBMembershipKeyedProof");
    let sk = obj_from_uint8array!(AccumSk, secret_key, true, "VBAccumulatorSk");
    to_verify_response!(proof.verify(&sk))
}

#[wasm_bindgen(js_name = proofOfValidityOfVBAccumMembershipKeyedProof)]
pub fn proof_of_validity_of_vb_accum_membership_keyed_proof(
    proof: Uint8Array,
    secret_key: Uint8Array,
    public_key: Uint8Array,
    params: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let proof = obj_from_uint8array!(VBMemKp<G1Affine>, proof, false, "VBMembershipKeyedProof");
    let sk = obj_from_uint8array!(AccumSk, secret_key, true, "VBAccumulatorSk");
    let pk = obj_from_uint8array!(AccumPkKV, public_key, false, "VBAccumulatorPkG1");
    let params = obj_from_uint8array!(AccumSetupParamsKV, params, false);
    let mut rng = get_seeded_rng();
    let p = proof.create_proof_of_validity::<_, Blake2b512>(&mut rng, &sk, &pk, &params);
    Ok(obj_to_uint8array!(
        &p,
        false,
        "ProofOfValidityOfVBAccumMembershipKeyedProof"
    ))
}

#[wasm_bindgen(js_name = verifyProofOfValidityOfVBAccumMembershipKeyedProof)]
pub fn verify_proof_of_validity_of_vb_accum_membership_keyed_proof(
    proof_of_validity: Uint8Array,
    keyed_proof: Uint8Array,
    public_key: Uint8Array,
    params: Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let proof_of_validity = obj_from_uint8array!(
        VbMemPvkp<G1Affine>,
        proof_of_validity,
        false,
        "ProofOfValidityOfVBAccumMembershipKeyedProof"
    );
    let keyed_proof = obj_from_uint8array!(VBMemKp<G1Affine>, keyed_proof, false, "VBMembershipKeyedProof");
    let pk = obj_from_uint8array!(AccumPkKV, public_key, false, "VBAccumulatorPkG1");
    let params = obj_from_uint8array!(AccumSetupParamsKV, params, false);
    to_verify_response!(proof_of_validity.verify::<Blake2b512>(&keyed_proof, &pk, &params))
}

#[wasm_bindgen(js_name = proofOfInvalidityOfVBAccumMembershipKeyedProof)]
pub fn proof_of_invalidity_of_vb_accum_membership_keyed_proof(
    proof: Uint8Array,
    secret_key: Uint8Array,
    public_key: Uint8Array,
    params: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let proof = obj_from_uint8array!(VBMemKp<G1Affine>, proof, false, "VBMembershipKeyedProof");
    let sk = obj_from_uint8array!(AccumSk, secret_key, true, "VBAccumulatorSk");
    let pk = obj_from_uint8array!(AccumPkKV, public_key, false, "VBAccumulatorPkG1");
    let params = obj_from_uint8array!(AccumSetupParamsKV, params, false);
    let mut rng = get_seeded_rng();
    match proof.create_proof_of_invalidity::<_, Blake2b512>(&mut rng, &sk, &pk, &params) {
        Ok(p) => Ok(obj_to_uint8array!(
            &p,
            false,
            "ProofOfInvalidityOfVBAccumMembershipKeyedProof"
        )),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = verifyProofOfInvalidityOfVBAccumMembershipKeyedProof)]
pub fn verify_proof_of_invalidity_of_vb_accum_membership_keyed_proof(
    proof_of_invalidity: Uint8Array,
    keyed_proof: Uint8Array,
    public_key: Uint8Array,
    params: Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let proof_of_invalidity = obj_from_uint8array!(
        VbMemPivkp<G1Affine>,
        proof_of_invalidity,
        false,
        "ProofOfInvalidityOfVBAccumMembershipKeyedProof"
    );
    let keyed_proof = obj_from_uint8array!(VBMemKp<G1Affine>, keyed_proof, false, "VBMembershipKeyedProof");
    let pk = obj_from_uint8array!(AccumPkKV, public_key, false, "VBAccumulatorPkG1");
    let params = obj_from_uint8array!(AccumSetupParamsKV, params, false);
    to_verify_response!(proof_of_invalidity.verify::<Blake2b512>(&keyed_proof, &pk, &params))
}

#[wasm_bindgen(js_name = verifyKBUniAccumMembershipKeyedProof)]
pub fn verify_kb_uni_accum_membership_keyed_proof(
    proof: Uint8Array,
    secret_key: Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let proof = obj_from_uint8array!(
        KBUniMemKp<G1Affine>,
        proof,
        false,
        "KBUniversalAccumulatorKeyedMembershipProof"
    );
    let sk = obj_from_uint8array!(AccumSk, secret_key, true, "VBAccumulatorSk");
    to_verify_response!(proof.verify(&sk))
}

#[wasm_bindgen(js_name = proofOfValidityOfKBUniAccumMembershipKeyedProof)]
pub fn proof_of_validity_of_kb_uni_accum_membership_keyed_proof(
    proof: Uint8Array,
    secret_key: Uint8Array,
    public_key: Uint8Array,
    params: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let proof = obj_from_uint8array!(KBUniMemKp<G1Affine>, proof, false, "KBUniMembershipKeyedProof");
    let sk = obj_from_uint8array!(AccumSk, secret_key, true, "VBAccumulatorSk");
    let pk = obj_from_uint8array!(AccumPkKV, public_key, false, "VBAccumulatorPkG1");
    let params = obj_from_uint8array!(AccumSetupParamsKV, params, false);
    let mut rng = get_seeded_rng();
    let p = proof.create_proof_of_validity::<_, Blake2b512>(&mut rng, &sk, &pk, &params);
    Ok(obj_to_uint8array!(
        &p,
        false,
        "ProofOfValidityOfKBUniAccumMembershipKeyedProof"
    ))
}

#[wasm_bindgen(js_name = verifyProofOfValidityOfKBUniAccumMembershipKeyedProof)]
pub fn verify_proof_of_validity_of_kb_uni_accum_membership_keyed_proof(
    proof_of_validity: Uint8Array,
    keyed_proof: Uint8Array,
    public_key: Uint8Array,
    params: Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let proof_of_validity = obj_from_uint8array!(
        KBUniMemPvkp<G1Affine>,
        proof_of_validity,
        false,
        "ProofOfValidityOfKBUniAccumMembershipKeyedProof"
    );
    let keyed_proof = obj_from_uint8array!(KBUniMemKp<G1Affine>, keyed_proof, false, "KBUniMembershipKeyedProof");
    let pk = obj_from_uint8array!(AccumPkKV, public_key, false, "VBAccumulatorPkG1");
    let params = obj_from_uint8array!(AccumSetupParamsKV, params, false);
    to_verify_response!(proof_of_validity.verify::<Blake2b512>(&keyed_proof, &pk, &params))
}

#[wasm_bindgen(js_name = proofOfInvalidityOfKBUniAccumMembershipKeyedProof)]
pub fn proof_of_invalidity_of_kb_uni_accum_membership_keyed_proof(
    proof: Uint8Array,
    secret_key: Uint8Array,
    public_key: Uint8Array,
    params: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let proof = obj_from_uint8array!(KBUniMemKp<G1Affine>, proof, false, "KBUniMembershipKeyedProof");
    let sk = obj_from_uint8array!(AccumSk, secret_key, true, "VBAccumulatorSk");
    let pk = obj_from_uint8array!(AccumPkKV, public_key, false, "VBAccumulatorPkG1");
    let params = obj_from_uint8array!(AccumSetupParamsKV, params, false);
    let mut rng = get_seeded_rng();
    match proof.create_proof_of_invalidity::<_, Blake2b512>(&mut rng, &sk, &pk, &params) {
        Ok(p) => Ok(obj_to_uint8array!(
            &p,
            false,
            "ProofOfInvalidityOfKBUniAccumMembershipKeyedProof"
        )),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = verifyProofOfInvalidityOfKBUniAccumMembershipKeyedProof)]
pub fn verify_proof_of_invalidity_of_kb_uni_accum_membership_keyed_proof(
    proof_of_invalidity: Uint8Array,
    keyed_proof: Uint8Array,
    public_key: Uint8Array,
    params: Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let proof_of_invalidity = obj_from_uint8array!(
        KBUniMemPivkp<G1Affine>,
        proof_of_invalidity,
        false,
        "ProofOfInvalidityOfKBUniAccumMembershipKeyedProof"
    );
    let keyed_proof = obj_from_uint8array!(KBUniMemKp<G1Affine>, keyed_proof, false, "KBUniMembershipKeyedProof");
    let pk = obj_from_uint8array!(AccumPkKV, public_key, false, "VBAccumulatorPkG1");
    let params = obj_from_uint8array!(AccumSetupParamsKV, params, false);
    to_verify_response!(proof_of_invalidity.verify::<Blake2b512>(&keyed_proof, &pk, &params))
}

#[wasm_bindgen(js_name = verifyKBUniAccumNonMembershipKeyedProof)]
pub fn verify_kb_uni_accum_non_membership_keyed_proof(
    proof: Uint8Array,
    secret_key: Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let proof = obj_from_uint8array!(
        KBUniNonMemKp<G1Affine>,
        proof,
        false,
        "KBUniversalAccumulatorKeyedNonMembershipProof"
    );
    let sk = obj_from_uint8array!(AccumSk, secret_key, true, "VBAccumulatorSk");
    to_verify_response!(proof.verify(&sk))
}

#[wasm_bindgen(js_name = proofOfValidityOfKBUniAccumNonMembershipKeyedProof)]
pub fn proof_of_validity_of_kb_uni_accum_non_membership_keyed_proof(
    proof: Uint8Array,
    secret_key: Uint8Array,
    public_key: Uint8Array,
    params: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let proof = obj_from_uint8array!(KBUniNonMemKp<G1Affine>, proof, false, "KBUniNonMembershipKeyedProof");
    let sk = obj_from_uint8array!(AccumSk, secret_key, true, "VBAccumulatorSk");
    let pk = obj_from_uint8array!(AccumPkKV, public_key, false, "VBAccumulatorPkG1");
    let params = obj_from_uint8array!(AccumSetupParamsKV, params, false);
    let mut rng = get_seeded_rng();
    let p = proof.create_proof_of_validity::<_, Blake2b512>(&mut rng, &sk, &pk, &params);
    Ok(obj_to_uint8array!(
        &p,
        false,
        "ProofOfValidityOfKBUniAccumNonMembershipKeyedProof"
    ))
}

#[wasm_bindgen(js_name = verifyProofOfValidityOfKBUniAccumNonMembershipKeyedProof)]
pub fn verify_proof_of_validity_of_kb_uni_accum_non_membership_keyed_proof(
    proof_of_validity: Uint8Array,
    keyed_proof: Uint8Array,
    public_key: Uint8Array,
    params: Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let proof_of_validity = obj_from_uint8array!(
        KBUniNonMemPvkp<G1Affine>,
        proof_of_validity,
        false,
        "ProofOfValidityOfKBUniAccumNonMembershipKeyedProof"
    );
    let keyed_proof = obj_from_uint8array!(KBUniNonMemKp<G1Affine>, keyed_proof, false, "KBUniNonMembershipKeyedProof");
    let pk = obj_from_uint8array!(AccumPkKV, public_key, false, "VBAccumulatorPkG1");
    let params = obj_from_uint8array!(AccumSetupParamsKV, params, false);
    to_verify_response!(proof_of_validity.verify::<Blake2b512>(&keyed_proof, &pk, &params))
}

#[wasm_bindgen(js_name = proofOfInvalidityOfKBUniAccumNonMembershipKeyedProof)]
pub fn proof_of_invalidity_of_kb_uni_accum_non_membership_keyed_proof(
    proof: Uint8Array,
    secret_key: Uint8Array,
    public_key: Uint8Array,
    params: Uint8Array,
) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let proof = obj_from_uint8array!(KBUniNonMemKp<G1Affine>, proof, false, "KBUniNonMembershipKeyedProof");
    let sk = obj_from_uint8array!(AccumSk, secret_key, true, "VBAccumulatorSk");
    let pk = obj_from_uint8array!(AccumPkKV, public_key, false, "VBAccumulatorPkG1");
    let params = obj_from_uint8array!(AccumSetupParamsKV, params, false);
    let mut rng = get_seeded_rng();
    match proof.create_proof_of_invalidity::<_, Blake2b512>(&mut rng, &sk, &pk, &params) {
        Ok(p) => Ok(obj_to_uint8array!(
            &p,
            false,
            "ProofOfInvalidityOfKBUniAccumNonMembershipKeyedProof"
        )),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = verifyProofOfInvalidityOfKBUniAccumNonMembershipKeyedProof)]
pub fn verify_proof_of_invalidity_of_kb_uni_accum_non_membership_keyed_proof(
    proof_of_invalidity: Uint8Array,
    keyed_proof: Uint8Array,
    public_key: Uint8Array,
    params: Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let proof_of_invalidity = obj_from_uint8array!(
        KBUniNonMemPivkp<G1Affine>,
        proof_of_invalidity,
        false,
        "ProofOfInvalidityOfKBUniAccumNonMembershipKeyedProof"
    );
    let keyed_proof = obj_from_uint8array!(KBUniNonMemKp<G1Affine>, keyed_proof, false, "KBUniNonMembershipKeyedProof");
    let pk = obj_from_uint8array!(AccumPkKV, public_key, false, "VBAccumulatorPkG1");
    let params = obj_from_uint8array!(AccumSetupParamsKV, params, false);
    to_verify_response!(proof_of_invalidity.verify::<Blake2b512>(&keyed_proof, &pk, &params))
}
