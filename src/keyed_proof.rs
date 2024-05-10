use crate::{
    accumulator::common::AccumSk, bddt16_kvac::BDDT16MACSecretKey, common::VerifyResponse,
    composite_proof_system::Proof, to_verify_response, utils::set_panic_hook, G1Affine,
};
use js_sys::Uint8Array;
use kvac::bddt_2016::keyed_proof::KeyedProof as BDDT16Kp;
use proof_system::prelude::StatementProof;
use vb_accumulator::{
    kb_universal_accumulator::proofs_keyed_verification::{
        KBUniversalAccumulatorKeyedMembershipProof as KBUniMemKp,
        KBUniversalAccumulatorKeyedNonMembershipProof as KBUniNonMemKp,
    },
    proofs_keyed_verification::KeyedMembershipProof as VBMemDp,
};
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
use zeroize::Zeroize;

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

#[wasm_bindgen(js_name = verifyVBAccumMembershipKeyedProof)]
pub fn verify_vb_accum_membership_keyed_proof(
    proof: Uint8Array,
    secret_key: Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let proof = obj_from_uint8array!(
        VBMemDp<G1Affine>,
        proof,
        false,
        "VBMembershipKeyedProof"
    );
    let sk = obj_from_uint8array!(AccumSk, secret_key, true, "VBAccumulatorSk");
    to_verify_response!(proof.verify(&sk))
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
