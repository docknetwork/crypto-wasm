use crate::{
    accumulator::common::AccumSk, bddt16_kvac::BDDT16MACSecretKey, common::VerifyResponse,
    composite_proof_system::Proof, to_verify_response, utils::set_panic_hook, G1Affine,
};
use js_sys::Uint8Array;
use kvac::bddt_2016::delegated_proof::DelegatedProof as BDDT16Dp;
use proof_system::prelude::StatementProof;
use vb_accumulator::{
    kb_universal_accumulator::proofs_keyed_verification::{
        KBUniversalAccumulatorDelegatedMembershipProof as KBUniMemDp,
        KBUniversalAccumulatorDelegatedNonMembershipProof as KBUniNonMemDp,
    },
    proofs_keyed_verification::DelegatedMembershipProof as VBMemDp,
};
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
use zeroize::Zeroize;

#[wasm_bindgen(js_name = getAllDelegatedSubproofsFromProof)]
pub fn get_all_delegated_subproofs_from_proof(proof: Uint8Array) -> Result<js_sys::Map, JsValue> {
    set_panic_hook();
    let proof = obj_from_uint8array!(Proof, proof, false);
    let r = js_sys::Map::new();
    for (i, s) in proof.statement_proofs.into_iter().enumerate() {
        match s {
            StatementProof::PoKOfBDDT16MAC(p) => {
                let dp = p.to_delegated_proof();
                let val = js_sys::Array::new();
                val.push(&JsValue::from(0_u32));
                val.push(&JsValue::from(obj_to_uint8array!(&dp, false)));
                r.set(&JsValue::from(i as u32), &val);
            }
            StatementProof::VBAccumulatorMembershipKV(p) => {
                let dp = p.to_delegated_proof();
                let val = js_sys::Array::new();
                val.push(&JsValue::from(1_u32));
                val.push(&JsValue::from(obj_to_uint8array!(&dp, false)));
                r.set(&JsValue::from(i as u32), &val);
            }
            StatementProof::KBUniversalAccumulatorMembershipKV(p) => {
                let dp = p.to_delegated_proof();
                let val = js_sys::Array::new();
                val.push(&JsValue::from(2_u32));
                val.push(&JsValue::from(obj_to_uint8array!(&dp, false)));
                r.set(&JsValue::from(i as u32), &val);
            }
            StatementProof::KBUniversalAccumulatorNonMembershipKV(p) => {
                let dp = p.to_delegated_proof();
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

#[wasm_bindgen(js_name = verifyBDDT16DelegatedProof)]
pub fn verify_bddt16_delegated_proof(
    proof: Uint8Array,
    secret_key: Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let proof = obj_from_uint8array!(BDDT16Dp<G1Affine>, proof, false, "BDDT16DelegatedProof");
    let sk = obj_from_uint8array!(BDDT16MACSecretKey, secret_key, true, "BDDT16MACSecretKey");
    to_verify_response!(proof.verify(&sk))
}

#[wasm_bindgen(js_name = verifyVBAccumMembershipDelegatedProof)]
pub fn verify_vb_accum_membership_delegated_proof(
    proof: Uint8Array,
    secret_key: Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let proof = obj_from_uint8array!(
        VBMemDp<G1Affine>,
        proof,
        false,
        "VBMembershipDelegatedProof"
    );
    let sk = obj_from_uint8array!(AccumSk, secret_key, true, "VBAccumulatorSk");
    to_verify_response!(proof.verify(&sk))
}

#[wasm_bindgen(js_name = verifyKBUniAccumMembershipDelegatedProof)]
pub fn verify_kb_uni_accum_membership_delegated_proof(
    proof: Uint8Array,
    secret_key: Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let proof = obj_from_uint8array!(
        KBUniMemDp<G1Affine>,
        proof,
        false,
        "KBUniversalAccumulatorDelegatedMembershipProof"
    );
    let sk = obj_from_uint8array!(AccumSk, secret_key, true, "VBAccumulatorSk");
    to_verify_response!(proof.verify(&sk))
}

#[wasm_bindgen(js_name = verifyKBUniAccumNonMembershipDelegatedProof)]
pub fn verify_kb_uni_accum_non_membership_delegated_proof(
    proof: Uint8Array,
    secret_key: Uint8Array,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let proof = obj_from_uint8array!(
        KBUniNonMemDp<G1Affine>,
        proof,
        false,
        "KBUniversalAccumulatorDelegatedNonMembershipProof"
    );
    let sk = obj_from_uint8array!(AccumSk, secret_key, true, "VBAccumulatorSk");
    to_verify_response!(proof.verify(&sk))
}
