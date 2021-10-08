use crate::utils::{
    encode_message_for_signing, fr_from_jsvalue, fr_to_jsvalue, g1_affine_from_jsvalue,
    g1_affine_to_jsvalue, g2_affine_from_jsvalue, g2_affine_to_jsvalue, get_seeded_rng,
    message_bytes_to_messages, msgs_bytes_map_to_fr_btreemap, random_bytes, set_panic_hook,
};

use serde_wasm_bindgen::*;
use wasm_bindgen::prelude::*;

use crate::common::VerifyResponse;
use crate::Fr;
use ark_bls12_381::Bls12_381;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::collections::{BTreeMap, BTreeSet};
use bbs_plus::prelude::{
    KeypairG1, KeypairG2, PoKOfSignatureG1Proof, PoKOfSignatureG1Protocol, PublicKeyG1,
    PublicKeyG2, SecretKey, SignatureG1, SignatureG2, SignatureParamsG1, SignatureParamsG2,
};
use blake2::Blake2b;

pub(crate) type BBSPlusSk = SecretKey<Fr>;
pub(crate) type SigParamsG1 = SignatureParamsG1<Bls12_381>;
pub(crate) type SigParamsG2 = SignatureParamsG2<Bls12_381>;
pub(crate) type BBSPlusPkG1 = PublicKeyG1<Bls12_381>;
pub(crate) type BBSPlusPkG2 = PublicKeyG2<Bls12_381>;
pub(crate) type SigG1 = SignatureG1<Bls12_381>;
pub(crate) type SigG2 = SignatureG2<Bls12_381>;
pub(crate) type PoKOfSigProtocol = PoKOfSignatureG1Protocol<Bls12_381>;
pub(crate) type PoKOfSigProof = PoKOfSignatureG1Proof<Bls12_381>;

#[wasm_bindgen(js_name = generateSignatureParamsG1)]
pub async fn bbs_generate_g1_params(
    message_count: usize,
    label: Option<Vec<u8>>,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let label = label.unwrap_or_else(|| random_bytes());
    let params = SignatureParamsG1::<Bls12_381>::new::<Blake2b>(&label, message_count);
    serde_wasm_bindgen::to_value(&params)
}

#[wasm_bindgen(js_name = isSignatureParamsG1Valid)]
pub async fn bbs_is_params_g1_valid(params: JsValue) -> Result<bool, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    Ok(params.is_valid())
}

#[wasm_bindgen(js_name = bbsSignatureParamsG1MaxSupportedMsgs)]
pub async fn bbs_params_g1_max_supported_msgs(
    params: JsValue,
) -> Result<js_sys::Number, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    Ok(js_sys::Number::from(params.max_message_count() as i32))
}

#[wasm_bindgen(js_name = generateSignatureParamsG2)]
pub async fn bbs_generate_g2_params(
    message_count: usize,
    label: Option<Vec<u8>>,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let label = label.unwrap_or_else(|| random_bytes());
    let params = SignatureParamsG2::<Bls12_381>::new::<Blake2b>(&label, message_count);
    serde_wasm_bindgen::to_value(&params)
}

#[wasm_bindgen(js_name = isSignatureParamsG2Valid)]
pub async fn bbs_is_params_g2_valid(params: JsValue) -> Result<bool, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let params: SigParamsG2 = serde_wasm_bindgen::from_value(params)?;
    Ok(params.is_valid())
}

#[wasm_bindgen(js_name = bbsSignatureParamsG2MaxSupportedMsgs)]
pub async fn bbs_params_g2_max_supported_msgs(
    params: JsValue,
) -> Result<js_sys::Number, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let params: SigParamsG2 = serde_wasm_bindgen::from_value(params)?;
    Ok(js_sys::Number::from(params.max_message_count() as i32))
}

#[wasm_bindgen(js_name = generateBBSSigningKey)]
pub async fn bbs_generate_secret_key(
    seed: Option<Vec<u8>>,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let seed = seed.unwrap_or_else(|| random_bytes());
    let sk = BBSPlusSk::generate_using_seed::<Blake2b>(&seed);
    serde_wasm_bindgen::to_value(&sk)
}

#[wasm_bindgen(js_name = generateBBSPublicKeyG1)]
pub async fn bbs_generate_public_key_g1(
    secret_key: JsValue,
    params: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let sk: BBSPlusSk = serde_wasm_bindgen::from_value(secret_key)?;
    let params: SigParamsG2 = serde_wasm_bindgen::from_value(params)?;
    serde_wasm_bindgen::to_value(&BBSPlusPkG1::generate_using_secret_key(&sk, &params))
}

#[wasm_bindgen(js_name = isBBSPublicKeyG1Valid)]
pub async fn bbs_is_pubkey_g1_valid(
    public_key: JsValue,
) -> Result<bool, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let pk: BBSPlusPkG1 = serde_wasm_bindgen::from_value(public_key)?;
    Ok(pk.is_valid())
}

#[wasm_bindgen(js_name = generateBBSPublicKeyG2)]
pub async fn bbs_generate_public_key_g2(
    secret_key: JsValue,
    params: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let sk: BBSPlusSk = serde_wasm_bindgen::from_value(secret_key)?;
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    serde_wasm_bindgen::to_value(&BBSPlusPkG2::generate_using_secret_key(&sk, &params))
}

#[wasm_bindgen(js_name = isBBSPublicKeyG2Valid)]
pub async fn bbs_is_pubkey_g2_valid(
    public_key: JsValue,
) -> Result<bool, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let pk: BBSPlusPkG2 = serde_wasm_bindgen::from_value(public_key)?;
    Ok(pk.is_valid())
}

#[wasm_bindgen(js_name = generateBBSKeyPairG1)]
pub async fn bbs_generate_g1_keypair(
    params: JsValue,
    seed: Option<Vec<u8>>,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let params: SigParamsG2 = serde_wasm_bindgen::from_value(params)?;
    let seed = seed.unwrap_or(random_bytes());
    let keypair = KeypairG1::generate_using_seed::<Blake2b>(&seed, &params);
    serde_wasm_bindgen::to_value(&keypair)
}

#[wasm_bindgen(js_name = generateBBSKeyPairG2)]
pub async fn bbs_generate_g2_keypair(
    params: JsValue,
    seed: Option<Vec<u8>>,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let seed = seed.unwrap_or(random_bytes());
    let keypair = KeypairG2::generate_using_seed::<Blake2b>(&seed, &params);
    serde_wasm_bindgen::to_value(&keypair)
}

#[wasm_bindgen(js_name = bbsGetBasesForCommitmentG1)]
pub async fn bbs_get_bases_for_commitment_g1(
    params: JsValue,
    indices_to_commit: js_sys::Set,
) -> Result<js_sys::Array, serde_wasm_bindgen::Error> {
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let bases = js_sys::Array::new();
    bases.push(&g1_affine_to_jsvalue(&params.h_0)?);
    for i in indices_to_commit.values() {
        let index: usize = serde_wasm_bindgen::from_value(i.unwrap())?;
        if index >= params.max_message_count() {
            return Err(JsValue::from(&format!(
                "Invalid index {:?} to get signature param",
                index
            ))
            .into());
        }
        bases.push(&g1_affine_to_jsvalue(&params.h[index])?);
    }
    Ok(bases)
}

#[wasm_bindgen(js_name = bbsGetBasesForCommitmentG2)]
pub async fn bbs_get_bases_for_commitment_g2(
    params: JsValue,
    indices_to_commit: js_sys::Set,
) -> Result<js_sys::Array, serde_wasm_bindgen::Error> {
    let params: SigParamsG2 = serde_wasm_bindgen::from_value(params)?;
    let bases = js_sys::Array::new();
    bases.push(&g2_affine_to_jsvalue(&params.h_0)?);
    for i in indices_to_commit.values() {
        let index: usize = serde_wasm_bindgen::from_value(i.unwrap())?;
        if index >= params.max_message_count() {
            return Err(JsValue::from(&format!(
                "Invalid index {:?} to get signature param",
                index
            ))
            .into());
        }
        bases.push(&g2_affine_to_jsvalue(&params.h[index])?);
    }
    Ok(bases)
}

#[wasm_bindgen(js_name = bbsEncodeMessageForSigning)]
pub async fn bbs_encode_message_for_signing(
    message: Vec<u8>,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let fr = encode_message_for_signing(&message);
    let fr = fr_to_jsvalue(&fr)?;
    Ok(fr)
}

#[wasm_bindgen(js_name = bbsEncodeMessagesForSigning)]
pub async fn bbs_encode_messages_for_signing(
    messages: JsValue,
    indices_to_encode: js_sys::Set,
) -> Result<js_sys::Array, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let messages_as_bytes: Vec<Vec<u8>> = serde_wasm_bindgen::from_value(messages)?;
    let encoded = js_sys::Array::new();
    for i in indices_to_encode.values() {
        let index: usize = serde_wasm_bindgen::from_value(i.unwrap())?;
        if index >= messages_as_bytes.len() {
            return Err(JsValue::from(&format!("Invalid index {:?} to get message", index)).into());
        }
        let fr = encode_message_for_signing(&messages_as_bytes[index]);
        encoded.push(&fr_to_jsvalue(&fr)?);
    }
    Ok(encoded)
}

#[wasm_bindgen(js_name = bbsCommitMsgsInG1)]
pub async fn bbs_commit_to_message_in_g1(
    messages_to_commit: js_sys::Map,
    blinding: JsValue,
    params: JsValue,
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let msgs = msgs_bytes_map_to_fr_btreemap(&messages_to_commit, encode_messages)?;
    let msgs_ref = msgs
        .iter()
        .map(|(i, m)| (*i, m))
        .collect::<BTreeMap<_, _>>();

    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let blinding = fr_from_jsvalue(blinding)?;
    match params.commit_to_messages(msgs_ref, &blinding) {
        Ok(comm) => g1_affine_to_jsvalue(&comm),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsCommitMsgsInG2)]
pub async fn bbs_commit_to_message_in_g2(
    messages_to_commit: js_sys::Map,
    blinding: JsValue,
    params: JsValue,
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let msgs = msgs_bytes_map_to_fr_btreemap(&messages_to_commit, encode_messages)?;
    let msgs_ref = msgs
        .iter()
        .map(|(i, m)| (*i, m))
        .collect::<BTreeMap<_, _>>();

    let params: SigParamsG2 = serde_wasm_bindgen::from_value(params)?;
    let blinding = fr_from_jsvalue(blinding)?;
    match params.commit_to_messages(msgs_ref, &blinding) {
        Ok(comm) => g2_affine_to_jsvalue(&comm),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsSignG1)]
pub async fn bbs_sign_g1(
    messages: JsValue,
    secret_key: JsValue,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let messages_as_bytes: Vec<Vec<u8>> = serde_wasm_bindgen::from_value(messages)?;
    let sk: BBSPlusSk = serde_wasm_bindgen::from_value(secret_key)?;
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;

    let messages = message_bytes_to_messages(&messages_as_bytes, encode_messages);

    let mut rng = get_seeded_rng();
    match SigG1::new(&mut rng, &messages, &sk, &params) {
        // Ok(sig) => Ok(serde_wasm_bindgen::to_value(&sig).unwrap()),
        Ok(sig) => Ok(obj_to_uint8array!(&sig)),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsBlindSignG1)]
pub async fn bbs_blind_sign_g1(
    commitment: JsValue,
    uncommitted_messages: js_sys::Map,
    secret_key: JsValue,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let commitment = g1_affine_from_jsvalue(commitment)?;
    let msgs = msgs_bytes_map_to_fr_btreemap(&uncommitted_messages, encode_messages)?;
    let msgs_ref = msgs
        .iter()
        .map(|(i, m)| (*i, m))
        .collect::<BTreeMap<_, _>>();
    let sk: BBSPlusSk = serde_wasm_bindgen::from_value(secret_key)?;
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;

    let mut rng = get_seeded_rng();
    match SigG1::new_with_committed_messages(&mut rng, &commitment, msgs_ref, &sk, &params) {
        // Ok(sig) => Ok(serde_wasm_bindgen::to_value(&sig).unwrap()),
        Ok(sig) => Ok(obj_to_uint8array!(&sig)),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsUnblindSigG1)]
pub async fn bbs_unblind_sig_g1(
    blind_signature: js_sys::Uint8Array,
    blinding: JsValue,
) -> Result<js_sys::Uint8Array, serde_wasm_bindgen::Error> {
    set_panic_hook();
    // let signature: SigG1 = serde_wasm_bindgen::from_value(blind_signature)?;
    let signature = obj_from_uint8array!(SigG1, blind_signature);
    let blinding = fr_from_jsvalue(blinding)?;
    // serde_wasm_bindgen::to_value(&signature.unblind(&blinding))
    Ok(obj_to_uint8array!(&signature.unblind(&blinding)))
}

#[wasm_bindgen(js_name = bbsVerfiyG1)]
pub async fn bbs_verify_g1(
    messages: JsValue,
    signature: js_sys::Uint8Array,
    public_key: JsValue,
    params: JsValue,
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    // let signature: SigG1 = serde_wasm_bindgen::from_value(signature)?;
    let signature = obj_from_uint8array!(SigG1, signature);
    let pk: BBSPlusPkG2 = serde_wasm_bindgen::from_value(public_key)?;
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;

    let messages_as_bytes: Vec<Vec<u8>> = serde_wasm_bindgen::from_value(messages)?;
    let messages = message_bytes_to_messages(&messages_as_bytes, encode_messages);

    match signature.verify(messages.as_slice(), &pk, &params) {
        Ok(_) => Ok(serde_wasm_bindgen::to_value(&VerifyResponse {
            verified: true,
            error: None,
        })
        .unwrap()),
        Err(e) => Ok(serde_wasm_bindgen::to_value(&VerifyResponse {
            verified: false,
            error: Some(format!("{:?}", e)),
        })
        .unwrap()),
    }
}

#[wasm_bindgen(js_name = bbsSignG2)]
pub async fn bbs_sign_g2(
    messages: JsValue,
    secret_key: JsValue,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let messages_as_bytes: Vec<Vec<u8>> = serde_wasm_bindgen::from_value(messages)?;
    let sk: BBSPlusSk = serde_wasm_bindgen::from_value(secret_key)?;
    let params: SigParamsG2 = serde_wasm_bindgen::from_value(params)?;

    let messages = message_bytes_to_messages(&messages_as_bytes, encode_messages);

    let mut rng = get_seeded_rng();
    match SigG2::new(&mut rng, &messages, &sk, &params) {
        // Ok(sig) => Ok(serde_wasm_bindgen::to_value(&sig).unwrap()),
        Ok(sig) => Ok(obj_to_uint8array!(&sig)),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsBlindSignG2)]
pub async fn bbs_blind_sign_g2(
    commitment: JsValue,
    uncommitted_messages: js_sys::Map,
    secret_key: JsValue,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let commitment = g2_affine_from_jsvalue(commitment)?;
    let msgs = msgs_bytes_map_to_fr_btreemap(&uncommitted_messages, encode_messages)?;
    let msgs_ref = msgs
        .iter()
        .map(|(i, m)| (*i, m))
        .collect::<BTreeMap<_, _>>();
    let sk: BBSPlusSk = serde_wasm_bindgen::from_value(secret_key)?;
    let params: SigParamsG2 = serde_wasm_bindgen::from_value(params)?;

    let mut rng = get_seeded_rng();
    match SigG2::new_with_committed_messages(&mut rng, &commitment, msgs_ref, &sk, &params) {
        // Ok(sig) => Ok(serde_wasm_bindgen::to_value(&sig).unwrap()),
        Ok(sig) => Ok(obj_to_uint8array!(&sig)),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsUnblindSigG2)]
pub async fn bbs_unblind_sig_g2(
    blind_signature: js_sys::Uint8Array,
    blinding: JsValue,
) -> Result<js_sys::Uint8Array, serde_wasm_bindgen::Error> {
    set_panic_hook();
    // let signature: SigG2 = serde_wasm_bindgen::from_value(blind_signature)?;
    let signature = obj_from_uint8array!(SigG2, blind_signature);
    let blinding = fr_from_jsvalue(blinding)?;
    // serde_wasm_bindgen::to_value(&signature.unblind(&blinding))
    Ok(obj_to_uint8array!(&signature.unblind(&blinding)))
}

#[wasm_bindgen(js_name = bbsVerfiyG2)]
pub async fn bbs_verify_g2(
    messages: JsValue,
    signature: js_sys::Uint8Array,
    public_key: JsValue,
    params: JsValue,
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    // let signature: SigG2 = serde_wasm_bindgen::from_value(signature)?;
    let signature = obj_from_uint8array!(SigG2, signature);
    let pk: BBSPlusPkG1 = serde_wasm_bindgen::from_value(public_key)?;
    let params: SigParamsG2 = serde_wasm_bindgen::from_value(params)?;

    let messages_as_bytes: Vec<Vec<u8>> = serde_wasm_bindgen::from_value(messages)?;
    let messages = message_bytes_to_messages(&messages_as_bytes, encode_messages);

    match signature.verify(messages.as_slice(), &pk, &params) {
        Ok(_) => Ok(serde_wasm_bindgen::to_value(&VerifyResponse {
            verified: true,
            error: None,
        })
        .unwrap()),
        Err(e) => Ok(serde_wasm_bindgen::to_value(&VerifyResponse {
            verified: false,
            error: Some(format!("{:?}", e)),
        })
        .unwrap()),
    }
}

#[wasm_bindgen(js_name = bbsInitializeProofOfKnowledgeOfSignature)]
pub async fn bbs_initialize_proof_of_knowledge_of_signature(
    signature: js_sys::Uint8Array,
    params: JsValue,
    messages: JsValue,
    blindings: js_sys::Map,
    revealed_indices: js_sys::Set,
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    // let signature: SigG1 = serde_wasm_bindgen::from_value(signature)?;
    let signature = obj_from_uint8array!(SigG1, signature);
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let blindings = msgs_bytes_map_to_fr_btreemap(&blindings, false)?;

    let messages_as_bytes: Vec<Vec<u8>> = serde_wasm_bindgen::from_value(messages)?;
    let messages = message_bytes_to_messages(&messages_as_bytes, encode_messages);

    let mut indices = BTreeSet::new();
    for i in revealed_indices.values() {
        let index: usize = serde_wasm_bindgen::from_value(i.unwrap()).unwrap();
        indices.insert(index);
    }
    let mut rng = get_seeded_rng();
    match PoKOfSigProtocol::init(&mut rng, &signature, &params, &messages, blindings, indices) {
        Ok(sig) => Ok(serde_wasm_bindgen::to_value(&sig).unwrap()),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsGenProofOfKnowledgeOfSignature)]
pub async fn bbs_gen_proof(
    protocol: JsValue,
    challenge: JsValue,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let protocol: PoKOfSigProtocol = serde_wasm_bindgen::from_value(protocol)?;
    let challenge = fr_from_jsvalue(challenge)?;
    match protocol.gen_proof(&challenge) {
        // Ok(proof) => Ok(serde_wasm_bindgen::to_value(&proof).unwrap()),
        Ok(proof) => Ok(obj_to_uint8array!(&proof)),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

#[wasm_bindgen(js_name = bbsVerifyProofOfKnowledgeOfSignature)]
pub async fn bbs_verify_proof(
    proof: js_sys::Uint8Array,
    revealed_msgs: js_sys::Map,
    challenge: JsValue,
    public_key: JsValue,
    params: JsValue,
    encode_messages: bool,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    // let proof: PoKOfSigProof = serde_wasm_bindgen::from_value(proof)?;
    let proof: PoKOfSigProof = obj_from_uint8array!(PoKOfSigProof, proof);
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let public_key: BBSPlusPkG2 = serde_wasm_bindgen::from_value(public_key)?;
    let challenge = fr_from_jsvalue(challenge)?;

    let msgs = msgs_bytes_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;

    match proof.verify(&msgs, &challenge, &public_key, &params) {
        Ok(_) => Ok(serde_wasm_bindgen::to_value(&VerifyResponse {
            verified: true,
            error: None,
        })
        .unwrap()),
        Err(e) => Ok(serde_wasm_bindgen::to_value(&VerifyResponse {
            verified: false,
            error: Some(format!("{:?}", e)),
        })
        .unwrap()),
    }
}

#[wasm_bindgen(js_name = bbsChallengeContributionFromProtocol)]
pub async fn bbs_challenge_contribution_from_protocol(
    protocol: JsValue,
    revealed_msgs: js_sys::Map,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let protocol: PoKOfSigProtocol = serde_wasm_bindgen::from_value(protocol)?;
    let msgs = msgs_bytes_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let mut bytes = vec![];
    protocol
        .challenge_contribution(&msgs, &params, &mut bytes)
        .map_err(|e| {
            JsValue::from(&format!(
                "Evaluating challenge_contribution returned error: {:?}",
                e
            ))
        })?;
    Ok(js_sys::Uint8Array::from(bytes.as_slice()))
}

#[wasm_bindgen(js_name = bbsChallengeContributionFromProof)]
pub async fn bbs_challenge_contribution_from_proof(
    proof: js_sys::Uint8Array,
    revealed_msgs: js_sys::Map,
    params: JsValue,
    encode_messages: bool,
) -> Result<js_sys::Uint8Array, serde_wasm_bindgen::Error> {
    set_panic_hook();
    // let proof: PoKOfSigProof = serde_wasm_bindgen::from_value(proof)?;
    let proof: PoKOfSigProof = obj_from_uint8array!(PoKOfSigProof, proof);
    let msgs = msgs_bytes_map_to_fr_btreemap(&revealed_msgs, encode_messages)?;
    let params: SigParamsG1 = serde_wasm_bindgen::from_value(params)?;
    let mut bytes = vec![];
    proof
        .challenge_contribution(&msgs, &params, &mut bytes)
        .map_err(|e| {
            JsValue::from(&format!(
                "Evaluating challenge_contribution returned error: {:?}",
                e
            ))
        })?;
    Ok(js_sys::Uint8Array::from(bytes.as_slice()))
}
