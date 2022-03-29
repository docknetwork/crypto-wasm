use crate::utils::{
    fr_to_jsvalue, g1_affine_to_jsvalue, get_seeded_rng, random_bytes, set_panic_hook,
};
use crate::Fr;
use ark_bls12_381::Bls12_381;
use ark_ec::PairingEngine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2::Blake2b;
use saver::{
    encryption::Ciphertext,
    keygen::{DecryptionKey, EncryptionKey, SecretKey},
    saver_groth16::{ProvingKey, VerifyingKey},
    setup::{setup_for_groth16, ChunkedCommitmentGens, EncryptionGens},
};
use serde_wasm_bindgen::*;
use wasm_bindgen::prelude::*;

pub(crate) type EncGens = EncryptionGens<Bls12_381>;
pub(crate) type ChunkedCommGens = ChunkedCommitmentGens<<Bls12_381 as PairingEngine>::G1Affine>;
pub(crate) type SaverSk = SecretKey<Fr>;
pub(crate) type SaverEk = EncryptionKey<Bls12_381>;
pub(crate) type SaverDk = DecryptionKey<Bls12_381>;
pub(crate) type SaverSnarkPk = ProvingKey<Bls12_381>;
pub(crate) type SaverSnarkVk = VerifyingKey<Bls12_381>;
pub(crate) type SaverCiphertext = Ciphertext<Bls12_381>;

#[wasm_bindgen(js_name = saverGenerateEncryptionGenerators)]
pub fn saver_generate_encryption_generators(
    label: Option<Vec<u8>>,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let label = label.unwrap_or_else(|| random_bytes());
    let gens = EncGens::new::<Blake2b>(&label);
    Ok(obj_to_uint8array!(&gens, "EncryptionGenerators"))
}

#[wasm_bindgen(js_name = saverGenerateChunkedCommitmentGenerators)]
pub fn saver_generate_chunked_commitment_generators(
    label: Option<Vec<u8>>,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let label = label.unwrap_or_else(|| random_bytes());
    let gens = ChunkedCommGens::new::<Blake2b>(&label);
    Ok(obj_to_uint8array!(&gens, "ChunkedCommitmentGenerators"))
}

#[wasm_bindgen(js_name = saverDecryptorSetup)]
pub fn saver_decryptor_setup(
    chunk_bit_size: u8,
    enc_gens: js_sys::Uint8Array,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    let enc_gens = obj_from_uint8array!(EncGens, enc_gens, "EncryptionGenerators");
    let mut rng = get_seeded_rng();
    let (snark_pk, sk, ek, dk) = setup_for_groth16(&mut rng, chunk_bit_size, &enc_gens)
        .map_err(|e| JsValue::from(&format!("Decryptor setup returned error: {:?}", e)))?;
    let setup = js_sys::Array::new();
    // setup.push(&serde_wasm_bindgen::to_value(&snark_pk)?);
    // setup.push(&serde_wasm_bindgen::to_value(&sk)?);
    // setup.push(&serde_wasm_bindgen::to_value(&ek)?);
    // setup.push(&serde_wasm_bindgen::to_value(&dk)?);
    let snark_pk = obj_to_uint8array!(&snark_pk, "SaverSnarkPk");
    let sk = obj_to_uint8array!(&sk, "SaverSk");
    let ek = obj_to_uint8array!(&ek, "SaverEk");
    let dk = obj_to_uint8array!(&dk, "SaverDk");
    setup.push(&snark_pk);
    setup.push(&sk);
    setup.push(&ek);
    setup.push(&dk);
    Ok(setup)
}

#[wasm_bindgen(js_name = saverDecryptCiphertextUsingSnarkVk)]
pub fn saver_decrypt_ciphertext_using_snark_vk(
    ciphertext: js_sys::Uint8Array,
    secret_key: js_sys::Uint8Array,
    decryption_key: js_sys::Uint8Array,
    snark_vk: js_sys::Uint8Array,
    chunk_bit_size: u8,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    let ct = obj_from_uint8array!(SaverCiphertext, ciphertext, "SaverCiphertext");
    let sk = obj_from_uint8array!(SaverSk, secret_key, "SaverSk");
    let dk = obj_from_uint8array!(SaverDk, decryption_key, "SaverDk");
    let snark_vk = obj_from_uint8array!(SaverSnarkVk, snark_vk, "SaverSnarkVk");
    let (decrypted_message, nu) = ct
        .decrypt_given_groth16_vk(&sk, &dk, &snark_vk, chunk_bit_size)
        .map_err(|e| JsValue::from(&format!("Decryption returned error: {:?}", e)))?;
    let dec = js_sys::Array::new();
    dec.push(&fr_to_jsvalue(&decrypted_message)?);
    dec.push(&g1_affine_to_jsvalue(&nu)?);
    Ok(dec)
}

#[wasm_bindgen(js_name = saverDecryptCiphertextUsingSnarkPk)]
pub fn saver_decrypt_ciphertext_using_snark_pk(
    ciphertext: js_sys::Uint8Array,
    secret_key: js_sys::Uint8Array,
    decryption_key: js_sys::Uint8Array,
    snark_pk: js_sys::Uint8Array,
    chunk_bit_size: u8,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    let ct = obj_from_uint8array!(SaverCiphertext, ciphertext, "SaverCiphertext");
    let sk = obj_from_uint8array!(SaverSk, secret_key, "SaverSk");
    let dk = obj_from_uint8array!(SaverDk, decryption_key, "SaverDk");
    let snark_pk = obj_from_uint8array!(SaverSnarkPk, snark_pk, "SaverSnarkPk");
    let (decrypted_message, nu) = ct
        .decrypt_given_groth16_vk(&sk, &dk, &snark_pk.pk.vk, chunk_bit_size)
        .map_err(|e| JsValue::from(&format!("Decryption returned error: {:?}", e)))?;
    let dec = js_sys::Array::new();
    dec.push(&fr_to_jsvalue(&decrypted_message)?);
    dec.push(&g1_affine_to_jsvalue(&nu)?);
    Ok(dec)
}
