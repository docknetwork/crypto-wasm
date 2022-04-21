use crate::common::VerifyResponse;
use crate::utils::{
    fr_from_uint8_array, fr_to_uint8_array, g1_affine_from_uint8_array, g1_affine_to_uint8_array,
    get_seeded_rng, random_bytes, set_panic_hook,
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
    return_uncompressed_snark_pk: bool,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    let enc_gens = obj_from_uint8array!(EncGens, enc_gens, "EncryptionGenerators");
    let mut rng = get_seeded_rng();
    let (snark_pk, sk, ek, dk) = setup_for_groth16(&mut rng, chunk_bit_size, &enc_gens)
        .map_err(|e| JsValue::from(&format!("Decryptor setup returned error: {:?}", e)))?;
    let setup = js_sys::Array::new();
    let snark_pk = if return_uncompressed_snark_pk {
        obj_to_uint8array_unchecked!(&snark_pk, "SaverSnarkPk")
    } else {
        obj_to_uint8array!(&snark_pk, "SaverSnarkPk")
    };
    let sk = obj_to_uint8array!(&sk, "SaverSk");
    let ek = obj_to_uint8array!(&ek, "SaverEk");
    let dk = obj_to_uint8array!(&dk, "SaverDk");
    setup.push(&snark_pk);
    setup.push(&sk);
    setup.push(&ek);
    setup.push(&dk);
    Ok(setup)
}

#[wasm_bindgen(js_name = saverDecompressEncryptionGenerators)]
pub fn saver_decompress_encryption_generators(
    enc_gens: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    let enc_gens = obj_from_uint8array!(EncGens, enc_gens, "EncryptionGenerators");
    Ok(obj_to_uint8array_unchecked!(
        &enc_gens,
        "EncryptionGenerators"
    ))
}

#[wasm_bindgen(js_name = saverDecompressChunkedCommitmentGenerators)]
pub fn saver_decompress_chunked_commitment_generators(
    comm_gens: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    let comm_gens = obj_from_uint8array!(ChunkedCommGens, comm_gens, "ChunkedCommitmentGenerators");
    Ok(obj_to_uint8array_unchecked!(
        &comm_gens,
        "ChunkedCommitmentGenerators"
    ))
}

#[wasm_bindgen(js_name = saverDecompressEncryptionKey)]
pub fn saver_decompress_encryption_key(
    enc_key: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    let enc_key = obj_from_uint8array!(SaverEk, enc_key, "SaverEk");
    Ok(obj_to_uint8array_unchecked!(&enc_key, "SaverEk"))
}

#[wasm_bindgen(js_name = saverDecompressDecryptionKey)]
pub fn saver_decompress_decryption_key(
    dec_key: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    let dec_key = obj_from_uint8array!(SaverDk, dec_key, "SaverDk");
    Ok(obj_to_uint8array_unchecked!(&dec_key, "SaverDk"))
}

#[wasm_bindgen(js_name = saverDecompressSnarkPk)]
pub fn saver_decompress_snark_pk(
    snark_pk: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    let snark_pk = obj_from_uint8array!(SaverSnarkPk, snark_pk, "SaverSnarkPk");
    Ok(obj_to_uint8array_unchecked!(&snark_pk, "SaverSnarkPk"))
}

/// Return the compressed or uncompressed SNARK verification key from compressed proving key
#[wasm_bindgen(js_name = saverGetSnarkVkFromPk)]
pub fn saver_get_snark_vk_from_pk(
    snark_pk: js_sys::Uint8Array,
    return_uncompressed: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    let snark_pk = obj_from_uint8array!(SaverSnarkPk, snark_pk, "SaverSnarkPk");
    Ok(if return_uncompressed {
        obj_to_uint8array_unchecked!(&snark_pk.pk.vk, "SaverSnarkVk")
    } else {
        obj_to_uint8array!(&snark_pk.pk.vk, "SaverSnarkVk")
    })
}

#[wasm_bindgen(js_name = saverDecompressSnarkVk)]
pub fn saver_decompress_snark_vk(
    snark_vk: js_sys::Uint8Array,
) -> Result<js_sys::Uint8Array, JsValue> {
    let snark_vk = obj_from_uint8array!(SaverSnarkVk, snark_vk, "SaverSnarkVk");
    Ok(obj_to_uint8array_unchecked!(&snark_vk, "SaverSnarkVk"))
}

#[wasm_bindgen(js_name = saverDecryptCiphertextUsingSnarkVk)]
pub fn saver_decrypt_ciphertext_using_snark_vk(
    ciphertext: js_sys::Uint8Array,
    secret_key: js_sys::Uint8Array,
    decryption_key: js_sys::Uint8Array,
    snark_vk: js_sys::Uint8Array,
    chunk_bit_size: u8,
    uncompressed_public_params: bool,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    let snark_vk = if uncompressed_public_params {
        obj_from_uint8array_unchecked!(SaverSnarkVk, snark_vk, "SaverSnarkVk")
    } else {
        obj_from_uint8array!(SaverSnarkVk, snark_vk, "SaverSnarkVk")
    };
    decrypt(
        ciphertext,
        secret_key,
        decryption_key,
        &snark_vk,
        chunk_bit_size,
        uncompressed_public_params,
    )
}

#[wasm_bindgen(js_name = saverDecryptCiphertextUsingSnarkPk)]
pub fn saver_decrypt_ciphertext_using_snark_pk(
    ciphertext: js_sys::Uint8Array,
    secret_key: js_sys::Uint8Array,
    decryption_key: js_sys::Uint8Array,
    snark_pk: js_sys::Uint8Array,
    chunk_bit_size: u8,
    uncompressed_public_params: bool,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    let snark_pk = if uncompressed_public_params {
        obj_from_uint8array_unchecked!(SaverSnarkPk, snark_pk, "SaverSnarkPk")
    } else {
        obj_from_uint8array!(SaverSnarkPk, snark_pk, "SaverSnarkPk")
    };
    decrypt(
        ciphertext,
        secret_key,
        decryption_key,
        &snark_pk.pk.vk,
        chunk_bit_size,
        uncompressed_public_params,
    )
}

#[wasm_bindgen(js_name = saverVerifyDecryptionUsingSnarkPk)]
pub fn saver_verify_decryption_using_snark_pk(
    ciphertext: js_sys::Uint8Array,
    decrypted_message: js_sys::Uint8Array,
    nu: js_sys::Uint8Array,
    decryption_key: js_sys::Uint8Array,
    snark_pk: js_sys::Uint8Array,
    enc_gens: js_sys::Uint8Array,
    chunk_bit_size: u8,
    uncompressed_public_params: bool,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let snark_pk = if uncompressed_public_params {
        obj_from_uint8array_unchecked!(SaverSnarkPk, snark_pk, "SaverSnarkPk")
    } else {
        obj_from_uint8array!(SaverSnarkPk, snark_pk, "SaverSnarkPk")
    };
    verify_decryption(
        ciphertext,
        decrypted_message,
        nu,
        decryption_key,
        &snark_pk.pk.vk,
        enc_gens,
        chunk_bit_size,
        uncompressed_public_params,
    )
}

#[wasm_bindgen(js_name = saverVerifyDecryptionUsingSnarkVk)]
pub fn saver_verify_decryption_using_snark_vk(
    ciphertext: js_sys::Uint8Array,
    decrypted_message: js_sys::Uint8Array,
    nu: js_sys::Uint8Array,
    decryption_key: js_sys::Uint8Array,
    snark_vk: js_sys::Uint8Array,
    enc_gens: js_sys::Uint8Array,
    chunk_bit_size: u8,
    uncompressed_public_params: bool,
) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let snark_vk = if uncompressed_public_params {
        obj_from_uint8array_unchecked!(SaverSnarkVk, snark_vk, "SaverSnarkVk")
    } else {
        obj_from_uint8array!(SaverSnarkVk, snark_vk, "SaverSnarkVk")
    };
    verify_decryption(
        ciphertext,
        decrypted_message,
        nu,
        decryption_key,
        &snark_vk,
        enc_gens,
        chunk_bit_size,
        uncompressed_public_params,
    )
}

fn decrypt(
    ciphertext: js_sys::Uint8Array,
    secret_key: js_sys::Uint8Array,
    decryption_key: js_sys::Uint8Array,
    snark_vk: &SaverSnarkVk,
    chunk_bit_size: u8,
    uncompressed_public_params: bool,
) -> Result<js_sys::Array, JsValue> {
    let ct = obj_from_uint8array!(SaverCiphertext, ciphertext, "SaverCiphertext");
    let sk = obj_from_uint8array!(SaverSk, secret_key, "SaverSk");
    let dk = if uncompressed_public_params {
        obj_from_uint8array_unchecked!(SaverDk, decryption_key, "SaverDk")
    } else {
        obj_from_uint8array!(SaverDk, decryption_key, "SaverDk")
    };
    let (decrypted_message, nu) = ct
        .decrypt_given_groth16_vk(&sk, &dk, snark_vk, chunk_bit_size)
        .map_err(|e| JsValue::from(&format!("Decryption returned error: {:?}", e)))?;
    let dec = js_sys::Array::new();
    let m = fr_to_uint8_array(&decrypted_message)?;
    let nu = g1_affine_to_uint8_array(&nu)?;
    dec.push(&m);
    dec.push(&nu);
    Ok(dec)
}

fn verify_decryption(
    ciphertext: js_sys::Uint8Array,
    decrypted_message: js_sys::Uint8Array,
    nu: js_sys::Uint8Array,
    decryption_key: js_sys::Uint8Array,
    snark_vk: &SaverSnarkVk,
    enc_gens: js_sys::Uint8Array,
    chunk_bit_size: u8,
    uncompressed_public_params: bool,
) -> Result<JsValue, JsValue> {
    let (enc_gens, dk) = if uncompressed_public_params {
        (
            obj_from_uint8array_unchecked!(EncGens, enc_gens, "EncryptionGenerators"),
            obj_from_uint8array_unchecked!(SaverDk, decryption_key, "SaverDk"),
        )
    } else {
        (
            obj_from_uint8array!(EncGens, enc_gens, "EncryptionGenerators"),
            obj_from_uint8array!(SaverDk, decryption_key, "SaverDk"),
        )
    };
    let ct = obj_from_uint8array!(SaverCiphertext, ciphertext, "SaverCiphertext");
    let decrypted_message = fr_from_uint8_array(decrypted_message).unwrap();
    let nu = g1_affine_from_uint8_array(nu).unwrap();
    match ct.verify_decryption_given_groth16_vk(
        &decrypted_message,
        &nu,
        chunk_bit_size,
        &dk,
        snark_vk,
        &enc_gens,
    ) {
        Ok(_) => Ok(serde_wasm_bindgen::to_value(&VerifyResponse {
            verified: true,
            error: None,
        })
        .unwrap()),
        Err(e) => Ok(serde_wasm_bindgen::to_value(&VerifyResponse {
            verified: false,
            error: Some(format!("Verifying decryption returned error {:?}", e)),
        })
        .unwrap()),
    }
}
