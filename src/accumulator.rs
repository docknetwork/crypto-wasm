use crate::utils::{random_bytes, set_panic_hook};

use ark_bls12_381::Bls12_381;
use ark_ec::PairingEngine;
use ark_ff::fields::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::collections::{BTreeMap, BTreeSet};
use ark_std::rand::{rngs::StdRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::*;
use wasm_bindgen::prelude::*;

use vb_accumulator::prelude::{Keypair, PublicKey, SecretKey, SetupParams};

use crate::Fr;
use blake2::Blake2b;
use std::convert::{TryFrom, TryInto};

type AccumSk = SecretKey<Fr>;
type AccumPk = PublicKey<<Bls12_381 as PairingEngine>::G2Affine>;
type AccumSetupParams = SetupParams<Bls12_381>;
type AccumKeypair = Keypair<Bls12_381>;

#[wasm_bindgen(js_name = generateAccumulatorParams)]
pub async fn generate_accumulator_params_using_seed(
    label: Option<Vec<u8>>,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let label = label.unwrap_or_else(|| random_bytes());
    let params = AccumSetupParams::new::<Blake2b>(&label);
    serde_wasm_bindgen::to_value(&params)
}

#[wasm_bindgen(js_name = generateAccumulatorSecretKey)]
pub async fn accumulator_secret_key(
    seed: Option<Vec<u8>>,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let seed = seed.unwrap_or_else(|| random_bytes());
    let sk = AccumSk::generate_using_seed::<Blake2b>(&seed);
    serde_wasm_bindgen::to_value(&sk)
}

#[wasm_bindgen(js_name = generateAccumulatorPublicKey)]
pub async fn accumulator_generate_public_key(
    secret_key: JsValue,
    params: JsValue,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let sk: AccumSk = serde_wasm_bindgen::from_value(secret_key)?;
    let params: AccumSetupParams = serde_wasm_bindgen::from_value(params)?;
    serde_wasm_bindgen::to_value(&AccumKeypair::public_key_from_secret_key(&sk, &params))
}

#[wasm_bindgen(js_name = generateAccumulatorKeyPair)]
pub async fn accumulator_generate_keypair(
    params: JsValue,
    seed: Option<Vec<u8>>,
) -> Result<JsValue, serde_wasm_bindgen::Error> {
    set_panic_hook();
    let params: AccumSetupParams = serde_wasm_bindgen::from_value(params)?;
    let seed = seed.unwrap_or(random_bytes());
    let keypair = AccumKeypair::generate_using_seed::<Blake2b>(&seed, &params);
    serde_wasm_bindgen::to_value(&keypair)
}
