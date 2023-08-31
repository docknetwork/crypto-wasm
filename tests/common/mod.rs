use ark_std::collections::BTreeSet;
use dock_crypto_wasm::{
    accumulator::{
        accumulator_generate_public_key, accumulator_generate_secret_key,
        generate_accumulator_params, universal_accumulator_compute_initial_fv,
        universal_accumulator_fixed_initial_elements, universal_accumulator_initialize_given_f_v,
    },
    bbs_plus::{
        bbs_plus_generate_g1_params, bbs_plus_generate_public_key_g2, bbs_plus_generate_secret_key,
    },
    common::random_ff,
    composite_proof_system::statement::generate_witness_equality_meta_statement,
    utils::{js_array_from_frs, random_bytes},
};
use js_sys::Uint8Array;
use wasm_bindgen::JsValue;

pub fn bbs_params_and_keys(message_count: u32) -> (JsValue, Uint8Array, Uint8Array) {
    let params = bbs_plus_generate_g1_params(message_count, None).unwrap();
    let sk = bbs_plus_generate_secret_key(None).unwrap();
    let pk = bbs_plus_generate_public_key_g2(sk.clone(), params.clone()).unwrap();
    (params, sk, pk)
}

pub fn gen_msgs(count: u32) -> Vec<Vec<u8>> {
    (0..count).map(|_| random_bytes()).collect::<Vec<Vec<u8>>>()
}

pub fn get_revealed_unrevealed(
    msgs: &Vec<Vec<u8>>,
    revealed_indices: &BTreeSet<usize>,
) -> (js_sys::Map, js_sys::Map) {
    let revealed_msgs = js_sys::Map::new();
    let unrevealed_msgs = js_sys::Map::new();
    for i in 0..msgs.len() {
        if revealed_indices.contains(&i) {
            revealed_msgs.set(
                &JsValue::from(i as u32),
                &serde_wasm_bindgen::to_value(&msgs[i]).unwrap(),
            );
        } else {
            unrevealed_msgs.set(
                &JsValue::from(i as u32),
                &serde_wasm_bindgen::to_value(&msgs[i]).unwrap(),
            );
        }
    }
    (revealed_msgs, unrevealed_msgs)
}

pub fn get_witness_equality_statement(witness_refs: Vec<(u32, u32)>) -> JsValue {
    let equality = js_sys::Set::new(&JsValue::undefined());
    for (s, w) in witness_refs {
        let wit_ref = js_sys::Array::new();
        wit_ref.push(&JsValue::from(s));
        wit_ref.push(&JsValue::from(w));
        equality.add(&wit_ref);
    }
    generate_witness_equality_meta_statement(equality).unwrap()
}

pub fn accum_params_and_keys() -> (Uint8Array, JsValue, Uint8Array) {
    let params = generate_accumulator_params(None).unwrap();
    let sk = accumulator_generate_secret_key(None).unwrap();
    let pk = accumulator_generate_public_key(sk.clone(), params.clone()).unwrap();
    (params, sk, pk)
}

pub fn get_universal_accum(sk: JsValue, params: Uint8Array, max_size: u32) -> JsValue {
    let initial_elements = (0..max_size + 1)
        .map(|_| random_ff(None))
        .collect::<Vec<_>>();

    let initial_fixed = universal_accumulator_fixed_initial_elements().unwrap();
    let initial_elements_arr = js_array_from_frs(initial_elements.as_slice()).unwrap();

    let all_initial_elements = initial_fixed.concat(&initial_elements_arr);

    let f_v = universal_accumulator_compute_initial_fv(all_initial_elements, sk).unwrap();
    universal_accumulator_initialize_given_f_v(f_v, params, max_size).unwrap()
}
