#![cfg(target_arch = "wasm32")]
extern crate wasm_bindgen_test;

use ark_bls12_381::Bls12_381;
use vb_accumulator::prelude::{PositiveAccumulator, UniversalAccumulator};
use wasm::accumulator::*;
use wasm::common::{
    generate_challenge_from_bytes, generate_random_field_element, random_ff, VerifyResponse,
};
use wasm::utils::{fr_from_uint8_array, js_array_from_frs};
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

fn js_value_to_bytes(js_value: JsValue) -> Vec<u8> {
    serde_wasm_bindgen::from_value::<Vec<u8>>(js_value).unwrap()
}

fn get_params_and_keys(
    label: Option<Vec<u8>>,
) -> (js_sys::Uint8Array, JsValue, js_sys::Uint8Array) {
    let params = generate_accumulator_params(label).unwrap();

    let seed = vec![0, 1, 2, 5, 10, 13];
    let sk = accumulator_generate_secret_key(Some(seed.clone())).unwrap();
    let pk = accumulator_generate_public_key(sk.clone(), params.clone()).unwrap();
    (params, sk, pk)
}

fn get_universal_accum(sk: JsValue, params: js_sys::Uint8Array, max_size: u32) -> JsValue {
    let initial_elements = (0..max_size + 1)
        .map(|_| random_ff(None))
        .collect::<Vec<_>>();

    let initial_fixed = universal_accumulator_fixed_initial_elements().unwrap();
    let initial_elements_arr = js_array_from_frs(initial_elements.as_slice()).unwrap();

    let all_initial_elements = initial_fixed.concat(&initial_elements_arr);

    let f_v = universal_accumulator_compute_initial_fv(all_initial_elements, sk).unwrap();
    universal_accumulator_initialize_given_f_v(f_v, params, max_size).unwrap()
}

fn positive_accumulator_verify_membership_for_batch(
    accum: JsValue,
    batch: js_sys::Array,
    witnesses: &js_sys::Array,
    pk: js_sys::Uint8Array,
    params: js_sys::Uint8Array,
) {
    let accum = positive_accumulator_get_accumulated(accum).unwrap();
    for w in witnesses.entries() {
        let arr = js_sys::Array::from(&w.unwrap());
        let i: u32 = serde_wasm_bindgen::from_value(arr.get(0)).unwrap();
        let witness = arr.get(1);
        assert!(positive_accumulator_verify_membership(
            accum.clone(),
            js_sys::Uint8Array::new(&batch.get(i)),
            witness,
            pk.clone(),
            params.clone()
        )
        .unwrap());
    }
}

fn universal_accumulator_verify_membership_for_batch(
    accum: JsValue,
    batch: js_sys::Array,
    witnesses: &js_sys::Array,
    pk: js_sys::Uint8Array,
    params: js_sys::Uint8Array,
) {
    let accum = universal_accumulator_get_accumulated(accum).unwrap();
    for w in witnesses.entries() {
        let arr = js_sys::Array::from(&w.unwrap());
        let i: u32 = serde_wasm_bindgen::from_value(arr.get(0)).unwrap();
        let witness = arr.get(1);
        assert!(universal_accumulator_verify_membership(
            accum.clone(),
            js_sys::Uint8Array::new(&batch.get(i)),
            witness,
            pk.clone(),
            params.clone()
        )
        .unwrap());
    }
}

fn verify_non_membership_for_batch(
    accum: JsValue,
    non_members: js_sys::Array,
    witnesses: &js_sys::Array,
    pk: js_sys::Uint8Array,
    params: js_sys::Uint8Array,
) {
    let accum = universal_accumulator_get_accumulated(accum).unwrap();
    for w in witnesses.entries() {
        let arr = js_sys::Array::from(&w.unwrap());
        let i: u32 = serde_wasm_bindgen::from_value(arr.get(0)).unwrap();
        let witness = arr.get(1);
        assert!(universal_accumulator_verify_non_membership(
            accum.clone(),
            js_sys::Uint8Array::new(&non_members.get(i)),
            witness,
            pk.clone(),
            params.clone()
        )
        .unwrap());
    }
}

fn positive_accumulator_create_verify_membership_for_batch(
    accum: JsValue,
    batch: js_sys::Array,
    sk: JsValue,
    pk: js_sys::Uint8Array,
    params: js_sys::Uint8Array,
) -> js_sys::Array {
    let witnesses =
        positive_accumulator_membership_witnesses_for_batch(accum.clone(), batch.clone(), sk)
            .unwrap();
    positive_accumulator_verify_membership_for_batch(accum, batch, &witnesses, pk, params);

    witnesses
}

fn universal_accumulator_create_verify_membership_for_batch(
    accum: JsValue,
    batch: js_sys::Array,
    sk: JsValue,
    pk: js_sys::Uint8Array,
    params: js_sys::Uint8Array,
) -> js_sys::Array {
    let witnesses =
        universal_accumulator_membership_witnesses_for_batch(accum.clone(), batch.clone(), sk)
            .unwrap();
    universal_accumulator_verify_membership_for_batch(accum, batch, &witnesses, pk, params);

    witnesses
}

fn create_verify_non_membership_for_batch(
    accum: JsValue,
    non_members_array: js_sys::Array,
    members_array: js_sys::Array,
    sk: JsValue,
    pk: js_sys::Uint8Array,
    params: js_sys::Uint8Array,
) -> js_sys::Array {
    let d = universal_accumulator_compute_d_for_batch(non_members_array.clone(), members_array)
        .unwrap();
    let witnesses = universal_accumulator_non_membership_witnesses_for_batch(
        accum.clone(),
        d,
        non_members_array.clone(),
        sk,
        params.clone(),
    )
    .unwrap();
    verify_non_membership_for_batch(accum, non_members_array, &witnesses, pk, params);

    witnesses
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn accumulator_params_and_keygen() {
    let label = b"test".to_vec();
    let params = generate_accumulator_params(Some(label)).unwrap();
    assert!(accumulator_is_params_valid(params.clone()).unwrap());

    let seed = vec![0, 1, 2, 5, 10, 13];

    let keypair = accumulator_generate_keypair(params.clone(), Some(seed.clone())).unwrap();

    let keypair_obj = js_sys::Object::try_from(&keypair).unwrap();

    let keys = js_sys::Object::keys(&keypair_obj);
    assert_eq!(keys.get(0), "secret_key");
    assert_eq!(keys.get(1), "public_key");

    let sk = accumulator_generate_secret_key(Some(seed.clone())).unwrap();
    let sk_1 = accumulator_generate_secret_key(Some(seed)).unwrap();
    assert_eq!(js_value_to_bytes(sk.clone()), js_value_to_bytes(sk_1));

    let pk = accumulator_generate_public_key(sk.clone(), params.clone()).unwrap();
    assert!(accumulator_is_pubkey_valid(pk.clone()).unwrap());

    let values_obj = js_sys::Object::values(&keypair_obj);
    assert_eq!(
        js_value_to_bytes(values_obj.get(0)),
        js_value_to_bytes(sk.clone())
    );
    assert_eq!(js_value_to_bytes(values_obj.get(1)), pk.to_vec());
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn positive_accumulator_membership() {
    let label = b"test".to_vec();
    let (params, sk, pk) = get_params_and_keys(Some(label));

    let mut accumulator = positive_accumulator_initialize(params.clone()).unwrap();

    let accumulator_0 = accumulator.clone();

    let element_1 = generate_random_field_element(None).unwrap();
    accumulator = positive_accumulator_add(accumulator, element_1.clone(), sk.clone()).unwrap();

    let witness =
        positive_accumulator_membership_witness(accumulator.clone(), element_1.clone(), sk.clone())
            .unwrap();
    let accum = positive_accumulator_get_accumulated(accumulator.clone()).unwrap();
    assert!(positive_accumulator_verify_membership(
        accum,
        element_1.clone(),
        witness.clone(),
        pk.clone(),
        params.clone()
    )
    .unwrap());

    // Witness does not verify with old accumulator
    assert!(!positive_accumulator_verify_membership(
        positive_accumulator_get_accumulated(accumulator_0.clone()).unwrap(),
        element_1.clone(),
        witness,
        pk.clone(),
        params.clone()
    )
    .unwrap());

    let accumulator_old = accumulator.clone();

    // Add elements 2 and 3 and remove 2
    let element_2 = generate_random_field_element(None).unwrap();
    let element_3 = generate_random_field_element(None).unwrap();
    accumulator = positive_accumulator_add(accumulator, element_2.clone(), sk.clone()).unwrap();
    accumulator = positive_accumulator_add(accumulator, element_3.clone(), sk.clone()).unwrap();
    accumulator = positive_accumulator_remove(accumulator, element_2.clone(), sk.clone()).unwrap();

    let witness =
        positive_accumulator_membership_witness(accumulator.clone(), element_3.clone(), sk.clone())
            .unwrap();
    assert!(positive_accumulator_verify_membership(
        positive_accumulator_get_accumulated(accumulator.clone()).unwrap(),
        element_3.clone(),
        witness.clone(),
        pk.clone(),
        params.clone()
    )
    .unwrap());
    // Witness does not verify with old accumulator
    assert!(!positive_accumulator_verify_membership(
        positive_accumulator_get_accumulated(accumulator_old.clone()).unwrap(),
        element_3,
        witness,
        pk.clone(),
        params.clone()
    )
    .unwrap());

    let witness =
        positive_accumulator_membership_witness(accumulator.clone(), element_1.clone(), sk.clone())
            .unwrap();
    assert!(positive_accumulator_verify_membership(
        positive_accumulator_get_accumulated(accumulator).unwrap(),
        element_1.clone(),
        witness.clone(),
        pk.clone(),
        params.clone()
    )
    .unwrap());
    // Witness does not verify with old accumulator
    assert!(!positive_accumulator_verify_membership(
        positive_accumulator_get_accumulated(accumulator_old).unwrap(),
        element_1,
        witness,
        pk,
        params
    )
    .unwrap());
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn universal_accumulator_initialize() {
    let label = b"test".to_vec();
    let (params, sk, _) = get_params_and_keys(Some(label));
    let max_size = 4;

    let initial_fixed = universal_accumulator_fixed_initial_elements().unwrap();

    let initial_elements = (0..max_size + 1)
        .map(|_| random_ff(None))
        .collect::<Vec<_>>();

    let initial_elements_arr = js_array_from_frs(initial_elements.as_slice()).unwrap();

    let all_initial_elements = initial_fixed.concat(&initial_elements_arr);

    let f_v = universal_accumulator_compute_initial_fv(all_initial_elements, sk.clone()).unwrap();

    universal_accumulator_initialize_given_f_v(f_v.clone(), params.clone(), max_size).unwrap();

    let f_v_0 = universal_accumulator_compute_initial_fv(initial_fixed, sk.clone()).unwrap();

    let mut initial_elements = initial_elements.chunks(2);
    let f_v_1 = universal_accumulator_compute_initial_fv(
        js_array_from_frs(initial_elements.next().unwrap()).unwrap(),
        sk.clone(),
    )
    .unwrap();
    let f_v_2 = universal_accumulator_compute_initial_fv(
        js_array_from_frs(initial_elements.next().unwrap()).unwrap(),
        sk.clone(),
    )
    .unwrap();
    let f_v_3 = universal_accumulator_compute_initial_fv(
        js_array_from_frs(initial_elements.next().unwrap()).unwrap(),
        sk.clone(),
    )
    .unwrap();

    let array = js_sys::Array::new();
    array.push(&f_v_0);
    array.push(&f_v_1);
    array.push(&f_v_2);
    array.push(&f_v_3);
    let combined_f_v = universal_accumulator_combine_multiple_initial_fv(array).unwrap();
    assert_eq!(f_v.to_vec(), combined_f_v.to_vec());
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn universal_accumulator_membership_non_membership() {
    let label = b"test".to_vec();
    let (params, sk, pk) = get_params_and_keys(Some(label));

    let max_size = 10;
    let mut accumulator = get_universal_accum(sk.clone(), params.clone(), max_size);

    let accumulator_0 = accumulator.clone();

    let element_1 = generate_random_field_element(None).unwrap();
    accumulator = universal_accumulator_add(accumulator, element_1.clone(), sk.clone()).unwrap();

    let witness = universal_accumulator_membership_witness(
        accumulator.clone(),
        element_1.clone(),
        sk.clone(),
    )
    .unwrap();
    assert!(universal_accumulator_verify_membership(
        universal_accumulator_get_accumulated(accumulator.clone()).unwrap(),
        element_1.clone(),
        witness.clone(),
        pk.clone(),
        params.clone()
    )
    .unwrap());
    // Witness does not verify with old accumulator
    assert!(!universal_accumulator_verify_membership(
        universal_accumulator_get_accumulated(accumulator_0.clone()).unwrap(),
        element_1.clone(),
        witness,
        pk.clone(),
        params.clone()
    )
    .unwrap());

    // Add elements 2 and 3 and remove 2
    let element_2 = generate_random_field_element(None).unwrap();
    let element_3 = generate_random_field_element(None).unwrap();
    accumulator = universal_accumulator_add(accumulator, element_2.clone(), sk.clone()).unwrap();
    accumulator = universal_accumulator_add(accumulator, element_3.clone(), sk.clone()).unwrap();
    accumulator = universal_accumulator_remove(accumulator, element_2.clone(), sk.clone()).unwrap();

    let witness = universal_accumulator_membership_witness(
        accumulator.clone(),
        element_3.clone(),
        sk.clone(),
    )
    .unwrap();
    assert!(universal_accumulator_verify_membership(
        universal_accumulator_get_accumulated(accumulator.clone()).unwrap(),
        element_3.clone(),
        witness,
        pk.clone(),
        params.clone()
    )
    .unwrap());
    let witness = universal_accumulator_membership_witness(
        accumulator.clone(),
        element_1.clone(),
        sk.clone(),
    )
    .unwrap();
    assert!(universal_accumulator_verify_membership(
        universal_accumulator_get_accumulated(accumulator.clone()).unwrap(),
        element_1.clone(),
        witness,
        pk.clone(),
        params.clone()
    )
    .unwrap());

    let accumulator_old = accumulator.clone();

    // Add element 4 and 5
    let element_4 = generate_random_field_element(None).unwrap();
    let element_5 = generate_random_field_element(None).unwrap();
    accumulator = universal_accumulator_add(accumulator, element_4.clone(), sk.clone()).unwrap();
    accumulator = universal_accumulator_add(accumulator, element_5.clone(), sk.clone()).unwrap();

    let non_member = generate_random_field_element(None).unwrap();
    let members = vec![
        fr_from_uint8_array(element_1.clone()).unwrap(),
        fr_from_uint8_array(element_3.clone()).unwrap(),
        fr_from_uint8_array(element_4.clone()).unwrap(),
        fr_from_uint8_array(element_5.clone()).unwrap(),
    ];
    let d =
        universal_accumulator_compute_d(non_member.clone(), js_array_from_frs(&members).unwrap())
            .unwrap();
    let witness = universal_accumulator_non_membership_witness(
        accumulator.clone(),
        d.clone(),
        non_member.clone(),
        sk.clone(),
        params.clone(),
    )
    .unwrap();
    assert!(universal_accumulator_verify_non_membership(
        universal_accumulator_get_accumulated(accumulator.clone()).unwrap(),
        non_member.clone(),
        witness.clone(),
        pk.clone(),
        params.clone()
    )
    .unwrap());
    // Witness does not verify with old accumulator
    assert!(!universal_accumulator_verify_non_membership(
        universal_accumulator_get_accumulated(accumulator_old.clone()).unwrap(),
        non_member.clone(),
        witness,
        pk.clone(),
        params.clone()
    )
    .unwrap());

    let d1 = universal_accumulator_compute_d(
        non_member.clone(),
        js_array_from_frs(&[
            fr_from_uint8_array(element_1).unwrap(),
            fr_from_uint8_array(element_3).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    let d2 = universal_accumulator_compute_d(
        non_member.clone(),
        js_array_from_frs(&[
            fr_from_uint8_array(element_4).unwrap(),
            fr_from_uint8_array(element_5).unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();

    let array = js_sys::Array::new();
    array.push(&d1);
    array.push(&d2);
    let combined_d = universal_accumulator_combine_multiple_d(array).unwrap();
    assert_eq!(combined_d.to_vec(), d.to_vec());
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn positive_accumulator_batch() {
    let label = b"test".to_vec();
    let (params, sk, pk) = get_params_and_keys(Some(label));

    let mut accumulator_0 = positive_accumulator_initialize(params.clone()).unwrap();

    let element_1 = generate_random_field_element(None).unwrap();
    let element_2 = generate_random_field_element(None).unwrap();
    accumulator_0 = positive_accumulator_add(accumulator_0, element_1.clone(), sk.clone()).unwrap();
    accumulator_0 = positive_accumulator_add(accumulator_0, element_2.clone(), sk.clone()).unwrap();

    // accumulator_1 will be updated with single updates, accumulator_2 with batch updates
    let mut accumulator_1 = accumulator_0.clone();
    let mut accumulator_2 = accumulator_0.clone();

    let element_3 = generate_random_field_element(None).unwrap();
    let element_4 = generate_random_field_element(None).unwrap();
    let element_5 = generate_random_field_element(None).unwrap();

    let add_batch = js_sys::Array::new();
    add_batch.push(&element_3);
    add_batch.push(&element_4);
    add_batch.push(&element_5);

    let remove_batch = js_sys::Array::new();
    remove_batch.push(&element_3);
    remove_batch.push(&element_4);

    let wont_remove = js_sys::Array::new();
    wont_remove.push(&element_1);
    wont_remove.push(&element_2);

    positive_accumulator_create_verify_membership_for_batch(
        accumulator_1.clone(),
        wont_remove.clone(),
        sk.clone(),
        pk.clone(),
        params.clone(),
    );

    for a in add_batch.values() {
        accumulator_1 = positive_accumulator_add(
            accumulator_1,
            js_sys::Uint8Array::new(&a.unwrap()),
            sk.clone(),
        )
        .unwrap();
    }

    positive_accumulator_create_verify_membership_for_batch(
        accumulator_1.clone(),
        add_batch.clone(),
        sk.clone(),
        pk.clone(),
        params.clone(),
    );
    positive_accumulator_create_verify_membership_for_batch(
        accumulator_1.clone(),
        wont_remove.clone(),
        sk.clone(),
        pk.clone(),
        params.clone(),
    );

    accumulator_2 =
        positive_accumulator_add_batch(accumulator_2, add_batch.clone(), sk.clone()).unwrap();

    positive_accumulator_create_verify_membership_for_batch(
        accumulator_2.clone(),
        add_batch.clone(),
        sk.clone(),
        pk.clone(),
        params.clone(),
    );
    positive_accumulator_create_verify_membership_for_batch(
        accumulator_2.clone(),
        wont_remove.clone(),
        sk.clone(),
        pk.clone(),
        params.clone(),
    );

    assert_eq!(
        serde_wasm_bindgen::from_value::<PositiveAccumulator<Bls12_381>>(accumulator_1.clone())
            .unwrap(),
        serde_wasm_bindgen::from_value::<PositiveAccumulator<Bls12_381>>(accumulator_2.clone())
            .unwrap(),
    );

    for r in remove_batch.values() {
        accumulator_1 = positive_accumulator_remove(
            accumulator_1,
            js_sys::Uint8Array::new(&r.unwrap()),
            sk.clone(),
        )
        .unwrap();
    }

    accumulator_2 =
        positive_accumulator_remove_batch(accumulator_2, remove_batch.clone(), sk.clone()).unwrap();

    assert_eq!(
        serde_wasm_bindgen::from_value::<PositiveAccumulator<Bls12_381>>(accumulator_1.clone())
            .unwrap(),
        serde_wasm_bindgen::from_value::<PositiveAccumulator<Bls12_381>>(accumulator_2.clone())
            .unwrap(),
    );

    let mut accumulator_3 = accumulator_0.clone();

    accumulator_0 = positive_accumulator_add(accumulator_0, element_5.clone(), sk.clone()).unwrap();

    accumulator_3 = positive_accumulator_batch_updates(
        accumulator_3,
        add_batch.clone(),
        remove_batch.clone(),
        sk.clone(),
    )
    .unwrap();

    assert_eq!(
        serde_wasm_bindgen::from_value::<PositiveAccumulator<Bls12_381>>(accumulator_0).unwrap(),
        serde_wasm_bindgen::from_value::<PositiveAccumulator<Bls12_381>>(accumulator_3.clone())
            .unwrap(),
    );

    positive_accumulator_create_verify_membership_for_batch(
        accumulator_3.clone(),
        wont_remove.clone(),
        sk.clone(),
        pk.clone(),
        params.clone(),
    );
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn universal_accumulator_d() {
    let non_members = vec![random_ff(None), random_ff(None), random_ff(None)];

    let members = vec![
        random_ff(None),
        random_ff(None),
        random_ff(None),
        random_ff(None),
        random_ff(None),
    ];

    let d = universal_accumulator_compute_d_for_batch(
        js_array_from_frs(&non_members).unwrap(),
        js_array_from_frs(&members).unwrap(),
    )
    .unwrap();

    let mut members_chunks = members.chunks(2);
    let d1 = universal_accumulator_compute_d_for_batch(
        js_array_from_frs(&non_members).unwrap(),
        js_array_from_frs(members_chunks.next().unwrap()).unwrap(),
    )
    .unwrap();
    let d2 = universal_accumulator_compute_d_for_batch(
        js_array_from_frs(&non_members).unwrap(),
        js_array_from_frs(members_chunks.next().unwrap()).unwrap(),
    )
    .unwrap();
    let d3 = universal_accumulator_compute_d_for_batch(
        js_array_from_frs(&non_members).unwrap(),
        js_array_from_frs(members_chunks.next().unwrap()).unwrap(),
    )
    .unwrap();

    let ds = js_sys::Array::new();
    ds.push(&d1);
    ds.push(&d2);
    ds.push(&d3);

    let combined_d = universal_accumulator_combine_multiple_d_for_batch(ds).unwrap();
    for i in 0..3 {
        assert_eq!(
            js_value_to_bytes(d.get(i)),
            js_value_to_bytes(combined_d.get(i))
        );
    }
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn universal_accumulator_batch() {
    let label = b"test".to_vec();
    let (params, sk, pk) = get_params_and_keys(Some(label));
    let max_size = 6;

    let mut accumulator_0 = get_universal_accum(sk.clone(), params.clone(), max_size);

    let non_members = vec![random_ff(None), random_ff(None), random_ff(None)];
    let non_members_array = js_array_from_frs(&non_members).unwrap();

    let element_1 = generate_random_field_element(None).unwrap();
    let element_2 = generate_random_field_element(None).unwrap();
    accumulator_0 =
        universal_accumulator_add(accumulator_0, element_1.clone(), sk.clone()).unwrap();
    accumulator_0 =
        universal_accumulator_add(accumulator_0, element_2.clone(), sk.clone()).unwrap();

    let wont_remove = js_sys::Array::new();
    wont_remove.push(&element_1);
    wont_remove.push(&element_2);

    universal_accumulator_create_verify_membership_for_batch(
        accumulator_0.clone(),
        wont_remove.clone(),
        sk.clone(),
        pk.clone(),
        params.clone(),
    );

    let mut members = wont_remove.clone();
    create_verify_non_membership_for_batch(
        accumulator_0.clone(),
        non_members_array.clone(),
        members.clone(),
        sk.clone(),
        pk.clone(),
        params.clone(),
    );

    // accumulator_1 will be updated with single updates, accumulator_2 with batch updates
    let mut accumulator_1 = accumulator_0.clone();
    let mut accumulator_2 = accumulator_0.clone();

    let element_3 = generate_random_field_element(None).unwrap();
    let element_4 = generate_random_field_element(None).unwrap();
    let element_5 = generate_random_field_element(None).unwrap();

    let add_batch = js_sys::Array::new();
    add_batch.push(&element_3);
    add_batch.push(&element_4);
    add_batch.push(&element_5);

    let remove_batch = js_sys::Array::new();
    remove_batch.push(&element_3);
    remove_batch.push(&element_4);

    for a in add_batch.values() {
        accumulator_1 = universal_accumulator_add(
            accumulator_1,
            js_sys::Uint8Array::new(&a.unwrap()),
            sk.clone(),
        )
        .unwrap();
    }
    universal_accumulator_create_verify_membership_for_batch(
        accumulator_1.clone(),
        add_batch.clone(),
        sk.clone(),
        pk.clone(),
        params.clone(),
    );
    universal_accumulator_create_verify_membership_for_batch(
        accumulator_1.clone(),
        wont_remove.clone(),
        sk.clone(),
        pk.clone(),
        params.clone(),
    );

    members = wont_remove.concat(&add_batch);
    create_verify_non_membership_for_batch(
        accumulator_1.clone(),
        non_members_array.clone(),
        members.clone(),
        sk.clone(),
        pk.clone(),
        params.clone(),
    );

    accumulator_2 =
        universal_accumulator_add_batch(accumulator_2, add_batch.clone(), sk.clone()).unwrap();

    assert_eq!(
        serde_wasm_bindgen::from_value::<UniversalAccumulator<Bls12_381>>(accumulator_1.clone())
            .unwrap(),
        serde_wasm_bindgen::from_value::<UniversalAccumulator<Bls12_381>>(accumulator_2.clone())
            .unwrap(),
    );

    for r in remove_batch.values() {
        accumulator_1 = universal_accumulator_remove(
            accumulator_1,
            js_sys::Uint8Array::new(&r.unwrap()),
            sk.clone(),
        )
        .unwrap();
    }

    universal_accumulator_create_verify_membership_for_batch(
        accumulator_1.clone(),
        wont_remove.clone(),
        sk.clone(),
        pk.clone(),
        params.clone(),
    );

    members = wont_remove.clone();
    members.push(&element_5);
    create_verify_non_membership_for_batch(
        accumulator_0.clone(),
        non_members_array.clone(),
        members.clone(),
        sk.clone(),
        pk.clone(),
        params.clone(),
    );

    accumulator_2 =
        universal_accumulator_remove_batch(accumulator_2, remove_batch.clone(), sk.clone())
            .unwrap();

    assert_eq!(
        serde_wasm_bindgen::from_value::<UniversalAccumulator<Bls12_381>>(accumulator_1.clone())
            .unwrap(),
        serde_wasm_bindgen::from_value::<UniversalAccumulator<Bls12_381>>(accumulator_2.clone())
            .unwrap(),
    );

    let mut accumulator_3 = accumulator_0.clone();

    accumulator_0 =
        universal_accumulator_add(accumulator_0, element_5.clone(), sk.clone()).unwrap();

    accumulator_3 = universal_accumulator_batch_updates(
        accumulator_3.clone(),
        add_batch.clone(),
        remove_batch.clone(),
        sk.clone(),
    )
    .unwrap();

    assert_eq!(
        serde_wasm_bindgen::from_value::<UniversalAccumulator<Bls12_381>>(accumulator_0).unwrap(),
        serde_wasm_bindgen::from_value::<UniversalAccumulator<Bls12_381>>(accumulator_3.clone())
            .unwrap(),
    );

    universal_accumulator_create_verify_membership_for_batch(
        accumulator_3.clone(),
        wont_remove.clone(),
        sk.clone(),
        pk.clone(),
        params.clone(),
    );
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn witness_update_single() {
    let label = b"test".to_vec();
    let (params, sk, pk) = get_params_and_keys(Some(label));

    let max_size = 100;
    let mut pos_accum = positive_accumulator_initialize(params.clone()).unwrap();
    let mut uni_accum = get_universal_accum(sk.clone(), params.clone(), max_size);

    let element_1 = generate_random_field_element(None).unwrap();
    pos_accum = positive_accumulator_add(pos_accum, element_1.clone(), sk.clone()).unwrap();

    let witness_1 =
        positive_accumulator_membership_witness(pos_accum.clone(), element_1.clone(), sk.clone())
            .unwrap();
    assert!(positive_accumulator_verify_membership(
        positive_accumulator_get_accumulated(pos_accum.clone()).unwrap(),
        element_1.clone(),
        witness_1.clone(),
        pk.clone(),
        params.clone()
    )
    .unwrap());

    let element_2 = generate_random_field_element(None).unwrap();
    let pos_accum_1 =
        positive_accumulator_add(pos_accum.clone(), element_2.clone(), sk.clone()).unwrap();

    let new_witness_1 = update_membership_witness_post_add(
        witness_1.clone(),
        element_1.clone(),
        element_2.clone(),
        positive_accumulator_get_accumulated(pos_accum.clone()).unwrap(),
    )
    .unwrap();
    assert!(positive_accumulator_verify_membership(
        positive_accumulator_get_accumulated(pos_accum_1.clone()).unwrap(),
        element_1.clone(),
        new_witness_1.clone(),
        pk.clone(),
        params.clone()
    )
    .unwrap());

    let pos_accum_2 =
        positive_accumulator_remove(pos_accum_1.clone(), element_2.clone(), sk.clone()).unwrap();

    let new_witness_1 = update_membership_witness_post_remove(
        new_witness_1,
        element_1.clone(),
        element_2.clone(),
        positive_accumulator_get_accumulated(pos_accum_2.clone()).unwrap(),
    )
    .unwrap();
    assert!(positive_accumulator_verify_membership(
        positive_accumulator_get_accumulated(pos_accum_2.clone()).unwrap(),
        element_1.clone(),
        new_witness_1,
        pk.clone(),
        params.clone()
    )
    .unwrap());

    let non_member = generate_random_field_element(None).unwrap();

    uni_accum = universal_accumulator_add(uni_accum, element_1.clone(), sk.clone()).unwrap();
    let witness_1 =
        universal_accumulator_membership_witness(uni_accum.clone(), element_1.clone(), sk.clone())
            .unwrap();
    assert!(universal_accumulator_verify_membership(
        universal_accumulator_get_accumulated(uni_accum.clone()).unwrap(),
        element_1.clone(),
        witness_1.clone(),
        pk.clone(),
        params.clone()
    )
    .unwrap());

    let members = js_sys::Array::new();
    members.push(&element_1);
    let d = universal_accumulator_compute_d(non_member.clone(), members).unwrap();
    let nm_witness_1 = universal_accumulator_non_membership_witness(
        uni_accum.clone(),
        d.clone(),
        non_member.clone(),
        sk.clone(),
        params.clone(),
    )
    .unwrap();
    assert!(universal_accumulator_verify_non_membership(
        universal_accumulator_get_accumulated(uni_accum.clone()).unwrap(),
        non_member.clone(),
        nm_witness_1.clone(),
        pk.clone(),
        params.clone()
    )
    .unwrap());

    let uni_accum_1 =
        universal_accumulator_add(uni_accum.clone(), element_2.clone(), sk.clone()).unwrap();

    let new_witness_1 = update_membership_witness_post_add(
        witness_1.clone(),
        element_1.clone(),
        element_2.clone(),
        universal_accumulator_get_accumulated(uni_accum.clone()).unwrap(),
    )
    .unwrap();
    assert!(universal_accumulator_verify_membership(
        universal_accumulator_get_accumulated(uni_accum_1.clone()).unwrap(),
        element_1.clone(),
        new_witness_1.clone(),
        pk.clone(),
        params.clone()
    )
    .unwrap());

    let new_nm_witness_1 = update_non_membership_witness_post_add(
        nm_witness_1.clone(),
        non_member.clone(),
        element_2.clone(),
        universal_accumulator_get_accumulated(uni_accum.clone()).unwrap(),
    )
    .unwrap();
    assert!(universal_accumulator_verify_non_membership(
        universal_accumulator_get_accumulated(uni_accum_1.clone()).unwrap(),
        non_member.clone(),
        new_nm_witness_1.clone(),
        pk.clone(),
        params.clone()
    )
    .unwrap());

    let uni_accum_2 =
        universal_accumulator_remove(uni_accum_1.clone(), element_2.clone(), sk.clone()).unwrap();

    let new_witness_1 = update_membership_witness_post_remove(
        new_witness_1,
        element_1.clone(),
        element_2.clone(),
        universal_accumulator_get_accumulated(uni_accum_2.clone()).unwrap(),
    )
    .unwrap();
    assert!(universal_accumulator_verify_membership(
        universal_accumulator_get_accumulated(uni_accum_2.clone()).unwrap(),
        element_1.clone(),
        new_witness_1,
        pk.clone(),
        params.clone()
    )
    .unwrap());

    let new_nm_witness_1 = update_non_membership_witness_post_remove(
        new_nm_witness_1,
        non_member.clone(),
        element_2.clone(),
        universal_accumulator_get_accumulated(uni_accum_2.clone()).unwrap(),
    )
    .unwrap();
    assert!(universal_accumulator_verify_non_membership(
        universal_accumulator_get_accumulated(uni_accum_2.clone()).unwrap(),
        non_member.clone(),
        new_nm_witness_1,
        pk.clone(),
        params.clone()
    )
    .unwrap());
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn multiple_witnesses_update_using_secret_key() {
    let label = b"test".to_vec();
    let (params, sk, pk) = get_params_and_keys(Some(label));

    let max_size = 100;
    let mut pos_accum = positive_accumulator_initialize(params.clone()).unwrap();
    let mut uni_accum = get_universal_accum(sk.clone(), params.clone(), max_size);

    let non_member_1 = generate_random_field_element(None).unwrap();
    let non_member_2 = generate_random_field_element(None).unwrap();
    let element_1 = generate_random_field_element(None).unwrap();
    let element_2 = generate_random_field_element(None).unwrap();
    let element_3 = generate_random_field_element(None).unwrap();
    let element_4 = generate_random_field_element(None).unwrap();
    let element_5 = generate_random_field_element(None).unwrap();
    let element_6 = generate_random_field_element(None).unwrap();

    let initial_batch = js_sys::Array::new();
    initial_batch.push(&element_1);
    initial_batch.push(&element_2);

    let non_members = js_sys::Array::new();
    initial_batch.push(&non_member_1);
    initial_batch.push(&non_member_2);

    pos_accum =
        positive_accumulator_add_batch(pos_accum, initial_batch.clone(), sk.clone()).unwrap();

    uni_accum =
        universal_accumulator_add_batch(uni_accum, initial_batch.clone(), sk.clone()).unwrap();

    let new_batch = js_sys::Array::new();
    new_batch.push(&element_3);
    new_batch.push(&element_4);

    pos_accum = positive_accumulator_add_batch(pos_accum, new_batch.clone(), sk.clone()).unwrap();

    uni_accum = universal_accumulator_add_batch(uni_accum, new_batch.clone(), sk.clone()).unwrap();

    let witnesses = positive_accumulator_create_verify_membership_for_batch(
        pos_accum.clone(),
        initial_batch.clone(),
        sk.clone(),
        pk.clone(),
        params.clone(),
    );

    let uni_witnesses = universal_accumulator_create_verify_membership_for_batch(
        uni_accum.clone(),
        initial_batch.clone(),
        sk.clone(),
        pk.clone(),
        params.clone(),
    );

    let members = js_sys::Array::new();
    members.push(&element_1);
    members.push(&element_2);
    members.push(&element_3);
    members.push(&element_4);
    let nm_witnesses = create_verify_non_membership_for_batch(
        uni_accum.clone(),
        non_members.clone(),
        members,
        sk.clone(),
        pk.clone(),
        params.clone(),
    );

    let add_batch = js_sys::Array::new();
    add_batch.push(&element_5);
    add_batch.push(&element_6);

    let remove_batch = js_sys::Array::new();
    remove_batch.push(&element_3);
    remove_batch.push(&element_4);

    let pos_accum_1 = positive_accumulator_batch_updates(
        pos_accum.clone(),
        add_batch.clone(),
        remove_batch.clone(),
        sk.clone(),
    )
    .unwrap();

    let uni_accum_1 = universal_accumulator_batch_updates(
        uni_accum.clone(),
        add_batch.clone(),
        remove_batch.clone(),
        sk.clone(),
    )
    .unwrap();

    let new_witnesses = update_membership_witnesses_post_batch_updates(
        witnesses,
        initial_batch.clone(),
        add_batch.clone(),
        remove_batch.clone(),
        positive_accumulator_get_accumulated(pos_accum.clone()).unwrap(),
        sk.clone(),
    )
    .unwrap();

    let new_uni_witnesses = update_membership_witnesses_post_batch_updates(
        uni_witnesses,
        initial_batch.clone(),
        add_batch.clone(),
        remove_batch.clone(),
        universal_accumulator_get_accumulated(uni_accum.clone()).unwrap(),
        sk.clone(),
    )
    .unwrap();

    let new_nm_witnesses = update_non_membership_witnesses_post_batch_updates(
        nm_witnesses,
        non_members.clone(),
        add_batch.clone(),
        remove_batch.clone(),
        universal_accumulator_get_accumulated(uni_accum.clone()).unwrap(),
        sk.clone(),
    )
    .unwrap();

    positive_accumulator_verify_membership_for_batch(
        pos_accum_1,
        initial_batch.clone(),
        &new_witnesses,
        pk.clone(),
        params.clone(),
    );

    universal_accumulator_verify_membership_for_batch(
        uni_accum_1.clone(),
        initial_batch.clone(),
        &new_uni_witnesses,
        pk.clone(),
        params.clone(),
    );

    verify_non_membership_for_batch(uni_accum_1, non_members, &new_nm_witnesses, pk, params);
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn witness_update_batch() {
    let label = b"test".to_vec();
    let (params, sk, pk) = get_params_and_keys(Some(label));

    let max_size = 100;
    let mut pos_accum = positive_accumulator_initialize(params.clone()).unwrap();
    let mut uni_accum = get_universal_accum(sk.clone(), params.clone(), max_size);

    let non_member = generate_random_field_element(None).unwrap();
    let element_1 = generate_random_field_element(None).unwrap();
    let element_2 = generate_random_field_element(None).unwrap();
    let element_3 = generate_random_field_element(None).unwrap();
    let element_4 = generate_random_field_element(None).unwrap();
    let element_5 = generate_random_field_element(None).unwrap();
    let element_6 = generate_random_field_element(None).unwrap();

    let initial_batch = js_sys::Array::new();
    initial_batch.push(&element_1);
    initial_batch.push(&element_2);
    initial_batch.push(&element_3);

    pos_accum =
        positive_accumulator_add_batch(pos_accum, initial_batch.clone(), sk.clone()).unwrap();
    let witness =
        positive_accumulator_membership_witness(pos_accum.clone(), element_3.clone(), sk.clone())
            .unwrap();

    uni_accum =
        universal_accumulator_add_batch(uni_accum, initial_batch.clone(), sk.clone()).unwrap();
    let uni_witness =
        universal_accumulator_membership_witness(uni_accum.clone(), element_3.clone(), sk.clone())
            .unwrap();

    let d = universal_accumulator_compute_d(non_member.clone(), initial_batch).unwrap();
    let nm_witness = universal_accumulator_non_membership_witness(
        uni_accum.clone(),
        d,
        non_member.clone(),
        sk.clone(),
        params.clone(),
    )
    .unwrap();

    let add_batch = js_sys::Array::new();
    add_batch.push(&element_4);
    add_batch.push(&element_5);
    add_batch.push(&element_6);

    let remove_batch = js_sys::Array::new();
    remove_batch.push(&element_1);
    remove_batch.push(&element_2);

    let pos_public_info = public_info_for_witness_update(
        positive_accumulator_get_accumulated(pos_accum.clone()).unwrap(),
        add_batch.clone(),
        remove_batch.clone(),
        sk.clone(),
    )
    .unwrap();

    let uni_public_info = public_info_for_witness_update(
        universal_accumulator_get_accumulated(uni_accum.clone()).unwrap(),
        add_batch.clone(),
        remove_batch.clone(),
        sk.clone(),
    )
    .unwrap();

    let pos_accum_1 = positive_accumulator_batch_updates(
        pos_accum,
        add_batch.clone(),
        remove_batch.clone(),
        sk.clone(),
    )
    .unwrap();
    let new_witness = update_membership_witness_using_public_info_after_batch_update(
        witness,
        element_3.clone(),
        add_batch.clone(),
        remove_batch.clone(),
        pos_public_info.clone(),
    )
    .unwrap();
    assert!(positive_accumulator_verify_membership(
        positive_accumulator_get_accumulated(pos_accum_1.clone()).unwrap(),
        element_3.clone(),
        new_witness,
        pk.clone(),
        params.clone()
    )
    .unwrap());

    let uni_accum_1 = universal_accumulator_batch_updates(
        uni_accum,
        add_batch.clone(),
        remove_batch.clone(),
        sk.clone(),
    )
    .unwrap();
    let new_uni_witness = update_membership_witness_using_public_info_after_batch_update(
        uni_witness,
        element_3.clone(),
        add_batch.clone(),
        remove_batch.clone(),
        uni_public_info.clone(),
    )
    .unwrap();
    assert!(universal_accumulator_verify_membership(
        universal_accumulator_get_accumulated(uni_accum_1.clone()).unwrap(),
        element_3.clone(),
        new_uni_witness,
        pk.clone(),
        params.clone()
    )
    .unwrap());

    let new_nm_witness = update_non_membership_witness_using_public_info_after_batch_update(
        nm_witness,
        non_member.clone(),
        add_batch.clone(),
        remove_batch.clone(),
        uni_public_info.clone(),
    )
    .unwrap();
    assert!(universal_accumulator_verify_non_membership(
        universal_accumulator_get_accumulated(uni_accum_1.clone()).unwrap(),
        non_member.clone(),
        new_nm_witness,
        pk.clone(),
        params.clone()
    )
    .unwrap());
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn witness_update_multiple_batches() {
    let label = b"test".to_vec();
    let (params, sk, pk) = get_params_and_keys(Some(label));

    let max_size = 100;
    let mut pos_accum = positive_accumulator_initialize(params.clone()).unwrap();
    let mut uni_accum = get_universal_accum(sk.clone(), params.clone(), max_size);

    let member = generate_random_field_element(None).unwrap();
    let non_member = generate_random_field_element(None).unwrap();

    pos_accum = positive_accumulator_add(pos_accum, member.clone(), sk.clone()).unwrap();
    uni_accum = universal_accumulator_add(uni_accum, member.clone(), sk.clone()).unwrap();

    let pos_witness =
        positive_accumulator_membership_witness(pos_accum.clone(), member.clone(), sk.clone())
            .unwrap();
    let uni_witness =
        universal_accumulator_membership_witness(uni_accum.clone(), member.clone(), sk.clone())
            .unwrap();
    let members = js_sys::Array::new();
    members.push(&member);
    let d = universal_accumulator_compute_d(non_member.clone(), members).unwrap();
    let nm_witness = universal_accumulator_non_membership_witness(
        uni_accum.clone(),
        d,
        non_member.clone(),
        sk.clone(),
        params.clone(),
    )
    .unwrap();

    let add_batch_0 = js_sys::Array::new();
    for _ in 0..2 {
        add_batch_0.push(&generate_random_field_element(None).unwrap());
    }

    let pos_public_info_0 = public_info_for_witness_update(
        positive_accumulator_get_accumulated(pos_accum.clone()).unwrap(),
        add_batch_0.clone(),
        js_sys::Array::new(),
        sk.clone(),
    )
    .unwrap();

    let uni_public_info_0 = public_info_for_witness_update(
        universal_accumulator_get_accumulated(uni_accum.clone()).unwrap(),
        add_batch_0.clone(),
        js_sys::Array::new(),
        sk.clone(),
    )
    .unwrap();

    pos_accum = positive_accumulator_add_batch(pos_accum, add_batch_0.clone(), sk.clone()).unwrap();

    uni_accum =
        universal_accumulator_add_batch(uni_accum, add_batch_0.clone(), sk.clone()).unwrap();

    let add_batch_1 = js_sys::Array::new();
    for _ in 0..2 {
        add_batch_1.push(&generate_random_field_element(None).unwrap());
    }
    let remove_batch_1 = add_batch_0.clone();

    let pos_public_info_1 = public_info_for_witness_update(
        positive_accumulator_get_accumulated(pos_accum.clone()).unwrap(),
        add_batch_1.clone(),
        remove_batch_1.clone(),
        sk.clone(),
    )
    .unwrap();

    let uni_public_info_1 = public_info_for_witness_update(
        universal_accumulator_get_accumulated(uni_accum.clone()).unwrap(),
        add_batch_1.clone(),
        remove_batch_1.clone(),
        sk.clone(),
    )
    .unwrap();

    pos_accum = positive_accumulator_batch_updates(
        pos_accum,
        add_batch_1.clone(),
        remove_batch_1.clone(),
        sk.clone(),
    )
    .unwrap();
    uni_accum = universal_accumulator_batch_updates(
        uni_accum,
        add_batch_1.clone(),
        remove_batch_1.clone(),
        sk.clone(),
    )
    .unwrap();

    let add_batch_2 = js_sys::Array::new();
    for _ in 0..2 {
        add_batch_2.push(&generate_random_field_element(None).unwrap());
    }
    let remove_batch_2 = add_batch_1.clone();

    let pos_public_info_2 = public_info_for_witness_update(
        positive_accumulator_get_accumulated(pos_accum.clone()).unwrap(),
        add_batch_2.clone(),
        remove_batch_2.clone(),
        sk.clone(),
    )
    .unwrap();

    let uni_public_info_2 = public_info_for_witness_update(
        universal_accumulator_get_accumulated(uni_accum.clone()).unwrap(),
        add_batch_2.clone(),
        remove_batch_2.clone(),
        sk.clone(),
    )
    .unwrap();

    pos_accum = positive_accumulator_batch_updates(
        pos_accum,
        add_batch_2.clone(),
        remove_batch_2.clone(),
        sk.clone(),
    )
    .unwrap();
    uni_accum = universal_accumulator_batch_updates(
        uni_accum,
        add_batch_2.clone(),
        remove_batch_2.clone(),
        sk.clone(),
    )
    .unwrap();

    let additions = js_sys::Array::new();
    let removals = js_sys::Array::new();
    let pos_public_info = js_sys::Array::new();
    let uni_public_info = js_sys::Array::new();
    additions.push(&add_batch_0);
    additions.push(&add_batch_1);
    additions.push(&add_batch_2);
    removals.push(&js_sys::Array::new());
    removals.push(&remove_batch_1);
    removals.push(&remove_batch_2);
    pos_public_info.push(&pos_public_info_0);
    pos_public_info.push(&pos_public_info_1);
    pos_public_info.push(&pos_public_info_2);
    uni_public_info.push(&uni_public_info_0);
    uni_public_info.push(&uni_public_info_1);
    uni_public_info.push(&uni_public_info_2);

    let new_pos_witness = update_membership_witness_using_public_info_after_multiple_batch_updates(
        pos_witness,
        member.clone(),
        additions.clone(),
        removals.clone(),
        pos_public_info.clone(),
    )
    .unwrap();
    assert!(positive_accumulator_verify_membership(
        positive_accumulator_get_accumulated(pos_accum.clone()).unwrap(),
        member.clone(),
        new_pos_witness,
        pk.clone(),
        params.clone()
    )
    .unwrap());

    let new_uni_witness = update_membership_witness_using_public_info_after_multiple_batch_updates(
        uni_witness,
        member.clone(),
        additions.clone(),
        removals.clone(),
        uni_public_info.clone(),
    )
    .unwrap();
    assert!(universal_accumulator_verify_membership(
        universal_accumulator_get_accumulated(uni_accum.clone()).unwrap(),
        member.clone(),
        new_uni_witness,
        pk.clone(),
        params.clone()
    )
    .unwrap());

    let new_nm_witness =
        update_non_membership_witness_using_public_info_after_multiple_batch_updates(
            nm_witness,
            non_member.clone(),
            additions.clone(),
            removals.clone(),
            uni_public_info.clone(),
        )
        .unwrap();
    assert!(universal_accumulator_verify_non_membership(
        universal_accumulator_get_accumulated(uni_accum.clone()).unwrap(),
        non_member.clone(),
        new_nm_witness,
        pk.clone(),
        params.clone()
    )
    .unwrap());
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn membership_proof() {
    let label = b"test".to_vec();
    let (params, sk, pk) = get_params_and_keys(Some(label));

    let max_size = 100;
    let mut pos_accum = positive_accumulator_initialize(params.clone()).unwrap();
    let mut uni_accum = get_universal_accum(sk.clone(), params.clone(), max_size);

    let member = generate_random_field_element(None).unwrap();

    pos_accum = positive_accumulator_add(pos_accum, member.clone(), sk.clone()).unwrap();
    uni_accum = universal_accumulator_add(uni_accum, member.clone(), sk.clone()).unwrap();

    let pos_witness =
        positive_accumulator_membership_witness(pos_accum.clone(), member.clone(), sk.clone())
            .unwrap();
    let uni_witness =
        universal_accumulator_membership_witness(uni_accum.clone(), member.clone(), sk.clone())
            .unwrap();

    let prk = generate_membership_proving_key(None).unwrap();

    let pos_accumulated = positive_accumulator_get_accumulated(pos_accum.clone()).unwrap();
    let uni_accumulated = universal_accumulator_get_accumulated(uni_accum.clone()).unwrap();

    let blinding = generate_random_field_element(None).unwrap();
    let protocol = accumulator_initialize_membership_proof(
        member.clone(),
        blinding,
        pos_witness,
        pk.clone(),
        params.clone(),
        prk.clone(),
    )
    .unwrap();

    let prover_bytes = accumulator_challenge_contribution_from_membership_protocol(
        protocol.clone(),
        pos_accumulated.clone(),
        pk.clone(),
        params.clone(),
        prk.clone(),
    )
    .unwrap();
    let prover_challenge = generate_challenge_from_bytes(prover_bytes.to_vec());

    let proof = accumulator_gen_membership_proof(protocol, prover_challenge.clone()).unwrap();

    let verifier_bytes = accumulator_challenge_contribution_from_membership_proof(
        proof.clone(),
        pos_accumulated.clone(),
        pk.clone(),
        params.clone(),
        prk.clone(),
    )
    .unwrap();
    let verifier_challenge = generate_challenge_from_bytes(verifier_bytes.to_vec());

    assert_eq!(prover_challenge.to_vec(), verifier_challenge.to_vec());

    let result = accumulator_verify_membership_proof(
        proof,
        pos_accumulated,
        verifier_challenge,
        pk.clone(),
        params.clone(),
        prk.clone(),
    )
    .unwrap();
    let r: VerifyResponse = serde_wasm_bindgen::from_value(result).unwrap();
    assert!(r.verified);
    assert!(r.error.is_none());

    let blinding = generate_random_field_element(None).unwrap();
    let protocol = accumulator_initialize_membership_proof(
        member,
        blinding,
        uni_witness,
        pk.clone(),
        params.clone(),
        prk.clone(),
    )
    .unwrap();

    let prover_bytes = accumulator_challenge_contribution_from_membership_protocol(
        protocol.clone(),
        uni_accumulated.clone(),
        pk.clone(),
        params.clone(),
        prk.clone(),
    )
    .unwrap();
    let prover_challenge = generate_challenge_from_bytes(prover_bytes.to_vec());

    let proof = accumulator_gen_membership_proof(protocol, prover_challenge.clone()).unwrap();

    let verifier_bytes = accumulator_challenge_contribution_from_membership_proof(
        proof.clone(),
        uni_accumulated.clone(),
        pk.clone(),
        params.clone(),
        prk.clone(),
    )
    .unwrap();
    let verifier_challenge = generate_challenge_from_bytes(verifier_bytes.to_vec());

    assert_eq!(prover_challenge.to_vec(), verifier_challenge.to_vec());

    let result = accumulator_verify_membership_proof(
        proof,
        universal_accumulator_get_accumulated(uni_accum).unwrap(),
        verifier_challenge,
        pk.clone(),
        params.clone(),
        prk.clone(),
    )
    .unwrap();
    let r: VerifyResponse = serde_wasm_bindgen::from_value(result).unwrap();
    assert!(r.verified);
    assert!(r.error.is_none());
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub fn non_membership_proof() {
    let label = b"test".to_vec();
    let (params, sk, pk) = get_params_and_keys(Some(label));

    let max_size = 100;
    let accum = get_universal_accum(sk.clone(), params.clone(), max_size);

    let non_member = generate_random_field_element(None).unwrap();

    let d = universal_accumulator_compute_d(non_member.clone(), js_sys::Array::new()).unwrap();
    let witness = universal_accumulator_non_membership_witness(
        accum.clone(),
        d,
        non_member.clone(),
        sk.clone(),
        params.clone(),
    )
    .unwrap();

    let accumulated = universal_accumulator_get_accumulated(accum.clone()).unwrap();

    let prk = generate_non_membership_proving_key(None).unwrap();

    let _mem_prk =
        accumulator_derive_membership_proving_key_from_non_membership_key(prk.clone()).unwrap();

    let blinding = generate_random_field_element(None).unwrap();
    let protocol = accumulator_initialize_non_membership_proof(
        non_member.clone(),
        blinding,
        witness,
        pk.clone(),
        params.clone(),
        prk.clone(),
    )
    .unwrap();

    let prover_bytes = accumulator_challenge_contribution_from_non_membership_protocol(
        protocol.clone(),
        accumulated.clone(),
        pk.clone(),
        params.clone(),
        prk.clone(),
    )
    .unwrap();
    let prover_challenge = generate_challenge_from_bytes(prover_bytes.to_vec());

    let proof = accumulator_gen_non_membership_proof(protocol, prover_challenge.clone()).unwrap();

    let verifier_bytes = accumulator_challenge_contribution_from_non_membership_proof(
        proof.clone(),
        accumulated.clone(),
        pk.clone(),
        params.clone(),
        prk.clone(),
    )
    .unwrap();
    let verifier_challenge = generate_challenge_from_bytes(verifier_bytes.to_vec());

    assert_eq!(prover_challenge.to_vec(), verifier_challenge.to_vec());

    let result = accumulator_verify_non_membership_proof(
        proof,
        accumulated,
        verifier_challenge,
        pk.clone(),
        params.clone(),
        prk.clone(),
    )
    .unwrap();
    let r: VerifyResponse = serde_wasm_bindgen::from_value(result).unwrap();
    assert!(r.verified);
    assert!(r.error.is_none());
}
