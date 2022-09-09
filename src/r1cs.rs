use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use legogroth16::circom::{
    r1cs::{Constraint, Curve, LC, R1CS},
    CircomCircuit, WitnessCalculator,
};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use crate::utils::{get_seeded_rng, js_array_from_frs, js_array_to_fr_vec, set_panic_hook};

fn parse_lc(lc: js_sys::Array) -> Result<LC<Bls12_381>, JsValue> {
    let mut terms = vec![];
    for t in lc.values() {
        let term = js_sys::Array::from(&t.unwrap());
        if term.length() != 2 {
            return Err(JsValue::from(&format!(
                "Each term should be of length 2 but found of length {:?}",
                term.length()
            )));
        }
        let i = term
            .get(0)
            .as_f64()
            .ok_or_else(|| JsValue::from("The 1st element of term should have been a number"))?
            as usize;
        let mut v_bytes = js_sys::Uint8Array::new(&term.get(1)).to_vec();

        // Create an field element from bytes in little-endian. Intentionally not calling `Fr::from_le_bytes_mod_order`
        // as that creates a vec internally.
        v_bytes.reverse();
        let v = Fr::from_be_bytes_mod_order(&v_bytes);

        terms.push((i, v))
    }
    Ok(LC(terms))
}

fn parse_constraints(constraints: js_sys::Array) -> Result<Vec<Constraint<Bls12_381>>, JsValue> {
    let mut cons = Vec::<Constraint<Bls12_381>>::with_capacity(constraints.length() as usize);
    for c in constraints.values() {
        let constraint = js_sys::Array::from(&c.unwrap());
        if constraint.length() != 3 {
            return Err(JsValue::from(&format!(
                "Each constraint should be of length 3 but was found of length {:?}",
                constraint.length()
            )));
        }
        let a = js_sys::Array::from(&constraint.get(0));
        let b = js_sys::Array::from(&constraint.get(1));
        let c = js_sys::Array::from(&constraint.get(2));
        cons.push(Constraint {
            a: parse_lc(a)?,
            b: parse_lc(b)?,
            c: parse_lc(c)?,
        });
    }
    Ok(cons)
}

pub fn gen_r1cs(
    curve_name: &str,
    num_public: usize,
    num_private: usize,
    constraints: js_sys::Array,
) -> Result<R1CS<Bls12_381>, JsValue> {
    if curve_name != "bls12381" {
        return Err(JsValue::from(&format!(
            "Only BLS12-381 curve is supported and curve name should be bls12381 but was given {:?}",
            curve_name
        )));
    }
    Ok(R1CS {
        curve: Curve::Bls12_381,
        num_public,
        num_private,
        constraints: parse_constraints(constraints)?,
        wire_to_label_mapping: vec![],
    })
}

pub fn gen_wires(
    wasm_bytes: js_sys::Uint8Array,
    input_wires: js_sys::Map,
) -> Result<Vec<Fr>, JsValue> {
    let mut witness_calculator =
        WitnessCalculator::<Bls12_381>::from_wasm_bytes(&wasm_bytes.to_vec()).unwrap();
    let mut inputs = vec![];
    for e in input_wires.entries() {
        let arr = js_sys::Array::from(&e.unwrap());
        let name: String = serde_wasm_bindgen::from_value(arr.get(0))?;
        let vals = js_sys::Array::from(&arr.get(1));
        inputs.push((name, js_array_to_fr_vec(&vals)?));
    }
    witness_calculator
        .calculate_witnesses(inputs.into_iter(), true)
        .map_err(|e| JsValue::from(&format!("Error while generating witnesses: {:?}", e)))
}

#[wasm_bindgen(js_name = r1csGenerateWires)]
pub fn r1cs_generate_wires(
    wasm_bytes: js_sys::Uint8Array,
    input_wires: js_sys::Map,
) -> Result<js_sys::Array, JsValue> {
    set_panic_hook();
    let wires = gen_wires(wasm_bytes, input_wires)?;
    js_array_from_frs(&wires)
}

#[wasm_bindgen(js_name = r1csCircuitSatisfied)]
pub fn r1cs_circuit_satisfied(
    curve_name: &str,
    num_public: usize,
    num_private: usize,
    constraints: js_sys::Array,
    wasm_bytes: js_sys::Uint8Array,
    input_wires: js_sys::Map,
) -> Result<bool, JsValue> {
    set_panic_hook();
    let r = gen_r1cs(curve_name, num_public, num_private, constraints)?;
    let mut circuit = CircomCircuit::setup(r);
    let wires = gen_wires(wasm_bytes, input_wires)?;
    circuit.set_wires(wires);
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit
        .clone()
        .generate_constraints(cs.clone())
        .map_err(|e| JsValue::from(&format!("Error while generating constraints: {:?}", e)))?;
    cs.is_satisfied().map_err(|e| {
        JsValue::from(&format!(
            "Error while checking if circuit is satisfied: {:?}",
            e
        ))
    })
}

#[wasm_bindgen(js_name = r1csSnarkSetup)]
pub fn r1cs_snark_setup(
    curve_name: &str,
    num_public: usize,
    num_private: usize,
    constraints: js_sys::Array,
    commit_witness_count: usize,
    return_uncompressed: bool,
) -> Result<js_sys::Uint8Array, JsValue> {
    set_panic_hook();
    let r = gen_r1cs(curve_name, num_public, num_private, constraints)?;
    let circuit = CircomCircuit::setup(r);
    let mut rng = get_seeded_rng();
    let pk = circuit
        .generate_proving_key(commit_witness_count, &mut rng)
        .map_err(|e| JsValue::from(&format!("SNARK setup for R1CS returned error: {:?}", e)))?;
    Ok(if return_uncompressed {
        obj_to_uint8array_unchecked!(&pk, "LegoProvingKey")
    } else {
        obj_to_uint8array!(&pk, false, "LegoProvingKey")
    })
}
