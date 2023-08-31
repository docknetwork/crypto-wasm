use blake2::Blake2b512;
use js_sys::Uint8Array;
use oblivious_transfer_protocols::ot_based_multiplication::{
    dkls18_mul_2p::MultiplicationOTEParams, dkls19_batch_mul_2p::GadgetVector,
};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use crate::{utils::set_panic_hook, Fr};

pub mod base_ot;
pub mod signing;

pub(crate) const BASE_OT_KEY_SIZE: u16 = 128;
pub(crate) const KAPPA: u16 = 256;
pub(crate) const STATISTICAL_SECURITY_PARAMETER: u16 = 80;
pub(crate) const SALT_SIZE: usize = 256;

#[wasm_bindgen(js_name = generateGadgetVectorForThresholdSig)]
pub fn generate_gadget_vector_for_threshold_sig(label: Vec<u8>) -> Result<Uint8Array, JsValue> {
    set_panic_hook();
    let ote_params = MultiplicationOTEParams::<KAPPA, STATISTICAL_SECURITY_PARAMETER> {};
    let gadget_vector = GadgetVector::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::new::<Blake2b512>(
        ote_params, &label,
    );
    Ok(obj_to_uint8array!(&gadget_vector, false, "GadgetVector"))
}
