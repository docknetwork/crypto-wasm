/*
 * Copyright 2020 - MATTR Limited
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#[cfg(feature = "dlmalloc")]
#[global_allocator]
static ALLOC: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;

pub use ark_bls12_381::{Bls12_381, G1Projective, G2Projective};
use ark_ec::pairing::Pairing;

#[macro_use]
pub mod utils;
pub mod accumulator;
pub mod bbs_plus;
pub mod bound_check;
pub mod common;
pub mod composite_proof_system;
pub mod legosnark;
pub mod ps;
pub mod r1cs;
pub mod saver;

// Trying to keep types at one place so changing the curve is easier
pub(crate) type Fr = <Bls12_381 as Pairing>::ScalarField;
pub(crate) type G1Affine = <Bls12_381 as Pairing>::G1Affine;
pub(crate) type G2Affine = <Bls12_381 as Pairing>::G2Affine;
