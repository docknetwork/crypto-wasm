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

import {
  BlsKeyPair,
  Bls12381ToBbsRequest,
  BbsKeyPair,
  BbsSignRequest,
  BlsBbsSignRequest,
  BbsVerifyRequest,
  BbsVerifyResult,
  BlsBbsVerifyRequest,
  BbsCreateProofRequest,
  BbsVerifyProofRequest,
  BbsSigParams,
  BbsKeypair,
  BbsSig,
  BbsPoKSigProtocol,
  BbsPoKSigProof
} from "./types";

export * from "./types";

export const BBS_SIGNATURE_LENGTH = 112;

export const DEFAULT_BLS12381_PRIVATE_KEY_LENGTH = 32;

export const DEFAULT_BLS12381_G1_PUBLIC_KEY_LENGTH = 48;

export const DEFAULT_BLS12381_G2_PUBLIC_KEY_LENGTH = 96;

export function generateBls12381G1KeyPair(
  seed?: Uint8Array
): Promise<Required<BlsKeyPair>>;

export function generateBls12381G2KeyPair(
  seed?: Uint8Array
): Promise<Required<BlsKeyPair>>;

export function bls12381toBbs(
  request: Bls12381ToBbsRequest
): Promise<BbsKeyPair>;

export function sign(request: BbsSignRequest): Promise<Uint8Array>;

export function blsSign(request: BlsBbsSignRequest): Promise<Uint8Array>;

export function verify(request: BbsVerifyRequest): Promise<BbsVerifyResult>;

export function blsVerify(
  request: BlsBbsVerifyRequest
): Promise<BbsVerifyResult>;

export function createProof(
  request: BbsCreateProofRequest
): Promise<Uint8Array>;

export function verifyProof(
  request: BbsVerifyProofRequest
): Promise<BbsVerifyResult>;

export function blsCreateProof(
  request: BbsCreateProofRequest
): Promise<Uint8Array>;

export function blsVerifyProof(
  request: BbsVerifyProofRequest
): Promise<BbsVerifyResult>;

export function generateRandomFieldElement(
  seed?: Uint8Array
): Promise<Uint8Array>;

export function generateBBSSigningKey(seed?: Uint8Array): Promise<Uint8Array>;

export function generateSignatureParamsG1(
  messageCount: number,
  label?: Uint8Array
): Promise<Required<BbsSigParams>>;

export function isSignatureParamsG1Valid(
    params: BbsSigParams
): Promise<boolean>;

export function bbsSignatureParamsG1MaxSupportedMsgs(
    params: BbsSigParams
): Promise<number>;

export function generateSignatureParamsG2(
  messageCount: number,
  label?: Uint8Array
): Promise<Required<BbsSigParams>>;

export function isSignatureParamsG2Valid(
    params: BbsSigParams
): Promise<boolean>;

export function bbsSignatureParamsG2MaxSupportedMsgs(
    params: BbsSigParams
): Promise<number>;

export function generateBBSPublicKeyG1(
  secretKey: Uint8Array,
  params: BbsSigParams
): Promise<Uint8Array>;

export function isBBSPublicKeyG1Valid(
    publicKey: Uint8Array
): Promise<Uint8Array>;

export function generateBBSPublicKeyG2(
  secretKey: Uint8Array,
  params: BbsSigParams
): Promise<Uint8Array>;

export function isBBSPublicKeyG2Valid(
    publicKey: Uint8Array
): Promise<Uint8Array>;

export function generateBBSKeyPairG1(
  params: BbsSigParams,
  seed?: Uint8Array
): Promise<Required<BbsKeypair>>;

export function generateBBSKeyPairG2(
  params: BbsSigParams,
  seed?: Uint8Array
): Promise<Required<BbsKeypair>>;

export function bbsSignG1(
  messages: Uint8Array[],
  secretKey: Uint8Array,
  params: BbsSigParams,
  encodeMessages: Boolean
): Promise<Required<BbsSig>>;

export function bbsSignG2(
  messages: Uint8Array[],
  secretKey: Uint8Array,
  params: BbsSigParams,
  encodeMessages: Boolean
): Promise<Required<BbsSig>>;

export function bbsVerfiyG1(
    messages: Uint8Array[],
    signature: BbsSig,
    publicKey: Uint8Array,
    params: BbsSigParams,
    encodeMessages: Boolean
): Promise<Required<BbsVerifyResult>>;

export function bbsVerfiyG2(
    messages: Uint8Array[],
    signature: BbsSig,
    publicKey: Uint8Array,
    params: BbsSigParams,
    encodeMessages: Boolean
): Promise<Required<BbsVerifyResult>>;

export function bbsCommitMsgsInG1(
    messages: Map<number, Uint8Array>,
    blinding: Uint8Array,
    params: BbsSigParams,
    encodeMessages: Boolean
): Promise<Uint8Array>;

export function bbsCommitMsgsInG2(
    messages: Map<number, Uint8Array>,
    blinding: Uint8Array,
    params: BbsSigParams,
    encodeMessages: Boolean
): Promise<Uint8Array>;

export function bbsBlindSignG1(
    commitment: Uint8Array,
    uncommittedMessages: Map<number, Uint8Array>,
    secretKey: Uint8Array,
    params: BbsSigParams,
    encodeMessages: Boolean
): Promise<BbsSig>;

export function bbsBlindSignG2(
    commitment: Uint8Array,
    uncommittedMessages: Map<number, Uint8Array>,
    secretKey: Uint8Array,
    params: BbsSigParams,
    encodeMessages: Boolean
): Promise<BbsSig>;

export function bbsUnblindSigG1(
    signature: BbsSig,
    blinding: Uint8Array,
): Promise<BbsSig>;

export function bbsUnblindSigG2(
    signature: BbsSig,
    blinding: Uint8Array,
): Promise<BbsSig>;

export function bbsInitializeProofOfKnowledgeOfSignature(
    signature: BbsSig,
    params: BbsSigParams,
    messages: Uint8Array[],
    blindings: Map<number, Uint8Array>,
    revealedIndices: Set<number>,
    encodeMessages: Boolean
): Promise<BbsPoKSigProtocol>;

export function bbsGenProofOfKnowledgeOfSignature(
    protocol: BbsPoKSigProtocol,
    challenge: Uint8Array
): Promise<BbsPoKSigProof>;

export function bbsVerifyProofOfKnowledgeOfSignature(
    proof: BbsPoKSigProof,
    revealedMessages: Map<number, Uint8Array>,
    challenge: Uint8Array,
    publicKey: Uint8Array,
    params: BbsSigParams,
    encodeMessages: Boolean
): Promise<Required<BbsVerifyResult>>;