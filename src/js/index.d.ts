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
  BbsPoKSigProtocol,
  BbsPoKSigProof,
  AccumulatorParams,
  Keypair,
  VerifyResult
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

export function generateRandomG1Element(): Promise<Uint8Array>;

export function generateRandomG2Element(): Promise<Uint8Array>;

export function generateFieldElementFromBytes(
    bytes: Uint8Array
): Promise<Uint8Array>;

export function fieldElementAsBytes(
    element: Uint8Array
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
): Promise<boolean>;

export function generateBBSPublicKeyG2(
  secretKey: Uint8Array,
  params: BbsSigParams
): Promise<Uint8Array>;

export function isBBSPublicKeyG2Valid(
    publicKey: Uint8Array
): Promise<boolean>;

export function generateBBSKeyPairG1(
  params: BbsSigParams,
  seed?: Uint8Array
): Promise<Required<Keypair>>;

export function generateBBSKeyPairG2(
  params: BbsSigParams,
  seed?: Uint8Array
): Promise<Required<Keypair>>;

export function bbsEncodeMessageForSigning(
    message: Uint8Array
): Promise<Uint8Array>;

export function bbsEncodeMessagesForSigning(
    messages: Uint8Array[],
    indicesToEncode: Set<number>
): Promise<Uint8Array[]>;

export function bbsGetBasesForCommitmentG1(
    params: BbsSigParams,
    indicesToCommit: Set<number>
): Promise<Uint8Array[]>;

export function bbsGetBasesForCommitmentG2(
    params: BbsSigParams,
    indicesToCommit: Set<number>
): Promise<Uint8Array[]>;

export function bbsSignG1(
  messages: Uint8Array[],
  secretKey: Uint8Array,
  params: BbsSigParams,
  encodeMessages: Boolean
): Promise<Uint8Array>;

export function bbsSignG2(
  messages: Uint8Array[],
  secretKey: Uint8Array,
  params: BbsSigParams,
  encodeMessages: Boolean
): Promise<Uint8Array>;

export function bbsVerfiyG1(
    messages: Uint8Array[],
    signature: Uint8Array,
    publicKey: Uint8Array,
    params: BbsSigParams,
    encodeMessages: Boolean
): Promise<Required<VerifyResult>>;

export function bbsVerfiyG2(
    messages: Uint8Array[],
    signature: Uint8Array,
    publicKey: Uint8Array,
    params: BbsSigParams,
    encodeMessages: Boolean
): Promise<Required<VerifyResult>>;

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
): Promise<Uint8Array>;

export function bbsBlindSignG2(
    commitment: Uint8Array,
    uncommittedMessages: Map<number, Uint8Array>,
    secretKey: Uint8Array,
    params: BbsSigParams,
    encodeMessages: Boolean
): Promise<Uint8Array>;

export function bbsUnblindSigG1(
    signature: Uint8Array,
    blinding: Uint8Array,
): Promise<Uint8Array>;

export function bbsUnblindSigG2(
    signature: Uint8Array,
    blinding: Uint8Array,
): Promise<Uint8Array>;

export function bbsInitializeProofOfKnowledgeOfSignature(
    signature: Uint8Array,
    params: BbsSigParams,
    messages: Uint8Array[],
    blindings: Map<number, Uint8Array>,
    revealedIndices: Set<number>,
    encodeMessages: Boolean
): Promise<BbsPoKSigProtocol>;

export function bbsGenProofOfKnowledgeOfSignature(
    protocol: BbsPoKSigProtocol,
    challenge: Uint8Array
): Promise<Uint8Array>;

export function bbsVerifyProofOfKnowledgeOfSignature(
    proof: Uint8Array,
    revealedMessages: Map<number, Uint8Array>,
    challenge: Uint8Array,
    publicKey: Uint8Array,
    params: BbsSigParams,
    encodeMessages: Boolean
): Promise<Required<VerifyResult>>;

export function bbsChallengeContributionFromProtocol(
    protocol: BbsPoKSigProtocol,
    revealedMessages: Map<number, Uint8Array>,
    params: BbsSigParams,
    encodeMessages: Boolean
): Promise<Uint8Array>;

export function bbsChallengeContributionFromProof(
    proof: Uint8Array,
    revealedMessages: Map<number, Uint8Array>,
    params: BbsSigParams,
    encodeMessages: Boolean
): Promise<Uint8Array>;

export function generateChallengeFromBytes(
    bytes: Uint8Array
): Promise<Uint8Array>;

export function generateAccumulatorParams(
    label?: Uint8Array
): Promise<Required<AccumulatorParams>>;

export function isAccumulatorParamsValid(
    params: AccumulatorParams
): Promise<boolean>;

export function generateAccumulatorSecretKey(seed?: Uint8Array): Promise<Uint8Array>;

export function generateAccumulatorPublicKey(
    secretKey: Uint8Array,
    params: AccumulatorParams
): Promise<Uint8Array>;

export function isAccumulatorPublicKeyValid(
    publicKey: Uint8Array
): Promise<boolean>;

export function generateAccumulatorKeyPair(
    params: AccumulatorParams,
    seed?: Uint8Array
): Promise<Required<Keypair>>;

export function generateFieldElementFromNumber(
    num: number,
): Promise<Uint8Array>;

export function accumulatorGetElementFromBytes(
    bytes: Uint8Array,
): Promise<Uint8Array>;

export function positiveAccumulatorInitialize(
    params: AccumulatorParams,
): Promise<Uint8Array>;

export function positiveAccumulatorGetAccumulated(
    accumulator: Uint8Array,
): Promise<Uint8Array>;

export function positiveAccumulatorAdd(
    accumulator: Uint8Array,
    element: Uint8Array,
    secretKey: Uint8Array,
): Promise<Uint8Array>;

export function positiveAccumulatorRemove(
    accumulator: Uint8Array,
    element: Uint8Array,
    secretKey: Uint8Array,
): Promise<Uint8Array>;

export function positiveAccumulatorMembershipWitness(
    accumulator: Uint8Array,
    element: Uint8Array,
    secretKey: Uint8Array,
): Promise<Uint8Array>;

export function positiveAccumulatorVerifyMembership(
    accumulator: Uint8Array,
    element: Uint8Array,
    witness: Uint8Array,
    publicKey: Uint8Array,
    params: AccumulatorParams,
): Promise<Boolean>;

export function positiveAccumulatorAddBatch(
    accumulator: Uint8Array,
    elements: Uint8Array[],
    secretKey: Uint8Array,
): Promise<Uint8Array>;

export function positiveAccumulatorRemoveBatch(
    accumulator: Uint8Array,
    elements: Uint8Array[],
    secretKey: Uint8Array,
): Promise<Uint8Array>;

export function positiveAccumulatorBatchUpdates(
    accumulator: Uint8Array,
    additions: Uint8Array[],
    removals: Uint8Array[],
    secretKey: Uint8Array,
): Promise<Uint8Array>;

export function positiveAccumulatorMembershipWitnessesForBatch(
    accumulator: Uint8Array,
    elements: Uint8Array[],
    secretKey: Uint8Array,
): Promise<Uint8Array[]>;

export function universalAccumulatorComputeInitialFv(
    initialElements: Uint8Array[],
    secretKey: Uint8Array,
): Promise<Uint8Array>;

export function universalAccumulatorCombineMultipleInitialFv(
    initialFVs: Uint8Array[],
): Promise<Uint8Array>;

export function universalAccumulatorInitialiseGivenFv(
    fV: Uint8Array,
    params: AccumulatorParams,
    maxSize: number,
): Promise<Uint8Array>;

export function universalAccumulatorGetAccumulated(
    accumulator: Uint8Array,
): Promise<Uint8Array>;

export function universalAccumulatorAdd(
    accumulator: Uint8Array,
    element: Uint8Array,
    secretKey: Uint8Array,
): Promise<Uint8Array>;

export function universalAccumulatorRemove(
    accumulator: Uint8Array,
    element: Uint8Array,
    secretKey: Uint8Array,
): Promise<Uint8Array>;

export function universalAccumulatorMembershipWitness(
    accumulator: Uint8Array,
    element: Uint8Array,
    secretKey: Uint8Array,
): Promise<Uint8Array>;

export function universalAccumulatorVerifyMembership(
    accumulator: Uint8Array,
    element: Uint8Array,
    witness: Uint8Array,
    publicKey: Uint8Array,
    params: AccumulatorParams,
): Promise<Boolean>;

export function universalAccumulatorComputeD(
    nonMember: Uint8Array,
    members: Uint8Array[]
): Promise<Uint8Array>;

export function universalAccumulatorCombineMultipleD(
    d: Uint8Array[],
): Promise<Uint8Array>;

export function universalAccumulatorNonMembershipWitness(
    accumulator: Uint8Array,
    d: Uint8Array,
    nonMember: Uint8Array,
    secretKey: Uint8Array,
    params: AccumulatorParams,
): Promise<Uint8Array>;

export function universalAccumulatorVerifyNonMembership(
    accumulator: Uint8Array,
    element: Uint8Array,
    witness: Uint8Array,
    publicKey: Uint8Array,
    params: AccumulatorParams,
): Promise<Boolean>;

export function universalAccumulatorAddBatch(
    accumulator: Uint8Array,
    elements: Uint8Array[],
    secretKey: Uint8Array,
): Promise<Uint8Array>;

export function universalAccumulatorRemoveBatch(
    accumulator: Uint8Array,
    elements: Uint8Array[],
    secretKey: Uint8Array,
): Promise<Uint8Array>;

export function universalAccumulatorBatchUpdates(
    accumulator: Uint8Array,
    additions: Uint8Array[],
    removals: Uint8Array[],
    secretKey: Uint8Array,
): Promise<Uint8Array>;

export function universalAccumulatorMembershipWitnessesForBatch(
    accumulator: Uint8Array,
    elements: Uint8Array[],
    secretKey: Uint8Array,
): Promise<Uint8Array[]>;

export function universalAccumulatorComputeDForBatch(
    nonMembers: Uint8Array[],
    members: Uint8Array[]
): Promise<Uint8Array[]>;

export function universalAccumulatorCombineMultipleDForBatch(
    d: Uint8Array[][],
): Promise<Uint8Array[]>;

export function universalAccumulatorNonMembershipWitnessesForBatch(
    accumulator: Uint8Array,
    d: Uint8Array[],
    nonMembers: Uint8Array[],
    secretKey: Uint8Array,
    params: AccumulatorParams,
): Promise<Uint8Array[]>;

export function updateMembershipWitnessPostAdd(
    witness: Uint8Array,
    member: Uint8Array,
    addition: Uint8Array,
    oldAccumulated: Uint8Array,
): Promise<Uint8Array>;

export function updateMembershipWitnessPostRemove(
    witness: Uint8Array,
    member: Uint8Array,
    removal: Uint8Array,
    newAccumulated: Uint8Array,
): Promise<Uint8Array>;

export function updateNonMembershipWitnessPostAdd(
    witness: Uint8Array,
    nonMember: Uint8Array,
    addition: Uint8Array,
    oldAccumulated: Uint8Array,
): Promise<Uint8Array>;

export function updateNonMembershipWitnessPostRemove(
    witness: Uint8Array,
    nonMember: Uint8Array,
    removal: Uint8Array,
    newAccumulated: Uint8Array,
): Promise<Uint8Array>;

export function publicInfoForWitnessUpdate(
    oldAccumulated: Uint8Array,
    additions: Uint8Array[],
    removals: Uint8Array[],
    secretKey: Uint8Array,
): Promise<Uint8Array>;

export function updateMembershipWitnessUsingPublicInfoAfterBatchUpdate(
    witness: Uint8Array,
    member: Uint8Array,
    additions: Uint8Array[],
    removals: Uint8Array[],
    publicInfo: Uint8Array,
): Promise<Uint8Array>;

export function updateNonMembershipWitnessUsingPublicInfoAfterBatchUpdate(
    witness: Uint8Array,
    nonMember: Uint8Array,
    additions: Uint8Array[],
    removals: Uint8Array[],
    publicInfo: Uint8Array,
): Promise<Uint8Array>;

export function updateMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates(
    witness: Uint8Array,
    member: Uint8Array,
    additions: Uint8Array[][],
    removals: Uint8Array[][],
    publicInfo: Uint8Array[],
): Promise<Uint8Array>;

export function updateNonMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates(
    witness: Uint8Array,
    nonMember: Uint8Array,
    additions: Uint8Array[][],
    removals: Uint8Array[][],
    publicInfo: Uint8Array[],
): Promise<Uint8Array>;

export function generateMembershipProvingKey(
    label?: Uint8Array
): Promise<Uint8Array>;

export function generateNonMembershipProvingKey(
    label?: Uint8Array
): Promise<Uint8Array>;

export function accumulatorDeriveMembershipProvingKeyFromNonMembershipKey(
    nonMembershipProvingKey: Uint8Array
): Promise<Uint8Array>;

export function accumulatorInitializeMembershipProof(
    member: Uint8Array,
    blinding: Uint8Array,
    witness: Uint8Array,
    publicKey: Uint8Array,
    params: AccumulatorParams,
    provingKey: Uint8Array,
): Promise<Uint8Array>;

export function accumulatorGenMembershipProof(
    protocol: Uint8Array,
    challenge: Uint8Array,
): Promise<Uint8Array>;

export function accumulatorVerifyMembershipProof(
    proof: Uint8Array,
    accumulated: Uint8Array,
    challenge: Uint8Array,
    publicKey: Uint8Array,
    params: AccumulatorParams,
    provingKey: Uint8Array,
): Promise<Required<VerifyResult>>;

export function accumulatorInitializeNonMembershipProof(
    nonMember: Uint8Array,
    blinding: Uint8Array,
    witness: Uint8Array,
    publicKey: Uint8Array,
    params: AccumulatorParams,
    provingKey: Uint8Array,
): Promise<Uint8Array>;

export function accumulatorGenNonMembershipProof(
    protocol: Uint8Array,
    challenge: Uint8Array,
): Promise<Uint8Array>;

export function accumulatorVerifyNonMembershipProof(
    proof: Uint8Array,
    accumulated: Uint8Array,
    challenge: Uint8Array,
    publicKey: Uint8Array,
    params: AccumulatorParams,
    provingKey: Uint8Array,
): Promise<Required<VerifyResult>>;

export function accumulatorChallengeContributionFromMembershipProtocol(
    protocol: Uint8Array,
    accumulated: Uint8Array,
    publicKey: Uint8Array,
    params: AccumulatorParams,
    provingKey: Uint8Array,
): Promise<Uint8Array>;

export function accumulatorChallengeContributionFromMembershipProof(
    proof: Uint8Array,
    accumulated: Uint8Array,
    publicKey: Uint8Array,
    params: AccumulatorParams,
    provingKey: Uint8Array,
): Promise<Uint8Array>;

export function accumulatorChallengeContributionFromNonMembershipProtocol(
    protocol: Uint8Array,
    accumulated: Uint8Array,
    publicKey: Uint8Array,
    params: AccumulatorParams,
    provingKey: Uint8Array,
): Promise<Uint8Array>;

export function accumulatorChallengeContributionFromNonMembershipProof(
    proof: Uint8Array,
    accumulated: Uint8Array,
    publicKey: Uint8Array,
    params: AccumulatorParams,
    provingKey: Uint8Array,
): Promise<Uint8Array>;

export function accumulatorChallengeContributionFromNonMembershipProof(
    proof: Uint8Array,
    accumulated: Uint8Array,
    publicKey: Uint8Array,
    params: AccumulatorParams,
    provingKey: Uint8Array,
): Promise<Uint8Array>;

export function generatePoKBBSSignatureStatement(
    params: BbsSigParams,
    publicKey: Uint8Array,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: Boolean
): Promise<Uint8Array>;

export function generateAccumulatorMembershipStatement(
    params: AccumulatorParams,
    publicKey: Uint8Array,
    provingKey: Uint8Array,
    accumulated: Uint8Array
): Promise<Uint8Array>;

export function generateAccumulatorNonMembershipStatement(
    params: AccumulatorParams,
    publicKey: Uint8Array,
    provingKey: Uint8Array,
    accumulated: Uint8Array
): Promise<Uint8Array>;

export function generatePedersenCommitmentG1Statement(
    bases: Uint8Array[],
    commitment: Uint8Array
): Promise<Uint8Array>;

export function generatePedersenCommitmentG2Statement(
    bases: Uint8Array[],
    commitment: Uint8Array
): Promise<Uint8Array>;

export function generateWitnessEqualityMetaStatement(
    equalities: Set<number[]>,
): Promise<Uint8Array>;

export function generatePoKBBSSignatureWitness(
    signature: Uint8Array,
    unrevealedMessages: Map<number, Uint8Array>,
    encodeMessages: Boolean
): Promise<Uint8Array>;

export function generateAccumulatorMembershipWitness(
    element: Uint8Array,
    witness: Uint8Array
): Promise<Uint8Array>;

export function generateAccumulatorNonMembershipWitness(
    element: Uint8Array,
    witness: Uint8Array
): Promise<Uint8Array>;

export function generatePedersenCommitmentWitness(
    elements: Uint8Array[]
): Promise<Uint8Array>;

export function generateProofSpec(
    statements: Uint8Array[],
    metaStatements: Uint8Array[],
    context?: Uint8Array
): Promise<Uint8Array>;

export function generateCompositeProof(
    proofSpec: Uint8Array,
    witnesses: Uint8Array[],
    nonce?: Uint8Array
): Promise<Uint8Array>;

export function verifyCompositeProof(
    proof: Uint8Array,
    proofSpec: Uint8Array,
    nonce?: Uint8Array
): Promise<Required<VerifyResult>>;