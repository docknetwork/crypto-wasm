import {AccumulatorParams, Keypair, VerifyResult} from "./types";

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
): Promise<boolean>;

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
): Promise<boolean>;

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
): Promise<boolean>;

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