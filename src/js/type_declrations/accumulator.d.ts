import {AccumulatorParams, Keypair, VerifyResult, UniversalAccumulator, NonMembershipWitness} from "../types";

export function generateAccumulatorParams(
    label?: Uint8Array
): Promise<Required<AccumulatorParams>>;

export function isAccumulatorParamsValid(
    params: AccumulatorParams
): Promise<boolean>;

export function accumulatorParamsToBytes(
    params: AccumulatorParams
): Promise<Uint8Array>;

export function accumulatorParamsFromBytes(
    bytes: Uint8Array
): Promise<AccumulatorParams>;

export function generateAccumulatorSecretKey(seed?: Uint8Array): Promise<Uint8Array>;

export function generateAccumulatorPublicKey(
    secretKey: Uint8Array,
    params: AccumulatorParams
): Promise<Uint8Array>;

export function isAccumulatorPublicKeyValid(
    publicKey: Uint8Array
): Promise<boolean>;

export function accumulatorPublicKeyToBytes(
    publicKey: Uint8Array
): Promise<Uint8Array>;

export function accumulatorPublicKeyFromBytes(
    bytes: Uint8Array
): Promise<Uint8Array>;

export function generateAccumulatorKeyPair(
    params: AccumulatorParams,
    seed?: Uint8Array
): Promise<Required<Keypair>>;

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
): Promise<Required<UniversalAccumulator>>;

export function universalAccumulatorGetAccumulated(
    accumulator: UniversalAccumulator,
): Promise<Uint8Array>;

export function universalAccumulatorAdd(
    accumulator: UniversalAccumulator,
    element: Uint8Array,
    secretKey: Uint8Array,
): Promise<UniversalAccumulator>;

export function universalAccumulatorRemove(
    accumulator: UniversalAccumulator,
    element: Uint8Array,
    secretKey: Uint8Array,
): Promise<UniversalAccumulator>;

export function universalAccumulatorMembershipWitness(
    accumulator: UniversalAccumulator,
    element: Uint8Array,
    secretKey: Uint8Array,
): Promise<Uint8Array>;

export function universalAccumulatorVerifyMembership(
    accumulated: Uint8Array,
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
    accumulator: UniversalAccumulator,
    d: Uint8Array,
    nonMember: Uint8Array,
    secretKey: Uint8Array,
    params: AccumulatorParams,
): Promise<NonMembershipWitness>;

export function universalAccumulatorVerifyNonMembership(
    accumulated: Uint8Array,
    element: Uint8Array,
    witness: NonMembershipWitness,
    publicKey: Uint8Array,
    params: AccumulatorParams,
): Promise<boolean>;

export function universalAccumulatorAddBatch(
    accumulator: UniversalAccumulator,
    elements: Uint8Array[],
    secretKey: Uint8Array,
): Promise<UniversalAccumulator>;

export function universalAccumulatorRemoveBatch(
    accumulator: UniversalAccumulator,
    elements: Uint8Array[],
    secretKey: Uint8Array,
): Promise<UniversalAccumulator>;

export function universalAccumulatorBatchUpdates(
    accumulator: UniversalAccumulator,
    additions: Uint8Array[],
    removals: Uint8Array[],
    secretKey: Uint8Array,
): Promise<UniversalAccumulator>;

export function universalAccumulatorMembershipWitnessesForBatch(
    accumulator: UniversalAccumulator,
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
    accumulator: UniversalAccumulator,
    d: Uint8Array[],
    nonMembers: Uint8Array[],
    secretKey: Uint8Array,
    params: AccumulatorParams,
): Promise<NonMembershipWitness[]>;

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
    witness: NonMembershipWitness,
    nonMember: Uint8Array,
    addition: Uint8Array,
    oldAccumulated: Uint8Array,
): Promise<NonMembershipWitness>;

export function updateNonMembershipWitnessPostRemove(
    witness: NonMembershipWitness,
    nonMember: Uint8Array,
    removal: Uint8Array,
    newAccumulated: Uint8Array,
): Promise<NonMembershipWitness>;

export function updateMembershipWitnessesPostBatchUpdates(
    witnesses: Uint8Array[],
    members: Uint8Array[],
    additions: Uint8Array[],
    removals: Uint8Array[],
    oldAccumulated: Uint8Array,
    secretKey: Uint8Array,
): Promise<Uint8Array[]>;

export function updateNonMembershipWitnessesPostBatchUpdates(
    witnesses: NonMembershipWitness[],
    nonMembers: Uint8Array[],
    additions: Uint8Array[],
    removals: Uint8Array[],
    oldAccumulated: Uint8Array,
    secretKey: Uint8Array,
): Promise<NonMembershipWitness[]>;

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
    witness: NonMembershipWitness,
    nonMember: Uint8Array,
    additions: Uint8Array[],
    removals: Uint8Array[],
    publicInfo: Uint8Array,
): Promise<NonMembershipWitness>;

export function updateMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates(
    witness: Uint8Array,
    member: Uint8Array,
    additions: Uint8Array[][],
    removals: Uint8Array[][],
    publicInfo: Uint8Array[],
): Promise<Uint8Array>;

export function updateNonMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates(
    witness: NonMembershipWitness,
    nonMember: Uint8Array,
    additions: Uint8Array[][],
    removals: Uint8Array[][],
    publicInfo: Uint8Array[],
): Promise<NonMembershipWitness>;

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
    witness: NonMembershipWitness,
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
