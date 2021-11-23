import {IKeypair, VerifyResult, IUniversalAccumulator, INonMembershipWitness} from "../types";

export function generateAccumulatorParams(
    label?: Uint8Array
): Uint8Array;

export function isAccumulatorParamsValid(
    params: Uint8Array
): boolean;

export function generateAccumulatorSecretKey(seed?: Uint8Array): Uint8Array;

export function generateAccumulatorPublicKey(
    secretKey: Uint8Array,
    params: Uint8Array
): Uint8Array;

export function isAccumulatorPublicKeyValid(
    publicKey: Uint8Array
): boolean;

export function generateAccumulatorKeyPair(
    params: Uint8Array,
    seed?: Uint8Array
): Required<IKeypair>;

export function accumulatorGetElementFromBytes(
    bytes: Uint8Array,
): Uint8Array;

export function positiveAccumulatorInitialize(
    params: Uint8Array,
): Uint8Array;

export function positiveAccumulatorGetAccumulated(
    accumulator: Uint8Array,
): Uint8Array;

export function positiveAccumulatorAdd(
    accumulator: Uint8Array,
    element: Uint8Array,
    secretKey: Uint8Array,
): Uint8Array;

export function positiveAccumulatorRemove(
    accumulator: Uint8Array,
    element: Uint8Array,
    secretKey: Uint8Array,
): Uint8Array;

export function positiveAccumulatorMembershipWitness(
    accumulator: Uint8Array,
    element: Uint8Array,
    secretKey: Uint8Array,
): Uint8Array;

export function positiveAccumulatorVerifyMembership(
    accumulator: Uint8Array,
    element: Uint8Array,
    witness: Uint8Array,
    publicKey: Uint8Array,
    params: Uint8Array,
): boolean;

export function positiveAccumulatorAddBatch(
    accumulator: Uint8Array,
    elements: Uint8Array[],
    secretKey: Uint8Array,
): Uint8Array;

export function positiveAccumulatorRemoveBatch(
    accumulator: Uint8Array,
    elements: Uint8Array[],
    secretKey: Uint8Array,
): Uint8Array;

export function positiveAccumulatorBatchUpdates(
    accumulator: Uint8Array,
    additions: Uint8Array[],
    removals: Uint8Array[],
    secretKey: Uint8Array,
): Uint8Array;

export function positiveAccumulatorMembershipWitnessesForBatch(
    accumulator: Uint8Array,
    elements: Uint8Array[],
    secretKey: Uint8Array,
): Uint8Array[];

export function universalAccumulatorFixedInitialElements(): Uint8Array[];

export function universalAccumulatorComputeInitialFv(
    initialElements: Uint8Array[],
    secretKey: Uint8Array,
): Uint8Array;

export function universalAccumulatorCombineMultipleInitialFv(
    initialFVs: Uint8Array[],
): Uint8Array;

export function universalAccumulatorInitialiseGivenFv(
    fV: Uint8Array,
    params: Uint8Array,
    maxSize: number,
): Required<IUniversalAccumulator>;

export function universalAccumulatorGetAccumulated(
    accumulator: IUniversalAccumulator,
): Uint8Array;

export function universalAccumulatorAdd(
    accumulator: IUniversalAccumulator,
    element: Uint8Array,
    secretKey: Uint8Array,
): IUniversalAccumulator;

export function universalAccumulatorRemove(
    accumulator: IUniversalAccumulator,
    element: Uint8Array,
    secretKey: Uint8Array,
): IUniversalAccumulator;

export function universalAccumulatorMembershipWitness(
    accumulator: IUniversalAccumulator,
    element: Uint8Array,
    secretKey: Uint8Array,
): Uint8Array;

export function universalAccumulatorVerifyMembership(
    accumulated: Uint8Array,
    element: Uint8Array,
    witness: Uint8Array,
    publicKey: Uint8Array,
    params: Uint8Array,
): boolean;

export function universalAccumulatorComputeD(
    nonMember: Uint8Array,
    members: Uint8Array[]
): Uint8Array;

export function universalAccumulatorCombineMultipleD(
    d: Uint8Array[],
): Uint8Array;

export function universalAccumulatorNonMembershipWitness(
    accumulator: IUniversalAccumulator,
    d: Uint8Array,
    nonMember: Uint8Array,
    secretKey: Uint8Array,
    params: Uint8Array,
): INonMembershipWitness;

export function universalAccumulatorVerifyNonMembership(
    accumulated: Uint8Array,
    element: Uint8Array,
    witness: INonMembershipWitness,
    publicKey: Uint8Array,
    params: Uint8Array,
): boolean;

export function universalAccumulatorAddBatch(
    accumulator: IUniversalAccumulator,
    elements: Uint8Array[],
    secretKey: Uint8Array,
): IUniversalAccumulator;

export function universalAccumulatorRemoveBatch(
    accumulator: IUniversalAccumulator,
    elements: Uint8Array[],
    secretKey: Uint8Array,
): IUniversalAccumulator;

export function universalAccumulatorBatchUpdates(
    accumulator: IUniversalAccumulator,
    additions: Uint8Array[],
    removals: Uint8Array[],
    secretKey: Uint8Array,
): IUniversalAccumulator;

export function universalAccumulatorMembershipWitnessesForBatch(
    accumulator: IUniversalAccumulator,
    elements: Uint8Array[],
    secretKey: Uint8Array,
): Uint8Array[];

export function universalAccumulatorComputeDForBatch(
    nonMembers: Uint8Array[],
    members: Uint8Array[]
): Uint8Array[];

export function universalAccumulatorCombineMultipleDForBatch(
    d: Uint8Array[][],
): Uint8Array[];

export function universalAccumulatorNonMembershipWitnessesForBatch(
    accumulator: IUniversalAccumulator,
    d: Uint8Array[],
    nonMembers: Uint8Array[],
    secretKey: Uint8Array,
    params: Uint8Array,
): INonMembershipWitness[];

export function updateMembershipWitnessPostAdd(
    witness: Uint8Array,
    member: Uint8Array,
    addition: Uint8Array,
    oldAccumulated: Uint8Array,
): Uint8Array;

export function updateMembershipWitnessPostRemove(
    witness: Uint8Array,
    member: Uint8Array,
    removal: Uint8Array,
    newAccumulated: Uint8Array,
): Uint8Array;

export function updateNonMembershipWitnessPostAdd(
    witness: INonMembershipWitness,
    nonMember: Uint8Array,
    addition: Uint8Array,
    oldAccumulated: Uint8Array,
): INonMembershipWitness;

export function updateNonMembershipWitnessPostRemove(
    witness: INonMembershipWitness,
    nonMember: Uint8Array,
    removal: Uint8Array,
    newAccumulated: Uint8Array,
): INonMembershipWitness;

export function updateMembershipWitnessesPostBatchUpdates(
    witnesses: Uint8Array[],
    members: Uint8Array[],
    additions: Uint8Array[],
    removals: Uint8Array[],
    oldAccumulated: Uint8Array,
    secretKey: Uint8Array,
): Uint8Array[];

export function updateNonMembershipWitnessesPostBatchUpdates(
    witnesses: INonMembershipWitness[],
    nonMembers: Uint8Array[],
    additions: Uint8Array[],
    removals: Uint8Array[],
    oldAccumulated: Uint8Array,
    secretKey: Uint8Array,
): INonMembershipWitness[];

export function publicInfoForWitnessUpdate(
    oldAccumulated: Uint8Array,
    additions: Uint8Array[],
    removals: Uint8Array[],
    secretKey: Uint8Array,
): Uint8Array;

export function updateMembershipWitnessUsingPublicInfoAfterBatchUpdate(
    witness: Uint8Array,
    member: Uint8Array,
    additions: Uint8Array[],
    removals: Uint8Array[],
    publicInfo: Uint8Array,
): Uint8Array;

export function updateNonMembershipWitnessUsingPublicInfoAfterBatchUpdate(
    witness: INonMembershipWitness,
    nonMember: Uint8Array,
    additions: Uint8Array[],
    removals: Uint8Array[],
    publicInfo: Uint8Array,
): INonMembershipWitness;

export function updateMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates(
    witness: Uint8Array,
    member: Uint8Array,
    additions: Uint8Array[][],
    removals: Uint8Array[][],
    publicInfo: Uint8Array[],
): Uint8Array;

export function updateNonMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates(
    witness: INonMembershipWitness,
    nonMember: Uint8Array,
    additions: Uint8Array[][],
    removals: Uint8Array[][],
    publicInfo: Uint8Array[],
): INonMembershipWitness;

export function generateMembershipProvingKey(
    label?: Uint8Array
): Uint8Array;

export function generateNonMembershipProvingKey(
    label?: Uint8Array
): Uint8Array;

export function accumulatorDeriveMembershipProvingKeyFromNonMembershipKey(
    nonMembershipProvingKey: Uint8Array
): Uint8Array;

export function accumulatorInitializeMembershipProof(
    member: Uint8Array,
    blinding: Uint8Array,
    witness: Uint8Array,
    publicKey: Uint8Array,
    params: Uint8Array,
    provingKey: Uint8Array,
): Uint8Array;

export function accumulatorGenMembershipProof(
    protocol: Uint8Array,
    challenge: Uint8Array,
): Uint8Array;

export function accumulatorVerifyMembershipProof(
    proof: Uint8Array,
    accumulated: Uint8Array,
    challenge: Uint8Array,
    publicKey: Uint8Array,
    params: Uint8Array,
    provingKey: Uint8Array,
): Required<VerifyResult>;

export function accumulatorInitializeNonMembershipProof(
    nonMember: Uint8Array,
    blinding: Uint8Array,
    witness: INonMembershipWitness,
    publicKey: Uint8Array,
    params: Uint8Array,
    provingKey: Uint8Array,
): Uint8Array;

export function accumulatorGenNonMembershipProof(
    protocol: Uint8Array,
    challenge: Uint8Array,
): Uint8Array;

export function accumulatorVerifyNonMembershipProof(
    proof: Uint8Array,
    accumulated: Uint8Array,
    challenge: Uint8Array,
    publicKey: Uint8Array,
    params: Uint8Array,
    provingKey: Uint8Array,
): Required<VerifyResult>;

export function accumulatorChallengeContributionFromMembershipProtocol(
    protocol: Uint8Array,
    accumulated: Uint8Array,
    publicKey: Uint8Array,
    params: Uint8Array,
    provingKey: Uint8Array,
): Uint8Array;

export function accumulatorChallengeContributionFromMembershipProof(
    proof: Uint8Array,
    accumulated: Uint8Array,
    publicKey: Uint8Array,
    params: Uint8Array,
    provingKey: Uint8Array,
): Uint8Array;

export function accumulatorChallengeContributionFromNonMembershipProtocol(
    protocol: Uint8Array,
    accumulated: Uint8Array,
    publicKey: Uint8Array,
    params: Uint8Array,
    provingKey: Uint8Array,
): Uint8Array;

export function accumulatorChallengeContributionFromNonMembershipProof(
    proof: Uint8Array,
    accumulated: Uint8Array,
    publicKey: Uint8Array,
    params: Uint8Array,
    provingKey: Uint8Array,
): Uint8Array;

export function accumulatorChallengeContributionFromNonMembershipProof(
    proof: Uint8Array,
    accumulated: Uint8Array,
    publicKey: Uint8Array,
    params: Uint8Array,
    provingKey: Uint8Array,
): Uint8Array;
