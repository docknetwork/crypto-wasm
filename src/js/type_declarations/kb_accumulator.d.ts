import {IKBUniversalAccumulator} from "../types";

export function kbUniversalAccumulatorInitialise(
    domain: Uint8Array[],
    secretKey: Uint8Array,
    params: Uint8Array
): Required<IKBUniversalAccumulator>;

export function kbUniversalAccumulatorComputeExtended(
    oldAccum: IKBUniversalAccumulator,
    newElements: Uint8Array[],
    secretKey: Uint8Array,
): Required<IKBUniversalAccumulator>;

export function kbUniversalAccumulatorAdd(
    accumulator: IKBUniversalAccumulator,
    element: Uint8Array,
    secretKey: Uint8Array,
): IKBUniversalAccumulator;

export function kbUniversalAccumulatorRemove(
    accumulator: IKBUniversalAccumulator,
    element: Uint8Array,
    secretKey: Uint8Array,
): IKBUniversalAccumulator;

export function kbUniversalAccumulatorMembershipWitness(
    accumulator: IKBUniversalAccumulator,
    element: Uint8Array,
    secretKey: Uint8Array,
): Uint8Array;

export function kbUniversalAccumulatorVerifyMembership(
    accumulator: IKBUniversalAccumulator,
    element: Uint8Array,
    witness: Uint8Array,
    publicKey: Uint8Array,
    params: Uint8Array,
): boolean;

export function kbUniversalAccumulatorNonMembershipWitness(
    accumulator: IKBUniversalAccumulator,
    element: Uint8Array,
    secretKey: Uint8Array,
): Uint8Array;

export function kbUniversalAccumulatorVerifyNonMembership(
    accumulator: IKBUniversalAccumulator,
    element: Uint8Array,
    witness: Uint8Array,
    publicKey: Uint8Array,
    params: Uint8Array,
): boolean;

export function kbUniversalAccumulatorAddBatch(
    accumulator: IKBUniversalAccumulator,
    elements: Uint8Array[],
    secretKey: Uint8Array,
): IKBUniversalAccumulator;

export function kbUniversalAccumulatorRemoveBatch(
    accumulator: IKBUniversalAccumulator,
    elements: Uint8Array[],
    secretKey: Uint8Array,
): IKBUniversalAccumulator;

export function kbUniversalAccumulatorBatchUpdates(
    accumulator: IKBUniversalAccumulator,
    additions: Uint8Array[],
    removals: Uint8Array[],
    secretKey: Uint8Array,
): IKBUniversalAccumulator;

export function kbUniversalAccumulatorMembershipWitnessesForBatch(
    accumulator: IKBUniversalAccumulator,
    elements: Uint8Array[],
    secretKey: Uint8Array,
): Uint8Array[];

export function kbUniversalAccumulatorNonMembershipWitnessesForBatch(
    accumulator: IKBUniversalAccumulator,
    elements: Uint8Array[],
    secretKey: Uint8Array,
): Uint8Array[];

export function kbUniversalUpdateMembershipWitnessPostAdd(
    witness: Uint8Array,
    member: Uint8Array,
    addition: Uint8Array,
    oldAccumulator: IKBUniversalAccumulator,
): Uint8Array;

export function kbUniversalUpdateMembershipWitnessPostRemove(
    witness: Uint8Array,
    member: Uint8Array,
    removal: Uint8Array,
    newAccumulator: IKBUniversalAccumulator,
): Uint8Array;

export function kbUniversalUpdateNonMembershipWitnessPostAdd(
    witness: Uint8Array,
    nonMember: Uint8Array,
    addition: Uint8Array,
    oldAccumulator: IKBUniversalAccumulator,
): Uint8Array;

export function kbUniversalUpdateNonMembershipWitnessPostRemove(
    witness: Uint8Array,
    nonMember: Uint8Array,
    removal: Uint8Array,
    newAccumulator: IKBUniversalAccumulator,
): Uint8Array;

export function kbUpdateMembershipWitnessesPostBatchUpdates(
    witnesses: Uint8Array[],
    members: Uint8Array[],
    additions: Uint8Array[],
    removals: Uint8Array[],
    oldAccumulator: IKBUniversalAccumulator,
    secretKey: Uint8Array,
): Uint8Array[];

export function kbUpdateNonMembershipWitnessesPostBatchUpdates(
    witnesses: Uint8Array[],
    nonMembers: Uint8Array[],
    additions: Uint8Array[],
    removals: Uint8Array[],
    oldAccumulator: IKBUniversalAccumulator,
    secretKey: Uint8Array,
): Uint8Array[];

export function kbUpdateBothWitnessesPostBatchUpdates(
    memWitnesses: Uint8Array[],
    members: Uint8Array[],
    nonMemWitnesses: Uint8Array[],
    nonMembers: Uint8Array[],
    additions: Uint8Array[],
    removals: Uint8Array[],
    oldAccumulator: IKBUniversalAccumulator,
    secretKey: Uint8Array,
): [Uint8Array[], Uint8Array[]];

export function publicInfoForKBUniversalMemWitnessUpdate(
    oldAccumulator: IKBUniversalAccumulator,
    additions: Uint8Array[],
    removals: Uint8Array[],
    secretKey: Uint8Array,
): Uint8Array;

export function publicInfoForKBUniversalNonMemWitnessUpdate(
    oldAccumulator: IKBUniversalAccumulator,
    additions: Uint8Array[],
    removals: Uint8Array[],
    secretKey: Uint8Array,
): Uint8Array;

export function publicInfoForBothKBUniversalWitnessUpdate(
    oldAccumulator: IKBUniversalAccumulator,
    additions: Uint8Array[],
    removals: Uint8Array[],
    secretKey: Uint8Array,
): [Uint8Array, Uint8Array];

export function updateKBUniversalMembershipWitnessUsingPublicInfoAfterBatchUpdate(
    witness: Uint8Array,
    member: Uint8Array,
    additions: Uint8Array[],
    removals: Uint8Array[],
    publicInfo: Uint8Array,
): Uint8Array;

export function updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterBatchUpdate(
    witness: Uint8Array,
    nonMember: Uint8Array,
    additions: Uint8Array[],
    removals: Uint8Array[],
    publicInfo: Uint8Array,
): Uint8Array;

export function updateKBUniversalMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates(
    witness: Uint8Array,
    member: Uint8Array,
    additions: Uint8Array[][],
    removals: Uint8Array[][],
    publicInfo: Uint8Array[],
): Uint8Array;

export function updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates(
    witness: Uint8Array,
    nonMember: Uint8Array,
    additions: Uint8Array[][],
    removals: Uint8Array[][],
    publicInfo: Uint8Array[],
): Uint8Array;