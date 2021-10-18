import {AccumulatorParams, BbsSigParams, NonMembershipWitness, VerifyResult} from "../types";

export function generatePoKBBSSignatureStatement(
    params: BbsSigParams,
    publicKey: Uint8Array,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
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
    encodeMessages: boolean
): Promise<Uint8Array>;

export function generateAccumulatorMembershipWitness(
    element: Uint8Array,
    witness: Uint8Array
): Promise<Uint8Array>;

export function generateAccumulatorNonMembershipWitness(
    element: Uint8Array,
    witness: NonMembershipWitness
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