import {BbsSigParams, INonMembershipWitness, VerifyResult} from "../types";

export function generatePoKBBSSignatureStatement(
    params: BbsSigParams,
    publicKey: Uint8Array,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
): Uint8Array;

export function generateAccumulatorMembershipStatement(
    params: Uint8Array,
    publicKey: Uint8Array,
    provingKey: Uint8Array,
    accumulated: Uint8Array
): Uint8Array;

export function generateAccumulatorNonMembershipStatement(
    params: Uint8Array,
    publicKey: Uint8Array,
    provingKey: Uint8Array,
    accumulated: Uint8Array
): Uint8Array;

export function generatePedersenCommitmentG1Statement(
    bases: Uint8Array[],
    commitment: Uint8Array
): Uint8Array;

export function generatePedersenCommitmentG2Statement(
    bases: Uint8Array[],
    commitment: Uint8Array
): Uint8Array;

export function generateWitnessEqualityMetaStatement(
    equalities: Set<[number, number]>,
): Uint8Array;

export function generatePoKBBSSignatureWitness(
    signature: Uint8Array,
    unrevealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
): Uint8Array;

export function generateAccumulatorMembershipWitness(
    element: Uint8Array,
    accumulatorWitness: Uint8Array
): Uint8Array;

export function generateAccumulatorNonMembershipWitness(
    element: Uint8Array,
    accumulatorWitness: INonMembershipWitness
): Uint8Array;

export function generatePedersenCommitmentWitness(
    elements: Uint8Array[]
): Uint8Array;

export function generateProofSpec(
    statements: Uint8Array[],
    metaStatements: Uint8Array[],
    context?: Uint8Array
): Uint8Array;

export function getProofSpecAsJson(
    proofSpec: Uint8Array
): string;

export function getProofSpecFromJson(
    json: string
): Uint8Array;

export function generateCompositeProof(
    proofSpec: Uint8Array,
    witnesses: Uint8Array[],
    nonce?: Uint8Array
): Uint8Array;

export function verifyCompositeProof(
    proof: Uint8Array,
    proofSpec: Uint8Array,
    nonce?: Uint8Array
): Required<VerifyResult>;
