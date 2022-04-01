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

export function generateSaverStatement(
    chunkBitSize: number,
    encGens: Uint8Array,
    commGens: Uint8Array,
    encryptionKey: Uint8Array,
    snarkPk: Uint8Array,
    uncompressedPublicParams: boolean
): Uint8Array;

export function generateBoundCheckLegoStatement(
    min: Uint8Array,
    max: Uint8Array,
    snarkPk: Uint8Array,
    uncompressedPublicParams: boolean
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

export function generateSaverWitness(
    message: Uint8Array
): Uint8Array;

export function generateBoundCheckWitness(
    message: Uint8Array
): Uint8Array;

export function generateProofSpecG1(
    statements: Uint8Array[],
    metaStatements: Uint8Array[],
    context?: Uint8Array
): Uint8Array;

export function generateProofSpecG2(
    statements: Uint8Array[],
    metaStatements: Uint8Array[],
    context?: Uint8Array
): Uint8Array;

export function generateCompositeProofG1(
    proofSpec: Uint8Array,
    witnesses: Uint8Array[],
    nonce?: Uint8Array
): Uint8Array;

export function generateCompositeProofG2(
    proofSpec: Uint8Array,
    witnesses: Uint8Array[],
    nonce?: Uint8Array
): Uint8Array;

export function verifyCompositeProofG1(
    proof: Uint8Array,
    proofSpec: Uint8Array,
    nonce?: Uint8Array
): Required<VerifyResult>;

export function verifyCompositeProofG2(
    proof: Uint8Array,
    proofSpec: Uint8Array,
    nonce?: Uint8Array
): Required<VerifyResult>;

export function generateCompositeProofG1WithDeconstructedProofSpec(
    statements: Uint8Array[],
    metaStatements: Uint8Array[],
    witnesses: Uint8Array[],
    context?: Uint8Array,
    nonce?: Uint8Array
): Uint8Array;

export function verifyCompositeProofG1WithDeconstructedProofSpec(
    proof: Uint8Array,
    statements: Uint8Array[],
    metaStatements: Uint8Array[],
    context?: Uint8Array,
    nonce?: Uint8Array
): Required<VerifyResult>;

export function saverGetCiphertextFromProof(
    proof: Uint8Array,
    statementIndex: number
): Uint8Array;

