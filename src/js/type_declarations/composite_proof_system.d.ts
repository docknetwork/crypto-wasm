import {BbsPlusSigParams, INonMembershipWitness, VerifyResult, Constraint, PSSigParams, BbsSigParams, Bddt16MacParams} from "../types";

export function generatePoKBBSSignatureProverStatement(
    params: BbsSigParams,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
): Uint8Array;

export function generatePoKBBSSignatureVerifierStatement(
    params: BbsSigParams,
    publicKey: Uint8Array,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
): Uint8Array;

export function generatePoKBBSPlusSignatureProverStatement(
    params: BbsPlusSigParams,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
): Uint8Array;

export function generatePoKBBSPlusSignatureVerifierStatement(
    params: BbsPlusSigParams,
    publicKey: Uint8Array,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
): Uint8Array;

export function generatePoKBBSSignatureProverStatementFromParamRefs(
    params: number,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
): Uint8Array;

export function generatePoKBBSSignatureVerifierStatementFromParamRefs(
    params: number,
    publicKey: number,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
): Uint8Array;

export function generatePoKBBSPlusSignatureProverStatementFromParamRefs(
    params: number,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
): Uint8Array;

export function generatePoKBBSPlusSignatureVerifierStatementFromParamRefs(
    params: number,
    publicKey: number,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
): Uint8Array;

export function generatePoKPSSignatureStatement(
    params: PSSigParams,
    publicKey: Uint8Array,
    revealedMessages: Map<number, Uint8Array>
): Uint8Array;

export function generatePoKPSSignatureStatementFromParamRefs(
    params: number,
    publicKey: number,
    revealedMessages: Map<number, Uint8Array>
): Uint8Array;

export function generateAccumulatorMembershipStatement(
    params: Uint8Array,
    publicKey: Uint8Array,
    provingKey: Uint8Array,
    accumulated: Uint8Array
): Uint8Array;

export function generateAccumulatorMembershipStatementFromParamRefs(
    params: number,
    publicKey: number,
    provingKey: number,
    accumulated: Uint8Array
): Uint8Array;

export function generateAccumulatorNonMembershipStatement(
    params: Uint8Array,
    publicKey: Uint8Array,
    provingKey: Uint8Array,
    accumulated: Uint8Array
): Uint8Array;

export function generateAccumulatorNonMembershipStatementFromParamRefs(
    params: number,
    publicKey: number,
    provingKey: number,
    accumulated: Uint8Array
): Uint8Array;

export function generatePedersenCommitmentG1Statement(
    bases: Uint8Array[],
    commitment: Uint8Array
): Uint8Array;

export function generatePedersenCommitmentG1StatementFromParamRefs(
    bases: number,
    commitment: Uint8Array
): Uint8Array;

export function generatePedersenCommitmentG2Statement(
    bases: Uint8Array[],
    commitment: Uint8Array
): Uint8Array;

export function generatePedersenCommitmentG2StatementFromParamRefs(
    bases: number,
    commitment: Uint8Array
): Uint8Array;

export function generateSaverProverStatement(
    chunkBitSize: number,
    encGens: Uint8Array,
    commGens: Uint8Array,
    encryptionKey: Uint8Array,
    snarkPk: Uint8Array,
    uncompressedPublicParams: boolean
): Uint8Array;

export function generateSaverProverStatementFromParamRefs(
    chunkBitSize: number,
    encGens: number,
    commGens: number,
    encryptionKey: number,
    snarkPk: number
): Uint8Array;

export function generateSaverVerifierStatement(
    chunkBitSize: number,
    encGens: Uint8Array,
    commGens: Uint8Array,
    encryptionKey: Uint8Array,
    snarkVk: Uint8Array,
    uncompressedPublicParams: boolean
): Uint8Array;

export function generateSaverVerifierStatementFromParamRefs(
    chunkBitSize: number,
    encGens: number,
    commGens: number,
    encryptionKey: number,
    snarkVk: number
): Uint8Array;

export function generateBoundCheckLegoProverStatement(
    min: number,
    max: number,
    snarkPk: Uint8Array,
    uncompressedPublicParams: boolean
): Uint8Array;

export function generateBoundCheckLegoProverStatementFromParamRefs(
    min: number,
    max: number,
    snarkPk: number
): Uint8Array;

export function generateBoundCheckLegoVerifierStatement(
    min: number,
    max: number,
    snarkVk: Uint8Array,
    uncompressedPublicParams: boolean
): Uint8Array;

export function generateBoundCheckLegoVerifierStatementFromParamRefs(
    min: number,
    max: number,
    snarkVk: number
): Uint8Array;

export function generateR1CSCircomProverStatement(
    curveName: string,
    numPublic: number,
    numPrivate: number,
    constraints: Constraint[],
    wasmBytes: Uint8Array,
    snarkPk: Uint8Array,
    uncompressedPublicParams: boolean
): Uint8Array;

export function generateR1CSCircomProverStatementFromParamRefs(
    r1cs: number,
    wasmBytes: number,
    snarkPk: number,
): Uint8Array;

export function generateR1CSCircomVerifierStatement(
    publicInputs: Uint8Array[],
    snarkVk: Uint8Array,
    uncompressedPublicParams: boolean
): Uint8Array;

export function generateR1CSCircomVerifierStatementFromParamRefs(
    publicInputs: number,
    snarkVk: number,
): Uint8Array;

export function generateBoundCheckBppStatement(
    min: number,
    max: number,
    params: Uint8Array,
    uncompressedPublicParams: boolean
): Uint8Array;

export function generateBoundCheckBppStatementFromParamRefs(
    min: number,
    max: number,
    params: number
): Uint8Array;

export function generateBoundCheckSmcStatement(
    min: number,
    max: number,
    params: Uint8Array,
    uncompressedParams: boolean
): Uint8Array;

export function generateBoundCheckSmcStatementFromParamRefs(
    min: number,
    max: number,
    params: number,
): Uint8Array;

export function generateBoundCheckSmcWithKVProverStatement(
    min: number,
    max: number,
    params: Uint8Array,
    uncompressedParams: boolean
): Uint8Array;

export function generateBoundCheckSmcWithKVProverStatementFromParamRefs(
    min: number,
    max: number,
    params: number,
): Uint8Array;

export function generateBoundCheckSmcWithKVVerifierStatement(
    min: number,
    max: number,
    params: Uint8Array,
    uncompressedParams: boolean
): Uint8Array;

export function generateBoundCheckSmcWithKVVerifierStatementFromParamRefs(
    min: number,
    max: number,
    params: number,
): Uint8Array;

export function generatePublicInequalityG1Statement(
    inequalTo: Uint8Array,
    commKey: Uint8Array,
    uncompressedKey: boolean
): Uint8Array;

export function generatePublicInequalityG1StatementFromParamRefs(
    inequalTo: Uint8Array,
    commKey: number,
): Uint8Array;

export function generateWitnessEqualityMetaStatement(
    equalities: Set<[number, number]>,
): Uint8Array;

export function generatePoKBBSSignatureWitness(
    signature: Uint8Array,
    unrevealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
): Uint8Array;

export function generatePoKBBSPlusSignatureWitness(
    signature: Uint8Array,
    unrevealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
): Uint8Array;

export function generatePoKPSSignatureWitness(
    signature: Uint8Array,
    unrevealedMessages: Map<number, Uint8Array>
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

export function generateR1CSCircomWitness(
    inputWires: Map<string, Uint8Array[]>,
    privates: string[],
    publics?: string[],
): Uint8Array;

export function generateBoundCheckBppWitness(
    message: Uint8Array
): Uint8Array;

export function generateBoundCheckSmcWitness(
    message: Uint8Array
): Uint8Array;

export function generateBoundCheckSmcWithKVWitness(
    message: Uint8Array
): Uint8Array;

export function generatePublicInequalityWitness(
    message: Uint8Array
): Uint8Array;

export function generateProofSpecG1(
    statements: Uint8Array[],
    metaStatements: Uint8Array[],
    setupParams: Uint8Array[],
    context?: Uint8Array
): Uint8Array;

export function isProofSpecG1Valid(
    proofSpec: Uint8Array
): boolean;

export function generateCompositeProofG1(
    proofSpec: Uint8Array,
    witnesses: Uint8Array[],
    nonce?: Uint8Array
): Uint8Array;

export function verifyCompositeProofG1(
    proof: Uint8Array,
    proofSpec: Uint8Array,
    nonce?: Uint8Array
): Required<VerifyResult>;

export function generateCompositeProofG1WithDeconstructedProofSpec(
    statements: Uint8Array[],
    metaStatements: Uint8Array[],
    setupParams: Uint8Array[],
    witnesses: Uint8Array[],
    context?: Uint8Array,
    nonce?: Uint8Array
): Uint8Array;

export function verifyCompositeProofG1WithDeconstructedProofSpec(
    proof: Uint8Array,
    statements: Uint8Array[],
    metaStatements: Uint8Array[],
    setupParams: Uint8Array[],
    context?: Uint8Array,
    nonce?: Uint8Array
): Required<VerifyResult>;

export function saverGetCiphertextFromProof(
    proof: Uint8Array,
    statementIndex: number
): Uint8Array;

export function saverGetCiphertextsFromProof(
    proof: Uint8Array,
    statementIndices: number[]
): Uint8Array[];

export function generatePoKBDDT16MacStatement(
    params: Bddt16MacParams,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
): Uint8Array;

export function generatePoKBDDT16MacStatementFromParamRefs(
    params: number,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
): Uint8Array;

export function generatePoKBDDT16MacFullVerifierStatement(
    params: Bddt16MacParams,
    secretKey: Uint8Array,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
): Uint8Array;

export function generatePoKBDDT16MacFullVerifierStatementFromParamRefs(
    params: number,
    secretKey: Uint8Array,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
): Uint8Array;

export function generatePoKBDDT16MacWitness(
    mac: Uint8Array,
    unrevealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
): Uint8Array;

export function generateAccumulatorKVMembershipStatement(
    accumulated: Uint8Array
): Uint8Array;

export function generateAccumulatorKVFullVerifierMembershipStatement(
    secretKey: Uint8Array,
    accumulated: Uint8Array
): Uint8Array;
