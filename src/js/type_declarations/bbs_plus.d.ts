import {BbsPlusPoKSigProtocol, BbsPlusSigParams, IKeypair, VerifyResult} from "../types";

export const DEFAULT_BLS12381_PRIVATE_KEY_LENGTH = 32;

export const DEFAULT_BLS12381_BBS_PLUS_G1_PUBLIC_KEY_LENGTH = 48;

export const DEFAULT_BLS12381_BBS_PLUS_G2_PUBLIC_KEY_LENGTH = 96;

export function bbsPlusGenerateSigningKey(seed?: Uint8Array): Uint8Array;

export function bbsPlusGenerateSignatureParamsG1(
    messageCount: number,
    label?: Uint8Array
): Required<BbsPlusSigParams>;

export function bbsPlusIsSignatureParamsG1Valid(
    params: BbsPlusSigParams
): boolean;

export function bbsPlusSignatureParamsG1MaxSupportedMsgs(
    params: BbsPlusSigParams
): number;

export function bbsPlusGenerateSignatureParamsG2(
    messageCount: number,
    label?: Uint8Array
): Required<BbsPlusSigParams>;

export function bbsPlusIsSignatureParamsG2Valid(
    params: BbsPlusSigParams
): boolean;

export function bbsPlusSignatureParamsG2MaxSupportedMsgs(
    params: BbsPlusSigParams
): number;

export function bbsPlusSignatureParamsG1ToBytes(
    params: BbsPlusSigParams
): Uint8Array;

export function bbsPlusSignatureParamsG1FromBytes(
    bytes: Uint8Array
): BbsPlusSigParams;

export function bbsPlusSignatureParamsG2ToBytes(
    params: BbsPlusSigParams
): Uint8Array;

export function bbsPlusSignatureParamsG2FromBytes(
    bytes: Uint8Array
): BbsPlusSigParams;

export function bbsPlusGeneratePublicKeyG1(
    secretKey: Uint8Array,
    params: BbsPlusSigParams
): Uint8Array;

export function bbsPlusIsPublicKeyG1Valid(
    publicKey: Uint8Array
): boolean;

export function bbsPlusGeneratePublicKeyG2(
    secretKey: Uint8Array,
    params: BbsPlusSigParams
): Uint8Array;

export function bbsPlusIsPublicKeyG2Valid(
    publicKey: Uint8Array
): boolean;

export function bbsPlusGenerateKeyPairG1(
    params: BbsPlusSigParams,
    seed?: Uint8Array
): Required<IKeypair>;

export function bbsPlusGenerateKeyPairG2(
    params: BbsPlusSigParams,
    seed?: Uint8Array
): Required<IKeypair>;

export function bbsPlusGetBasesForCommitmentG1(
    params: BbsPlusSigParams,
    indicesToCommit: number[]
): Uint8Array[];

export function bbsPlusGetBasesForCommitmentG2(
    params: BbsPlusSigParams,
    indicesToCommit: number[]
): Uint8Array[];

export function bbsPlusSignG1(
    messages: Uint8Array[],
    secretKey: Uint8Array,
    params: BbsPlusSigParams,
    encodeMessages: boolean
): Uint8Array;

export function bbsPlusSignG2(
    messages: Uint8Array[],
    secretKey: Uint8Array,
    params: BbsPlusSigParams,
    encodeMessages: boolean
): Uint8Array;

export function bbsPlusVerifyG1(
    messages: Uint8Array[],
    signature: Uint8Array,
    publicKey: Uint8Array,
    params: BbsPlusSigParams,
    encodeMessages: boolean
): Required<VerifyResult>;

export function bbsPlusVerifyG2(
    messages: Uint8Array[],
    signature: Uint8Array,
    publicKey: Uint8Array,
    params: BbsPlusSigParams,
    encodeMessages: boolean
): Required<VerifyResult>;

export function bbsPlusCommitMsgsInG1(
    messages: Map<number, Uint8Array>,
    blinding: Uint8Array,
    params: BbsPlusSigParams,
    encodeMessages: boolean
): Uint8Array;

export function bbsPlusCommitMsgsInG2(
    messages: Map<number, Uint8Array>,
    blinding: Uint8Array,
    params: BbsPlusSigParams,
    encodeMessages: boolean
): Uint8Array;

export function bbsPlusBlindSignG1(
    commitment: Uint8Array,
    uncommittedMessages: Map<number, Uint8Array>,
    secretKey: Uint8Array,
    params: BbsPlusSigParams,
    encodeMessages: boolean
): Uint8Array;

export function bbsPlusBlindSignG2(
    commitment: Uint8Array,
    uncommittedMessages: Map<number, Uint8Array>,
    secretKey: Uint8Array,
    params: BbsPlusSigParams,
    encodeMessages: boolean
): Uint8Array;

export function bbsPlusUnblindSigG1(
    signature: Uint8Array,
    blinding: Uint8Array,
): Uint8Array;

export function bbsPlusUnblindSigG2(
    signature: Uint8Array,
    blinding: Uint8Array,
): Uint8Array;

export function bbsPlusInitializeProofOfKnowledgeOfSignature(
    signature: Uint8Array,
    params: BbsPlusSigParams,
    messages: Uint8Array[],
    blindings: Map<number, Uint8Array>,
    revealedIndices: Set<number>,
    encodeMessages: boolean
): BbsPlusPoKSigProtocol;

export function bbsPlusGenProofOfKnowledgeOfSignature(
    protocol: BbsPlusPoKSigProtocol,
    challenge: Uint8Array
): Uint8Array;

export function bbsPlusVerifyProofOfKnowledgeOfSignature(
    proof: Uint8Array,
    revealedMessages: Map<number, Uint8Array>,
    challenge: Uint8Array,
    publicKey: Uint8Array,
    params: BbsPlusSigParams,
    encodeMessages: boolean
): Required<VerifyResult>;

export function bbsPlusChallengeContributionFromProtocol(
    protocol: BbsPlusPoKSigProtocol,
    revealedMessages: Map<number, Uint8Array>,
    params: BbsPlusSigParams,
    encodeMessages: boolean
): Uint8Array;

export function bbsPlusChallengeContributionFromProof(
    proof: Uint8Array,
    revealedMessages: Map<number, Uint8Array>,
    params: BbsPlusSigParams,
    encodeMessages: boolean
): Uint8Array;

export function bbsPlusAdaptSigParamsG1ForMsgCount(
    params: BbsPlusSigParams,
    generating_label: Uint8Array,
    new_count: number
): BbsPlusSigParams;

export function bbsPlusAdaptSigParamsG2ForMsgCount(
    params: BbsPlusSigParams,
    generating_label: Uint8Array,
    new_count: number
): BbsPlusSigParams;
