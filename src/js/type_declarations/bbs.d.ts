import {BbsPoKSigProtocol, BbsSigParams, IKeypair, VerifyResult} from "../types";

export const DEFAULT_BLS12381_PRIVATE_KEY_LENGTH = 32;

export const DEFAULT_BLS12381_G1_PUBLIC_KEY_LENGTH = 48;

export const DEFAULT_BLS12381_G2_PUBLIC_KEY_LENGTH = 96;

export function bbsGenerateSigningKey(seed?: Uint8Array): Uint8Array;

export function bbsGenerateSignatureParams(
    messageCount: number,
    label?: Uint8Array
): Required<BbsSigParams>;

export function bbsIsSignatureParamsValid(
    params: BbsSigParams
): boolean;

export function bbsSignatureParamsMaxSupportedMsgs(
    params: BbsSigParams
): number;

export function bbsGenerateSignatureParamsG2(
    messageCount: number,
    label?: Uint8Array
): Required<BbsSigParams>;

export function bbsIsSignatureParamsG2Valid(
    params: BbsSigParams
): boolean;

export function bbsSignatureParamsG2MaxSupportedMsgs(
    params: BbsSigParams
): number;

export function bbsSignatureParamsToBytes(
    params: BbsSigParams
): Uint8Array;

export function bbsSignatureParamsFromBytes(
    bytes: Uint8Array
): BbsSigParams;

export function bbsSignatureParamsG2ToBytes(
    params: BbsSigParams
): Uint8Array;

export function bbsSignatureParamsG2FromBytes(
    bytes: Uint8Array
): BbsSigParams;

export function bbsGeneratePublicKeyG1(
    secretKey: Uint8Array,
    params: BbsSigParams
): Uint8Array;

export function bbsIsPublicKeyG1Valid(
    publicKey: Uint8Array
): boolean;

export function bbsGeneratePublicKey(
    secretKey: Uint8Array,
    params: BbsSigParams
): Uint8Array;

export function bbsIsPublicKeyValid(
    publicKey: Uint8Array
): boolean;

export function bbsGenerateKeyPair(
    params: BbsSigParams,
    seed?: Uint8Array
): Required<IKeypair>;

export function bbsGetBasesForCommitmentG1(
    params: BbsSigParams,
    indicesToCommit: number[]
): Uint8Array[];

export function bbsGetBasesForCommitmentG2(
    params: BbsSigParams,
    indicesToCommit: number[]
): Uint8Array[];

export function bbsSign(
    messages: Uint8Array[],
    secretKey: Uint8Array,
    params: BbsSigParams,
    encodeMessages: boolean
): Uint8Array;

export function bbsSignG2(
    messages: Uint8Array[],
    secretKey: Uint8Array,
    params: BbsSigParams,
    encodeMessages: boolean
): Uint8Array;

export function bbsVerify(
    messages: Uint8Array[],
    signature: Uint8Array,
    publicKey: Uint8Array,
    params: BbsSigParams,
    encodeMessages: boolean
): Required<VerifyResult>;

export function bbsCommitMsgs(
    messages: Map<number, Uint8Array>,
    params: BbsSigParams,
    encodeMessages: boolean
): Uint8Array;

export function bbsBlindSign(
    commitment: Uint8Array,
    uncommittedMessages: Map<number, Uint8Array>,
    secretKey: Uint8Array,
    params: BbsSigParams,
    encodeMessages: boolean
): Uint8Array;

export function bbsUnblindSigG1(
    signature: Uint8Array,
    blinding: Uint8Array,
): Uint8Array;

export function bbsUnblindSigG2(
    signature: Uint8Array,
    blinding: Uint8Array,
): Uint8Array;

export function bbsInitializeProofOfKnowledgeOfSignature(
    signature: Uint8Array,
    params: BbsSigParams,
    messages: Uint8Array[],
    blindings: Map<number, Uint8Array>,
    revealedIndices: Set<number>,
    encodeMessages: boolean
): BbsPoKSigProtocol;

export function bbsGenProofOfKnowledgeOfSignature(
    protocol: BbsPoKSigProtocol,
    challenge: Uint8Array
): Uint8Array;

export function bbsVerifyProofOfKnowledgeOfSignature(
    proof: Uint8Array,
    revealedMessages: Map<number, Uint8Array>,
    challenge: Uint8Array,
    publicKey: Uint8Array,
    params: BbsSigParams,
    encodeMessages: boolean
): Required<VerifyResult>;

export function bbsChallengeContributionFromProtocol(
    protocol: BbsPoKSigProtocol,
    revealedMessages: Map<number, Uint8Array>,
    params: BbsSigParams,
    encodeMessages: boolean
): Uint8Array;

export function bbsChallengeContributionFromProof(
    proof: Uint8Array,
    revealedMessages: Map<number, Uint8Array>,
    params: BbsSigParams,
    encodeMessages: boolean
): Uint8Array;

export function bbsAdaptSigParamsForMsgCount(
    params: BbsSigParams,
    generating_label: Uint8Array,
    new_count: number
): BbsSigParams;

export function bbsAdaptSigParamsG2ForMsgCount(
    params: BbsSigParams,
    generating_label: Uint8Array,
    new_count: number
): BbsSigParams;