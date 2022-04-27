import {BbsPoKSigProtocol, BbsSigParams, IKeypair, VerifyResult} from "../types";

export const BBS_SIGNATURE_LENGTH = 112;

export const DEFAULT_BLS12381_PRIVATE_KEY_LENGTH = 32;

export const DEFAULT_BLS12381_G1_PUBLIC_KEY_LENGTH = 48;

export const DEFAULT_BLS12381_G2_PUBLIC_KEY_LENGTH = 96;

export function generateBBSSigningKey(seed?: Uint8Array): Uint8Array;

export function generateSignatureParamsG1(
    messageCount: number,
    label?: Uint8Array
): Required<BbsSigParams>;

export function isSignatureParamsG1Valid(
    params: BbsSigParams
): boolean;

export function bbsSignatureParamsG1MaxSupportedMsgs(
    params: BbsSigParams
): number;

export function generateSignatureParamsG2(
    messageCount: number,
    label?: Uint8Array
): Required<BbsSigParams>;

export function isSignatureParamsG2Valid(
    params: BbsSigParams
): boolean;

export function bbsSignatureParamsG2MaxSupportedMsgs(
    params: BbsSigParams
): number;

export function bbsSignatureParamsG1ToBytes(
    params: BbsSigParams
): Uint8Array;

export function bbsSignatureParamsG1FromBytes(
    bytes: Uint8Array
): BbsSigParams;

export function bbsSignatureParamsG2ToBytes(
    params: BbsSigParams
): Uint8Array;

export function bbsSignatureParamsG2FromBytes(
    bytes: Uint8Array
): BbsSigParams;

export function generateBBSPublicKeyG1(
    secretKey: Uint8Array,
    params: BbsSigParams
): Uint8Array;

export function isBBSPublicKeyG1Valid(
    publicKey: Uint8Array
): boolean;

export function generateBBSPublicKeyG2(
    secretKey: Uint8Array,
    params: BbsSigParams
): Uint8Array;

export function isBBSPublicKeyG2Valid(
    publicKey: Uint8Array
): boolean;

export function generateBBSKeyPairG1(
    params: BbsSigParams,
    seed?: Uint8Array
): Required<IKeypair>;

export function generateBBSKeyPairG2(
    params: BbsSigParams,
    seed?: Uint8Array
): Required<IKeypair>;

export function bbsEncodeMessageForSigning(
    message: Uint8Array
): Uint8Array;

export function bbsEncodeMessagesForSigning(
    messages: Uint8Array[],
    indicesToEncode: number[]
): Uint8Array[];

export function bbsGetBasesForCommitmentG1(
    params: BbsSigParams,
    indicesToCommit: number[]
): Uint8Array[];

export function bbsGetBasesForCommitmentG2(
    params: BbsSigParams,
    indicesToCommit: number[]
): Uint8Array[];

export function bbsSignG1(
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

export function bbsVerifyG1(
    messages: Uint8Array[],
    signature: Uint8Array,
    publicKey: Uint8Array,
    params: BbsSigParams,
    encodeMessages: boolean
): Required<VerifyResult>;

export function bbsVerifyG2(
    messages: Uint8Array[],
    signature: Uint8Array,
    publicKey: Uint8Array,
    params: BbsSigParams,
    encodeMessages: boolean
): Required<VerifyResult>;

export function bbsCommitMsgsInG1(
    messages: Map<number, Uint8Array>,
    blinding: Uint8Array,
    params: BbsSigParams,
    encodeMessages: boolean
): Uint8Array;

export function bbsCommitMsgsInG2(
    messages: Map<number, Uint8Array>,
    blinding: Uint8Array,
    params: BbsSigParams,
    encodeMessages: boolean
): Uint8Array;

export function bbsBlindSignG1(
    commitment: Uint8Array,
    uncommittedMessages: Map<number, Uint8Array>,
    secretKey: Uint8Array,
    params: BbsSigParams,
    encodeMessages: boolean
): Uint8Array;

export function bbsBlindSignG2(
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

export function bbsAdaptSigParamsG1ForMsgCount(
    params: BbsSigParams,
    generating_label: Uint8Array,
    new_count: number
): BbsSigParams;

export function bbsAdaptSigParamsG2ForMsgCount(
    params: BbsSigParams,
    generating_label: Uint8Array,
    new_count: number
): BbsSigParams;
