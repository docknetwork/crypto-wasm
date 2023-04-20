import {PSPoKSigProtocol, PSSigParams, IKeypair, VerifyResult, PSCommitmentOrMessage, PSSig} from "../types";
import { PSCommitMessage } from "../types/PSCommitMessage";

export const PS_SIGNATURE_LENGTH = 112;

export function psGenerateSigningKey(message_count: number, seed?: Uint8Array): Uint8Array;

export function psIsSignatureParamsValid(
    params: PSSigParams
): boolean;

export function psSignatureParamsMaxSupportedMsgs(
    params: PSSigParams
): number;

export function psGenerateSignatureParams(
    messageCount: number,
    label?: Uint8Array
): Required<PSSigParams>;

export function psSignatureParamsMaxSupportedMsgs(
    params: PSSigParams
): number;

export function psSignatureParamsToBytes(
    params: PSSigParams
): Uint8Array;

export function psSignatureParamsFromBytes(
    bytes: Uint8Array
): PSSigParams;

export function psGeneratePublicKey(
    secretKey: Uint8Array,
    params: PSSigParams
): Uint8Array;

export function psIsPublicKeyValid(
    publicKey: Uint8Array
): boolean;

export function psIsPublicKeyValid(
    publicKey: Uint8Array
): boolean;

export function psEncodeMessageForSigning(
    message: Uint8Array
): Uint8Array;

export function psEncodeMessagesForSigning(
    messages: Uint8Array[],
    indicesToEncode: number[]
): Uint8Array[];

export function psGetBasesForCommitment(
    params: PSSigParams,
    indicesToCommit: number[]
): Uint8Array[];

export function psSign(
    messages: Uint8Array[],
    secretKey: Uint8Array,
    params: PSSigParams
): Uint8Array;

export function psVerify(
    messages: Uint8Array[],
    signature: Uint8Array,
    publicKey: Uint8Array,
    params: PSSigParams
): Required<VerifyResult>;

export function psMessageCommitment(
    blinding: Uint8Array,
    message: Uint8Array,
    h: Uint8Array,
    params: PSSigParams,
): Uint8Array;

export function psBlindSign(
    messages: Iterable<PSCommitmentOrMessage>,
    secret_key: Uint8Array,
    h: Uint8Array
): Uint8Array;

export function psUnblindSignature(
    blind_signature: Uint8Array,
    indexed_blindings: Map<number, Uint8Array>,
    pk: Uint8Array,
): Uint8Array;

export function psInitializeSignaturePoK(
    signature: Uint8Array,
    params: PSSigParams,
    public_key: Uint8Array,
    messages: Iterable<PSCommitMessage>
): PSPoKSigProtocol;

export function psInitializeMessagesPoK(
    messages: Iterable<PSCommitMessage>,
    params: PSSigParams,
    h: Object
): PSPoKSigProtocol;

export function psGenSignaturePoK(
    protocol: PSPoKSigProtocol,
    challenge: Uint8Array
): Uint8Array;

export function psGenMessagesPoK(
    protocol: PSPoKSigProtocol,
    challenge: Uint8Array
): Uint8Array;

export function psVerifySignaturePoK(
    proof: Uint8Array,
    revealedMessages: Map<number, Uint8Array>,
    challenge: Uint8Array,
    publicKey: Uint8Array,
    params: PSSigParams
): Required<VerifyResult>;

export function psVerifyMessagesPoK(
    proof: Uint8Array,
    revealedIndices: Set<number>,
    challenge: Uint8Array,
    params: PSSigParams,
    h: Object
): Required<VerifyResult>;

export function psChallengeSignaturePoKContributionFromProtocol(
    protocol: PSPoKSigProtocol,
    publicKey: Uint8Array,
    params: PSSigParams
): Uint8Array;

export function psChallengeSignaturePoKContributionFromProof(
    proof: Uint8Array,
    publicKey: Uint8Array,
    params: PSSigParams,
): Uint8Array;

export function psChallengeMessagesPoKContributionFromProtocol(
    protocol: PSPoKSigProtocol,
    params: PSSigParams,
    h: Object
): Uint8Array;

export function psChallengeMessagesPoKContributionFromProof(
    proof: Uint8Array,
    params: PSSigParams,
    h: Object
): Uint8Array;

export function psAdaptSignatureParamsForMsgCount(
    params: PSSigParams,
    generating_label: Uint8Array,
    new_count: number
): PSSigParams;
