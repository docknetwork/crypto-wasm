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

export function psPublicKeyMaxSupportedMsgs(
    publicKey: Uint8Array
): number;

export function psSigningKeyMaxSupportedMsgs(
    signingKey: Uint8Array
): number;

export function psSignatureParamsToBytes(
    params: PSSigParams
): Uint8Array;

export function psSignatureParamsFromBytes(
    bytes: Uint8Array
): PSSigParams;

export function psShamirDeal(
    message_count: number,
    threshold: number,
    total: number,
): [Uint8Array, Uint8Array[]];

export function psAggregateSignatures(
    participantSignatures: Map<number, Uint8Array>,
    h: Uint8Array
): PSSig;

export function psGeneratePublicKey(
    secretKey: Uint8Array,
    params: PSSigParams
): Uint8Array;

export function psAdaptSecretKeyForMoreMessages(
    secretKey: Uint8Array,
    seed: Uint8Array,
    messageCount: number
): Uint8Array | null;

export function psAdaptSecretKeyForLessMessages(
    secretKey: Uint8Array,
    messageCount: number
): Uint8Array | null;

export function psAdaptPublicKeyForLessMessages(
    publicKey: Uint8Array,
    messageCount: number
): Uint8Array | null;

export function psAdaptSecretKeyForMoreMessages(
    secretKey: Uint8Array,
    messageCount: number
): Uint8Array | null;

export function psIsPublicKeyValid(
    publicKey: Uint8Array
): boolean;

export function psIsPublicKeyValid(
    publicKey: Uint8Array
): boolean;

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
    h: Uint8Array
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
    h: Uint8Array
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
    h: Uint8Array
): Uint8Array;

export function psChallengeMessagesPoKContributionFromProof(
    proof: Uint8Array,
    params: PSSigParams,
    h: Uint8Array
): Uint8Array;

export function psBlindMessageRandomly(
    message: Uint8Array
): PSCommitMessage;

export function psRevealMessage(
    message: Uint8Array
): PSCommitMessage;

export function psBlindMessageWithConcreteBlinding(
    message: Uint8Array,
    blinding: Uint8Array
): PSCommitMessage;

export function psBlindedMessage(
    commitment: Uint8Array
): PSCommitmentOrMessage;

export function psRevealedMessage(
    message: Uint8Array
): PSCommitmentOrMessage;

export function psAdaptSignatureParamsForMsgCount(
    params: PSSigParams,
    generating_label: Uint8Array,
    new_count: number
): PSSigParams;
