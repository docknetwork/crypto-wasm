import {PSPoKSigProtocol, PSSigParams, IKeypair, VerifyResult, CommitmentOrMessage} from "../types";
import { CommitMessage } from "../types/CommitMessage";

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
    messages: Iterable<CommitmentOrMessage>,
    secret_key: Uint8Array,
    h: Uint8Array
): Uint8Array;

export function psUnblindSignature(
    blind_signature: Uint8Array,
    indexed_blindings: Map<number, Uint8Array>,
    pk: Uint8Array,
): Uint8Array;

export function psInitializeProofOfKnowledgeOfSignature(
    signature: Uint8Array,
    params: PSSigParams,
    public_key: Uint8Array,
    messages: Iterable<CommitMessage>
): PSPoKSigProtocol;

export function psGenProofOfKnowledgeOfSignature(
    protocol: PSPoKSigProtocol,
    challenge: Uint8Array
): Uint8Array;

export function psVerifyProofOfKnowledgeOfSignature(
    proof: Uint8Array,
    revealedMessages: Map<number, Uint8Array>,
    challenge: Uint8Array,
    publicKey: Uint8Array,
    params: PSSigParams
): Required<VerifyResult>;

export function psChallengeContributionFromProtocol(
    protocol: PSPoKSigProtocol,
    publicKey: Uint8Array,
    params: PSSigParams
): Uint8Array;

export function psChallengeContributionFromProof(
    proof: Uint8Array,
    publicKey: Uint8Array,
    params: PSSigParams,
): Uint8Array;

export function psAdaptSignatureParamsForMsgCount(
    params: PSSigParams,
    generating_label: Uint8Array,
    new_count: number
): PSSigParams;
