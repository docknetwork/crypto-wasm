import {Bddt16MacParams, VerifyResult} from "../types";
import {bbsPlusChallengeContributionFromProofConstantTime} from "./bbs_plus";

export function bddt16MacGenerateSecretKey(seed?: Uint8Array): Uint8Array;

export function bddt16GenerateMacParams(
    messageCount: number,
    label?: Uint8Array
): Required<Bddt16MacParams>;

export function bddt16IsMacParamsValid(
    params: Bddt16MacParams
): boolean;

export function bddt16MacParamsMaxSupportedMsgs(
    params: Bddt16MacParams
): number;

export function bddt16MacParamsToBytes(
    params: Bddt16MacParams
): Uint8Array;

export function bddt16MacParamsFromBytes(
    bytes: Uint8Array
): Bddt16MacParams;

export function bddt16MacAdaptParamsForMsgCount(
    params: Bddt16MacParams,
    generating_label: Uint8Array,
    new_count: number
): Bddt16MacParams;

export function bddt16MacGeneratePublicKeyG1(secretKey: Uint8Array, params: Bddt16MacParams): Uint8Array;

export function bddt16MacIsPublicKeyG1Valid(publicKey: Uint8Array): boolean;

export function bddt16MacGetBasesForCommitment(
    params: Bddt16MacParams,
    indicesToCommit: number[]
): Uint8Array[];

export function bddt16MacGenerate(
    messages: Uint8Array[],
    secretKey: Uint8Array,
    params: Bddt16MacParams,
    encodeMessages: boolean
): Uint8Array;

export function bddt16MacGenerateConstantTime(
    messages: Uint8Array[],
    secretKey: Uint8Array,
    params: Bddt16MacParams,
    encodeMessages: boolean
): Uint8Array;

export function bddt16MacVerify(
    messages: Uint8Array[],
    mac: Uint8Array,
    secretKey: Uint8Array,
    params: Bddt16MacParams,
    encodeMessages: boolean
): Required<VerifyResult>;

export function bddt16MacVerifyConstantTime(
    messages: Uint8Array[],
    mac: Uint8Array,
    secretKey: Uint8Array,
    params: Bddt16MacParams,
    encodeMessages: boolean
): Required<VerifyResult>;

export function bddt16MacProofOfValidity(
    mac: Uint8Array,
    secretKey: Uint8Array,
    publicKey: Uint8Array,
    params: Bddt16MacParams,
): Uint8Array;

export function bddt16MacVerifyProofOfValidity(
    proof: Uint8Array,
    mac: Uint8Array,
    messages: Uint8Array[],
    publicKey: Uint8Array,
    params: Bddt16MacParams,
    encodeMessages: boolean
): Required<VerifyResult>;

export function bddt16MacCommitMsgs(
    messages: Map<number, Uint8Array>,
    blinding: Uint8Array,
    params: Bddt16MacParams,
    encodeMessages: boolean
): Uint8Array;

export function bddt16MacCommitMsgsConstantTime(
    messages: Map<number, Uint8Array>,
    blinding: Uint8Array,
    params: Bddt16MacParams,
    encodeMessages: boolean
): Uint8Array;

export function bddt16BlindMacGenerate(
    commitment: Uint8Array,
    uncommittedMessages: Map<number, Uint8Array>,
    secretKey: Uint8Array,
    params: Bddt16MacParams,
    encodeMessages: boolean
): Uint8Array;

export function bddt16BlindMacGenerateConstantTime(
    commitment: Uint8Array,
    uncommittedMessages: Map<number, Uint8Array>,
    secretKey: Uint8Array,
    params: Bddt16MacParams,
    encodeMessages: boolean
): Uint8Array;

export function bddt16UnblindMac(
    mac: Uint8Array,
    blinding: Uint8Array,
): Uint8Array;
