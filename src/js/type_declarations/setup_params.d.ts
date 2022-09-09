import {BbsSigParams, Constraint} from "../types";

export function generateSetupParamForBBSSignatureParametersG1(
    params: BbsSigParams
): Uint8Array;

export function generateSetupParamForBBSPublicKeyG2(
    publicKey: Uint8Array
): Uint8Array;

export function generateSetupParamForVbAccumulatorParams(
    params: Uint8Array
): Uint8Array;

export function generateSetupParamForVbAccumulatorPublicKey(
    publicKey: Uint8Array
): Uint8Array;

export function generateSetupParamForVbAccumulatorMemProvingKey(
    provingKey: Uint8Array
): Uint8Array;

export function generateSetupParamForVbAccumulatorNonMemProvingKey(
    provingKey: Uint8Array
): Uint8Array;

export function generateSetupParamForPedersenCommitmentKeyG1(
    commitmentKey: Uint8Array[]
): Uint8Array;

export function generateSetupParamForPedersenCommitmentKeyG2(
    commitmentKey: Uint8Array[]
): Uint8Array;

export function generateSetupParamForSaverEncryptionGens(
    encGens: Uint8Array,
    uncompressed: boolean
): Uint8Array;

export function generateSetupParamForSaverCommitmentGens(
    commGens: Uint8Array,
    uncompressed: boolean
): Uint8Array;

export function generateSetupParamForSaverEncryptionKey(
    encKey: Uint8Array,
    uncompressed: boolean
): Uint8Array;

export function generateSetupParamForSaverProvingKey(
    provingKey: Uint8Array,
    uncompressed: boolean
): Uint8Array;

export function generateSetupParamForSaverVerifyingKey(
    verifyingKey: Uint8Array,
    uncompressed: boolean
): Uint8Array;

export function generateSetupParamForLegoProvingKey(
    provingKey: Uint8Array,
    uncompressed: boolean
): Uint8Array;

export function generateSetupParamForLegoVerifyingKey(
    verifyingKey: Uint8Array,
    uncompressed: boolean
): Uint8Array;

export function generateSetupParamForR1CS(
    curveName: string, numPublic: number, numPrivate: number, constraints: Constraint[]
): Uint8Array;

export function generateSetupParamForBytes(
    bytes: Uint8Array
): Uint8Array;

export function generateSetupParamForFieldElemVec(
    arr: Uint8Array[]
): Uint8Array;
