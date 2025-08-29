import { BbsPlusSigParams, BbsSigParams, Constraint, PSSigParams, Bddt16MacParams } from "../types";

export function generateSetupParamForBBSPlusSignatureParametersG1(
    params: BbsPlusSigParams
): Uint8Array;

export function generateSetupParamForBBSPlusPublicKeyG2(
    publicKey: Uint8Array
): Uint8Array;

export function generateSetupParamForPSPublicKey(
    publicKey: Uint8Array
): Uint8Array;

export function generateSetupParamForBBSSignatureParameters(
    params: BbsSigParams
): Uint8Array;

export function generateSetupParamForPSSignatureParameters(
    params: PSSigParams
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

export function generateSetupParamForBppParams(
    params: Uint8Array,
    uncompressed: boolean
): Uint8Array;

export function generateSetupParamForSmcParams(
    params: Uint8Array,
    uncompressed: boolean
): Uint8Array;

export function generateSetupParamForSmcParamsKV(
    params: Uint8Array,
    uncompressed: boolean
): Uint8Array;

export function generateSetupParamForSmcParamsKVAndSk(params: Uint8Array,
    uncompressed: boolean
): Uint8Array;

export function generateSetupParamForCommitmentKey(
    commKey: Uint8Array,
    uncompressed: boolean
): Uint8Array;

export function generateSetupParamForBDDT16MacParameters(
    params: Bddt16MacParams
): Uint8Array;
