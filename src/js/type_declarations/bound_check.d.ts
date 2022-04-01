import {BbsSigParams, VerifyResult} from "../types";

export function boundCheckSnarkSetup(): Uint8Array;

export function boundCheckDecompressSnarkPk(
    snarkPk: Uint8Array
): Uint8Array;

export function boundCheckGetSnarkVkFromPk(
    snarkPk: Uint8Array
): Uint8Array;
