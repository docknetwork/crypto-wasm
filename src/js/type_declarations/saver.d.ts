import {VerifyResult} from "../types";

export function saverGenerateEncryptionGenerators(
    label?: Uint8Array
): Uint8Array;

export function saverGenerateChunkedCommitmentGenerators(
    label?: Uint8Array
): Uint8Array;

// TODO: Fix return type to be an array of 4 bytearrays
export function saverDecryptorSetup(
    chunkBitSize: number,
    encGens: Uint8Array
): Uint8Array[];

export function saverDecompressEncryptionGenerators(
    encGens: Uint8Array
): Uint8Array;

export function saverDecompressChunkedCommitmentGenerators(
    commGens: Uint8Array
): Uint8Array;

export function saverDecompressEncryptionKey(
    encryptionKey: Uint8Array
): Uint8Array;

export function saverDecompressDecryptionKey(
    decryptionKey: Uint8Array
): Uint8Array;

export function saverDecompressSnarkPk(
    snarkPk: Uint8Array
): Uint8Array;

export function saverGetSnarkVkFromPk(
    snarkPk: Uint8Array
): Uint8Array;

// TODO: Fix return type to be an array of 2 bytearrays
export function saverDecryptCiphertextUsingSnarkPk(
    ciphertext: Uint8Array,
    secretKey: Uint8Array,
    decryptionKey: Uint8Array,
    snarkPk: Uint8Array,
    chunkBitSize: number,
    uncompressedPublicParams: boolean
): Uint8Array[];

export function saverDecryptCiphertextUsingSnarkVk(
    ciphertext: Uint8Array,
    secretKey: Uint8Array,
    decryptionKey: Uint8Array,
    snarkVk: Uint8Array,
    chunkBitSize: number,
    uncompressedPublicParams: boolean
): Uint8Array[];

export function saverVerifyDecryptionUsingSnarkPk(
    ciphertext: Uint8Array,
    message: Uint8Array,
    nu: Uint8Array,
    decryptionKey: Uint8Array,
    snarkPk: Uint8Array,
    encGens: Uint8Array,
    chunkBitSize: number,
    uncompressedPublicParams: boolean
): Required<VerifyResult>;

