import {VerifyResult} from "../types";

export function saverGenerateEncryptionGenerators(
    label?: Uint8Array
): Uint8Array;

export function saverGenerateChunkedCommitmentGenerators(
    label?: Uint8Array
): Uint8Array;

export function saverDecryptorSetup(
    chunkBitSize: number,
    encGens: Uint8Array,
    returnUncompressedSnarkPk: boolean,
): [Uint8Array, Uint8Array, Uint8Array, Uint8Array];

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
    snarkPk: Uint8Array,
    returnUncompressed: boolean
): Uint8Array;

export function saverDecompressSnarkVk(
    snarkVk: Uint8Array
): Uint8Array;

export function saverDecryptCiphertextUsingSnarkPk(
    ciphertext: Uint8Array,
    secretKey: Uint8Array,
    decryptionKey: Uint8Array,
    snarkPk: Uint8Array,
    chunkBitSize: number,
    uncompressedPublicParams: boolean
): [Uint8Array, Uint8Array];

export function saverDecryptCiphertextUsingSnarkVk(
    ciphertext: Uint8Array,
    secretKey: Uint8Array,
    decryptionKey: Uint8Array,
    snarkVk: Uint8Array,
    chunkBitSize: number,
    uncompressedPublicParams: boolean
): [Uint8Array, Uint8Array];

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

export function saverVerifyDecryptionUsingSnarkVk(
    ciphertext: Uint8Array,
    message: Uint8Array,
    nu: Uint8Array,
    decryptionKey: Uint8Array,
    snarkVk: Uint8Array,
    encGens: Uint8Array,
    chunkBitSize: number,
    uncompressedPublicParams: boolean
): Required<VerifyResult>;
