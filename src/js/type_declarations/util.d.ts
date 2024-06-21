export function generateRandomFieldElement(
    seed?: Uint8Array
): Uint8Array;

export function generateRandomG1Element(seed?: Uint8Array): Uint8Array;

export function generateRandomG2Element(seed?: Uint8Array): Uint8Array;

export function generateFieldElementFromBytes(
    bytes: Uint8Array
): Uint8Array;

export function encodeMessageForSigning(
    message: Uint8Array
): Uint8Array;

export function encodeMessagesForSigning(
    messages: Uint8Array[],
    indicesToEncode?: number[]
): Uint8Array[];

export function encodeMessageForSigningInConstantTime(
    message: Uint8Array
): Uint8Array;

export function encodeMessagesForSigningInConstantTime(
    messages: Uint8Array[],
    indicesToEncode?: number[]
): Uint8Array[];

export function fieldElementAsBytes(
    element: Uint8Array,
    elementIsSecure: boolean
): Uint8Array;

export function generateChallengeFromBytes(
    bytes: Uint8Array
): Uint8Array;

export function generateFieldElementFromNumber(
    num: number,
): Uint8Array;

export function pedersenCommitmentG1(
    bases: Uint8Array[],
    messages: Uint8Array[],
): Uint8Array;

export function pedersenCommitmentG2(
    bases: Uint8Array[],
    messages: Uint8Array[],
): Uint8Array;

export function generatePedersenCommKeyG1(
    label: Uint8Array,
    returnUncompressed: boolean,
): Uint8Array;

export function decompressPedersenCommKeyG1(
    commKey: Uint8Array
): Uint8Array;
