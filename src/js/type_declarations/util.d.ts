export function generateRandomFieldElement(
    seed?: Uint8Array
): Uint8Array;

export function generateRandomG1Element(): Uint8Array;

export function generateRandomG2Element(): Uint8Array;

export function generateFieldElementFromBytes(
    bytes: Uint8Array
): Uint8Array;

export function fieldElementAsBytes(
    element: Uint8Array
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
