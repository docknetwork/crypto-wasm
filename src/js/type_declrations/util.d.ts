export function generateRandomFieldElement(
    seed?: Uint8Array
): Promise<Uint8Array>;

export function generateRandomG1Element(): Promise<Uint8Array>;

export function generateRandomG2Element(): Promise<Uint8Array>;

export function generateFieldElementFromBytes(
    bytes: Uint8Array
): Promise<Uint8Array>;

export function fieldElementAsBytes(
    element: Uint8Array
): Promise<Uint8Array>;

export function generateChallengeFromBytes(
    bytes: Uint8Array
): Promise<Uint8Array>;

export function generateFieldElementFromNumber(
    num: number,
): Promise<Uint8Array>;
