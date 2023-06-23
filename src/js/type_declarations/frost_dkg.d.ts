export function generateRandomPublicKeyBaseInG1(seed?: Uint8Array): Uint8Array;

export function generateRandomPublicKeyBaseInG2(seed?: Uint8Array): Uint8Array;

export function generateKeyBaseFromGivenG1Point(point: Uint8Array): Uint8Array;

export function generateKeyBaseFromGivenG2Point(point: Uint8Array): Uint8Array;

export function frostKeygenG1StartRound1(participantId: number, threshold: number, total: number, schnorrProofCtx: Uint8Array, pkBase: Uint8Array): [Uint8Array, Uint8Array];

export function frostKeygenG2StartRound1(participantId: number, threshold: number, total: number, schnorrProofCtx: Uint8Array, pkBase: Uint8Array): [Uint8Array, Uint8Array];

export function frostKeygenG1Round1ProcessReceivedMessage(roundState: Uint8Array, msg: Uint8Array, schnorrProofCtx: Uint8Array, pkBase: Uint8Array): Uint8Array;

export function frostKeygenG2Round1ProcessReceivedMessage(roundState: Uint8Array, msg: Uint8Array, schnorrProofCtx: Uint8Array, pkBase: Uint8Array): Uint8Array;

export function frostKeygenG1Round1Finish(roundState: Uint8Array): [Uint8Array, Uint8Array[]];

export function frostKeygenG2Round1Finish(roundState: Uint8Array): [Uint8Array, Uint8Array[]];

export function frostKeygenG1Round2ProcessReceivedMessage(roundState: Uint8Array, senderId: number, share: Uint8Array, pkBase: Uint8Array): Uint8Array;

export function frostKeygenG2Round2ProcessReceivedMessage(roundState: Uint8Array, senderId: number, share: Uint8Array, pkBase: Uint8Array): Uint8Array;

export function frostKeygenG1Round2Finish(roundState: Uint8Array, pkBase: Uint8Array): [Uint8Array, Uint8Array, Uint8Array];

export function frostKeygenG2Round2Finish(roundState: Uint8Array, pkBase: Uint8Array): [Uint8Array, Uint8Array, Uint8Array];

export function frostKeygenG1PubkeyFromSecretKey(secretKey: Uint8Array, pkBase: Uint8Array): Uint8Array;

export function frostKeygenG2PubkeyFromSecretKey(secretKey: Uint8Array, pkBase: Uint8Array): Uint8Array;

export function frostKeygenG1ThresholdPubkeyFromPubkeys(pubkeys: [number, Uint8Array][], threshold: number): Uint8Array;

export function frostKeygenG2ThresholdPubkeyFromPubkeys(pubkeys: [number, Uint8Array][], threshold: number): Uint8Array;