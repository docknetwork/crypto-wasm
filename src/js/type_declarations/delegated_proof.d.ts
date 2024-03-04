import {VerifyResult} from "../types";

export function getAllDelegatedSubproofsFromProof(proof: Uint8Array): Map<number, [number, Uint8Array]>;

export function verifyBDDT16DelegatedProof(proof: Uint8Array, secretKey: Uint8Array): Required<VerifyResult>;

export function verifyVBAccumMembershipDelegatedProof(proof: Uint8Array, secretKey: Uint8Array): Required<VerifyResult>;