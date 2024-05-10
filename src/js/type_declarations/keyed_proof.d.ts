import {VerifyResult} from "../types";

export function getAllKeyedSubproofsFromProof(proof: Uint8Array): Map<number, [number, Uint8Array]>;

export function verifyBDDT16KeyedProof(proof: Uint8Array, secretKey: Uint8Array): Required<VerifyResult>;

export function verifyVBAccumMembershipKeyedProof(proof: Uint8Array, secretKey: Uint8Array): Required<VerifyResult>;

export function verifyKBUniAccumMembershipKeyedProof(proof: Uint8Array, secretKey: Uint8Array): Required<VerifyResult>;

export function verifyKBUniAccumNonMembershipKeyedProof(proof: Uint8Array, secretKey: Uint8Array): Required<VerifyResult>;