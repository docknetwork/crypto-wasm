import {Bddt16MacParams, VerifyResult} from "../types";

export function getAllKeyedSubproofsFromProof(proof: Uint8Array): Map<number, [number, Uint8Array]>;

export function verifyBDDT16KeyedProof(proof: Uint8Array, secretKey: Uint8Array): Required<VerifyResult>;

export function proofOfValidityOfBDDT16KeyedProof(proof: Uint8Array, secretKey: Uint8Array, publicKey: Uint8Array, params: Bddt16MacParams): Uint8Array;

export function verifyProofOfValidityOfBDDT16KeyedProof(proofOfValidity: Uint8Array, keyedProof: Uint8Array, publicKey: Uint8Array, params: Bddt16MacParams): Required<VerifyResult>;

export function proofOfInvalidityOfBDDT16KeyedProof(proof: Uint8Array, secretKey: Uint8Array, publicKey: Uint8Array, params: Bddt16MacParams): Uint8Array;

export function verifyProofOfInvalidityOfBDDT16KeyedProof(proofOfInvalidity: Uint8Array, keyedProof: Uint8Array, publicKey: Uint8Array, params: Bddt16MacParams): Required<VerifyResult>;

export function verifyVBAccumMembershipKeyedProof(proof: Uint8Array, secretKey: Uint8Array): Required<VerifyResult>;

export function proofOfValidityOfVBAccumMembershipKeyedProof(proof: Uint8Array, secretKey: Uint8Array, publicKey: Uint8Array, params: Uint8Array): Uint8Array;

export function verifyProofOfValidityOfVBAccumMembershipKeyedProof(proofOfValidity: Uint8Array, keyedProof: Uint8Array, publicKey: Uint8Array, params: Uint8Array): Required<VerifyResult>;

export function proofOfInvalidityOfVBAccumMembershipKeyedProof(proof: Uint8Array, secretKey: Uint8Array, publicKey: Uint8Array, params: Uint8Array): Uint8Array;

export function verifyProofOfInvalidityOfVBAccumMembershipKeyedProof(proofOfValidity: Uint8Array, keyedProof: Uint8Array, publicKey: Uint8Array, params: Uint8Array): Required<VerifyResult>;

export function verifyKBUniAccumMembershipKeyedProof(proof: Uint8Array, secretKey: Uint8Array): Required<VerifyResult>;

export function proofOfValidityOfKBUniAccumMembershipKeyedProof(proof: Uint8Array, secretKey: Uint8Array, publicKey: Uint8Array, params: Uint8Array): Uint8Array;

export function verifyProofOfValidityOfKBUniAccumMembershipKeyedProof(proofOfValidity: Uint8Array, keyedProof: Uint8Array, publicKey: Uint8Array, params: Uint8Array): Required<VerifyResult>;

export function proofOfInvalidityOfKBUniAccumMembershipKeyedProof(proof: Uint8Array, secretKey: Uint8Array, publicKey: Uint8Array, params: Uint8Array): Uint8Array;

export function verifyProofOfInvalidityOfKBUniAccumMembershipKeyedProof(proofOfValidity: Uint8Array, keyedProof: Uint8Array, publicKey: Uint8Array, params: Uint8Array): Required<VerifyResult>;

export function verifyKBUniAccumNonMembershipKeyedProof(proof: Uint8Array, secretKey: Uint8Array): Required<VerifyResult>;

export function proofOfValidityOfKBUniAccumNonMembershipKeyedProof(proof: Uint8Array, secretKey: Uint8Array, publicKey: Uint8Array, params: Uint8Array): Uint8Array;

export function verifyProofOfValidityOfKBUniAccumNonMembershipKeyedProof(proofOfValidity: Uint8Array, keyedProof: Uint8Array, publicKey: Uint8Array, params: Uint8Array): Required<VerifyResult>;

export function proofOfInvalidityOfKBUniAccumNonMembershipKeyedProof(proof: Uint8Array, secretKey: Uint8Array, publicKey: Uint8Array, params: Uint8Array): Uint8Array;

export function verifyProofOfInvalidityOfKBUniAccumNonMembershipKeyedProof(proofOfValidity: Uint8Array, keyedProof: Uint8Array, publicKey: Uint8Array, params: Uint8Array): Required<VerifyResult>;
