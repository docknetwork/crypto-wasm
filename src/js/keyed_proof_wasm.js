const {
    wasm, requireWasmInitialized
} = require('./init_wasm');

module.exports.getAllKeyedSubproofsFromProof = (proof) => {
    requireWasmInitialized();
    return wasm.getAllKeyedSubproofsFromProof(proof);
};

module.exports.verifyBDDT16KeyedProof = (proof, secretKey) => {
    requireWasmInitialized();
    return wasm.verifyBDDT16KeyedProof(proof, secretKey);
};

module.exports.proofOfValidityOfBDDT16KeyedProof = (proof, secretKey, publicKey, params) => {
    requireWasmInitialized();
    return wasm.proofOfValidityOfBDDT16KeyedProof(proof, secretKey, publicKey, params);
};

module.exports.verifyProofOfValidityOfBDDT16KeyedProof = (proofOfValidity, keyedProof, publicKey, params) => {
    requireWasmInitialized();
    return wasm.verifyProofOfValidityOfBDDT16KeyedProof(proofOfValidity, keyedProof, publicKey, params);
};

module.exports.proofOfInvalidityOfBDDT16KeyedProof = (proof, secretKey, publicKey, params) => {
    requireWasmInitialized();
    return wasm.proofOfInvalidityOfBDDT16KeyedProof(proof, secretKey, publicKey, params);
};

module.exports.verifyProofOfInvalidityOfBDDT16KeyedProof = (proofOfInvalidity, keyedProof, publicKey, params) => {
    requireWasmInitialized();
    return wasm.verifyProofOfInvalidityOfBDDT16KeyedProof(proofOfInvalidity, keyedProof, publicKey, params);
};

module.exports.verifyVBAccumMembershipKeyedProof = (proof, secretKey) => {
    requireWasmInitialized();
    return wasm.verifyVBAccumMembershipKeyedProof(proof, secretKey);
};

module.exports.proofOfValidityOfVBAccumMembershipKeyedProof = (proof, secretKey, publicKey, params) => {
    requireWasmInitialized();
    return wasm.proofOfValidityOfVBAccumMembershipKeyedProof(proof, secretKey, publicKey, params);
};

module.exports.verifyProofOfValidityOfVBAccumMembershipKeyedProof = (proofOfValidity, keyedProof, publicKey, params) => {
    requireWasmInitialized();
    return wasm.verifyProofOfValidityOfVBAccumMembershipKeyedProof(proofOfValidity, keyedProof, publicKey, params);
};

module.exports.proofOfInvalidityOfVBAccumMembershipKeyedProof = (proof, secretKey, publicKey, params) => {
    requireWasmInitialized();
    return wasm.proofOfInvalidityOfVBAccumMembershipKeyedProof(proof, secretKey, publicKey, params);
};

module.exports.verifyProofOfInvalidityOfVBAccumMembershipKeyedProof = (proofOfInvalidity, keyedProof, publicKey, params) => {
    requireWasmInitialized();
    return wasm.verifyProofOfInvalidityOfVBAccumMembershipKeyedProof(proofOfInvalidity, keyedProof, publicKey, params);
};

module.exports.verifyKBUniAccumMembershipKeyedProof = (proof, secretKey) => {
    requireWasmInitialized();
    return wasm.verifyKBUniAccumMembershipKeyedProof(proof, secretKey);
};

module.exports.proofOfValidityOfKBUniAccumMembershipKeyedProof = (proof, secretKey, publicKey, params) => {
    requireWasmInitialized();
    return wasm.proofOfValidityOfKBUniAccumMembershipKeyedProof(proof, secretKey, publicKey, params);
};

module.exports.verifyProofOfValidityOfKBUniAccumMembershipKeyedProof = (proofOfValidity, keyedProof, publicKey, params) => {
    requireWasmInitialized();
    return wasm.verifyProofOfValidityOfKBUniAccumMembershipKeyedProof(proofOfValidity, keyedProof, publicKey, params);
};

module.exports.proofOfInvalidityOfKBUniAccumMembershipKeyedProof = (proof, secretKey, publicKey, params) => {
    requireWasmInitialized();
    return wasm.proofOfInvalidityOfKBUniAccumMembershipKeyedProof(proof, secretKey, publicKey, params);
};

module.exports.verifyProofOfInvalidityOfKBUniAccumMembershipKeyedProof = (proofOfInvalidity, keyedProof, publicKey, params) => {
    requireWasmInitialized();
    return wasm.verifyProofOfInvalidityOfKBUniAccumMembershipKeyedProof(proofOfInvalidity, keyedProof, publicKey, params);
};

module.exports.verifyKBUniAccumNonMembershipKeyedProof = (proof, secretKey) => {
    requireWasmInitialized();
    return wasm.verifyKBUniAccumNonMembershipKeyedProof(proof, secretKey);
};

module.exports.proofOfValidityOfKBUniAccumNonMembershipKeyedProof = (proof, secretKey, publicKey, params) => {
    requireWasmInitialized();
    return wasm.proofOfValidityOfKBUniAccumNonMembershipKeyedProof(proof, secretKey, publicKey, params);
};

module.exports.verifyProofOfValidityOfKBUniAccumNonMembershipKeyedProof = (proofOfValidity, keyedProof, publicKey, params) => {
    requireWasmInitialized();
    return wasm.verifyProofOfValidityOfKBUniAccumNonMembershipKeyedProof(proofOfValidity, keyedProof, publicKey, params);
};

module.exports.proofOfInvalidityOfKBUniAccumNonMembershipKeyedProof = (proof, secretKey, publicKey, params) => {
    requireWasmInitialized();
    return wasm.proofOfInvalidityOfKBUniAccumNonMembershipKeyedProof(proof, secretKey, publicKey, params);
};

module.exports.verifyProofOfInvalidityOfKBUniAccumNonMembershipKeyedProof = (proofOfInvalidity, keyedProof, publicKey, params) => {
    requireWasmInitialized();
    return wasm.verifyProofOfInvalidityOfKBUniAccumNonMembershipKeyedProof(proofOfInvalidity, keyedProof, publicKey, params);
};
