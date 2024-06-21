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

module.exports.verifyKBUniAccumMembershipKeyedProof = (proof, secretKey) => {
    requireWasmInitialized();
    return wasm.verifyKBUniAccumMembershipKeyedProof(proof, secretKey);
};

module.exports.verifyKBUniAccumNonMembershipKeyedProof = (proof, secretKey) => {
    requireWasmInitialized();
    return wasm.verifyKBUniAccumNonMembershipKeyedProof(proof, secretKey);
};