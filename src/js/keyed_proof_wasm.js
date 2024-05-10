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