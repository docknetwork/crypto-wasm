const {
    wasm, requireWasmInitialized
} = require('./init_wasm');

module.exports.getAllDelegatedSubproofsFromProof = (proof) => {
    requireWasmInitialized();
    return wasm.getAllDelegatedSubproofsFromProof(proof);
};

module.exports.verifyBDDT16DelegatedProof = (proof, secretKey) => {
    requireWasmInitialized();
    return wasm.verifyBDDT16DelegatedProof(proof, secretKey);
};

module.exports.verifyVBAccumMembershipDelegatedProof = (proof, secretKey) => {
    requireWasmInitialized();
    return wasm.verifyVBAccumMembershipDelegatedProof(proof, secretKey);
};
