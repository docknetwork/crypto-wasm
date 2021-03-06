const {
    wasm, requireWasmInitialized
} = require('./init_wasm');

module.exports.generateSetupParamForBBSSignatureParametersG1 = (params) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForBBSSignatureParametersG1(params);
};

module.exports.generateSetupParamForBBSPublicKeyG2 = (publicKey) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForBBSPublicKeyG2(publicKey);
};

module.exports.generateSetupParamForVbAccumulatorParams = (params) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForVbAccumulatorParams(params);
};

module.exports.generateSetupParamForVbAccumulatorPublicKey = (publicKey) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForVbAccumulatorPublicKey(publicKey);
};

module.exports.generateSetupParamForVbAccumulatorMemProvingKey = (provingKey) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForVbAccumulatorMemProvingKey(provingKey);
};

module.exports.generateSetupParamForVbAccumulatorNonMemProvingKey = (provingKey) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForVbAccumulatorNonMemProvingKey(provingKey);
};

module.exports.generateSetupParamForPedersenCommitmentKeyG1 = (commitmentKey) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForPedersenCommitmentKeyG1(commitmentKey);
};

module.exports.generateSetupParamForPedersenCommitmentKeyG2 = (commitmentKey) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForPedersenCommitmentKeyG2(commitmentKey);
};

module.exports.generateSetupParamForSaverEncryptionGens = (encGens, uncompressed) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForSaverEncryptionGens(encGens, uncompressed);
};

module.exports.generateSetupParamForSaverCommitmentGens = (commGens, uncompressed) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForSaverCommitmentGens(commGens, uncompressed);
};

module.exports.generateSetupParamForSaverEncryptionKey = (encKey, uncompressed) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForSaverEncryptionKey(encKey, uncompressed);
};

module.exports.generateSetupParamForSaverProvingKey = (provingKey, uncompressed) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForSaverProvingKey(provingKey, uncompressed);
};

module.exports.generateSetupParamForSaverVerifyingKey = (verifyingKey, uncompressed) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForSaverVerifyingKey(verifyingKey, uncompressed);
};

module.exports.generateSetupParamForLegoProvingKey = (provingKey, uncompressed) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForLegoProvingKey(provingKey, uncompressed);
};

module.exports.generateSetupParamForLegoVerifyingKey = (verifyingKey, uncompressed) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForLegoVerifyingKey(verifyingKey, uncompressed);
};
