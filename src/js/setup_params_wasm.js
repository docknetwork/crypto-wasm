const {
    wasm, requireWasmInitialized
} = require('./init_wasm');

module.exports.generateSetupParamForBBSPlusSignatureParametersG1 = (params) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForBBSPlusSignatureParametersG1(params);
};

module.exports.generateSetupParamForBBSPlusPublicKeyG2 = (publicKey) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForBBSPlusPublicKeyG2(publicKey);
};

module.exports.generateSetupParamForPSPublicKey = (publicKey) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForPSPublicKey(publicKey);
};

module.exports.generateSetupParamForPSSignatureParameters = (params) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForPSSignatureParameters(params);
};

module.exports.generateSetupParamForBBSSignatureParameters = (params) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForBBSSignatureParameters(params);
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

module.exports.generateSetupParamForR1CS = (curveName, numPublic, numPrivate, constraints) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForR1CS(curveName, numPublic, numPrivate, constraints);
};

module.exports.generateSetupParamForBytes = (bytes) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForBytes(bytes);
};

module.exports.generateSetupParamForFieldElemVec = (arr) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForFieldElemVec(arr);
};

module.exports.generateSetupParamForBppParams = (params, uncompressed) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForBppParams(params, uncompressed);
};

module.exports.generateSetupParamForSmcParams = (params, uncompressed) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForSmcParams(params, uncompressed);
};

module.exports.generateSetupParamForSmcParamsKV = (params, uncompressed) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForSmcParamsKV(params, uncompressed);
};

module.exports.generateSetupParamForSmcParamsKVAndSk = (params, uncompressed) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForSmcParamsKVAndSk(params, uncompressed);
};

module.exports.generateSetupParamForCommitmentKey = (commKey, uncompressed) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForCommitmentKey(commKey, uncompressed);
};

module.exports.generateSetupParamForBDDT16MacParameters = (params) => {
    requireWasmInitialized();
    return wasm.generateSetupParamForBDDT16MacParameters(params);
};