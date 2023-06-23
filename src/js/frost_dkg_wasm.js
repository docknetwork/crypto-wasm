const {
    wasm, requireWasmInitialized
} = require('./init_wasm');

module.exports.generateRandomPublicKeyBaseInG1 = (seed) => {
    requireWasmInitialized();
    return wasm.generateRandomPublicKeyBaseInG1(seed);
};

module.exports.generateRandomPublicKeyBaseInG2 = (seed) => {
    requireWasmInitialized();
    return wasm.generateRandomPublicKeyBaseInG2(seed);
};

module.exports.generateKeyBaseFromGivenG1Point = (point) => {
    requireWasmInitialized();
    return wasm.generateKeyBaseFromGivenG1Point(point);
};

module.exports.generateKeyBaseFromGivenG2Point = (point) => {
    requireWasmInitialized();
    return wasm.generateKeyBaseFromGivenG2Point(point);
};

module.exports.frostKeygenG1StartRound1 = (participantId, threshold, total, schnorrProofCtx, pkBase) => {
    requireWasmInitialized();
    return wasm.frostKeygenG1StartRound1(participantId, threshold, total, schnorrProofCtx, pkBase);
};

module.exports.frostKeygenG2StartRound1 = (participantId, threshold, total, schnorrProofCtx, pkBase) => {
    requireWasmInitialized();
    return wasm.frostKeygenG2StartRound1(participantId, threshold, total, schnorrProofCtx, pkBase);
};

module.exports.frostKeygenG1Round1ProcessReceivedMessage = (roundState, msg, schnorrProofCtx, pkBase) => {
    requireWasmInitialized();
    return wasm.frostKeygenG1Round1ProcessReceivedMessage(roundState, msg, schnorrProofCtx, pkBase);
};

module.exports.frostKeygenG2Round1ProcessReceivedMessage = (roundState, msg, schnorrProofCtx, pkBase) => {
    requireWasmInitialized();
    return wasm.frostKeygenG2Round1ProcessReceivedMessage(roundState, msg, schnorrProofCtx, pkBase);
};

module.exports.frostKeygenG1Round1Finish = (roundState) => {
    requireWasmInitialized();
    return wasm.frostKeygenG1Round1Finish(roundState);
};

module.exports.frostKeygenG2Round1Finish = (roundState) => {
    requireWasmInitialized();
    return wasm.frostKeygenG2Round1Finish(roundState);
};

module.exports.frostKeygenG1Round2ProcessReceivedMessage = (roundState, senderId, share, pkBase) => {
    requireWasmInitialized();
    return wasm.frostKeygenG1Round2ProcessReceivedMessage(roundState, senderId, share, pkBase);
};

module.exports.frostKeygenG2Round2ProcessReceivedMessage = (roundState, senderId, share, pkBase) => {
    requireWasmInitialized();
    return wasm.frostKeygenG2Round2ProcessReceivedMessage(roundState, senderId, share, pkBase);
};

module.exports.frostKeygenG1Round2Finish = (roundState, pkBase) => {
    requireWasmInitialized();
    return wasm.frostKeygenG1Round2Finish(roundState, pkBase);
};

module.exports.frostKeygenG2Round2Finish = (roundState, pkBase) => {
    requireWasmInitialized();
    return wasm.frostKeygenG2Round2Finish(roundState, pkBase);
};

module.exports.frostKeygenG1PubkeyFromSecretKey = (secretKey, pkBase) => {
    requireWasmInitialized();
    return wasm.frostKeygenG1PubkeyFromSecretKey(secretKey, pkBase);
};

module.exports.frostKeygenG2PubkeyFromSecretKey = (secretKey, pkBase) => {
    requireWasmInitialized();
    return wasm.frostKeygenG2PubkeyFromSecretKey(secretKey, pkBase);
};

module.exports.frostKeygenG1ThresholdPubkeyFromPubkeys = (pubKeys, threshold) => {
    requireWasmInitialized();
    return wasm.frostKeygenG1ThresholdPubkeyFromPubkeys(pubKeys, threshold);
};

module.exports.frostKeygenG2ThresholdPubkeyFromPubkeys = (pubKeys, threshold) => {
    requireWasmInitialized();
    return wasm.frostKeygenG2ThresholdPubkeyFromPubkeys(pubKeys, threshold);
};