const {
    wasm, requireWasmInitialized
} = require('./init_wasm');

const {
    ensurePositiveInteger
} = require('./common');

module.exports.bddt16MacGenerateSecretKey = (seed) => {
    requireWasmInitialized();
    return wasm.bddt16MacGenerateSecretKey(seed);
};

module.exports.bddt16GenerateMacParams = (messageCount, label) => {
    requireWasmInitialized();
    ensurePositiveInteger(messageCount);
    return wasm.bddt16GenerateMacParams(messageCount, label);
};

module.exports.bddt16IsMacParamsValid = (params) => {
    requireWasmInitialized();
    return wasm.bddt16IsMacParamsValid(params);
};

module.exports.bddt16MacParamsMaxSupportedMsgs = (params) => {
    requireWasmInitialized();
    return wasm.bddt16MacParamsMaxSupportedMsgs(params);
};

module.exports.bddt16MacParamsToBytes = (params) => {
    requireWasmInitialized();
    return wasm.bddt16MacParamsToBytes(params);
};

module.exports.bddt16MacParamsFromBytes = (bytes) => {
    requireWasmInitialized();
    return wasm.bddt16MacParamsFromBytes(bytes);
};

module.exports.bddt16MacAdaptParamsForMsgCount = (params, generating_label, new_count) => {
    requireWasmInitialized();
    return wasm.bddt16MacAdaptParamsForMsgCount(params, generating_label, new_count);
};

module.exports.bddt16MacGetBasesForCommitment = (params, indicesToCommit) => {
    requireWasmInitialized();
    return wasm.bddt16MacGetBasesForCommitment(params, indicesToCommit);
};

module.exports.bddt16MacGenerate = (
    messages,
    secretKey,
    params,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.bddt16MacGenerate(messages, secretKey, params, encodeMessages);
};

module.exports.bddt16MacVerify = (
    messages,
    mac,
    secretKey,
    params,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.bddt16MacVerify(messages, mac, secretKey, params, encodeMessages);
};

module.exports.bddt16MacCommitMsgs = (
    messages,
    blinding,
    params,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.bddt16MacCommitMsgs(messages, blinding, params, encodeMessages);
};

module.exports.bddt16BlindMacGenerate = (
    commitment,
    uncommittedMessages,
    secretKey,
    params,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.bddt16BlindMacGenerate(commitment, uncommittedMessages, secretKey, params, encodeMessages);
};

module.exports.bddt16UnblindMac = (
    mac,
    blinding,
) => {
    requireWasmInitialized();
    return wasm.bddt16UnblindMac(mac, blinding);
};

