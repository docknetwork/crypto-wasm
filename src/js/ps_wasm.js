const {
    wasm, requireWasmInitialized
} = require('./init_wasm');

function ensurePositiveInteger(num) {
    if (!Number.isInteger(num) || num < 0) {
        throw new Error(`Need a positive integer but found ${num} `);
    }
}

module.exports.DEFAULT_BLS12381_PRIVATE_KEY_LENGTH = 32;

module.exports.DEFAULT_BLS12381__PUBLIC_KEY_LENGTH = 48;

module.exports.DEFAULT_BLS12381__PUBLIC_KEY_LENGTH = 96;

module.exports.BBS_SIGNATURE_LENGTH = 112;

module.exports.psGenerateSigningKey = (messageCount, seed) => {
    requireWasmInitialized();
    ensurePositiveInteger(messageCount);
    return wasm.psGenerateSigningKey(messageCount, seed);
};

module.exports.psGenerateSignatureParams = (messageCount, label) => {
    requireWasmInitialized();
    ensurePositiveInteger(messageCount);
    return wasm.psGenerateSignatureParams(messageCount, label);
};

module.exports.psIsSignatureParamsValid = (params) => {
    requireWasmInitialized();
    return wasm.psIsSignatureParamsValid(params);
};

module.exports.psSignatureParamsMaxSupportedMsgs = (params) => {
    requireWasmInitialized();
    return wasm.psSignatureParamsMaxSupportedMsgs(params);
};

module.exports.psGenerateSignatureParams = (messageCount, label) => {
    requireWasmInitialized();
    ensurePositiveInteger(messageCount);
    return wasm.psGenerateSignatureParams(messageCount, label);
};

module.exports.psIsSignatureParamsValid = (params) => {
    requireWasmInitialized();
    return wasm.psIsSignatureParamsValid(params);
};

module.exports.psSignatureParamsMaxSupportedMsgs = (params) => {
    requireWasmInitialized();
    return wasm.psSignatureParamsMaxSupportedMsgs(params);
};

module.exports.psSignatureParamsToBytes = (params) => {
    requireWasmInitialized();
    return wasm.psSignatureParamsToBytes(params);
};

module.exports.psSignatureParamsFromBytes = (bytes) => {
    requireWasmInitialized();
    return wasm.psSignatureParamsFromBytes(bytes);
};

module.exports.psSignatureParamsFromBytes = (bytes) => {
    requireWasmInitialized();
    return wasm.psSignatureParamsFromBytes(bytes);
};

module.exports.psGeneratePublicKey = (secretKey, params) => {
    requireWasmInitialized();
    return wasm.psGeneratePublicKey(secretKey, params);
};

module.exports.psIsPublicKeyValid = (publicKey) => {
    requireWasmInitialized();
    return wasm.psIsPublicKeyValid(publicKey);
};

module.exports.psEncodeMessageForSigning = (message) => {
    requireWasmInitialized();
    return wasm.psEncodeMessageForSigning(message);
};

module.exports.psEncodeMessagesForSigning = (messages, indicesToEncode) => {
    requireWasmInitialized();
    return wasm.psEncodeMessagesForSigning(messages, indicesToEncode);
}

module.exports.psGetBasesForCommitment = (params, indicesToCommit) => {
    requireWasmInitialized();
    return wasm.psGetBasesForCommitment(params, indicesToCommit);
};

module.exports.psSign = (
    messages,
    secretKey,
    params,
) => {
    requireWasmInitialized();
    return wasm.psSign(messages, secretKey, params);
};

module.exports.psVerify = (
    messages,
    signature,
    publicKey,
    params
) => {
    requireWasmInitialized();
    return wasm.psVerify(messages, signature, publicKey, params);
};

module.exports.psMessageCommitment = (
    messages,
    blinding,
    params,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.psMessageCommitment(messages, blinding, params, encodeMessages);
};

module.exports.psBlindSign = (
    commitment,
    uncommittedMessages,
    secretKey,
    params,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.psBlindSign(commitment, uncommittedMessages, secretKey, params, encodeMessages);
};

module.exports.psUnblindSignature = (
    blind_signature,
    indexed_blindings,
    pk,
) => {
    requireWasmInitialized();
    return wasm.psUnblindSignature(blind_signature, indexed_blindings, pk);
};

module.exports.psInitializeProofOfKnowledgeOfSignature = (
    signature,
    params,
    messages,
    blindings,
    revealedIndices,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.psInitializeProofOfKnowledgeOfSignature(signature, params, messages, blindings, revealedIndices, encodeMessages);
};

module.exports.psGenProofOfKnowledgeOfSignature = (
    protocol,
    challenge
) => {
    requireWasmInitialized();
    return wasm.psGenProofOfKnowledgeOfSignature(protocol, challenge);
};

module.exports.psVerifyProofOfKnowledgeOfSignature = (
    proof,
    revealedMessages,
    challenge,
    publicKey,
    params
) => {
    requireWasmInitialized();
    return wasm.psVerifyProofOfKnowledgeOfSignature(proof, revealedMessages, challenge, publicKey, params);
};

module.exports.psChallengeContributionFromProtocol = (
    protocol,
    revealedMessages,
    params
) => {
    requireWasmInitialized();
    return wasm.psChallengeContributionFromProtocol(protocol, revealedMessages, params);
};

module.exports.psChallengeContributionFromProof = (
    proof,
    publicKey,
    params
) => {
    requireWasmInitialized();
    return wasm.psChallengeContributionFromProof(proof, publicKey, params);
};

module.exports.psAdaptSignatureParamsForMsgCount = (params, generating_label, new_count) => {
    requireWasmInitialized();
    return wasm.psAdaptSignatureParamsForMsgCount(params, generating_label, new_count);
};
