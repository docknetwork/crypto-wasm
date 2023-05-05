const {
    wasm, requireWasmInitialized
} = require('./init_wasm');

function ensurePositiveInteger(num) {
    if (!Number.isInteger(num) || num < 0) {
        throw new Error(`Need a positive integer but found ${num} `);
    }
}

module.exports.DEFAULT_BLS12381_PRIVATE_KEY_LENGTH = 32;

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

module.exports.psSigningKeyMaxSupportedMsgs = (params) => {
    requireWasmInitialized();
    return wasm.psSigningKeyMaxSupportedMsgs(params);
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

module.exports.psBlindMessageRandomly = function(
    message,
) {
    requireWasmInitialized();
    return wasm.psBlindMessageRandomly(message)
}

module.exports.psRevealMessage = function(
    message,
) {
    requireWasmInitialized();
    return wasm.psRevealMessage(message)
}

module.exports.psBlindMessageWithConcreteBlinding = function(
    message,
    blinding,
) {
    requireWasmInitialized();
    return wasm.psBlindMessageWithConcreteBlinding(message, blinding)
}

module.exports.psBlindedMessage = function(
    commitment,
) {
    requireWasmInitialized();
    return wasm.psBlindedMessage(commitment);
}

module.exports.psRevealedMessage = function(
    message,
) {
    requireWasmInitialized();
    return wasm.psRevealedMessage(message)
}

module.exports.psPublicKeyMaxSupportedMsgs = (params) => {
    requireWasmInitialized();
    return wasm.psPublicKeyMaxSupportedMsgs(params);
};

module.exports.psSignatureParamsToBytes = (params) => {
    requireWasmInitialized();
    return wasm.psSignatureParamsToBytes(params);
};

module.exports.psAggregateSignatures = (participantSignatures, h) => {
    requireWasmInitialized();
    return wasm.psAggregateSignatures(participantSignatures, h);
};

module.exports.psSignatureParamsFromBytes = (bytes) => {
    requireWasmInitialized();
    return wasm.psSignatureParamsFromBytes(bytes);
};

module.exports.psShamirDeal = (messageCount, threshold, total) => {
    requireWasmInitialized();
    return wasm.psShamirDeal(messageCount, threshold, total);
};

module.exports.psGeneratePublicKey = (secretKey, params) => {
    requireWasmInitialized();
    return wasm.psGeneratePublicKey(secretKey, params);
};

module.exports.psAdaptSecretKeyForLessMessages = (secretKey, messageCount) => {
    requireWasmInitialized();
    return wasm.psAdaptSecretKeyForLessMessages(secretKey, messageCount);
};

module.exports.psAdaptPublicKeyForLessMessages = (secretKey, messageCount) => {
    requireWasmInitialized();
    return wasm.psAdaptPublicKeyForLessMessages(secretKey, messageCount);
};

module.exports.psAdaptSecretKeyForMoreMessages = (secretKey, seed, messageCount) => {
    requireWasmInitialized();
    return wasm.psAdaptSecretKeyForMoreMessages(secretKey, seed, messageCount);
};

module.exports.psIsPublicKeyValid = (publicKey) => {
    requireWasmInitialized();
    return wasm.psIsPublicKeyValid(publicKey);
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

module.exports.psInitializeSignaturePoK = (
    signature,
    params,
    messages,
    blindings,
    revealedIndices,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.psInitializeSignaturePoK(signature, params, messages, blindings, revealedIndices, encodeMessages);
};

module.exports.psInitializeMessagesPoK = (
    params,
    h,
    messages
) => {
    requireWasmInitialized();
    return wasm.psInitializeMessagesPoK(
        params,
        h,
        messages
    );
};

module.exports.psGenSignaturePoK = (
    protocol,
    challenge
) => {
    requireWasmInitialized();
    return wasm.psGenSignaturePoK(protocol, challenge);
};

module.exports.psGenMessagesPoK = (
    protocol,
    challenge
) => {
    requireWasmInitialized();
    return wasm.psGenMessagesPoK(protocol, challenge);
};


module.exports.psVerifySignaturePoK = (
    proof,
    revealedMessages,
    challenge,
    publicKey,
    params
) => {
    requireWasmInitialized();
    return wasm.psVerifySignaturePoK(proof, revealedMessages, challenge, publicKey, params);
};

module.exports.psVerifyMessagesPoK = (
    proof,
    revealedIndices,
    challenge,
    params,
    h
) => {
    requireWasmInitialized();
    return wasm.psVerifyMessagesPoK(proof, revealedIndices, challenge, params, h);
};

module.exports.psChallengeSignaturePoKContributionFromProtocol = (
    protocol,
    revealedMessages,
    params
) => {
    requireWasmInitialized();
    return wasm.psChallengeSignaturePoKContributionFromProtocol(protocol, revealedMessages, params);
};

module.exports.psChallengeMessagesPoKContributionFromProtocol = (
    protocol,
    params,
    h
) => {
    requireWasmInitialized();
    return wasm.psChallengeMessagesPoKContributionFromProtocol(protocol, params, h);
};

module.exports.psChallengeSignaturePoKContributionFromProof = (
    proof,
    publicKey,
    params
) => {
    requireWasmInitialized();
    return wasm.psChallengeSignaturePoKContributionFromProof(proof, publicKey, params);
};

module.exports.psChallengeMessagesPoKContributionFromProof = (
    proof,
    params,
    h
) => {
    requireWasmInitialized();
    return wasm.psChallengeMessagesPoKContributionFromProof(proof, params, h);
};

module.exports.psAdaptSignatureParamsForMsgCount = (params, generating_label, new_count) => {
    requireWasmInitialized();
    return wasm.psAdaptSignatureParamsForMsgCount(params, generating_label, new_count);
};
