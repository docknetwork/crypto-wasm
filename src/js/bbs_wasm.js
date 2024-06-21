const {
    wasm, requireWasmInitialized
} = require('./init_wasm');

const {
    ensurePositiveInteger
} = require('./common');

module.exports.DEFAULT_BLS12381_BBS_PRIVATE_KEY_LENGTH = 32;

module.exports.DEFAULT_BLS12381_BBS_PUBLIC_KEY_LENGTH = 96;

module.exports.DEFAULT_BLS12381_BBS_SIGNATURE_LENGTH = 80;

module.exports.bbsGenerateSigningKey = (seed) => {
    requireWasmInitialized();
    return wasm.bbsGenerateSigningKey(seed);
};

module.exports.bbsGenerateSignatureParams = (messageCount, label) => {
    requireWasmInitialized();
    ensurePositiveInteger(messageCount);
    return wasm.bbsGenerateSignatureParams(messageCount, label);
};

module.exports.bbsIsSignatureParamsValid = (params) => {
    requireWasmInitialized();
    return wasm.bbsIsSignatureParamsValid(params);
};

module.exports.bbsSignatureParamsMaxSupportedMsgs = (params) => {
    requireWasmInitialized();
    return wasm.bbsSignatureParamsMaxSupportedMsgs(params);
};

module.exports.bbsSignatureParamsToBytes = (params) => {
    requireWasmInitialized();
    return wasm.bbsSignatureParamsToBytes(params);
};

module.exports.bbsSignatureParamsFromBytes = (bytes) => {
    requireWasmInitialized();
    return wasm.bbsSignatureParamsFromBytes(bytes);
};

module.exports.bbsGeneratePublicKey = (secretKey, params) => {
    requireWasmInitialized();
    return wasm.bbsGeneratePublicKey(secretKey, params);
};

module.exports.bbsIsPublicKeyValid = (publicKey) => {
    requireWasmInitialized();
    return wasm.bbsIsPublicKeyValid(publicKey);
};

module.exports.bbsGenerateKeyPair = (params, seed) => {
    requireWasmInitialized();
    return wasm.bbsGenerateKeyPair(params, seed);
};

module.exports.bbsSign = (
    messages,
    secretKey,
    params,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.bbsSign(messages, secretKey, params, encodeMessages);
};

module.exports.bbsSignConstantTime = (
    messages,
    secretKey,
    params,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.bbsSignConstantTime(messages, secretKey, params, encodeMessages);
};

module.exports.bbsVerify = (
    messages,
    signature,
    publicKey,
    params,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.bbsVerify(messages, signature, publicKey, params, encodeMessages);
};

module.exports.bbsVerifyConstantTime = (
    messages,
    signature,
    publicKey,
    params,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.bbsVerifyConstantTime(messages, signature, publicKey, params, encodeMessages);
};

module.exports.bbsCommitMsgs = (
    messages,
    params,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.bbsCommitMsgs(messages, params, encodeMessages);
};

module.exports.bbsCommitMsgsConstantTime = (
    messages,
    params,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.bbsCommitMsgsConstantTime(messages, params, encodeMessages);
};

module.exports.bbsBlindSign = (
    commitment,
    uncommittedMessages,
    secretKey,
    params,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.bbsBlindSign(commitment, uncommittedMessages, secretKey, params, encodeMessages);
};

module.exports.bbsBlindSignConstantTime = (
    commitment,
    uncommittedMessages,
    secretKey,
    params,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.bbsBlindSignConstantTime(commitment, uncommittedMessages, secretKey, params, encodeMessages);
};

module.exports.bbsInitializeProofOfKnowledgeOfSignature = (
    signature,
    params,
    messages,
    blindings,
    revealedIndices,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.bbsInitializeProofOfKnowledgeOfSignature(signature, params, messages, blindings, revealedIndices, encodeMessages);
};

module.exports.bbsInitializeProofOfKnowledgeOfSignatureNew = (
    signature,
    params,
    messages,
    blindings,
    revealedIndices,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.bbsInitializeProofOfKnowledgeOfSignatureNew(signature, params, messages, blindings, revealedIndices, encodeMessages);
};

module.exports.bbsInitializeProofOfKnowledgeOfSignatureConstantTime = (
    signature,
    params,
    messages,
    blindings,
    revealedIndices,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.bbsInitializeProofOfKnowledgeOfSignatureConstantTime(signature, params, messages, blindings, revealedIndices, encodeMessages);
};

module.exports.bbsGenProofOfKnowledgeOfSignature = (
    protocol,
    challenge
) => {
    requireWasmInitialized();
    return wasm.bbsGenProofOfKnowledgeOfSignature(protocol, challenge);
};

module.exports.bbsGenProofOfKnowledgeOfSignatureNew = (
    protocol,
    challenge
) => {
    requireWasmInitialized();
    return wasm.bbsGenProofOfKnowledgeOfSignatureNew(protocol, challenge);
};

module.exports.bbsVerifyProofOfKnowledgeOfSignature = (
    proof,
    revealedMessages,
    challenge,
    publicKey,
    params,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.bbsVerifyProofOfKnowledgeOfSignature(proof, revealedMessages, challenge, publicKey, params, encodeMessages);
};

module.exports.bbsVerifyProofOfKnowledgeOfSignatureNew = (
    proof,
    revealedMessages,
    challenge,
    publicKey,
    params,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.bbsVerifyProofOfKnowledgeOfSignatureNew(proof, revealedMessages, challenge, publicKey, params, encodeMessages);
};

module.exports.bbsVerifyProofOfKnowledgeOfSignatureConstantTime = (
    proof,
    revealedMessages,
    challenge,
    publicKey,
    params,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.bbsVerifyProofOfKnowledgeOfSignatureConstantTime(proof, revealedMessages, challenge, publicKey, params, encodeMessages);
};

module.exports.bbsChallengeContributionFromProtocol = (
    protocol,
    revealedMessages,
    params,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.bbsChallengeContributionFromProtocol(protocol, revealedMessages, params, encodeMessages);
};

module.exports.bbsChallengeContributionFromProtocolNew = (
    protocol,
    revealedMessages,
    params,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.bbsChallengeContributionFromProtocolNew(protocol, revealedMessages, params, encodeMessages);
};

module.exports.bbsChallengeContributionFromProtocolConstantTime = (
    protocol,
    revealedMessages,
    params,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.bbsChallengeContributionFromProtocolConstantTime(protocol, revealedMessages, params, encodeMessages);
};

module.exports.bbsChallengeContributionFromProof = (
    proof,
    revealedMessages,
    params,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.bbsChallengeContributionFromProof(proof, revealedMessages, params, encodeMessages);
};

module.exports.bbsChallengeContributionFromProofNew = (
    proof,
    revealedMessages,
    params,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.bbsChallengeContributionFromProofNew(proof, revealedMessages, params, encodeMessages);
};

module.exports.bbsChallengeContributionFromProofConstantTime = (
    proof,
    revealedMessages,
    params,
    encodeMessages
) => {
    requireWasmInitialized();
    return wasm.bbsChallengeContributionFromProofConstantTime(proof, revealedMessages, params, encodeMessages);
};

module.exports.bbsAdaptSigParamsForMsgCount = (params, generating_label, new_count) => {
    requireWasmInitialized();
    return wasm.bbsAdaptSigParamsForMsgCount(params, generating_label, new_count);
};
