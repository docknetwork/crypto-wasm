const {
    wasm, requireWasmInitialized
} = require('./init_wasm');

module.exports.generateGadgetVectorForThresholdSig = (label) => {
    requireWasmInitialized();
    return wasm.generateGadgetVectorForThresholdSig(label);
};

module.exports.startBaseOTPhase = (participantId, others, pkBase, numBaseOt) => {
    requireWasmInitialized();
    return wasm.startBaseOTPhase(participantId, others, pkBase, numBaseOt);
};

module.exports.baseOTPhaseProcessSenderPubkey = (baseOTPhase, senderId, publicKeyAndProof, pkBase) => {
    requireWasmInitialized();
    return wasm.baseOTPhaseProcessSenderPubkey(baseOTPhase, senderId, publicKeyAndProof, pkBase);
};

module.exports.baseOTPhaseProcessReceiverPubkey = (baseOTPhase, receiverId, publicKey, pkBase) => {
    requireWasmInitialized();
    return wasm.baseOTPhaseProcessReceiverPubkey(baseOTPhase, receiverId, publicKey, pkBase);
};

module.exports.baseOTPhaseProcessChallenges = (baseOTPhase, senderId, challenges) => {
    requireWasmInitialized();
    return wasm.baseOTPhaseProcessChallenges(baseOTPhase, senderId, challenges);
};

module.exports.baseOTPhaseProcessResponses = (baseOTPhase, senderId, responses) => {
    requireWasmInitialized();
    return wasm.baseOTPhaseProcessResponses(baseOTPhase, senderId, responses);
};

module.exports.baseOTPhaseProcessHashedKeys = (baseOTPhase, senderId, hashedKeys) => {
    requireWasmInitialized();
    return wasm.baseOTPhaseProcessHashedKeys(baseOTPhase, senderId, hashedKeys);
};

module.exports.baseOTPhaseFinish = (baseOTPhase) => {
    requireWasmInitialized();
    return wasm.baseOTPhaseFinish(baseOTPhase);
};

module.exports.baseOTOutputCheck = (baseOTOutputs) => {
    requireWasmInitialized();
    return wasm.baseOTOutputCheck(baseOTOutputs);
};

// Following are for BBS+

module.exports.thresholdBbsPlusStartPhase1 = (sigBatchSize, participantId, others, protocolId) => {
    requireWasmInitialized();
    return wasm.thresholdBbsPlusStartPhase1(sigBatchSize, participantId, others, protocolId);
};

module.exports.thresholdBbsPlusPhase1ProcessCommitments = (phase1, senderId, commitments, commitmentsZeroShare) => {
    requireWasmInitialized();
    return wasm.thresholdBbsPlusPhase1ProcessCommitments(phase1, senderId, commitments, commitmentsZeroShare);
};

module.exports.thresholdBbsPlusPhase1GetSharesForOther = (phase1, otherId) => {
    requireWasmInitialized();
    return wasm.thresholdBbsPlusPhase1GetSharesForOther(phase1, otherId);
};

module.exports.thresholdBbsPlusPhase1GetSharesForOthers = (phase1, otherIds) => {
    requireWasmInitialized();
    return wasm.thresholdBbsPlusPhase1GetSharesForOthers(phase1, otherIds);
};

module.exports.thresholdBbsPlusPhase1ProcessShares = (phase1, senderId, shares, zeroShares) => {
    requireWasmInitialized();
    return wasm.thresholdBbsPlusPhase1ProcessShares(phase1, senderId, shares, zeroShares);
};

module.exports.thresholdBbsPlusPhase1Finish = (phase1, secretKey) => {
    requireWasmInitialized();
    return wasm.thresholdBbsPlusPhase1Finish(phase1, secretKey);
};

module.exports.thresholdBbsPlusPhase2Start = (participantId, others, phase1Output, baseOTOutput, gadgetVector) => {
    requireWasmInitialized();
    return wasm.thresholdBbsPlusPhase2Start(participantId, others, phase1Output, baseOTOutput, gadgetVector);
};

module.exports.thresholdBbsPlusPhase2ReceiveMessage1 = (phase2, senderId, message, gadgetVector) => {
    requireWasmInitialized();
    return wasm.thresholdBbsPlusPhase2ReceiveMessage1(phase2, senderId, message, gadgetVector);
};

module.exports.thresholdBbsPlusPhase2ReceiveMessage2 = (phase2, senderId, message, gadgetVector) => {
    requireWasmInitialized();
    return wasm.thresholdBbsPlusPhase2ReceiveMessage2(phase2, senderId, message, gadgetVector);
};

module.exports.thresholdBbsPlusPhase2Finish = (phase2) => {
    requireWasmInitialized();
    return wasm.thresholdBbsPlusPhase2Finish(phase2);
};

module.exports.thresholdBbsPlusCreateSignatureShare = (messages, indexInOutput, phase1Output, phase2Output, params, encodeMessages) => {
    requireWasmInitialized();
    return wasm.thresholdBbsPlusCreateSignatureShare(messages, indexInOutput, phase1Output, phase2Output, params, encodeMessages);
};

module.exports.thresholdBbsPlusAggregateSignatureShares = (shares) => {
    requireWasmInitialized();
    return wasm.thresholdBbsPlusAggregateSignatureShares(shares);
};

// Following are for BBS

module.exports.thresholdBbsStartPhase1 = (sigBatchSize, participantId, others, protocolId) => {
    requireWasmInitialized();
    return wasm.thresholdBbsStartPhase1(sigBatchSize, participantId, others, protocolId);
};

module.exports.thresholdBbsPhase1ProcessCommitments = (phase1, senderId, commitments, commitmentsZeroShare) => {
    requireWasmInitialized();
    return wasm.thresholdBbsPhase1ProcessCommitments(phase1, senderId, commitments, commitmentsZeroShare);
};

module.exports.thresholdBbsPhase1GetSharesForOther = (phase1, otherId) => {
    requireWasmInitialized();
    return wasm.thresholdBbsPhase1GetSharesForOther(phase1, otherId);
};

module.exports.thresholdBbsPhase1GetSharesForOthers = (phase1, otherIds) => {
    requireWasmInitialized();
    return wasm.thresholdBbsPhase1GetSharesForOthers(phase1, otherIds);
};

module.exports.thresholdBbsPhase1ProcessShares = (phase1, senderId, shares, zeroShares) => {
    requireWasmInitialized();
    return wasm.thresholdBbsPhase1ProcessShares(phase1, senderId, shares, zeroShares);
};

module.exports.thresholdBbsPhase1Finish = (phase1, secretKey) => {
    requireWasmInitialized();
    return wasm.thresholdBbsPhase1Finish(phase1, secretKey);
};

module.exports.thresholdBbsPhase2Start = (participantId, others, phase1Output, baseOTOutput, gadgetVector) => {
    requireWasmInitialized();
    return wasm.thresholdBbsPhase2Start(participantId, others, phase1Output, baseOTOutput, gadgetVector);
};

module.exports.thresholdBbsPhase2ReceiveMessage1 = (phase2, senderId, message, gadgetVector) => {
    requireWasmInitialized();
    return wasm.thresholdBbsPhase2ReceiveMessage1(phase2, senderId, message, gadgetVector);
};

module.exports.thresholdBbsPhase2ReceiveMessage2 = (phase2, senderId, message, gadgetVector) => {
    requireWasmInitialized();
    return wasm.thresholdBbsPhase2ReceiveMessage2(phase2, senderId, message, gadgetVector);
};

module.exports.thresholdBbsPhase2Finish = (phase2) => {
    requireWasmInitialized();
    return wasm.thresholdBbsPhase2Finish(phase2);
};

module.exports.thresholdBbsCreateSignatureShare = (messages, indexInOutput, phase1Output, phase2Output, params, encodeMessages) => {
    requireWasmInitialized();
    return wasm.thresholdBbsCreateSignatureShare(messages, indexInOutput, phase1Output, phase2Output, params, encodeMessages);
};

module.exports.thresholdBbsAggregateSignatureShares = (shares) => {
    requireWasmInitialized();
    return wasm.thresholdBbsAggregateSignatureShares(shares);
};