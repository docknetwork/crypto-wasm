const {
    wasm, requireWasmInitialized
} = require('./init_wasm');

module.exports.kbUniversalAccumulatorInitialise = (domain, secretKey, params) => {
    requireWasmInitialized();
    return wasm.kbUniversalAccumulatorInitialise(domain, secretKey, params)
};

module.exports.kbUniversalAccumulatorComputeExtended = (oldAccum, newElements, secretKey) => {
    requireWasmInitialized();
    return wasm.kbUniversalAccumulatorComputeExtended(oldAccum, newElements, secretKey)
};

module.exports.kbUniversalAccumulatorAdd = (accumulator, element, secretKey) => {
    requireWasmInitialized();
    return wasm.kbUniversalAccumulatorAdd(accumulator, element, secretKey)
};

module.exports.kbUniversalAccumulatorRemove = (accumulator, element, secretKey) => {
    requireWasmInitialized();
    return wasm.kbUniversalAccumulatorRemove(accumulator, element, secretKey)
};

module.exports.kbUniversalAccumulatorMembershipWitness = (accumulator, element, secretKey) => {
    requireWasmInitialized();
    return wasm.kbUniversalAccumulatorMembershipWitness(accumulator, element, secretKey)
};

module.exports.kbUniversalAccumulatorVerifyMembership = (accumulator, element, witness, publicKey, params) => {
    requireWasmInitialized();
    return wasm.kbUniversalAccumulatorVerifyMembership(accumulator, element, witness, publicKey, params)
};

module.exports.kbUniversalAccumulatorNonMembershipWitness = (accumulator, element, secretKey) => {
    requireWasmInitialized();
    return wasm.kbUniversalAccumulatorNonMembershipWitness(accumulator, element, secretKey)
};

module.exports.kbUniversalAccumulatorVerifyNonMembership = (accumulator, element, witness, publicKey, params) => {
    requireWasmInitialized();
    return wasm.kbUniversalAccumulatorVerifyNonMembership(accumulator, element, witness, publicKey, params)
};

module.exports.kbUniversalAccumulatorAddBatch = (accumulator, elements, secretKey) => {
    requireWasmInitialized();
    return wasm.kbUniversalAccumulatorAddBatch(accumulator, elements, secretKey)
};

module.exports.kbUniversalAccumulatorRemoveBatch = (accumulator, elements, secretKey) => {
    requireWasmInitialized();
    return wasm.kbUniversalAccumulatorRemoveBatch(accumulator, elements, secretKey)
};

module.exports.kbUniversalAccumulatorBatchUpdates = (accumulator, additions, removals, secretKey) => {
    requireWasmInitialized();
    return wasm.kbUniversalAccumulatorBatchUpdates(accumulator, additions, removals, secretKey)
};

module.exports.kbUniversalAccumulatorMembershipWitnessesForBatch = (accumulator, elements, secretKey) => {
    requireWasmInitialized();
    return wasm.kbUniversalAccumulatorMembershipWitnessesForBatch(accumulator, elements, secretKey)
};

module.exports.kbUniversalAccumulatorNonMembershipWitnessesForBatch = (accumulator, elements, secretKey) => {
    requireWasmInitialized();
    return wasm.kbUniversalAccumulatorNonMembershipWitnessesForBatch(accumulator, elements, secretKey)
};

module.exports.kbUniversalUpdateMembershipWitnessPostAdd = (witness, member, addition, oldAccumulator) => {
    requireWasmInitialized();
    return wasm.kbUniversalUpdateMembershipWitnessPostAdd(witness, member, addition, oldAccumulator)
};

module.exports.kbUniversalUpdateMembershipWitnessPostRemove = (witness, member, removal, oldAccumulator) => {
    requireWasmInitialized();
    return wasm.kbUniversalUpdateMembershipWitnessPostRemove(witness, member, removal, oldAccumulator)
};

module.exports.kbUniversalUpdateNonMembershipWitnessPostAdd = (witness, member, addition, oldAccumulator) => {
    requireWasmInitialized();
    return wasm.kbUniversalUpdateNonMembershipWitnessPostAdd(witness, member, addition, oldAccumulator)
};

module.exports.kbUniversalUpdateNonMembershipWitnessPostRemove = (witness, member, removal, oldAccumulator) => {
    requireWasmInitialized();
    return wasm.kbUniversalUpdateNonMembershipWitnessPostRemove(witness, member, removal, oldAccumulator)
};

module.exports.kbUpdateMembershipWitnessesPostBatchUpdates = (witnesses, members, additions, removals, oldAccumulator, secretKey) => {
    requireWasmInitialized();
    return wasm.kbUpdateMembershipWitnessesPostBatchUpdates(witnesses, members, additions, removals, oldAccumulator, secretKey)
};

module.exports.kbUpdateNonMembershipWitnessesPostBatchUpdates = (witnesses, nonMembers, additions, removals, oldAccumulator, secretKey) => {
    requireWasmInitialized();
    return wasm.kbUpdateNonMembershipWitnessesPostBatchUpdates(witnesses, nonMembers, additions, removals, oldAccumulator, secretKey)
};

module.exports.kbUpdateBothWitnessesPostBatchUpdates = (memWitnesses, members, nonMemWitnesses, nonMembers, additions, removals, oldAccumulator, secretKey) => {
    requireWasmInitialized();
    return wasm.kbUpdateBothWitnessesPostBatchUpdates(memWitnesses, members, nonMemWitnesses, nonMembers, additions, removals, oldAccumulator, secretKey)
};

module.exports.publicInfoForKBUniversalMemWitnessUpdate = (oldAccumulator, additions, removals, secretKey) => {
    requireWasmInitialized();
    return wasm.publicInfoForKBUniversalMemWitnessUpdate(oldAccumulator, additions, removals, secretKey)
};

module.exports.publicInfoForKBUniversalNonMemWitnessUpdate = (oldAccumulator, additions, removals, secretKey) => {
    requireWasmInitialized();
    return wasm.publicInfoForKBUniversalNonMemWitnessUpdate(oldAccumulator, additions, removals, secretKey)
};

module.exports.publicInfoForBothKBUniversalWitnessUpdate = (oldAccumulator, additions, removals, secretKey) => {
    requireWasmInitialized();
    return wasm.publicInfoForBothKBUniversalWitnessUpdate(oldAccumulator, additions, removals, secretKey)
};

module.exports.updateKBUniversalMembershipWitnessUsingPublicInfoAfterBatchUpdate = (witness, member, additions, removals, publicInfo) => {
    requireWasmInitialized();
    return wasm.updateKBUniversalMembershipWitnessUsingPublicInfoAfterBatchUpdate(witness, member, additions, removals, publicInfo)
};

module.exports.updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterBatchUpdate = (witness, nonMember, additions, removals, publicInfo) => {
    requireWasmInitialized();
    return wasm.updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterBatchUpdate(witness, nonMember, additions, removals, publicInfo)
};

module.exports.updateKBUniversalMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates = (witness, member, additions, removals, publicInfo) => {
    requireWasmInitialized();
    return wasm.updateKBUniversalMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates(witness, member, additions, removals, publicInfo)
};

module.exports.updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates = (witness, nonMember, additions, removals, publicInfo) => {
    requireWasmInitialized();
    return wasm.updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates(witness, nonMember, additions, removals, publicInfo)
};