const {
    wasm, initialize
} = require('./init_wasm');

const {
    throwErrorOnRejectedPromise
} = require('./util');

module.exports.generateAccumulatorSecretKey = async (seed) => {
    await initialize();
    return throwErrorOnRejectedPromise(wasm.generateAccumulatorSecretKey(seed));
};

module.exports.generateAccumulatorParams = async (label) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.generateAccumulatorParams(label)
    );
};

module.exports.isAccumulatorParamsValid = async (params) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.isAccumulatorParamsValid(params)
    );
};

module.exports.generateAccumulatorPublicKey = async (secretKey, params) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.generateAccumulatorPublicKey(secretKey, params)
    );
};

module.exports.isAccumulatorPublicKeyValid = async (publicKey) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.isAccumulatorPublicKeyValid(publicKey)
    );
};

module.exports.generateAccumulatorKeyPair = async (params, seed) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.generateAccumulatorKeyPair(params, seed)
    );
};

module.exports.generateFieldElementFromNumber = async (num) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.generateFieldElementFromNumber(num)
    );
};

module.exports.accumulatorGetElementFromBytes = async (bytes) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.accumulatorGetElementFromBytes(bytes)
    );
};

module.exports.positiveAccumulatorInitialize = async (params) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.positiveAccumulatorInitialize(params)
    );
};

module.exports.positiveAccumulatorGetAccumulated = async (accumulator) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.positiveAccumulatorGetAccumulated(accumulator)
    );
};

module.exports.positiveAccumulatorAdd = async (accumulator, element, secretKey) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.positiveAccumulatorAdd(accumulator, element, secretKey)
    );
};

module.exports.positiveAccumulatorRemove = async (accumulator, element, secretKey) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.positiveAccumulatorRemove(accumulator, element, secretKey)
    );
};

module.exports.positiveAccumulatorMembershipWitness = async (accumulator, element, secretKey) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.positiveAccumulatorMembershipWitness(accumulator, element, secretKey)
    );
};

module.exports.positiveAccumulatorVerifyMembership = async (accumulator, element, witness, publicKey, params) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.positiveAccumulatorVerifyMembership(accumulator, element, witness, publicKey, params)
    );
};

module.exports.positiveAccumulatorAddBatch = async (accumulator, elements, secretKey) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.positiveAccumulatorAddBatch(accumulator, elements, secretKey)
    );
};

module.exports.positiveAccumulatorRemoveBatch = async (accumulator, elements, secretKey) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.positiveAccumulatorRemoveBatch(accumulator, elements, secretKey)
    );
};

module.exports.positiveAccumulatorBatchUpdates = async (accumulator, additions, removals, secretKey) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.positiveAccumulatorBatchUpdates(accumulator, additions, removals, secretKey)
    );
};

module.exports.positiveAccumulatorMembershipWitnessesForBatch = async (accumulator, elements, secretKey) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.positiveAccumulatorMembershipWitnessesForBatch(accumulator, elements, secretKey)
    );
};

module.exports.universalAccumulatorComputeInitialFv = async (initialElements, secretKey) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.universalAccumulatorComputeInitialFv(initialElements, secretKey)
    );
};

module.exports.universalAccumulatorCombineMultipleInitialFv = async (initialFVs) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.universalAccumulatorCombineMultipleInitialFv(initialFVs)
    );
};

module.exports.universalAccumulatorInitialiseGivenFv = async (fV, params, maxSize) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.universalAccumulatorInitialiseGivenFv(fV, params, maxSize)
    );
};

module.exports.universalAccumulatorGetAccumulated = async (accumulator) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.universalAccumulatorGetAccumulated(accumulator)
    );
};

module.exports.universalAccumulatorAdd = async (accumulator, element, secretKey) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.universalAccumulatorAdd(accumulator, element, secretKey)
    );
};

module.exports.universalAccumulatorRemove = async (accumulator, element, secretKey) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.universalAccumulatorRemove(accumulator, element, secretKey)
    );
};

module.exports.universalAccumulatorMembershipWitness = async (accumulator, element, secretKey) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.universalAccumulatorMembershipWitness(accumulator, element, secretKey)
    );
};

module.exports.universalAccumulatorVerifyMembership = async (accumulator, element, witness, publicKey, params) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.universalAccumulatorVerifyMembership(accumulator, element, witness, publicKey, params)
    );
};

module.exports.universalAccumulatorComputeD = async (nonMember, members) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.universalAccumulatorComputeD(nonMember, members)
    );
};

module.exports.universalAccumulatorCombineMultipleD = async (d) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.universalAccumulatorCombineMultipleD(d)
    );
};

module.exports.universalAccumulatorNonMembershipWitness = async (accumulator, d, nonMember, secretKey, params) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.universalAccumulatorNonMembershipWitness(accumulator, d, nonMember, secretKey, params)
    );
};

module.exports.universalAccumulatorVerifyNonMembership = async (accumulator, element, witness, publicKey, params) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.universalAccumulatorVerifyNonMembership(accumulator, element, witness, publicKey, params)
    );
};

module.exports.universalAccumulatorAddBatch = async (accumulator, elements, secretKey) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.universalAccumulatorAddBatch(accumulator, elements, secretKey)
    );
};

module.exports.universalAccumulatorRemoveBatch = async (accumulator, elements, secretKey) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.universalAccumulatorRemoveBatch(accumulator, elements, secretKey)
    );
};

module.exports.universalAccumulatorBatchUpdates = async (accumulator, additions, removals, secretKey) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.universalAccumulatorBatchUpdates(accumulator, additions, removals, secretKey)
    );
};

module.exports.universalAccumulatorMembershipWitnessesForBatch = async (accumulator, elements, secretKey) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.universalAccumulatorMembershipWitnessesForBatch(accumulator, elements, secretKey)
    );
};

module.exports.universalAccumulatorComputeDForBatch = async (nonMembers, members) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.universalAccumulatorComputeDForBatch(nonMembers, members)
    );
};

module.exports.universalAccumulatorCombineMultipleDForBatch = async (d) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.universalAccumulatorCombineMultipleDForBatch(d)
    );
};

module.exports.universalAccumulatorNonMembershipWitnessesForBatch = async (accumulator, d, nonMembers, secretKey, params) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.universalAccumulatorNonMembershipWitnessesForBatch(accumulator, d, nonMembers, secretKey, params)
    );
};

module.exports.updateMembershipWitnessPostAdd = async (witness, member, addition, oldAccumulated) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.updateMembershipWitnessPostAdd(witness, member, addition, oldAccumulated)
    );
};

module.exports.updateMembershipWitnessPostRemove = async (witness, member, removal, oldAccumulated) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.updateMembershipWitnessPostRemove(witness, member, removal, oldAccumulated)
    );
};

module.exports.updateNonMembershipWitnessPostAdd = async (witness, member, addition, oldAccumulated) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.updateNonMembershipWitnessPostAdd(witness, member, addition, oldAccumulated)
    );
};

module.exports.updateNonMembershipWitnessPostRemove = async (witness, member, removal, oldAccumulated) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.updateNonMembershipWitnessPostRemove(witness, member, removal, oldAccumulated)
    );
};

module.exports.publicInfoForWitnessUpdate = async (oldAccumulated, additions, removals, secretKey) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.publicInfoForWitnessUpdate(oldAccumulated, additions, removals, secretKey)
    );
};

module.exports.updateMembershipWitnessUsingPublicInfoAfterBatchUpdate = async (witness, member, additions, removals, publicInfo) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.updateMembershipWitnessUsingPublicInfoAfterBatchUpdate(witness, member, additions, removals, publicInfo)
    );
};

module.exports.updateNonMembershipWitnessUsingPublicInfoAfterBatchUpdate = async (witness, nonMember, additions, removals, publicInfo) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.updateNonMembershipWitnessUsingPublicInfoAfterBatchUpdate(witness, nonMember, additions, removals, publicInfo)
    );
};

module.exports.updateMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates = async (witness, member, additions, removals, publicInfo) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.updateMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates(witness, member, additions, removals, publicInfo)
    );
};

module.exports.updateNonMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates = async (witness, nonMember, additions, removals, publicInfo) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.updateNonMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates(witness, nonMember, additions, removals, publicInfo)
    );
};

module.exports.generateMembershipProvingKey = async (label) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.generateMembershipProvingKey(label)
    );
};

module.exports.generateNonMembershipProvingKey = async (label) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.generateNonMembershipProvingKey(label)
    );
};

module.exports.accumulatorDeriveMembershipProvingKeyFromNonMembershipKey = async (key) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.accumulatorDeriveMembershipProvingKeyFromNonMembershipKey(key)
    );
};

module.exports.accumulatorInitializeMembershipProof = async (member, blinding, witness, publicKey, params, provingKey) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.accumulatorInitializeMembershipProof(member, blinding, witness, publicKey, params, provingKey)
    );
};

module.exports.accumulatorGenMembershipProof = async (protocol, challenge) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.accumulatorGenMembershipProof(protocol, challenge)
    );
};

module.exports.accumulatorVerifyMembershipProof = async (proof, accumulated, challenge, publicKey, params, provingKey) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.accumulatorVerifyMembershipProof(proof, accumulated, challenge, publicKey, params, provingKey)
    );
};

module.exports.accumulatorInitializeNonMembershipProof = async (nonMember, blinding, witness, publicKey, params, provingKey) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.accumulatorInitializeNonMembershipProof(nonMember, blinding, witness, publicKey, params, provingKey)
    );
};

module.exports.accumulatorGenNonMembershipProof = async (protocol, challenge) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.accumulatorGenNonMembershipProof(protocol, challenge)
    );
};

module.exports.accumulatorVerifyNonMembershipProof = async (proof, accumulated, challenge, publicKey, params, provingKey) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.accumulatorVerifyNonMembershipProof(proof, accumulated, challenge, publicKey, params, provingKey)
    );
};

module.exports.accumulatorChallengeContributionFromMembershipProtocol = async (protocol, accumulated, publicKey, params, provingKey) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.accumulatorChallengeContributionFromMembershipProtocol(protocol, accumulated, publicKey, params, provingKey)
    );
};

module.exports.accumulatorChallengeContributionFromMembershipProof = async (proof, accumulated, publicKey, params, provingKey) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.accumulatorChallengeContributionFromMembershipProof(proof, accumulated, publicKey, params, provingKey)
    );
};

module.exports.accumulatorChallengeContributionFromNonMembershipProtocol = async (protocol, accumulated, publicKey, params, provingKey) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.accumulatorChallengeContributionFromNonMembershipProtocol(protocol, accumulated, publicKey, params, provingKey)
    );
};

module.exports.accumulatorChallengeContributionFromNonMembershipProof = async (proof, accumulated, publicKey, params, provingKey) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.accumulatorChallengeContributionFromNonMembershipProof(proof, accumulated, publicKey, params, provingKey)
    );
};
