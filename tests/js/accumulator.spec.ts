import {
    accumulatorGetElementFromBytes,
    generateAccumulatorParams,
    generateAccumulatorPublicKey,
    generateAccumulatorSecretKey,
    generateFieldElementFromNumber,
    generateRandomFieldElement,
    isAccumulatorParamsValid,
    isAccumulatorPublicKeyValid,
    positiveAccumulatorAdd,
    positiveAccumulatorAddBatch,
    positiveAccumulatorBatchUpdates,
    positiveAccumulatorGetAccumulated,
    positiveAccumulatorInitialize,
    positiveAccumulatorMembershipWitness,
    positiveAccumulatorMembershipWitnessesForBatch,
    positiveAccumulatorRemove,
    positiveAccumulatorRemoveBatch,
    positiveAccumulatorVerifyMembership,
    publicInfoForWitnessUpdate,
    universalAccumulatorAdd,
    universalAccumulatorAddBatch,
    universalAccumulatorBatchUpdates,
    universalAccumulatorCombineMultipleD,
    universalAccumulatorCombineMultipleDForBatch,
    universalAccumulatorCombineMultipleInitialFv,
    universalAccumulatorComputeD,
    universalAccumulatorComputeDForBatch,
    universalAccumulatorComputeInitialFv,
    universalAccumulatorGetAccumulated,
    universalAccumulatorInitialiseGivenFv,
    universalAccumulatorMembershipWitness,
    universalAccumulatorMembershipWitnessesForBatch,
    universalAccumulatorNonMembershipWitness,
    universalAccumulatorNonMembershipWitnessesForBatch,
    universalAccumulatorRemove,
    universalAccumulatorRemoveBatch,
    universalAccumulatorVerifyMembership,
    universalAccumulatorVerifyNonMembership,
    updateMembershipWitnessPostAdd,
    updateMembershipWitnessPostRemove,
    updateMembershipWitnessUsingPublicInfoAfterBatchUpdate,
    updateMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates,
    updateNonMembershipWitnessPostAdd,
    updateNonMembershipWitnessPostRemove,
    updateNonMembershipWitnessUsingPublicInfoAfterBatchUpdate,
    updateNonMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates,
    generateMembershipProvingKey,
    generateNonMembershipProvingKey,
    accumulatorInitializeMembershipProof,
    accumulatorGenMembershipProof,
    accumulatorVerifyMembershipProof,
    accumulatorInitializeNonMembershipProof,
    accumulatorGenNonMembershipProof,
    accumulatorVerifyNonMembershipProof,
    generateChallengeFromBytes,
    accumulatorChallengeContributionFromMembershipProtocol,
    accumulatorChallengeContributionFromMembershipProof,
    accumulatorChallengeContributionFromNonMembershipProtocol,
    accumulatorChallengeContributionFromNonMembershipProof
} from "../../lib";

import {AccumulatorParams} from "../../lib/types";

import {stringToBytes} from "../utilities";

describe("For Positive accumulator", () => {
    let params: AccumulatorParams, sk: Uint8Array, pk: Uint8Array, accumulator: Uint8Array;

    const seed = new Uint8Array([0, 2, 3, 4, 5]);

    it("generate params", async () => {
        const params0 = await generateAccumulatorParams();
        expect(params0).toBeInstanceOf(Object);
        expect(await isAccumulatorParamsValid(params0)).toBe(true);

        const label = stringToBytes("Accumulator params");

        const params1 = await generateAccumulatorParams(label);
        expect(params1).toBeInstanceOf(Object);
        expect(await isAccumulatorParamsValid(params1)).toBe(true);

        const params2 = await generateAccumulatorParams(label);
        expect(params2).toBeInstanceOf(Object);
        expect(await isAccumulatorParamsValid(params2)).toBe(true);

        expect(params1).toEqual(params2);

        params = params1;
    });

    it("generate secret key", async () => {
        const sk_ = await generateAccumulatorSecretKey();
        expect(sk_).toBeInstanceOf(Uint8Array);

        const sk1 = await generateAccumulatorSecretKey(seed);
        expect(sk1).toBeInstanceOf(Uint8Array);

        const sk2 = await generateAccumulatorSecretKey(seed);
        expect(sk2).toBeInstanceOf(Uint8Array);

        expect(sk1).toEqual(sk2);

        sk = sk1;
    });

    it("generate public key from secret key", async () => {
        pk = await generateAccumulatorPublicKey(sk, params);
        expect(pk).toBeInstanceOf(Uint8Array);
        expect(await isAccumulatorPublicKeyValid(pk)).toBe(true);
    });

    it("initialize", async () => {
        accumulator = await positiveAccumulatorInitialize(params);
        expect(accumulator).toBeInstanceOf(Uint8Array);
    });

    it("add an element", async () => {
        const e1 = await generateFieldElementFromNumber(1);
        accumulator = await positiveAccumulatorAdd(accumulator, e1, sk);
        expect(accumulator).toBeInstanceOf(Uint8Array);
        const e2 = await generateFieldElementFromNumber(2);
        accumulator = await positiveAccumulatorAdd(accumulator, e2, sk);
        expect(accumulator).toBeInstanceOf(Uint8Array);

        const e3 = await accumulatorGetElementFromBytes(stringToBytes("user-id:1"));
        accumulator = await positiveAccumulatorAdd(accumulator, e3, sk);
        expect(accumulator).toBeInstanceOf(Uint8Array);

        const e4 = await generateRandomFieldElement();
        accumulator = await positiveAccumulatorAdd(accumulator, e4, sk);
        expect(accumulator).toBeInstanceOf(Uint8Array);
    });

    it("membership after single element updates", async () => {
        const e1 = await generateFieldElementFromNumber(101);
        const e2 = await generateFieldElementFromNumber(102);

        const accumulator1 = await positiveAccumulatorAdd(accumulator, e1, sk);
        const witness1 = await positiveAccumulatorMembershipWitness(accumulator1, e1, sk);
        expect(await positiveAccumulatorVerifyMembership(accumulator1, e1, witness1, pk, params)).toBe(true);

        const accumulator2 = await positiveAccumulatorAdd(accumulator1, e2, sk);
        const witness2 = await positiveAccumulatorMembershipWitness(accumulator2, e2, sk);
        expect(await positiveAccumulatorVerifyMembership(accumulator2, e2, witness2, pk, params)).toBe(true);
        expect(await positiveAccumulatorVerifyMembership(accumulator2, e1, witness1, pk, params)).toBe(false);

        const accumulator3 = await positiveAccumulatorRemove(accumulator2, e2, sk);
        // e2 was added and removed so the accumulator becomes same as before
        expect(accumulator1).toEqual(accumulator3);

        const witness11 = await positiveAccumulatorMembershipWitness(accumulator3, e1, sk);
        expect(await positiveAccumulatorVerifyMembership(accumulator3, e1, witness11, pk, params)).toBe(true);

        expect(await positiveAccumulatorVerifyMembership(accumulator3, e1, witness1, pk, params)).toBe(true);
    });

    it("membership after batch updates", async () => {
        const e1 = await generateFieldElementFromNumber(101);
        const e2 = await generateFieldElementFromNumber(102);
        const e3 = await generateFieldElementFromNumber(103);
        const e4 = await generateFieldElementFromNumber(104);
        const e5 = await generateFieldElementFromNumber(105);
        const e6 = await generateFieldElementFromNumber(106);

        // Add a batch to `accumulator`
        const addBatch = [e1, e2, e3, e4];
        const accumulator1 = await positiveAccumulatorAddBatch(accumulator, addBatch, sk);

        const witness1 = await positiveAccumulatorMembershipWitness(accumulator1, e1, sk);
        expect(await positiveAccumulatorVerifyMembership(accumulator1, e1, witness1, pk, params)).toBe(true);
        const witness2 = await positiveAccumulatorMembershipWitness(accumulator1, e2, sk);
        expect(await positiveAccumulatorVerifyMembership(accumulator1, e2, witness2, pk, params)).toBe(true);
        const witness3 = await positiveAccumulatorMembershipWitness(accumulator1, e3, sk);
        expect(await positiveAccumulatorVerifyMembership(accumulator1, e3, witness3, pk, params)).toBe(true);
        const witness4 = await positiveAccumulatorMembershipWitness(accumulator1, e4, sk);
        expect(await positiveAccumulatorVerifyMembership(accumulator1, e4, witness4, pk, params)).toBe(true);

        // Then remove a batch from new `accumulator1`
        const removeBatch = [e1, e3];
        const accumulator2 = await positiveAccumulatorRemoveBatch(accumulator1, removeBatch, sk);

        expect(await positiveAccumulatorVerifyMembership(accumulator2, e1, witness1, pk, params)).toBe(false);
        expect(await positiveAccumulatorVerifyMembership(accumulator2, e2, witness2, pk, params)).toBe(false);
        expect(await positiveAccumulatorVerifyMembership(accumulator2, e3, witness3, pk, params)).toBe(false);
        expect(await positiveAccumulatorVerifyMembership(accumulator2, e4, witness4, pk, params)).toBe(false);

        const witness22 = await positiveAccumulatorMembershipWitness(accumulator2, e2, sk);
        expect(await positiveAccumulatorVerifyMembership(accumulator2, e2, witness22, pk, params)).toBe(true);
        const witness42 = await positiveAccumulatorMembershipWitness(accumulator2, e4, sk);
        expect(await positiveAccumulatorVerifyMembership(accumulator2, e4, witness42, pk, params)).toBe(true);

        // Then add and remove a batch from new `accumulator2`
        const addNewBatch = [e5, e6];
        const removeNewBatch = [e2, e4];
        const accumulator3 = await positiveAccumulatorBatchUpdates(accumulator2, addNewBatch, removeNewBatch, sk);

        const witness5 = await positiveAccumulatorMembershipWitness(accumulator3, e5, sk);
        expect(await positiveAccumulatorVerifyMembership(accumulator3, e5, witness5, pk, params)).toBe(true);
        const witness6 = await positiveAccumulatorMembershipWitness(accumulator3, e6, sk);
        expect(await positiveAccumulatorVerifyMembership(accumulator3, e6, witness6, pk, params)).toBe(true);

        // Add a batch to `accumulator`, remove a batch from `accumulator`, then add a batch and then remove
        let accumulator4 = await positiveAccumulatorAddBatch(accumulator, addBatch, sk);
        accumulator4 = await positiveAccumulatorRemoveBatch(accumulator4, removeBatch, sk);
        accumulator4 = await positiveAccumulatorAddBatch(accumulator4, addNewBatch, sk);
        accumulator4 = await positiveAccumulatorRemoveBatch(accumulator4, removeNewBatch, sk);
        expect(accumulator4).toEqual(accumulator3);
    });

    it("membership witnesses for multiple members", async () => {
        const e1 = await generateFieldElementFromNumber(101);
        const e2 = await generateFieldElementFromNumber(102);
        const e3 = await generateFieldElementFromNumber(103);

        const batch = [e1, e2, e3];
        const accumulator1 = await positiveAccumulatorAddBatch(accumulator, batch, sk);
        const witnesses = await positiveAccumulatorMembershipWitnessesForBatch(accumulator1, batch, sk);
        expect(await positiveAccumulatorVerifyMembership(accumulator1, batch[0], witnesses[0], pk, params)).toBe(true);
        expect(await positiveAccumulatorVerifyMembership(accumulator1, batch[1], witnesses[1], pk, params)).toBe(true);
        expect(await positiveAccumulatorVerifyMembership(accumulator1, batch[2], witnesses[2], pk, params)).toBe(true);
    });
});

describe("For Universal accumulator", () => {
    let params: AccumulatorParams, sk: Uint8Array, pk: Uint8Array, accumulator: Uint8Array;

    const seed = new Uint8Array([0, 2, 3, 4, 5]);
    const maxSize = 20;

    it("initialize", async () => {
        params = await generateAccumulatorParams();
        sk = await generateAccumulatorSecretKey(seed);
        pk = await generateAccumulatorPublicKey(sk, params);

        const initialElements = [
            await generateFieldElementFromNumber(101),
            await generateFieldElementFromNumber(102),
            await generateFieldElementFromNumber(103),
            await generateFieldElementFromNumber(104),
            await generateFieldElementFromNumber(105),
        ];

        const fV = await universalAccumulatorComputeInitialFv(initialElements, sk);

        const fV1 = await universalAccumulatorComputeInitialFv(initialElements.slice(0, 2), sk);
        const fV2 = await universalAccumulatorComputeInitialFv(initialElements.slice(2), sk);
        const combinedFV = await universalAccumulatorCombineMultipleInitialFv([fV1, fV2]);

        expect(combinedFV).toEqual(fV);

        accumulator = await universalAccumulatorInitialiseGivenFv(fV, params, maxSize);
        expect(accumulator).toBeInstanceOf(Object);
    });

    it("add an element", async () => {
        const e1 = await generateFieldElementFromNumber(1);
        let accumulator1 = await universalAccumulatorAdd(accumulator, e1, sk);
        expect(accumulator1).toBeInstanceOf(Object);
        const e2 = await generateFieldElementFromNumber(2);
        accumulator1 = await universalAccumulatorAdd(accumulator1, e2, sk);
        expect(accumulator1).toBeInstanceOf(Object);

        const e3 = await accumulatorGetElementFromBytes(stringToBytes("user-id:1"));
        accumulator1 = await universalAccumulatorAdd(accumulator1, e3, sk);
        expect(accumulator1).toBeInstanceOf(Object);

        const e4 = await generateRandomFieldElement();
        accumulator1 = await universalAccumulatorAdd(accumulator1, e4, sk);
        expect(accumulator1).toBeInstanceOf(Object);
    });

    it("membership and non-membership after single element updates", async () => {
        const nonMember = await generateFieldElementFromNumber(100);

        const e1 = await generateFieldElementFromNumber(101);
        const e2 = await generateFieldElementFromNumber(102);

        const accumulator1 = await universalAccumulatorAdd(accumulator, e1, sk);
        const witness1 = await universalAccumulatorMembershipWitness(accumulator1, e1, sk);
        expect(await universalAccumulatorVerifyMembership(accumulator1, e1, witness1, pk, params)).toBe(true);

        const accumulator2 = await universalAccumulatorAdd(accumulator1, e2, sk);
        const witness2 = await universalAccumulatorMembershipWitness(accumulator2, e2, sk);
        expect(await universalAccumulatorVerifyMembership(accumulator2, e2, witness2, pk, params)).toBe(true);
        expect(await universalAccumulatorVerifyMembership(accumulator2, e1, witness1, pk, params)).toBe(false);

        let accumulator3 = await universalAccumulatorRemove(accumulator2, e2, sk);
        // e2 was added and removed so the accumulator becomes same as before
        expect(accumulator1).toEqual(accumulator3);

        const witness11 = await universalAccumulatorMembershipWitness(accumulator3, e1, sk);
        expect(await universalAccumulatorVerifyMembership(accumulator3, e1, witness11, pk, params)).toBe(true);

        expect(await universalAccumulatorVerifyMembership(accumulator3, e1, witness1, pk, params)).toBe(true);

        const e3 = await generateFieldElementFromNumber(103);
        const e4 = await generateFieldElementFromNumber(104);
        accumulator3 = await universalAccumulatorAdd(accumulator3, e3, sk);
        accumulator3 = await universalAccumulatorAdd(accumulator3, e4, sk);

        const d = await universalAccumulatorComputeD(nonMember, [e1, e3, e4]);
        const witness = await universalAccumulatorNonMembershipWitness(accumulator3, d, nonMember, sk, params);
        expect(await universalAccumulatorVerifyNonMembership(accumulator3, nonMember, witness, pk, params)).toBe(true);

        const d1 = await universalAccumulatorComputeD(nonMember, [e1, e3]);
        const d2 = await universalAccumulatorComputeD(nonMember, [e4]);
        const combinedD = await universalAccumulatorCombineMultipleD([d1, d2]);
        expect(combinedD).toEqual(d);
    });

    it("membership and non-membership after batch updates", async () => {
        const nonMember = await generateFieldElementFromNumber(100);
        let d = await universalAccumulatorComputeD(nonMember, []);
        let nmWitness = await universalAccumulatorNonMembershipWitness(accumulator, d, nonMember, sk, params);
        expect(await universalAccumulatorVerifyNonMembership(accumulator, nonMember, nmWitness, pk, params)).toBe(true);

        const e1 = await generateFieldElementFromNumber(101);
        const e2 = await generateFieldElementFromNumber(102);
        const e3 = await generateFieldElementFromNumber(103);
        const e4 = await generateFieldElementFromNumber(104);
        const e5 = await generateFieldElementFromNumber(105);
        const e6 = await generateFieldElementFromNumber(106);

        // Add a batch to `accumulator`
        const addBatch = [e1, e2, e3, e4];
        const accumulator1 = await universalAccumulatorAddBatch(accumulator, addBatch, sk);

        const witness1 = await universalAccumulatorMembershipWitness(accumulator1, e1, sk);
        expect(await universalAccumulatorVerifyMembership(accumulator1, e1, witness1, pk, params)).toBe(true);
        const witness2 = await universalAccumulatorMembershipWitness(accumulator1, e2, sk);
        expect(await universalAccumulatorVerifyMembership(accumulator1, e2, witness2, pk, params)).toBe(true);
        const witness3 = await universalAccumulatorMembershipWitness(accumulator1, e3, sk);
        expect(await universalAccumulatorVerifyMembership(accumulator1, e3, witness3, pk, params)).toBe(true);
        const witness4 = await universalAccumulatorMembershipWitness(accumulator1, e4, sk);
        expect(await universalAccumulatorVerifyMembership(accumulator1, e4, witness4, pk, params)).toBe(true);

        d = await universalAccumulatorComputeD(nonMember, addBatch);
        nmWitness = await universalAccumulatorNonMembershipWitness(accumulator1, d, nonMember, sk, params);
        expect(await universalAccumulatorVerifyNonMembership(accumulator1, nonMember, nmWitness, pk, params)).toBe(true);

        // Then remove a batch from new `accumulator1`
        const removeBatch = [e1, e3];
        const accumulator2 = await universalAccumulatorRemoveBatch(accumulator1, removeBatch, sk);

        expect(await universalAccumulatorVerifyMembership(accumulator2, e1, witness1, pk, params)).toBe(false);
        expect(await universalAccumulatorVerifyMembership(accumulator2, e2, witness2, pk, params)).toBe(false);
        expect(await universalAccumulatorVerifyMembership(accumulator2, e3, witness3, pk, params)).toBe(false);
        expect(await universalAccumulatorVerifyMembership(accumulator2, e4, witness4, pk, params)).toBe(false);

        const witness22 = await universalAccumulatorMembershipWitness(accumulator2, e2, sk);
        expect(await universalAccumulatorVerifyMembership(accumulator2, e2, witness22, pk, params)).toBe(true);
        const witness42 = await universalAccumulatorMembershipWitness(accumulator2, e4, sk);
        expect(await universalAccumulatorVerifyMembership(accumulator2, e4, witness42, pk, params)).toBe(true);

        d = await universalAccumulatorComputeD(nonMember, [e2, e4]);
        nmWitness = await universalAccumulatorNonMembershipWitness(accumulator2, d, nonMember, sk, params);
        expect(await universalAccumulatorVerifyNonMembership(accumulator2, nonMember, nmWitness, pk, params)).toBe(true);

        // Then add and remove a batch from new `accumulator2`
        const addNewBatch = [e5, e6];
        const removeNewBatch = [e2, e4];
        const accumulator3 = await universalAccumulatorBatchUpdates(accumulator2, addNewBatch, removeNewBatch, sk);

        const witness5 = await universalAccumulatorMembershipWitness(accumulator3, e5, sk);
        expect(await universalAccumulatorVerifyMembership(accumulator3, e5, witness5, pk, params)).toBe(true);
        const witness6 = await universalAccumulatorMembershipWitness(accumulator3, e6, sk);
        expect(await universalAccumulatorVerifyMembership(accumulator3, e6, witness6, pk, params)).toBe(true);

        d = await universalAccumulatorComputeD(nonMember, [e5, e6]);
        nmWitness = await universalAccumulatorNonMembershipWitness(accumulator3, d, nonMember, sk, params);
        expect(await universalAccumulatorVerifyNonMembership(accumulator3, nonMember, nmWitness, pk, params)).toBe(true);

        // Add a batch to `accumulator`, remove a batch from `accumulator`, then add a batch and then remove
        let accumulator4 = await universalAccumulatorAddBatch(accumulator, addBatch, sk);
        accumulator4 = await universalAccumulatorRemoveBatch(accumulator4, removeBatch, sk);
        accumulator4 = await universalAccumulatorAddBatch(accumulator4, addNewBatch, sk);
        accumulator4 = await universalAccumulatorRemoveBatch(accumulator4, removeNewBatch, sk);
        expect(accumulator4).toEqual(accumulator3);
    });

    it("membership and non-membership witnesses for multiple members", async () => {
        const e1 = await generateFieldElementFromNumber(101);
        const e2 = await generateFieldElementFromNumber(102);
        const e3 = await generateFieldElementFromNumber(103);

        const batch = [e1, e2, e3];
        const accumulator1 = await universalAccumulatorAddBatch(accumulator, batch, sk);

        const witnesses = await universalAccumulatorMembershipWitnessesForBatch(accumulator1, batch, sk);
        expect(await universalAccumulatorVerifyMembership(accumulator1, batch[0], witnesses[0], pk, params)).toBe(true);
        expect(await universalAccumulatorVerifyMembership(accumulator1, batch[1], witnesses[1], pk, params)).toBe(true);
        expect(await universalAccumulatorVerifyMembership(accumulator1, batch[2], witnesses[2], pk, params)).toBe(true);

        let nonMembers = [
            await generateFieldElementFromNumber(104),
            await generateFieldElementFromNumber(105),
            await generateFieldElementFromNumber(106),
        ];
        const d = await universalAccumulatorComputeDForBatch(nonMembers, batch);
        const nmWitnesses = await universalAccumulatorNonMembershipWitnessesForBatch(accumulator1, d, nonMembers, sk, params);
        expect(await universalAccumulatorVerifyNonMembership(accumulator1, nonMembers[0], nmWitnesses[0], pk, params)).toBe(true);
        expect(await universalAccumulatorVerifyNonMembership(accumulator1, nonMembers[1], nmWitnesses[1], pk, params)).toBe(true);
        expect(await universalAccumulatorVerifyNonMembership(accumulator1, nonMembers[2], nmWitnesses[2], pk, params)).toBe(true);

        const d1 = await universalAccumulatorComputeDForBatch(nonMembers, [e1, e2]);
        const d2 = await universalAccumulatorComputeDForBatch(nonMembers, [e3]);
        const combinedD = await universalAccumulatorCombineMultipleDForBatch([d1, d2]);
        expect(combinedD).toEqual(d);
    });
});

describe("Witness update", () => {
    let params: AccumulatorParams, sk: Uint8Array, pk: Uint8Array, posAccumulator: Uint8Array,
        uniAccumulator: Uint8Array;

    beforeAll(async () => {
        params = await generateAccumulatorParams();
        sk = await generateAccumulatorSecretKey();
        pk = await generateAccumulatorPublicKey(sk, params);

        posAccumulator = await positiveAccumulatorInitialize(params);

        const initialElements = [
            await generateFieldElementFromNumber(101),
            await generateFieldElementFromNumber(102),
            await generateFieldElementFromNumber(103),
            await generateFieldElementFromNumber(104),
            await generateFieldElementFromNumber(105),
            await generateFieldElementFromNumber(106),
            await generateFieldElementFromNumber(107),
            await generateFieldElementFromNumber(108),
            await generateFieldElementFromNumber(109),
            await generateFieldElementFromNumber(110),
        ];
        const fV = await universalAccumulatorComputeInitialFv(initialElements, sk);
        uniAccumulator = await universalAccumulatorInitialiseGivenFv(fV, params, initialElements.length - 1);
    });

    it("after single update", async () => {
        const nonMember = await generateRandomFieldElement();

        const e1 = await generateFieldElementFromNumber(1);
        posAccumulator = await positiveAccumulatorAdd(posAccumulator, e1, sk);
        uniAccumulator = await universalAccumulatorAdd(uniAccumulator, e1, sk);

        let posMemWit = await positiveAccumulatorMembershipWitness(posAccumulator, e1, sk);
        expect(await positiveAccumulatorVerifyMembership(posAccumulator, e1, posMemWit, pk, params)).toBe(true);

        let uniMemWit = await universalAccumulatorMembershipWitness(uniAccumulator, e1, sk);
        expect(await universalAccumulatorVerifyMembership(uniAccumulator, e1, uniMemWit, pk, params)).toBe(true);

        const d = await universalAccumulatorComputeD(nonMember, [e1]);
        let nonMemWit = await universalAccumulatorNonMembershipWitness(uniAccumulator, d, nonMember, sk, params);
        expect(await universalAccumulatorVerifyNonMembership(uniAccumulator, nonMember, nonMemWit, pk, params)).toBe(true);

        const e2 = await generateFieldElementFromNumber(2);

        const posAccumulator1 = await positiveAccumulatorAdd(posAccumulator, e2, sk);
        const uniAccumulator1 = await universalAccumulatorAdd(uniAccumulator, e2, sk);

        posMemWit = await updateMembershipWitnessPostAdd(posMemWit, e1, e2, await positiveAccumulatorGetAccumulated(posAccumulator));
        expect(await positiveAccumulatorVerifyMembership(posAccumulator1, e1, posMemWit, pk, params)).toBe(true);

        uniMemWit = await updateMembershipWitnessPostAdd(uniMemWit, e1, e2, await universalAccumulatorGetAccumulated(uniAccumulator));
        expect(await universalAccumulatorVerifyMembership(uniAccumulator1, e1, uniMemWit, pk, params)).toBe(true);

        nonMemWit = await updateNonMembershipWitnessPostAdd(nonMemWit, nonMember, e2, await universalAccumulatorGetAccumulated(uniAccumulator));
        expect(await universalAccumulatorVerifyNonMembership(uniAccumulator1, nonMember, nonMemWit, pk, params)).toBe(true);

        const posAccumulator2 = await positiveAccumulatorRemove(posAccumulator1, e2, sk);
        const uniAccumulator2 = await universalAccumulatorRemove(uniAccumulator1, e2, sk);

        posMemWit = await updateMembershipWitnessPostRemove(posMemWit, e1, e2, await positiveAccumulatorGetAccumulated(posAccumulator2));
        expect(await positiveAccumulatorVerifyMembership(posAccumulator2, e1, posMemWit, pk, params)).toBe(true);

        uniMemWit = await updateMembershipWitnessPostRemove(uniMemWit, e1, e2, await universalAccumulatorGetAccumulated(uniAccumulator2));
        expect(await universalAccumulatorVerifyMembership(uniAccumulator2, e1, uniMemWit, pk, params)).toBe(true);

        nonMemWit = await updateNonMembershipWitnessPostRemove(nonMemWit, nonMember, e2, await universalAccumulatorGetAccumulated(uniAccumulator2));
        expect(await universalAccumulatorVerifyNonMembership(uniAccumulator2, nonMember, nonMemWit, pk, params)).toBe(true);
    });

    it("after batch updates", async () => {
        const member = await generateRandomFieldElement();
        const nonMember = await generateRandomFieldElement();

        posAccumulator = await positiveAccumulatorAdd(posAccumulator, member, sk);
        uniAccumulator = await universalAccumulatorAdd(uniAccumulator, member, sk);

        let posMemWitInitial = await positiveAccumulatorMembershipWitness(posAccumulator, member, sk);
        expect(await positiveAccumulatorVerifyMembership(posAccumulator, member, posMemWitInitial, pk, params)).toBe(true);

        const uniMemWitInitial = await universalAccumulatorMembershipWitness(uniAccumulator, member, sk);
        expect(await universalAccumulatorVerifyMembership(uniAccumulator, member, uniMemWitInitial, pk, params)).toBe(true);

        const d = await universalAccumulatorComputeD(nonMember, [member]);
        const nonMemWitInitial = await universalAccumulatorNonMembershipWitness(uniAccumulator, d, nonMember, sk, params);
        expect(await universalAccumulatorVerifyNonMembership(uniAccumulator, nonMember, nonMemWitInitial, pk, params)).toBe(true);

        const addBatch0 = [
            await generateRandomFieldElement(),
            await generateRandomFieldElement()
        ];

        const posPublicInfo0 = await publicInfoForWitnessUpdate(await positiveAccumulatorGetAccumulated(posAccumulator), addBatch0, [], sk);
        const uniPublicInfo0 = await publicInfoForWitnessUpdate(await universalAccumulatorGetAccumulated(uniAccumulator), addBatch0, [], sk);

        posAccumulator = await positiveAccumulatorAddBatch(posAccumulator, addBatch0, sk);
        uniAccumulator = await universalAccumulatorAddBatch(uniAccumulator, addBatch0, sk);

        let posMemWit = await updateMembershipWitnessUsingPublicInfoAfterBatchUpdate(posMemWitInitial, member, addBatch0, [], posPublicInfo0);
        expect(await positiveAccumulatorVerifyMembership(posAccumulator, member, posMemWit, pk, params)).toBe(true);

        let uniMemWit = await updateMembershipWitnessUsingPublicInfoAfterBatchUpdate(uniMemWitInitial, member, addBatch0, [], uniPublicInfo0);
        expect(await universalAccumulatorVerifyMembership(uniAccumulator, member, uniMemWit, pk, params)).toBe(true);

        let nonMemWit = await updateNonMembershipWitnessUsingPublicInfoAfterBatchUpdate(nonMemWitInitial, nonMember, addBatch0, [], uniPublicInfo0);
        expect(await universalAccumulatorVerifyNonMembership(uniAccumulator, nonMember, nonMemWit, pk, params)).toBe(true);

        const addBatch1 = [
            await generateRandomFieldElement(),
            await generateRandomFieldElement()
        ];
        const remBatch1 = addBatch0;

        const posPublicInfo1 = await publicInfoForWitnessUpdate(await positiveAccumulatorGetAccumulated(posAccumulator), addBatch1, remBatch1, sk);
        const uniPublicInfo1 = await publicInfoForWitnessUpdate(await universalAccumulatorGetAccumulated(uniAccumulator), addBatch1, remBatch1, sk);

        posAccumulator = await positiveAccumulatorBatchUpdates(posAccumulator, addBatch1, remBatch1, sk);
        uniAccumulator = await universalAccumulatorBatchUpdates(uniAccumulator, addBatch1, remBatch1, sk);

        posMemWit = await updateMembershipWitnessUsingPublicInfoAfterBatchUpdate(posMemWit, member, addBatch1, remBatch1, posPublicInfo1);
        expect(await positiveAccumulatorVerifyMembership(posAccumulator, member, posMemWit, pk, params)).toBe(true);

        uniMemWit = await updateMembershipWitnessUsingPublicInfoAfterBatchUpdate(uniMemWit, member, addBatch1, remBatch1, uniPublicInfo1);
        expect(await universalAccumulatorVerifyMembership(uniAccumulator, member, uniMemWit, pk, params)).toBe(true);

        nonMemWit = await updateNonMembershipWitnessUsingPublicInfoAfterBatchUpdate(nonMemWit, nonMember, addBatch1, remBatch1, uniPublicInfo1);
        expect(await universalAccumulatorVerifyNonMembership(uniAccumulator, nonMember, nonMemWit, pk, params)).toBe(true);

        const addBatch2 = [
            await generateRandomFieldElement(),
            await generateRandomFieldElement()
        ];
        const remBatch2 = addBatch1;

        const posPublicInfo2 = await publicInfoForWitnessUpdate(await positiveAccumulatorGetAccumulated(posAccumulator), addBatch2, remBatch2, sk);
        const uniPublicInfo2 = await publicInfoForWitnessUpdate(await universalAccumulatorGetAccumulated(uniAccumulator), addBatch2, remBatch2, sk);

        posAccumulator = await positiveAccumulatorBatchUpdates(posAccumulator, addBatch2, remBatch2, sk);
        uniAccumulator = await universalAccumulatorBatchUpdates(uniAccumulator, addBatch2, remBatch2, sk);

        posMemWit = await updateMembershipWitnessUsingPublicInfoAfterBatchUpdate(posMemWit, member, addBatch2, remBatch2, posPublicInfo2);
        expect(await positiveAccumulatorVerifyMembership(posAccumulator, member, posMemWit, pk, params)).toBe(true);

        uniMemWit = await updateMembershipWitnessUsingPublicInfoAfterBatchUpdate(uniMemWit, member, addBatch2, remBatch2, uniPublicInfo2);
        expect(await universalAccumulatorVerifyMembership(uniAccumulator, member, uniMemWit, pk, params)).toBe(true);

        nonMemWit = await updateNonMembershipWitnessUsingPublicInfoAfterBatchUpdate(nonMemWit, nonMember, addBatch2, remBatch2, uniPublicInfo2);
        expect(await universalAccumulatorVerifyNonMembership(uniAccumulator, nonMember, nonMemWit, pk, params)).toBe(true);

        posMemWit = await updateMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates(posMemWitInitial, member, [addBatch0, addBatch1, addBatch2], [[], remBatch1, remBatch2], [posPublicInfo0, posPublicInfo1, posPublicInfo2]);
        expect(await positiveAccumulatorVerifyMembership(posAccumulator, member, posMemWit, pk, params)).toBe(true);

        uniMemWit = await updateMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates(uniMemWitInitial, member, [addBatch0, addBatch1, addBatch2], [[], remBatch1, remBatch2], [uniPublicInfo0, uniPublicInfo1, uniPublicInfo2]);
        expect(await universalAccumulatorVerifyMembership(uniAccumulator, member, uniMemWit, pk, params)).toBe(true);

        nonMemWit = await updateNonMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates(nonMemWitInitial, nonMember, [addBatch0, addBatch1, addBatch2], [[], remBatch1, remBatch2], [uniPublicInfo0, uniPublicInfo1, uniPublicInfo2]);
        expect(await universalAccumulatorVerifyNonMembership(uniAccumulator, nonMember, nonMemWit, pk, params)).toBe(true);
    });
});

describe("Proofs ", () => {
    let params: AccumulatorParams, sk: Uint8Array, pk: Uint8Array, posAccumulator: Uint8Array,
        accumulator: Uint8Array;

    beforeAll(async () => {
        params = await generateAccumulatorParams();
        sk = await generateAccumulatorSecretKey();
        pk = await generateAccumulatorPublicKey(sk, params);

        posAccumulator = await positiveAccumulatorInitialize(params);

        const initialElements = [
            await generateFieldElementFromNumber(101),
            await generateFieldElementFromNumber(102),
            await generateFieldElementFromNumber(103),
            await generateFieldElementFromNumber(104),
            await generateFieldElementFromNumber(105),
            await generateFieldElementFromNumber(106),
            await generateFieldElementFromNumber(107),
            await generateFieldElementFromNumber(108),
            await generateFieldElementFromNumber(109),
            await generateFieldElementFromNumber(110),
        ];
        const fV = await universalAccumulatorComputeInitialFv(initialElements, sk);
        accumulator = await universalAccumulatorInitialiseGivenFv(fV, params, initialElements.length - 1);
    });

    it("for membership", async () => {
        const prk = await generateMembershipProvingKey();
        const member = await generateFieldElementFromNumber(1);

        posAccumulator = await positiveAccumulatorAdd(posAccumulator, member, sk);
        accumulator = await universalAccumulatorAdd(accumulator, member, sk);

        const posMemWit = await positiveAccumulatorMembershipWitness(posAccumulator, member, sk);
        expect(await positiveAccumulatorVerifyMembership(posAccumulator, member, posMemWit, pk, params)).toBe(true);

        const uniMemWit = await universalAccumulatorMembershipWitness(accumulator, member, sk);
        expect(await universalAccumulatorVerifyMembership(accumulator, member, uniMemWit, pk, params)).toBe(true);

        let blinding = await generateRandomFieldElement();
        let protocol = await accumulatorInitializeMembershipProof(member, blinding, posMemWit, pk, params, prk);

        let pBytes = await accumulatorChallengeContributionFromMembershipProtocol(protocol, await positiveAccumulatorGetAccumulated(posAccumulator) , pk, params, prk);
        expect(pBytes).toBeInstanceOf(Uint8Array);
        let proverChallenge = await generateChallengeFromBytes(pBytes);

        let proof = await accumulatorGenMembershipProof(protocol, proverChallenge);

        let vBytes = await accumulatorChallengeContributionFromMembershipProof(proof, await positiveAccumulatorGetAccumulated(posAccumulator) , pk, params, prk) ;
        expect(vBytes).toBeInstanceOf(Uint8Array);
        expect(pBytes).toEqual(vBytes);
        let verifierChallenge = await generateChallengeFromBytes(vBytes);
        expect(proverChallenge).toEqual(verifierChallenge);

        let result = await accumulatorVerifyMembershipProof(proof, await positiveAccumulatorGetAccumulated(posAccumulator), verifierChallenge, pk, params, prk);
        expect(result.verified).toBe(true);

        blinding = await generateRandomFieldElement();
        protocol = await accumulatorInitializeMembershipProof(member, blinding, uniMemWit, pk, params, prk);

        pBytes = await accumulatorChallengeContributionFromMembershipProtocol(protocol, await universalAccumulatorGetAccumulated(accumulator) , pk, params, prk);
        expect(pBytes).toBeInstanceOf(Uint8Array);
        proverChallenge = await generateChallengeFromBytes(pBytes);

        proof = await accumulatorGenMembershipProof(protocol, proverChallenge);

        vBytes = await accumulatorChallengeContributionFromMembershipProof(proof, await universalAccumulatorGetAccumulated(accumulator) , pk, params, prk) ;
        expect(vBytes).toBeInstanceOf(Uint8Array);
        expect(pBytes).toEqual(vBytes);
        verifierChallenge = await generateChallengeFromBytes(vBytes);
        expect(proverChallenge).toEqual(verifierChallenge);

        result = await accumulatorVerifyMembershipProof(proof, await universalAccumulatorGetAccumulated(accumulator), verifierChallenge, pk, params, prk);
        expect(result.verified).toBe(true);
    });

    it("for non-membership", async () => {
        const prk = await generateNonMembershipProvingKey();
        const nonMember = await generateRandomFieldElement();
        const member = await generateRandomFieldElement();

        accumulator = await universalAccumulatorAdd(accumulator, member, sk);

        const d = await universalAccumulatorComputeD(nonMember, [member]);
        const nonMemWit = await universalAccumulatorNonMembershipWitness(accumulator, d, nonMember, sk, params);
        expect(await universalAccumulatorVerifyNonMembership(accumulator, nonMember, nonMemWit, pk, params)).toBe(true);

        const blinding = await generateRandomFieldElement();
        const protocol = await accumulatorInitializeNonMembershipProof(nonMember, blinding, nonMemWit, pk, params, prk);

        const pBytes = await accumulatorChallengeContributionFromNonMembershipProtocol(protocol, await universalAccumulatorGetAccumulated(accumulator) , pk, params, prk);
        expect(pBytes).toBeInstanceOf(Uint8Array);
        const proverChallenge = await generateChallengeFromBytes(pBytes);

        const proof = await accumulatorGenNonMembershipProof(protocol, proverChallenge);

        const vBytes = await accumulatorChallengeContributionFromNonMembershipProof(proof, await universalAccumulatorGetAccumulated(accumulator) , pk, params, prk) ;
        expect(vBytes).toBeInstanceOf(Uint8Array);
        expect(pBytes).toEqual(vBytes);
        const verifierChallenge = await generateChallengeFromBytes(vBytes);
        expect(proverChallenge).toEqual(verifierChallenge);

        const result = await accumulatorVerifyNonMembershipProof(proof, await universalAccumulatorGetAccumulated(accumulator), verifierChallenge, pk, params, prk);
        expect(result.verified).toBe(true);
    });
});