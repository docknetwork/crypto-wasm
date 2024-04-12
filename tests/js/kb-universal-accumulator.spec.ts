import {
    generateAccumulatorParams,
    generateAccumulatorPublicKey,
    generateAccumulatorSecretKey,
    generateFieldElementFromNumber,
    generateRandomFieldElement,
    IKBUniversalAccumulator,
    initializeWasm,
    kbUniversalAccumulatorAdd,
    kbUniversalAccumulatorComputeExtended,
    kbUniversalAccumulatorInitialise,
    kbUniversalAccumulatorRemove,
    kbUniversalAccumulatorAddBatch,
    kbUniversalAccumulatorBatchUpdates,
    kbUniversalAccumulatorMembershipWitness,
    kbUniversalAccumulatorMembershipWitnessesForBatch,
    kbUniversalAccumulatorNonMembershipWitness,
    kbUniversalAccumulatorNonMembershipWitnessesForBatch,
    kbUniversalAccumulatorRemoveBatch,
    kbUniversalAccumulatorVerifyMembership,
    kbUniversalAccumulatorVerifyNonMembership,
    kbUniversalUpdateMembershipWitnessPostAdd,
    kbUniversalUpdateMembershipWitnessPostRemove,
    kbUniversalUpdateNonMembershipWitnessPostAdd,
    kbUniversalUpdateNonMembershipWitnessPostRemove,
    kbUpdateMembershipWitnessesPostBatchUpdates,
    publicInfoForKBUniversalMemWitnessUpdate,
    publicInfoForKBUniversalNonMemWitnessUpdate,
    updateKBUniversalMembershipWitnessUsingPublicInfoAfterBatchUpdate,
    updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterBatchUpdate,
    updateKBUniversalMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates,
    updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates,
    publicInfoForBothKBUniversalWitnessUpdate,
    kbUpdateNonMembershipWitnessesPostBatchUpdates,
    kbUpdateBothWitnessesPostBatchUpdates,
    kbUpdateNonMembershipWitnessesPostDomainExtension,
    publicInfoForKBUniversalNonMemWitnessUpdateOnDomainExtension,
    updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterDomainExtension,
    updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterMultipleDomainExtensions
} from "../../lib";
import {areUint8ArraysEqual, stringToBytes} from "./util";

describe("For KB universal accumulator", () => {
    let params: Uint8Array,
        sk: Uint8Array,
        pk: Uint8Array,
        accumulator: IKBUniversalAccumulator;
    let domain: Uint8Array[];

    const seed = new Uint8Array([0, 2, 3, 4, 5]);
    const maxSize = 20;

    beforeAll(async () => {
        await initializeWasm();
    });

    it("initialize accumulator", () => {
        params = generateAccumulatorParams();
        sk = generateAccumulatorSecretKey(seed);
        pk = generateAccumulatorPublicKey(sk, params);

        domain = [];
        for (let i = 1; i <= 5; i++) {
            domain.push(generateFieldElementFromNumber(100 + i));
        }

        accumulator = kbUniversalAccumulatorInitialise(domain, sk, params);
        expect(accumulator).toBeInstanceOf(Object);

        const newElements: Uint8Array[] = [];
        for (let i = 106; i <= 120; i++) {
            newElements.push(generateFieldElementFromNumber(100 + i));
        }

        const accumulator1 = kbUniversalAccumulatorComputeExtended(accumulator, newElements, sk);
        expect(accumulator1.mem).toEqual(accumulator.mem);
        expect(accumulator1.non_mem).not.toEqual(accumulator.non_mem);

        accumulator = accumulator1;
        domain.push(...newElements);
    });

    it("add an element", () => {
        let accumulator1 = kbUniversalAccumulatorAdd(accumulator, domain[0], sk);
        expect(accumulator1.mem).not.toEqual(accumulator.mem);
        expect(accumulator1.non_mem).not.toEqual(accumulator.non_mem);

        accumulator1 = kbUniversalAccumulatorAdd(accumulator1, domain[1], sk);
        expect(accumulator1.mem).not.toEqual(accumulator.mem);
        expect(accumulator1.non_mem).not.toEqual(accumulator.non_mem);

        accumulator = accumulator1;
    });

    it("membership and non-membership after single element updates", () => {
        const nonMember = domain[10];

        const e1 = domain[0];
        const e2 = domain[1];

        const accumulator1 = kbUniversalAccumulatorAdd(accumulator, e1, sk);
        const witness1 = kbUniversalAccumulatorMembershipWitness(
            accumulator1,
            e1,
            sk
        );
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator1,
                e1,
                witness1,
                pk,
                params
            )
        ).toBe(true);

        const accumulator2 = kbUniversalAccumulatorAdd(accumulator1, e2, sk);
        const witness2 = kbUniversalAccumulatorMembershipWitness(
            accumulator2,
            e2,
            sk
        );
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator2,
                e2,
                witness2,
                pk,
                params
            )
        ).toBe(true);
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator2,
                e1,
                witness1,
                pk,
                params
            )
        ).toBe(false);

        let accumulator3 = kbUniversalAccumulatorRemove(accumulator2, e2, sk);
        // e2 was added and removed so the accumulator becomes same as before
        expect(accumulator1).toEqual(accumulator3);

        const witness11 = kbUniversalAccumulatorMembershipWitness(
            accumulator3,
            e1,
            sk
        );
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator3,
                e1,
                witness11,
                pk,
                params
            )
        ).toBe(true);

        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator3,
                e1,
                witness1,
                pk,
                params
            )
        ).toBe(true);

        const e3 = domain[2];
        const e4 = domain[3];
        accumulator3 = kbUniversalAccumulatorAdd(accumulator3, e3, sk);
        accumulator3 = kbUniversalAccumulatorAdd(accumulator3, e4, sk);

        const witness = kbUniversalAccumulatorNonMembershipWitness(
            accumulator3,
            nonMember,
            sk
        );
        expect(
            kbUniversalAccumulatorVerifyNonMembership(
                accumulator3,
                nonMember,
                witness,
                pk,
                params
            )
        ).toBe(true);
    });

    it("membership and non-membership after batch updates", () => {
        const nonMember = domain[10];
        let nmWitness = kbUniversalAccumulatorNonMembershipWitness(
            accumulator,
            nonMember,
            sk
        );
        expect(
            kbUniversalAccumulatorVerifyNonMembership(
                accumulator,
                nonMember,
                nmWitness,
                pk,
                params
            )
        ).toBe(true);

        const e1 = domain[0];
        const e2 = domain[1];
        const e3 = domain[2];
        const e4 = domain[3];
        const e5 = domain[4];
        const e6 = domain[5];

        // Add a batch to `accumulator`
        const addBatch = [e1, e2, e3, e4];
        const accumulator1 = kbUniversalAccumulatorAddBatch(
            accumulator,
            addBatch,
            sk
        );

        const witness1 = kbUniversalAccumulatorMembershipWitness(
            accumulator1,
            e1,
            sk
        );
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator1,
                e1,
                witness1,
                pk,
                params
            )
        ).toBe(true);
        const witness2 = kbUniversalAccumulatorMembershipWitness(
            accumulator1,
            e2,
            sk
        );
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator1,
                e2,
                witness2,
                pk,
                params
            )
        ).toBe(true);
        const witness3 = kbUniversalAccumulatorMembershipWitness(
            accumulator1,
            e3,
            sk
        );
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator1,
                e3,
                witness3,
                pk,
                params
            )
        ).toBe(true);
        const witness4 = kbUniversalAccumulatorMembershipWitness(
            accumulator1,
            e4,
            sk
        );
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator1,
                e4,
                witness4,
                pk,
                params
            )
        ).toBe(true);

        nmWitness = kbUniversalAccumulatorNonMembershipWitness(
            accumulator1,
            nonMember,
            sk
        );
        expect(
            kbUniversalAccumulatorVerifyNonMembership(
                accumulator1,
                nonMember,
                nmWitness,
                pk,
                params
            )
        ).toBe(true);

        // Then remove a batch from new `accumulator1`
        const removeBatch = [e1, e3];
        const accumulator2 = kbUniversalAccumulatorRemoveBatch(
            accumulator1,
            removeBatch,
            sk
        );

        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator2,
                e1,
                witness1,
                pk,
                params
            )
        ).toBe(false);
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator2,
                e2,
                witness2,
                pk,
                params
            )
        ).toBe(false);
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator2,
                e3,
                witness3,
                pk,
                params
            )
        ).toBe(false);
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator2,
                e4,
                witness4,
                pk,
                params
            )
        ).toBe(false);

        const witness22 = kbUniversalAccumulatorMembershipWitness(
            accumulator2,
            e2,
            sk
        );
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator2,
                e2,
                witness22,
                pk,
                params
            )
        ).toBe(true);
        const witness42 = kbUniversalAccumulatorMembershipWitness(
            accumulator2,
            e4,
            sk
        );
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator2,
                e4,
                witness42,
                pk,
                params
            )
        ).toBe(true);

        nmWitness = kbUniversalAccumulatorNonMembershipWitness(
            accumulator2,
            nonMember,
            sk
        );
        expect(
            kbUniversalAccumulatorVerifyNonMembership(
                accumulator2,
                nonMember,
                nmWitness,
                pk,
                params
            )
        ).toBe(true);

        // Then add and remove a batch from new `accumulator2`
        const addNewBatch = [e5, e6];
        const removeNewBatch = [e2, e4];
        const accumulator3 = kbUniversalAccumulatorBatchUpdates(
            accumulator2,
            addNewBatch,
            removeNewBatch,
            sk
        );

        const witness5 = kbUniversalAccumulatorMembershipWitness(
            accumulator3,
            e5,
            sk
        );
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator3,
                e5,
                witness5,
                pk,
                params
            )
        ).toBe(true);
        const witness6 = kbUniversalAccumulatorMembershipWitness(
            accumulator3,
            e6,
            sk
        );
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator3,
                e6,
                witness6,
                pk,
                params
            )
        ).toBe(true);

        nmWitness = kbUniversalAccumulatorNonMembershipWitness(
            accumulator3,
            nonMember,
            sk
        );
        expect(
            kbUniversalAccumulatorVerifyNonMembership(
                accumulator3,
                nonMember,
                nmWitness,
                pk,
                params
            )
        ).toBe(true);

        // Add a batch to `accumulator`, remove a batch from `accumulator`, then add a batch and then remove
        let accumulator4 = kbUniversalAccumulatorAddBatch(accumulator, addBatch, sk);
        accumulator4 = kbUniversalAccumulatorRemoveBatch(
            accumulator4,
            removeBatch,
            sk
        );
        accumulator4 = kbUniversalAccumulatorAddBatch(accumulator4, addNewBatch, sk);
        accumulator4 = kbUniversalAccumulatorRemoveBatch(
            accumulator4,
            removeNewBatch,
            sk
        );
        expect(accumulator4).toEqual(accumulator3);
    });

    it("membership and non-membership witnesses for multiple members", () => {
        const e1 = domain[0];
        const e2 = domain[1];
        const e3 = domain[2];

        const batch = [e1, e2, e3];
        const accumulator1 = kbUniversalAccumulatorAddBatch(accumulator, batch, sk);

        const witnesses = kbUniversalAccumulatorMembershipWitnessesForBatch(
            accumulator1,
            batch,
            sk
        );
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator1,
                batch[0],
                witnesses[0],
                pk,
                params
            )
        ).toBe(true);
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator1,
                batch[1],
                witnesses[1],
                pk,
                params
            )
        ).toBe(true);
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator1,
                batch[2],
                witnesses[2],
                pk,
                params
            )
        ).toBe(true);

        let nonMembers = [
            domain[10],
            domain[11],
            domain[12],
        ];
        const nmWitnesses = kbUniversalAccumulatorNonMembershipWitnessesForBatch(
            accumulator1,
            nonMembers,
            sk
        );
        expect(
            kbUniversalAccumulatorVerifyNonMembership(
                accumulator1,
                nonMembers[0],
                nmWitnesses[0],
                pk,
                params
            )
        ).toBe(true);
        expect(
            kbUniversalAccumulatorVerifyNonMembership(
                accumulator1,
                nonMembers[1],
                nmWitnesses[1],
                pk,
                params
            )
        ).toBe(true);
        expect(
            kbUniversalAccumulatorVerifyNonMembership(
                accumulator1,
                nonMembers[2],
                nmWitnesses[2],
                pk,
                params
            )
        ).toBe(true);
    });
});

describe("For KB universal accumulator witness update", () => {
    let params: Uint8Array,
        sk: Uint8Array,
        pk: Uint8Array,
        accumulator: IKBUniversalAccumulator;

    let domain: Uint8Array[];

    beforeAll(async () => {
        await initializeWasm();
    });

    beforeEach(() => {
        params = generateAccumulatorParams();
        sk = generateAccumulatorSecretKey();
        pk = generateAccumulatorPublicKey(sk, params);

        domain = [];
        for (let i = 1; i <= 20; i++) {
            domain.push(generateFieldElementFromNumber(100 + i));
        }

        accumulator = kbUniversalAccumulatorInitialise(domain, sk, params);
    });

    it("after single update", () => {
        const nonMember = domain[10];

        const e1 = domain[0];
        accumulator = kbUniversalAccumulatorAdd(accumulator, e1, sk);
        
        let uniMemWit = kbUniversalAccumulatorMembershipWitness(
            accumulator,
            e1,
            sk
        );
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator,
                e1,
                uniMemWit,
                pk,
                params
            )
        ).toBe(true);

        let nonMemWit = kbUniversalAccumulatorNonMembershipWitness(
            accumulator,
            nonMember,
            sk
        );
        expect(
            kbUniversalAccumulatorVerifyNonMembership(
                accumulator,
                nonMember,
                nonMemWit,
                pk,
                params
            )
        ).toBe(true);

        const e2 = domain[1];

        const accumulator1 = kbUniversalAccumulatorAdd(accumulator, e2, sk);
        
        uniMemWit = kbUniversalUpdateMembershipWitnessPostAdd(
            uniMemWit,
            e1,
            e2,
            accumulator
        );
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator1,
                e1,
                uniMemWit,
                pk,
                params
            )
        ).toBe(true);

        nonMemWit = kbUniversalUpdateNonMembershipWitnessPostAdd(
            nonMemWit,
            nonMember,
            e2,
            accumulator1
        );
        expect(
            kbUniversalAccumulatorVerifyNonMembership(
                accumulator1,
                nonMember,
                nonMemWit,
                pk,
                params
            )
        ).toBe(true);

        const accumulator2 = kbUniversalAccumulatorRemove(accumulator1, e2, sk);
        
        uniMemWit = kbUniversalUpdateMembershipWitnessPostRemove(
            uniMemWit,
            e1,
            e2,
            accumulator2
        );
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator2,
                e1,
                uniMemWit,
                pk,
                params
            )
        ).toBe(true);

        nonMemWit = kbUniversalUpdateNonMembershipWitnessPostRemove(
            nonMemWit,
            nonMember,
            e2,
            accumulator1
        );
        expect(
            kbUniversalAccumulatorVerifyNonMembership(
                accumulator2,
                nonMember,
                nonMemWit,
                pk,
                params
            )
        ).toBe(true);

        accumulator = accumulator2;
    });

    it("by manager after batch updates", () => {
        const nonMember1 = domain[10];
        const nonMember2 = domain[11];
        const member1 = domain[0];
        const member2 = domain[1];

        accumulator = kbUniversalAccumulatorAddBatch(
            accumulator,
            [member1, member2],
            sk
        );
        const memWits = kbUniversalAccumulatorMembershipWitnessesForBatch(
            accumulator,
            [member1, member2],
            sk
        );
        const nonMemWits = kbUniversalAccumulatorNonMembershipWitnessesForBatch(
            accumulator,
            [nonMember1, nonMember2],
            sk
        );

        const member3 = generateRandomFieldElement();
        const member4 = generateRandomFieldElement();

        const accumulator1 = kbUniversalAccumulatorAddBatch(
            accumulator,
            [member3, member4],
            sk
        );

        const newMemWits = kbUpdateMembershipWitnessesPostBatchUpdates(
            memWits,
            [member1, member2],
            [member3, member4],
            [],
            accumulator,
            sk
        );
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator1,
                member1,
                newMemWits[0],
                pk,
                params
            )
        ).toBe(true);
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator1,
                member2,
                newMemWits[1],
                pk,
                params
            )
        ).toBe(true);

        const newNonMemWits = kbUpdateNonMembershipWitnessesPostBatchUpdates(
            nonMemWits,
            [nonMember1, nonMember2],
            [member3, member4],
            [],
            accumulator,
            sk
        );
        expect(
            kbUniversalAccumulatorVerifyNonMembership(
                accumulator1,
                nonMember1,
                newNonMemWits[0],
                pk,
                params
            )
        ).toBe(true);
        expect(
            kbUniversalAccumulatorVerifyNonMembership(
                accumulator1,
                nonMember2,
                newNonMemWits[1],
                pk,
                params
            )
        ).toBe(true);

        const [newMemWits_, newNonMemWits_] = kbUpdateBothWitnessesPostBatchUpdates(memWits, [member1, member2], nonMemWits, [nonMember1, nonMember2], [member3, member4], [], accumulator, sk);
        expect(newMemWits.length).toEqual(newMemWits_.length);
        expect(newNonMemWits.length).toEqual(newNonMemWits_.length);
        for (let i = 0; i < newMemWits.length; i++) {
            expect(areUint8ArraysEqual(newMemWits[i], newMemWits_[i])).toEqual(true);
        }
        for (let i = 0; i < newNonMemWits.length; i++) {
            expect(areUint8ArraysEqual(newNonMemWits[i], newNonMemWits_[i])).toEqual(true);
        }

        const newElements = [generateFieldElementFromNumber(200 + 1), generateFieldElementFromNumber(200 + 2), generateFieldElementFromNumber(200 + 3)];
        const newerNonMemWits = kbUpdateNonMembershipWitnessesPostDomainExtension(newNonMemWits, [nonMember1, nonMember2], newElements, accumulator1, sk);
        const accumulator2 = kbUniversalAccumulatorComputeExtended(accumulator1, newElements, sk);
        expect(
            kbUniversalAccumulatorVerifyNonMembership(
                accumulator2,
                nonMember1,
                newNonMemWits[0],
                pk,
                params
            )
        ).toBe(false);
        expect(
            kbUniversalAccumulatorVerifyNonMembership(
                accumulator2,
                nonMember2,
                newNonMemWits[1],
                pk,
                params
            )
        ).toBe(false);

        expect(
            kbUniversalAccumulatorVerifyNonMembership(
                accumulator2,
                nonMember1,
                newerNonMemWits[0],
                pk,
                params
            )
        ).toBe(true);
        expect(
            kbUniversalAccumulatorVerifyNonMembership(
                accumulator2,
                nonMember2,
                newerNonMemWits[1],
                pk,
                params
            )
        ).toBe(true);

        accumulator = accumulator2;
    });

    it("after batch updates", () => {
        const member = domain[0];
        const nonMember = domain[10];

        accumulator = kbUniversalAccumulatorAdd(accumulator, member, sk);
        
        const uniMemWitInitial = kbUniversalAccumulatorMembershipWitness(
            accumulator,
            member,
            sk
        );
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator,
                member,
                uniMemWitInitial,
                pk,
                params
            )
        ).toBe(true);

        const nonMemWitInitial = kbUniversalAccumulatorNonMembershipWitness(
            accumulator,
            nonMember,
            sk
        );
        expect(
            kbUniversalAccumulatorVerifyNonMembership(
                accumulator,
                nonMember,
                nonMemWitInitial,
                pk,
                params
            )
        ).toBe(true);

        const addBatch0 = [
            domain[1],
            domain[2],
        ];

        const memPublicInfo0 = publicInfoForKBUniversalMemWitnessUpdate(
            accumulator,
            addBatch0,
            [],
            sk
        );
        const nonMemPublicInfo0 = publicInfoForKBUniversalNonMemWitnessUpdate(
            accumulator,
            addBatch0,
            [],
            sk
        );
        let [memPublicInfo_, nonMemPublicInfo_] = publicInfoForBothKBUniversalWitnessUpdate(
            accumulator,
            addBatch0,
            [],
            sk
        );
        expect(areUint8ArraysEqual(memPublicInfo0, memPublicInfo_)).toEqual(true);
        expect(areUint8ArraysEqual(nonMemPublicInfo0, nonMemPublicInfo_)).toEqual(true);

        accumulator = kbUniversalAccumulatorAddBatch(
            accumulator,
            addBatch0,
            sk
        );
        
        let uniMemWit = updateKBUniversalMembershipWitnessUsingPublicInfoAfterBatchUpdate(
            uniMemWitInitial,
            member,
            addBatch0,
            [],
            memPublicInfo0
        );
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator,
                member,
                uniMemWit,
                pk,
                params
            )
        ).toBe(true);

        let nonMemWit = updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterBatchUpdate(
            nonMemWitInitial,
            nonMember,
            addBatch0,
            [],
            nonMemPublicInfo0
        );
        expect(
            kbUniversalAccumulatorVerifyNonMembership(
                accumulator,
                nonMember,
                nonMemWit,
                pk,
                params
            )
        ).toBe(true);

        const addBatch1 = [
            domain[3],
            domain[4],
        ];
        const remBatch1 = addBatch0;

        const memPublicInfo1 = publicInfoForKBUniversalMemWitnessUpdate(
            accumulator,
            addBatch1,
            remBatch1,
            sk
        );
        const nonMemPublicInfo1 = publicInfoForKBUniversalNonMemWitnessUpdate(
            accumulator,
            addBatch1,
            remBatch1,
            sk
        );

        [memPublicInfo_, nonMemPublicInfo_] = publicInfoForBothKBUniversalWitnessUpdate(
            accumulator,
            addBatch1,
            remBatch1,
            sk
        );
        expect(areUint8ArraysEqual(memPublicInfo1, memPublicInfo_)).toEqual(true);
        expect(areUint8ArraysEqual(nonMemPublicInfo1, nonMemPublicInfo_)).toEqual(true);

        accumulator = kbUniversalAccumulatorBatchUpdates(
            accumulator,
            addBatch1,
            remBatch1,
            sk
        );
        
        uniMemWit = updateKBUniversalMembershipWitnessUsingPublicInfoAfterBatchUpdate(
            uniMemWit,
            member,
            addBatch1,
            remBatch1,
            memPublicInfo1
        );
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator,
                member,
                uniMemWit,
                pk,
                params
            )
        ).toBe(true);

        nonMemWit = updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterBatchUpdate(
            nonMemWit,
            nonMember,
            addBatch1,
            remBatch1,
            nonMemPublicInfo1
        );
        expect(
            kbUniversalAccumulatorVerifyNonMembership(
                accumulator,
                nonMember,
                nonMemWit,
                pk,
                params
            )
        ).toBe(true);

        const addBatch2 = [
            domain[5],
            domain[6],
        ];
        const remBatch2 = addBatch1;

        const memPublicInfo2 = publicInfoForKBUniversalMemWitnessUpdate(
            accumulator,
            addBatch2,
            remBatch2,
            sk
        );

        const nonMemPublicInfo2 = publicInfoForKBUniversalNonMemWitnessUpdate(
            accumulator,
            addBatch2,
            remBatch2,
            sk
        );

        accumulator = kbUniversalAccumulatorBatchUpdates(
            accumulator,
            addBatch2,
            remBatch2,
            sk
        );

        uniMemWit = updateKBUniversalMembershipWitnessUsingPublicInfoAfterBatchUpdate(
            uniMemWit,
            member,
            addBatch2,
            remBatch2,
            memPublicInfo2
        );
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator,
                member,
                uniMemWit,
                pk,
                params
            )
        ).toBe(true);

        nonMemWit = updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterBatchUpdate(
            nonMemWit,
            nonMember,
            addBatch2,
            remBatch2,
            nonMemPublicInfo2
        );
        expect(
            kbUniversalAccumulatorVerifyNonMembership(
                accumulator,
                nonMember,
                nonMemWit,
                pk,
                params
            )
        ).toBe(true);


        uniMemWit = updateKBUniversalMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates(
            uniMemWitInitial,
            member,
            [addBatch0, addBatch1, addBatch2],
            [[], remBatch1, remBatch2],
            [memPublicInfo0, memPublicInfo1, memPublicInfo2]
        );
        expect(
            kbUniversalAccumulatorVerifyMembership(
                accumulator,
                member,
                uniMemWit,
                pk,
                params
            )
        ).toBe(true);

        nonMemWit = updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates(
            nonMemWitInitial,
            nonMember,
            [addBatch0, addBatch1, addBatch2],
            [[], remBatch1, remBatch2],
            [nonMemPublicInfo0, nonMemPublicInfo1, nonMemPublicInfo2]
        );
        expect(
            kbUniversalAccumulatorVerifyNonMembership(
                accumulator,
                nonMember,
                nonMemWit,
                pk,
                params
            )
        ).toBe(true);

        const newElements1 = [generateRandomFieldElement(), generateRandomFieldElement(), generateRandomFieldElement()];
        const publicInfo1 = publicInfoForKBUniversalNonMemWitnessUpdateOnDomainExtension(accumulator, newElements1, sk);
        const accumulator1 = kbUniversalAccumulatorComputeExtended(accumulator, newElements1, sk);

        expect(
            kbUniversalAccumulatorVerifyNonMembership(
                accumulator1,
                nonMember,
                nonMemWit,
                pk,
                params
            )
        ).toBe(false);
        nonMemWit = updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterDomainExtension(nonMemWit, nonMember, newElements1, publicInfo1);
        expect(
            kbUniversalAccumulatorVerifyNonMembership(
                accumulator1,
                nonMember,
                nonMemWit,
                pk,
                params
            )
        ).toBe(true);

        const newElements2 = [generateRandomFieldElement(), generateRandomFieldElement(), generateRandomFieldElement()];
        const publicInfo2 = publicInfoForKBUniversalNonMemWitnessUpdateOnDomainExtension(accumulator1, newElements2, sk);
        const accumulator2 = kbUniversalAccumulatorComputeExtended(accumulator1, newElements2, sk);

        const newElements3 = [generateRandomFieldElement(), generateRandomFieldElement()];
        const publicInfo3 = publicInfoForKBUniversalNonMemWitnessUpdateOnDomainExtension(accumulator2, newElements3, sk);
        const accumulator3 = kbUniversalAccumulatorComputeExtended(accumulator2, newElements3, sk);

        const newElements4 = [generateRandomFieldElement(), generateRandomFieldElement(), generateRandomFieldElement(), generateRandomFieldElement()];
        const publicInfo4 = publicInfoForKBUniversalNonMemWitnessUpdateOnDomainExtension(accumulator3, newElements4, sk);
        const accumulator4 = kbUniversalAccumulatorComputeExtended(accumulator3, newElements4, sk);

        expect(
            kbUniversalAccumulatorVerifyNonMembership(
                accumulator4,
                nonMember,
                nonMemWit,
                pk,
                params
            )
        ).toBe(false);
        nonMemWit = updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterMultipleDomainExtensions(nonMemWit, nonMember, [newElements2, newElements3, newElements4], [publicInfo2, publicInfo3, publicInfo4]);
        expect(
            kbUniversalAccumulatorVerifyNonMembership(
                accumulator4,
                nonMember,
                nonMemWit,
                pk,
                params
            )
        ).toBe(true);
    });
});