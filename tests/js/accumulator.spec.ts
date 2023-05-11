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
  accumulatorChallengeContributionFromNonMembershipProof,
  IUniversalAccumulator,
  initializeWasm,
  updateMembershipWitnessesPostBatchUpdates,
  universalAccumulatorFixedInitialElements,
} from "../../lib";

import { stringToBytes } from "../utilities";

describe("For Positive accumulator", () => {
  let params: Uint8Array,
    sk: Uint8Array,
    pk: Uint8Array,
    accumulator: Uint8Array;

  const seed = new Uint8Array([0, 2, 3, 4, 5]);

  beforeAll(async () => {
    await initializeWasm();
  });

  it("generate params", () => {
    const params0 = generateAccumulatorParams();
    expect(isAccumulatorParamsValid(params0)).toBe(true);

    const label = stringToBytes("Accumulator params");

    const params1 = generateAccumulatorParams(label);
    expect(isAccumulatorParamsValid(params1)).toBe(true);

    const params2 = generateAccumulatorParams(label);
    expect(isAccumulatorParamsValid(params2)).toBe(true);

    expect(params1).toEqual(params2);

    params = params1;
  });

  it("generate secret key", () => {
    const sk_ = generateAccumulatorSecretKey();
    expect(sk_).toBeInstanceOf(Array);

    const sk1 = generateAccumulatorSecretKey(seed);
    expect(sk1).toBeInstanceOf(Array);

    const sk2 = generateAccumulatorSecretKey(seed);
    expect(sk2).toBeInstanceOf(Array);

    expect(sk1).toEqual(sk2);

    sk = sk1;
  });

  it("generate public key from secret key", () => {
    pk = generateAccumulatorPublicKey(sk, params);
    expect(pk).toBeInstanceOf(Uint8Array);
    expect(isAccumulatorPublicKeyValid(pk)).toBe(true);
  });

  it("initialize", () => {
    accumulator = positiveAccumulatorInitialize(params);
    expect(accumulator).toBeInstanceOf(Array);
  });

  it("add an element", () => {
    const e1 = generateFieldElementFromNumber(1);
    accumulator = positiveAccumulatorAdd(accumulator, e1, sk);
    expect(accumulator).toBeInstanceOf(Array);
    const e2 = generateFieldElementFromNumber(2);
    accumulator = positiveAccumulatorAdd(accumulator, e2, sk);
    expect(accumulator).toBeInstanceOf(Array);

    const e3 = accumulatorGetElementFromBytes(stringToBytes("user-id:1"));
    accumulator = positiveAccumulatorAdd(accumulator, e3, sk);
    expect(accumulator).toBeInstanceOf(Array);

    const e4 = generateRandomFieldElement();
    accumulator = positiveAccumulatorAdd(accumulator, e4, sk);
    expect(accumulator).toBeInstanceOf(Array);
  });

  it("membership after single element updates", () => {
    const e1 = generateFieldElementFromNumber(101);
    const e2 = generateFieldElementFromNumber(102);

    const accumulator1 = positiveAccumulatorAdd(accumulator, e1, sk);
    const witness1 = positiveAccumulatorMembershipWitness(accumulator1, e1, sk);
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(accumulator1),
        e1,
        witness1,
        pk,
        params
      )
    ).toBe(true);

    const accumulator2 = positiveAccumulatorAdd(accumulator1, e2, sk);
    const witness2 = positiveAccumulatorMembershipWitness(accumulator2, e2, sk);
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(accumulator2),
        e2,
        witness2,
        pk,
        params
      )
    ).toBe(true);
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(accumulator2),
        e1,
        witness1,
        pk,
        params
      )
    ).toBe(false);

    const accumulator3 = positiveAccumulatorRemove(accumulator2, e2, sk);
    // e2 was added and removed so the accumulator becomes same as before
    expect(accumulator1).toEqual(accumulator3);

    const witness11 = positiveAccumulatorMembershipWitness(
      accumulator3,
      e1,
      sk
    );
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(accumulator3),
        e1,
        witness11,
        pk,
        params
      )
    ).toBe(true);

    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(accumulator3),
        e1,
        witness1,
        pk,
        params
      )
    ).toBe(true);
  });

  it("membership after batch updates", () => {
    const e1 = generateFieldElementFromNumber(101);
    const e2 = generateFieldElementFromNumber(102);
    const e3 = generateFieldElementFromNumber(103);
    const e4 = generateFieldElementFromNumber(104);
    const e5 = generateFieldElementFromNumber(105);
    const e6 = generateFieldElementFromNumber(106);

    // Add a batch to `accumulator`
    const addBatch = [e1, e2, e3, e4];
    const accumulator1 = positiveAccumulatorAddBatch(accumulator, addBatch, sk);

    const witness1 = positiveAccumulatorMembershipWitness(accumulator1, e1, sk);
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(accumulator1),
        e1,
        witness1,
        pk,
        params
      )
    ).toBe(true);
    const witness2 = positiveAccumulatorMembershipWitness(accumulator1, e2, sk);
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(accumulator1),
        e2,
        witness2,
        pk,
        params
      )
    ).toBe(true);
    const witness3 = positiveAccumulatorMembershipWitness(accumulator1, e3, sk);
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(accumulator1),
        e3,
        witness3,
        pk,
        params
      )
    ).toBe(true);
    const witness4 = positiveAccumulatorMembershipWitness(accumulator1, e4, sk);
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(accumulator1),
        e4,
        witness4,
        pk,
        params
      )
    ).toBe(true);

    // Then remove a batch from new `accumulator1`
    const removeBatch = [e1, e3];
    const accumulator2 = positiveAccumulatorRemoveBatch(
      accumulator1,
      removeBatch,
      sk
    );

    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(accumulator2),
        e1,
        witness1,
        pk,
        params
      )
    ).toBe(false);
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(accumulator2),
        e2,
        witness2,
        pk,
        params
      )
    ).toBe(false);
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(accumulator2),
        e3,
        witness3,
        pk,
        params
      )
    ).toBe(false);
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(accumulator2),
        e4,
        witness4,
        pk,
        params
      )
    ).toBe(false);

    const witness22 = positiveAccumulatorMembershipWitness(
      accumulator2,
      e2,
      sk
    );
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(accumulator2),
        e2,
        witness22,
        pk,
        params
      )
    ).toBe(true);
    const witness42 = positiveAccumulatorMembershipWitness(
      accumulator2,
      e4,
      sk
    );
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(accumulator2),
        e4,
        witness42,
        pk,
        params
      )
    ).toBe(true);

    // Then add and remove a batch from new `accumulator2`
    const addNewBatch = [e5, e6];
    const removeNewBatch = [e2, e4];
    const accumulator3 = positiveAccumulatorBatchUpdates(
      accumulator2,
      addNewBatch,
      removeNewBatch,
      sk
    );

    const witness5 = positiveAccumulatorMembershipWitness(accumulator3, e5, sk);
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(accumulator3),
        e5,
        witness5,
        pk,
        params
      )
    ).toBe(true);
    const witness6 = positiveAccumulatorMembershipWitness(accumulator3, e6, sk);
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(accumulator3),
        e6,
        witness6,
        pk,
        params
      )
    ).toBe(true);

    // Add a batch to `accumulator`, remove a batch from `accumulator`, then add a batch and then remove
    let accumulator4 = positiveAccumulatorAddBatch(accumulator, addBatch, sk);
    accumulator4 = positiveAccumulatorRemoveBatch(
      accumulator4,
      removeBatch,
      sk
    );
    accumulator4 = positiveAccumulatorAddBatch(accumulator4, addNewBatch, sk);
    accumulator4 = positiveAccumulatorRemoveBatch(
      accumulator4,
      removeNewBatch,
      sk
    );
    expect(accumulator4).toEqual(accumulator3);
  });

  it("membership witnesses for multiple members", () => {
    const e1 = generateFieldElementFromNumber(101);
    const e2 = generateFieldElementFromNumber(102);
    const e3 = generateFieldElementFromNumber(103);

    const batch = [e1, e2, e3];
    const accumulator1 = positiveAccumulatorAddBatch(accumulator, batch, sk);
    const witnesses = positiveAccumulatorMembershipWitnessesForBatch(
      accumulator1,
      batch,
      sk
    );
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(accumulator1),
        batch[0],
        witnesses[0],
        pk,
        params
      )
    ).toBe(true);
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(accumulator1),
        batch[1],
        witnesses[1],
        pk,
        params
      )
    ).toBe(true);
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(accumulator1),
        batch[2],
        witnesses[2],
        pk,
        params
      )
    ).toBe(true);
  });
});

describe("For Universal accumulator", () => {
  let params: Uint8Array,
    sk: Uint8Array,
    pk: Uint8Array,
    accumulator: IUniversalAccumulator;

  const seed = new Uint8Array([0, 2, 3, 4, 5]);
  const maxSize = 20;

  beforeAll(async () => {
    await initializeWasm();
  });

  it("initialize accumulator", () => {
    params = generateAccumulatorParams();
    sk = generateAccumulatorSecretKey(seed);
    pk = generateAccumulatorPublicKey(sk, params);

    const fixedInitial = universalAccumulatorFixedInitialElements();

    const initialElements = [
      generateFieldElementFromNumber(101),
      generateFieldElementFromNumber(102),
      generateFieldElementFromNumber(103),
      generateFieldElementFromNumber(104),
      generateFieldElementFromNumber(105),
    ];

    const allInitial = fixedInitial.concat(initialElements);

    const fV = universalAccumulatorComputeInitialFv(allInitial, sk);

    const fV0 = universalAccumulatorComputeInitialFv(fixedInitial, sk);
    const fV1 = universalAccumulatorComputeInitialFv(
      initialElements.slice(0, 2),
      sk
    );
    const fV2 = universalAccumulatorComputeInitialFv(
      initialElements.slice(2),
      sk
    );
    const combinedFV = universalAccumulatorCombineMultipleInitialFv([
      fV0,
      fV1,
      fV2,
    ]);

    expect(combinedFV).toEqual(fV);

    accumulator = universalAccumulatorInitialiseGivenFv(fV, params, maxSize);
    expect(accumulator).toBeInstanceOf(Object);
  });

  it("add an element", () => {
    const e1 = generateFieldElementFromNumber(1);
    let accumulator1 = universalAccumulatorAdd(accumulator, e1, sk);
    expect(accumulator1).toBeInstanceOf(Object);
    const e2 = generateFieldElementFromNumber(2);
    accumulator1 = universalAccumulatorAdd(accumulator1, e2, sk);
    expect(accumulator1).toBeInstanceOf(Object);

    const e3 = accumulatorGetElementFromBytes(stringToBytes("user-id:1"));
    accumulator1 = universalAccumulatorAdd(accumulator1, e3, sk);
    expect(accumulator1).toBeInstanceOf(Object);

    const e4 = generateRandomFieldElement();
    accumulator1 = universalAccumulatorAdd(accumulator1, e4, sk);
    expect(accumulator1).toBeInstanceOf(Object);
  });

  it("membership and non-membership after single element updates", () => {
    const nonMember = generateFieldElementFromNumber(100);

    const e1 = generateFieldElementFromNumber(101);
    const e2 = generateFieldElementFromNumber(102);

    const accumulator1 = universalAccumulatorAdd(accumulator, e1, sk);
    const witness1 = universalAccumulatorMembershipWitness(
      accumulator1,
      e1,
      sk
    );
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(accumulator1),
        e1,
        witness1,
        pk,
        params
      )
    ).toBe(true);

    const accumulator2 = universalAccumulatorAdd(accumulator1, e2, sk);
    const witness2 = universalAccumulatorMembershipWitness(
      accumulator2,
      e2,
      sk
    );
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(accumulator2),
        e2,
        witness2,
        pk,
        params
      )
    ).toBe(true);
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(accumulator2),
        e1,
        witness1,
        pk,
        params
      )
    ).toBe(false);

    let accumulator3 = universalAccumulatorRemove(accumulator2, e2, sk);
    // e2 was added and removed so the accumulator becomes same as before
    expect(accumulator1).toEqual(accumulator3);

    const witness11 = universalAccumulatorMembershipWitness(
      accumulator3,
      e1,
      sk
    );
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(accumulator3),
        e1,
        witness11,
        pk,
        params
      )
    ).toBe(true);

    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(accumulator3),
        e1,
        witness1,
        pk,
        params
      )
    ).toBe(true);

    const e3 = generateFieldElementFromNumber(103);
    const e4 = generateFieldElementFromNumber(104);
    accumulator3 = universalAccumulatorAdd(accumulator3, e3, sk);
    accumulator3 = universalAccumulatorAdd(accumulator3, e4, sk);

    const d = universalAccumulatorComputeD(nonMember, [e1, e3, e4]);
    const witness = universalAccumulatorNonMembershipWitness(
      accumulator3,
      d,
      nonMember,
      sk,
      params
    );
    expect(
      universalAccumulatorVerifyNonMembership(
        universalAccumulatorGetAccumulated(accumulator3),
        nonMember,
        witness,
        pk,
        params
      )
    ).toBe(true);

    const d1 = universalAccumulatorComputeD(nonMember, [e1, e3]);
    const d2 = universalAccumulatorComputeD(nonMember, [e4]);
    const combinedD = universalAccumulatorCombineMultipleD([d1, d2]);
    expect(combinedD).toEqual(d);
  });

  it("membership and non-membership after batch updates", () => {
    const nonMember = generateFieldElementFromNumber(100);
    let d = universalAccumulatorComputeD(nonMember, []);
    let nmWitness = universalAccumulatorNonMembershipWitness(
      accumulator,
      d,
      nonMember,
      sk,
      params
    );
    expect(
      universalAccumulatorVerifyNonMembership(
        universalAccumulatorGetAccumulated(accumulator),
        nonMember,
        nmWitness,
        pk,
        params
      )
    ).toBe(true);

    const e1 = generateFieldElementFromNumber(101);
    const e2 = generateFieldElementFromNumber(102);
    const e3 = generateFieldElementFromNumber(103);
    const e4 = generateFieldElementFromNumber(104);
    const e5 = generateFieldElementFromNumber(105);
    const e6 = generateFieldElementFromNumber(106);

    // Add a batch to `accumulator`
    const addBatch = [e1, e2, e3, e4];
    const accumulator1 = universalAccumulatorAddBatch(
      accumulator,
      addBatch,
      sk
    );

    const witness1 = universalAccumulatorMembershipWitness(
      accumulator1,
      e1,
      sk
    );
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(accumulator1),
        e1,
        witness1,
        pk,
        params
      )
    ).toBe(true);
    const witness2 = universalAccumulatorMembershipWitness(
      accumulator1,
      e2,
      sk
    );
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(accumulator1),
        e2,
        witness2,
        pk,
        params
      )
    ).toBe(true);
    const witness3 = universalAccumulatorMembershipWitness(
      accumulator1,
      e3,
      sk
    );
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(accumulator1),
        e3,
        witness3,
        pk,
        params
      )
    ).toBe(true);
    const witness4 = universalAccumulatorMembershipWitness(
      accumulator1,
      e4,
      sk
    );
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(accumulator1),
        e4,
        witness4,
        pk,
        params
      )
    ).toBe(true);

    d = universalAccumulatorComputeD(nonMember, addBatch);
    nmWitness = universalAccumulatorNonMembershipWitness(
      accumulator1,
      d,
      nonMember,
      sk,
      params
    );
    expect(
      universalAccumulatorVerifyNonMembership(
        universalAccumulatorGetAccumulated(accumulator1),
        nonMember,
        nmWitness,
        pk,
        params
      )
    ).toBe(true);

    // Then remove a batch from new `accumulator1`
    const removeBatch = [e1, e3];
    const accumulator2 = universalAccumulatorRemoveBatch(
      accumulator1,
      removeBatch,
      sk
    );

    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(accumulator2),
        e1,
        witness1,
        pk,
        params
      )
    ).toBe(false);
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(accumulator2),
        e2,
        witness2,
        pk,
        params
      )
    ).toBe(false);
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(accumulator2),
        e3,
        witness3,
        pk,
        params
      )
    ).toBe(false);
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(accumulator2),
        e4,
        witness4,
        pk,
        params
      )
    ).toBe(false);

    const witness22 = universalAccumulatorMembershipWitness(
      accumulator2,
      e2,
      sk
    );
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(accumulator2),
        e2,
        witness22,
        pk,
        params
      )
    ).toBe(true);
    const witness42 = universalAccumulatorMembershipWitness(
      accumulator2,
      e4,
      sk
    );
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(accumulator2),
        e4,
        witness42,
        pk,
        params
      )
    ).toBe(true);

    d = universalAccumulatorComputeD(nonMember, [e2, e4]);
    nmWitness = universalAccumulatorNonMembershipWitness(
      accumulator2,
      d,
      nonMember,
      sk,
      params
    );
    expect(
      universalAccumulatorVerifyNonMembership(
        universalAccumulatorGetAccumulated(accumulator2),
        nonMember,
        nmWitness,
        pk,
        params
      )
    ).toBe(true);

    // Then add and remove a batch from new `accumulator2`
    const addNewBatch = [e5, e6];
    const removeNewBatch = [e2, e4];
    const accumulator3 = universalAccumulatorBatchUpdates(
      accumulator2,
      addNewBatch,
      removeNewBatch,
      sk
    );

    const witness5 = universalAccumulatorMembershipWitness(
      accumulator3,
      e5,
      sk
    );
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(accumulator3),
        e5,
        witness5,
        pk,
        params
      )
    ).toBe(true);
    const witness6 = universalAccumulatorMembershipWitness(
      accumulator3,
      e6,
      sk
    );
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(accumulator3),
        e6,
        witness6,
        pk,
        params
      )
    ).toBe(true);

    d = universalAccumulatorComputeD(nonMember, [e5, e6]);
    nmWitness = universalAccumulatorNonMembershipWitness(
      accumulator3,
      d,
      nonMember,
      sk,
      params
    );
    expect(
      universalAccumulatorVerifyNonMembership(
        universalAccumulatorGetAccumulated(accumulator3),
        nonMember,
        nmWitness,
        pk,
        params
      )
    ).toBe(true);

    // Add a batch to `accumulator`, remove a batch from `accumulator`, then add a batch and then remove
    let accumulator4 = universalAccumulatorAddBatch(accumulator, addBatch, sk);
    accumulator4 = universalAccumulatorRemoveBatch(
      accumulator4,
      removeBatch,
      sk
    );
    accumulator4 = universalAccumulatorAddBatch(accumulator4, addNewBatch, sk);
    accumulator4 = universalAccumulatorRemoveBatch(
      accumulator4,
      removeNewBatch,
      sk
    );
    expect(accumulator4).toEqual(accumulator3);
  });

  it("membership and non-membership witnesses for multiple members", () => {
    const e1 = generateFieldElementFromNumber(101);
    const e2 = generateFieldElementFromNumber(102);
    const e3 = generateFieldElementFromNumber(103);

    const batch = [e1, e2, e3];
    const accumulator1 = universalAccumulatorAddBatch(accumulator, batch, sk);

    const witnesses = universalAccumulatorMembershipWitnessesForBatch(
      accumulator1,
      batch,
      sk
    );
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(accumulator1),
        batch[0],
        witnesses[0],
        pk,
        params
      )
    ).toBe(true);
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(accumulator1),
        batch[1],
        witnesses[1],
        pk,
        params
      )
    ).toBe(true);
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(accumulator1),
        batch[2],
        witnesses[2],
        pk,
        params
      )
    ).toBe(true);

    let nonMembers = [
      generateFieldElementFromNumber(104),
      generateFieldElementFromNumber(105),
      generateFieldElementFromNumber(106),
    ];
    const d = universalAccumulatorComputeDForBatch(nonMembers, batch);
    const nmWitnesses = universalAccumulatorNonMembershipWitnessesForBatch(
      accumulator1,
      d,
      nonMembers,
      sk,
      params
    );
    expect(
      universalAccumulatorVerifyNonMembership(
        universalAccumulatorGetAccumulated(accumulator1),
        nonMembers[0],
        nmWitnesses[0],
        pk,
        params
      )
    ).toBe(true);
    expect(
      universalAccumulatorVerifyNonMembership(
        universalAccumulatorGetAccumulated(accumulator1),
        nonMembers[1],
        nmWitnesses[1],
        pk,
        params
      )
    ).toBe(true);
    expect(
      universalAccumulatorVerifyNonMembership(
        universalAccumulatorGetAccumulated(accumulator1),
        nonMembers[2],
        nmWitnesses[2],
        pk,
        params
      )
    ).toBe(true);

    const d1 = universalAccumulatorComputeDForBatch(nonMembers, [e1, e2]);
    const d2 = universalAccumulatorComputeDForBatch(nonMembers, [e3]);
    const combinedD = universalAccumulatorCombineMultipleDForBatch([d1, d2]);
    expect(combinedD).toEqual(d);
  });
});

describe("Witness update", () => {
  let params: Uint8Array,
    sk: Uint8Array,
    pk: Uint8Array,
    posAccumulator: Uint8Array,
    uniAccumulator: IUniversalAccumulator;

  beforeAll(async () => {
    await initializeWasm();
  });

  beforeEach(() => {
    params = generateAccumulatorParams();
    sk = generateAccumulatorSecretKey();
    pk = generateAccumulatorPublicKey(sk, params);

    posAccumulator = positiveAccumulatorInitialize(params);

    const initialElements = [
      generateFieldElementFromNumber(101),
      generateFieldElementFromNumber(102),
      generateFieldElementFromNumber(103),
      generateFieldElementFromNumber(104),
      generateFieldElementFromNumber(105),
      generateFieldElementFromNumber(106),
      generateFieldElementFromNumber(107),
      generateFieldElementFromNumber(108),
      generateFieldElementFromNumber(109),
      generateFieldElementFromNumber(110),
    ];

    const fixedInitial = universalAccumulatorFixedInitialElements();
    const allInitial = fixedInitial.concat(initialElements);

    const fV = universalAccumulatorComputeInitialFv(allInitial, sk);
    uniAccumulator = universalAccumulatorInitialiseGivenFv(
      fV,
      params,
      initialElements.length - 1
    );
  });

  it("after single update", () => {
    const nonMember = generateRandomFieldElement();

    const e1 = generateFieldElementFromNumber(1);
    posAccumulator = positiveAccumulatorAdd(posAccumulator, e1, sk);
    uniAccumulator = universalAccumulatorAdd(uniAccumulator, e1, sk);

    let posMemWit = positiveAccumulatorMembershipWitness(
      posAccumulator,
      e1,
      sk
    );
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(posAccumulator),
        e1,
        posMemWit,
        pk,
        params
      )
    ).toBe(true);

    let uniMemWit = universalAccumulatorMembershipWitness(
      uniAccumulator,
      e1,
      sk
    );
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(uniAccumulator),
        e1,
        uniMemWit,
        pk,
        params
      )
    ).toBe(true);

    const d = universalAccumulatorComputeD(nonMember, [e1]);
    let nonMemWit = universalAccumulatorNonMembershipWitness(
      uniAccumulator,
      d,
      nonMember,
      sk,
      params
    );
    expect(
      universalAccumulatorVerifyNonMembership(
        universalAccumulatorGetAccumulated(uniAccumulator),
        nonMember,
        nonMemWit,
        pk,
        params
      )
    ).toBe(true);

    const e2 = generateFieldElementFromNumber(2);

    const posAccumulator1 = positiveAccumulatorAdd(posAccumulator, e2, sk);
    const uniAccumulator1 = universalAccumulatorAdd(uniAccumulator, e2, sk);

    posMemWit = updateMembershipWitnessPostAdd(
      posMemWit,
      e1,
      e2,
      positiveAccumulatorGetAccumulated(posAccumulator)
    );
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(posAccumulator1),
        e1,
        posMemWit,
        pk,
        params
      )
    ).toBe(true);

    uniMemWit = updateMembershipWitnessPostAdd(
      uniMemWit,
      e1,
      e2,
      universalAccumulatorGetAccumulated(uniAccumulator)
    );
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(uniAccumulator1),
        e1,
        uniMemWit,
        pk,
        params
      )
    ).toBe(true);

    nonMemWit = updateNonMembershipWitnessPostAdd(
      nonMemWit,
      nonMember,
      e2,
      universalAccumulatorGetAccumulated(uniAccumulator)
    );
    expect(
      universalAccumulatorVerifyNonMembership(
        universalAccumulatorGetAccumulated(uniAccumulator1),
        nonMember,
        nonMemWit,
        pk,
        params
      )
    ).toBe(true);

    const posAccumulator2 = positiveAccumulatorRemove(posAccumulator1, e2, sk);
    const uniAccumulator2 = universalAccumulatorRemove(uniAccumulator1, e2, sk);

    posMemWit = updateMembershipWitnessPostRemove(
      posMemWit,
      e1,
      e2,
      positiveAccumulatorGetAccumulated(posAccumulator2)
    );
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(posAccumulator2),
        e1,
        posMemWit,
        pk,
        params
      )
    ).toBe(true);

    uniMemWit = updateMembershipWitnessPostRemove(
      uniMemWit,
      e1,
      e2,
      universalAccumulatorGetAccumulated(uniAccumulator2)
    );
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(uniAccumulator2),
        e1,
        uniMemWit,
        pk,
        params
      )
    ).toBe(true);

    nonMemWit = updateNonMembershipWitnessPostRemove(
      nonMemWit,
      nonMember,
      e2,
      universalAccumulatorGetAccumulated(uniAccumulator2)
    );
    expect(
      universalAccumulatorVerifyNonMembership(
        universalAccumulatorGetAccumulated(uniAccumulator2),
        nonMember,
        nonMemWit,
        pk,
        params
      )
    ).toBe(true);
  });

  it("by manager after batch updates", () => {
    const member1 = generateRandomFieldElement();
    const member2 = generateRandomFieldElement();

    posAccumulator = positiveAccumulatorAddBatch(
      posAccumulator,
      [member1, member2],
      sk
    );
    const wits = positiveAccumulatorMembershipWitnessesForBatch(
      posAccumulator,
      [member1, member2],
      sk
    );

    const member3 = generateRandomFieldElement();
    const member4 = generateRandomFieldElement();

    const posAccumulator1 = positiveAccumulatorAddBatch(
      posAccumulator,
      [member3, member4],
      sk
    );

    const newWits = updateMembershipWitnessesPostBatchUpdates(
      wits,
      [member1, member2],
      [member3, member4],
      [],
      positiveAccumulatorGetAccumulated(posAccumulator),
      sk
    );
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(posAccumulator1),
        member1,
        newWits[0],
        pk,
        params
      )
    ).toBe(true);
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(posAccumulator1),
        member2,
        newWits[1],
        pk,
        params
      )
    ).toBe(true);

    posAccumulator = posAccumulator1;
  });

  it("after batch updates", () => {
    const member = generateRandomFieldElement();
    const nonMember = generateRandomFieldElement();

    posAccumulator = positiveAccumulatorAdd(posAccumulator, member, sk);
    uniAccumulator = universalAccumulatorAdd(uniAccumulator, member, sk);

    let posMemWitInitial = positiveAccumulatorMembershipWitness(
      posAccumulator,
      member,
      sk
    );
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(posAccumulator),
        member,
        posMemWitInitial,
        pk,
        params
      )
    ).toBe(true);

    const uniMemWitInitial = universalAccumulatorMembershipWitness(
      uniAccumulator,
      member,
      sk
    );
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(uniAccumulator),
        member,
        uniMemWitInitial,
        pk,
        params
      )
    ).toBe(true);

    const d = universalAccumulatorComputeD(nonMember, [member]);
    const nonMemWitInitial = universalAccumulatorNonMembershipWitness(
      uniAccumulator,
      d,
      nonMember,
      sk,
      params
    );
    expect(
      universalAccumulatorVerifyNonMembership(
        universalAccumulatorGetAccumulated(uniAccumulator),
        nonMember,
        nonMemWitInitial,
        pk,
        params
      )
    ).toBe(true);

    const addBatch0 = [
      generateRandomFieldElement(),
      generateRandomFieldElement(),
    ];

    const posPublicInfo0 = publicInfoForWitnessUpdate(
      positiveAccumulatorGetAccumulated(posAccumulator),
      addBatch0,
      [],
      sk
    );
    const uniPublicInfo0 = publicInfoForWitnessUpdate(
      universalAccumulatorGetAccumulated(uniAccumulator),
      addBatch0,
      [],
      sk
    );

    posAccumulator = positiveAccumulatorAddBatch(posAccumulator, addBatch0, sk);
    uniAccumulator = universalAccumulatorAddBatch(
      uniAccumulator,
      addBatch0,
      sk
    );

    let posMemWit = updateMembershipWitnessUsingPublicInfoAfterBatchUpdate(
      posMemWitInitial,
      member,
      addBatch0,
      [],
      posPublicInfo0
    );
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(posAccumulator),
        member,
        posMemWit,
        pk,
        params
      )
    ).toBe(true);

    let uniMemWit = updateMembershipWitnessUsingPublicInfoAfterBatchUpdate(
      uniMemWitInitial,
      member,
      addBatch0,
      [],
      uniPublicInfo0
    );
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(uniAccumulator),
        member,
        uniMemWit,
        pk,
        params
      )
    ).toBe(true);

    let nonMemWit = updateNonMembershipWitnessUsingPublicInfoAfterBatchUpdate(
      nonMemWitInitial,
      nonMember,
      addBatch0,
      [],
      uniPublicInfo0
    );
    expect(
      universalAccumulatorVerifyNonMembership(
        universalAccumulatorGetAccumulated(uniAccumulator),
        nonMember,
        nonMemWit,
        pk,
        params
      )
    ).toBe(true);

    const addBatch1 = [
      generateRandomFieldElement(),
      generateRandomFieldElement(),
    ];
    const remBatch1 = addBatch0;

    const posPublicInfo1 = publicInfoForWitnessUpdate(
      positiveAccumulatorGetAccumulated(posAccumulator),
      addBatch1,
      remBatch1,
      sk
    );
    const uniPublicInfo1 = publicInfoForWitnessUpdate(
      universalAccumulatorGetAccumulated(uniAccumulator),
      addBatch1,
      remBatch1,
      sk
    );

    posAccumulator = positiveAccumulatorBatchUpdates(
      posAccumulator,
      addBatch1,
      remBatch1,
      sk
    );
    uniAccumulator = universalAccumulatorBatchUpdates(
      uniAccumulator,
      addBatch1,
      remBatch1,
      sk
    );

    posMemWit = updateMembershipWitnessUsingPublicInfoAfterBatchUpdate(
      posMemWit,
      member,
      addBatch1,
      remBatch1,
      posPublicInfo1
    );
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(posAccumulator),
        member,
        posMemWit,
        pk,
        params
      )
    ).toBe(true);

    uniMemWit = updateMembershipWitnessUsingPublicInfoAfterBatchUpdate(
      uniMemWit,
      member,
      addBatch1,
      remBatch1,
      uniPublicInfo1
    );
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(uniAccumulator),
        member,
        uniMemWit,
        pk,
        params
      )
    ).toBe(true);

    nonMemWit = updateNonMembershipWitnessUsingPublicInfoAfterBatchUpdate(
      nonMemWit,
      nonMember,
      addBatch1,
      remBatch1,
      uniPublicInfo1
    );
    expect(
      universalAccumulatorVerifyNonMembership(
        universalAccumulatorGetAccumulated(uniAccumulator),
        nonMember,
        nonMemWit,
        pk,
        params
      )
    ).toBe(true);

    const addBatch2 = [
      generateRandomFieldElement(),
      generateRandomFieldElement(),
    ];
    const remBatch2 = addBatch1;

    const posPublicInfo2 = publicInfoForWitnessUpdate(
      positiveAccumulatorGetAccumulated(posAccumulator),
      addBatch2,
      remBatch2,
      sk
    );
    const uniPublicInfo2 = publicInfoForWitnessUpdate(
      universalAccumulatorGetAccumulated(uniAccumulator),
      addBatch2,
      remBatch2,
      sk
    );

    posAccumulator = positiveAccumulatorBatchUpdates(
      posAccumulator,
      addBatch2,
      remBatch2,
      sk
    );
    uniAccumulator = universalAccumulatorBatchUpdates(
      uniAccumulator,
      addBatch2,
      remBatch2,
      sk
    );

    posMemWit = updateMembershipWitnessUsingPublicInfoAfterBatchUpdate(
      posMemWit,
      member,
      addBatch2,
      remBatch2,
      posPublicInfo2
    );
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(posAccumulator),
        member,
        posMemWit,
        pk,
        params
      )
    ).toBe(true);

    uniMemWit = updateMembershipWitnessUsingPublicInfoAfterBatchUpdate(
      uniMemWit,
      member,
      addBatch2,
      remBatch2,
      uniPublicInfo2
    );
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(uniAccumulator),
        member,
        uniMemWit,
        pk,
        params
      )
    ).toBe(true);

    nonMemWit = updateNonMembershipWitnessUsingPublicInfoAfterBatchUpdate(
      nonMemWit,
      nonMember,
      addBatch2,
      remBatch2,
      uniPublicInfo2
    );
    expect(
      universalAccumulatorVerifyNonMembership(
        universalAccumulatorGetAccumulated(uniAccumulator),
        nonMember,
        nonMemWit,
        pk,
        params
      )
    ).toBe(true);

    posMemWit = updateMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates(
      posMemWitInitial,
      member,
      [addBatch0, addBatch1, addBatch2],
      [[], remBatch1, remBatch2],
      [posPublicInfo0, posPublicInfo1, posPublicInfo2]
    );
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(posAccumulator),
        member,
        posMemWit,
        pk,
        params
      )
    ).toBe(true);

    uniMemWit = updateMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates(
      uniMemWitInitial,
      member,
      [addBatch0, addBatch1, addBatch2],
      [[], remBatch1, remBatch2],
      [uniPublicInfo0, uniPublicInfo1, uniPublicInfo2]
    );
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(uniAccumulator),
        member,
        uniMemWit,
        pk,
        params
      )
    ).toBe(true);

    nonMemWit = updateNonMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates(
      nonMemWitInitial,
      nonMember,
      [addBatch0, addBatch1, addBatch2],
      [[], remBatch1, remBatch2],
      [uniPublicInfo0, uniPublicInfo1, uniPublicInfo2]
    );
    expect(
      universalAccumulatorVerifyNonMembership(
        universalAccumulatorGetAccumulated(uniAccumulator),
        nonMember,
        nonMemWit,
        pk,
        params
      )
    ).toBe(true);
  });
});

describe("Proofs ", () => {
  let params: Uint8Array,
    sk: Uint8Array,
    pk: Uint8Array,
    posAccumulator: Uint8Array,
    accumulator: IUniversalAccumulator;

  beforeAll(async () => {
    await initializeWasm();
    params = generateAccumulatorParams();
    sk = generateAccumulatorSecretKey();
    pk = generateAccumulatorPublicKey(sk, params);

    posAccumulator = positiveAccumulatorInitialize(params);

    const initialElements = [
      generateFieldElementFromNumber(101),
      generateFieldElementFromNumber(102),
      generateFieldElementFromNumber(103),
      generateFieldElementFromNumber(104),
      generateFieldElementFromNumber(105),
      generateFieldElementFromNumber(106),
      generateFieldElementFromNumber(107),
      generateFieldElementFromNumber(108),
      generateFieldElementFromNumber(109),
      generateFieldElementFromNumber(110),
    ];

    const fixedInitial = universalAccumulatorFixedInitialElements();
    const allInitial = fixedInitial.concat(initialElements);

    const fV = universalAccumulatorComputeInitialFv(allInitial, sk);
    accumulator = universalAccumulatorInitialiseGivenFv(
      fV,
      params,
      initialElements.length - 1
    );
  });

  it("for membership", () => {
    const prk = generateMembershipProvingKey();
    const member = generateFieldElementFromNumber(1);

    posAccumulator = positiveAccumulatorAdd(posAccumulator, member, sk);
    accumulator = universalAccumulatorAdd(accumulator, member, sk);

    const posMemWit = positiveAccumulatorMembershipWitness(
      posAccumulator,
      member,
      sk
    );
    expect(
      positiveAccumulatorVerifyMembership(
        positiveAccumulatorGetAccumulated(posAccumulator),
        member,
        posMemWit,
        pk,
        params
      )
    ).toBe(true);

    const uniMemWit = universalAccumulatorMembershipWitness(
      accumulator,
      member,
      sk
    );
    expect(
      universalAccumulatorVerifyMembership(
        universalAccumulatorGetAccumulated(accumulator),
        member,
        uniMemWit,
        pk,
        params
      )
    ).toBe(true);

    let blinding = generateRandomFieldElement();
    let protocol = accumulatorInitializeMembershipProof(
      member,
      blinding,
      posMemWit,
      pk,
      params,
      prk
    );

    let pBytes = accumulatorChallengeContributionFromMembershipProtocol(
      protocol,
      positiveAccumulatorGetAccumulated(posAccumulator),
      pk,
      params,
      prk
    );
    expect(pBytes).toBeInstanceOf(Uint8Array);
    let proverChallenge = generateChallengeFromBytes(pBytes);

    let proof = accumulatorGenMembershipProof(protocol, proverChallenge);

    let vBytes = accumulatorChallengeContributionFromMembershipProof(
      proof,
      positiveAccumulatorGetAccumulated(posAccumulator),
      pk,
      params,
      prk
    );
    expect(vBytes).toBeInstanceOf(Uint8Array);
    expect(pBytes).toEqual(vBytes);
    let verifierChallenge = generateChallengeFromBytes(vBytes);
    expect(proverChallenge).toEqual(verifierChallenge);

    let result = accumulatorVerifyMembershipProof(
      proof,
      positiveAccumulatorGetAccumulated(posAccumulator),
      verifierChallenge,
      pk,
      params,
      prk
    );
    expect(result.verified).toBe(true);

    blinding = generateRandomFieldElement();
    protocol = accumulatorInitializeMembershipProof(
      member,
      blinding,
      uniMemWit,
      pk,
      params,
      prk
    );

    pBytes = accumulatorChallengeContributionFromMembershipProtocol(
      protocol,
      universalAccumulatorGetAccumulated(accumulator),
      pk,
      params,
      prk
    );
    expect(pBytes).toBeInstanceOf(Uint8Array);
    proverChallenge = generateChallengeFromBytes(pBytes);

    proof = accumulatorGenMembershipProof(protocol, proverChallenge);

    vBytes = accumulatorChallengeContributionFromMembershipProof(
      proof,
      universalAccumulatorGetAccumulated(accumulator),
      pk,
      params,
      prk
    );
    expect(vBytes).toBeInstanceOf(Uint8Array);
    expect(pBytes).toEqual(vBytes);
    verifierChallenge = generateChallengeFromBytes(vBytes);
    expect(proverChallenge).toEqual(verifierChallenge);

    result = accumulatorVerifyMembershipProof(
      proof,
      universalAccumulatorGetAccumulated(accumulator),
      verifierChallenge,
      pk,
      params,
      prk
    );
    expect(result.verified).toBe(true);
  });

  it("for non-membership", () => {
    const prk = generateNonMembershipProvingKey();
    const nonMember = generateRandomFieldElement();
    const member = generateRandomFieldElement();

    accumulator = universalAccumulatorAdd(accumulator, member, sk);

    const d = universalAccumulatorComputeD(nonMember, [member]);
    const nonMemWit = universalAccumulatorNonMembershipWitness(
      accumulator,
      d,
      nonMember,
      sk,
      params
    );
    expect(
      universalAccumulatorVerifyNonMembership(
        universalAccumulatorGetAccumulated(accumulator),
        nonMember,
        nonMemWit,
        pk,
        params
      )
    ).toBe(true);

    const blinding = generateRandomFieldElement();
    const protocol = accumulatorInitializeNonMembershipProof(
      nonMember,
      blinding,
      nonMemWit,
      pk,
      params,
      prk
    );

    const pBytes = accumulatorChallengeContributionFromNonMembershipProtocol(
      protocol,
      universalAccumulatorGetAccumulated(accumulator),
      pk,
      params,
      prk
    );
    expect(pBytes).toBeInstanceOf(Uint8Array);
    const proverChallenge = generateChallengeFromBytes(pBytes);

    const proof = accumulatorGenNonMembershipProof(protocol, proverChallenge);

    const vBytes = accumulatorChallengeContributionFromNonMembershipProof(
      proof,
      universalAccumulatorGetAccumulated(accumulator),
      pk,
      params,
      prk
    );
    expect(vBytes).toBeInstanceOf(Uint8Array);
    expect(pBytes).toEqual(vBytes);
    const verifierChallenge = generateChallengeFromBytes(vBytes);
    expect(proverChallenge).toEqual(verifierChallenge);

    const result = accumulatorVerifyNonMembershipProof(
      proof,
      universalAccumulatorGetAccumulated(accumulator),
      verifierChallenge,
      pk,
      params,
      prk
    );
    expect(result.verified).toBe(true);
  });
});
