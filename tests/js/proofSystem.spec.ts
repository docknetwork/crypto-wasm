import { stringToBytes, getRevealedUnrevealed } from "../utilities";
import {
  BbsPlusSigParams,
  accumulatorDeriveMembershipProvingKeyFromNonMembershipKey,
  bbsPlusBlindSignG1,
  bbsPlusCommitMsgsInG1,
  encodeMessageForSigning,
  encodeMessagesForSigning,
  bbsPlusGetBasesForCommitmentG1,
  generatePoKPSSignatureStatement,
  bbsPlusSignG1,
  generatePoKPSSignatureWitness,
  bbsPlusUnblindSigG1,
  bbsPlusVerifyG1,
  generateAccumulatorMembershipStatement,
  generateAccumulatorMembershipWitness,
  generateAccumulatorNonMembershipStatement,
  generateAccumulatorNonMembershipWitness,
  generateAccumulatorParams,
  generateAccumulatorPublicKey,
  generateAccumulatorSecretKey,
  bbsPlusGeneratePublicKeyG2,
  bbsPlusGenerateSigningKey,
  generateFieldElementFromBytes,
  generateFieldElementFromNumber,
  generateNonMembershipProvingKey,
  generatePedersenCommitmentG1Statement,
  generatePedersenCommitmentWitness,
  generatePoKBBSPlusSignatureStatement,
  generatePoKBBSPlusSignatureWitness,
  generateCompositeProofG1,
  generateCompositeProofG2,
  generateProofSpecG1,
  generateProofSpecG2,
  generateRandomFieldElement,
  bbsPlusGenerateSignatureParamsG1,
  generateWitnessEqualityMetaStatement,
  positiveAccumulatorAdd,
  positiveAccumulatorGetAccumulated,
  positiveAccumulatorInitialize,
  positiveAccumulatorMembershipWitness,
  universalAccumulatorAdd,
  universalAccumulatorComputeD,
  universalAccumulatorComputeInitialFv,
  universalAccumulatorGetAccumulated,
  universalAccumulatorInitialiseGivenFv,
  universalAccumulatorMembershipWitness,
  universalAccumulatorNonMembershipWitness,
  verifyCompositeProofG1,
  verifyCompositeProofG2,
  initializeWasm,
  universalAccumulatorFixedInitialElements,
  generateRandomG1Element,
  pedersenCommitmentG1,
  pedersenCommitmentG2,
  generateRandomG2Element,
  generatePedersenCommitmentG2Statement,
  generateSetupParamForBBSPlusSignatureParametersG1,
  generateSetupParamForBBSPlusPublicKeyG2,
  generateSetupParamForVbAccumulatorParams,
  generateSetupParamForVbAccumulatorPublicKey,
  generateSetupParamForVbAccumulatorMemProvingKey,
  generateSetupParamForVbAccumulatorNonMemProvingKey,
  generatePoKBBSPlusSignatureStatementFromParamRefs,
  generateAccumulatorMembershipStatementFromParamRefs,
  generateAccumulatorNonMembershipStatementFromParamRefs,
  IUniversalAccumulator,
  isProofSpecG1Valid,
  isProofSpecG2Valid,
  psSign,
  psGenerateSigningKey,
  psGenerateSignatureParams,
  psGeneratePublicKey,
  bbsGenerateSignatureParams,
  bbsGenerateSigningKey,
  bbsGeneratePublicKey,
  generatePoKBBSSignatureStatement,
  bbsSign,
  generatePoKBBSSignatureWitness,
  generateSetupParamForPSSignatureParameters,
} from "../../lib";
import { BbsSigParams, PSSigParams } from "../../lib/types";

function setupMessages(
  messageCount: number,
  prefix: string,
  encode: boolean
): Uint8Array[] {
  const messages: Uint8Array[] = [];
  for (let i = 0; i < messageCount; i++) {
    let m = stringToBytes(`${prefix}-${i + 1}`);
    if (encode) {
      m = encodeMessageForSigning(m);
    }
    messages.push(m);
  }
  return messages;
}

function setupSignerBBS(
  messageCount: number
): [BbsSigParams, Uint8Array, Uint8Array] {
  const sigParams = bbsGenerateSignatureParams(messageCount);
  const sk = bbsGenerateSigningKey();
  const pk = bbsGeneratePublicKey(sk, sigParams);
  return [sigParams, sk, pk];
}

function setupSignerBBSPlus(
  messageCount: number
): [BbsPlusSigParams, Uint8Array, Uint8Array] {
  const sigParams = bbsPlusGenerateSignatureParamsG1(messageCount);
  const sk = bbsPlusGenerateSigningKey();
  const pk = bbsPlusGeneratePublicKeyG2(sk, sigParams);
  return [sigParams, sk, pk];
}

function setupSignerPS(
  messageCount: number
): [PSSigParams, Uint8Array, Uint8Array] {
  const sigParams = psGenerateSignatureParams(messageCount);
  const sk = psGenerateSigningKey(messageCount);
  const pk = psGeneratePublicKey(sk, sigParams);
  return [sigParams, sk, pk];
}

function setupBBS(
  messageCount: number,
  prefix: string,
  encode: boolean
): [BbsSigParams, Uint8Array, Uint8Array, Uint8Array[]] {
  return [
    ...setupSignerBBS(messageCount),
    setupMessages(messageCount, prefix, encode),
  ];
}

function setupBBSPlus(
  messageCount: number,
  prefix: string,
  encode: boolean
): [BbsPlusSigParams, Uint8Array, Uint8Array, Uint8Array[]] {
  return [
    ...setupSignerBBSPlus(messageCount),
    setupMessages(messageCount, prefix, encode),
  ];
}

function setupPS(
  messageCount: number,
  prefix: string,
  encode: boolean
): [PSSigParams, Uint8Array, Uint8Array, Uint8Array[]] {
  return [
    ...setupSignerPS(messageCount),
    setupMessages(messageCount, prefix, encode),
  ];
}

function getUniversalAccum(
  initialElements: Uint8Array[],
  sk: Uint8Array,
  params: Uint8Array,
  maxSize: number
): IUniversalAccumulator {
  const fixedInitial = universalAccumulatorFixedInitialElements();
  const allInitial = fixedInitial.concat(initialElements);
  const fV = universalAccumulatorComputeInitialFv(allInitial, sk);
  return universalAccumulatorInitialiseGivenFv(fV, params, maxSize);
}

describe("Proving knowledge of many signatures", () => {
  const proveAndVerifySig = (
    setup,
    sign,
    buildStatement,
    buildWitness,
    messageCount1: number,
    messageCount2: number,
    messageCount3: number,
    encodeWhileSigning: boolean
  ) => {
    let [sigParams1, sk1, pk1, messages1] = setup(
      messageCount1,
      "Message1",
      !encodeWhileSigning
    );
    let [sigParams2, sk2, pk2, messages2] = setup(
      messageCount2,
      "Message2",
      !encodeWhileSigning
    );
    let [sigParams3, sk3, pk3, messages3] = setup(
      messageCount3,
      "Message3",
      !encodeWhileSigning
    );

    messages2[3] = messages1[2];
    messages2[4] = messages1[3];
    messages2[5] = messages1[4];

    messages3[3] = messages1[2];
    messages3[5] = messages1[4];

    const sig1 = sign(messages1, sk1, sigParams1, encodeWhileSigning);
    const sig2 = sign(messages2, sk2, sigParams2, encodeWhileSigning);
    const sig3 = sign(messages3, sk3, sigParams3, encodeWhileSigning);

    const revealedIndices1 = new Set<number>();
    revealedIndices1.add(0);
    const revealedIndices2 = new Set<number>();
    revealedIndices2.add(1);
    const revealedIndices3 = new Set<number>();
    revealedIndices3.add(2);

    const [revealedMsgs1, unrevealedMsgs1] = getRevealedUnrevealed(
      messages1,
      revealedIndices1
    );
    const [revealedMsgs2, unrevealedMsgs2] = getRevealedUnrevealed(
      messages2,
      revealedIndices2
    );
    const [revealedMsgs3, unrevealedMsgs3] = getRevealedUnrevealed(
      messages3,
      revealedIndices3
    );

    const statement1 = buildStatement(
      sigParams1,
      pk1,
      revealedMsgs1,
      encodeWhileSigning
    );
    const statement2 = buildStatement(
      sigParams2,
      pk2,
      revealedMsgs2,
      encodeWhileSigning
    );
    const statement3 = buildStatement(
      sigParams3,
      pk3,
      revealedMsgs3,
      encodeWhileSigning
    );

    const metaStatements: Uint8Array[] = [];

    const set1 = new Set<[number, number]>();
    set1.add([0, 2]);
    set1.add([1, 3]);
    set1.add([2, 3]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set1));

    const set2 = new Set<[number, number]>();
    set2.add([0, 3]);
    set2.add([1, 4]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set2));

    const set3 = new Set<[number, number]>();
    set3.add([0, 4]);
    set3.add([1, 5]);
    set3.add([2, 5]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set3));

    const statements: Uint8Array[] = [];
    statements.push(statement1);
    statements.push(statement2);
    statements.push(statement3);

    const context = stringToBytes("test-context");
    const proofSpec = generateProofSpecG1(
      statements,
      metaStatements,
      [],
      context
    );

    expect(isProofSpecG1Valid(proofSpec)).toEqual(true);

    const witness1 = buildWitness(
      sig1,
      unrevealedMsgs1,
      encodeWhileSigning
    );
    const witness2 = buildWitness(
      sig2,
      unrevealedMsgs2,
      encodeWhileSigning
    );
    const witness3 = buildWitness(
      sig3,
      unrevealedMsgs3,
      encodeWhileSigning
    );

    const witnesses: Uint8Array[] = [];
    witnesses.push(witness1);
    witnesses.push(witness2);
    witnesses.push(witness3);

    const nonce = stringToBytes("test-nonce");

    const proof = generateCompositeProofG1(proofSpec, witnesses, nonce);
    const res = verifyCompositeProofG1(proof, proofSpec, nonce);
    expect(res.verified).toBe(true);
  };

  beforeAll(async () => {
    await initializeWasm();
  });

  it("generate and verify a proof of knowledge of 3 BBS signatures", () => {
    const messageCount1 = 6;
    const messageCount2 = 10;
    const messageCount3 = 9;

    proveAndVerifySig(
      setupBBS,
      bbsSign,
      generatePoKBBSSignatureStatement,
      generatePoKBBSSignatureWitness,
      messageCount1,
      messageCount2,
      messageCount3,
      true
    );
    proveAndVerifySig(
      setupBBS,
      bbsSign,
      generatePoKBBSSignatureStatement,
      generatePoKBBSSignatureWitness,
      messageCount1,
      messageCount2,
      messageCount3,
      false
    );
  });

  it("generate and verify a proof of knowledge of 3 BBS+ signatures", () => {
    const messageCount1 = 6;
    const messageCount2 = 10;
    const messageCount3 = 9;

    proveAndVerifySig(
      setupBBSPlus,
      bbsPlusSignG1,
      generatePoKBBSPlusSignatureStatement,
      generatePoKBBSPlusSignatureWitness,
      messageCount1,
      messageCount2,
      messageCount3,
      true
    );
    proveAndVerifySig(
      setupBBSPlus,
      bbsPlusSignG1,
      generatePoKBBSPlusSignatureStatement,
      generatePoKBBSPlusSignatureWitness,
      messageCount1,
      messageCount2,
      messageCount3,
      false
    );
  });

  it("generate and verify a proof of knowledge of 3 PS signatures", () => {
    const messageCount1 = 6;
    const messageCount2 = 10;
    const messageCount3 = 9;

    proveAndVerifySig(
      setupPS,
      psSign,
      generatePoKPSSignatureStatement,
      generatePoKPSSignatureWitness,
      messageCount1,
      messageCount2,
      messageCount3,
      false
    );
  });
});

describe("Proving knowledge of BBS+ signatures and accumulator membership and non-membership", () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  function checkSig(setup, sign, buildStatement, buildWitness) {
    const messageCount1 = 6;
    const messageCount2 = 8;
    let [sigParams1, sk1, pk1, messages1] = setup(
      messageCount1,
      "Message1",
      true
    );
    let [sigParams2, sk2, pk2, messages2] = setup(
      messageCount2,
      "Message2",
      true
    );

    // Message at index 5 is the accumulator member
    let member = generateFieldElementFromBytes(stringToBytes("userid-1234"));
    messages1[5] = member;
    messages2[5] = member;

    const sig1 = sign(messages1, sk1, sigParams1, false);
    const sig2 = sign(messages2, sk2, sigParams2, false);

    const revealedIndices1 = new Set<number>();
    revealedIndices1.add(0);
    const revealedIndices2 = new Set<number>();
    revealedIndices2.add(1);

    const [revealedMsgs1, unrevealedMsgs1] = getRevealedUnrevealed(
      messages1,
      revealedIndices1
    );
    const [revealedMsgs2, unrevealedMsgs2] = getRevealedUnrevealed(
      messages2,
      revealedIndices2
    );

    const params = generateAccumulatorParams();
    const sk = generateAccumulatorSecretKey();
    const pk = generateAccumulatorPublicKey(sk, params);

    let posAccumulator = positiveAccumulatorInitialize(params);

    const initialElements = [
      generateFieldElementFromNumber(101),
      generateFieldElementFromNumber(102),
      generateFieldElementFromNumber(103),
      generateFieldElementFromNumber(104),
      generateFieldElementFromNumber(105),
    ];

    let uniAccumulator = getUniversalAccum(initialElements, sk, params, 100);
    const nonMemPrk = generateNonMembershipProvingKey();
    const memPrk = accumulatorDeriveMembershipProvingKeyFromNonMembershipKey(
      nonMemPrk
    );

    posAccumulator = positiveAccumulatorAdd(posAccumulator, member, sk);
    uniAccumulator = universalAccumulatorAdd(uniAccumulator, member, sk);

    const nonMember = messages1[3];

    const posWitness = positiveAccumulatorMembershipWitness(
      posAccumulator,
      member,
      sk
    );
    const uniWitness = universalAccumulatorMembershipWitness(
      uniAccumulator,
      member,
      sk
    );

    const d = universalAccumulatorComputeD(nonMember, [member]);
    const nmWitness = universalAccumulatorNonMembershipWitness(
      uniAccumulator,
      d,
      nonMember,
      sk,
      params
    );

    const posAccumulated = positiveAccumulatorGetAccumulated(posAccumulator);
    const uniAccumulated = universalAccumulatorGetAccumulated(uniAccumulator);

    const statement1 = buildStatement(sigParams1, pk1, revealedMsgs1, false);
    const statement2 = buildStatement(sigParams2, pk2, revealedMsgs2, false);
    const statement3 = generateAccumulatorMembershipStatement(
      params,
      pk,
      memPrk,
      posAccumulated
    );
    const statement4 = generateAccumulatorMembershipStatement(
      params,
      pk,
      memPrk,
      uniAccumulated
    );
    const statement5 = generateAccumulatorNonMembershipStatement(
      params,
      pk,
      nonMemPrk,
      uniAccumulated
    );

    const metaStatements: Uint8Array[] = [];

    const set1 = new Set<[number, number]>();
    set1.add([0, 5]);
    set1.add([1, 5]);
    set1.add([2, 0]);
    set1.add([3, 0]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set1));

    const set2 = new Set<[number, number]>();
    set2.add([0, 3]);
    set2.add([4, 0]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set2));

    const statements: Uint8Array[] = [];
    statements.push(statement1);
    statements.push(statement2);
    statements.push(statement3);
    statements.push(statement4);
    statements.push(statement5);

    const proofSpec = generateProofSpecG1(statements, metaStatements, []);
    expect(isProofSpecG1Valid(proofSpec)).toEqual(true);

    const witness1 = buildWitness(sig1, unrevealedMsgs1, false);
    const witness2 = buildWitness(sig2, unrevealedMsgs2, false);
    const witness3 = generateAccumulatorMembershipWitness(member, posWitness);
    const witness4 = generateAccumulatorMembershipWitness(member, uniWitness);
    const witness5 = generateAccumulatorNonMembershipWitness(
      nonMember,
      nmWitness
    );

    const witnesses: Uint8Array[] = [];
    witnesses.push(witness1);
    witnesses.push(witness2);
    witnesses.push(witness3);
    witnesses.push(witness4);
    witnesses.push(witness5);

    const proof = generateCompositeProofG1(proofSpec, witnesses);

    const res = verifyCompositeProofG1(proof, proofSpec);
    expect(res.verified).toBe(true);
  }

  it("generate and verify a proof of knowledge of a BBS signature and accumulator membership", () => {
    checkSig(
      setupBBS,
      bbsSign,
      generatePoKBBSSignatureStatement,
      generatePoKBBSSignatureWitness
    );
  });

  it("generate and verify a proof of knowledge of a BBS+ signature and accumulator membership", () => {
    checkSig(
      setupBBSPlus,
      bbsPlusSignG1,
      generatePoKBBSPlusSignatureStatement,
      generatePoKBBSPlusSignatureWitness
    );
  });

  it("generate and verify a proof of knowledge of a PS signature and accumulator membership", () => {
    checkSig(
      setupPS,
      psSign,
      generatePoKPSSignatureStatement,
      generatePoKPSSignatureWitness
    );
  });
});

describe("Proving knowledge of a BBS+ signature while requesting a partially blind BBS+ signature", () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  it("generate and verify a proof of knowledge of a BBS+ signature and accumulator membership", () => {
    const messageCount1 = 5;
    const messageCount2 = 6;

    let [sigParams1, sk1, pk1, messages1] = setupBBSPlus(
      messageCount1,
      "Message1",
      false
    );
    let [sigParams2, sk2, pk2, messages2] = setupBBSPlus(
      messageCount2,
      "Message2",
      false
    );

    messages2[5] = messages1[4];

    const sig1 = bbsPlusSignG1(messages1, sk1, sigParams1, true);

    const revealedIndices1 = new Set<number>();
    revealedIndices1.add(0);
    const [revealedMsgs1, unrevealedMsgs1] = getRevealedUnrevealed(
      messages1,
      revealedIndices1
    );

    const indicesToCommit = new Array<number>();
    indicesToCommit.push(0);
    indicesToCommit.push(1);
    indicesToCommit.push(5);
    const msgsToCommit = new Map();
    const msgsToNotCommit = new Map();
    for (let i = 0; i < messageCount2; i++) {
      if (indicesToCommit.indexOf(i) !== -1) {
        msgsToCommit.set(i, messages2[i]);
      } else {
        msgsToNotCommit.set(i, messages2[i]);
      }
    }

    const blinding = generateRandomFieldElement();
    const commitment = bbsPlusCommitMsgsInG1(
      msgsToCommit,
      blinding,
      sigParams2,
      true
    );
    const bases = bbsPlusGetBasesForCommitmentG1(sigParams2, indicesToCommit);

    const statement1 = generatePoKBBSPlusSignatureStatement(
      sigParams1,
      pk1,
      revealedMsgs1,
      true
    );
    const statement2 = generatePedersenCommitmentG1Statement(bases, commitment);

    const statements: Uint8Array[] = [];
    statements.push(statement1);
    statements.push(statement2);

    const metaStatements: Uint8Array[] = [];

    const set = new Set<[number, number]>();
    set.add([0, 4]);
    set.add([1, 3]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set));

    const proofSpec = generateProofSpecG1(statements, metaStatements, []);
    expect(isProofSpecG1Valid(proofSpec)).toEqual(true);

    const witness1 = generatePoKBBSPlusSignatureWitness(
      sig1,
      unrevealedMsgs1,
      true
    );

    const pcWits = encodeMessagesForSigning(messages2, indicesToCommit);
    pcWits.splice(0, 0, blinding);
    const witness2 = generatePedersenCommitmentWitness(pcWits);

    const witnesses: Uint8Array[] = [];
    witnesses.push(witness1);
    witnesses.push(witness2);

    const nonce = stringToBytes("test");

    const proof = generateCompositeProofG1(proofSpec, witnesses, nonce);
    const res = verifyCompositeProofG1(proof, proofSpec, nonce);
    expect(res.verified).toBe(true);

    const blindSig = bbsPlusBlindSignG1(
      commitment,
      msgsToNotCommit,
      sk2,
      sigParams2,
      true
    );
    const sig2 = bbsPlusUnblindSigG1(blindSig, blinding);
    const res1 = bbsPlusVerifyG1(messages2, sig2, pk2, sigParams2, true);
    expect(res1.verified).toBe(true);
  });
});

describe("Proving equality of openings of Pedersen commitments", () => {
  let messages: Uint8Array[];

  beforeAll(async () => {
    await initializeWasm();
    messages = [
      generateRandomFieldElement(),
      generateRandomFieldElement(),
      generateRandomFieldElement(),
    ];
  });

  it("commitments in G1", () => {
    const bases1 = [generateRandomG1Element(), generateRandomG1Element()];
    const m1 = [messages[0], messages[1]];
    const commitment1 = pedersenCommitmentG1(bases1, m1);

    const bases2 = [
      generateRandomG1Element(),
      generateRandomG1Element(),
      generateRandomG1Element(),
    ];
    const m2 = [messages[0], messages[1], messages[2]];
    const commitment2 = pedersenCommitmentG1(bases2, m2);

    const statement1 = generatePedersenCommitmentG1Statement(
      bases1,
      commitment1
    );
    const statement2 = generatePedersenCommitmentG1Statement(
      bases2,
      commitment2
    );

    const statements: Uint8Array[] = [];
    statements.push(statement1);
    statements.push(statement2);

    const metaStatements: Uint8Array[] = [];

    const set1 = new Set<[number, number]>();
    set1.add([0, 0]);
    set1.add([1, 0]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set1));
    const set2 = new Set<[number, number]>();
    set2.add([0, 1]);
    set2.add([1, 1]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set2));

    const proofSpec = generateProofSpecG1(statements, metaStatements, []);
    expect(isProofSpecG1Valid(proofSpec)).toEqual(true);

    const witness1 = generatePedersenCommitmentWitness(m1);
    const witness2 = generatePedersenCommitmentWitness(m2);
    const witnesses: Uint8Array[] = [];
    witnesses.push(witness1);
    witnesses.push(witness2);

    const proof = generateCompositeProofG1(proofSpec, witnesses);
    const res = verifyCompositeProofG1(proof, proofSpec);
    expect(res.verified).toBe(true);
  });

  it("commitments in G2", () => {
    const bases1 = [generateRandomG2Element(), generateRandomG2Element()];
    const m1 = [messages[0], messages[1]];
    const commitment1 = pedersenCommitmentG2(bases1, m1);

    const bases2 = [
      generateRandomG2Element(),
      generateRandomG2Element(),
      generateRandomG2Element(),
    ];
    const m2 = [messages[0], messages[1], messages[2]];
    const commitment2 = pedersenCommitmentG2(bases2, m2);

    const statement1 = generatePedersenCommitmentG2Statement(
      bases1,
      commitment1
    );
    const statement2 = generatePedersenCommitmentG2Statement(
      bases2,
      commitment2
    );

    const statements: Uint8Array[] = [];
    statements.push(statement1);
    statements.push(statement2);

    const metaStatements: Uint8Array[] = [];

    const set1 = new Set<[number, number]>();
    set1.add([0, 0]);
    set1.add([1, 0]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set1));
    const set2 = new Set<[number, number]>();
    set2.add([0, 1]);
    set2.add([1, 1]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set2));

    const proofSpec = generateProofSpecG2(statements, metaStatements, []);
    expect(isProofSpecG2Valid(proofSpec)).toEqual(true);

    const witness1 = generatePedersenCommitmentWitness(m1);
    const witness2 = generatePedersenCommitmentWitness(m2);
    const witnesses: Uint8Array[] = [];
    witnesses.push(witness1);
    witnesses.push(witness2);

    const proof = generateCompositeProofG2(proofSpec, witnesses);
    const res = verifyCompositeProofG2(proof, proofSpec);
    expect(res.verified).toBe(true);
  });
});

describe("Reusing setup params of BBS+ and accumulator", () => {
  const messageCount = 5;
  let sigParams1: BbsPlusSigParams,
    sigParams2: BbsPlusSigParams,
    sigSk1: Uint8Array,
    sigSk2: Uint8Array,
    sigPk1: Uint8Array,
    sigPk2: Uint8Array;
  let messages1: Uint8Array[],
    messages2: Uint8Array[],
    messages3: Uint8Array[],
    messages4: Uint8Array[];
  let accumParams1: Uint8Array,
    accumParams2: Uint8Array,
    accumSk1: Uint8Array,
    accumSk2: Uint8Array,
    accumPk1: Uint8Array,
    accumPk2: Uint8Array;

  beforeAll(async () => {
    await initializeWasm();
    [sigParams1, sigSk1, sigPk1] = setupSignerBBSPlus(messageCount);
    [sigParams2, sigSk2, sigPk2] = setupSignerBBSPlus(messageCount);
    messages1 = setupMessages(messageCount, "Message1", true);
    messages2 = setupMessages(messageCount, "Message2", true);
    messages3 = setupMessages(messageCount, "Message3", true);
    messages4 = setupMessages(messageCount, "Message4", true);

    accumParams1 = generateAccumulatorParams();
    accumSk1 = generateAccumulatorSecretKey();
    accumPk1 = generateAccumulatorPublicKey(accumSk1, accumParams1);

    accumParams2 = generateAccumulatorParams();
    accumSk2 = generateAccumulatorSecretKey();
    accumPk2 = generateAccumulatorPublicKey(accumSk2, accumParams2);
  });

  it("generate and verify a proof of knowledge using setup parameters", () => {
    const memberIndex = 0;
    const nonMemberIndex = 1;

    const sig1 = bbsPlusSignG1(messages1, sigSk1, sigParams1, false);
    const sig2 = bbsPlusSignG1(messages2, sigSk1, sigParams1, false);
    const sig3 = bbsPlusSignG1(messages3, sigSk2, sigParams2, false);
    const sig4 = bbsPlusSignG1(messages4, sigSk2, sigParams2, false);

    let posAccumulator1 = positiveAccumulatorInitialize(accumParams1);
    let posAccumulator2 = positiveAccumulatorInitialize(accumParams2);

    posAccumulator1 = positiveAccumulatorAdd(
      posAccumulator1,
      messages1[memberIndex],
      accumSk1
    );
    posAccumulator1 = positiveAccumulatorAdd(
      posAccumulator1,
      messages2[memberIndex],
      accumSk1
    );
    posAccumulator2 = positiveAccumulatorAdd(
      posAccumulator2,
      messages3[memberIndex],
      accumSk2
    );
    posAccumulator2 = positiveAccumulatorAdd(
      posAccumulator2,
      messages4[memberIndex],
      accumSk2
    );

    const initialElements1 = [
      generateFieldElementFromNumber(101),
      generateFieldElementFromNumber(102),
      generateFieldElementFromNumber(103),
    ];
    const initialElements2 = [
      generateFieldElementFromNumber(201),
      generateFieldElementFromNumber(202),
      generateFieldElementFromNumber(203),
    ];

    let uniAccumulator1 = getUniversalAccum(
      initialElements1,
      accumSk1,
      accumParams1,
      100
    );
    let uniAccumulator2 = getUniversalAccum(
      initialElements2,
      accumSk2,
      accumParams2,
      100
    );

    const nonMemPrk = generateNonMembershipProvingKey();
    const memPrk = accumulatorDeriveMembershipProvingKeyFromNonMembershipKey(
      nonMemPrk
    );

    const [revealedMsgs1, unrevealedMsgs1] = getRevealedUnrevealed(
      messages1,
      new Set<number>()
    );
    const [revealedMsgs2, unrevealedMsgs2] = getRevealedUnrevealed(
      messages2,
      new Set<number>()
    );
    const [revealedMsgs3, unrevealedMsgs3] = getRevealedUnrevealed(
      messages3,
      new Set<number>()
    );
    const [revealedMsgs4, unrevealedMsgs4] = getRevealedUnrevealed(
      messages4,
      new Set<number>()
    );

    const posWitness1 = positiveAccumulatorMembershipWitness(
      posAccumulator1,
      messages1[memberIndex],
      accumSk1
    );
    const posWitness2 = positiveAccumulatorMembershipWitness(
      posAccumulator1,
      messages2[memberIndex],
      accumSk1
    );
    const posWitness3 = positiveAccumulatorMembershipWitness(
      posAccumulator2,
      messages3[memberIndex],
      accumSk2
    );
    const posWitness4 = positiveAccumulatorMembershipWitness(
      posAccumulator2,
      messages4[memberIndex],
      accumSk2
    );

    let d = universalAccumulatorComputeD(messages1[nonMemberIndex], []);
    const uniWitness1 = universalAccumulatorNonMembershipWitness(
      uniAccumulator1,
      d,
      messages1[nonMemberIndex],
      accumSk1,
      accumParams1
    );
    d = universalAccumulatorComputeD(messages2[nonMemberIndex], []);
    const uniWitness2 = universalAccumulatorNonMembershipWitness(
      uniAccumulator1,
      d,
      messages2[nonMemberIndex],
      accumSk1,
      accumParams1
    );
    d = universalAccumulatorComputeD(messages3[nonMemberIndex], []);
    const uniWitness3 = universalAccumulatorNonMembershipWitness(
      uniAccumulator2,
      d,
      messages3[nonMemberIndex],
      accumSk2,
      accumParams2
    );
    d = universalAccumulatorComputeD(messages4[nonMemberIndex], []);
    const uniWitness4 = universalAccumulatorNonMembershipWitness(
      uniAccumulator2,
      d,
      messages4[nonMemberIndex],
      accumSk2,
      accumParams2
    );

    const posAccumulated1 = positiveAccumulatorGetAccumulated(posAccumulator1);
    const posAccumulated2 = positiveAccumulatorGetAccumulated(posAccumulator2);
    const uniAccumulated1 = universalAccumulatorGetAccumulated(uniAccumulator1);
    const uniAccumulated2 = universalAccumulatorGetAccumulated(uniAccumulator2);

    const allSetupParams: Uint8Array[] = [];
    allSetupParams.push(
      generateSetupParamForBBSPlusSignatureParametersG1(sigParams1)
    );
    allSetupParams.push(generateSetupParamForBBSPlusPublicKeyG2(sigPk1));
    allSetupParams.push(
      generateSetupParamForBBSPlusSignatureParametersG1(sigParams2)
    );
    allSetupParams.push(generateSetupParamForBBSPlusPublicKeyG2(sigPk2));
    allSetupParams.push(generateSetupParamForVbAccumulatorParams(accumParams1));
    allSetupParams.push(generateSetupParamForVbAccumulatorPublicKey(accumPk1));
    allSetupParams.push(generateSetupParamForVbAccumulatorParams(accumParams2));
    allSetupParams.push(generateSetupParamForVbAccumulatorPublicKey(accumPk2));
    allSetupParams.push(
      generateSetupParamForVbAccumulatorMemProvingKey(memPrk)
    );
    allSetupParams.push(
      generateSetupParamForVbAccumulatorNonMemProvingKey(nonMemPrk)
    );

    const statement1 = generatePoKBBSPlusSignatureStatementFromParamRefs(
      0,
      1,
      revealedMsgs1,
      false
    );
    const statement2 = generatePoKBBSPlusSignatureStatementFromParamRefs(
      0,
      1,
      revealedMsgs2,
      false
    );
    const statement3 = generatePoKBBSPlusSignatureStatementFromParamRefs(
      2,
      3,
      revealedMsgs3,
      false
    );
    const statement4 = generatePoKBBSPlusSignatureStatementFromParamRefs(
      2,
      3,
      revealedMsgs4,
      false
    );
    const statement5 = generateAccumulatorMembershipStatementFromParamRefs(
      4,
      5,
      8,
      posAccumulated1
    );
    const statement6 = generateAccumulatorMembershipStatementFromParamRefs(
      4,
      5,
      8,
      posAccumulated1
    );
    const statement7 = generateAccumulatorMembershipStatementFromParamRefs(
      6,
      7,
      8,
      posAccumulated2
    );
    const statement8 = generateAccumulatorMembershipStatementFromParamRefs(
      6,
      7,
      8,
      posAccumulated2
    );
    const statement9 = generateAccumulatorNonMembershipStatementFromParamRefs(
      4,
      5,
      9,
      uniAccumulated1
    );
    const statement10 = generateAccumulatorNonMembershipStatementFromParamRefs(
      4,
      5,
      9,
      uniAccumulated1
    );
    const statement11 = generateAccumulatorNonMembershipStatementFromParamRefs(
      6,
      7,
      9,
      uniAccumulated2
    );
    const statement12 = generateAccumulatorNonMembershipStatementFromParamRefs(
      6,
      7,
      9,
      uniAccumulated2
    );

    const statements: Uint8Array[] = [];
    statements.push(statement1);
    statements.push(statement2);
    statements.push(statement3);
    statements.push(statement4);
    statements.push(statement5);
    statements.push(statement6);
    statements.push(statement7);
    statements.push(statement8);
    statements.push(statement9);
    statements.push(statement10);
    statements.push(statement11);
    statements.push(statement12);

    const proofSpec = generateProofSpecG1(statements, [], allSetupParams);
    expect(isProofSpecG1Valid(proofSpec)).toEqual(true);

    const witness1 = generatePoKBBSPlusSignatureWitness(
      sig1,
      unrevealedMsgs1,
      false
    );
    const witness2 = generatePoKBBSPlusSignatureWitness(
      sig2,
      unrevealedMsgs2,
      false
    );
    const witness3 = generatePoKBBSPlusSignatureWitness(
      sig3,
      unrevealedMsgs3,
      false
    );
    const witness4 = generatePoKBBSPlusSignatureWitness(
      sig4,
      unrevealedMsgs4,
      false
    );
    const witness5 = generateAccumulatorMembershipWitness(
      messages1[memberIndex],
      posWitness1
    );
    const witness6 = generateAccumulatorMembershipWitness(
      messages2[memberIndex],
      posWitness2
    );
    const witness7 = generateAccumulatorMembershipWitness(
      messages3[memberIndex],
      posWitness3
    );
    const witness8 = generateAccumulatorMembershipWitness(
      messages4[memberIndex],
      posWitness4
    );
    const witness9 = generateAccumulatorNonMembershipWitness(
      messages1[nonMemberIndex],
      uniWitness1
    );
    const witness10 = generateAccumulatorNonMembershipWitness(
      messages2[nonMemberIndex],
      uniWitness2
    );
    const witness11 = generateAccumulatorNonMembershipWitness(
      messages3[nonMemberIndex],
      uniWitness3
    );
    const witness12 = generateAccumulatorNonMembershipWitness(
      messages4[nonMemberIndex],
      uniWitness4
    );

    const witnesses: Uint8Array[] = [];
    witnesses.push(witness1);
    witnesses.push(witness2);
    witnesses.push(witness3);
    witnesses.push(witness4);
    witnesses.push(witness5);
    witnesses.push(witness6);
    witnesses.push(witness7);
    witnesses.push(witness8);
    witnesses.push(witness9);
    witnesses.push(witness10);
    witnesses.push(witness11);
    witnesses.push(witness12);

    const proof = generateCompositeProofG1(proofSpec, witnesses);

    const res = verifyCompositeProofG1(proof, proofSpec);
    expect(res.verified).toBe(true);
  });
});
