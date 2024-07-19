import {
  BbsPlusSigParams,
  accumulatorDeriveMembershipProvingKeyFromNonMembershipKey,
  encodeMessageForSigningInConstantTime,
  encodeMessagesForSigningInConstantTime,
  bbsPlusGetBasesForCommitmentG1,
  generatePoKPSSignatureStatement,
  bbsPlusSignG1,
  bbsPlusUnblindSigG1,
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
  generateCompositeProofG1,
  generateProofSpecG1,
  generateRandomFieldElement,
  bbsPlusGenerateSignatureParamsG1,
  generateWitnessEqualityMetaStatement,
  positiveAccumulatorAdd,
  positiveAccumulatorInitialize,
  positiveAccumulatorMembershipWitness,
  universalAccumulatorAdd,
  universalAccumulatorComputeD,
  universalAccumulatorComputeInitialFv,
  universalAccumulatorInitialiseGivenFv,
  universalAccumulatorMembershipWitness,
  universalAccumulatorNonMembershipWitness,
  verifyCompositeProofG1,
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
  generateAccumulatorMembershipStatementFromParamRefs,
  generateAccumulatorNonMembershipStatementFromParamRefs,
  IUniversalAccumulator,
  isProofSpecG1Valid,
  psSign,
  psGenerateSigningKey,
  psGenerateSignatureParams,
  psGeneratePublicKey,
  bbsGenerateSignatureParams,
  bbsGenerateSigningKey,
  bbsGeneratePublicKey,
  generatePoKBBSSignatureWitness,
  generateSetupParamForBBSSignatureParameters,
  generatePublicInequalityG1Statement,
  generatePedersenCommKeyG1,
  generatePublicInequalityWitness,
  Bddt16MacParams,
  bddt16GenerateMacParams,
  bddt16MacGenerateSecretKey,
  generatePoKBDDT16MacFullVerifierStatement,
  bddt16UnblindMac,
  bddt16MacGetBasesForCommitment,
  generateAccumulatorKVMembershipStatement,
  generateAccumulatorKVFullVerifierMembershipStatement,
  generateSetupParamForBDDT16MacParameters,
  generateMembershipProvingKey,
  getAllKeyedSubproofsFromProof,
  verifyBDDT16KeyedProof,
  verifyVBAccumMembershipKeyedProof,
  kbUniversalAccumulatorInitialise,
  kbUniversalAccumulatorAdd,
  kbUniversalAccumulatorMembershipWitness,
  kbUniversalAccumulatorNonMembershipWitness,
  generateKBUniversalAccumulatorKVMembershipStatement,
  generateKBUniversalAccumulatorKVNonMembershipStatement,
  generateKBUniversalAccumulatorMembershipProverStatement,
  generateKBUniversalAccumulatorNonMembershipProverStatement,
  generateKBUniversalAccumulatorMembershipWitness,
  generateKBUniversalAccumulatorNonMembershipWitness,
  generateKBUniversalAccumulatorMembershipVerifierStatement,
  generateKBUniversalAccumulatorNonMembershipVerifierStatement,
  generateKBUniversalAccumulatorKVFullVerifierMembershipStatement,
  generateKBUniversalAccumulatorKVFullVerifierNonMembershipStatement,
  generateKBUniversalAccumulatorMembershipVerifierStatementFromParamRefs,
  generateKBUniversalAccumulatorNonMembershipVerifierStatementFromParamRefs,
  verifyKBUniAccumMembershipKeyedProof,
  verifyKBUniAccumNonMembershipKeyedProof,
  bbsSignConstantTime,
  generatePoKBBSSignatureProverStatementConstantTime,
  generatePoKBBSSignatureVerifierStatementConstantTime,
  generatePoKBBSSignatureWitnessConstantTime,
  generatePoKBBSPlusSignatureProverStatementConstantTime,
  generatePoKBBSPlusSignatureVerifierStatementConstantTime,
  generatePoKBBSPlusSignatureWitnessConstantTime,
  generatePoKPSSignatureStatementConstantTime,
  generatePoKPSSignatureWitnessConstantTime,
  generatePoKBDDT16MacWitnessConstantTime,
  generatePoKBDDT16MacStatementConstantTime,
  bddt16MacGenerateConstantTime,
  bbsPlusSignG1ConstantTime,
  bbsPlusBlindSignG1ConstantTime,
  bbsPlusVerifyG1ConstantTime,
  bbsPlusCommitMsgsInG1ConstantTime,
  bddt16MacVerifyConstantTime,
  bddt16BlindMacGenerateConstantTime,
  bddt16MacCommitMsgsConstantTime,
  generatePoKBDDT16MacFullVerifierStatementFromParamRefsConstantTime,
  generatePoKBBSPlusSignatureProverStatementFromParamRefsConstantTime,
  generatePoKBBSPlusSignatureVerifierStatementFromParamRefsConstantTime,
  generatePoKBBSSignatureVerifierStatementFromParamRefsConstantTime,
  generatePoKBBSSignatureProverStatementFromParamRefsConstantTime,
  generatePoKBDDT16MacStatementFromParamRefsConstantTime,
  generatePoKBDDT16MacFullVerifierStatementConstantTime,
  proofOfValidityOfBDDT16KeyedProof,
  bddt16MacGeneratePublicKeyG1,
  verifyProofOfValidityOfBDDT16KeyedProof,
  generatePoKBBSSignatureProverStatementNew,
  generatePoKBBSSignatureVerifierStatementNew,
  generatePoKBBSSignatureProverStatementFromParamRefsNew,
  generatePoKBBSSignatureVerifierStatementFromParamRefsNew,
  generateAccumulatorPublicKeyForKeyedVerification,
  generateAccumulatorParamsForKeyedVerification,
  proofOfValidityOfVBAccumMembershipKeyedProof,
  verifyProofOfValidityOfVBAccumMembershipKeyedProof,
  proofOfValidityOfKBUniAccumMembershipKeyedProof,
  verifyProofOfValidityOfKBUniAccumMembershipKeyedProof,
  proofOfValidityOfKBUniAccumNonMembershipKeyedProof, verifyProofOfValidityOfKBUniAccumNonMembershipKeyedProof
} from "../../lib";
import { BbsSigParams, PSSigParams } from "../../lib/types";
import {checkResult, getRevealedUnrevealed, stringToBytes} from "./util";

function setupMessages(
  messageCount: number,
  prefix: string,
  encode: boolean
): Uint8Array[] {
  const messages: Uint8Array[] = [];
  for (let i = 0; i < messageCount; i++) {
    let m = stringToBytes(`${prefix}-${i + 1}`);
    if (encode) {
      m = encodeMessageForSigningInConstantTime(m);
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

function setupSignerBDDT16(
    messageCount: number
): [Bddt16MacParams, Uint8Array] {
  const macParams = bddt16GenerateMacParams(messageCount);
  const sk = bddt16MacGenerateSecretKey();
  return [macParams, sk];
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

function setupBDDT16(
    messageCount: number,
    prefix: string,
    encode: boolean
): [Bddt16MacParams, Uint8Array, Uint8Array, Uint8Array[]] {
  return [
    ...setupSignerBDDT16(messageCount),
    new Uint8Array(), // dummy to reuse following test code
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
    buildProverStatement,
    buildVerifierStatement,
    buildWitness,
    messageCount1: number,
    messageCount2: number,
    messageCount3: number,
    encodeWhileSigning: boolean,
    isPs = false,
    isKvac = false
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

    const statement1 = !isPs ? buildProverStatement(
        sigParams1,
        revealedMsgs1,
        encodeWhileSigning
    ) : buildProverStatement(
      sigParams1,
      pk1,
      revealedMsgs1,
      encodeWhileSigning
    );
    const statement2 = !isPs ? buildProverStatement(
        sigParams2,
        revealedMsgs2,
        encodeWhileSigning
    ) : buildProverStatement(
      sigParams2,
      pk2,
      revealedMsgs2,
      encodeWhileSigning
    );
    const statement3 = !isPs ? buildProverStatement(
        sigParams3,
        revealedMsgs3,
        encodeWhileSigning
    ) : buildProverStatement(
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

    const proverStatements: Uint8Array[] = [];
    proverStatements.push(statement1);
    proverStatements.push(statement2);
    proverStatements.push(statement3);

    const context = stringToBytes("test-context");
    const proverProofSpec = generateProofSpecG1(
      proverStatements,
      metaStatements,
      [],
      context
    );

    expect(isProofSpecG1Valid(proverProofSpec)).toEqual(true);

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

    const proof = generateCompositeProofG1(proverProofSpec, witnesses, nonce);

    const verifierStatements: Uint8Array[] = [];
    verifierStatements.push(isKvac ? buildVerifierStatement(
        sigParams1,
        revealedMsgs1,
        encodeWhileSigning
    ) : buildVerifierStatement(
        sigParams1,
        pk1,
        revealedMsgs1,
        encodeWhileSigning
    ));
    verifierStatements.push(isKvac ? buildVerifierStatement(
        sigParams2,
        revealedMsgs2,
        encodeWhileSigning
    ) : buildVerifierStatement(
        sigParams2,
        pk2,
        revealedMsgs2,
        encodeWhileSigning
    ));
    verifierStatements.push(isKvac ? buildVerifierStatement(
        sigParams3,
        revealedMsgs3,
        encodeWhileSigning
    ) : buildVerifierStatement(
        sigParams3,
        pk3,
        revealedMsgs3,
        encodeWhileSigning
    ));
    const verifierProofSpec = generateProofSpecG1(
        verifierStatements,
        metaStatements,
        [],
        context
    );
    const res = verifyCompositeProofG1(proof, verifierProofSpec, nonce);
    checkResult(res);

    if (isKvac) {
      const statements: Uint8Array[] = [];
      statements.push(generatePoKBDDT16MacFullVerifierStatementConstantTime(
          sigParams1,
          sk1,
          revealedMsgs1,
          encodeWhileSigning
      ));
      statements.push(generatePoKBDDT16MacFullVerifierStatementConstantTime(
          sigParams2,
          sk2,
          revealedMsgs2,
          encodeWhileSigning
      ));
      statements.push(generatePoKBDDT16MacFullVerifierStatementConstantTime(
          sigParams3,
          sk3,
          revealedMsgs3,
          encodeWhileSigning
      ));
      const proofSpec = generateProofSpecG1(
          statements,
          metaStatements,
          [],
          context
      );
      const res = verifyCompositeProofG1(proof, proofSpec, nonce);
      expect(res.verified).toBe(true);
    }
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
      bbsSignConstantTime,
      generatePoKBBSSignatureProverStatementConstantTime,
      generatePoKBBSSignatureVerifierStatementConstantTime,
      generatePoKBBSSignatureWitnessConstantTime,
      messageCount1,
      messageCount2,
      messageCount3,
      true
    );
    proveAndVerifySig(
      setupBBS,
      bbsSignConstantTime,
      generatePoKBBSSignatureProverStatementConstantTime,
      generatePoKBBSSignatureVerifierStatementConstantTime,
      generatePoKBBSSignatureWitness,
      messageCount1,
      messageCount2,
      messageCount3,
      false
    );
    // Using the new protocol
    proveAndVerifySig(
        setupBBS,
        bbsSignConstantTime,
        generatePoKBBSSignatureProverStatementNew,
        generatePoKBBSSignatureVerifierStatementNew,
        generatePoKBBSSignatureWitnessConstantTime,
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
      bbsPlusSignG1ConstantTime,
      generatePoKBBSPlusSignatureProverStatementConstantTime,
      generatePoKBBSPlusSignatureVerifierStatementConstantTime,
      generatePoKBBSPlusSignatureWitnessConstantTime,
      messageCount1,
      messageCount2,
      messageCount3,
      true
    );
    proveAndVerifySig(
      setupBBSPlus,
      bbsPlusSignG1,
      generatePoKBBSPlusSignatureProverStatementConstantTime,
      generatePoKBBSPlusSignatureVerifierStatementConstantTime,
      generatePoKBBSPlusSignatureWitnessConstantTime,
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
      generatePoKPSSignatureStatementConstantTime,
        generatePoKPSSignatureStatementConstantTime,
      generatePoKPSSignatureWitnessConstantTime,
      messageCount1,
      messageCount2,
      messageCount3,
      false,
        true
    );
  });

  it("generate and verify a proof of knowledge of 3 BDDT16 MACs", () => {
    const messageCount1 = 6;
    const messageCount2 = 10;
    const messageCount3 = 9;

    proveAndVerifySig(
        setupBDDT16,
        bddt16MacGenerateConstantTime,
        generatePoKBDDT16MacStatementConstantTime,
        generatePoKBDDT16MacStatementConstantTime,
        generatePoKBDDT16MacWitnessConstantTime,
        messageCount1,
        messageCount2,
        messageCount3,
        true,
        false,
        true
    );
    proveAndVerifySig(
        setupBDDT16,
        bddt16MacGenerateConstantTime,
        generatePoKBDDT16MacStatementConstantTime,
        generatePoKBDDT16MacStatementConstantTime,
        generatePoKBDDT16MacWitnessConstantTime,
        messageCount1,
        messageCount2,
        messageCount3,
        false,
        false,
        true
    );
  });
});

describe("Proving knowledge of signatures and accumulator membership and non-membership", () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  function check(setup, sign, buildProverStatement, buildVerifierStatement, buildWitness, isPs = false, isKvac = false) {
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

    const nonMember = messages1[3];

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

    const domain: Uint8Array[] = [];
    for (let i = 1; i <= 10; i++) {
      domain.push(generateFieldElementFromNumber(100 + i));
    }
    // Non-member should be part of the domain
    domain.push(nonMember);

    let kbUniAccumulator = kbUniversalAccumulatorInitialise(domain, sk, params);

    const nonMemPrk = generateNonMembershipProvingKey();
    const memPrk = accumulatorDeriveMembershipProvingKeyFromNonMembershipKey(
      nonMemPrk
    );

    posAccumulator = positiveAccumulatorAdd(posAccumulator, member, sk);
    uniAccumulator = universalAccumulatorAdd(uniAccumulator, member, sk);
    kbUniAccumulator = kbUniversalAccumulatorAdd(kbUniAccumulator, member, sk);

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
    const kbUniWitness = kbUniversalAccumulatorMembershipWitness(
        kbUniAccumulator,
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

    const kbUniNmWitness = kbUniversalAccumulatorNonMembershipWitness(
        kbUniAccumulator,
        nonMember,
        sk
    );

    const posAccumulated = posAccumulator;
    const uniAccumulated = uniAccumulator.V;

    const statement1 = !isPs ? buildProverStatement(
        sigParams1,
        revealedMsgs1,
        false
    ) : buildProverStatement(
        sigParams1,
        pk1,
        revealedMsgs1,
        false
    );
    const statement2 = !isPs ? buildProverStatement(
        sigParams2,
        revealedMsgs2,
        false
    ) : buildProverStatement(
        sigParams2,
        pk2,
        revealedMsgs2,
        false
    );
    const statement3 = isKvac ? generateAccumulatorKVMembershipStatement(posAccumulated) : generateAccumulatorMembershipStatement(
        params,
        pk,
        memPrk,
        posAccumulated
    );
    const statement4 = isKvac ? generateAccumulatorKVMembershipStatement(uniAccumulated) : generateAccumulatorMembershipStatement(
        params,
        pk,
        memPrk,
        uniAccumulated
    );
    const statement5 = isKvac ? generateKBUniversalAccumulatorKVMembershipStatement(kbUniAccumulator.mem) : generateKBUniversalAccumulatorMembershipProverStatement(
        kbUniAccumulator.mem
    );
    const statement6 = isKvac ? generateKBUniversalAccumulatorKVNonMembershipStatement(kbUniAccumulator.non_mem) : generateKBUniversalAccumulatorNonMembershipProverStatement(
        kbUniAccumulator.non_mem
    );
    let statement7;
    if (!isKvac) {
      statement7 = generateAccumulatorNonMembershipStatement(
          params,
          pk,
          nonMemPrk,
          uniAccumulated
      );
    }

    const metaStatements: Uint8Array[] = [];

    const set1 = new Set<[number, number]>();
    set1.add([0, 5]);
    set1.add([1, 5]);
    set1.add([2, 0]);
    set1.add([3, 0]);
    set1.add([4, 0]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set1));

    const set2 = new Set<[number, number]>();
    set2.add([0, 3]);
    set2.add([5, 0]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set2));

    if (!isKvac) {
      const set3 = new Set<[number, number]>();
      set3.add([0, 3]);
      set3.add([6, 0]);
      metaStatements.push(generateWitnessEqualityMetaStatement(set3));
    }

    const proverStatements: Uint8Array[] = [];
    proverStatements.push(statement1);
    proverStatements.push(statement2);
    proverStatements.push(statement3);
    proverStatements.push(statement4);
    proverStatements.push(statement5);
    proverStatements.push(statement6);
    if (!isKvac) {
      proverStatements.push(statement7);
    }

    const proverProofSpec = generateProofSpecG1(proverStatements, metaStatements, []);
    expect(isProofSpecG1Valid(proverProofSpec)).toEqual(true);

    const witness1 = buildWitness(sig1, unrevealedMsgs1, false);
    const witness2 = buildWitness(sig2, unrevealedMsgs2, false);
    const witness3 = generateAccumulatorMembershipWitness(member, posWitness);
    const witness4 = generateAccumulatorMembershipWitness(member, uniWitness);
    const witness5 = generateKBUniversalAccumulatorMembershipWitness(member, kbUniWitness);
    const witness6 = generateKBUniversalAccumulatorNonMembershipWitness(nonMember, kbUniNmWitness);
    let witness7;
    if (!isKvac) {
      witness7 = generateAccumulatorNonMembershipWitness(
          nonMember,
          nmWitness
      );
    }

    const witnesses: Uint8Array[] = [];
    witnesses.push(witness1);
    witnesses.push(witness2);
    witnesses.push(witness3);
    witnesses.push(witness4);
    witnesses.push(witness5);
    witnesses.push(witness6);
    if (!isKvac) {
      witnesses.push(witness7);
    }

    const proof = generateCompositeProofG1(proverProofSpec, witnesses);

    const verifierStatements: Uint8Array[] = [];
    verifierStatements.push(isKvac ? buildVerifierStatement(
        sigParams1,
        revealedMsgs1,
        false
    ) : buildVerifierStatement(
        sigParams1,
        pk1,
        revealedMsgs1,
        false
    ));
    verifierStatements.push(isKvac ? buildVerifierStatement(
        sigParams2,
        revealedMsgs2,
        false
    ) : buildVerifierStatement(
        sigParams2,
        pk2,
        revealedMsgs2,
        false
    ));
    verifierStatements.push(statement3);
    verifierStatements.push(statement4);
    verifierStatements.push(isKvac ? statement5 : generateKBUniversalAccumulatorMembershipVerifierStatement(
        params,
        pk,
        kbUniAccumulator.mem));
    verifierStatements.push(isKvac ? statement6 : generateKBUniversalAccumulatorNonMembershipVerifierStatement(
        params,
        pk,
        kbUniAccumulator.non_mem));
    if (!isKvac) {
      verifierStatements.push(statement7);
    }
    const verifierProofSpec = generateProofSpecG1(verifierStatements, metaStatements, []);
    expect(isProofSpecG1Valid(verifierProofSpec)).toEqual(true);
    const res = verifyCompositeProofG1(proof, verifierProofSpec);
    checkResult(res);

    if (isKvac) {
      const statements: Uint8Array[] = [];
      statements.push(generatePoKBDDT16MacFullVerifierStatement(
          sigParams1,
          sk1,
          revealedMsgs1,
          false
      ));
      statements.push(generatePoKBDDT16MacFullVerifierStatement(
          sigParams2,
          sk2,
          revealedMsgs2,
          false
      ));
      statements.push(
          generateAccumulatorKVFullVerifierMembershipStatement(sk, posAccumulated)
      );
      statements.push(
          generateAccumulatorKVFullVerifierMembershipStatement(sk, uniAccumulated)
      );
      statements.push(
          generateKBUniversalAccumulatorKVFullVerifierMembershipStatement(sk, kbUniAccumulator.mem)
      );
      statements.push(
          generateKBUniversalAccumulatorKVFullVerifierNonMembershipStatement(sk, kbUniAccumulator.non_mem)
      );
      const proofSpec = generateProofSpecG1(statements, metaStatements, []);
      const res = verifyCompositeProofG1(proof, proofSpec);
      checkResult(res);
    }
  }

  it("generate and verify a proof of knowledge of a BBS signature and accumulator membership", () => {
    check(
      setupBBS,
      bbsSignConstantTime,
      generatePoKBBSSignatureProverStatementConstantTime,
      generatePoKBBSSignatureVerifierStatementConstantTime,
      generatePoKBBSSignatureWitnessConstantTime
    );
  });

  it("generate and verify a proof of knowledge of a BBS signature using new protocol and accumulator membership", () => {
    check(
        setupBBS,
        bbsSignConstantTime,
        generatePoKBBSSignatureProverStatementNew,
        generatePoKBBSSignatureVerifierStatementNew,
        generatePoKBBSSignatureWitnessConstantTime
    );
  });

  it("generate and verify a proof of knowledge of a BBS+ signature and accumulator membership", () => {
    check(
      setupBBSPlus,
      bbsPlusSignG1ConstantTime,
      generatePoKBBSPlusSignatureProverStatementConstantTime,
      generatePoKBBSPlusSignatureVerifierStatementConstantTime,
      generatePoKBBSPlusSignatureWitnessConstantTime
    );
  });

  it("generate and verify a proof of knowledge of a PS signature and accumulator membership", () => {
    check(
      setupPS,
      psSign,
      generatePoKPSSignatureStatementConstantTime,
      generatePoKPSSignatureStatement,
      generatePoKPSSignatureWitnessConstantTime,
      true
    );
  });

  it("generate and verify a proof of knowledge of a MAC and accumulator membership", () => {
    check(
        setupBDDT16,
        bddt16MacGenerateConstantTime,
        generatePoKBDDT16MacStatementConstantTime,
        generatePoKBDDT16MacStatementConstantTime,
        generatePoKBDDT16MacWitnessConstantTime,
        false,
        true
    );
  });
});

describe("Proving knowledge of a signature or MAC while requesting a partially blind signature or MAC", () => {
  const messageCount1 = 5;
  const messageCount2 = 6;

  beforeAll(async () => {
    await initializeWasm();
  });

  function check(setup, sign, verify, blindSign, unblind, commit, getBases, buildProverStatement, buildVerifierStatement, buildWitness, isKvac = false) {
    let [sigParams1, sk1, pk1, messages1] = setup(
        messageCount1,
        "Message1",
        false
    );
    let [sigParams2, sk2, pk2, messages2] = setup(
        messageCount2,
        "Message2",
        false
    );

    messages2[5] = messages1[4];

    const sig1 = sign(messages1, sk1, sigParams1, true);
    checkResult(isKvac ? verify(messages1, sig1, sk1, sigParams1, true) : verify(messages1, sig1, pk1, sigParams1, true))

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
    const commitment = commit(
        msgsToCommit,
        blinding,
        sigParams2,
        true
    );
    const bases = getBases(sigParams2, indicesToCommit);

    const statement1 = buildProverStatement(
        sigParams1,
        revealedMsgs1,
        true
    );
    const statement2 = generatePedersenCommitmentG1Statement(bases, commitment);

    const proverStatements: Uint8Array[] = [];
    proverStatements.push(statement1);
    proverStatements.push(statement2);

    const metaStatements: Uint8Array[] = [];

    const set = new Set<[number, number]>();
    set.add([0, 4]);
    set.add([1, 3]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set));

    const proverProofSpec = generateProofSpecG1(proverStatements, metaStatements, []);
    expect(isProofSpecG1Valid(proverProofSpec)).toEqual(true);

    const witness1 = buildWitness(
        sig1,
        unrevealedMsgs1,
        true
    );

    const pcWits = encodeMessagesForSigningInConstantTime(messages2, indicesToCommit);
    pcWits.splice(0, 0, blinding);
    const witness2 = generatePedersenCommitmentWitness(pcWits);

    const witnesses: Uint8Array[] = [];
    witnesses.push(witness1);
    witnesses.push(witness2);

    const nonce = stringToBytes("test");

    const proof = generateCompositeProofG1(proverProofSpec, witnesses, nonce);

    const verifierStatements: Uint8Array[] = [];
    verifierStatements.push(isKvac ? buildVerifierStatement(
        sigParams1,
        revealedMsgs1,
        true
    ) : buildVerifierStatement(
        sigParams1,
        pk1,
        revealedMsgs1,
        true
    ));
    verifierStatements.push(statement2);
    const verifierProofSpec = generateProofSpecG1(verifierStatements, metaStatements, []);
    expect(isProofSpecG1Valid(verifierProofSpec)).toEqual(true);

    const res = verifyCompositeProofG1(proof, verifierProofSpec, nonce);
    checkResult(res);

    const blindSig = blindSign(
        commitment,
        msgsToNotCommit,
        sk2,
        sigParams2,
        true
    );
    const sig2 = unblind(blindSig, blinding);
    const res1 = isKvac ? verify(messages2, sig2, sk2, sigParams2, true) : verify(messages2, sig2, pk2, sigParams2, true);
    expect(res1.verified).toBe(true);
  }

  it("generate and verify a proof of knowledge of a BBS+ signature and request a blind BBS+ signature", () => {
    check(
        setupBBSPlus,
        bbsPlusSignG1ConstantTime,
        bbsPlusVerifyG1ConstantTime,
        bbsPlusBlindSignG1ConstantTime,
        bbsPlusUnblindSigG1,
        bbsPlusCommitMsgsInG1ConstantTime,
        bbsPlusGetBasesForCommitmentG1,
        generatePoKBBSPlusSignatureProverStatementConstantTime,
        generatePoKBBSPlusSignatureVerifierStatementConstantTime,
        generatePoKBBSPlusSignatureWitnessConstantTime
    )
  });

  it("generate and verify a proof of knowledge of a MAC and request a blind MAC", () => {
    check(
        setupBDDT16,
        bddt16MacGenerateConstantTime,
        bddt16MacVerifyConstantTime,
        bddt16BlindMacGenerateConstantTime,
        bddt16UnblindMac,
        bddt16MacCommitMsgsConstantTime,
        bddt16MacGetBasesForCommitment,
        generatePoKBDDT16MacStatementConstantTime,
        generatePoKBDDT16MacStatementConstantTime,
        generatePoKBDDT16MacWitnessConstantTime,
        true
    )
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
});

describe("Reusing setup params of BBS, BBS+ and accumulator", () => {
  const messageCount = 5;
  let sigParams1: BbsPlusSigParams,
    sigParams2: BbsPlusSigParams,
    sigSk1: Uint8Array,
    sigSk2: Uint8Array,
    sigPk1: Uint8Array,
    sigPk2: Uint8Array,
    macParams1: Bddt16MacParams,
    macParams2: Bddt16MacParams,
    macSk1: Uint8Array,
    macSk2: Uint8Array;

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
    [macParams1, macSk1] = setupSignerBDDT16(messageCount);
    [macParams2, macSk2] = setupSignerBDDT16(messageCount);

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

  function check(sigParams1, sigSk1, sigPk1, sigParams2, sigSk2, sigPk2, signFunc, setupParamsForSigParamsFunc, setupParamsForPkFunc, sigPrvStmtFunc, sigVerStmtFunc, sigWitFunc, isKvac = false) {
    const memberIndex = 0;
    const nonMemberIndex = 1;

    const sig1 = signFunc(messages1, sigSk1, sigParams1, false);
    const sig2 = signFunc(messages2, sigSk1, sigParams1, false);
    const sig3 = signFunc(messages3, sigSk2, sigParams2, false);
    const sig4 = signFunc(messages4, sigSk2, sigParams2, false);

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

    const domain1: Uint8Array[] = [];
    for (let i = 1; i <= 10; i++) {
      domain1.push(generateFieldElementFromNumber(100 + i));
    }
    domain1.push(messages3[nonMemberIndex]);
    let kbUniAccumulator1 = kbUniversalAccumulatorInitialise(domain1, accumSk1, accumParams1);

    const domain2: Uint8Array[] = [];
    for (let i = 1; i <= 10; i++) {
      domain2.push(generateFieldElementFromNumber(200 + i));
    }
    domain2.push(messages4[nonMemberIndex]);
    let kbUniAccumulator2 = kbUniversalAccumulatorInitialise(domain2, accumSk2, accumParams2);

    const nonMemPrk = generateNonMembershipProvingKey();
    const memPrk = accumulatorDeriveMembershipProvingKeyFromNonMembershipKey(
        nonMemPrk
    );

    kbUniAccumulator1 = kbUniversalAccumulatorAdd(
        kbUniAccumulator1,
        messages1[memberIndex],
        accumSk1
    );
    kbUniAccumulator2 = kbUniversalAccumulatorAdd(
        kbUniAccumulator2,
        messages2[memberIndex],
        accumSk2
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

    const kbUniMemWitness1 = kbUniversalAccumulatorMembershipWitness(
        kbUniAccumulator1,
        messages1[memberIndex],
        accumSk1
    );
    const kbUniMemWitness2 = kbUniversalAccumulatorMembershipWitness(
        kbUniAccumulator2,
        messages2[memberIndex],
        accumSk2
    );
    const kbUniNonMemWitness1 = kbUniversalAccumulatorNonMembershipWitness(
        kbUniAccumulator1,
        messages3[nonMemberIndex],
        accumSk1
    );
    const kbUniNonMemWitness2 = kbUniversalAccumulatorNonMembershipWitness(
        kbUniAccumulator2,
        messages4[nonMemberIndex],
        accumSk2
    );

    const posAccumulated1 = posAccumulator1;
    const posAccumulated2 = posAccumulator2;
    const uniAccumulated1 = uniAccumulator1.V;
    const uniAccumulated2 = uniAccumulator2.V;

    const allSetupParams: Uint8Array[] = [];
    allSetupParams.push(
        setupParamsForSigParamsFunc(sigParams1)
    );
    if (!isKvac) {
      allSetupParams.push(setupParamsForPkFunc(sigPk1));
    }
    allSetupParams.push(
        setupParamsForSigParamsFunc(sigParams2)
    );
    if (!isKvac) {
      allSetupParams.push(setupParamsForPkFunc(sigPk2));
    }
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

    const statement1 = sigPrvStmtFunc(0, revealedMsgs1, false);
    const statement2 = sigPrvStmtFunc(0, revealedMsgs2, false);
    const statement3 = sigPrvStmtFunc(isKvac ? 1: 2, revealedMsgs3, false);
    const statement4 = sigPrvStmtFunc(isKvac ? 1: 2, revealedMsgs4, false);
    const accumStmtOffset = isKvac ? 2 : 0;
    const statement5 = generateAccumulatorMembershipStatementFromParamRefs(
        4 - accumStmtOffset,
        5 - accumStmtOffset,
        8 - accumStmtOffset,
        posAccumulated1
    );
    const statement6 = generateAccumulatorMembershipStatementFromParamRefs(
        4 - accumStmtOffset,
        5 - accumStmtOffset,
        8 - accumStmtOffset,
        posAccumulated1
    );
    const statement7 = generateAccumulatorMembershipStatementFromParamRefs(
        6 - accumStmtOffset,
        7 - accumStmtOffset,
        8 - accumStmtOffset,
        posAccumulated2
    );
    const statement8 = generateAccumulatorMembershipStatementFromParamRefs(
        6 - accumStmtOffset,
        7 - accumStmtOffset,
        8 - accumStmtOffset,
        posAccumulated2
    );
    const statement9 = generateAccumulatorNonMembershipStatementFromParamRefs(
        4 - accumStmtOffset,
        5 - accumStmtOffset,
        9 - accumStmtOffset,
        uniAccumulated1
    );
    const statement10 = generateAccumulatorNonMembershipStatementFromParamRefs(
        4 - accumStmtOffset,
        5 - accumStmtOffset,
        9 - accumStmtOffset,
        uniAccumulated1
    );
    const statement11 = generateAccumulatorNonMembershipStatementFromParamRefs(
        6 - accumStmtOffset,
        7 - accumStmtOffset,
        9 - accumStmtOffset,
        uniAccumulated2
    );
    const statement12 = generateAccumulatorNonMembershipStatementFromParamRefs(
        6 - accumStmtOffset,
        7 - accumStmtOffset,
        9 - accumStmtOffset,
        uniAccumulated2
    );
    const statement13 = generateKBUniversalAccumulatorMembershipProverStatement(
        kbUniAccumulator1.mem
    );
    const statement14 = generateKBUniversalAccumulatorMembershipProverStatement(
        kbUniAccumulator2.mem
    );
    const statement15 = generateKBUniversalAccumulatorNonMembershipProverStatement(
        kbUniAccumulator1.non_mem
    );
    const statement16 = generateKBUniversalAccumulatorNonMembershipProverStatement(
        kbUniAccumulator2.non_mem
    );

    const proverStatements: Uint8Array[] = [];
    proverStatements.push(statement1);
    proverStatements.push(statement2);
    proverStatements.push(statement3);
    proverStatements.push(statement4);
    proverStatements.push(statement5);
    proverStatements.push(statement6);
    proverStatements.push(statement7);
    proverStatements.push(statement8);
    proverStatements.push(statement9);
    proverStatements.push(statement10);
    proverStatements.push(statement11);
    proverStatements.push(statement12);
    proverStatements.push(statement13);
    proverStatements.push(statement14);
    proverStatements.push(statement15);
    proverStatements.push(statement16);

    const metaStatements: Uint8Array[] = [];

    metaStatements.push(generateWitnessEqualityMetaStatement(new Set<[number, number]>([[0, memberIndex], [4, 0]])));
    metaStatements.push(generateWitnessEqualityMetaStatement(new Set<[number, number]>([[1, memberIndex], [5, 0]])));
    metaStatements.push(generateWitnessEqualityMetaStatement(new Set<[number, number]>([[2, memberIndex], [6, 0]])));
    metaStatements.push(generateWitnessEqualityMetaStatement(new Set<[number, number]>([[3, memberIndex], [7, 0]])));

    metaStatements.push(generateWitnessEqualityMetaStatement(new Set<[number, number]>([[0, nonMemberIndex], [8, 0]])));
    metaStatements.push(generateWitnessEqualityMetaStatement(new Set<[number, number]>([[1, nonMemberIndex], [9, 0]])));
    metaStatements.push(generateWitnessEqualityMetaStatement(new Set<[number, number]>([[2, nonMemberIndex], [10, 0]])));
    metaStatements.push(generateWitnessEqualityMetaStatement(new Set<[number, number]>([[3, nonMemberIndex], [11, 0]])));

    metaStatements.push(generateWitnessEqualityMetaStatement(new Set<[number, number]>([[0, memberIndex], [12, 0]])));
    metaStatements.push(generateWitnessEqualityMetaStatement(new Set<[number, number]>([[1, memberIndex], [13, 0]])));
    metaStatements.push(generateWitnessEqualityMetaStatement(new Set<[number, number]>([[2, nonMemberIndex], [14, 0]])));
    metaStatements.push(generateWitnessEqualityMetaStatement(new Set<[number, number]>([[3, nonMemberIndex], [15, 0]])));

    const proverProofSpec = generateProofSpecG1(proverStatements, metaStatements, allSetupParams);
    expect(isProofSpecG1Valid(proverProofSpec)).toEqual(true);

    const witness1 = sigWitFunc(
        sig1,
        unrevealedMsgs1,
        false
    );
    const witness2 = sigWitFunc(
        sig2,
        unrevealedMsgs2,
        false
    );
    const witness3 = sigWitFunc(
        sig3,
        unrevealedMsgs3,
        false
    );
    const witness4 = sigWitFunc(
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
    const witness13 = generateKBUniversalAccumulatorMembershipWitness(
        messages1[memberIndex],
        kbUniMemWitness1
    );
    const witness14 = generateKBUniversalAccumulatorMembershipWitness(
        messages2[memberIndex],
        kbUniMemWitness2
    );
    const witness15 = generateKBUniversalAccumulatorNonMembershipWitness(
        messages3[nonMemberIndex],
        kbUniNonMemWitness1
    );
    const witness16 = generateKBUniversalAccumulatorNonMembershipWitness(
        messages4[nonMemberIndex],
        kbUniNonMemWitness2
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
    witnesses.push(witness13);
    witnesses.push(witness14);
    witnesses.push(witness15);
    witnesses.push(witness16);

    const proof = generateCompositeProofG1(proverProofSpec, witnesses);

    const statement17 = generateKBUniversalAccumulatorMembershipVerifierStatementFromParamRefs(4 - accumStmtOffset,
        5 - accumStmtOffset, kbUniAccumulator1.mem);
    const statement18 = generateKBUniversalAccumulatorMembershipVerifierStatementFromParamRefs(6 - accumStmtOffset,
        7 - accumStmtOffset, kbUniAccumulator2.mem);
    const statement19 = generateKBUniversalAccumulatorNonMembershipVerifierStatementFromParamRefs(4 - accumStmtOffset,
        5 - accumStmtOffset, kbUniAccumulator1.non_mem);
    const statement20 = generateKBUniversalAccumulatorNonMembershipVerifierStatementFromParamRefs(6 - accumStmtOffset,
        7 - accumStmtOffset, kbUniAccumulator2.non_mem);

    const verifierStatements: Uint8Array[] = [];
    verifierStatements.push(isKvac ? sigVerStmtFunc(
        0,
        revealedMsgs1,
        false
    ) : sigVerStmtFunc(
        0,
        1,
        revealedMsgs1,
        false
    ));
    verifierStatements.push(isKvac ? sigVerStmtFunc(
        0,
        revealedMsgs2,
        false
    ) : sigVerStmtFunc(
        0,
        1,
        revealedMsgs2,
        false
    ));
    verifierStatements.push(isKvac ? sigVerStmtFunc(
        1,
        revealedMsgs3,
        false
    ) : sigVerStmtFunc(
        2,
        3,
        revealedMsgs3,
        false
    ));
    verifierStatements.push(isKvac ? sigVerStmtFunc(
        1,
        revealedMsgs4,
        false
    ) : sigVerStmtFunc(
        2,
        3,
        revealedMsgs4,
        false
    ));
    verifierStatements.push(statement5);
    verifierStatements.push(statement6);
    verifierStatements.push(statement7);
    verifierStatements.push(statement8);
    verifierStatements.push(statement9);
    verifierStatements.push(statement10);
    verifierStatements.push(statement11);
    verifierStatements.push(statement12);
    verifierStatements.push(statement17);
    verifierStatements.push(statement18);
    verifierStatements.push(statement19);
    verifierStatements.push(statement20);

    const verifierProofSpec = generateProofSpecG1(verifierStatements, metaStatements, allSetupParams);
    expect(isProofSpecG1Valid(verifierProofSpec)).toEqual(true);

    const res = verifyCompositeProofG1(proof, verifierProofSpec);
    checkResult(res);

    if (isKvac) {
      const statements: Uint8Array[] = [];
      statements.push(generatePoKBDDT16MacFullVerifierStatementFromParamRefsConstantTime(0, sigSk1,  revealedMsgs1, false));
      statements.push(generatePoKBDDT16MacFullVerifierStatementFromParamRefsConstantTime(0, sigSk1,  revealedMsgs2, false));
      statements.push(generatePoKBDDT16MacFullVerifierStatementFromParamRefsConstantTime(1, sigSk2,  revealedMsgs3, false));
      statements.push(generatePoKBDDT16MacFullVerifierStatementFromParamRefsConstantTime(1, sigSk2,  revealedMsgs4, false));
      statements.push(statement5);
      statements.push(statement6);
      statements.push(statement7);
      statements.push(statement8);
      statements.push(statement9);
      statements.push(statement10);
      statements.push(statement11);
      statements.push(statement12);
      statements.push(statement17);
      statements.push(statement18);
      statements.push(statement19);
      statements.push(statement20);

      const proofSpec = generateProofSpecG1(statements, metaStatements, allSetupParams);
      const res = verifyCompositeProofG1(proof, proofSpec);
      expect(res.verified).toBe(true);
    }
  }

  it("generate and verify a proof of knowledge with BBS+ signature and accumulator using setup parameters", () => {
    check(sigParams1, sigSk1, sigPk1, sigParams2, sigSk2, sigPk2, bbsPlusSignG1ConstantTime, generateSetupParamForBBSPlusSignatureParametersG1, generateSetupParamForBBSPlusPublicKeyG2, generatePoKBBSPlusSignatureProverStatementFromParamRefsConstantTime, generatePoKBBSPlusSignatureVerifierStatementFromParamRefsConstantTime, generatePoKBBSPlusSignatureWitnessConstantTime)
  });

  it("generate and verify a proof of knowledge with BBS signature and accumulator using setup parameters", () => {
    check(sigParams1, sigSk1, sigPk1, sigParams2, sigSk2, sigPk2, bbsSignConstantTime, generateSetupParamForBBSSignatureParameters, generateSetupParamForBBSPlusPublicKeyG2, generatePoKBBSSignatureProverStatementFromParamRefsConstantTime, generatePoKBBSSignatureVerifierStatementFromParamRefsConstantTime, generatePoKBBSSignatureWitnessConstantTime)
  });

  it("generate and verify a proof of knowledge with BBS signature using new protocol and accumulator using setup parameters", () => {
    check(sigParams1, sigSk1, sigPk1, sigParams2, sigSk2, sigPk2, bbsSignConstantTime, generateSetupParamForBBSSignatureParameters, generateSetupParamForBBSPlusPublicKeyG2, generatePoKBBSSignatureProverStatementFromParamRefsNew, generatePoKBBSSignatureVerifierStatementFromParamRefsNew, generatePoKBBSSignatureWitnessConstantTime)
  });

  it("generate and verify a proof of knowledge with MAC and accumulator using setup parameters", () => {
    check(
        macParams1, macSk1, undefined, macParams2, macSk2, undefined, bddt16MacGenerateConstantTime, generateSetupParamForBDDT16MacParameters, undefined, generatePoKBDDT16MacStatementFromParamRefsConstantTime, generatePoKBDDT16MacStatementFromParamRefsConstantTime, generatePoKBDDT16MacWitnessConstantTime, true
    )
  });
});

describe("Proving knowledge of signature and inequality of a signed message with a public value", () => {
  const check = (
      setup,
      sign,
      buildProverStatement,
      buildVerifierStatement,
      buildWitness,
      isPs = false,
      isKvac = false,
  ) => {
    let [sigParams, sk, pk, messages] = setup(
        5,
        "Message",
        true
    );

    let comm_key = generatePedersenCommKeyG1(stringToBytes('test'), true);
    const sig = sign(messages, sk, sigParams, false);

    const revealedIndices = new Set<number>();
    revealedIndices.add(0);

    const [revealedMsgs, unrevealedMsgs] = getRevealedUnrevealed(
        messages,
        revealedIndices
    );

    const inequalMsgIdx = 1;
    const inequalTo = generateRandomFieldElement();
    expect(messages[inequalMsgIdx]).not.toEqual(inequalTo);

    const statement1 = !isPs ? buildProverStatement(
        sigParams,
        revealedMsgs,
        false
    ) : buildProverStatement(
        sigParams,
        pk,
        revealedMsgs,
        false
    );;
    const statement2 = generatePublicInequalityG1Statement(inequalTo, comm_key, true);

    const metaStatements: Uint8Array[] = [];

    const set = new Set<[number, number]>();
    set.add([0, inequalMsgIdx]);
    set.add([1, 0]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set));

    const proverStatements: Uint8Array[] = [];
    proverStatements.push(statement1);
    proverStatements.push(statement2);

    const context = stringToBytes("test-context");
    const proverProofSpec = generateProofSpecG1(
        proverStatements,
        metaStatements,
        [],
        context
    );

    expect(isProofSpecG1Valid(proverProofSpec)).toEqual(true);

    const witness1 = buildWitness(
        sig,
        unrevealedMsgs,
        false
    );
    const witness2 = generatePublicInequalityWitness(messages[inequalMsgIdx]);

    const witnesses: Uint8Array[] = [];
    witnesses.push(witness1);
    witnesses.push(witness2);

    const nonce = stringToBytes("test-nonce");

    const proof = generateCompositeProofG1(proverProofSpec, witnesses, nonce);

    const verifierStatements: Uint8Array[] = [];
    verifierStatements.push(isKvac ? buildVerifierStatement(
        sigParams,
        revealedMsgs,
        false
    ) : buildVerifierStatement(
        sigParams,
        pk,
        revealedMsgs,
        false
    ));
    verifierStatements.push(statement2);
    const verifierProofSpec = generateProofSpecG1(
        verifierStatements,
        metaStatements,
        [],
        context
    );

    const res = verifyCompositeProofG1(proof, verifierProofSpec, nonce);
    checkResult(res);
  };

  beforeAll(async () => {
    await initializeWasm();
  });

  it("when BBS signatures", () => {
    check(
        setupBBS,
        bbsSignConstantTime,
        generatePoKBBSSignatureProverStatementConstantTime,
        generatePoKBBSSignatureVerifierStatementConstantTime,
        generatePoKBBSSignatureWitnessConstantTime,
    );
  });

  it("when BBS signatures - new protocol", () => {
    check(
        setupBBS,
        bbsSignConstantTime,
        generatePoKBBSSignatureProverStatementNew,
        generatePoKBBSSignatureVerifierStatementNew,
        generatePoKBBSSignatureWitnessConstantTime,
    );
  });

  it("when BBS+ signatures", () => {
    check(
        setupBBSPlus,
        bbsPlusSignG1ConstantTime,
        generatePoKBBSPlusSignatureProverStatementConstantTime,
        generatePoKBBSPlusSignatureVerifierStatementConstantTime,
        generatePoKBBSPlusSignatureWitnessConstantTime,
    );
  });

  it("when PS signatures", () => {
    check(
        setupPS,
        psSign,
        generatePoKPSSignatureStatementConstantTime,
        generatePoKPSSignatureStatementConstantTime,
        generatePoKPSSignatureWitnessConstantTime,
        true
    );
  });

  it("when BDDT16 MAC signatures", () => {
    check(
        setupBDDT16,
        bddt16MacGenerateConstantTime,
        generatePoKBDDT16MacStatementConstantTime,
        generatePoKBDDT16MacStatementConstantTime,
        generatePoKBDDT16MacWitnessConstantTime,
        false,
        true
    );
  });
});

describe("Keyed proofs", () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  it("works", () => {
    const messageCount = 6;
    let [bbsParams, bbsSk, bbsPk, messages1] = setupBBS(
        messageCount,
        "Message",
        true
    );
    let [bddt16Params, bddt16Sk, , messages2] = setupBDDT16(
        messageCount,
        "Message",
        true
    );

    // This will be added in accumulator
    let member = generateFieldElementFromBytes(stringToBytes("userid-1234"));
    messages1[5] = member;
    messages2[5] = member;

    const nonMember = messages1[3];

    const sig1 = bbsSignConstantTime(messages1, bbsSk, bbsParams, false);
    const sig2 = bddt16MacGenerateConstantTime(messages2, bddt16Sk, bddt16Params, false);

    const params = generateAccumulatorParams();
    const sk = generateAccumulatorSecretKey();
    const pk = generateAccumulatorPublicKey(sk, params);

    let accumulator = positiveAccumulatorInitialize(params);
    const prk = generateMembershipProvingKey();
    accumulator = positiveAccumulatorAdd(accumulator, member, sk);
    const witness = positiveAccumulatorMembershipWitness(
        accumulator,
        member,
        sk
    );
    const accumulated = accumulator;

    const domain: Uint8Array[] = [];
    for (let i = 1; i <= 10; i++) {
      domain.push(generateFieldElementFromNumber(100 + i));
    }
    domain.push(nonMember);
    let kbUniAccumulator = kbUniversalAccumulatorInitialise(domain, sk, params);
    kbUniAccumulator = kbUniversalAccumulatorAdd(kbUniAccumulator, member, sk);
    const kbUniMemWitness = kbUniversalAccumulatorMembershipWitness(
        kbUniAccumulator,
        member,
        sk
    );

    const kbUniNonMemWitness = kbUniversalAccumulatorNonMembershipWitness(
        kbUniAccumulator,
        nonMember,
        sk
    );

    const [revealedMsgs1, unrevealedMsgs1] = getRevealedUnrevealed(
        messages1,
        new Set()
    );
    const [revealedMsgs2, unrevealedMsgs2] = getRevealedUnrevealed(
        messages2,
        new Set()
    );

    const proverStatements: Uint8Array[] = [];
    proverStatements.push(generatePoKBBSSignatureProverStatementConstantTime(bbsParams, revealedMsgs1, false));
    proverStatements.push(generatePoKBDDT16MacStatementConstantTime(bddt16Params, revealedMsgs2, false));

    proverStatements.push(generateAccumulatorMembershipStatement(
        params,
        pk,
        prk,
        accumulated
    ));
    proverStatements.push(generateAccumulatorKVMembershipStatement(accumulated));

    proverStatements.push(generateKBUniversalAccumulatorMembershipProverStatement(kbUniAccumulator.mem));
    proverStatements.push(generateKBUniversalAccumulatorNonMembershipProverStatement(kbUniAccumulator.non_mem));
    proverStatements.push(generateKBUniversalAccumulatorKVMembershipStatement(kbUniAccumulator.mem));
    proverStatements.push(generateKBUniversalAccumulatorKVNonMembershipStatement(kbUniAccumulator.non_mem));

    const metaStatements: Uint8Array[] = [];

    const set1 = new Set<[number, number]>();
    set1.add([0, 5]);
    set1.add([1, 5]);
    set1.add([2, 0]);
    set1.add([3, 0]);
    set1.add([4, 0]);
    set1.add([6, 0]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set1));

    const set2 = new Set<[number, number]>();
    set2.add([0, 3]);
    set2.add([5, 0]);
    set2.add([7, 0]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set2));

    const proverProofSpec = generateProofSpecG1(proverStatements, metaStatements, []);
    expect(isProofSpecG1Valid(proverProofSpec)).toEqual(true);

    const witness1 = generatePoKBBSSignatureWitnessConstantTime(sig1, unrevealedMsgs1, false);
    const witness2 = generatePoKBDDT16MacWitnessConstantTime(sig2, unrevealedMsgs2, false);
    const witness3 = generateAccumulatorMembershipWitness(member, witness);
    const witness4 = generateAccumulatorMembershipWitness(member, witness);
    const witness5 = generateKBUniversalAccumulatorMembershipWitness(member, kbUniMemWitness);
    const witness6 = generateKBUniversalAccumulatorNonMembershipWitness(nonMember, kbUniNonMemWitness);
    const witness7 = generateKBUniversalAccumulatorMembershipWitness(member, kbUniMemWitness);
    const witness8 = generateKBUniversalAccumulatorNonMembershipWitness(nonMember, kbUniNonMemWitness);

    const witnesses: Uint8Array[] = [];
    witnesses.push(witness1);
    witnesses.push(witness2);
    witnesses.push(witness3);
    witnesses.push(witness4);
    witnesses.push(witness5);
    witnesses.push(witness6);
    witnesses.push(witness7);
    witnesses.push(witness8);

    const proof = generateCompositeProofG1(proverProofSpec, witnesses);

    const verifierStatements: Uint8Array[] = [];
    verifierStatements.push(generatePoKBBSSignatureVerifierStatementConstantTime(bbsParams,
        bbsPk,
        revealedMsgs1,
        false));
    verifierStatements.push(generatePoKBDDT16MacStatementConstantTime(bddt16Params,
        revealedMsgs1,
        false));
    verifierStatements.push(generateAccumulatorMembershipStatement(
        params,
        pk,
        prk,
        accumulated
    ));
    verifierStatements.push(generateAccumulatorKVMembershipStatement(accumulated));
    verifierStatements.push(generateKBUniversalAccumulatorMembershipVerifierStatement(params, pk, kbUniAccumulator.mem));
    verifierStatements.push(generateKBUniversalAccumulatorNonMembershipVerifierStatement(params, pk, kbUniAccumulator.non_mem));
    verifierStatements.push(generateKBUniversalAccumulatorKVMembershipStatement(kbUniAccumulator.mem));
    verifierStatements.push(generateKBUniversalAccumulatorKVNonMembershipStatement(kbUniAccumulator.non_mem));

    const verifierProofSpec = generateProofSpecG1(verifierStatements, metaStatements, []);
    expect(isProofSpecG1Valid(verifierProofSpec)).toEqual(true);
    checkResult(verifyCompositeProofG1(proof, verifierProofSpec));

    const dps: Map<number, [number, Uint8Array]> = getAllKeyedSubproofsFromProof(proof);
    expect(dps.size).toEqual(4);
    const dp0 = dps.get(1);
    const dp1 = dps.get(3);
    const dp2 = dps.get(6);
    const dp3 = dps.get(7);
    expect(Array.isArray(dp0) && dp0.length).toEqual(2);
    expect(Array.isArray(dp1) && dp1.length).toEqual(2);
    expect(Array.isArray(dp2) && dp2.length).toEqual(2);
    expect(Array.isArray(dp3) && dp3.length).toEqual(2);
    // @ts-ignore
    expect(dp0[0]).toEqual(0);
    // @ts-ignore
    expect(dp1[0]).toEqual(1);
    // @ts-ignore
    expect(dp2[0]).toEqual(2);
    // @ts-ignore
    expect(dp3[0]).toEqual(3);

    // @ts-ignore
    checkResult(verifyBDDT16KeyedProof(dp0[1], bddt16Sk));
    // @ts-ignore
    checkResult(verifyVBAccumMembershipKeyedProof(dp1[1], sk));
    // @ts-ignore
    checkResult(verifyKBUniAccumMembershipKeyedProof(dp2[1], sk));
    // @ts-ignore
    checkResult(verifyKBUniAccumNonMembershipKeyedProof(dp3[1], sk));

    const macPkG1 = bddt16MacGeneratePublicKeyG1(bddt16Sk, bddt16Params);
    // @ts-ignore
    const pv1 = proofOfValidityOfBDDT16KeyedProof(dp0[1], bddt16Sk, macPkG1, bddt16Params);
    // @ts-ignore
    checkResult(verifyProofOfValidityOfBDDT16KeyedProof(pv1, dp0[1], macPkG1, bddt16Params));

    const accumParamsKv = generateAccumulatorParamsForKeyedVerification();
    const accumPkG1 = generateAccumulatorPublicKeyForKeyedVerification(sk, accumParamsKv);
    // @ts-ignore
    const pv2 = proofOfValidityOfVBAccumMembershipKeyedProof(dp1[1], sk, accumPkG1, accumParamsKv);
    // @ts-ignore
    checkResult(verifyProofOfValidityOfVBAccumMembershipKeyedProof(pv2, dp1[1], accumPkG1, accumParamsKv));

    // @ts-ignore
    const pv3 = proofOfValidityOfKBUniAccumMembershipKeyedProof(dp2[1], sk, accumPkG1, accumParamsKv);
    // @ts-ignore
    checkResult(verifyProofOfValidityOfKBUniAccumMembershipKeyedProof(pv3, dp2[1], accumPkG1, accumParamsKv));

    // @ts-ignore
    const pv4 = proofOfValidityOfKBUniAccumNonMembershipKeyedProof(dp3[1], sk, accumPkG1, accumParamsKv);
    // @ts-ignore
    checkResult(verifyProofOfValidityOfKBUniAccumNonMembershipKeyedProof(pv4, dp3[1], accumPkG1, accumParamsKv));
  })
})