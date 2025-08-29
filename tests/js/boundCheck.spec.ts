import {
  initializeWasm,
  boundCheckSnarkSetup,
  legosnarkDecompressPk,
  bbsPlusGenerateSignatureParamsG1,
  bbsPlusGenerateSigningKey,
  bbsPlusGeneratePublicKeyG2,
  BbsPlusSigParams,
  bbsPlusSignG1,
  bbsPlusVerifyG1,
  generatePoKBBSPlusSignatureVerifierStatement,
  generateBoundCheckLegoProverStatement,
  generateFieldElementFromNumber,
  generateWitnessEqualityMetaStatement,
  generatePoKBBSPlusSignatureWitness,
  generateBoundCheckWitness,
  generateCompositeProofG1WithDeconstructedProofSpec,
  verifyCompositeProofG1WithDeconstructedProofSpec,
  generateBoundCheckLegoVerifierStatement,
  legosnarkVkFromPk,
  generateBoundCheckLegoProverStatementFromParamRefs,
  generateSetupParamForLegoVerifyingKey,
  generateBoundCheckLegoVerifierStatementFromParamRefs,
  generateSetupParamForLegoProvingKey,
  boundCheckBppSetup,
  generateBoundCheckBppStatement,
  generateBoundCheckBppWitness,
  decompressBppParams,
  generateSetupParamForBppParams,
  generateBoundCheckBppStatementFromParamRefs,
  boundCheckSmcSetup,
  decompressSmcParams,
  generateBoundCheckSmcStatement,
  generateBoundCheckSmcWitness,
  generateSetupParamForSmcParams,
  generateBoundCheckSmcStatementFromParamRefs,
  boundCheckSmcWithKVSetup,
  generateBoundCheckSmcWithKVProverStatement,
  generateBoundCheckSmcWithKVVerifierStatement,
  generateBoundCheckSmcWithKVProverStatementFromParamRefs, generateBoundCheckSmcWithKVVerifierStatementFromParamRefs,
  generateBoundCheckSmcWithKVWitness, generatePoKBBSPlusSignatureProverStatement,
  decompressSmcParamsKV, decompressSmcParamsKVAndSk, generateSetupParamForSmcParamsKV, generateSetupParamForSmcParamsKVAndSk
} from "../../lib";

import { checkResult, getRevealedUnrevealed, stringToBytes } from "./util";

describe("Prove and verify bounds on signed messages", () => {
  const messageCount = 5;
  // Message index whose bounds are checked
  const msgIdx = 1;

  let sigParams: BbsPlusSigParams,
    sigSk: Uint8Array,
    sigPk: Uint8Array,
    sig: Uint8Array,
    min: number,
    max: number,
    proof: Uint8Array;
  let snarkPk: Uint8Array, snarkPkDecom: Uint8Array, snarkVkDecom: Uint8Array;
  const base = 2, valueBitSize = 64;
  let bppSetupParams: Uint8Array, bppSetupParamsDecom: Uint8Array;
  let smcSetupParams: Uint8Array, smcSetupParamsDecom: Uint8Array;
  let smcWithKVSetup: Uint8Array[], smcWithKVProverParams: Uint8Array, smcWithKVVerifierParams: Uint8Array;

  const messages: Uint8Array[] = [];

  function checkOverSingleMessage(proverStmt, verifierStmt, witnessGen, proverParams, verifierParams) {
    const revealedIndices = new Set<number>();
    revealedIndices.add(4);

    const [revealedMsgs, unrevealedMsgs] = getRevealedUnrevealed(
      messages,
      revealedIndices
    );
    const statement1 = generatePoKBBSPlusSignatureProverStatement(
      sigParams,
      revealedMsgs,
      false
    );

    console.time("bound check prover stmt");
    const statement2 = proverStmt(
      min,
      max,
      proverParams,
      true
    );
    console.timeEnd("bound check prover stmt");

    const proverStatements: Uint8Array[] = [];
    proverStatements.push(statement1);
    proverStatements.push(statement2);

    const metaStatements: Uint8Array[] = [];
    const set = new Set<[number, number]>();
    set.add([0, msgIdx]);
    set.add([1, 0]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set));

    const witness1 = generatePoKBBSPlusSignatureWitness(sig, unrevealedMsgs, false);
    const witness2 = witnessGen(messages[msgIdx]);

    const witnesses: Uint8Array[] = [];
    witnesses.push(witness1);
    witnesses.push(witness2);

    const nonce = stringToBytes("test-nonce");

    console.time("proof gen");
    proof = generateCompositeProofG1WithDeconstructedProofSpec(
      proverStatements,
      metaStatements,
      [],
      witnesses,
      undefined,
      nonce
    );
    console.timeEnd("proof gen");

    console.time("bound check verifier stmt");
    const statement3 = verifierStmt(
      min,
      max,
      verifierParams,
      true
    );
    console.timeEnd("bound check verifier stmt");

    const verifierStatements: Uint8Array[] = [];
    verifierStatements.push(generatePoKBBSPlusSignatureVerifierStatement(
      sigParams,
      sigPk,
      revealedMsgs,
      false
    ));
    verifierStatements.push(statement3);

    console.time("proof ver");
    const res = verifyCompositeProofG1WithDeconstructedProofSpec(
      proof,
      verifierStatements,
      metaStatements,
      [],
      undefined,
      nonce
    );
    console.timeEnd("proof ver");
    checkResult(res);
  }

  function checkOverMultipleMessages(setupParamProver, setupParamVerifier, proverStmt, verifierStmt, witnessGen, proverParams, verifierParams) {
    const [revealedMsgs, unrevealedMsgs] = getRevealedUnrevealed(
      messages,
      new Set<number>()
    );
    const statement1 = generatePoKBBSPlusSignatureProverStatement(
      sigParams,
      revealedMsgs,
      false
    );

    console.time("bound check prover setup param");
    const provingSetupParams: Uint8Array[] = [];
    provingSetupParams.push(
      setupParamProver(proverParams, true)
    );
    console.timeEnd("bound check prover setup param");

    const statement2 = proverStmt(
      min,
      max,
      0
    );
    const statement3 = proverStmt(
      min,
      max,
      0
    );
    const statement4 = proverStmt(
      min,
      max,
      0
    );

    const proverStatements: Uint8Array[] = [];
    proverStatements.push(statement1);
    proverStatements.push(statement2);
    proverStatements.push(statement3);
    proverStatements.push(statement4);

    // All messages are within bounds by choice during test setup
    const metaStatements: Uint8Array[] = [];
    const set1 = new Set<[number, number]>();
    set1.add([0, msgIdx]);
    set1.add([1, 0]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set1));

    const set2 = new Set<[number, number]>();
    set2.add([0, msgIdx + 1]);
    set2.add([2, 0]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set2));

    const set3 = new Set<[number, number]>();
    set3.add([0, msgIdx + 2]);
    set3.add([3, 0]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set3));

    const witness1 = generatePoKBBSPlusSignatureWitness(sig, unrevealedMsgs, false);
    const witness2 = witnessGen(messages[msgIdx]);
    const witness3 = witnessGen(messages[msgIdx + 1]);
    const witness4 = witnessGen(messages[msgIdx + 2]);

    const witnesses: Uint8Array[] = [];
    witnesses.push(witness1);
    witnesses.push(witness2);
    witnesses.push(witness3);
    witnesses.push(witness4);

    const nonce = stringToBytes("test-nonce");

    console.time("proof gen");
    proof = generateCompositeProofG1WithDeconstructedProofSpec(
      proverStatements,
      metaStatements,
      provingSetupParams,
      witnesses,
      undefined,
      nonce
    );
    console.timeEnd("proof gen");

    console.time("bound check verifier setup param");
    const verifierSetupParams: Uint8Array[] = [];
    verifierSetupParams.push(
      setupParamVerifier(verifierParams, true)
    );
    console.timeEnd("bound check verifier setup param");

    const statement5 = verifierStmt(
      min,
      max,
      0
    );
    const statement6 = verifierStmt(
      min,
      max,
      0
    );
    const statement7 = verifierStmt(
      min,
      max,
      0
    );

    const verifierStatements: Uint8Array[] = [];
    verifierStatements.push(generatePoKBBSPlusSignatureVerifierStatement(
      sigParams,
      sigPk,
      revealedMsgs,
      false
    ));
    verifierStatements.push(statement5);
    verifierStatements.push(statement6);
    verifierStatements.push(statement7);

    console.time("proof ver");
    const res = verifyCompositeProofG1WithDeconstructedProofSpec(
      proof,
      verifierStatements,
      metaStatements,
      verifierSetupParams,
      undefined,
      nonce
    );
    console.timeEnd("proof ver");
    expect(res.verified).toBe(true);
  }

  beforeAll(async () => {
    await initializeWasm();
  });

  it("verifier setup for Legogroth16 based", () => {
    snarkPk = boundCheckSnarkSetup(false);
  }, 10000);

  it("public setup for Bulletproofs++ based", () => {
    bppSetupParams = boundCheckBppSetup(stringToBytes("test"), base, valueBitSize, false);
  }, 10000);

  it("verifier setup for set-membership check based", () => {
    smcSetupParams = boundCheckSmcSetup(stringToBytes("test"), base, false);
  }, 10000);

  it("verifier setup for set-membership check based with keyed-verification", () => {
    smcWithKVSetup = boundCheckSmcWithKVSetup(stringToBytes("test"), base, false);
  }, 10000);

  it("decompress snark proving and verifying key", () => {
    console.time("Snark Pk decompressed");
    snarkPkDecom = legosnarkDecompressPk(snarkPk);
    console.timeEnd("Snark Pk decompressed");

    console.time("Snark Vk decompressed");
    snarkVkDecom = legosnarkVkFromPk(snarkPk, true);
    console.timeEnd("Snark Vk decompressed");
  }, 50000);

  it("decompress Bulletproofs++ params", () => {
    console.time("Bulletproofs++ params decompressed");
    bppSetupParamsDecom = decompressBppParams(bppSetupParams);
    console.timeEnd("Bulletproofs++ params decompressed");
  }, 50000);

  it("decompress set-membership check params", () => {
    console.time("set-membership check params decompressed");
    smcSetupParamsDecom = decompressSmcParams(smcSetupParams);
    console.timeEnd("set-membership check params decompressed");
  }, 50000);

  it("decompress set-membership check with keyed verification params", () => {
    console.time("set-membership check params decompressed");
    smcWithKVSetup = boundCheckSmcWithKVSetup(stringToBytes("test"), base, false);
    smcWithKVProverParams = decompressSmcParamsKV(smcWithKVSetup[0]);
    smcWithKVVerifierParams = decompressSmcParamsKVAndSk(smcWithKVSetup[1]); console.timeEnd("set-membership check params decompressed");
  }, 50000);

  it("signature setup and sign messages", () => {
    sigParams = bbsPlusGenerateSignatureParamsG1(messageCount);
    sigSk = bbsPlusGenerateSigningKey();
    sigPk = bbsPlusGeneratePublicKeyG2(sigSk, sigParams);

    min = 100;
    max = 200;
    for (let i = 0; i < messageCount; i++) {
      let m = generateFieldElementFromNumber(min + 1 + i);
      messages.push(m);
    }
    sig = bbsPlusSignG1(messages, sigSk, sigParams, false);
    const res = bbsPlusVerifyG1(messages, sig, sigPk, sigParams, false);
    expect(res.verified).toBe(true);
  });

  it("bounds should be positive integers", () => {
    expect(() =>
      generateBoundCheckLegoProverStatement(-6, max, snarkPkDecom, true)
    ).toThrow();
    expect(() =>
      generateBoundCheckLegoVerifierStatement(-6, max, snarkVkDecom, true)
    ).toThrow();
    expect(() =>
      generateBoundCheckLegoProverStatement(10.1, max, snarkPkDecom, true)
    ).toThrow();
    expect(() =>
      generateBoundCheckLegoVerifierStatement(10.1, max, snarkVkDecom, true)
    ).toThrow();
    expect(() =>
      generateBoundCheckLegoProverStatement(10, 20.8, snarkPkDecom, true)
    ).toThrow();
    expect(() =>
      generateBoundCheckLegoVerifierStatement(10, 20.8, snarkVkDecom, true)
    ).toThrow();
    expect(() =>
      generateBoundCheckLegoProverStatement(10, -90, snarkPkDecom, true)
    ).toThrow();
    expect(() =>
      generateBoundCheckLegoVerifierStatement(10, -90, snarkVkDecom, true)
    ).toThrow();
  });

  it("create and verify a proof over single signed message using Legogroth16", () => {
    checkOverSingleMessage(generateBoundCheckLegoProverStatement, generateBoundCheckLegoVerifierStatement, generateBoundCheckWitness, snarkPkDecom, snarkVkDecom)
  }, 10000);

  it("create and verify a proof over single signed message using Bulletproofs++", () => {
    checkOverSingleMessage(generateBoundCheckBppStatement, generateBoundCheckBppStatement, generateBoundCheckBppWitness, bppSetupParamsDecom, bppSetupParamsDecom)
  }, 10000);

  it("create and verify a proof over single signed message using set-membership check", () => {
    checkOverSingleMessage(generateBoundCheckSmcStatement, generateBoundCheckSmcStatement, generateBoundCheckSmcWitness, smcSetupParamsDecom, smcSetupParamsDecom)
  }, 10000);

  it("create and verify a proof over single signed message using set-membership check with keyed-verification", () => {
    checkOverSingleMessage(generateBoundCheckSmcWithKVProverStatement, generateBoundCheckSmcWithKVVerifierStatement, generateBoundCheckSmcWithKVWitness, smcWithKVProverParams, smcWithKVVerifierParams)
  }, 10000);

  it("create and verify a proof over multiple signed messages using Legogroth16", () => {
    checkOverMultipleMessages(generateSetupParamForLegoProvingKey, generateSetupParamForLegoVerifyingKey, generateBoundCheckLegoProverStatementFromParamRefs, generateBoundCheckLegoVerifierStatementFromParamRefs, generateBoundCheckWitness, snarkPkDecom, snarkVkDecom)
  }, 10000);

  it("create and verify a proof over multiple signed messages using Bulletproofs++", () => {
    checkOverMultipleMessages(generateSetupParamForBppParams, generateSetupParamForBppParams, generateBoundCheckBppStatementFromParamRefs, generateBoundCheckBppStatementFromParamRefs, generateBoundCheckBppWitness, bppSetupParamsDecom, bppSetupParamsDecom)
  }, 10000);

  it("create and verify a proof over multiple signed messages using set-membership check", () => {
    checkOverMultipleMessages(generateSetupParamForSmcParams, generateSetupParamForSmcParams, generateBoundCheckSmcStatementFromParamRefs, generateBoundCheckSmcStatementFromParamRefs, generateBoundCheckSmcWitness, smcSetupParamsDecom, smcSetupParamsDecom)
  }, 10000);

  it("create and verify a proof over multiple signed messages using set-membership check with keyed-verification", () => {
    checkOverMultipleMessages(generateSetupParamForSmcParamsKV, generateSetupParamForSmcParamsKVAndSk, generateBoundCheckSmcWithKVProverStatementFromParamRefs, generateBoundCheckSmcWithKVVerifierStatementFromParamRefs, generateBoundCheckSmcWithKVWitness, smcWithKVProverParams, smcWithKVVerifierParams)
  }, 10000);
});
