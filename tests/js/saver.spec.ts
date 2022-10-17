import {
  bbsEncodeMessageForSigning,
  bbsSignG1,
  BbsSigParams,
  bbsVerifyG1,
  generateBBSPublicKeyG2,
  generateBBSSigningKey,
  generateCompositeProofG1WithDeconstructedProofSpec,
  generatePoKBBSSignatureStatement,
  generatePoKBBSSignatureWitness,
  generateSaverProverStatement,
  generateSaverProverStatementFromParamRefs,
  generateSaverVerifierStatement,
  generateSaverVerifierStatementFromParamRefs,
  generateSaverWitness,
  generateSetupParamForSaverCommitmentGens,
  generateSetupParamForSaverEncryptionGens,
  generateSetupParamForSaverEncryptionKey,
  generateSetupParamForSaverProvingKey,
  generateSetupParamForSaverVerifyingKey,
  generateSignatureParamsG1,
  generateWitnessEqualityMetaStatement,
  initializeWasm,
  saverDecompressChunkedCommitmentGenerators,
  saverDecompressDecryptionKey,
  saverDecompressEncryptionGenerators,
  saverDecompressEncryptionKey,
  saverDecompressSnarkPk,
  saverDecryptCiphertextUsingSnarkPk,
  saverDecryptCiphertextUsingSnarkVk,
  saverDecryptorSetup,
  saverGenerateChunkedCommitmentGenerators,
  saverGenerateEncryptionGenerators,
  saverGetCiphertextFromProof,
  saverGetCiphertextsFromProof,
  saverGetSnarkVkFromPk,
  saverVerifyDecryptionUsingSnarkPk,
  saverVerifyDecryptionUsingSnarkVk,
  verifyCompositeProofG1WithDeconstructedProofSpec,
} from "../../lib";

import {stringToBytes, getRevealedUnrevealed, areUint8ArraysEqual} from "../utilities";

describe("Verifiable encryption of a signed message", () => {
  const messageCount = 5;
  const chunkBitSize = 16;
  const encMsgIdx = 0;

  let sigParams: BbsSigParams,
    sigSk: Uint8Array,
    sigPk: Uint8Array,
    sig: Uint8Array,
    proof: Uint8Array;
  let snarkPk: Uint8Array,
    sk: Uint8Array,
    ek: Uint8Array,
    dk: Uint8Array,
    encGens: Uint8Array,
    commGens: Uint8Array;
  let snarkPkDecom: Uint8Array,
    snarkVkDecom: Uint8Array,
    ekDecom: Uint8Array,
    dkDecom: Uint8Array,
    encGensDecom: Uint8Array,
    commGensDecom: Uint8Array;

  const messages = new Array<Uint8Array>();

  beforeAll(async () => {
    await initializeWasm();
  });

  it("decryptor setup", () => {
    encGens = saverGenerateEncryptionGenerators();
    [snarkPk, sk, ek, dk] = saverDecryptorSetup(chunkBitSize, encGens, false);
  }, 10000);

  it("verifier setup", () => {
    commGens = saverGenerateChunkedCommitmentGenerators();
  });

  it("decompress public params", () => {
    encGensDecom = saverDecompressEncryptionGenerators(encGens);
    commGensDecom = saverDecompressChunkedCommitmentGenerators(commGens);
    ekDecom = saverDecompressEncryptionKey(ek);
    dkDecom = saverDecompressDecryptionKey(dk);
    console.log("Params and keys decompressed");
    console.time("Snark Pk decompressed");
    snarkPkDecom = saverDecompressSnarkPk(snarkPk);
    console.timeEnd("Snark Pk decompressed");
    console.time("Snark Vk decompressed");
    snarkVkDecom = saverGetSnarkVkFromPk(snarkPk, true);
    console.timeEnd("Snark Vk decompressed");
  }, 150000);

  it("signature setup and sign messages", () => {
    sigParams = generateSignatureParamsG1(messageCount);
    sigSk = generateBBSSigningKey();
    sigPk = generateBBSPublicKeyG2(sigSk, sigParams);

    for (let i = 0; i < messageCount; i++) {
      let m = stringToBytes(`${i + 1}`);
      m = bbsEncodeMessageForSigning(m);
      messages.push(m);
    }
    sig = bbsSignG1(messages, sigSk, sigParams, false);
    const res = bbsVerifyG1(messages, sig, sigPk, sigParams, false);
    expect(res.verified).toBe(true);
  });

  it("create and verify a proof of a single verifiably encrypted message", () => {
    const revealedIndices = new Set<number>();
    revealedIndices.add(4);

    const [revealedMsgs, unrevealedMsgs] = getRevealedUnrevealed(
      messages,
      revealedIndices
    );
    const statement1 = generatePoKBBSSignatureStatement(
      sigParams,
      sigPk,
      revealedMsgs,
      false
    );

    console.time("saver stmt");
    const statement2 = generateSaverProverStatement(
      chunkBitSize,
      encGensDecom,
      commGensDecom,
      ekDecom,
      snarkPkDecom,
      true
    );
    console.timeEnd("saver stmt");

    const proverStatements = new Array<Uint8Array>();
    proverStatements.push(statement1);
    proverStatements.push(statement2);

    const metaStatements = new Array<Uint8Array>();
    const set = new Set<[number, number]>();
    set.add([0, encMsgIdx]);
    set.add([1, 0]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set));

    const witness1 = generatePoKBBSSignatureWitness(sig, unrevealedMsgs, false);
    const witness2 = generateSaverWitness(messages[encMsgIdx]);

    const witnesses = new Array<Uint8Array>();
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

    console.time("saver verifier stmt");
    const statement3 = generateSaverVerifierStatement(
      chunkBitSize,
      encGensDecom,
      commGensDecom,
      ekDecom,
      snarkVkDecom,
      true
    );
    console.timeEnd("saver check verifier stmt");

    const verifierStatements = new Array<Uint8Array>();
    verifierStatements.push(statement1);
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
    expect(res.verified).toBe(true);
  }, 30000);

  it("decrypt and verify", () => {
    const ct = saverGetCiphertextFromProof(proof, 1);
    const ct1 = saverGetCiphertextsFromProof(proof, [1]);
    expect(areUint8ArraysEqual(ct, ct1[0])).toEqual(true);

    console.time("decrypt using pk");
    const [decryptedMessage, nu] = saverDecryptCiphertextUsingSnarkPk(
      ct,
      sk,
      dkDecom,
      snarkPkDecom,
      chunkBitSize,
      true
    );
    console.timeEnd("decrypt using pk");

    expect(decryptedMessage).toEqual(messages[encMsgIdx]);

    console.time("decrypt ver using pk");
    const res = saverVerifyDecryptionUsingSnarkPk(
      ct,
      decryptedMessage,
      nu,
      dkDecom,
      snarkPkDecom,
      encGensDecom,
      chunkBitSize,
      true
    );
    console.timeEnd("decrypt ver using pk");
    expect(res.verified).toBe(true);

    console.time("decrypt using vk");
    const [decryptedMessage1, nu1] = saverDecryptCiphertextUsingSnarkVk(
      ct,
      sk,
      dkDecom,
      snarkVkDecom,
      chunkBitSize,
      true
    );
    console.timeEnd("decrypt using vk");

    expect(decryptedMessage1).toEqual(messages[encMsgIdx]);

    console.time("decrypt ver using vk");
    const res1 = saverVerifyDecryptionUsingSnarkVk(
      ct,
      decryptedMessage1,
      nu1,
      dkDecom,
      snarkVkDecom,
      encGensDecom,
      chunkBitSize,
      true
    );
    console.timeEnd("decrypt ver using vk");
    expect(res1.verified).toBe(true);
  }, 10000);

  it("create and verify a proof of multiple verifiably encrypted messages", () => {
    const [revealedMsgs, unrevealedMsgs] = getRevealedUnrevealed(
      messages,
      new Set<number>()
    );
    const statement1 = generatePoKBBSSignatureStatement(
      sigParams,
      sigPk,
      revealedMsgs,
      false
    );

    console.time("saver setup params");
    const provingSetupParams = new Array<Uint8Array>();
    provingSetupParams.push(
      generateSetupParamForSaverEncryptionGens(encGensDecom, true)
    );
    provingSetupParams.push(
      generateSetupParamForSaverCommitmentGens(commGensDecom, true)
    );
    provingSetupParams.push(
      generateSetupParamForSaverEncryptionKey(ekDecom, true)
    );
    provingSetupParams.push(
      generateSetupParamForSaverProvingKey(snarkPkDecom, true)
    );
    console.timeEnd("saver setup params");

    const statement2 = generateSaverProverStatementFromParamRefs(
      chunkBitSize,
      0,
      1,
      2,
      3
    );
    const statement3 = generateSaverProverStatementFromParamRefs(
      chunkBitSize,
      0,
      1,
      2,
      3
    );
    const statement4 = generateSaverProverStatementFromParamRefs(
      chunkBitSize,
      0,
      1,
      2,
      3
    );

    const proverStatements = new Array<Uint8Array>();
    proverStatements.push(statement1);
    proverStatements.push(statement2);
    proverStatements.push(statement3);
    proverStatements.push(statement4);

    const metaStatements = new Array<Uint8Array>();
    const set1 = new Set<[number, number]>();
    set1.add([0, encMsgIdx]);
    set1.add([1, 0]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set1));

    const set2 = new Set<[number, number]>();
    set2.add([0, encMsgIdx + 1]);
    set2.add([2, 0]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set2));

    const set3 = new Set<[number, number]>();
    set3.add([0, encMsgIdx + 2]);
    set3.add([3, 0]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set3));

    const witness1 = generatePoKBBSSignatureWitness(sig, unrevealedMsgs, false);
    const witness2 = generateSaverWitness(messages[encMsgIdx]);
    const witness3 = generateSaverWitness(messages[encMsgIdx + 1]);
    const witness4 = generateSaverWitness(messages[encMsgIdx + 2]);

    const witnesses = new Array<Uint8Array>();
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

    console.time("saver verifier setup params");
    const verifierSetupParams = new Array<Uint8Array>();
    verifierSetupParams.push(
      generateSetupParamForSaverEncryptionGens(encGensDecom, true)
    );
    verifierSetupParams.push(
      generateSetupParamForSaverCommitmentGens(commGensDecom, true)
    );
    verifierSetupParams.push(
      generateSetupParamForSaverEncryptionKey(ekDecom, true)
    );
    verifierSetupParams.push(
      generateSetupParamForSaverVerifyingKey(snarkVkDecom, true)
    );
    console.timeEnd("saver check verifier setup params");

    const statement5 = generateSaverVerifierStatementFromParamRefs(
      chunkBitSize,
      0,
      1,
      2,
      3
    );
    const statement6 = generateSaverVerifierStatementFromParamRefs(
      chunkBitSize,
      0,
      1,
      2,
      3
    );
    const statement7 = generateSaverVerifierStatementFromParamRefs(
      chunkBitSize,
      0,
      1,
      2,
      3
    );

    const verifierStatements = new Array<Uint8Array>();
    verifierStatements.push(statement1);
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
  }, 90000);
});
