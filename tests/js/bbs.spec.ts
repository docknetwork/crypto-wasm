import {
  bbsGenerateSignatureParams,
  bbsIsSignatureParamsValid,
  bbsSignatureParamsMaxSupportedMsgs,
  bbsGenerateSigningKey,
  bbsGeneratePublicKey,
  bbsIsPublicKeyValid,
  bbsSign,
  generateRandomFieldElement,
  bbsCommitMsgs,
  bbsInitializeProofOfKnowledgeOfSignature,
  bbsGenProofOfKnowledgeOfSignature,
  bbsVerifyProofOfKnowledgeOfSignature,
  bbsChallengeContributionFromProtocol,
  bbsChallengeContributionFromProof,
  generateChallengeFromBytes,
  bbsAdaptSigParamsForMsgCount,
  bbsSignatureParamsToBytes,
  bbsSignatureParamsFromBytes,
  BbsSigParams,
  initializeWasm,
  bbsGenerateKeyPair,
  bbsVerify,
  bbsBlindSign,
} from "../../lib";

import { stringToBytes } from "../utilities";

describe("For BBS signatures", () => {
  let sigParamsG1: BbsSigParams, sk: Uint8Array, pkG2: Uint8Array;
  const seed = new Uint8Array([0, 2, 3, 4, 5]);
  const messages = [
    stringToBytes("Message1"),
    stringToBytes("Message2"),
    stringToBytes("Message3"),
    stringToBytes("Message4"),
    stringToBytes("Message4"),
    stringToBytes("Message6"),
  ];
  const messageCount = messages.length;

  beforeAll(async () => {
    await initializeWasm();
  });

  it("generate secret key", () => {
    const sk_ = bbsGenerateSigningKey();
    expect(sk_).toBeInstanceOf(Uint8Array);

    const sk1 = bbsGenerateSigningKey(seed);
    expect(sk1).toBeInstanceOf(Uint8Array);

    const sk2 = bbsGenerateSigningKey(seed);
    expect(sk2).toBeInstanceOf(Uint8Array);

    expect(sk1).toEqual(sk2);

    sk = sk1;
  });

  it("generate signature params in G1", () => {
    expect(() => bbsGenerateSignatureParams(-5)).toThrow();
    expect(() => bbsGenerateSignatureParams(6.3)).toThrow();

    const params0 = bbsGenerateSignatureParams(messageCount);
    expect(params0).toBeInstanceOf(Object);
    expect(params0.h.length).toEqual(messageCount);
    expect(bbsIsSignatureParamsValid(params0)).toBe(true);

    const label = stringToBytes("Sig params g1");
    const params = bbsGenerateSignatureParams(messageCount, label);
    expect(params).toBeInstanceOf(Object);
    expect(params.h.length).toEqual(messageCount);
    expect(bbsIsSignatureParamsValid(params)).toBe(true);
    expect(bbsSignatureParamsMaxSupportedMsgs(params)).toBe(messageCount);

    const bytes = bbsSignatureParamsToBytes(params);
    const deserzParams = bbsSignatureParamsFromBytes(bytes);
    expect(params).toEqual(deserzParams);

    sigParamsG1 = params;
  });

  it("generate public key in G2 from secret key", () => {
    pkG2 = bbsGeneratePublicKey(sk, sigParamsG1);
    expect(pkG2).toBeInstanceOf(Uint8Array);
    expect(bbsIsPublicKeyValid(pkG2)).toBe(true);
  });

  it("generate keypair in G2 from given seed", () => {
    const keypair = bbsGenerateKeyPair(sigParamsG1, seed);
    expect(keypair).toBeInstanceOf(Object);
    const keypair1 = bbsGenerateKeyPair(sigParamsG1, seed);
    expect(keypair1).toBeInstanceOf(Object);
    expect(keypair).toEqual(keypair1);

    expect(keypair.secret_key).toEqual([...sk]);
    expect(keypair.public_key).toEqual([...pkG2]);
  });

  it("generate and verify signature in G1", () => {
    const sig = bbsSign(messages, sk, sigParamsG1, true);
    const res = bbsVerify(messages, sig, pkG2, sigParamsG1, true);
    expect(res.verified).toBe(true);
  });

  it("extend signature params in G1", () => {
    const label = stringToBytes("Sig params g1");
    const params0 = bbsGenerateSignatureParams(1);
    expect(bbsSignatureParamsMaxSupportedMsgs(params0)).toBe(1);

    const params1 = bbsAdaptSigParamsForMsgCount(params0, label, 5);
    expect(bbsSignatureParamsMaxSupportedMsgs(params1)).toBe(5);
    expect(bbsIsSignatureParamsValid(params1)).toBe(true);
    expect(params0.h[0]).toEqual(params1.h[0]);

    const params2 = bbsAdaptSigParamsForMsgCount(params1, label, 2);
    expect(bbsSignatureParamsMaxSupportedMsgs(params2)).toBe(2);
    expect(bbsIsSignatureParamsValid(params2)).toBe(true);
    expect(params1.h[0]).toEqual(params2.h[0]);
    expect(params1.h[1]).toEqual(params2.h[1]);
  });

  it("generate and verify a blind signature in G1", () => {
    // Commit to message indices 1 and 5
    const msgsToCommit = new Map();
    msgsToCommit.set(1, messages[1]);
    msgsToCommit.set(5, messages[5]);

    const msgsNotToCommit = new Map();
    msgsNotToCommit.set(0, messages[0]);
    msgsNotToCommit.set(2, messages[2]);
    msgsNotToCommit.set(3, messages[3]);
    msgsNotToCommit.set(4, messages[4]);

    const commitment = bbsCommitMsgs(msgsToCommit, sigParamsG1, true);
    const sig = bbsBlindSign(
      commitment,
      msgsNotToCommit,
      sk,
      sigParamsG1,
      true
    );
    const res = bbsVerify(messages, sig, pkG2, sigParamsG1, true);
    expect(res.verified).toBe(true);
  });

  it("generate a proof of knowledge of signature in G1", () => {
    const sig = bbsSign(messages, sk, sigParamsG1, true);
    const res = bbsVerify(messages, sig, pkG2, sigParamsG1, true);
    expect(res.verified).toBe(true);

    // Prover reveals message indices 0 and 2 and supplies blindings for message indices 1, 4 and 5
    const blindings = new Map();
    const revealed: Set<number> = new Set();
    const revealedMsgs = new Map();

    blindings.set(1, generateRandomFieldElement());
    blindings.set(4, generateRandomFieldElement());
    blindings.set(5, generateRandomFieldElement());
    revealed.add(0);
    revealed.add(2);
    revealedMsgs.set(0, messages[0]);
    revealedMsgs.set(2, messages[2]);

    const protocol = bbsInitializeProofOfKnowledgeOfSignature(
      sig,
      sigParamsG1,
      messages,
      blindings,
      revealed,
      true
    );
    const pBytes = bbsChallengeContributionFromProtocol(
      protocol,
      revealedMsgs,
      sigParamsG1,
      true
    );
    expect(pBytes).toBeInstanceOf(Uint8Array);
    const proverChallenge = generateChallengeFromBytes(pBytes);
    const proof = bbsGenProofOfKnowledgeOfSignature(protocol, proverChallenge);

    const vBytes = bbsChallengeContributionFromProof(
      proof,
      revealedMsgs,
      sigParamsG1,
      true
    );
    expect(vBytes).toBeInstanceOf(Uint8Array);
    expect(pBytes).toEqual(vBytes);
    const verifierChallenge = generateChallengeFromBytes(vBytes);
    expect(proverChallenge).toEqual(verifierChallenge);
    const result = bbsVerifyProofOfKnowledgeOfSignature(
      proof,
      revealedMsgs,
      verifierChallenge,
      pkG2,
      sigParamsG1,
      true
    );
    expect(result.verified).toBe(true);
  });
});
