import {
  generateSignatureParamsG1,
  generateSignatureParamsG2,
  isSignatureParamsG1Valid,
  bbsSignatureParamsG1MaxSupportedMsgs,
  isSignatureParamsG2Valid,
  bbsSignatureParamsG2MaxSupportedMsgs,
  generateBBSSigningKey,
  generateBBSPublicKeyG1,
  generateBBSPublicKeyG2,
  generateBBSKeyPairG1,
  generateBBSKeyPairG2,
  isBBSPublicKeyG1Valid,
  isBBSPublicKeyG2Valid,
  bbsSignG1,
  bbsVerifyG1,
  bbsSignG2,
  bbsVerifyG2,
  generateRandomFieldElement,
  bbsCommitMsgsInG1,
  bbsCommitMsgsInG2,
  bbsBlindSignG1,
  bbsBlindSignG2,
  bbsUnblindSigG1,
  bbsUnblindSigG2,
  bbsInitializeProofOfKnowledgeOfSignature,
  bbsGenProofOfKnowledgeOfSignature,
  bbsVerifyProofOfKnowledgeOfSignature,
  bbsChallengeContributionFromProtocol,
  bbsChallengeContributionFromProof,
  generateChallengeFromBytes,
  bbsAdaptSigParamsG1ForMsgCount,
  bbsAdaptSigParamsG2ForMsgCount,
  bbsSignatureParamsG1ToBytes,
  bbsSignatureParamsG1FromBytes,
  bbsSignatureParamsG2FromBytes,
  bbsSignatureParamsG2ToBytes,
  BbsSigParams,
  initializeWasm,
} from "../../lib";

import { stringToBytes } from "../utilities";

describe("For BBS+ signatures", () => {
  let sigParamsG1: BbsSigParams,
    sigParamsG2: BbsSigParams,
    sk: Uint8Array,
    pkG1: Uint8Array,
    pkG2: Uint8Array;
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
    const sk_ = generateBBSSigningKey();
    expect(sk_).toBeInstanceOf(Uint8Array);

    const sk1 = generateBBSSigningKey(seed);
    expect(sk1).toBeInstanceOf(Uint8Array);

    const sk2 = generateBBSSigningKey(seed);
    expect(sk2).toBeInstanceOf(Uint8Array);

    expect(sk1).toEqual(sk2);

    sk = sk1;
  });

  it("generate signature params in G1", () => {
    expect(() => generateSignatureParamsG1(-5)).toThrow();
    expect(() => generateSignatureParamsG1(6.3)).toThrow();

    const params0 = generateSignatureParamsG1(messageCount);
    expect(params0).toBeInstanceOf(Object);
    expect(params0.h.length).toEqual(messageCount);
    expect(isSignatureParamsG1Valid(params0)).toBe(true);

    const label = stringToBytes("Sig params g1");
    const params = generateSignatureParamsG1(messageCount, label);
    expect(params).toBeInstanceOf(Object);
    expect(params.h.length).toEqual(messageCount);
    expect(isSignatureParamsG1Valid(params)).toBe(true);
    expect(bbsSignatureParamsG1MaxSupportedMsgs(params)).toBe(messageCount);

    const bytes = bbsSignatureParamsG1ToBytes(params);
    const deserzParams = bbsSignatureParamsG1FromBytes(bytes);
    expect(params).toEqual(deserzParams);

    sigParamsG1 = params;
  });

  it("generate signature params in G2", () => {
    expect(() => generateSignatureParamsG2(-5)).toThrow();
    expect(() => generateSignatureParamsG2(6.3)).toThrow();

    const params0 = generateSignatureParamsG2(messageCount);
    expect(params0).toBeInstanceOf(Object);
    expect(params0.h.length).toEqual(messageCount);
    expect(isSignatureParamsG2Valid(params0)).toBe(true);

    const params = generateSignatureParamsG2(messageCount);
    expect(params).toBeInstanceOf(Object);
    expect(params.h.length).toEqual(messageCount);
    expect(isSignatureParamsG2Valid(params)).toBe(true);
    expect(bbsSignatureParamsG2MaxSupportedMsgs(params)).toBe(messageCount);

    const bytes = bbsSignatureParamsG2ToBytes(params);
    const deserzParams = bbsSignatureParamsG2FromBytes(bytes);
    expect(params).toEqual(deserzParams);

    sigParamsG2 = params;
  });

  it("generate public key in G1 from secret key", () => {
    pkG1 = generateBBSPublicKeyG1(sk, sigParamsG2);
    expect(pkG1).toBeInstanceOf(Uint8Array);
    expect(isBBSPublicKeyG1Valid(pkG1)).toBe(true);
  });

  it("generate public key in G2 from secret key", () => {
    pkG2 = generateBBSPublicKeyG2(sk, sigParamsG1);
    expect(pkG2).toBeInstanceOf(Uint8Array);
    expect(isBBSPublicKeyG2Valid(pkG2)).toBe(true);
  });

  it("generate keypair in G1 from given seed", () => {
    const keypair = generateBBSKeyPairG1(sigParamsG2, seed);
    expect(keypair).toBeInstanceOf(Object);
    const keypair1 = generateBBSKeyPairG1(sigParamsG2, seed);
    expect(keypair1).toBeInstanceOf(Object);
    expect(keypair).toEqual(keypair1);

    expect(keypair.secret_key).toEqual(sk);
    expect(keypair.public_key).toEqual(pkG1);
  });

  it("generate keypair in G2 from given seed", () => {
    const keypair = generateBBSKeyPairG2(sigParamsG1, seed);
    expect(keypair).toBeInstanceOf(Object);
    const keypair1 = generateBBSKeyPairG2(sigParamsG1, seed);
    expect(keypair1).toBeInstanceOf(Object);
    expect(keypair).toEqual(keypair1);

    expect(keypair.secret_key).toEqual(sk);
    expect(keypair.public_key).toEqual(pkG2);
  });

  it("generate and verify signature in G1", () => {
    const sig = bbsSignG1(messages, sk, sigParamsG1, true);
    const res = bbsVerifyG1(messages, sig, pkG2, sigParamsG1, true);
    expect(res.verified).toBe(true);
  });

  it("generate and verify signature in G2", () => {
    const sig = bbsSignG2(messages, sk, sigParamsG2, true);
    const res = bbsVerifyG2(messages, sig, pkG1, sigParamsG2, true);
    expect(res.verified).toBe(true);
  });

  it("extend signature params in G1", () => {
    const label = stringToBytes("Sig params g1");
    const params0 = generateSignatureParamsG1(1);
    expect(bbsSignatureParamsG1MaxSupportedMsgs(params0)).toBe(1);

    const params1 = bbsAdaptSigParamsG1ForMsgCount(params0, label, 5);
    expect(bbsSignatureParamsG1MaxSupportedMsgs(params1)).toBe(5);
    expect(isSignatureParamsG1Valid(params1)).toBe(true);
    expect(params0.h[0]).toEqual(params1.h[0]);

    const params2 = bbsAdaptSigParamsG1ForMsgCount(params1, label, 2);
    expect(bbsSignatureParamsG1MaxSupportedMsgs(params2)).toBe(2);
    expect(isSignatureParamsG1Valid(params2)).toBe(true);
    expect(params1.h[0]).toEqual(params2.h[0])
    expect(params1.h[1]).toEqual(params2.h[1])
  });

  it("extend signature params in G2", () => {
    const label = stringToBytes("Sig params g2");
    const params0 = generateSignatureParamsG2(1);
    expect(bbsSignatureParamsG2MaxSupportedMsgs(params0)).toBe(1);

    const params1 = bbsAdaptSigParamsG2ForMsgCount(params0, label, 5);
    expect(bbsSignatureParamsG2MaxSupportedMsgs(params1)).toBe(5);
    expect(isSignatureParamsG2Valid(params1)).toBe(true);
    expect(params0.h[0]).toEqual(params1.h[0]);

    const params2 = bbsAdaptSigParamsG2ForMsgCount(params1, label, 2);
    expect(bbsSignatureParamsG2MaxSupportedMsgs(params2)).toBe(2);
    expect(isSignatureParamsG2Valid(params2)).toBe(true);
    expect(params1.h[0]).toEqual(params2.h[0])
    expect(params1.h[1]).toEqual(params2.h[1])
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

    const blinding = generateRandomFieldElement();
    const commitment = bbsCommitMsgsInG1(msgsToCommit, blinding, sigParamsG1, true);
    const blindSig = bbsBlindSignG1(commitment, msgsNotToCommit, sk, sigParamsG1, true);
    const sig = bbsUnblindSigG1(blindSig, blinding);
    const res = bbsVerifyG1(messages, sig, pkG2, sigParamsG1, true);
    expect(res.verified).toBe(true);
  });

  it("generate and verify a blind signature in G2", () => {
    // Commit to message indices 1 and 5
    const msgsToCommit = new Map();
    msgsToCommit.set(1, messages[1]);
    msgsToCommit.set(5, messages[5]);

    const msgsNotToCommit = new Map();
    msgsNotToCommit.set(0, messages[0]);
    msgsNotToCommit.set(2, messages[2]);
    msgsNotToCommit.set(3, messages[3]);
    msgsNotToCommit.set(4, messages[4]);

    const blinding = generateRandomFieldElement();
    const commitment = bbsCommitMsgsInG2(msgsToCommit, blinding, sigParamsG2, true);
    const blindSig = bbsBlindSignG2(commitment, msgsNotToCommit, sk, sigParamsG2, true);
    const sig = bbsUnblindSigG2(blindSig, blinding);
    const res = bbsVerifyG2(messages, sig, pkG1, sigParamsG2, true);
    expect(res.verified).toBe(true);
  });

  it("generate a proof of knowledge of signature in G1", () => {
    const sig = bbsSignG1(messages, sk, sigParamsG1, true);
    const res = bbsVerifyG1(messages, sig, pkG2, sigParamsG1, true);
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

    const protocol = bbsInitializeProofOfKnowledgeOfSignature(sig, sigParamsG1, messages, blindings, revealed, true);
    const pBytes = bbsChallengeContributionFromProtocol(protocol, revealedMsgs, sigParamsG1, true);
    expect(pBytes).toBeInstanceOf(Uint8Array);
    const proverChallenge = generateChallengeFromBytes(pBytes);
    const proof = bbsGenProofOfKnowledgeOfSignature(protocol, proverChallenge);

    const vBytes = bbsChallengeContributionFromProof(proof, revealedMsgs, sigParamsG1, true);
    expect(vBytes).toBeInstanceOf(Uint8Array);
    expect(pBytes).toEqual(vBytes);
    const verifierChallenge = generateChallengeFromBytes(vBytes);
    expect(proverChallenge).toEqual(verifierChallenge);
    const result = bbsVerifyProofOfKnowledgeOfSignature(proof, revealedMsgs, verifierChallenge, pkG2, sigParamsG1, true);
    expect(result.verified).toBe(true);
  });

});
