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
  bbsVerfiyG1,
  bbsSignG2,
  bbsVerfiyG2,
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
  generateChallengeFromBytes, bbsExtendSigParamsG1ForMsgCount, bbsExtendSigParamsG2ForMsgCount
} from "../../lib";

import { BbsSigParams } from "../../lib/types";

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

  it("generate secret key", async () => {
    const sk_ = await generateBBSSigningKey();
    expect(sk_).toBeInstanceOf(Uint8Array);

    const sk1 = await generateBBSSigningKey(seed);
    expect(sk1).toBeInstanceOf(Uint8Array);

    const sk2 = await generateBBSSigningKey(seed);
    expect(sk2).toBeInstanceOf(Uint8Array);

    expect(sk1).toEqual(sk2);

    sk = sk1;
  });

  it("generate signature params in G1", async () => {
    const params0 = await generateSignatureParamsG1(messageCount);
    expect(params0).toBeInstanceOf(Object);
    expect(params0.h.length).toEqual(messageCount);
    expect(await isSignatureParamsG1Valid(params0)).toBe(true);

    const label = stringToBytes("Sig params g1");
    const params = await generateSignatureParamsG1(messageCount, label);
    expect(params).toBeInstanceOf(Object);
    expect(params.h.length).toEqual(messageCount);
    expect(await isSignatureParamsG1Valid(params)).toBe(true);
    expect(await bbsSignatureParamsG1MaxSupportedMsgs(params)).toBe(messageCount);

    sigParamsG1 = params;
  });

  it("generate signature params in G2", async () => {
    const params0 = await generateSignatureParamsG2(messageCount);
    expect(params0).toBeInstanceOf(Object);
    expect(params0.h.length).toEqual(messageCount);
    expect(await isSignatureParamsG2Valid(params0)).toBe(true);

    const params = await generateSignatureParamsG2(messageCount);
    expect(params).toBeInstanceOf(Object);
    expect(params.h.length).toEqual(messageCount);
    expect(await isSignatureParamsG2Valid(params)).toBe(true);
    expect(await bbsSignatureParamsG2MaxSupportedMsgs(params)).toBe(messageCount);

    sigParamsG2 = params;
  });

  it("generate public key in G1 from secret key", async () => {
    pkG1 = await generateBBSPublicKeyG1(sk, sigParamsG2);
    expect(pkG1).toBeInstanceOf(Uint8Array);
    expect(await isBBSPublicKeyG1Valid(pkG1)).toBe(true);
  });

  it("generate public key in G2 from secret key", async () => {
    pkG2 = await generateBBSPublicKeyG2(sk, sigParamsG1);
    expect(pkG2).toBeInstanceOf(Uint8Array);
    expect(await isBBSPublicKeyG2Valid(pkG2)).toBe(true);
  });

  it("generate keypair in G1 from given seed", async () => {
    const keypair = await generateBBSKeyPairG1(sigParamsG2, seed);
    expect(keypair).toBeInstanceOf(Object);
    const keypair1 = await generateBBSKeyPairG1(sigParamsG2, seed);
    expect(keypair1).toBeInstanceOf(Object);
    expect(keypair).toEqual(keypair1);

    expect(keypair.secret_key).toEqual(sk);
    expect(keypair.public_key).toEqual(pkG1);
  });

  it("generate keypair in G2 from given seed", async () => {
    const keypair = await generateBBSKeyPairG2(sigParamsG1, seed);
    expect(keypair).toBeInstanceOf(Object);
    const keypair1 = await generateBBSKeyPairG2(sigParamsG1, seed);
    expect(keypair1).toBeInstanceOf(Object);
    expect(keypair).toEqual(keypair1);

    expect(keypair.secret_key).toEqual(sk);
    expect(keypair.public_key).toEqual(pkG2);
  });

  it("generate and verify signature in G1", async () => {
    const sig = await bbsSignG1(messages, sk, sigParamsG1, true);
    const res = await bbsVerfiyG1(messages, sig, pkG2, sigParamsG1, true);
    expect(res.verified).toBe(true);
  });

  it("generate and verify signature in G2", async () => {
    const sig = await bbsSignG2(messages, sk, sigParamsG2, true);
    const res = await bbsVerfiyG2(messages, sig, pkG1, sigParamsG2, true);
    expect(res.verified).toBe(true);
  });

  it("extend signature params in G1", async () => {
    const label = stringToBytes("Sig params g1");
    const params0 = await generateSignatureParamsG1(1);
    expect(await bbsSignatureParamsG1MaxSupportedMsgs(params0)).toBe(1);

    const params1 = await bbsExtendSigParamsG1ForMsgCount(params0, label, 5);
    expect(await bbsSignatureParamsG1MaxSupportedMsgs(params1)).toBe(5);
    expect(params0.h[0]).toEqual(params1.h[0]);

    const params2 = await bbsExtendSigParamsG1ForMsgCount(params1, label, 2);
    expect(await bbsSignatureParamsG1MaxSupportedMsgs(params2)).toBe(2);
    expect(params1.h[0]).toEqual(params2.h[0])
    expect(params1.h[1]).toEqual(params2.h[1])
  });

  it("extend signature params in G2", async () => {
    const label = stringToBytes("Sig params g2");
    const params0 = await generateSignatureParamsG2(1);
    expect(await bbsSignatureParamsG2MaxSupportedMsgs(params0)).toBe(1);

    const params1 = await bbsExtendSigParamsG2ForMsgCount(params0, label, 5);
    expect(await bbsSignatureParamsG2MaxSupportedMsgs(params1)).toBe(5);
    expect(params0.h[0]).toEqual(params1.h[0]);

    const params2 = await bbsExtendSigParamsG2ForMsgCount(params1, label, 2);
    expect(await bbsSignatureParamsG2MaxSupportedMsgs(params2)).toBe(2);
    expect(params1.h[0]).toEqual(params2.h[0])
    expect(params1.h[1]).toEqual(params2.h[1])
  });

  it("generate and verify a blind signature in G1", async () => {
    // Commit to message indices 1 and 5
    const msgsToCommit = new Map();
    msgsToCommit.set(1, messages[1]);
    msgsToCommit.set(5, messages[5]);

    const msgsNotToCommit = new Map();
    msgsNotToCommit.set(0, messages[0]);
    msgsNotToCommit.set(2, messages[2]);
    msgsNotToCommit.set(3, messages[3]);
    msgsNotToCommit.set(4, messages[4]);

    const blinding = await generateRandomFieldElement();
    const commitment = await bbsCommitMsgsInG1(msgsToCommit, blinding, sigParamsG1, true);
    const blindSig = await bbsBlindSignG1(commitment, msgsNotToCommit, sk, sigParamsG1, true);
    const sig = await bbsUnblindSigG1(blindSig, blinding);
    const res = await bbsVerfiyG1(messages, sig, pkG2, sigParamsG1, true);
    expect(res.verified).toBe(true);
  });

  it("generate and verify a blind signature in G2", async () => {
    // Commit to message indices 1 and 5
    const msgsToCommit = new Map();
    msgsToCommit.set(1, messages[1]);
    msgsToCommit.set(5, messages[5]);

    const msgsNotToCommit = new Map();
    msgsNotToCommit.set(0, messages[0]);
    msgsNotToCommit.set(2, messages[2]);
    msgsNotToCommit.set(3, messages[3]);
    msgsNotToCommit.set(4, messages[4]);

    const blinding = await generateRandomFieldElement();
    const commitment = await bbsCommitMsgsInG2(msgsToCommit, blinding, sigParamsG2, true);
    const blindSig = await bbsBlindSignG2(commitment, msgsNotToCommit, sk, sigParamsG2, true);
    const sig = await bbsUnblindSigG2(blindSig, blinding);
    const res = await bbsVerfiyG2(messages, sig, pkG1, sigParamsG2, true);
    expect(res.verified).toBe(true);
  });

  it("generate a proof of knowledge of signature in G1", async () => {
    const sig = await bbsSignG1(messages, sk, sigParamsG1, true);
    const res = await bbsVerfiyG1(messages, sig, pkG2, sigParamsG1, true);
    expect(res.verified).toBe(true);

    // Prover reveals message indices 0 and 2 and supplies blindings for message indices 1, 4 and 5
    const blindings = new Map();
    const revealed: Set<number> = new Set();
    const revealedMsgs = new Map();

    blindings.set(1, await generateRandomFieldElement());
    blindings.set(4, await generateRandomFieldElement());
    blindings.set(5, await generateRandomFieldElement());
    revealed.add(0);
    revealed.add(2);
    revealedMsgs.set(0, messages[0]);
    revealedMsgs.set(2, messages[2]);

    const protocol = await bbsInitializeProofOfKnowledgeOfSignature(sig, sigParamsG1, messages, blindings, revealed, true);
    const pBytes = await bbsChallengeContributionFromProtocol(protocol, revealedMsgs, sigParamsG1, true);
    expect(pBytes).toBeInstanceOf(Uint8Array);
    const proverChallenge = await generateChallengeFromBytes(pBytes);
    const proof = await bbsGenProofOfKnowledgeOfSignature(protocol, proverChallenge);

    const vBytes = await bbsChallengeContributionFromProof(proof, revealedMsgs, sigParamsG1, true);
    expect(vBytes).toBeInstanceOf(Uint8Array);
    expect(pBytes).toEqual(vBytes);
    const verifierChallenge = await generateChallengeFromBytes(vBytes);
    expect(proverChallenge).toEqual(verifierChallenge);
    const result = await bbsVerifyProofOfKnowledgeOfSignature(proof, revealedMsgs, verifierChallenge, pkG2, sigParamsG1, true);
    expect(result.verified).toBe(true);
  });

});
