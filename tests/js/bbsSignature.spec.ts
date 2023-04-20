import {
  bbsPlusGenerateSignatureParamsG1,
  bbsPlusGenerateSignatureParamsG2,
  bbsPlusIsSignatureParamsG1Valid,
  bbsPlusSignatureParamsG1MaxSupportedMsgs,
  bbsPlusIsSignatureParamsG2Valid,
  bbsPlusSignatureParamsG2MaxSupportedMsgs,
  bbsPlusGenerateSigningKey,
  bbsPlusGeneratePublicKeyG1,
  bbsPlusGeneratePublicKeyG2,
  bbsPlusGenerateKeyPairG1,
  bbsPlusGenerateKeyPairG2,
  bbsPlusIsPublicKeyG1Valid,
  bbsPlusIsPublicKeyG2Valid,
  bbsPlusSignG1,
  bbsPlusVerifyG1,
  bbsPlusSignG2,
  bbsPlusVerifyG2,
  generateRandomFieldElement,
  bbsPlusCommitMsgsInG1,
  bbsPlusCommitMsgsInG2,
  bbsPlusBlindSignG1,
  bbsPlusBlindSignG2,
  bbsPlusUnblindSigG1,
  bbsPlusUnblindSigG2,
  bbsPlusInitializeProofOfKnowledgeOfSignature,
  bbsPlusGenProofOfKnowledgeOfSignature,
  bbsPlusVerifyProofOfKnowledgeOfSignature,
  bbsPlusChallengeContributionFromProtocol,
  bbsPlusChallengeContributionFromProof,
  generateChallengeFromBytes,
  bbsPlusAdaptSigParamsG1ForMsgCount,
  bbsPlusAdaptSigParamsG2ForMsgCount,
  bbsPlusSignatureParamsG1ToBytes,
  bbsPlusSignatureParamsG1FromBytes,
  bbsPlusSignatureParamsG2FromBytes,
  bbsPlusSignatureParamsG2ToBytes,
  BbsPlusSigParams,
  initializeWasm,
} from "../../lib";

import { stringToBytes } from "../utilities";

describe("For BBS+ signatures", () => {
  let sigParamsG1: BbsPlusSigParams,
    sigParamsG2: BbsPlusSigParams,
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
    const sk_ = bbsPlusGenerateSigningKey();
    expect(sk_).toBeInstanceOf(Uint8Array);

    const sk1 = bbsPlusGenerateSigningKey(seed);
    expect(sk1).toBeInstanceOf(Uint8Array);

    const sk2 = bbsPlusGenerateSigningKey(seed);
    expect(sk2).toBeInstanceOf(Uint8Array);

    expect(sk1).toEqual(sk2);

    sk = sk1;
  });

  it("generate signature params in G1", () => {
    expect(() => bbsPlusGenerateSignatureParamsG1(-5)).toThrow();
    expect(() => bbsPlusGenerateSignatureParamsG1(6.3)).toThrow();

    const params0 = bbsPlusGenerateSignatureParamsG1(messageCount);
    expect(params0).toBeInstanceOf(Object);
    expect(params0.h.length).toEqual(messageCount);
    expect(bbsPlusIsSignatureParamsG1Valid(params0)).toBe(true);

    const label = stringToBytes("Sig params g1");
    const params = bbsPlusGenerateSignatureParamsG1(messageCount, label);
    expect(params).toBeInstanceOf(Object);
    expect(params.h.length).toEqual(messageCount);
    expect(bbsPlusIsSignatureParamsG1Valid(params)).toBe(true);
    expect(bbsPlusSignatureParamsG1MaxSupportedMsgs(params)).toBe(messageCount);

    const bytes = bbsPlusSignatureParamsG1ToBytes(params);
    const deserzParams = bbsPlusSignatureParamsG1FromBytes(bytes);
    expect(params).toEqual(deserzParams);

    sigParamsG1 = params;
  });

  it("generate signature params in G2", () => {
    expect(() => bbsPlusGenerateSignatureParamsG2(-5)).toThrow();
    expect(() => bbsPlusGenerateSignatureParamsG2(6.3)).toThrow();

    const params0 = bbsPlusGenerateSignatureParamsG2(messageCount);
    expect(params0).toBeInstanceOf(Object);
    expect(params0.h.length).toEqual(messageCount);
    expect(bbsPlusIsSignatureParamsG2Valid(params0)).toBe(true);

    const params = bbsPlusGenerateSignatureParamsG2(messageCount);
    expect(params).toBeInstanceOf(Object);
    expect(params.h.length).toEqual(messageCount);
    expect(bbsPlusIsSignatureParamsG2Valid(params)).toBe(true);
    expect(bbsPlusSignatureParamsG2MaxSupportedMsgs(params)).toBe(messageCount);

    const bytes = bbsPlusSignatureParamsG2ToBytes(params);
    const deserzParams = bbsPlusSignatureParamsG2FromBytes(bytes);
    expect(params).toEqual(deserzParams);

    sigParamsG2 = params;
  });

  it("generate public key in G1 from secret key", () => {
    pkG1 = bbsPlusGeneratePublicKeyG1(sk, sigParamsG2);
    expect(pkG1).toBeInstanceOf(Uint8Array);
    expect(bbsPlusIsPublicKeyG1Valid(pkG1)).toBe(true);
  });

  it("generate public key in G2 from secret key", () => {
    pkG2 = bbsPlusGeneratePublicKeyG2(sk, sigParamsG1);
    expect(pkG2).toBeInstanceOf(Uint8Array);
    expect(bbsPlusIsPublicKeyG2Valid(pkG2)).toBe(true);
  });

  it("generate keypair in G1 from given seed", () => {
    const keypair = bbsPlusGenerateKeyPairG1(sigParamsG2, seed);
    expect(keypair).toBeInstanceOf(Object);
    const keypair1 = bbsPlusGenerateKeyPairG1(sigParamsG2, seed);
    expect(keypair1).toBeInstanceOf(Object);
    expect(keypair).toEqual(keypair1);
    console.log(sk, keypair.secret_key, typeof keypair.secret_key)

    expect(keypair.secret_key).toEqual([...sk]);
    expect(keypair.public_key).toEqual([...pkG1]);
  });

  it("generate keypair in G2 from given seed", () => {
    const keypair = bbsPlusGenerateKeyPairG2(sigParamsG1, seed);
    expect(keypair).toBeInstanceOf(Object);
    const keypair1 = bbsPlusGenerateKeyPairG2(sigParamsG1, seed);
    expect(keypair1).toBeInstanceOf(Object);
    expect(keypair).toEqual(keypair1);

    expect(keypair.secret_key).toEqual([...sk]);
    expect(keypair.public_key).toEqual([...pkG2]);
  });

  it("generate and verify signature in G1", () => {
    const sig = bbsPlusSignG1(messages, sk, sigParamsG1, true);
    const res = bbsPlusVerifyG1(messages, sig, pkG2, sigParamsG1, true);
    expect(res.verified).toBe(true);
  });

  it("generate and verify signature in G2", () => {
    const sig = bbsPlusSignG2(messages, sk, sigParamsG2, true);
    const res = bbsPlusVerifyG2(messages, sig, pkG1, sigParamsG2, true);
    expect(res.verified).toBe(true);
  });

  it("extend signature params in G1", () => {
    const label = stringToBytes("Sig params g1");
    const params0 = bbsPlusGenerateSignatureParamsG1(1);
    expect(bbsPlusSignatureParamsG1MaxSupportedMsgs(params0)).toBe(1);

    const params1 = bbsPlusAdaptSigParamsG1ForMsgCount(params0, label, 5);
    expect(bbsPlusSignatureParamsG1MaxSupportedMsgs(params1)).toBe(5);
    expect(bbsPlusIsSignatureParamsG1Valid(params1)).toBe(true);
    expect(params0.h[0]).toEqual(params1.h[0]);

    const params2 = bbsPlusAdaptSigParamsG1ForMsgCount(params1, label, 2);
    expect(bbsPlusSignatureParamsG1MaxSupportedMsgs(params2)).toBe(2);
    expect(bbsPlusIsSignatureParamsG1Valid(params2)).toBe(true);
    expect(params1.h[0]).toEqual(params2.h[0]);
    expect(params1.h[1]).toEqual(params2.h[1]);
  });

  it("extend signature params in G2", () => {
    const label = stringToBytes("Sig params g2");
    const params0 = bbsPlusGenerateSignatureParamsG2(1);
    expect(bbsPlusSignatureParamsG2MaxSupportedMsgs(params0)).toBe(1);

    const params1 = bbsPlusAdaptSigParamsG2ForMsgCount(params0, label, 5);
    expect(bbsPlusSignatureParamsG2MaxSupportedMsgs(params1)).toBe(5);
    expect(bbsPlusIsSignatureParamsG2Valid(params1)).toBe(true);
    expect(params0.h[0]).toEqual(params1.h[0]);

    const params2 = bbsPlusAdaptSigParamsG2ForMsgCount(params1, label, 2);
    expect(bbsPlusSignatureParamsG2MaxSupportedMsgs(params2)).toBe(2);
    expect(bbsPlusIsSignatureParamsG2Valid(params2)).toBe(true);
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

    const blinding = generateRandomFieldElement();
    const commitment = bbsPlusCommitMsgsInG1(
      msgsToCommit,
      blinding,
      sigParamsG1,
      true
    );
    const blindSig = bbsPlusBlindSignG1(
      commitment,
      msgsNotToCommit,
      sk,
      sigParamsG1,
      true
    );
    const sig = bbsPlusUnblindSigG1(blindSig, blinding);
    const res = bbsPlusVerifyG1(messages, sig, pkG2, sigParamsG1, true);
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
    const commitment = bbsPlusCommitMsgsInG2(
      msgsToCommit,
      blinding,
      sigParamsG2,
      true
    );
    const blindSig = bbsPlusBlindSignG2(
      commitment,
      msgsNotToCommit,
      sk,
      sigParamsG2,
      true
    );
    const sig = bbsPlusUnblindSigG2(blindSig, blinding);
    const res = bbsPlusVerifyG2(messages, sig, pkG1, sigParamsG2, true);
    expect(res.verified).toBe(true);
  });

  it("generate a proof of knowledge of signature in G1", () => {
    const sig = bbsPlusSignG1(messages, sk, sigParamsG1, true);
    const res = bbsPlusVerifyG1(messages, sig, pkG2, sigParamsG1, true);
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

    const protocol = bbsPlusInitializeProofOfKnowledgeOfSignature(
      sig,
      sigParamsG1,
      messages,
      blindings,
      revealed,
      true
    );
    const pBytes = bbsPlusChallengeContributionFromProtocol(
      protocol,
      revealedMsgs,
      sigParamsG1,
      true
    );
    expect(pBytes).toBeInstanceOf(Uint8Array);
    const proverChallenge = generateChallengeFromBytes(pBytes);
    const proof = bbsPlusGenProofOfKnowledgeOfSignature(protocol, proverChallenge);

    const vBytes = bbsPlusChallengeContributionFromProof(
      proof,
      revealedMsgs,
      sigParamsG1,
      true
    );
    expect(vBytes).toBeInstanceOf(Uint8Array);
    expect(pBytes).toEqual(vBytes);
    const verifierChallenge = generateChallengeFromBytes(vBytes);
    expect(proverChallenge).toEqual(verifierChallenge);
    const result = bbsPlusVerifyProofOfKnowledgeOfSignature(
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
