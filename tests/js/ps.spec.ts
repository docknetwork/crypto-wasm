import {
  psAdaptPublicKeyForLessMessages,
  psAdaptSecretKeyForLessMessages,
  psAdaptSecretKeyForMoreMessages,
  psChallengeMessagesPoKContributionFromProof,
  psChallengeMessagesPoKContributionFromProtocol,
  psEncodeMessageForSigning,
  psGenMessagesPoK,
  psInitializeMessagesPoK,
  psPublicKeyMaxSupportedMsgs,
  psSigningKeyMaxSupportedMsgs,
  psVerifyMessagesPoK,
} from "../../lib";
import {
  psGenerateSignatureParams,
  psIsSignatureParamsValid,
  psSignatureParamsMaxSupportedMsgs,
  psGenerateSigningKey,
  psGeneratePublicKey,
  psIsPublicKeyValid,
  psSign,
  psVerify,
  generateRandomFieldElement,
  psMessageCommitment,
  psBlindSign,
  psUnblindSignature,
  psInitializeSignaturePoK,
  psGenSignaturePoK,
  psVerifySignaturePoK,
  psChallengeSignaturePoKContributionFromProtocol,
  psChallengeSignaturePoKContributionFromProof,
  generateChallengeFromBytes,
  psAdaptSignatureParamsForMsgCount,
  psSignatureParamsFromBytes,
  psSignatureParamsToBytes,
  PSSigParams,
  initializeWasm,
  PSCommitmentOrMessage,
} from "../../lib";
import { generateRandomG1Element } from "../../lib/dock_crypto_wasm";

import { stringToBytes } from "../utilities";

describe("For PS signatures", () => {
  let sigParams: PSSigParams, sk: Uint8Array, pk: Uint8Array, messages, h;
  const seed = new Uint8Array([0, 2, 3, 4, 5]);
  const messageCount = 6;

  beforeAll(async () => {
    await initializeWasm();

    h = generateRandomG1Element();
    messages = [
      stringToBytes("Message1"),
      stringToBytes("Message2"),
      stringToBytes("Message3"),
      stringToBytes("Message4"),
      stringToBytes("Message4"),
      stringToBytes("Message6"),
    ].map(psEncodeMessageForSigning);
    sigParams = psGenerateSignatureParams(
      messageCount,
      stringToBytes("test label")
    );
    sk = psGenerateSigningKey(messageCount);
    pk = psGeneratePublicKey(sk, sigParams);
  });

  it("checks key generation", () => {
    const sk_ = psGenerateSigningKey(6);
    expect(psSigningKeyMaxSupportedMsgs(sk_)).toBe(6);
    expect(sk_).toBeInstanceOf(Uint8Array);

    const sk1 = psGenerateSigningKey(6, seed);
    expect(sk1).toBeInstanceOf(Uint8Array);

    const sk2 = psGenerateSigningKey(6, seed);
    expect(sk2).toBeInstanceOf(Uint8Array);

    expect(sk1).toEqual(sk2);
  });

  it("generate signature params", () => {
    expect(() => psGenerateSignatureParams(-5)).toThrow();
    expect(() => psGenerateSignatureParams(6.3)).toThrow();

    const params0 = psGenerateSignatureParams(messageCount);
    expect(params0).toBeInstanceOf(Object);
    expect(params0.h.length).toEqual(messageCount);
    expect(psIsSignatureParamsValid(params0)).toBe(true);

    const label = stringToBytes("Sig params g1");
    const params = psGenerateSignatureParams(messageCount, label);
    expect(params).toBeInstanceOf(Object);
    expect(params.h.length).toEqual(messageCount);
    expect(psIsSignatureParamsValid(params)).toBe(true);
    expect(psSignatureParamsMaxSupportedMsgs(params)).toBe(messageCount);

    const bytes = psSignatureParamsToBytes(params);
    const deserzParams = psSignatureParamsFromBytes(bytes);
    expect(params).toEqual(deserzParams);
  });

  it("generate signature params", () => {
    expect(() => psGenerateSignatureParams(-5)).toThrow();
    expect(() => psGenerateSignatureParams(6.3)).toThrow();

    const params0 = psGenerateSignatureParams(messageCount);
    expect(params0).toBeInstanceOf(Object);
    expect(params0.h.length).toEqual(messageCount);
    expect(psIsSignatureParamsValid(params0)).toBe(true);

    const params = psGenerateSignatureParams(messageCount);
    expect(params).toBeInstanceOf(Object);
    expect(params.h.length).toEqual(messageCount);
    expect(psIsSignatureParamsValid(params)).toBe(true);
    expect(psSignatureParamsMaxSupportedMsgs(params)).toBe(messageCount);

    const bytes = psSignatureParamsToBytes(params);
    const deserzParams = psSignatureParamsFromBytes(bytes);
    expect(params).toEqual(deserzParams);
  });

  it("generate public key from secret key", () => {
    expect(psPublicKeyMaxSupportedMsgs(pk)).toBe(messageCount);
    expect(pk).toBeInstanceOf(Uint8Array);
    expect(psIsPublicKeyValid(pk)).toBe(true);
  });

  it("generate and verify signature", () => {
    const sig = psSign(messages, sk, sigParams);
    const res = psVerify(messages, sig, pk, sigParams);
    expect(res.verified).toBe(true);
  });

  it("generate and verify signature", () => {
    const sig = psSign(messages, sk, sigParams);
    const res = psVerify(messages, sig, pk, sigParams);
    expect(res.verified).toBe(true);
  });

  it("extend signature params", () => {
    const label = stringToBytes("Sig params g1");
    const params0 = psGenerateSignatureParams(1);
    expect(psSignatureParamsMaxSupportedMsgs(params0)).toBe(1);

    const params1 = psAdaptSignatureParamsForMsgCount(params0, label, 5);
    expect(psSignatureParamsMaxSupportedMsgs(params1)).toBe(5);
    expect(psIsSignatureParamsValid(params1)).toBe(true);
    expect(params0.h[0]).toEqual(params1.h[0]);

    const params2 = psAdaptSignatureParamsForMsgCount(params1, label, 2);
    expect(psSignatureParamsMaxSupportedMsgs(params2)).toBe(2);
    expect(psIsSignatureParamsValid(params2)).toBe(true);
    expect(params1.h[0]).toEqual(params2.h[0]);
    expect(params1.h[1]).toEqual(params2.h[1]);
  });

  it("extend signature params", () => {
    const label = stringToBytes("Sig params g2");
    const params0 = psGenerateSignatureParams(1);
    expect(psSignatureParamsMaxSupportedMsgs(params0)).toBe(1);

    const params1 = psAdaptSignatureParamsForMsgCount(params0, label, 5);
    expect(psSignatureParamsMaxSupportedMsgs(params1)).toBe(5);
    expect(psIsSignatureParamsValid(params1)).toBe(true);
    expect(params0.h[0]).toEqual(params1.h[0]);

    const params2 = psAdaptSignatureParamsForMsgCount(params1, label, 2);
    expect(psSignatureParamsMaxSupportedMsgs(params2)).toBe(2);
    expect(psIsSignatureParamsValid(params2)).toBe(true);
    expect(params1.h[0]).toEqual(params2.h[0]);
    expect(params1.h[1]).toEqual(params2.h[1]);
  });

  it("adapt secret key", () => {
    const seed = stringToBytes("123");
    const sk5 = psGenerateSigningKey(5, seed);
    expect(psSigningKeyMaxSupportedMsgs(sk5)).toBe(5);

    const sk2 = psAdaptSecretKeyForLessMessages(sk5, 2)!;
    expect(psAdaptSecretKeyForLessMessages(sk5, 6)).toBe(undefined);
    expect(psSigningKeyMaxSupportedMsgs(sk2)).toBe(2);

    const sk7 = psAdaptSecretKeyForMoreMessages(sk5, seed, 7)!;
    expect(psSigningKeyMaxSupportedMsgs(sk7)).toBe(7);
    expect(sk7).toEqual(psGenerateSigningKey(7, seed));
  });

  it("adapt public key", () => {
    const sk = psGenerateSigningKey(5);
    const pk = psGeneratePublicKey(sk, sigParams);
    expect(psPublicKeyMaxSupportedMsgs(pk)).toBe(5);

    const pk1 = psAdaptPublicKeyForLessMessages(pk, 1)!;
    expect(psAdaptPublicKeyForLessMessages(pk, messageCount + 1)).toBe(
      undefined
    );
    expect(psPublicKeyMaxSupportedMsgs(pk1)).toBe(1);
  });

  it("generate and verify a blind signature", () => {
    // Commit to message indices 1 and 5
    const commitIndices = new Set([1, 5]);
    const usedBlindings = new Map();

    const msgOrComs: PSCommitmentOrMessage[] = [];
    for (let i = 0; i < messages.length; i++) {
      let msgOrCom;
      if (commitIndices.has(i)) {
        const msg = messages[i];
        const blinding = generateRandomFieldElement();

        msgOrCom = {
          BlindedMessage: psMessageCommitment(blinding, msg, h, sigParams),
        };
        usedBlindings.set(i, blinding);
      } else {
        msgOrCom = {
          RevealedMessage: messages[i],
        };
      }

      msgOrComs.push(msgOrCom);
    }

    const blindSig = psBlindSign(msgOrComs, sk, h);
    const sig = psUnblindSignature(blindSig, usedBlindings, pk);
    const res = psVerify(messages, sig, pk, sigParams);
    expect(res.verified).toBe(true);
  });

  it("generate a proof of knowledge of signature", () => {
    const sig = psSign(messages, sk, sigParams);
    const res = psVerify(messages, sig, pk, sigParams);
    expect(res.verified).toBe(true);

    // Prover reveals message indices 0 and 2 and supplies blindings for message indices 1, 4 and 5
    const blindingsMap = new Map();
    const revealedMsgs = new Map();

    blindingsMap.set(1, generateRandomFieldElement());
    blindingsMap.set(4, generateRandomFieldElement());
    blindingsMap.set(5, generateRandomFieldElement());
    revealedMsgs.set(0, messages[0]);
    revealedMsgs.set(2, messages[2]);
    revealedMsgs.set(3, messages[3]);

    const protocol = psInitializeSignaturePoK(
      sig,
      sigParams,
      pk,
      messages.map((message, idx) => {
        const blinding = blindingsMap.get(idx);

        return blinding != void 0
          ? { BlindMessageWithConcreteBlinding: { message, blinding } }
          : "RevealMessage";
      })
    );
    const pBytes = psChallengeSignaturePoKContributionFromProtocol(
      protocol,
      pk,
      sigParams
    );
    expect(pBytes).toBeInstanceOf(Uint8Array);
    const proverChallenge = generateChallengeFromBytes(pBytes);
    const proof = psGenSignaturePoK(protocol, proverChallenge);

    const vBytes = psChallengeSignaturePoKContributionFromProof(
      proof,
      pk,
      sigParams
    );
    expect(vBytes).toBeInstanceOf(Uint8Array);
    expect(pBytes).toEqual(vBytes);
    const verifierChallenge = generateChallengeFromBytes(vBytes);
    expect(proverChallenge).toEqual(verifierChallenge);
    const result = psVerifySignaturePoK(
      proof,
      revealedMsgs,
      verifierChallenge,
      pk,
      sigParams
    );
    expect(result.verified).toBe(true);
  });

  it("generate a proof of knowledge of messages", () => {
    // Prover reveals message indices 0 and 2 and supplies blindings for message indices 1, 4 and 5
    const blindingsMap = new Map();
    const revealedMsgs = new Map();
    const h = generateRandomG1Element();

    blindingsMap.set(1, generateRandomFieldElement());
    blindingsMap.set(4, generateRandomFieldElement());
    blindingsMap.set(5, generateRandomFieldElement());
    revealedMsgs.set(0, messages[0]);
    revealedMsgs.set(2, messages[2]);
    revealedMsgs.set(3, messages[3]);

    const protocol = psInitializeMessagesPoK(
      messages.map((message, idx) => {
        const blinding = blindingsMap.get(idx);

        return blinding != void 0
          ? { BlindMessageWithConcreteBlinding: { message, blinding } }
          : "RevealMessage";
      }),
      sigParams,
      h
    );
    const pBytes = psChallengeMessagesPoKContributionFromProtocol(
      protocol,
      sigParams,
      h
    );
    expect(pBytes).toBeInstanceOf(Uint8Array);
    const proverChallenge = generateChallengeFromBytes(pBytes);
    const proof = psGenMessagesPoK(protocol, proverChallenge);

    const vBytes = psChallengeMessagesPoKContributionFromProof(
      proof,
      sigParams,
      h
    );
    expect(vBytes).toBeInstanceOf(Uint8Array);
    expect(pBytes).toEqual(vBytes);
    const verifierChallenge = generateChallengeFromBytes(vBytes);
    expect(proverChallenge).toEqual(verifierChallenge);
    const result = psVerifyMessagesPoK(
      proof,
      new Set(revealedMsgs.keys()),
      verifierChallenge,
      sigParams,
      h
    );
    expect(result.verified).toBe(true);
  });
});
