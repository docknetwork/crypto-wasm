// main benchmark routine
import {
  psChallengeContributionFromProof,
  psChallengeContributionFromProtocol,
  psGenProofOfKnowledgeOfSignature,
  psInitializeProofOfKnowledgeOfSignature,
  psSign,
  psVerify,
  psVerifyProofOfKnowledgeOfSignature,
  generateChallengeFromBytes,
  psGenerateSignatureParams,
  initializeWasm,
  psGenerateSigningKey,
  psGeneratePublicKey,
  psEncodeMessageForSigning,
  psEncodeMessagesForSigning,
} from "../lib";
import { benchmark, report } from "@stablelib/benchmark";
import { generateMessages } from "./helper";

export const benchmarkPS = async (
  numberOfMessages: number,
  messageSizeInBytes: number,
  numberRevealed: number
): Promise<void> => {
  await initializeWasm();

  // Generate params
  report(
    `PS Params generation for ${numberOfMessages} messages`,
    benchmark(() => psGenerateSignatureParams(numberOfMessages))
  );
  const sigParams = psGenerateSignatureParams(numberOfMessages);

  // Generate a new key pair
  report(
    "PS Key Generation",
    benchmark(() => {
      const sk = psGenerateSigningKey(numberOfMessages);
      psGeneratePublicKey(sk, sigParams);
    })
  );
  const sk = psGenerateSigningKey(numberOfMessages);
  const pk = psGeneratePublicKey(sk, sigParams);

  const messages = generateMessages(numberOfMessages, messageSizeInBytes);
  report(
    `PS encode ${numberOfMessages}, ${messageSizeInBytes} byte message(s)`,
    benchmark(() => {
      psEncodeMessagesForSigning(messages, Object.keys(messages).map(idx => +idx));
    })
  );

  const encodedMessages = psEncodeMessagesForSigning(messages, Object.keys(messages).map(idx => +idx));

  report(
    `PS Sign ${numberOfMessages}, ${messageSizeInBytes} byte message(s)`,
    benchmark(() => {
      psSign(encodedMessages, sk, sigParams);
    })
  );
  const signature = psSign(encodedMessages, sk, sigParams);

  report(
    `PS Verify ${numberOfMessages}, ${messageSizeInBytes} byte message(s)`,
    benchmark(() => psVerify(encodedMessages, signature, pk, sigParams))
  );

  const revealed: Set<number> = new Set([...Array(numberRevealed).keys()]);
  const revealedMsgs = new Map();
  revealed.forEach((i) => {
    revealedMsgs.set(i, encodedMessages[i]);
  });

  function createProof() {
    const protocol = psInitializeProofOfKnowledgeOfSignature(
      signature,
      sigParams,
      pk,
      encodedMessages.map((message, idx) =>
        !revealedMsgs.has(idx)
          ? { BlindMessageRandomly: message }
          : "RevealMessage"
      )
    );
    const pBytes = psChallengeContributionFromProtocol(protocol, pk, sigParams);
    const proverChallenge = generateChallengeFromBytes(pBytes);
    return psGenProofOfKnowledgeOfSignature(protocol, proverChallenge);
  }

  report(
    `PS Create Proof ${numberOfMessages}, ${messageSizeInBytes} byte message(s), revealing ${numberRevealed} message(s).`,
    benchmark(() => createProof())
  );
  const proof = createProof();

  function verifyProof() {
    const vBytes = psChallengeContributionFromProof(proof, pk, sigParams);
    const verifierChallenge = generateChallengeFromBytes(vBytes);
    psVerifyProofOfKnowledgeOfSignature(
      proof,
      revealedMsgs,
      verifierChallenge,
      pk,
      sigParams
    );
  }

  report(
    `PS Verify Proof ${numberOfMessages}, ${messageSizeInBytes} byte message(s), revealing ${numberRevealed} message(s).`,
    benchmark(() => verifyProof())
  );
};
