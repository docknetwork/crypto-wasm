// main benchmark routine
import {
    bbsChallengeContributionFromProof,
    bbsChallengeContributionFromProtocol,
    bbsGenProofOfKnowledgeOfSignature,
    bbsInitializeProofOfKnowledgeOfSignature,
    bbsSign,
    bbsVerify,
    bbsVerifyProofOfKnowledgeOfSignature,
    bbsGenerateKeyPair,
    generateChallengeFromBytes,
    bbsGenerateSignatureParams,
    initializeWasm,
    bbsEncodeMessageForSigning,
    bbsEncodeMessagesForSigning
} from "../lib";
import {benchmark, report} from "@stablelib/benchmark";
import {generateMessages} from "./helper";

export const benchmarkBBSPlus = async (
    numberOfMessages: number,
    messageSizeInBytes: number,
    numberRevealed: number
): Promise<void> => {
    await initializeWasm();

    // Generate params
    report(
        `BBB+ Params generation for ${numberOfMessages} messages`,
        benchmark(() => bbsGenerateSignatureParams(numberOfMessages))
    );
    const sigParams = bbsGenerateSignatureParams(numberOfMessages);

    // Generate a new key pair
    report(
        "BBB+ Key Generation",
        benchmark(() => bbsGenerateKeyPair(sigParams))
    );
    const keypair = bbsGenerateKeyPair(sigParams);
    const sk = keypair.secret_key;
    const pk = keypair.public_key;

    const messages = generateMessages(numberOfMessages, messageSizeInBytes);
    report(
        `BBS encode ${numberOfMessages}, ${messageSizeInBytes} byte message(s)`,
        benchmark(() => {
            bbsEncodeMessagesForSigning(messages, Object.keys(messages).map(idx => +idx))
        })
      );

    report(
        `BBS Sign ${numberOfMessages}, ${messageSizeInBytes} byte message(s)`,
        benchmark(() => bbsSign(messages, sk, sigParams, true))
    );
    const signature = bbsSign(messages, sk, sigParams, true);

    report(
        `BBS Verify ${numberOfMessages}, ${messageSizeInBytes} byte message(s)`,
        benchmark(() => bbsVerify(messages, signature, pk, sigParams, true))
    );

    const revealed: Set<number> = new Set([...Array(numberRevealed).keys()]);
    const revealedMsgs = new Map();
    revealed.forEach((i) => {
        revealedMsgs.set(i, messages[i]);
    })

    function createProof() {
        const protocol = bbsInitializeProofOfKnowledgeOfSignature(signature, sigParams, messages, new Map(), revealed, true);
        const pBytes = bbsChallengeContributionFromProtocol(protocol, revealedMsgs, sigParams, true);
        const proverChallenge = generateChallengeFromBytes(pBytes);
        return bbsGenProofOfKnowledgeOfSignature(protocol, proverChallenge);
    }

    report(
        `BBS Create Proof ${numberOfMessages}, ${messageSizeInBytes} byte message(s), revealing ${numberRevealed} message(s).`,
        benchmark(() => createProof())
    );
    const proof = createProof();


    function verifyProof() {
        const vBytes = bbsChallengeContributionFromProof(proof, revealedMsgs, sigParams, true);
        const verifierChallenge = generateChallengeFromBytes(vBytes);
        bbsVerifyProofOfKnowledgeOfSignature(proof, revealedMsgs, verifierChallenge, pk, sigParams, true);
    }

    report(
        `BBS Verify Proof ${numberOfMessages}, ${messageSizeInBytes} byte message(s), revealing ${numberRevealed} message(s).`,
        benchmark(() => verifyProof())
    );
};
