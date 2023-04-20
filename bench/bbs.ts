// main benchmark routine
import {
    bbsPlusChallengeContributionFromProof,
    bbsPlusChallengeContributionFromProtocol,
    bbsPlusGenProofOfKnowledgeOfSignature,
    bbsPlusInitializeProofOfKnowledgeOfSignature,
    bbsPlusSignG1,
    bbsPlusVerifyG1,
    bbsPlusVerifyProofOfKnowledgeOfSignature,
    bbsPlusGenerateKeyPairG2,
    generateChallengeFromBytes,
    bbsPlusGenerateSignatureParamsG1,
    initializeWasm,
    bbsPlusEncodeMessageForSigning,
    bbsPlusEncodeMessagesForSigning
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
        benchmark(() => bbsPlusGenerateSignatureParamsG1(numberOfMessages))
    );
    const sigParams = bbsPlusGenerateSignatureParamsG1(numberOfMessages);

    // Generate a new key pair
    report(
        "BBB+ Key Generation",
        benchmark(() => bbsPlusGenerateKeyPairG2(sigParams))
    );
    const keypair = bbsPlusGenerateKeyPairG2(sigParams);
    const sk = keypair.secret_key;
    const pk = keypair.public_key;

    const messages = generateMessages(numberOfMessages, messageSizeInBytes);
    report(
        `BBS+ encode ${numberOfMessages}, ${messageSizeInBytes} byte message(s)`,
        benchmark(() => {
            bbsPlusEncodeMessagesForSigning(messages, Object.keys(messages).map(idx => +idx))
        })
      );

    report(
        `BBS+ Sign ${numberOfMessages}, ${messageSizeInBytes} byte message(s)`,
        benchmark(() => bbsPlusSignG1(messages, sk, sigParams, true))
    );
    const signature = bbsPlusSignG1(messages, sk, sigParams, true);

    report(
        `BBS+ Verify ${numberOfMessages}, ${messageSizeInBytes} byte message(s)`,
        benchmark(() => bbsPlusVerifyG1(messages, signature, pk, sigParams, true))
    );

    const revealed: Set<number> = new Set([...Array(numberRevealed).keys()]);
    const revealedMsgs = new Map();
    revealed.forEach((i) => {
        revealedMsgs.set(i, messages[i]);
    })

    function createProof() {
        const protocol = bbsPlusInitializeProofOfKnowledgeOfSignature(signature, sigParams, messages, new Map(), revealed, true);
        const pBytes = bbsPlusChallengeContributionFromProtocol(protocol, revealedMsgs, sigParams, true);
        const proverChallenge = generateChallengeFromBytes(pBytes);
        return bbsPlusGenProofOfKnowledgeOfSignature(protocol, proverChallenge);
    }

    report(
        `BBS+ Create Proof ${numberOfMessages}, ${messageSizeInBytes} byte message(s), revealing ${numberRevealed} message(s).`,
        benchmark(() => createProof())
    );
    const proof = createProof();


    function verifyProof() {
        const vBytes = bbsPlusChallengeContributionFromProof(proof, revealedMsgs, sigParams, true);
        const verifierChallenge = generateChallengeFromBytes(vBytes);
        bbsPlusVerifyProofOfKnowledgeOfSignature(proof, revealedMsgs, verifierChallenge, pk, sigParams, true);
    }

    report(
        `BBS+ Verify Proof ${numberOfMessages}, ${messageSizeInBytes} byte message(s), revealing ${numberRevealed} message(s).`,
        benchmark(() => verifyProof())
    );
};
