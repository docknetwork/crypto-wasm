// main benchmark routine
import {
    bbsChallengeContributionFromProof,
    bbsChallengeContributionFromProtocol,
    bbsGenProofOfKnowledgeOfSignature,
    bbsInitializeProofOfKnowledgeOfSignature,
    bbsSignG1,
    bbsVerifyG1,
    bbsVerifyProofOfKnowledgeOfSignature,
    generateBBSKeyPairG2,
    generateChallengeFromBytes,
    generateSignatureParamsG1,
    initializeWasm
} from "../lib";
import {benchmark, report} from "@stablelib/benchmark";
import {generateMessages} from "./helper";

export const benchmarkBbs = async (
    numberOfMessages: number,
    messageSizeInBytes: number,
    numberRevealed: number
): Promise<void> => {
    await initializeWasm();

    // Generate params
    report(
        `BBB+ Params generation for ${numberOfMessages} messages`,
        benchmark(() => generateSignatureParamsG1(numberOfMessages))
    );
    const sigParams = generateSignatureParamsG1(numberOfMessages);

    // Generate a new key pair
    report(
        "BBB+ Key Generation",
        benchmark(() => generateBBSKeyPairG2(sigParams))
    );
    const keypair = generateBBSKeyPairG2(sigParams);
    const sk = keypair.secret_key;
    const pk = keypair.public_key;

    const messages = generateMessages(numberOfMessages, messageSizeInBytes);

    report(
        `BBS Sign ${numberOfMessages}, ${messageSizeInBytes} byte message(s)`,
        benchmark(() => bbsSignG1(messages, sk, sigParams, true))
    );
    const signature = bbsSignG1(messages, sk, sigParams, true);

    report(
        `BBS Verify ${numberOfMessages}, ${messageSizeInBytes} byte message(s)`,
        benchmark(() => bbsVerifyG1(messages, signature, pk, sigParams, true))
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
