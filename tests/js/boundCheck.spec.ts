import {
    initializeWasm,
    boundCheckSnarkSetup,
    legosnarkDecompressPk,
    generateSignatureParamsG1,
    generateBBSSigningKey,
    generateBBSPublicKeyG2,
    BbsSigParams,
    bbsSignG1,
    bbsVerifyG1,
    generatePoKBBSSignatureStatement,
    generateBoundCheckLegoProverStatement,
    generateFieldElementFromNumber,
    generateWitnessEqualityMetaStatement,
    generatePoKBBSSignatureWitness,
    generateBoundCheckWitness,
    generateCompositeProofG1WithDeconstructedProofSpec,
    verifyCompositeProofG1WithDeconstructedProofSpec,
    generateBoundCheckLegoVerifierStatement,
    legosnarkVkFromPk,
    generateBoundCheckLegoProverStatementFromParamRefs,
    generateSetupParamForLegoVerifyingKey, generateBoundCheckLegoVerifierStatementFromParamRefs,
    generateSetupParamForLegoProvingKey
} from "../../lib";
import {getRevealedUnrevealed} from "../utilities";

describe("Prove and verify bounds on signed messages", () => {
    const messageCount = 5;
    // Message index whose bounds are checked
    const msgIdx = 1;

    let sigParams: BbsSigParams, sigSk: Uint8Array, sigPk: Uint8Array, sig: Uint8Array, min: number,
        max: number, proof: Uint8Array;
    let snarkPk: Uint8Array, snarkPkDecom: Uint8Array, snarkVkDecom: Uint8Array;

    const messages: Uint8Array[] = [];

    beforeAll(async () => {
        await initializeWasm();
    });

    it("verifier setup", () => {
        snarkPk = boundCheckSnarkSetup(false);
    }, 10000);

    it("decompress snark proving and verifying key", () => {
        console.time('Snark Pk decompressed');
        snarkPkDecom = legosnarkDecompressPk(snarkPk);
        console.timeEnd('Snark Pk decompressed');

        console.time('Snark Vk decompressed');
        snarkVkDecom = legosnarkVkFromPk(snarkPk, true);
        console.timeEnd('Snark Vk decompressed');
    }, 50000)

    it("signature setup and sign messages", () => {
        sigParams = generateSignatureParamsG1(messageCount);
        sigSk = generateBBSSigningKey();
        sigPk = generateBBSPublicKeyG2(sigSk, sigParams);

        min = 100;
        max = 200;
        for (let i = 0; i < messageCount; i++) {
            let m = generateFieldElementFromNumber(min + 1 + i);
            messages.push(m);
        }
        sig = bbsSignG1(messages, sigSk, sigParams, false);
        const res = bbsVerifyG1(messages, sig, sigPk, sigParams, false);
        expect(res.verified).toBe(true);
    });

    it("bounds should be positive integers", () => {
        expect(() => generateBoundCheckLegoProverStatement(-6, max, snarkPkDecom, true)).toThrow();
        expect(() => generateBoundCheckLegoVerifierStatement(-6, max, snarkVkDecom, true)).toThrow();
        expect(() => generateBoundCheckLegoProverStatement(10.1, max, snarkPkDecom, true)).toThrow();
        expect(() => generateBoundCheckLegoVerifierStatement(10.1, max, snarkVkDecom, true)).toThrow();
        expect(() => generateBoundCheckLegoProverStatement(10, 20.8, snarkPkDecom, true)).toThrow();
        expect(() => generateBoundCheckLegoVerifierStatement(10, 20.8, snarkVkDecom, true)).toThrow();
        expect(() => generateBoundCheckLegoProverStatement(10, -90, snarkPkDecom, true)).toThrow();
        expect(() => generateBoundCheckLegoVerifierStatement(10, -90, snarkVkDecom, true)).toThrow();
    });

    it("create and verify a proof over single signed message", () => {
        const revealedIndices = new Set<number>();
        revealedIndices.add(4);

        const [revealedMsgs, unrevealedMsgs] = getRevealedUnrevealed(messages, revealedIndices);
        const statement1 = generatePoKBBSSignatureStatement(sigParams, sigPk, revealedMsgs, false);

        console.time("bound check prover stmt");
        const statement2 = generateBoundCheckLegoProverStatement(min, max, snarkPkDecom, true);
        console.timeEnd("bound check prover stmt");

        const proverStatements = [];
        proverStatements.push(statement1);
        proverStatements.push(statement2);

        const metaStatements = [];
        const set = new Set<[number, number]>();
        set.add([0, msgIdx]);
        set.add([1, 0]);
        metaStatements.push(generateWitnessEqualityMetaStatement(set));

        const witness1 = generatePoKBBSSignatureWitness(sig, unrevealedMsgs, false);
        const witness2 = generateBoundCheckWitness(messages[msgIdx]);

        const witnesses = [];
        witnesses.push(witness1);
        witnesses.push(witness2);

        console.time("proof gen");
        proof = generateCompositeProofG1WithDeconstructedProofSpec(proverStatements, metaStatements, [], witnesses);
        console.timeEnd("proof gen");

        console.time("bound check verifier stmt");
        const statement3 = generateBoundCheckLegoVerifierStatement(min, max, snarkVkDecom, true);
        console.timeEnd("bound check verifier stmt");

        const verifierStatements = [];
        verifierStatements.push(statement1);
        verifierStatements.push(statement3);

        console.time("proof ver");
        const res = verifyCompositeProofG1WithDeconstructedProofSpec(proof, verifierStatements, metaStatements, []);
        console.timeEnd("proof ver");
        expect(res.verified).toBe(true);
    }, 10000);

    it("create and verify a proof over multiple signed messages", () => {
        const [revealedMsgs, unrevealedMsgs] = getRevealedUnrevealed(messages, new Set<number>());
        const statement1 = generatePoKBBSSignatureStatement(sigParams, sigPk, revealedMsgs, false);

        console.time("bound check prover setup param");
        const provingSetupParams = [];
        provingSetupParams.push(generateSetupParamForLegoProvingKey(snarkPkDecom, true))
        console.timeEnd("bound check prover setup param");

        const statement2 = generateBoundCheckLegoProverStatementFromParamRefs(min, max, 0);
        const statement3 = generateBoundCheckLegoProverStatementFromParamRefs(min, max, 0);
        const statement4 = generateBoundCheckLegoProverStatementFromParamRefs(min, max, 0);

        const proverStatements = [];
        proverStatements.push(statement1);
        proverStatements.push(statement2);
        proverStatements.push(statement3);
        proverStatements.push(statement4);

        // All messages are within bounds by choice during test setup
        const metaStatements = [];
        const set1 = new Set<[number, number]>();
        set1.add([0, msgIdx]);
        set1.add([1, 0]);
        metaStatements.push(generateWitnessEqualityMetaStatement(set1));

        const set2 = new Set<[number, number]>();
        set2.add([0, msgIdx+1]);
        set2.add([2, 0]);
        metaStatements.push(generateWitnessEqualityMetaStatement(set2));

        const set3 = new Set<[number, number]>();
        set3.add([0, msgIdx+2]);
        set3.add([3, 0]);
        metaStatements.push(generateWitnessEqualityMetaStatement(set3));

        const witness1 = generatePoKBBSSignatureWitness(sig, unrevealedMsgs, false);
        const witness2 = generateBoundCheckWitness(messages[msgIdx]);
        const witness3 = generateBoundCheckWitness(messages[msgIdx+1]);
        const witness4 = generateBoundCheckWitness(messages[msgIdx+2]);

        const witnesses = [];
        witnesses.push(witness1);
        witnesses.push(witness2);
        witnesses.push(witness3);
        witnesses.push(witness4);

        console.time("proof gen");
        proof = generateCompositeProofG1WithDeconstructedProofSpec(proverStatements, metaStatements, provingSetupParams, witnesses);
        console.timeEnd("proof gen");

        console.time("bound check verifier setup param");
        const verifierSetupParams = [];
        verifierSetupParams.push(generateSetupParamForLegoVerifyingKey(snarkVkDecom, true))
        console.timeEnd("bound check verifier setup param");

        const statement5 = generateBoundCheckLegoVerifierStatementFromParamRefs(min, max, 0);
        const statement6 = generateBoundCheckLegoVerifierStatementFromParamRefs(min, max, 0);
        const statement7 = generateBoundCheckLegoVerifierStatementFromParamRefs(min, max, 0);

        const verifierStatements = [];
        verifierStatements.push(statement1);
        verifierStatements.push(statement5);
        verifierStatements.push(statement6);
        verifierStatements.push(statement7);

        console.time("proof ver");
        const res = verifyCompositeProofG1WithDeconstructedProofSpec(proof, verifierStatements, metaStatements, verifierSetupParams);
        console.timeEnd("proof ver");
        expect(res.verified).toBe(true);
    }, 10000);
});
