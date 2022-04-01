import {
    initializeWasm,
    boundCheckSnarkSetup,
    boundCheckDecompressSnarkPk,
    generateSignatureParamsG1,
    generateBBSSigningKey,
    generateBBSPublicKeyG2,
    BbsSigParams,
    bbsEncodeMessageForSigning,
    bbsSignG1,
    bbsVerifyG1,
    generatePoKBBSSignatureStatement,
    generateBoundCheckLegoStatement,
    generateFieldElementFromNumber,
    generateWitnessEqualityMetaStatement,
    generatePoKBBSSignatureWitness,
    generateBoundCheckWitness,
    generateCompositeProofG1WithDeconstructedProofSpec,
    verifyCompositeProofG1WithDeconstructedProofSpec
} from "../../lib";
import {getRevealedUnrevealed, stringToBytes} from "../utilities";

describe("Prove and verify bounds on a signed message", () => {
    const messageCount = 5;
    // Message index whose bounds are checked
    const msgIdx = 1;

    let sigParams: BbsSigParams, sigSk: Uint8Array, sigPk: Uint8Array, sig: Uint8Array, min: Uint8Array,
        max: Uint8Array, proof: Uint8Array;
    let snarkPk: Uint8Array, snarkPkDecom: Uint8Array;

    const messages: Uint8Array[] = [];

    beforeAll(async () => {
        await initializeWasm();
    });

    it("verifier setup", () => {
        snarkPk = boundCheckSnarkSetup();
    }, 10000);

    it("decompress snark public key", () => {
        console.time('Snark Pk decompressed');
        snarkPkDecom = boundCheckDecompressSnarkPk(snarkPk);
        console.timeEnd('Snark Pk decompressed');
    }, 40000)

    it("signature setup and sign messages", () => {
        sigParams = generateSignatureParamsG1(messageCount);
        sigSk = generateBBSSigningKey();
        sigPk = generateBBSPublicKeyG2(sigSk, sigParams);

        min = generateFieldElementFromNumber(100);
        max = generateFieldElementFromNumber(200);
        for (let i = 0; i < messageCount; i++) {
            let m = generateFieldElementFromNumber(100 + 1 + i);
            messages.push(m);
        }
        sig = bbsSignG1(messages, sigSk, sigParams, false);
        const res = bbsVerifyG1(messages, sig, sigPk, sigParams, false);
        expect(res.verified).toBe(true);
    });

    it("create proof and verify", () => {
        const revealedIndices = new Set<number>();
        revealedIndices.add(4);

        const [revealedMsgs, unrevealedMsgs] = getRevealedUnrevealed(messages, revealedIndices);
        const statement1 = generatePoKBBSSignatureStatement(sigParams, sigPk, revealedMsgs, false);

        console.time("bound check stmt");
        const statement2 = generateBoundCheckLegoStatement(min, max, snarkPkDecom, true);
        console.timeEnd("bound check stmt");

        const statements = [];
        statements.push(statement1);
        statements.push(statement2);

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
        proof = generateCompositeProofG1WithDeconstructedProofSpec(statements, metaStatements, witnesses);
        console.timeEnd("proof gen");

        console.time("proof ver");
        const res = verifyCompositeProofG1WithDeconstructedProofSpec(proof, statements, metaStatements);
        console.timeEnd("proof ver");
        expect(res.verified).toBe(true);
    }, 10000);
});
