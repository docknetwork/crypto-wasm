import {
    bbsEncodeMessageForSigning,
    bbsSignG1,
    BbsSigParams,
    bbsVerifyG1,
    generateBBSPublicKeyG2,
    generateBBSSigningKey,
    generateCompositeProofG1WithDeconstructedProofSpec,
    generatePoKBBSSignatureStatement,
    generatePoKBBSSignatureWitness,
    generateSaverStatement,
    generateSaverWitness,
    generateSignatureParamsG1,
    generateWitnessEqualityMetaStatement,
    initializeWasm, saverDecompressChunkedCommitmentGenerators,
    saverDecompressDecryptionKey,
    saverDecompressEncryptionGenerators,
    saverDecompressEncryptionKey,
    saverDecompressSnarkPk, saverDecryptCiphertextUsingSnarkPk,
    saverDecryptorSetup,
    saverGenerateChunkedCommitmentGenerators,
    saverGenerateEncryptionGenerators,
    saverGetCiphertextFromProof, saverVerifyDecryptionUsingSnarkPk,
    verifyCompositeProofG1WithDeconstructedProofSpec
} from "../../lib";

import {stringToBytes, getRevealedUnrevealed} from "../utilities";

describe("Verifiable encryption of a signed message", () => {
    const messageCount = 5;
    const chunkBitSize = 8;
    const encMsgIdx = 2;

    let sigParams: BbsSigParams, sigSk: Uint8Array, sigPk: Uint8Array, sig: Uint8Array, proof: Uint8Array;
    let snarkPk: Uint8Array, sk: Uint8Array, ek: Uint8Array, dk: Uint8Array, encGens: Uint8Array, commGens: Uint8Array;
    let snarkPkDecom: Uint8Array, ekDecom: Uint8Array, dkDecom: Uint8Array, encGensDecom: Uint8Array,
        commGensDecom: Uint8Array;

    const messages: Uint8Array[] = [];

    beforeAll(async () => {
        await initializeWasm();
    });

    it("decryptor setup", () => {
        encGens = saverGenerateEncryptionGenerators();
        commGens = saverGenerateChunkedCommitmentGenerators();
        const setup = saverDecryptorSetup(chunkBitSize, encGens);
        snarkPk = setup[0];
        sk = setup[1];
        ek = setup[2];
        dk = setup[3];
    }, 10000);

    it("decompress public params", () => {
        encGensDecom = saverDecompressEncryptionGenerators(encGens);
        commGensDecom = saverDecompressChunkedCommitmentGenerators(commGens);
        ekDecom = saverDecompressEncryptionKey(ek);
        dkDecom = saverDecompressDecryptionKey(dk);
        console.log('Params and keys decompressed');
        console.time('Snark Pk decompressed');
        snarkPkDecom = saverDecompressSnarkPk(snarkPk);
        console.timeEnd('Snark Pk decompressed');
    }, 120000);

    it("signature setup and sign messages", () => {
        sigParams = generateSignatureParamsG1(messageCount);
        sigSk = generateBBSSigningKey();
        sigPk = generateBBSPublicKeyG2(sigSk, sigParams);

        for (let i = 0; i < messageCount; i++) {
            let m = stringToBytes(`${i + 1}`);
            m = bbsEncodeMessageForSigning(m);
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

        console.time("saver stmt");
        const statement2 = generateSaverStatement(chunkBitSize, encGensDecom, commGensDecom, ekDecom, snarkPkDecom, true);
        console.timeEnd("saver stmt");

        const statements = [];
        statements.push(statement1);
        statements.push(statement2);

        const metaStatements = [];
        const set = new Set<[number, number]>();
        set.add([0, encMsgIdx]);
        set.add([1, 0]);
        metaStatements.push(generateWitnessEqualityMetaStatement(set));

        const witness1 = generatePoKBBSSignatureWitness(sig, unrevealedMsgs, false);
        const witness2 = generateSaverWitness(messages[encMsgIdx]);

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
    }, 120000);

    it("decrypt and verify", () => {
        const ct = saverGetCiphertextFromProof(proof, 1);

        console.time("decrypt");
        const dec = saverDecryptCiphertextUsingSnarkPk(ct, sk, dkDecom, snarkPkDecom, chunkBitSize, true);
        console.timeEnd("decrypt");

        console.time("decrypt ver");
        const res = saverVerifyDecryptionUsingSnarkPk(ct, dec[0], dec[1], dkDecom, snarkPkDecom, encGensDecom, chunkBitSize, true);
        console.timeEnd("decrypt ver");
    }, 80000);
});
