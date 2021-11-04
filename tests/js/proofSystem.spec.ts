import { stringToBytes } from "../utilities";
import {
    BbsSigParams, accumulatorDeriveMembershipProvingKeyFromNonMembershipKey, bbsBlindSignG1, bbsCommitMsgsInG1,
    bbsEncodeMessageForSigning, bbsEncodeMessagesForSigning, bbsGetBasesForCommitmentG1,
    bbsSignG1, bbsUnblindSigG1, bbsVerifyG1,
    generateAccumulatorMembershipStatement,
    generateAccumulatorMembershipWitness,
    generateAccumulatorNonMembershipStatement,
    generateAccumulatorNonMembershipWitness,
    generateAccumulatorParams,
    generateAccumulatorPublicKey,
    generateAccumulatorSecretKey,
    generateBBSPublicKeyG2,
    generateBBSSigningKey,
    generateFieldElementFromBytes,
    generateFieldElementFromNumber,
    generateNonMembershipProvingKey, generatePedersenCommitmentG1Statement, generatePedersenCommitmentWitness,
    generatePoKBBSSignatureStatement,
    generatePoKBBSSignatureWitness,
    generateCompositeProof,
    generateProofSpec, generateRandomFieldElement,
    generateSignatureParamsG1,
    generateWitnessEqualityMetaStatement,
    positiveAccumulatorAdd,
    positiveAccumulatorGetAccumulated,
    positiveAccumulatorInitialize,
    positiveAccumulatorMembershipWitness,
    universalAccumulatorAdd,
    universalAccumulatorComputeD,
    universalAccumulatorComputeInitialFv,
    universalAccumulatorGetAccumulated,
    universalAccumulatorInitialiseGivenFv,
    universalAccumulatorMembershipWitness,
    universalAccumulatorNonMembershipWitness,
    verifyCompositeProof, initializeWasm, getProofSpecAsJson
} from "../../lib";

function setupBBS(messageCount: number, prefix: string, encode: boolean): [BbsSigParams, Uint8Array, Uint8Array, Uint8Array[]] {
    const sigParams = generateSignatureParamsG1(messageCount);
    const sk = generateBBSSigningKey();
    const pk = generateBBSPublicKeyG2(sk, sigParams);
    const messages = [];
    for (let i = 0; i < messageCount; i++) {
        let m = stringToBytes(`${prefix}-${i+1}`);
        if (encode) {
            m = bbsEncodeMessageForSigning(m);
        }
        messages.push(m);
    }
    return [sigParams, sk, pk, messages];
}

function getRevealedUnrevealed(messages: Uint8Array[], revealedIndices: Set<number>): [Map<number, Uint8Array>, Map<number, Uint8Array>] {
    const revealedMsgs = new Map();
    const unrevealedMsgs = new Map();
    for (let i = 0; i < messages.length; i++) {
        if (revealedIndices.has(i)) {
            revealedMsgs.set(i, messages[i]);
        } else {
            unrevealedMsgs.set(i, messages[i]);
        }
    }

    return [revealedMsgs, unrevealedMsgs];
}

describe("Proving knowledge of many BBS+ signatures", () => {

    function proveAndVerifyBBS(messageCount1: number, messageCount2: number, messageCount3: number, encodeWhileSigning: boolean) {
        let [sigParams1, sk1, pk1, messages1] = setupBBS(messageCount1, 'Message1', !encodeWhileSigning);
        let [sigParams2, sk2, pk2, messages2] = setupBBS(messageCount2, 'Message2', !encodeWhileSigning);
        let [sigParams3, sk3, pk3, messages3] = setupBBS(messageCount3, 'Message3', !encodeWhileSigning);

        messages2[3] = messages1[2];
        messages2[4] = messages1[3];
        messages2[5] = messages1[4];

        messages3[3] = messages1[2];
        messages3[5] = messages1[4];

        const sig1 = bbsSignG1(messages1, sk1, sigParams1, encodeWhileSigning);
        const sig2 = bbsSignG1(messages2, sk2, sigParams2, encodeWhileSigning);
        const sig3 = bbsSignG1(messages3, sk3, sigParams3, encodeWhileSigning);

        const revealedIndices1 = new Set<number>();
        revealedIndices1.add(0);
        const revealedIndices2 = new Set<number>();
        revealedIndices2.add(1);
        const revealedIndices3 = new Set<number>();
        revealedIndices3.add(2);

        const [revealedMsgs1, unrevealedMsgs1] = getRevealedUnrevealed(messages1, revealedIndices1);
        const [revealedMsgs2, unrevealedMsgs2] = getRevealedUnrevealed(messages2, revealedIndices2);
        const [revealedMsgs3, unrevealedMsgs3] = getRevealedUnrevealed(messages3, revealedIndices3);

        const statement1 = generatePoKBBSSignatureStatement(sigParams1, pk1, revealedMsgs1, encodeWhileSigning);
        const statement2 = generatePoKBBSSignatureStatement(sigParams2, pk2, revealedMsgs2, encodeWhileSigning);
        const statement3 = generatePoKBBSSignatureStatement(sigParams3, pk3, revealedMsgs3, encodeWhileSigning);

        const metaStatements = [];

        const set1 = new Set<[number, number]>();
        set1.add([0, 2]);
        set1.add([1, 3]);
        set1.add([2, 3]);
        metaStatements.push(generateWitnessEqualityMetaStatement(set1));

        const set2 = new Set<[number, number]>();
        set2.add([0, 3]);
        set2.add([1, 4]);
        metaStatements.push(generateWitnessEqualityMetaStatement(set2));

        const set3 = new Set<[number, number]>();
        set3.add([0, 4]);
        set3.add([1, 5]);
        set3.add([2, 5]);
        metaStatements.push(generateWitnessEqualityMetaStatement(set3));

        const statements = [];
        statements.push(statement1);
        statements.push(statement2);
        statements.push(statement3);

        const context = stringToBytes('test-context');
        const proofSpec = generateProofSpec(statements, metaStatements, context);

        const witness1 = generatePoKBBSSignatureWitness(sig1, unrevealedMsgs1, encodeWhileSigning);
        const witness2 = generatePoKBBSSignatureWitness(sig2, unrevealedMsgs2, encodeWhileSigning);
        const witness3 = generatePoKBBSSignatureWitness(sig3, unrevealedMsgs3, encodeWhileSigning);

        const witnesses = [];
        witnesses.push(witness1);
        witnesses.push(witness2);
        witnesses.push(witness3);

        const nonce = stringToBytes('test-nonce');

        const proof = generateCompositeProof(proofSpec, witnesses, nonce);
        const res = verifyCompositeProof(proof, proofSpec, nonce);
        expect(res.verified).toBe(true);
    }

    beforeAll(async () => {
        await initializeWasm();
    });

    it("generate and verify a proof of knowledge of 3 BBS+ signatures", () => {
        const messageCount1 = 6;
        const messageCount2 = 10;
        const messageCount3 = 9;

        proveAndVerifyBBS(messageCount1, messageCount2, messageCount3, true);
        proveAndVerifyBBS(messageCount1, messageCount2, messageCount3, false);
    });
});

describe("Proving knowledge of BBS+ signatures and accumulator membership and non-membership", () => {
    it("generate and verify a proof of knowledge of a BBS+ signature and accumulator membership", () => {
        const messageCount1 = 6;
        const messageCount2 = 8;
        let [sigParams1, sk1, pk1, messages1] = setupBBS(messageCount1, 'Message1', true);
        let [sigParams2, sk2, pk2, messages2] = setupBBS(messageCount2, 'Message2', true);

        // Message at index 5 is the the accumulator member
        let member = generateFieldElementFromBytes(stringToBytes("userid-1234"));
        messages1[5] = member;
        messages2[5] = member;

        const sig1 = bbsSignG1(messages1, sk1, sigParams1, false);
        const sig2 = bbsSignG1(messages2, sk2, sigParams2, false);

        const revealedIndices1 = new Set<number>();
        revealedIndices1.add(0);
        const revealedIndices2 = new Set<number>();
        revealedIndices2.add(1);

        const [revealedMsgs1, unrevealedMsgs1] = getRevealedUnrevealed(messages1, revealedIndices1);
        const [revealedMsgs2, unrevealedMsgs2] = getRevealedUnrevealed(messages2, revealedIndices2);

        const params = generateAccumulatorParams();
        const sk = generateAccumulatorSecretKey();
        const pk = generateAccumulatorPublicKey(sk, params);

        let posAccumulator = positiveAccumulatorInitialize(params);

        const initialElements = [
            generateFieldElementFromNumber(101),
            generateFieldElementFromNumber(102),
            generateFieldElementFromNumber(103),
            generateFieldElementFromNumber(104),
            generateFieldElementFromNumber(105),
        ];
        const fV = universalAccumulatorComputeInitialFv(initialElements, sk);
        let uniAccumulator = universalAccumulatorInitialiseGivenFv(fV, params, 100);
        const nonMemPrk = generateNonMembershipProvingKey();
        const memPrk = accumulatorDeriveMembershipProvingKeyFromNonMembershipKey(nonMemPrk);

        posAccumulator = positiveAccumulatorAdd(posAccumulator, member, sk);
        uniAccumulator = universalAccumulatorAdd(uniAccumulator, member, sk);

        const nonMember = messages1[3];

        const posWitness = positiveAccumulatorMembershipWitness(posAccumulator, member, sk);
        const uniWitness = universalAccumulatorMembershipWitness(uniAccumulator, member, sk);

        const d = universalAccumulatorComputeD(nonMember, [member]);
        const nmWitness = universalAccumulatorNonMembershipWitness(uniAccumulator, d, nonMember, sk, params);

        const posAccumulated = positiveAccumulatorGetAccumulated(posAccumulator);
        const uniAccumulated = universalAccumulatorGetAccumulated(uniAccumulator);

        const statement1 = generatePoKBBSSignatureStatement(sigParams1, pk1, revealedMsgs1, false);
        const statement2 = generatePoKBBSSignatureStatement(sigParams2, pk2, revealedMsgs2, false);
        const statement3 = generateAccumulatorMembershipStatement(params, pk, memPrk, posAccumulated);
        const statement4 = generateAccumulatorMembershipStatement(params, pk, memPrk, uniAccumulated);
        const statement5 = generateAccumulatorNonMembershipStatement(params, pk, nonMemPrk, uniAccumulated);

        const metaStatements = [];

        const set1 = new Set<[number, number]>();
        set1.add([0, 5]);
        set1.add([1, 5]);
        set1.add([2, 0]);
        set1.add([3, 0]);
        metaStatements.push(generateWitnessEqualityMetaStatement(set1));

        const set2 = new Set<[number, number]>();
        set2.add([0, 3]);
        set2.add([4, 0]);
        metaStatements.push(generateWitnessEqualityMetaStatement(set2));

        const statements = [];
        statements.push(statement1);
        statements.push(statement2);
        statements.push(statement3);
        statements.push(statement4);
        statements.push(statement5);

        const proofSpec = generateProofSpec(statements, metaStatements);

        const witness1 = generatePoKBBSSignatureWitness(sig1, unrevealedMsgs1, false);
        const witness2 = generatePoKBBSSignatureWitness(sig2, unrevealedMsgs2, false);
        const witness3 = generateAccumulatorMembershipWitness(member, posWitness);
        const witness4 = generateAccumulatorMembershipWitness(member, uniWitness);
        const witness5 = generateAccumulatorNonMembershipWitness(nonMember, nmWitness);

        const witnesses = [];
        witnesses.push(witness1);
        witnesses.push(witness2);
        witnesses.push(witness3);
        witnesses.push(witness4);
        witnesses.push(witness5);

        const proof = generateCompositeProof(proofSpec, witnesses);

        const res = verifyCompositeProof(proof, proofSpec);
        expect(res.verified).toBe(true);
    });
});

describe("Proving knowledge of a BBS+ signature while requesting a partially blind BBS+ signature", () => {
    it("generate and verify a proof of knowledge of a BBS+ signature and accumulator membership", () => {
        const messageCount1 = 5;
        const messageCount2 = 6;

        let [sigParams1, sk1, pk1, messages1] = setupBBS(messageCount1, 'Message1', false);
        let [sigParams2, sk2, pk2, messages2] = setupBBS(messageCount2, 'Message2', false);

        messages2[5] = messages1[4];

        const sig1 = bbsSignG1(messages1, sk1, sigParams1, true);

        const revealedIndices1 = new Set<number>();
        revealedIndices1.add(0);
        const [revealedMsgs1, unrevealedMsgs1] = getRevealedUnrevealed(messages1, revealedIndices1);

        const indicesToCommit = new Set<number>();
        const indicesToCommitArr = new Array<number>();
        indicesToCommit.add(0);
        indicesToCommitArr.push(0);
        indicesToCommit.add(1);
        indicesToCommitArr.push(1);
        indicesToCommit.add(5);
        indicesToCommitArr.push(5);
        const msgsToCommit = new Map();
        const msgsToNotCommit = new Map();
        for (let i = 0; i < messageCount2; i++) {
            if (indicesToCommit.has(i)) {
                msgsToCommit.set(i, messages2[i]);
            } else {
                msgsToNotCommit.set(i, messages2[i]);
            }
        }

        const blinding = generateRandomFieldElement();
        const commitment = bbsCommitMsgsInG1(msgsToCommit, blinding, sigParams2, true);
        const bases = bbsGetBasesForCommitmentG1(sigParams2, indicesToCommitArr);

        const statement1 = generatePoKBBSSignatureStatement(sigParams1, pk1, revealedMsgs1, true);
        const statement2 = generatePedersenCommitmentG1Statement(bases, commitment);

        const statements = [];
        statements.push(statement1);
        statements.push(statement2);

        const metaStatements = [];

        const set = new Set<[number, number]>();
        set.add([0, 4]);
        set.add([1, 3]);
        metaStatements.push(generateWitnessEqualityMetaStatement(set));

        const proofSpec = generateProofSpec(statements, metaStatements);

        const witness1 = generatePoKBBSSignatureWitness(sig1, unrevealedMsgs1, true);

        const pcWits = bbsEncodeMessagesForSigning(messages2, indicesToCommit);
        pcWits.splice(0, 0, blinding);
        const witness2 = generatePedersenCommitmentWitness(pcWits);

        const witnesses = [];
        witnesses.push(witness1);
        witnesses.push(witness2);

        const nonce = stringToBytes('test');

        const proof = generateCompositeProof(proofSpec, witnesses, nonce);
        const res = verifyCompositeProof(proof, proofSpec, nonce);
        expect(res.verified).toBe(true);

        const blindSig = bbsBlindSignG1(commitment, msgsToNotCommit, sk2, sigParams2, true);
        const sig2 = bbsUnblindSigG1(blindSig, blinding);
        const res1 = bbsVerifyG1(messages2, sig2, pk2, sigParams2, true);
        expect(res1.verified).toBe(true);
    })
});
