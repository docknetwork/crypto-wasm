import {
    bbsGenerateSignatureParams,
    bbsPlusGenerateSignatureParamsG1,
    BbsPlusSigParams,
    BbsSigParams,
    frostKeygenG2PubkeyFromSecretKey,
    frostKeygenG2Round1Finish,
    frostKeygenG2Round1ProcessReceivedMessage,
    frostKeygenG2Round2Finish,
    frostKeygenG2Round2ProcessReceivedMessage,
    frostKeygenG2StartRound1,
    frostKeygenG2ThresholdPubkeyFromPubkeys,
    generateKeyBaseFromGivenG2Point,
    generateRandomPublicKeyBaseInG1,
    initializeWasm,
    baseOTPhaseProcessChallenges,
    baseOTPhaseProcessReceiverPubkey,
    baseOTPhaseProcessResponses,
    baseOTPhaseProcessSenderPubkey,
    generateGadgetVectorForThresholdSig,
    startBaseOTPhase,
    baseOTPhaseFinish,
    baseOTPhaseProcessHashedKeys,
    thresholdBbsPlusStartPhase1,
    thresholdBbsPlusPhase1ProcessCommitments,
    thresholdBbsPlusPhase1ProcessShares,
    thresholdBbsPlusPhase1GetSharesForOther,
    thresholdBbsPlusPhase1Finish,
    bbsPlusGeneratePublicKeyG2,
    bbsPlusIsPublicKeyG2Valid,
    bbsGeneratePublicKey,
    bbsIsPublicKeyValid,
    thresholdBbsPlusPhase2Start,
    baseOTOutputCheck,
    thresholdBbsPlusPhase2ReceiveMessage1,
    thresholdBbsPlusPhase2ReceiveMessage2,
    thresholdBbsPlusPhase2Finish,
    thresholdBbsPlusCreateSignatureShare,
    thresholdBbsPlusAggregateSignatureShares,
    bbsPlusVerifyG1,
    bbsVerify,
    thresholdBbsStartPhase1,
    thresholdBbsPhase1ProcessCommitments,
    thresholdBbsPhase1GetSharesForOther,
    thresholdBbsPhase1ProcessShares,
    thresholdBbsPhase1Finish,
    thresholdBbsPhase2Start,
    thresholdBbsPhase2ReceiveMessage1,
    thresholdBbsPhase2ReceiveMessage2,
    thresholdBbsPhase2Finish,
    thresholdBbsCreateSignatureShare,
    thresholdBbsAggregateSignatureShares,
    bbsPlusVerifyG1ConstantTime,
    bbsVerifyConstantTime
} from "../../lib";

import {doFrostDKG, stringToBytes} from "./util";

describe("For threshold BBS+ and BBS", () => {
    const threshold = 3;
    const total = 5;
    const messageCount = 10;
    const sigBatchSize = 2;
    const allSignerIds = new Set(Array.from({length: total}, (_, i) => i + 1));

    let paramsBbsPlus: BbsPlusSigParams;
    let paramsBbs: BbsSigParams;
    let gadgetVector: Uint8Array;

    let secretKeysBbsPlus: Uint8Array[] = [];
    let publicKeysBbsPlus: Uint8Array[] = [];
    let thresholdPubkeyBbsPlus: Uint8Array;

    let secretKeysBbs: Uint8Array[] = [];
    let publicKeysBbs: Uint8Array[] = [];
    let thresholdPubkeyBbs: Uint8Array;

    let baseOTOutputs: Uint8Array[] = []

    beforeAll(async () => {
        await initializeWasm();
        paramsBbsPlus = bbsPlusGenerateSignatureParamsG1(messageCount);
        paramsBbs = bbsGenerateSignatureParams(messageCount);

        const pubKeyBaseBbsPlus = (_seed) => {
          return generateKeyBaseFromGivenG2Point(paramsBbsPlus.g2);
        };
        const pubKeyBaseBbs = (_seed) => {
            return generateKeyBaseFromGivenG2Point(paramsBbs.g2);
        };

        const [s1, p1, t1] = doFrostDKG(threshold, total, pubKeyBaseBbsPlus, frostKeygenG2StartRound1, frostKeygenG2Round1ProcessReceivedMessage, frostKeygenG2Round1Finish, frostKeygenG2Round2ProcessReceivedMessage, frostKeygenG2Round2Finish, frostKeygenG2PubkeyFromSecretKey, frostKeygenG2ThresholdPubkeyFromPubkeys);
        secretKeysBbsPlus = s1.slice(0, threshold);
        publicKeysBbsPlus = p1.slice(0, threshold);
        thresholdPubkeyBbsPlus = t1;

        const [s2, p2, t2] = doFrostDKG(threshold, total, pubKeyBaseBbs, frostKeygenG2StartRound1, frostKeygenG2Round1ProcessReceivedMessage, frostKeygenG2Round1Finish, frostKeygenG2Round2ProcessReceivedMessage, frostKeygenG2Round2Finish, frostKeygenG2PubkeyFromSecretKey, frostKeygenG2ThresholdPubkeyFromPubkeys);
        secretKeysBbs = s2.slice(0, threshold);
        publicKeysBbs = p2.slice(0, threshold);
        thresholdPubkeyBbs = t2;

        for (let i = 0; i < threshold; i++) {
            let pk = bbsPlusGeneratePublicKeyG2(secretKeysBbsPlus[i], paramsBbsPlus);
            expect(bbsPlusIsPublicKeyG2Valid(pk)).toBe(true);
            expect(pk).toEqual(publicKeysBbsPlus[i]);

            pk = bbsGeneratePublicKey(secretKeysBbs[i], paramsBbs);
            expect(bbsIsPublicKeyValid(pk)).toBe(true);
            expect(pk).toEqual(publicKeysBbs[i]);
        }

        gadgetVector = generateGadgetVectorForThresholdSig(stringToBytes("test"));
    });

    it("run base OT phase", () => {
        let pkBase = generateRandomPublicKeyBaseInG1();
        const baseOTPhases: Uint8Array[] = [];
        const senderPkAndProofs: Map<number, Uint8Array>[] = [];
        const receiverPks = new Map<[number, number], Uint8Array>();
        const challenges = new Map<[number, number], Uint8Array>();
        const responses = new Map<[number, number], Uint8Array>();
        const hashedKeys = new Map<[number, number], Uint8Array>();

        for (let i = 1; i <= total; i++) {
            const others = new Set(allSignerIds);
            others.delete(i);
            const [baseOTPhase, pkAndProof] = startBaseOTPhase(i, others, pkBase);
            baseOTPhases.push(baseOTPhase);
            senderPkAndProofs.push(pkAndProof);
        }
        senderPkAndProofs.forEach((pkAndProof, i) => {
            const senderId = i + 1;
            for (const [receiverId, pp] of pkAndProof) {
                const r = baseOTPhaseProcessSenderPubkey(baseOTPhases[receiverId-1], senderId, pp, pkBase);
                baseOTPhases[receiverId-1] = r[0];
                receiverPks.set([receiverId, senderId], r[1]);
            }
        });

        for (const [[senderId, receiverId], pk] of receiverPks) {
            const r = baseOTPhaseProcessReceiverPubkey(baseOTPhases[receiverId-1], senderId, pk);
            baseOTPhases[receiverId-1] = r[0];
            challenges.set([receiverId, senderId], r[1]);
        }

        for (const [[senderId, receiverId], chal] of challenges) {
            const r = baseOTPhaseProcessChallenges(baseOTPhases[receiverId-1], senderId, chal);
            baseOTPhases[receiverId-1] = r[0];
            responses.set([receiverId, senderId], r[1]);
        }

        for (const [[senderId, receiverId], resp] of responses) {
            const r = baseOTPhaseProcessResponses(baseOTPhases[receiverId-1], senderId, resp);
            baseOTPhases[receiverId-1] = r[0];
            hashedKeys.set([receiverId, senderId], r[1]);
        }

        for (const [[senderId, receiverId], hk] of hashedKeys) {
            baseOTPhases[receiverId-1] = baseOTPhaseProcessHashedKeys(baseOTPhases[receiverId - 1], senderId, hk);
        }

        for (let i = 0; i < total; i++) {
            baseOTOutputs.push(baseOTPhaseFinish(baseOTPhases[i]));
        }

        baseOTOutputCheck(baseOTOutputs)
    });

    function checkThresholdSig(protocolId: Uint8Array, params, pk, sk, startPhase1Func, phaseProcessCommsFunc, phase1GetSharesFunc, phase1ProcessSharesFunc, phase1FinishFunc, phase2StartFunc, phase2RecvMsg1Func, phase2RecvMsg2Func, phase2FinishFunc, createSigShareFunc, aggrSigShareFunc, verifySigFunc) {
        const phase1s: Uint8Array[] = []
        const comms: Uint8Array[] = []
        const commsZero: Map<number, Uint8Array>[] = []
        const phase1Outputs: Uint8Array[] = [];

        const participatingSignerIds = new Set(Array.from({length: threshold}, (_, i) => i + 1));

        // Start Phase1 of signing
        for (let i = 1; i <= threshold; i++) {
            const others = new Set(participatingSignerIds);
            others.delete(i);
            const [phase1, comm, commZero] = startPhase1Func(sigBatchSize, i, others, protocolId);
            phase1s.push(phase1);
            comms.push(comm);
            commsZero.push(commZero);
        }

        for (let receiverId = 1; receiverId <= threshold; receiverId++) {
            for (let senderId = 1; senderId <= threshold; senderId++) {
                if (receiverId != senderId) {
                    phase1s[receiverId - 1] = phaseProcessCommsFunc(phase1s[receiverId - 1], senderId, comms[senderId - 1], commsZero[senderId - 1].get(receiverId) as Uint8Array);
                }
            }
        }

        for (let receiverId = 1; receiverId <= threshold; receiverId++) {
            for (let senderId = 1; senderId <= threshold; senderId++) {
                if (receiverId != senderId) {
                    const [share, zeroShare] = phase1GetSharesFunc(phase1s[senderId - 1], receiverId);
                    phase1s[receiverId - 1] = phase1ProcessSharesFunc(phase1s[receiverId - 1], senderId, share, zeroShare);
                }
            }
        }

        // Finish Phase1 of signing
        for (let i = 0; i < threshold; i++) {
            phase1Outputs.push(phase1FinishFunc(phase1s[i], sk[i]));
        }

        // Start Phase2 of signing
        const phase2s: Uint8Array[] = [];
        const msg1ToSend: [number, Map<number, Uint8Array>][] = [];
        const msg2s = new Map<[number, number], Uint8Array>();
        const phase2Outputs: Uint8Array[] = []
        for (let i = 1; i <= threshold; i++) {
            const others = new Set(participatingSignerIds);
            others.delete(i);
            const [phase2, msgs] = phase2StartFunc(i, others, phase1Outputs[i-1], baseOTOutputs[i-1], gadgetVector);
            phase2s.push(phase2);
            msg1ToSend.push([i, msgs]);
        }

        for (const [senderId, msgs] of msg1ToSend) {
            for (const [receiverId, msg] of msgs) {
                const r = phase2RecvMsg1Func(phase2s[receiverId - 1], senderId, msg, gadgetVector);
                phase2s[receiverId - 1] = r[0];
                msg2s.set([receiverId, senderId], r[1]);
            }
        }

        for (const [[senderId, receiverId], m] of msg2s) {
            phase2s[receiverId - 1] = phase2RecvMsg2Func(phase2s[receiverId - 1], senderId, m, gadgetVector);
        }

        // Finish Phase2 of signing
        for (let i = 0; i < threshold; i++) {
            phase2Outputs.push(phase2FinishFunc(phase2s[i]));
        }

        // For each sig, create signature shares, aggregate them to form a sig and verify them
        for (let i = 0; i < sigBatchSize; i++) {
            const msgsToSign: Uint8Array[] = [];
            for (let j = 0; j < messageCount; j++) {
                msgsToSign.push(stringToBytes(`Message-${i}-${j}`));
            }

            // Create sig shares
            const shares: Uint8Array[] = [];
            for (let j = 0; j < threshold; j++) {
                shares.push(createSigShareFunc(msgsToSign, i, phase1Outputs[j], phase2Outputs[j], params, true))
            }

            // Aggregate shares to form a sig
            const sig = aggrSigShareFunc(shares);

            // Verify sig
            const res = verifySigFunc(msgsToSign, sig, pk, params, true);
            expect(res.verified).toBe(true);
        }
    }

    it("create a threshold BBS+ signature", () => {
        const protocolId = stringToBytes("test BBS+");
        checkThresholdSig(protocolId, paramsBbsPlus, thresholdPubkeyBbsPlus, secretKeysBbsPlus, thresholdBbsPlusStartPhase1, thresholdBbsPlusPhase1ProcessCommitments, thresholdBbsPlusPhase1GetSharesForOther, thresholdBbsPlusPhase1ProcessShares, thresholdBbsPlusPhase1Finish, thresholdBbsPlusPhase2Start, thresholdBbsPlusPhase2ReceiveMessage1, thresholdBbsPlusPhase2ReceiveMessage2, thresholdBbsPlusPhase2Finish, thresholdBbsPlusCreateSignatureShare, thresholdBbsPlusAggregateSignatureShares, bbsPlusVerifyG1ConstantTime)
    })

    it("create a threshold BBS signature", () => {
        const protocolId = stringToBytes("test BBS");
        checkThresholdSig(protocolId, paramsBbs, thresholdPubkeyBbs, secretKeysBbs, thresholdBbsStartPhase1, thresholdBbsPhase1ProcessCommitments, thresholdBbsPhase1GetSharesForOther, thresholdBbsPhase1ProcessShares, thresholdBbsPhase1Finish, thresholdBbsPhase2Start, thresholdBbsPhase2ReceiveMessage1, thresholdBbsPhase2ReceiveMessage2, thresholdBbsPhase2Finish, thresholdBbsCreateSignatureShare, thresholdBbsAggregateSignatureShares, bbsVerifyConstantTime)
    })
})