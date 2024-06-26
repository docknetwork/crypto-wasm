import {
    bddt16MacAdaptParamsForMsgCount,
    bddt16BlindMacGenerate,
    bddt16GenerateMacParams,
    bddt16IsMacParamsValid,
    bddt16MacCommitMsgs,
    bddt16MacGenerate,
    bddt16MacGenerateSecretKey,
    Bddt16MacParams,
    bddt16MacParamsFromBytes,
    bddt16MacParamsMaxSupportedMsgs,
    bddt16MacParamsToBytes,
    bddt16MacVerify,
    bddt16UnblindMac,
    generateRandomFieldElement,
    initializeWasm,
    bddt16MacGeneratePublicKeyG1,
    bddt16MacIsPublicKeyG1Valid,
    bddt16MacProofOfValidity,
    bddt16MacVerifyProofOfValidity,
    bddt16MacGenerateConstantTime,
    bddt16MacVerifyConstantTime,
    bddt16MacCommitMsgsConstantTime,
    bddt16BlindMacGenerateConstantTime,
    encodeMessageForSigningInConstantTime,
} from "../../lib";
import {checkResult, stringToBytes} from "./util";

describe("For BDDT16 MAC", () => {
    let macParams: Bddt16MacParams, sk: Uint8Array, pkG1: Uint8Array;
    const seed = new Uint8Array([0, 2, 3, 4, 5]);
    const messages = [
        stringToBytes("Message1"),
        stringToBytes("Message2"),
        stringToBytes("Message3"),
        stringToBytes("Message4"),
        stringToBytes("Message4"),
        stringToBytes("Message6"),
    ];
    const messageCount = messages.length;

    beforeAll(async () => {
        await initializeWasm();
    });

    it("generate secret key", () => {
        const sk_ = bddt16MacGenerateSecretKey();
        expect(sk_).toBeInstanceOf(Uint8Array);

        const sk1 = bddt16MacGenerateSecretKey(seed);
        expect(sk1).toBeInstanceOf(Uint8Array);

        const sk2 = bddt16MacGenerateSecretKey(seed);
        expect(sk2).toBeInstanceOf(Uint8Array);

        expect(sk1).toEqual(sk2);

        sk = sk1;
    });

    it("generate MAC params", () => {
        expect(() => bddt16GenerateMacParams(-5)).toThrow();
        expect(() => bddt16GenerateMacParams(6.3)).toThrow();

        const params0 = bddt16GenerateMacParams(messageCount);
        expect(params0).toBeInstanceOf(Object);
        expect(params0.g_vec.length).toEqual(messageCount);
        expect(bddt16IsMacParamsValid(params0)).toBe(true);

        const label = stringToBytes("MAC params");
        const params = bddt16GenerateMacParams(messageCount, label);
        expect(params).toBeInstanceOf(Object);
        expect(params.g_vec.length).toEqual(messageCount);
        expect(bddt16IsMacParamsValid(params)).toBe(true);
        expect(bddt16MacParamsMaxSupportedMsgs(params)).toBe(messageCount);

        const bytes = bddt16MacParamsToBytes(params);
        const deserzParams = bddt16MacParamsFromBytes(bytes);
        expect(params).toEqual(deserzParams);

        macParams = params;
    });

    it("generate public key in G1 from secret key", () => {
        pkG1 = bddt16MacGeneratePublicKeyG1(sk, macParams);
        expect(pkG1).toBeInstanceOf(Uint8Array);
        expect(bddt16MacIsPublicKeyG1Valid(pkG1)).toBe(true);
    });

    it("generate and verify MAC", () => {
        const mac = bddt16MacGenerate(messages, sk, macParams, true);
        const res = bddt16MacVerify(messages, mac, sk, macParams, true);
        checkResult(res);
    });

    it("generate and verify MAC and its proof of validity with constant time encoding", () => {
        const mac = bddt16MacGenerateConstantTime(messages, sk, macParams, true);
        const res = bddt16MacVerifyConstantTime(messages, mac, sk, macParams, true);
        checkResult(res);

        let proofOfValidity = bddt16MacProofOfValidity(mac, sk, pkG1, macParams);
        checkResult(bddt16MacVerifyProofOfValidity(proofOfValidity, mac, messages, pkG1, macParams, true));
    });

    it("generate and verify signature in G1 with encoded messages", () => {
        const encMsgs = messages.map((m) => encodeMessageForSigningInConstantTime(m));

        const sig1 = bddt16MacGenerateConstantTime(encMsgs, sk, macParams, false);
        const res1 = bddt16MacVerify(encMsgs, sig1, sk, macParams, false);
        expect(res1.verified).toBe(true);

        const sig2 = bddt16MacGenerate(encMsgs, sk, macParams, false);
        const res2 = bddt16MacVerifyConstantTime(encMsgs, sig2, sk, macParams, false);
        expect(res2.verified).toBe(true);
    })

    it("extend MAC params", () => {
        const label = stringToBytes("MAC param");
        const params0 = bddt16GenerateMacParams(1);
        expect(bddt16MacParamsMaxSupportedMsgs(params0)).toBe(1);

        const params1 = bddt16MacAdaptParamsForMsgCount(params0, label, 5);
        expect(bddt16MacParamsMaxSupportedMsgs(params1)).toBe(5);
        expect(bddt16IsMacParamsValid(params1)).toBe(true);
        expect(params0.g_vec[0]).toEqual(params1.g_vec[0]);

        const params2 = bddt16MacAdaptParamsForMsgCount(params1, label, 2);
        expect(bddt16MacParamsMaxSupportedMsgs(params2)).toBe(2);
        expect(bddt16IsMacParamsValid(params2)).toBe(true);
        expect(params1.g_vec[0]).toEqual(params2.g_vec[0]);
        expect(params1.g_vec[1]).toEqual(params2.g_vec[1]);
    });

    function checkBlind(commitFunc, signFunc, verifyFunc) {
        // Commit to message indices 1 and 5
        const msgsToCommit = new Map();
        msgsToCommit.set(1, messages[1]);
        msgsToCommit.set(5, messages[5]);

        const msgsNotToCommit = new Map();
        msgsNotToCommit.set(0, messages[0]);
        msgsNotToCommit.set(2, messages[2]);
        msgsNotToCommit.set(3, messages[3]);
        msgsNotToCommit.set(4, messages[4]);

        const blinding = generateRandomFieldElement();
        const commitment = commitFunc(
            msgsToCommit,
            blinding,
            macParams,
            true
        );
        const blindMac = signFunc(
            commitment,
            msgsNotToCommit,
            sk,
            macParams,
            true
        );
        const mac = bddt16UnblindMac(blindMac, blinding);
        const res = verifyFunc(messages, mac, sk, macParams, true);
        expect(res.verified).toBe(true);
    }

    it("generate and verify a blind MAC", () => {
        checkBlind(bddt16MacCommitMsgs, bddt16BlindMacGenerate, bddt16MacVerify)
    });

    it("generate and verify a blind MAC with constant time encoding", () => {
        checkBlind(bddt16MacCommitMsgsConstantTime, bddt16BlindMacGenerateConstantTime, bddt16MacVerifyConstantTime)
    });
})