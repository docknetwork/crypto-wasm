import {
    frostKeygenG1PubkeyFromSecretKey,
    frostKeygenG1Round1Finish,
    frostKeygenG1Round1ProcessReceivedMessage,
    frostKeygenG1Round2Finish,
    frostKeygenG1Round2ProcessReceivedMessage,
    frostKeygenG1StartRound1,
    frostKeygenG1ThresholdPubkeyFromPubkeys,
    frostKeygenG2PubkeyFromSecretKey,
    frostKeygenG2Round1Finish,
    frostKeygenG2Round1ProcessReceivedMessage,
    frostKeygenG2Round2Finish,
    frostKeygenG2Round2ProcessReceivedMessage,
    frostKeygenG2StartRound1,
    frostKeygenG2ThresholdPubkeyFromPubkeys,
    generateKeyBaseFromGivenG1Point,
    generateKeyBaseFromGivenG2Point,
    generateRandomG1Element,
    generateRandomG2Element,
    generateRandomPublicKeyBaseInG1,
    generateRandomPublicKeyBaseInG2,
    initializeWasm
} from "../../lib";
import {stringToBytes} from "../utilities";
import {doFrostDKG} from "./util";

describe("For Frost DKG", () => {
    beforeAll(async () => {
        await initializeWasm();
    });

    it("generate public key base", () => {
        const seed = stringToBytes("test");

        const pkb1 = generateRandomPublicKeyBaseInG1(seed);
        const g1 = generateRandomG1Element(seed);
        expect(pkb1).toEqual(g1);
        expect(pkb1).toEqual(generateKeyBaseFromGivenG1Point(g1));

        const pkb2 = generateRandomPublicKeyBaseInG2(seed);
        const g2 = generateRandomG2Element(seed);
        expect(pkb2).toEqual(g2);
        expect(pkb2).toEqual(generateKeyBaseFromGivenG2Point(g2));
    });

    it("generate keys in G1", () => {
        doFrostDKG(3, 5, generateRandomPublicKeyBaseInG1, frostKeygenG1StartRound1, frostKeygenG1Round1ProcessReceivedMessage, frostKeygenG1Round1Finish, frostKeygenG1Round2ProcessReceivedMessage, frostKeygenG1Round2Finish, frostKeygenG1PubkeyFromSecretKey, frostKeygenG1ThresholdPubkeyFromPubkeys)
    });

    it("generate keys in G2", () => {
        doFrostDKG(3, 5, generateRandomPublicKeyBaseInG2, frostKeygenG2StartRound1, frostKeygenG2Round1ProcessReceivedMessage, frostKeygenG2Round1Finish, frostKeygenG2Round2ProcessReceivedMessage, frostKeygenG2Round2Finish, frostKeygenG2PubkeyFromSecretKey, frostKeygenG2ThresholdPubkeyFromPubkeys)
    });
});