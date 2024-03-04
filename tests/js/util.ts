import {VerifyResult} from "../../lib";
import {error} from "console";

/**
 * Converts a UTF-8 Encoded string to a byte array
 * @param string
 */
export const stringToBytes = (string: string): Uint8Array =>
    Uint8Array.from(Buffer.from(string, "utf-8"));

export function getRevealedUnrevealed(messages: Uint8Array[], revealedIndices: Set<number>): [Map<number, Uint8Array>, Map<number, Uint8Array>] {
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

export function areUint8ArraysEqual(arr1: Uint8Array, arr2: Uint8Array): boolean {
    if (arr1.length !== arr2.length) {
        return false;
    }

    for (let i = 0; i < arr1.length; i++) {
        if (arr1[i] !== arr2[i]) {
            return false;
        }
    }

    return true;
}

/**
 * Convert little-endian bytearray to BigInt
 * @param arr
 * @returns
 */
export function fromLeToBigInt(arr: Uint8Array): BigInt {
    let r = BigInt(0);
    let m = BigInt(1);
    for (let i = 0; i < arr.length; i++) {
        r += m * BigInt(arr[i]);
        m <<= BigInt(8);
    }
    return r;
}

export function checkResult(result: VerifyResult) {
    const verified = result.verified;
    if (!verified) {
        error(result);
    }
    expect(verified).toEqual(true);
}

export function doFrostDKG(threshold, total, pkBaseFunc, startRound1Func, recvRound1Func, finishRound1Func, recRound2Func, finishRound2Func, pkFromShareFunc, tpkFromPkFunc): [Uint8Array[], Uint8Array[], Uint8Array] {
    const seed = stringToBytes("test");
    const pkBase = pkBaseFunc(seed);

    const schnorrPrfContext = stringToBytes("test-context");

    const round1States: Uint8Array[] = [];
    const round1Msgs: Uint8Array[] = [];
    const round2States: Uint8Array[] = [];
    const sharesToSend: Uint8Array[][] = [];
    const pkWithIds: [number, Uint8Array][] = [];

    for (let i = 1; i <= total; i++) {
        const [state, msg] = startRound1Func(i, threshold, total, schnorrPrfContext, pkBase);
        round1States.push(state);
        round1Msgs.push(msg);
    }

    for (let receiverId = 1; receiverId <= total; receiverId++) {
        for (let senderId = 1; senderId <= total; senderId++) {
            if (receiverId != senderId) {
                round1States[receiverId - 1] = recvRound1Func(round1States[receiverId - 1], round1Msgs[senderId - 1], schnorrPrfContext, pkBase);
            }
        }
    }

    for (let i = 0; i < total; i++) {
        const [state, shares] = finishRound1Func(round1States[i]);
        expect(shares.length).toEqual(total);
        round2States.push(state);
        sharesToSend.push(shares);
    }

    for (let receiverId = 1; receiverId <= total; receiverId++) {
        for (let senderId = 1; senderId <= total; senderId++) {
            if (receiverId != senderId) {
                round2States[receiverId - 1] = recRound2Func(round2States[receiverId - 1], senderId, sharesToSend[senderId - 1][receiverId - 1], pkBase);
            }
        }
    }

    let sks: Uint8Array[] = [];
    let pks: Uint8Array[] = [];
    let expectedTpk: Uint8Array;
    for (let i = 0; i < total; i++) {
        const [sk, pk, tpk] = finishRound2Func(round2States[i], pkBase);
        expect(pkFromShareFunc(sk, pkBase)).toEqual(pk);
        if (i == 0) {
            expectedTpk = tpk
        } else {
            // @ts-ignore
            expect(tpk).toEqual(expectedTpk);
        }
        pkWithIds.push([i + 1, pk]);
        sks.push(sk);
        pks.push(pk);
    }

    // @ts-ignore
    expect(tpkFromPkFunc(pkWithIds, threshold)).toEqual(expectedTpk);
    // @ts-ignore
    return [sks, pks, expectedTpk];
}