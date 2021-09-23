export interface BbsPoKSigProof {
    readonly A_prime: Uint8Array;
    readonly A_bar: Uint8Array;
    readonly d: Uint8Array;
    readonly T1: Uint8Array;
    readonly sc_resp_1: Uint8Array;
    readonly T2: Uint8Array;
    readonly sc_resp_2: Uint8Array;
}
