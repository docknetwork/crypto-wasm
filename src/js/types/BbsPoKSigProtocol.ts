export interface BbsPoKSigProtocol {
    readonly A_prime: Uint8Array;
    readonly A_bar: Uint8Array;
    readonly d: Uint8Array;
    readonly sc_comm_1: Uint8Array;
    readonly sc_wits_1: Uint8Array;
    readonly sc_comm_2: Uint8Array;
    readonly sc_wits_2: Uint8Array;
}
