export interface BbsPoKSigProtocol {
    readonly A_bar: Uint8Array;
    readonly B_bar: Uint8Array;
    readonly T: Uint8Array;
    readonly sc_comm: Uint8Array;
    readonly sc_wits: Uint8Array[];
}
