import { PSSig } from "./PSSig";

export interface PSPoKSigProtocol {
    readonly witness: Uint8Array,
    readonly k: Uint8Array,
    readonly randomized_sig: PSSig,
}
