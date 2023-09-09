import { type PSSig } from "./PSSig";

export interface PSPoKSigProof {
   readonly k: Uint8Array,
   readonly randomized_sig: PSSig,
}
