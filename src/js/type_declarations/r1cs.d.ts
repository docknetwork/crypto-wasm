import {Constraint} from "../types";

export function r1csSnarkSetup(curveName: string, numPublic: number, numPrivate: number, constraints: Constraint[], commitWitnessCount: number, returnUncompressed: boolean): Uint8Array;

export function r1csGenerateWires(wasmBytes: Uint8Array, inputWires: Map<string, Uint8Array[]>): Uint8Array[];

export function r1csCircuitSatisfied(curveName: string, numPublic: number, numPrivate: number, constraints: Constraint[], wasmBytes: Uint8Array, inputWires: Map<string, Uint8Array[]>): boolean;
