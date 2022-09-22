export type LCTerm = [number, Uint8Array];

export type LC = LCTerm[];

export type Constraint = [LC, LC, LC];

export interface R1CS {
    readonly curveName: string;
    readonly numPublic: number;
    readonly numPrivate: number;
    readonly constraints: Constraint[];
}
