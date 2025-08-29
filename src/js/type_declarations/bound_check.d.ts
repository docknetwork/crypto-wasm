export function boundCheckSnarkSetup(returnUncompressed: boolean): Uint8Array;

export function boundCheckBppSetup(label: Uint8Array, base: number, valueBitSize: number, returnUncompressed: boolean): Uint8Array;

export function boundCheckSmcSetup(label: Uint8Array, base: number, returnUncompressed: boolean): Uint8Array;

export function boundCheckSmcWithKVSetup(label: Uint8Array, base: number, returnUncompressed: boolean): [Uint8Array, Uint8Array];

export function decompressBppParams(params: Uint8Array): Uint8Array;

export function decompressSmcParams(params: Uint8Array): Uint8Array;

export function decompressSmcParamsKV(params: Uint8Array): Uint8Array;

export function decompressSmcParamsKVAndSk(params: Uint8Array): Uint8Array;
