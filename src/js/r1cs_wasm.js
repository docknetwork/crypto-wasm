const {
    wasm, requireWasmInitialized
} = require('./init_wasm');

module.exports.r1csSnarkSetup = (curveName, numPublic, numPrivate, constraints, commitWitnessCount, returnUncompressed) => {
    requireWasmInitialized();
    return wasm.r1csSnarkSetup(curveName, numPublic, numPrivate, constraints, commitWitnessCount, returnUncompressed);
};

module.exports.r1csGenerateWires = (wasmBytes, inputWires) => {
    requireWasmInitialized();
    return wasm.r1csGenerateWires(wasmBytes, inputWires);
};

module.exports.r1csCircuitSatisfied = (curveName, numPublic, numPrivate, constraints, wasmBytes, inputWires) => {
    requireWasmInitialized();
    return wasm.r1csCircuitSatisfied(curveName, numPublic, numPrivate, constraints, wasmBytes, inputWires);
};