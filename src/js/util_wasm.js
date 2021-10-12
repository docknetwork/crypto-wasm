const {
    wasm, initialize
} = require('./init_wasm');

const {
    throwErrorOnRejectedPromise
} = require('./util');


module.exports.generateRandomFieldElement = async (seed) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.generateRandomFieldElement(seed)
    );
};

module.exports.generateRandomG1Element = async () => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.generateRandomG1Element()
    );
};

module.exports.generateRandomG2Element = async () => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.generateRandomG2Element()
    );
};

module.exports.generateFieldElementFromBytes = async (bytes) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.generateFieldElementFromBytes(bytes)
    );
};

module.exports.fieldElementAsBytes = async (element) => {
    await initialize();
    return throwErrorOnRejectedPromise(
        wasm.fieldElementAsBytes(element)
    );
};

module.exports.generateChallengeFromBytes = async (bytes) => {
    await initialize();
    return throwErrorOnRejectedPromise(wasm.generateChallengeFromBytes(bytes));
};
