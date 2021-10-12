const wasm = require("./wasm.js");

let initializedModule;

const initialize = async () => {
    if (!initializedModule) {
        initializedModule = await wasm.default();
    }
};

module.exports = {
    wasm, initialize
}