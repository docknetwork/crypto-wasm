import {
    initializeWasm, isWasmInitialized, requireWasmInitialized
} from "../../lib";

describe("For WASM initialization", () => {
    it("returns false when not initialized", () => {
        expect(isWasmInitialized()).toBe(false);
    })

    it("throws when required", () => {
        expect(requireWasmInitialized).toThrow();
    })

    it("returns true when initialized and does not throw", async () => {
        await initializeWasm();
        expect(isWasmInitialized()).toBe(true);
        requireWasmInitialized();
    })
});
