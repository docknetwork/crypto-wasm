import {
    generateFieldElementFromNumber,
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

describe("For utils", () => {
    beforeAll(async () => {
        await initializeWasm();
    });

    it("generateFieldElementFromNumber only expects a positive integer of <= 32 bits", () => {
        expect(() => generateFieldElementFromNumber(-20)).toThrow();
        expect(() => generateFieldElementFromNumber(10.6)).toThrow();
        expect(() => generateFieldElementFromNumber(1651153384148)).toThrow();
        expect(() => generateFieldElementFromNumber(165)).not.toThrow();
    })
});
