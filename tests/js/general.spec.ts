import {
  generateFieldElementFromNumber,
  fieldElementAsBytes,
  initializeWasm,
  isWasmInitialized,
  requireWasmInitialized, encodeMessageForSigning, encodeMessageForSigningInConstantTime,
} from "../../lib";
import {stringToBytes} from "./util";

describe("For WASM initialization", () => {
  it("returns false when not initialized", () => {
    expect(isWasmInitialized()).toBe(false);
  });

  it("throws when required", () => {
    expect(requireWasmInitialized).toThrow();
  });

  it("returns true when initialized and does not throw", async () => {
    await initializeWasm();
    expect(isWasmInitialized()).toBe(true);
    requireWasmInitialized();
  });
});

describe("For utils", () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  it("generateFieldElementFromNumber only expects a positive safe integer", () => {
    expect(() => generateFieldElementFromNumber(165)).not.toThrow();
    expect(() => generateFieldElementFromNumber(-20)).toThrow();
    expect(() => generateFieldElementFromNumber(10.6)).toThrow();
    const unsafeInteger = 9906920304888000;
    expect(Number.isSafeInteger(unsafeInteger)).toEqual(false);
    expect(() => generateFieldElementFromNumber(unsafeInteger)).toThrow();
  });

  it("fieldElementAsBytes does not clear the input", () => {
    let x = generateFieldElementFromNumber(165);
    expect(x[0]).toEqual(165);
    let y = fieldElementAsBytes(x, false);
    expect(y[0]).toEqual(165);
    expect(x[0]).toEqual(165);
    let z = fieldElementAsBytes(x, true);
    expect(z[0]).toEqual(165);
    expect(x[0]).toEqual(165);
  });

  it("decoding generateFieldElementFromNumber", () => {
    function bytearrayToNumber(arr: Uint8Array) {
      const buffer = Buffer.from(arr);

      return buffer.readUIntLE(0, 6);
    }
    console.log(generateFieldElementFromNumber(1));
    console.log(generateFieldElementFromNumber(2));
    console.log(generateFieldElementFromNumber(255));
    console.log(generateFieldElementFromNumber(256));
    [1, 2, 255, 256, 512, 1000].forEach((i) => {
      expect(bytearrayToNumber(generateFieldElementFromNumber(i))).toEqual(i);
    })
  })

  it("message encoding timings", () => {
    const count = 500;
    console.time('Variable time encoding');
    for (let i = 0; i < count; i++) {
      let m = stringToBytes(`message no-${i + 1}`);
      m = encodeMessageForSigning(m)
    }
    console.timeEnd('Variable time encoding');

    console.time('Constant time encoding');
    for (let i = 0; i < count; i++) {
      let m = stringToBytes(`message no-${i + 1}`);
      m = encodeMessageForSigningInConstantTime(m)
    }
    console.timeEnd('Constant time encoding');
  })
});
