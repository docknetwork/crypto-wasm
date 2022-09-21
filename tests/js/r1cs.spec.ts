import * as r1csf from "r1csfile";
import * as fs from "fs";
import * as path from "path";

import {
  bbsSignG1,
  bbsVerifyG1,
  generateBBSPublicKeyG2,
  generateBBSSigningKey,
  generateCompositeProofG1WithDeconstructedProofSpec,
  generateFieldElementFromNumber,
  generatePoKBBSSignatureStatement,
  generatePoKBBSSignatureWitness,
  generateR1CSCircomProverStatement,
  generateR1CSCircomProverStatementFromParamRefs,
  generateR1CSCircomVerifierStatement,
  generateR1CSCircomVerifierStatementFromParamRefs,
  generateR1CSCircomWitness,
  generateSetupParamForBytes,
  generateSetupParamForFieldElemVec,
  generateSetupParamForLegoProvingKey,
  generateSetupParamForLegoVerifyingKey,
  generateSetupParamForR1CS,
  generateSignatureParamsG1,
  generateWitnessEqualityMetaStatement,
  initializeWasm,
  legosnarkDecompressPk,
  legosnarkDecompressVk,
  legosnarkVkFromPk, R1CS,
  r1csCircuitSatisfied,
  r1csGenerateWires,
  r1csSnarkSetup,
  verifyCompositeProofG1WithDeconstructedProofSpec,
} from "../../lib";
import {areUint8ArraysEqual, fromLeToBigInt, getRevealedUnrevealed} from "../utilities";
import {Constraint, LC, LCTerm} from "../../src/js";

interface ParsedR1CSFile {
  F: {fromMontgomery: (n: Uint8Array) => Uint8Array},
  curve: { name: string };
  n8: number;
  nPubInputs: number;
  nPrvInputs: number;
  nOutputs: number;
  nVars: number;
  constraints: [object, object, object];
}

function processParsedR1CSFile(parsed: ParsedR1CSFile): R1CS {
  const curveName = parsed.curve.name as string;
  const numPublic = 1 + parsed.nPubInputs + parsed.nOutputs;
  const numPrivate = parsed.nVars - numPublic;

  function parseLC(i, v): [number, Uint8Array] {
    return [parseInt(i), parsed.F.fromMontgomery(v)];
  }

  const constraints = parsed.constraints.map((c) => {
    const A: LC = Object.entries(c[0]).map(([i, v]) => parseLC(i, v) as LCTerm);
    const B: LC = Object.entries(c[1]).map(([i, v]) => parseLC(i, v) as LCTerm);
    const C: LC = Object.entries(c[2]).map(([i, v]) => parseLC(i, v) as LCTerm);
    return [A, B, C] as Constraint;
  });
  return {curveName, numPublic, numPrivate, constraints};
}

function circomArtifactPath(fileName: string): string {
  return `${path.resolve("./")}/tests/circom/${fileName}`;
}

async function getProcessedR1CS(r1csName: string): Promise<R1CS> {
  const parsed = await parseR1CSFile(r1csName);
  return processParsedR1CSFile(parsed);
}

async function parseR1CSFile(r1csName: string): Promise<ParsedR1CSFile> {
  const parsed = await r1csf.readR1cs(circomArtifactPath(r1csName));
  await parsed.curve.terminate();
  return parsed;
}

function checkProcessedR1CS(
  processed: R1CS,
  commitWitnessCount: number
) {
  const pkCom = r1csSnarkSetup(
    processed.curveName,
    processed.numPublic,
    processed.numPrivate,
    processed.constraints,
    commitWitnessCount,
    false
  );
  const pkDecom = r1csSnarkSetup(
    processed.curveName,
    processed.numPublic,
    processed.numPrivate,
    processed.constraints,
    commitWitnessCount,
    true
  );
  const vkCom = legosnarkVkFromPk(pkCom, false);
  const vkDecom = legosnarkVkFromPk(pkCom, true);
  expect(areUint8ArraysEqual(legosnarkDecompressVk(vkCom), vkDecom)).toEqual(
    true
  );
}

function getWasmBytes(fileName: string): Uint8Array {
  const content = fs.readFileSync(circomArtifactPath(fileName));
  return new Uint8Array(content);
}

async function checkIfCircuitSatisfied(
  r1csName: string,
  wasmName: string,
  inputWires: Map<string, Uint8Array[]>,
  res: boolean
) {
  const r = await getProcessedR1CS(r1csName);
  const wasmBytes = getWasmBytes(wasmName);
  expect(
    r1csCircuitSatisfied(
      r.curveName,
      r.numPublic,
      r.numPrivate,
      r.constraints,
      wasmBytes,
      inputWires
    )
  ).toEqual(res);
}

async function snarkSetupFromFileName(
  r1csName: string,
  commitWitnessCount: number
): Promise<[R1CS, Uint8Array, Uint8Array, Uint8Array]> {
  const processedR1CS = await getProcessedR1CS(r1csName);
  const snarkPk = r1csSnarkSetup(
    processedR1CS.curveName,
    processedR1CS.numPublic,
    processedR1CS.numPrivate,
    processedR1CS.constraints,
    commitWitnessCount,
    false
  );
  const snarkPkDecom = legosnarkDecompressPk(snarkPk);
  const snarkVkDecom = legosnarkVkFromPk(snarkPk, true);
  return [processedR1CS, snarkPk, snarkPkDecom, snarkVkDecom];
}

describe("Check constraints", () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  it("check constraints for multiply", async () => {
    const processedR1CS = await getProcessedR1CS("multiply2.r1cs");
    expect(processedR1CS.constraints.length).toEqual(1);
    expect(processedR1CS.constraints[0].length).toEqual(3);
    expect(fromLeToBigInt(processedR1CS.constraints[0][0][0][1])).toEqual(
      BigInt(
        "52435875175126190479447740508185965837690552500527637822603658699938581184512"
      )
    );
    expect(fromLeToBigInt(processedR1CS.constraints[0][1][0][1])).toEqual(
      BigInt("1")
    );
    expect(fromLeToBigInt(processedR1CS.constraints[0][2][0][1])).toEqual(
      BigInt(
        "52435875175126190479447740508185965837690552500527637822603658699938581184512"
      )
    );
  });

  it("check constraints for test1", async () => {
    const processedR1CS = await getProcessedR1CS("test1.r1cs");
    expect(processedR1CS.constraints.length).toEqual(2);
    expect(processedR1CS.constraints[0].length).toEqual(3);
    expect(processedR1CS.constraints[1].length).toEqual(3);

    expect(fromLeToBigInt(processedR1CS.constraints[0][0][0][1])).toEqual(
      BigInt(
        "52435875175126190479447740508185965837690552500527637822603658699938581184512"
      )
    );
    expect(fromLeToBigInt(processedR1CS.constraints[0][1][0][1])).toEqual(
      BigInt("1")
    );
    expect(fromLeToBigInt(processedR1CS.constraints[0][2][0][1])).toEqual(
      BigInt(
        "52435875175126190479447740508185965837690552500527637822603658699938581184512"
      )
    );

    expect(fromLeToBigInt(processedR1CS.constraints[1][0][0][1])).toEqual(
      BigInt(
        "52435875175126190479447740508185965837690552500527637822603658699938581184512"
      )
    );
    expect(fromLeToBigInt(processedR1CS.constraints[1][1][0][1])).toEqual(
      BigInt("1")
    );
    expect(fromLeToBigInt(processedR1CS.constraints[1][2][0][1])).toEqual(
      BigInt("5")
    );
    expect(fromLeToBigInt(processedR1CS.constraints[1][2][1][1])).toEqual(
      BigInt(
        "52435875175126190479447740508185965837690552500527637822603658699938581184512"
      )
    );
    expect(fromLeToBigInt(processedR1CS.constraints[1][2][2][1])).toEqual(
      BigInt("1")
    );
  });

  it("check constraints for test2", async () => {
    const processedR1CS = await getProcessedR1CS("test2.r1cs");
    expect(processedR1CS.constraints.length).toEqual(3);
    expect(processedR1CS.constraints[0].length).toEqual(3);
    expect(processedR1CS.constraints[1].length).toEqual(3);
    expect(processedR1CS.constraints[2].length).toEqual(3);

    expect(fromLeToBigInt(processedR1CS.constraints[0][0][0][1])).toEqual(
      BigInt(
        "52435875175126190479447740508185965837690552500527637822603658699938581184512"
      )
    );
    expect(fromLeToBigInt(processedR1CS.constraints[0][1][0][1])).toEqual(
      BigInt("1")
    );
    expect(fromLeToBigInt(processedR1CS.constraints[0][2][0][1])).toEqual(
      BigInt(
        "52435875175126190479447740508185965837690552500527637822603658699938581184512"
      )
    );

    expect(fromLeToBigInt(processedR1CS.constraints[1][0][0][1])).toEqual(
      BigInt(
        "52435875175126190479447740508185965837690552500527637822603658699938581184512"
      )
    );
    expect(fromLeToBigInt(processedR1CS.constraints[1][1][0][1])).toEqual(
      BigInt("1")
    );
    expect(fromLeToBigInt(processedR1CS.constraints[1][2][0][1])).toEqual(
      BigInt(
        "52435875175126190479447740508185965837690552500527637822603658699938581184512"
      )
    );

    expect(fromLeToBigInt(processedR1CS.constraints[2][0][0][1])).toEqual(
      BigInt(
        "52435875175126190479447740508185965837690552500527637822603658699938581184511"
      )
    );
    expect(fromLeToBigInt(processedR1CS.constraints[2][1][0][1])).toEqual(
      BigInt("1")
    );
    expect(fromLeToBigInt(processedR1CS.constraints[2][2][0][1])).toEqual(
      BigInt("1")
    );
    expect(fromLeToBigInt(processedR1CS.constraints[2][2][1][1])).toEqual(
      BigInt(
        "52435875175126190479447740508185965837690552500527637822603658699938581184512"
      )
    );
    expect(fromLeToBigInt(processedR1CS.constraints[2][2][2][1])).toEqual(
      BigInt("1")
    );
    expect(fromLeToBigInt(processedR1CS.constraints[2][2][3][1])).toEqual(
      BigInt("1")
    );
    expect(fromLeToBigInt(processedR1CS.constraints[2][2][4][1])).toEqual(
      BigInt("1")
    );
  });
});

describe("Check wires", () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  it("check wires for multiply2", async () => {
    const wasmBytes = getWasmBytes('multiply2.wasm');
    const inputWires = new Map<string, Uint8Array[]>();
    inputWires.set("a", [generateFieldElementFromNumber(1010)]);
    inputWires.set("b", [generateFieldElementFromNumber(1030)]);
    const wires = r1csGenerateWires(wasmBytes, inputWires);

    expect(fromLeToBigInt(wires[0])).toEqual(BigInt("1"));
    expect(fromLeToBigInt(wires[1])).toEqual(BigInt("1040300"));
    expect(fromLeToBigInt(wires[2])).toEqual(BigInt("1010"));
    expect(fromLeToBigInt(wires[3])).toEqual(BigInt("1030"));
  });

  it("check wires for less than", async () => {
    const wasmBytes = getWasmBytes('less_than_32.wasm');

    let inputWires = new Map<string, Uint8Array[]>();
    inputWires.set("a", [generateFieldElementFromNumber(1010)]);
    inputWires.set("b", [generateFieldElementFromNumber(1030)]);
    let wires = r1csGenerateWires(wasmBytes, inputWires);

    expect(fromLeToBigInt(wires[0])).toEqual(BigInt("1"));
    expect(fromLeToBigInt(wires[1])).toEqual(BigInt("1"));
    expect(fromLeToBigInt(wires[2])).toEqual(BigInt("1010"));
    expect(fromLeToBigInt(wires[3])).toEqual(BigInt("1030"));

    inputWires = new Map<string, Uint8Array[]>();
    inputWires.set("a", [generateFieldElementFromNumber(1030)]);
    inputWires.set("b", [generateFieldElementFromNumber(1010)]);
    wires = r1csGenerateWires(wasmBytes, inputWires);

    expect(fromLeToBigInt(wires[0])).toEqual(BigInt("1"));
    expect(fromLeToBigInt(wires[1])).toEqual(BigInt("0"));
    expect(fromLeToBigInt(wires[2])).toEqual(BigInt("1030"));
    expect(fromLeToBigInt(wires[3])).toEqual(BigInt("1010"));
  });

  it("check wires for less than public", async () => {
    const wasmBytes = getWasmBytes('less_than_public_64.wasm');

    let inputWires = new Map<string, Uint8Array[]>();
    inputWires.set("a", [generateFieldElementFromNumber(1010)]);
    inputWires.set("b", [generateFieldElementFromNumber(1030)]);
    let wires = r1csGenerateWires(wasmBytes, inputWires);

    expect(fromLeToBigInt(wires[0])).toEqual(BigInt("1"));
    expect(fromLeToBigInt(wires[1])).toEqual(BigInt("1"));
    expect(fromLeToBigInt(wires[2])).toEqual(BigInt("1030"));
    expect(fromLeToBigInt(wires[3])).toEqual(BigInt("1010"));

    inputWires = new Map<string, Uint8Array[]>();
    inputWires.set("a", [generateFieldElementFromNumber(1030)]);
    inputWires.set("b", [generateFieldElementFromNumber(1010)]);
    wires = r1csGenerateWires(wasmBytes, inputWires);

    expect(fromLeToBigInt(wires[0])).toEqual(BigInt("1"));
    expect(fromLeToBigInt(wires[1])).toEqual(BigInt("0"));
    expect(fromLeToBigInt(wires[2])).toEqual(BigInt("1010"));
    expect(fromLeToBigInt(wires[3])).toEqual(BigInt("1030"));
  });
});

describe("Check if circuit is satisfied", () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  it("check if multiplication circuit satisfied", async () => {
    const inputWires = new Map<string, Uint8Array[]>();
    inputWires.set("a", [generateFieldElementFromNumber(1010)]);
    inputWires.set("b", [generateFieldElementFromNumber(1030)]);
    await checkIfCircuitSatisfied(
      "multiply2.r1cs",
      "multiply2.wasm",
      inputWires,
      true
    );
  });

  it("check if less than circuit satisfied", async () => {
    const inputWires = new Map<string, Uint8Array[]>();
    inputWires.set("a", [generateFieldElementFromNumber(1000)]);
    inputWires.set("b", [generateFieldElementFromNumber(1030)]);
    await checkIfCircuitSatisfied(
      "less_than_32.r1cs",
      "less_than_32.wasm",
      inputWires,
      true
    );
  });

  it("check if test1 circuit satisfied", async () => {
    const inputWires = new Map<string, Uint8Array[]>();
    inputWires.set("x", [generateFieldElementFromNumber(5)]);
    await checkIfCircuitSatisfied("test1.r1cs", "test1.wasm", inputWires, true);
  });

  it("check if test2 circuit satisfied", async () => {
    const inputWires = new Map<string, Uint8Array[]>();
    inputWires.set("x", [generateFieldElementFromNumber(1)]);
    inputWires.set("z", [generateFieldElementFromNumber(3)]);
    await checkIfCircuitSatisfied("test2.r1cs", "test2.wasm", inputWires, true);
  });

  it("check if test3 circuit satisfied", async () => {
    const inputWires = new Map<string, Uint8Array[]>();
    inputWires.set("x", [generateFieldElementFromNumber(3)]);
    inputWires.set("y", [generateFieldElementFromNumber(4)]);
    inputWires.set("a", [generateFieldElementFromNumber(5)]);
    inputWires.set("b", [generateFieldElementFromNumber(6)]);
    inputWires.set("c", [generateFieldElementFromNumber(7)]);
    inputWires.set("d", [generateFieldElementFromNumber(8)]);
    await checkIfCircuitSatisfied("test3.r1cs", "test3.wasm", inputWires, true);
  });

  it("check if test4 circuit satisfied", async () => {
    const inputWires = new Map<string, Uint8Array[]>();
    inputWires.set("x", [generateFieldElementFromNumber(3)]);
    inputWires.set("y", [generateFieldElementFromNumber(4)]);
    inputWires.set("a", [generateFieldElementFromNumber(5)]);
    inputWires.set("b", [generateFieldElementFromNumber(6)]);
    inputWires.set("p", [generateFieldElementFromNumber(7)]);
    inputWires.set("q", [generateFieldElementFromNumber(8)]);
    inputWires.set("r", [generateFieldElementFromNumber(9)]);
    inputWires.set("s", [generateFieldElementFromNumber(10)]);
    await checkIfCircuitSatisfied("test4.r1cs", "test4.wasm", inputWires, true);
  });
});

describe("Generate proving Key from R1CS", () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  it("generates proving key from R1CS file correctly", async () => {
    for (const [name, cm] of [
      ["multiply2.r1cs", 2],
      ["less_than_32.r1cs", 2],
      ["less_than_public_64.r1cs", 1],
      ["test1.r1cs", 1],
      ["test2.r1cs", 2],
      ["test3.r1cs", 6],
      ["test4.r1cs", 8],
    ]) {
      const processedR1CS = await getProcessedR1CS(name as string);
      checkProcessedR1CS(processedR1CS, cm as number);
    }
  });
});

describe("Proof generation and verification from R1CS and WASM file", () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  it("generate and verify proof for multiply circuit", async () => {
    const [
      processedR1CS,
      _,
      snarkPkDecom,
      snarkVkDecom,
    ] = await snarkSetupFromFileName("multiply2.r1cs", 2);

    const wasmBytes = getWasmBytes("multiply2.wasm");

    const messageCount = 5;
    const sigParams = generateSignatureParamsG1(messageCount);
    const sigSk = generateBBSSigningKey();
    const sigPk = generateBBSPublicKeyG2(sigSk, sigParams);

    const messages: Uint8Array[] = [];
    const messagesAsIntegers: number[] = [];
    for (let i = 0; i < messageCount; i++) {
      messagesAsIntegers.push((100 + i) * 10);
      messages.push(generateFieldElementFromNumber(messagesAsIntegers[i]));
    }
    const in1Index = 1;
    const in2Index = 3;
    const publicOutput = generateFieldElementFromNumber(
      messagesAsIntegers[in1Index] * messagesAsIntegers[in2Index]
    );
    const sig = bbsSignG1(messages, sigSk, sigParams, false);
    const res = bbsVerifyG1(messages, sig, sigPk, sigParams, false);
    expect(res.verified).toBe(true);

    const revealedIndices = new Set<number>();
    revealedIndices.add(0);

    const [revealedMsgs, unrevealedMsgs] = getRevealedUnrevealed(
      messages,
      revealedIndices
    );
    const statement1 = generatePoKBBSSignatureStatement(
      sigParams,
      sigPk,
      revealedMsgs,
      false
    );

    const statement2 = generateR1CSCircomProverStatement(
      processedR1CS.curveName,
      processedR1CS.numPublic,
      processedR1CS.numPrivate,
      processedR1CS.constraints,
      wasmBytes,
      snarkPkDecom,
      true
    );

    const proverStatements: Uint8Array[] = [];
    proverStatements.push(statement1);
    proverStatements.push(statement2);

    const metaStatements: Uint8Array[] = [];

    const set1 = new Set<[number, number]>();
    set1.add([0, in1Index]);
    set1.add([1, 0]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set1));

    const set2 = new Set<[number, number]>();
    set2.add([0, in2Index]);
    set2.add([1, 1]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set2));

    const witness1 = generatePoKBBSSignatureWitness(sig, unrevealedMsgs, false);
    const inputWires = new Map<string, Uint8Array[]>();
    inputWires.set("a", [messages[in1Index]]);
    inputWires.set("b", [messages[in2Index]]);
    const witness2 = generateR1CSCircomWitness(inputWires, ["a", "b"]);

    const witnesses: Uint8Array[] = [];
    witnesses.push(witness1);
    witnesses.push(witness2);

    console.time("proof gen");
    const proof = generateCompositeProofG1WithDeconstructedProofSpec(
      proverStatements,
      metaStatements,
      [],
      witnesses
    );
    console.timeEnd("proof gen");

    const statement3 = generateR1CSCircomVerifierStatement(
      [publicOutput],
      snarkVkDecom,
      true
    );

    const verifierStatements: Uint8Array[] = [];
    verifierStatements.push(statement1);
    verifierStatements.push(statement3);

    console.time("proof ver");
    const res1 = verifyCompositeProofG1WithDeconstructedProofSpec(
      proof,
      verifierStatements,
      metaStatements,
      []
    );
    console.timeEnd("proof ver");
    expect(res1.verified).toBe(true);
  });

  it("generate and verify proof less_than_32 circuit", async () => {
    const [
      processedR1CS,
      _,
      snarkPkDecom,
      snarkVkDecom,
    ] = await snarkSetupFromFileName("less_than_32.r1cs", 2);

    const wasmBytes = getWasmBytes("less_than_32.wasm");

    const messageCount = 5;
    const sigParams = generateSignatureParamsG1(messageCount);
    const sigSk = generateBBSSigningKey();
    const sigPk = generateBBSPublicKeyG2(sigSk, sigParams);

    const messages: Uint8Array[] = [];
    const messagesAsIntegers: number[] = [];
    for (let i = 0; i < messageCount; i++) {
      messagesAsIntegers.push((10 + i) * 10);
      messages.push(generateFieldElementFromNumber(messagesAsIntegers[i]));
    }
    const in1Index = 1;
    const in2Index = 3;
    const publicOutput = generateFieldElementFromNumber(1);
    const sig = bbsSignG1(messages, sigSk, sigParams, false);
    const res = bbsVerifyG1(messages, sig, sigPk, sigParams, false);
    expect(res.verified).toBe(true);

    const revealedIndices = new Set<number>();
    revealedIndices.add(0);

    const [revealedMsgs, unrevealedMsgs] = getRevealedUnrevealed(
      messages,
      revealedIndices
    );
    const statement1 = generatePoKBBSSignatureStatement(
      sigParams,
      sigPk,
      revealedMsgs,
      false
    );

    const statement2 = generateR1CSCircomProverStatement(
      processedR1CS.curveName,
      processedR1CS.numPublic,
      processedR1CS.numPrivate,
      processedR1CS.constraints,
      wasmBytes,
      snarkPkDecom,
      true
    );

    const proverStatements: Uint8Array[] = [];
    proverStatements.push(statement1);
    proverStatements.push(statement2);

    const metaStatements: Uint8Array[] = [];

    const set1 = new Set<[number, number]>();
    set1.add([0, in1Index]);
    set1.add([1, 0]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set1));

    const set2 = new Set<[number, number]>();
    set2.add([0, in2Index]);
    set2.add([1, 1]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set2));

    const witness1 = generatePoKBBSSignatureWitness(sig, unrevealedMsgs, false);
    const inputWires = new Map<string, Uint8Array[]>();
    inputWires.set("a", [messages[in1Index]]);
    inputWires.set("b", [messages[in2Index]]);
    const witness2 = generateR1CSCircomWitness(inputWires, ["a", "b"]);

    const witnesses: Uint8Array[] = [];
    witnesses.push(witness1);
    witnesses.push(witness2);

    console.time("proof gen");
    const proof = generateCompositeProofG1WithDeconstructedProofSpec(
      proverStatements,
      metaStatements,
      [],
      witnesses
    );
    console.timeEnd("proof gen");

    const statement3 = generateR1CSCircomVerifierStatement(
      [publicOutput],
      snarkVkDecom,
      true
    );

    const verifierStatements: Uint8Array[] = [];
    verifierStatements.push(statement1);
    verifierStatements.push(statement3);

    console.time("proof ver");
    const res1 = verifyCompositeProofG1WithDeconstructedProofSpec(
      proof,
      verifierStatements,
      metaStatements,
      []
    );
    console.timeEnd("proof ver");
    expect(res1.verified).toBe(true);
  });

  it("generate and verify proof for less_than_public_64 circuit", async () => {
    const [
      processedR1CS,
      _,
      snarkPkDecom,
      snarkVkDecom,
    ] = await snarkSetupFromFileName("less_than_public_64.r1cs", 1);

    const wasmBytes = getWasmBytes("less_than_public_64.wasm");

    const messageCount = 5;
    const sigParams = generateSignatureParamsG1(messageCount);
    const sigSk = generateBBSSigningKey();
    const sigPk = generateBBSPublicKeyG2(sigSk, sigParams);

    const messages: Uint8Array[] = [];
    const messagesAsIntegers: number[] = [];
    for (let i = 0; i < messageCount; i++) {
      messagesAsIntegers.push((10 + i) * 10);
      messages.push(generateFieldElementFromNumber(messagesAsIntegers[i]));
    }
    const in1Index = 1;
    const publicGt = generateFieldElementFromNumber(500000);
    const sig = bbsSignG1(messages, sigSk, sigParams, false);
    const res = bbsVerifyG1(messages, sig, sigPk, sigParams, false);
    expect(res.verified).toBe(true);

    const revealedIndices = new Set<number>();
    revealedIndices.add(0);

    const [revealedMsgs, unrevealedMsgs] = getRevealedUnrevealed(
      messages,
      revealedIndices
    );
    const statement1 = generatePoKBBSSignatureStatement(
      sigParams,
      sigPk,
      revealedMsgs,
      false
    );

    const statement2 = generateR1CSCircomProverStatement(
      processedR1CS.curveName,
      processedR1CS.numPublic,
      processedR1CS.numPrivate,
      processedR1CS.constraints,
      wasmBytes,
      snarkPkDecom,
      true
    );

    const proverStatements: Uint8Array[] = [];
    proverStatements.push(statement1);
    proverStatements.push(statement2);

    const metaStatements: Uint8Array[] = [];

    const set1 = new Set<[number, number]>();
    set1.add([0, in1Index]);
    set1.add([1, 0]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set1));

    const witness1 = generatePoKBBSSignatureWitness(sig, unrevealedMsgs, false);
    const inputWires = new Map<string, Uint8Array[]>();
    inputWires.set("a", [messages[in1Index]]);
    inputWires.set("b", [publicGt]);
    const witness2 = generateR1CSCircomWitness(inputWires, ["a"], ["b"]);

    const witnesses: Uint8Array[] = [];
    witnesses.push(witness1);
    witnesses.push(witness2);

    console.time("proof gen");
    const proof = generateCompositeProofG1WithDeconstructedProofSpec(
      proverStatements,
      metaStatements,
      [],
      witnesses
    );
    console.timeEnd("proof gen");

    const statement3 = generateR1CSCircomVerifierStatement(
      [generateFieldElementFromNumber(1), publicGt],
      snarkVkDecom,
      true
    );

    const verifierStatements: Uint8Array[] = [];
    verifierStatements.push(statement1);
    verifierStatements.push(statement3);

    console.time("proof ver");
    const res1 = verifyCompositeProofG1WithDeconstructedProofSpec(
      proof,
      verifierStatements,
      metaStatements,
      []
    );
    console.timeEnd("proof ver");
    expect(res1.verified).toBe(true);
  });

  it("generate and verify proof for less_than_public_64 circuit for multiple messages", async () => {
    const [
      processedR1CS,
      _,
      snarkPkDecom,
      snarkVkDecom,
    ] = await snarkSetupFromFileName("less_than_public_64.r1cs", 1);

    const wasmBytes = getWasmBytes("less_than_public_64.wasm");

    const messageCount = 5;
    const sigParams = generateSignatureParamsG1(messageCount);
    const sigSk = generateBBSSigningKey();
    const sigPk = generateBBSPublicKeyG2(sigSk, sigParams);

    const messages: Uint8Array[] = [];
    const messagesAsIntegers: number[] = [];
    for (let i = 0; i < messageCount; i++) {
      messagesAsIntegers.push((10 + i) * 10);
      messages.push(generateFieldElementFromNumber(messagesAsIntegers[i]));
    }

    const publicGt = generateFieldElementFromNumber(500000);
    const sig = bbsSignG1(messages, sigSk, sigParams, false);
    const res = bbsVerifyG1(messages, sig, sigPk, sigParams, false);
    expect(res.verified).toBe(true);

    const revealedIndices = new Set<number>();
    const [revealedMsgs, unrevealedMsgs] = getRevealedUnrevealed(
      messages,
      revealedIndices
    );

    const proverSetupParams: Uint8Array[] = [];
    proverSetupParams.push(
      generateSetupParamForR1CS(
        processedR1CS.curveName,
        processedR1CS.numPublic,
        processedR1CS.numPrivate,
        processedR1CS.constraints
      )
    );
    proverSetupParams.push(generateSetupParamForBytes(wasmBytes));
    proverSetupParams.push(
      generateSetupParamForLegoProvingKey(snarkPkDecom, true)
    );

    const proverStatements: Uint8Array[] = [];
    const metaStatements: Uint8Array[] = [];

    proverStatements.push(
      generatePoKBBSSignatureStatement(sigParams, sigPk, revealedMsgs, false)
    );

    for (let i = 0; i < messageCount; i++) {
      proverStatements.push(
        generateR1CSCircomProverStatementFromParamRefs(0, 1, 2)
      );
      const set = new Set<[number, number]>();
      set.add([0, i]);
      set.add([1 + i, 0]);
      metaStatements.push(generateWitnessEqualityMetaStatement(set));
    }

    const witnesses: Uint8Array[] = [];
    witnesses.push(generatePoKBBSSignatureWitness(sig, unrevealedMsgs, false));
    for (let i = 0; i < messageCount; i++) {
      const inputWires = new Map<string, Uint8Array[]>();
      inputWires.set("a", [messages[i]]);
      inputWires.set("b", [publicGt]);
      witnesses.push(generateR1CSCircomWitness(inputWires, ["a"], ["b"]));
    }

    console.time("proof gen");
    const proof = generateCompositeProofG1WithDeconstructedProofSpec(
      proverStatements,
      metaStatements,
      proverSetupParams,
      witnesses
    );
    console.timeEnd("proof gen");

    const verifierSetupParams: Uint8Array[] = [];
    verifierSetupParams.push(
      generateSetupParamForFieldElemVec([
        generateFieldElementFromNumber(1),
        publicGt,
      ])
    );
    verifierSetupParams.push(
      generateSetupParamForLegoVerifyingKey(snarkVkDecom, true)
    );

    const verifierStatements: Uint8Array[] = [];
    verifierStatements.push(
      generatePoKBBSSignatureStatement(sigParams, sigPk, revealedMsgs, false)
    );

    for (let i = 0; i < messageCount; i++) {
      verifierStatements.push(
        generateR1CSCircomVerifierStatementFromParamRefs(0, 1)
      );
    }

    const res1 = verifyCompositeProofG1WithDeconstructedProofSpec(
      proof,
      verifierStatements,
      metaStatements,
      verifierSetupParams
    );
    expect(res1.verified).toBe(true);
  });

  it("generate and verify proof for test1 circuit", async () => {
    const [
      processedR1CS,
      _,
      snarkPkDecom,
      snarkVkDecom,
    ] = await snarkSetupFromFileName("test1.r1cs", 1);

    const wasmBytes = getWasmBytes("test1.wasm");

    const messageCount = 5;
    const sigParams = generateSignatureParamsG1(messageCount);
    const sigSk = generateBBSSigningKey();
    const sigPk = generateBBSPublicKeyG2(sigSk, sigParams);

    const messages: Uint8Array[] = [];
    const messagesAsIntegers: number[] = [];
    for (let i = 0; i < messageCount; i++) {
      messagesAsIntegers.push((10 + i) * 10);
      messages.push(generateFieldElementFromNumber(messagesAsIntegers[i]));
    }
    const idx = 1;
    const publicGt = generateFieldElementFromNumber(
      Math.trunc(Math.pow(messagesAsIntegers[idx], 3)) +
        messagesAsIntegers[idx] +
        5
    );
    const sig = bbsSignG1(messages, sigSk, sigParams, false);
    const res = bbsVerifyG1(messages, sig, sigPk, sigParams, false);
    expect(res.verified).toBe(true);

    const revealedIndices = new Set<number>();
    revealedIndices.add(0);

    const [revealedMsgs, unrevealedMsgs] = getRevealedUnrevealed(
      messages,
      revealedIndices
    );
    const statement1 = generatePoKBBSSignatureStatement(
      sigParams,
      sigPk,
      revealedMsgs,
      false
    );

    const statement2 = generateR1CSCircomProverStatement(
      processedR1CS.curveName,
      processedR1CS.numPublic,
      processedR1CS.numPrivate,
      processedR1CS.constraints,
      wasmBytes,
      snarkPkDecom,
      true
    );

    const proverStatements: Uint8Array[] = [];
    proverStatements.push(statement1);
    proverStatements.push(statement2);

    const metaStatements: Uint8Array[] = [];

    const set1 = new Set<[number, number]>();
    set1.add([0, idx]);
    set1.add([1, 0]);
    metaStatements.push(generateWitnessEqualityMetaStatement(set1));

    const witness1 = generatePoKBBSSignatureWitness(sig, unrevealedMsgs, false);
    const inputWires = new Map<string, Uint8Array[]>();
    inputWires.set("x", [messages[idx]]);
    const witness2 = generateR1CSCircomWitness(inputWires, ["x"]);

    const witnesses: Uint8Array[] = [];
    witnesses.push(witness1);
    witnesses.push(witness2);

    console.time("proof gen");
    const proof = generateCompositeProofG1WithDeconstructedProofSpec(
      proverStatements,
      metaStatements,
      [],
      witnesses
    );
    console.timeEnd("proof gen");

    const statement3 = generateR1CSCircomVerifierStatement(
      [publicGt],
      snarkVkDecom,
      true
    );

    const verifierStatements: Uint8Array[] = [];
    verifierStatements.push(statement1);
    verifierStatements.push(statement3);

    console.time("proof ver");
    const res1 = verifyCompositeProofG1WithDeconstructedProofSpec(
      proof,
      verifierStatements,
      metaStatements,
      []
    );
    console.timeEnd("proof ver");
    expect(res1.verified).toBe(true);
  });
});
