// This ends up pointing to a CJS version of the ES module generated by wasm-pack
// which is done post-compile via rollup
/*const {
    generatePoKBBSSignatureStatement, generateAccumulatorMembershipStatement,
    generateAccumulatorNonMembershipStatement, generatePedersenCommitmentStatement, generateWitnessEqualityMetaStatement,
    generatePoKBBSSignatureWitness, generateAccumulatorMembershipWitness, generateAccumulatorNonMembershipWitness,
    generatePedersenCommitmentWitness, generateProofSpecG1, generateCompositeProof, verifyCompositeProof
} = require("./index");*/

const {
    wasm, requireWasmInitialized
} = require('./init_wasm');

module.exports.generatePoKBBSSignatureStatement = (params, publicKey, revealedMessages, encodeMessages) => {
    requireWasmInitialized();
    return wasm.generatePoKBBSSignatureStatement(params, publicKey, revealedMessages, encodeMessages);
};

module.exports.generatePoKBBSSignatureStatementFromParamRefs = (params, publicKey, revealedMessages, encodeMessages) => {
    requireWasmInitialized();
    return wasm.generatePoKBBSSignatureStatementFromParamRefs(params, publicKey, revealedMessages, encodeMessages);
};

module.exports.generateAccumulatorMembershipStatement = (params, publicKey, provingKey, accumulated) => {
    requireWasmInitialized();
    return wasm.generateAccumulatorMembershipStatement(params, publicKey, provingKey, accumulated);
};

module.exports.generateAccumulatorMembershipStatementFromParamRefs = (params, publicKey, provingKey, accumulated) => {
    requireWasmInitialized();
    return wasm.generateAccumulatorMembershipStatementFromParamRefs(params, publicKey, provingKey, accumulated);
};

module.exports.generateAccumulatorNonMembershipStatement = (params, publicKey, provingKey, accumulated) => {
    requireWasmInitialized();
    return wasm.generateAccumulatorNonMembershipStatement(params, publicKey, provingKey, accumulated);
};

module.exports.generateAccumulatorNonMembershipStatementFromParamRefs = (params, publicKey, provingKey, accumulated) => {
    requireWasmInitialized();
    return wasm.generateAccumulatorNonMembershipStatementFromParamRefs(params, publicKey, provingKey, accumulated);
};

module.exports.generatePedersenCommitmentG1Statement = (bases, commitment) => {
    requireWasmInitialized();
    return wasm.generatePedersenCommitmentG1Statement(bases, commitment);
};

module.exports.generatePedersenCommitmentG1StatementFromParamRefs = (bases, commitment) => {
    requireWasmInitialized();
    return wasm.generatePedersenCommitmentG1StatementFromParamRefs(bases, commitment);
};

module.exports.generatePedersenCommitmentG2Statement = (bases, commitment) => {
    requireWasmInitialized();
    return wasm.generatePedersenCommitmentG2Statement(bases, commitment);
};

module.exports.generatePedersenCommitmentG2StatementFromParamRefs = (bases, commitment) => {
    requireWasmInitialized();
    return wasm.generatePedersenCommitmentG2StatementFromParamRefs(bases, commitment);
};

module.exports.generateSaverProverStatement = (chunkBitSize, encGens, commGens, encryptionKey, snarkPk, uncompressedPublicParams) => {
    requireWasmInitialized();
    return wasm.generateSaverProverStatement(chunkBitSize, encGens, commGens, encryptionKey, snarkPk, uncompressedPublicParams);
};

module.exports.generateSaverProverStatementFromParamRefs = (chunkBitSize, encGens, commGens, encryptionKey, snarkPk) => {
    requireWasmInitialized();
    return wasm.generateSaverProverStatementFromParamRefs(chunkBitSize, encGens, commGens, encryptionKey, snarkPk);
};

module.exports.generateSaverVerifierStatement = (chunkBitSize, encGens, commGens, encryptionKey, snarkVk, uncompressedPublicParams) => {
    requireWasmInitialized();
    return wasm.generateSaverVerifierStatement(chunkBitSize, encGens, commGens, encryptionKey, snarkVk, uncompressedPublicParams);
};

module.exports.generateSaverVerifierStatementFromParamRefs = (chunkBitSize, encGens, commGens, encryptionKey, snarkVk) => {
    requireWasmInitialized();
    return wasm.generateSaverVerifierStatementFromParamRefs(chunkBitSize, encGens, commGens, encryptionKey, snarkVk);
};

module.exports.generateBoundCheckLegoProverStatement = (min, max, snarkPk, uncompressedPublicParams) => {
    requireWasmInitialized();
    return wasm.generateBoundCheckLegoProverStatement(min, max, snarkPk, uncompressedPublicParams);
};

module.exports.generateBoundCheckLegoProverStatementFromParamRefs = (min, max, snarkPk) => {
    requireWasmInitialized();
    return wasm.generateBoundCheckLegoProverStatementFromParamRefs(min, max, snarkPk);
};

module.exports.generateBoundCheckLegoVerifierStatement = (min, max, snarkVk, uncompressedPublicParams) => {
    requireWasmInitialized();
    return wasm.generateBoundCheckLegoVerifierStatement(min, max, snarkVk, uncompressedPublicParams);
};

module.exports.generateBoundCheckLegoVerifierStatementFromParamRefs = (min, max, snarkVk) => {
    requireWasmInitialized();
    return wasm.generateBoundCheckLegoVerifierStatementFromParamRefs(min, max, snarkVk);
};

module.exports.generateWitnessEqualityMetaStatement = (equalities) => {
    requireWasmInitialized();
    return wasm.generateWitnessEqualityMetaStatement(equalities);
};

module.exports.generatePoKBBSSignatureWitness = (signature, unrevealedMessages, encodeMessages) => {
    requireWasmInitialized();
    return wasm.generatePoKBBSSignatureWitness(signature, unrevealedMessages, encodeMessages);
};

module.exports.generateAccumulatorMembershipWitness = (element, witness) => {
    requireWasmInitialized();
    return wasm.generateAccumulatorMembershipWitness(element, witness);
};

module.exports.generateAccumulatorNonMembershipWitness = (element, witness) => {
    requireWasmInitialized();
    return wasm.generateAccumulatorNonMembershipWitness(element, witness);
};

module.exports.generatePedersenCommitmentWitness = (elements) => {
    requireWasmInitialized();
    return wasm.generatePedersenCommitmentWitness(elements);
};

module.exports.generateSaverWitness = (message) => {
    requireWasmInitialized();
    return wasm.generateSaverWitness(message);
};

module.exports.generateBoundCheckWitness = (message) => {
    requireWasmInitialized();
    return wasm.generateBoundCheckWitness(message);
};

module.exports.generateProofSpecG1 = (statements, metaStatements, setupParams, context) => {
    requireWasmInitialized();
    return wasm.generateProofSpecG1(statements, metaStatements, setupParams, context);
};

module.exports.generateProofSpecG2 = (statements, metaStatements, setupParams, context) => {
    requireWasmInitialized();
    return wasm.generateProofSpecG2(statements, metaStatements, setupParams, context);
};

module.exports.generateCompositeProofG1 = (proofSpec, witnesses, nonce) => {
    requireWasmInitialized();
    return wasm.generateCompositeProofG1(proofSpec, witnesses, nonce);
};

module.exports.generateCompositeProofG2 = (proofSpec, witnesses, nonce) => {
    requireWasmInitialized();
    return wasm.generateCompositeProofG2(proofSpec, witnesses, nonce);
};

module.exports.verifyCompositeProofG1 = (proof, proofSpec, nonce) => {
    requireWasmInitialized();
    return wasm.verifyCompositeProofG1(proof, proofSpec, nonce);
};

module.exports.verifyCompositeProofG2 = (proof, proofSpec, nonce) => {
    requireWasmInitialized();
    return wasm.verifyCompositeProofG2(proof, proofSpec, nonce);
};

module.exports.generateCompositeProofG1WithDeconstructedProofSpec = (statements, metaStatements, setupParams, witnesses, context, nonce) => {
    requireWasmInitialized();
    return wasm.generateCompositeProofG1WithDeconstructedProofSpec(statements, metaStatements, setupParams, witnesses, context, nonce);
};

module.exports.verifyCompositeProofG1WithDeconstructedProofSpec = (proof, statements, metaStatements, setupParams, context, nonce) => {
    requireWasmInitialized();
    return wasm.verifyCompositeProofG1WithDeconstructedProofSpec(proof, statements, metaStatements, setupParams, context, nonce);
};

module.exports.saverGetCiphertextFromProof = (proof, statementIndex) => {
    requireWasmInitialized();
    return wasm.saverGetCiphertextFromProof(proof, statementIndex);
};