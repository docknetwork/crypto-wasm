const {
    wasm, requireWasmInitialized
} = require('./init_wasm');

module.exports.generatePoKBBSSignatureProverStatement = (params, revealedMessages, encodeMessages) => {
    requireWasmInitialized();
    return wasm.generatePoKBBSSignatureProverStatement(params, revealedMessages, encodeMessages);
};

module.exports.generatePoKBBSSignatureVerifierStatement = (params, publicKey, revealedMessages, encodeMessages) => {
    requireWasmInitialized();
    return wasm.generatePoKBBSSignatureVerifierStatement(params, publicKey, revealedMessages, encodeMessages);
};

module.exports.generatePoKBBSPlusSignatureProverStatement = (params, revealedMessages, encodeMessages) => {
    requireWasmInitialized();
    return wasm.generatePoKBBSPlusSignatureProverStatement(params, revealedMessages, encodeMessages);
};

module.exports.generatePoKBBSPlusSignatureVerifierStatement = (params, publicKey, revealedMessages, encodeMessages) => {
    requireWasmInitialized();
    return wasm.generatePoKBBSPlusSignatureVerifierStatement(params, publicKey, revealedMessages, encodeMessages);
};

module.exports.generatePoKBBSSignatureProverStatementFromParamRefs = (params, revealedMessages, encodeMessages) => {
    requireWasmInitialized();
    return wasm.generatePoKBBSSignatureProverStatementFromParamRefs(params, revealedMessages, encodeMessages);
};

module.exports.generatePoKBBSSignatureVerifierStatementFromParamRefs = (params, publicKey, revealedMessages, encodeMessages) => {
    requireWasmInitialized();
    return wasm.generatePoKBBSSignatureVerifierStatementFromParamRefs(params, publicKey, revealedMessages, encodeMessages);
};

module.exports.generatePoKBBSPlusSignatureProverStatementFromParamRefs = (params, revealedMessages, encodeMessages) => {
    requireWasmInitialized();
    return wasm.generatePoKBBSPlusSignatureProverStatementFromParamRefs(params, revealedMessages, encodeMessages);
};

module.exports.generatePoKBBSPlusSignatureVerifierStatementFromParamRefs = (params, publicKey, revealedMessages, encodeMessages) => {
    requireWasmInitialized();
    return wasm.generatePoKBBSPlusSignatureVerifierStatementFromParamRefs(params, publicKey, revealedMessages, encodeMessages);
};

module.exports.generatePoKPSSignatureStatement = (params, publicKey, revealedMessages) => {
    requireWasmInitialized();
    return wasm.generatePoKPSSignatureStatement(params, publicKey, revealedMessages);
};

module.exports.generatePoKPSSignatureStatementFromParamRefs = (params, publicKey, revealedMessages) => {
    requireWasmInitialized();
    return wasm.generatePoKPSSignatureStatementFromParamRefs(params, publicKey, revealedMessages);
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

module.exports.generateR1CSCircomProverStatement = (curveName, numPublic, numPrivate, constraints, wasmBytes, snarkPk, uncompressedPublicParams) => {
    requireWasmInitialized();
    return wasm.generateR1CSCircomProverStatement(curveName, numPublic, numPrivate, constraints, wasmBytes, snarkPk, uncompressedPublicParams);
};

module.exports.generateR1CSCircomProverStatementFromParamRefs = (r1cs, wasmBytes, snarkPk) => {
    requireWasmInitialized();
    return wasm.generateR1CSCircomProverStatementFromParamRefs(r1cs, wasmBytes, snarkPk);
};

module.exports.generateR1CSCircomVerifierStatement = (publicInputs, snarkVk, uncompressedPublicParams) => {
    requireWasmInitialized();
    return wasm.generateR1CSCircomVerifierStatement(publicInputs, snarkVk, uncompressedPublicParams);
};

module.exports.generateR1CSCircomVerifierStatementFromParamRefs = (publicInputs, snarkVk) => {
    requireWasmInitialized();
    return wasm.generateR1CSCircomVerifierStatementFromParamRefs(publicInputs, snarkVk);
};

module.exports.generateBoundCheckBppStatement = (min, max, params, uncompressedPublicParams) => {
    requireWasmInitialized();
    return wasm.generateBoundCheckBppStatement(min, max, params, uncompressedPublicParams);
};

module.exports.generateBoundCheckBppStatementFromParamRefs = (min, max, params) => {
    requireWasmInitialized();
    return wasm.generateBoundCheckBppStatementFromParamRefs(min, max, params);
};

module.exports.generateBoundCheckSmcStatement = (min, max, params, uncompressedParams) => {
    requireWasmInitialized();
    return wasm.generateBoundCheckSmcStatement(min, max, params, uncompressedParams);
};

module.exports.generateBoundCheckSmcStatementFromParamRefs = (min, max, params) => {
    requireWasmInitialized();
    return wasm.generateBoundCheckSmcStatementFromParamRefs(min, max, params);
};

module.exports.generateBoundCheckSmcWithKVProverStatement = (min, max, params, uncompressedParams) => {
    requireWasmInitialized();
    return wasm.generateBoundCheckSmcWithKVProverStatement(min, max, params, uncompressedParams);
};

module.exports.generateBoundCheckSmcWithKVProverStatementFromParamRefs = (min, max, params) => {
    requireWasmInitialized();
    return wasm.generateBoundCheckSmcWithKVProverStatementFromParamRefs(min, max, params);
};

module.exports.generateBoundCheckSmcWithKVVerifierStatement = (min, max, params, uncompressedParams) => {
    requireWasmInitialized();
    return wasm.generateBoundCheckSmcWithKVVerifierStatement(min, max, params, uncompressedParams);
};

module.exports.generateBoundCheckSmcWithKVVerifierStatementFromParamRefs = (min, max, params) => {
    requireWasmInitialized();
    return wasm.generateBoundCheckSmcWithKVVerifierStatementFromParamRefs(min, max, params);
};

module.exports.generatePublicInequalityG1Statement = (inequalTo, commKey, uncompressedKey) => {
    requireWasmInitialized();
    return wasm.generatePublicInequalityG1Statement(inequalTo, commKey, uncompressedKey);
};

module.exports.generatePublicInequalityG1StatementFromParamRefs = (inequalTo, commKey) => {
    requireWasmInitialized();
    return wasm.generatePublicInequalityG1StatementFromParamRefs(inequalTo, commKey);
};

module.exports.generateWitnessEqualityMetaStatement = (equalities) => {
    requireWasmInitialized();
    return wasm.generateWitnessEqualityMetaStatement(equalities);
};

module.exports.generatePoKBBSSignatureWitness = (signature, unrevealedMessages, encodeMessages) => {
    requireWasmInitialized();
    return wasm.generatePoKBBSSignatureWitness(signature, unrevealedMessages, encodeMessages);
};

module.exports.generatePoKBBSPlusSignatureWitness = (signature, unrevealedMessages, encodeMessages) => {
    requireWasmInitialized();
    return wasm.generatePoKBBSPlusSignatureWitness(signature, unrevealedMessages, encodeMessages);
};

module.exports.generatePoKPSSignatureWitness = (signature, unrevealedMessages) => {
    requireWasmInitialized();
    return wasm.generatePoKPSSignatureWitness(signature, unrevealedMessages);
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

module.exports.generateR1CSCircomWitness = (inputWires, privates, publics = []) => {
    requireWasmInitialized();
    return wasm.generateR1CSCircomWitness(inputWires, privates, publics);
};

module.exports.generateBoundCheckBppWitness = (message) => {
    requireWasmInitialized();
    return wasm.generateBoundCheckBppWitness(message);
};

module.exports.generateBoundCheckSmcWitness = (message) => {
    requireWasmInitialized();
    return wasm.generateBoundCheckSmcWitness(message);
};

module.exports.generateBoundCheckSmcWithKVWitness = (message) => {
    requireWasmInitialized();
    return wasm.generateBoundCheckSmcWithKVWitness(message);
};

module.exports.generatePublicInequalityWitness = (message) => {
    requireWasmInitialized();
    return wasm.generatePublicInequalityWitness(message);
};

module.exports.generateProofSpecG1 = (statements, metaStatements, setupParams, context) => {
    requireWasmInitialized();
    return wasm.generateProofSpecG1(statements, metaStatements, setupParams, context);
};

module.exports.isProofSpecG1Valid = (proofSpec) => {
    requireWasmInitialized();
    return wasm.isProofSpecG1Valid(proofSpec);
};

module.exports.generateCompositeProofG1 = (proofSpec, witnesses, nonce) => {
    requireWasmInitialized();
    return wasm.generateCompositeProofG1(proofSpec, witnesses, nonce);
};

module.exports.verifyCompositeProofG1 = (proof, proofSpec, nonce) => {
    requireWasmInitialized();
    return wasm.verifyCompositeProofG1(proof, proofSpec, nonce);
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

module.exports.saverGetCiphertextsFromProof = (proof, statementIndices) => {
    requireWasmInitialized();
    return wasm.saverGetCiphertextsFromProof(proof, statementIndices);
};

module.exports.generatePoKBDDT16MacStatement = (params, revealedMessages, encodeMessages) => {
    requireWasmInitialized();
    return wasm.generatePoKBDDT16MacStatement(params, revealedMessages, encodeMessages);
};

module.exports.generatePoKBDDT16MacStatementFromParamRefs = (params, revealedMessages, encodeMessages) => {
    requireWasmInitialized();
    return wasm.generatePoKBDDT16MacStatementFromParamRefs(params, revealedMessages, encodeMessages);
};

module.exports.generatePoKBDDT16MacFullVerifierStatement = (params, secretKey, revealedMessages, encodeMessages) => {
    requireWasmInitialized();
    return wasm.generatePoKBDDT16MacFullVerifierStatement(params, secretKey, revealedMessages, encodeMessages);
};

module.exports.generatePoKBDDT16MacFullVerifierStatementFromParamRefs = (params, secretKey, revealedMessages, encodeMessages) => {
    requireWasmInitialized();
    return wasm.generatePoKBDDT16MacFullVerifierStatementFromParamRefs(params, secretKey, revealedMessages, encodeMessages);
};

module.exports.generatePoKBDDT16MacWitness = (mac, unrevealedMessages, encodeMessages) => {
    requireWasmInitialized();
    return wasm.generatePoKBDDT16MacWitness(mac, unrevealedMessages, encodeMessages);
};

module.exports.generateAccumulatorKVMembershipStatement = (accumulated) => {
    requireWasmInitialized();
    return wasm.generateAccumulatorKVMembershipStatement(accumulated);
};

module.exports.generateAccumulatorKVFullVerifierMembershipStatement = (secretKey, accumulated) => {
    requireWasmInitialized();
    return wasm.generateAccumulatorKVFullVerifierMembershipStatement(secretKey, accumulated);
};