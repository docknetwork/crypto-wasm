/*
 * Copyright 2020 - MATTR Limited
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {
  bbsPlusGenerateSignatureParamsG1, bbsPlusGeneratePublicKeyG2, bbsPlusGenerateSigningKey, bbsPlusSignG1, bbsPlusVerifyG1,
  bbsPlusInitializeProofOfKnowledgeOfSignature, bbsPlusGenProofOfKnowledgeOfSignature, bbsPlusVerifyProofOfKnowledgeOfSignature,
  bbsPlusChallengeContributionFromProtocol, bbsPlusChallengeContributionFromProof, generateChallengeFromBytes,
  initializeWasm
} from "../../../lib";

const stringToBytes = (str: string) => Uint8Array.from(Buffer.from(str, "utf-8"));

const main = async () => {
  // Load the WASM module
  await initializeWasm();

  // Generate some random messages
  const messages = [
    Uint8Array.from(Buffer.from("message1", "utf8")),
    Uint8Array.from(Buffer.from("message2", "utf8")),
    Uint8Array.from(Buffer.from("message3", "utf8")),
  ];

  const label = stringToBytes("test-params");
  const messageCount = messages.length;

  // Generate params deterministically using a label
  const sigParams = bbsPlusGenerateSignatureParamsG1(messageCount, label);
  console.log('params is', sigParams);

  // Generate a new key pair
  const sk = bbsPlusGenerateSigningKey();
  const pk = bbsPlusGeneratePublicKeyG2(sk, sigParams);
  console.log("Key pair generated");
  console.log(
    `Public key base64 = ${Buffer.from(pk).toString("base64")}`
  );

  console.log("Signing a message set of " + messages);

  // Create the signature
  const signature = bbsPlusSignG1(messages, sk, sigParams, true);
  console.log(
    `Output signature base64 = ${Buffer.from(signature).toString("base64")}`
  );

  // Verify the signature
  const isVerified = bbsPlusVerifyG1(messages, signature, pk, sigParams, true);
  const isVerifiedString = JSON.stringify(isVerified);
  console.log(`Signature verified ? ${isVerifiedString}`);

  // Derive a proof from the signature revealing the first message
  const revealed = new Set<number>();
  revealed.add(0);
  const revealedMsgs = new Map();
  revealedMsgs.set(0, messages[0]);

  const protocol = bbsPlusInitializeProofOfKnowledgeOfSignature(
      signature,
      sigParams,
      messages,
    new Map(),
      revealed,
      true
  );

  const challengeProver = generateChallengeFromBytes(bbsPlusChallengeContributionFromProtocol(protocol, revealedMsgs, sigParams, true));
  const proof = bbsPlusGenProofOfKnowledgeOfSignature(protocol, challengeProver);

  console.log(`Output proof base64 = ${Buffer.from(proof).toString("base64")}`);

  // Verify the created proof
  const challengeVerifier = generateChallengeFromBytes(bbsPlusChallengeContributionFromProof(proof, revealedMsgs, sigParams, true));
  const isProofVerified = bbsPlusVerifyProofOfKnowledgeOfSignature(
    proof,
      revealedMsgs,
    challengeVerifier,
    pk,
    sigParams,
    true,
  );
  const isProofVerifiedString = JSON.stringify(isProofVerified);
  console.log(`Proof verified ? ${isProofVerifiedString}`);
};

main();
