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
  generateSignatureParamsG1,
  generateBBSPublicKeyG2,
  generateBBSSigningKey,
  bbsSignG1,
  bbsVerifyG1,
  initializeWasm,
  generateRandomFieldElement,
  bbsInitializeProofOfKnowledgeOfSignature,
  bbsChallengeContributionFromProtocol,
  generateChallengeFromBytes,
  bbsGenProofOfKnowledgeOfSignature,
  bbsChallengeContributionFromProof,
  bbsVerifyProofOfKnowledgeOfSignature
} from "../../lib";

const stringToBytes = (str) => Uint8Array.from(Buffer.from(str, "utf-8"));

const main = async () => {
  await initializeWasm();
  const messageCount = 2;
  // Generate params
  const sigParams = generateSignatureParamsG1(messageCount);
  // Generate a new key pair
  const sk = generateBBSSigningKey();
  const pk = generateBBSPublicKeyG2(sk, sigParams);

  console.log("Key pair generated");
  console.log(
    `Public key base64 = ${Buffer.from(pk).toString("base64")}`
  );

  //Set of messages we wish to sign
  const messages = [stringToBytes("message1"), stringToBytes("message2")];

  console.log("Signing a message set of " + messages);

  // Create the signature
  const signature = bbsSignG1(messages, sk, sigParams, true);

  console.log(
    `Output signature base64 = ${Buffer.from(signature).toString("base64")}`
  );

  // Verify the signature
  const isVerified = bbsVerifyG1(messages, signature, pk, sigParams, true);

  const isVerifiedString = JSON.stringify(isVerified);
  console.log(`Signature verified ? ${isVerifiedString}`);

  // Derive a proof from the signature revealing the first message
  const revealed = new Set();
  const revealedMsgs = new Map();

  revealed.add(0);
  revealedMsgs.set(0, messages[0]);

  const protocol = bbsInitializeProofOfKnowledgeOfSignature(signature, sigParams, messages, new Map(), revealed, true);
  const pBytes = bbsChallengeContributionFromProtocol(protocol, revealedMsgs, sigParams, true);
  const proverChallenge = generateChallengeFromBytes(pBytes);
  const proof = bbsGenProofOfKnowledgeOfSignature(protocol, proverChallenge);

  console.log(`Output proof base64 = ${Buffer.from(proof).toString("base64")}`);

  // Verify the created proof
  const vBytes = bbsChallengeContributionFromProof(proof, revealedMsgs, sigParams, true);
  const verifierChallenge = generateChallengeFromBytes(vBytes);
  const result = bbsVerifyProofOfKnowledgeOfSignature(proof, revealedMsgs, verifierChallenge, pk, sigParams, true);

  const isProofVerifiedString = JSON.stringify(result);
  console.log(`Proof verified ? ${isProofVerifiedString}`);
};

main();
