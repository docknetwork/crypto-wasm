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

import {generateSignatureParamsG1, generateBBSPublicKeyG2, generateBBSSigningKey, bbsSignG1, bbsVerifyG1, bbsInitializeProofOfKnowledgeOfSignature, bbsGenProofOfKnowledgeOfSignature, bbsVerifyProofOfKnowledgeOfSignature, bbsChallengeContributionFromProtocol, bbsChallengeContributionFromProof, generateChallengeFromBytes, initializeWasm} from "../../../lib";

const stringToBytes = (str: string) => Uint8Array.from(Buffer.from(str, "utf-8"));

const main = async () => {
  await initializeWasm();
  const messages = [
    Uint8Array.from(Buffer.from("message1", "utf8")),
    Uint8Array.from(Buffer.from("message2", "utf8")),
    Uint8Array.from(Buffer.from("message3", "utf8")),
  ];

  const label = stringToBytes("test");
  const messageCount = messages.length;
  // Generate params
  const sigParams = generateSignatureParamsG1(messageCount, label);
  console.log('params is', sigParams);
  // Generate a new key pair
  const sk = generateBBSSigningKey();
  const pk = generateBBSPublicKeyG2(sk, sigParams);

  console.log("Key pair generated");
  console.log(
    `Public key base64 = ${Buffer.from(pk).toString("base64")}`
  );

  console.log("Signing a message set of " + messages);

  //Create the signature
  const signature = bbsSignG1(messages, sk, sigParams, true);

  console.log(
    `Output signature base64 = ${Buffer.from(signature).toString("base64")}`
  );

  //Verify the signature
  const isVerified = bbsVerifyG1(messages, signature, pk, sigParams, true);

  const isVerifiedString = JSON.stringify(isVerified);
  console.log(`Signature verified ? ${isVerifiedString}`);

  // Derive a proof from the signature revealing the first message
  const revealed = new Set<number>();
  revealed.add(0);
  const revealedMsgs = new Map();
  revealedMsgs.set(0, messages[0]);
  const unrevealedMsgs = new Map();
  unrevealedMsgs.set(1, messages[1]);
  unrevealedMsgs.set(2, messages[2]);

  const protocol = bbsInitializeProofOfKnowledgeOfSignature(
      signature,
      sigParams,
      messages,
    new Map(),
      revealed,
      true
  );

  const challengeProver = generateChallengeFromBytes(bbsChallengeContributionFromProtocol(protocol, revealedMsgs, sigParams, true));
  const proof = bbsGenProofOfKnowledgeOfSignature(protocol, challengeProver);

  console.log(`Output proof base64 = ${Buffer.from(proof).toString("base64")}`);

  // Verify the created proof
  const challengeVerifier = generateChallengeFromBytes(bbsChallengeContributionFromProof(proof, revealedMsgs, sigParams, true));
  const isProofVerified = bbsVerifyProofOfKnowledgeOfSignature(
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
