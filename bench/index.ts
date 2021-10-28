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

/* eslint-disable @typescript-eslint/camelcase */
import { benchmark, report } from "@stablelib/benchmark";
import {
  generateSignatureParamsG1,
  generateBBSKeyPairG2,
  bbsSignG1,
  bbsVerifyG1,
  initializeWasm,
  bbsInitializeProofOfKnowledgeOfSignature,
  bbsChallengeContributionFromProtocol,
  generateChallengeFromBytes,
  bbsGenProofOfKnowledgeOfSignature,
  bbsChallengeContributionFromProof,
  bbsVerifyProofOfKnowledgeOfSignature
} from "../lib";
import {generateMessages} from "./helper";


// main benchmark routine
const runBbsBenchmark = async (
  numberOfMessages: number,
  messageSizeInBytes: number,
  numberRevealed: number
): Promise<void> => {
  await initializeWasm();

  // Generate params
  report(
      `BBB+ Params generation for ${numberOfMessages} messages`,
      benchmark(() => generateSignatureParamsG1(numberOfMessages))
  );
  const sigParams = generateSignatureParamsG1(numberOfMessages);

  // Generate a new key pair
  report(
      "BBB+ Key Generation",
      benchmark(() => generateBBSKeyPairG2(sigParams))
  );
  const keypair = generateBBSKeyPairG2(sigParams);
  const sk = keypair.secret_key;
  const pk = keypair.public_key;

  const messages = generateMessages(numberOfMessages, messageSizeInBytes);

  report(
      `BBS Sign ${numberOfMessages}, ${messageSizeInBytes} byte message(s)`,
      benchmark(() => bbsSignG1(messages, sk, sigParams, true))
  );
  const signature = bbsSignG1(messages, sk, sigParams, true);

  report(
      `BBS Verify ${numberOfMessages}, ${messageSizeInBytes} byte message(s)`,
      benchmark(() => bbsVerifyG1(messages, signature, pk, sigParams, true))
  );
  const isVerified = bbsVerifyG1(messages, signature, pk, sigParams, true);

  const revealed: Set<number> = new Set([...Array(numberRevealed).keys()]);
  const revealedMsgs = new Map();
  revealed.forEach((i) => {
    revealedMsgs.set(i, messages[i]);
  })

  function createProof() {
    const protocol = bbsInitializeProofOfKnowledgeOfSignature(signature, sigParams, messages, new Map(), revealed, true);
    const pBytes = bbsChallengeContributionFromProtocol(protocol, revealedMsgs, sigParams, true);
    const proverChallenge = generateChallengeFromBytes(pBytes);
    return bbsGenProofOfKnowledgeOfSignature(protocol, proverChallenge);
  }

  report(
      `BBS Create Proof ${numberOfMessages}, ${messageSizeInBytes} byte message(s), revealing ${numberRevealed} message(s).`,
      benchmark(() => createProof())
  );
  const proof = createProof();


  function verifyProof() {
    const vBytes = bbsChallengeContributionFromProof(proof, revealedMsgs, sigParams, true);
    const verifierChallenge = generateChallengeFromBytes(vBytes);
    bbsVerifyProofOfKnowledgeOfSignature(proof, revealedMsgs, verifierChallenge, pk, sigParams, true);
  }

  report(
      `BBS Verify Proof ${numberOfMessages}, ${messageSizeInBytes} byte message(s), revealing ${numberRevealed} message(s).`,
      benchmark(() => verifyProof())
  );
};

// ------------------------------ Sign/Verify/CreateProof/VerifyProof 1, 100 byte message ------------------------------
runBbsBenchmark(1, 100, 1);
// ---------------------------------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify/CreateProof/VerifyProof 1, 1000 byte message ------------------------------
runBbsBenchmark(1, 1000, 1);
// ----------------------------------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify/CreateProof/VerifyProof 10, 100 byte messages ------------------------------
runBbsBenchmark(10, 100, 1);
// -----------------------------------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify/CreateProof/VerifyProof 10, 1000 byte messages ------------------------------
runBbsBenchmark(10, 1000, 1);
// ------------------------------------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify/CreateProof/VerifyProof 100, 100 byte messages ------------------------------
runBbsBenchmark(100, 100, 1);
// -------------------------------------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify/CreateProof/VerifyProof 100, 1000 byte messages ------------------------------
runBbsBenchmark(100, 1000, 1);
// -------------------------------------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify/CreateProof/VerifyProof 100, 100 byte messages ------------------------------
runBbsBenchmark(100, 100, 50);
// -------------------------------------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify/CreateProof/VerifyProof 100, 1000 byte messages ------------------------------
runBbsBenchmark(100, 1000, 60);
// -------------------------------------------------------------------------------------------------------------------------
