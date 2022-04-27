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
import {benchmarkBbs} from "./bbs";
import {benchmarkBoundCheckSnark} from "./bound-check-snark";


// ------------------------------ Sign/Verify/CreateProof/VerifyProof 1, 100 byte message ------------------------------
benchmarkBbs(1, 100, 1);
// ---------------------------------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify/CreateProof/VerifyProof 1, 1000 byte message ------------------------------
benchmarkBbs(1, 1000, 1);
// ----------------------------------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify/CreateProof/VerifyProof 10, 100 byte messages ------------------------------
benchmarkBbs(10, 100, 1);
// -----------------------------------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify/CreateProof/VerifyProof 10, 1000 byte messages ------------------------------
benchmarkBbs(10, 1000, 1);
// ------------------------------------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify/CreateProof/VerifyProof 100, 100 byte messages ------------------------------
benchmarkBbs(100, 100, 1);
// -------------------------------------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify/CreateProof/VerifyProof 100, 1000 byte messages ------------------------------
benchmarkBbs(100, 1000, 1);
// -------------------------------------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify/CreateProof/VerifyProof 100, 100 byte messages ------------------------------
benchmarkBbs(100, 100, 50);
// -------------------------------------------------------------------------------------------------------------------------

// ------------------------------ Sign/Verify/CreateProof/VerifyProof 100, 1000 byte messages ------------------------------
benchmarkBbs(100, 1000, 60);
// -------------------------------------------------------------------------------------------------------------------------

benchmarkBoundCheckSnark();
