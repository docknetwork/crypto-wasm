"use strict";
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

// TODO should be able to remove this duplicate definition syntax by using ESM over index.web.js
// in future

// The functions defined in this package are async as each call has to make sure that WASM code has been loaded
// using `WebAssembly.instantiate` which returns a promise and thus any function may need to wait for the promise to
// resolve. Another possible approach is to have something like polkadot-js's `cryptoWaitReady` which should be called
// before any function is called. This will simplify the Rust code.

const {
  wasm, initializedModule, initialize
} = require('./init_wasm');

module.exports = {
  ...require('./util_wasm'),
  ...require('./bbs_plus_wasm'),
  ...require('./accumulator_wasm'),
  ...require('./proof_system_wasm'),
};
