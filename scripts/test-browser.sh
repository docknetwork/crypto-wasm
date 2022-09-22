#!/usr/bin/env bash

set -e

echo "*** Testing WASM on chrome"
WASM_BINDGEN_TEST_TIMEOUT=360 rustup run stable wasm-pack test --release --headless --chrome