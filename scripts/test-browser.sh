#!/usr/bin/env bash

set -e

echo "*** Testing WASM on chrome"
rustup run stable WASM_BINDGEN_TEST_TIMEOUT=360 wasm-pack test --release --headless --chrome