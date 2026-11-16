#!/usr/bin/env bash
# Full gate. Every cargo call goes through cargo-slot.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -z "${CARGO_TARGET_DIR:-}" ]; then
    . /home/concordium/workshop/gait-worker/targets/message-attestation.env
fi

cargo-slot cargo fmt --all -- --check
cargo-slot cargo clippy --all-targets -- -D warnings
cargo-slot cargo clippy --all-targets --all-features -- -D warnings
cargo-slot cargo test
cargo-slot cargo test --all-features
cargo-slot cargo check --no-default-features

echo "check: ok"
