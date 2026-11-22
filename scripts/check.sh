#!/usr/bin/env bash
# Full gate. Runs anywhere: uses cargo-slot when it is on PATH, plain cargo otherwise.
set -euo pipefail
cd "$(dirname "$0")/.."

if command -v cargo-slot >/dev/null 2>&1; then
    run() { cargo-slot cargo "$@"; }
else
    run() { cargo "$@"; }
fi

run fmt --all -- --check
run clippy --workspace --all-targets -- -D warnings
run clippy --workspace --all-targets --all-features -- -D warnings
run test --workspace
run test --workspace --all-features
run check --no-default-features

# The signer crate names no service: the words are built from parts so this file does not contain them.
w1="gr""org"; w2="multi""matrix"; w3="access""-control"
if grep -rniE "$w1|$w2|$w3" message-signer/src message-signer/Cargo.toml; then
    echo "FAIL: a service name or access-control appears in message-signer" >&2
    exit 1
fi

echo "check: ok"
