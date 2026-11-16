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
run clippy --all-targets -- -D warnings
run clippy --all-targets --all-features -- -D warnings
run test
run test --all-features
run check --no-default-features

echo "check: ok"
