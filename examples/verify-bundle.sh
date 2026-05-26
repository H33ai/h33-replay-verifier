#!/usr/bin/env bash
# Verify the canonical PASS fixture and pretty-print the report.
#
# Expected output: exit 0, JSON report with "passed": true, 10 checks all PASS.
#
# Run from the repo root:
#   ./examples/verify-bundle.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${ROOT}/target/release/h33-replay-verify"

if [[ ! -x "$BIN" ]]; then
  echo "Building release binary..."
  (cd "$ROOT" && cargo build --release --bin h33-replay-verify)
fi

"$BIN" "${ROOT}/fixtures/real-case-bundle-v0.1.json"
