#!/usr/bin/env bash
# Round-trip a bundle through sign + verify-transcript.
#
# 1. Generate an ephemeral verifier identity in a tempdir (never reused).
# 2. Sign the canonical PASS fixture.
# 3. Verify the produced signed transcript (with bundle cross-check).
#
# Expected: every step exits 0; final cross-check reports both
# transcript_verified=true AND bundle_cross_check.matches=true.
#
# Run from the repo root:
#   ./examples/sign-and-verify.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${ROOT}/target/release/h33-replay-verify"

if [[ ! -x "$BIN" ]]; then
  (cd "$ROOT" && cargo build --release --bin h33-replay-verify)
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

BUNDLE="${ROOT}/fixtures/real-case-bundle-v0.1.json"
SIGNED="${TMP}/signed.json"
KEY_DIR="${TMP}/keys"

echo "1. Sign the canonical fixture with a fresh ephemeral identity..."
H33_REPLAY_VERIFY_KEY_DIR="$KEY_DIR" "$BIN" "$BUNDLE" --sign > "$SIGNED"
echo "   wrote $SIGNED"
echo

echo "2. Verify the signed transcript (with bundle cross-check)..."
"$BIN" "$BUNDLE" --verify-transcript "$SIGNED"
