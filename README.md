# h33-replay-verifier

**Replay the decision. Verify the outcome. Independently.**

```
$ h33-replay-verify case-bundle.json
{
  "bundle_version": "0.1",
  "passed": true,
  "checks": [
    { "check": "schema_parse",           "passed": true, "examined": 1 },
    { "check": "timeline_ordering",      "passed": true, "examined": 3 },
    { "check": "receipt_commitments",    "passed": true, "examined": 2 },
    { "check": "frame_refs_resolve",     "passed": true, "examined": 1 },
    { "check": "continuity_consistency", "passed": true, "examined": 1 },
    { "check": "no_orphans",             "passed": true, "examined": 5 },
    { "check": "hash_algorithms_known",  "passed": true, "examined": 1 },
    { "check": "same_scope_isolation",   "passed": true, "examined": 5 },
    { "check": "substrate_bindings",     "passed": true, "examined": 0 },
    { "check": "merkle_roots",           "passed": true, "examined": 0 }
  ],
  ...
}
```

## What it does

Given a SCIF replay bundle — a JSON document describing one case's full operational lineage (agents, sessions, actions, proofs, frames, substrate bindings, continuity roots) — `h33-replay-verify` runs **10 deterministic checks** and emits a PASS/FAIL verdict plus a per-check breakdown.

With `--sign` it wraps the verdict in an **ML-DSA-65 (FIPS 204) signed transcript** bound to a persistent verifier identity. Any third party — a regulator, an auditor, an opposing counterparty — can re-verify that transcript offline with any conformant ML-DSA-65 implementation. The signed bytes travel embedded inside the envelope, so external verifiers do not need a canonical-JSON library.

> **Relationship to [`h33-verify`](https://github.com/H33ai/h33-verifier):** `h33-verify` validates individual 74-byte H33 substrate receipts (the atom). `h33-replay-verify` validates full case-level bundles (the story). One verifies the atom; one verifies the story. Use both for full coverage.

No network. No daemon. No config. No H33 dependency. Just SHA3, ML-DSA-65, and the [published specs](./spec/).

## Why it exists

Replay bundles only matter if anyone — your auditor, your insurer, your regulator, a competing implementation, an AI agent acting on your behalf — can verify them without trusting H33's infrastructure. This binary is that verifier.

It is intentionally minimal:

- One binary, one library, one WASM build.
- Pure Rust, no external services, no environment dependencies.
- The CLI is the source of truth. The browser playground compiles the same Rust core to WebAssembly; the in-page ML-DSA-65 signature check runs in pure JS against the FIPS 204 standard.

## Try it in the browser

**[h33.ai/verify-the-story/playground/](https://h33.ai/verify-the-story/playground/)** — drag a bundle or signed report, see the verdict locally, no install.

The playground is also published in this repo at [`playground/`](./playground/) and on GitHub Pages.

![playground screenshot placeholder — drop a bundle, see PASS/FAIL, see signed transcript verification](./playground/screenshot.png)

> *Screenshot pending — see [#1](https://github.com/H33ai/h33-replay-verifier/issues/1).*

## Install

### From source

```bash
git clone https://github.com/H33ai/h33-replay-verifier
cd h33-replay-verifier
cargo install --path crates/h33-replay-verify-cli
h33-replay-verify --help
```

### Pre-built binaries

GitHub Releases ship signed binaries for darwin-arm64, darwin-x86_64, linux-x86_64, and windows-x86_64. See [Releases](https://github.com/H33ai/h33-replay-verifier/releases).

```bash
# Example (macOS Apple Silicon):
curl -L -o h33-replay-verify https://github.com/H33ai/h33-replay-verifier/releases/download/v0.3.0/h33-replay-verify-v0.3.0-darwin-arm64
chmod +x h33-replay-verify
./h33-replay-verify --help
```

## Usage

### Plain verify

```bash
h33-replay-verify bundle.json
h33-replay-verify bundle.json --payloads ./sealed-blobs/
h33-replay-verify bundle.json --strict
```

Exit codes:

- `0` — PASS, every check succeeded (or every non-skipped check in non-strict mode).
- `1` — FAIL, at least one check failed.
- `2` — ERROR (file unreadable, JSON parse failure, invalid arg).

### Sign + verify in one step

```bash
h33-replay-verify bundle.json --sign > signed-report.json
```

First run auto-creates an ML-DSA-65 identity in `~/.h33-replay-verify/keys/` (override with `--key-dir <dir>` or `$H33_REPLAY_VERIFY_KEY_DIR`).

### Verify someone else's signed transcript

```bash
h33-replay-verify --verify-transcript signed-report.json

# Or, cross-check the bundle hash too:
h33-replay-verify bundle.json --verify-transcript signed-report.json
```

## Specs

- **Wire format** — [`spec/h33-replay-bundle-v0.1.md`](./spec/h33-replay-bundle-v0.1.md)
- **Signed transcript envelope** — [`spec/h33-signed-verify-report-v0.1.md`](./spec/h33-signed-verify-report-v0.1.md)

Any conformant verifier in any language, fed the canonical fixture at [`fixtures/real-case-bundle-v0.1.json`](./fixtures/real-case-bundle-v0.1.json), must emit PASS.

## What PASS proves (and does not prove)

See [`THREAT_MODEL.md`](./THREAT_MODEL.md). The short version:

**PASS proves:** schema conformance, timeline ordering, chain hash recompute, frame ref resolution, continuity consistency, no orphans, recognized verifier algorithms, same-scope tenant/case isolation, substrate binding recompute.

**PASS does NOT prove:** completeness (the bundle may be a subset), receipt cryptographic validity (use [`h33-verify`](https://github.com/H33ai/h33-verifier)), on-chain anchor presence, time-of-attestation against a trusted clock, verifier-identity provenance (established out of band).

## Boundary

Verification artifacts are public and independently reproducible. Production computation infrastructure remains proprietary. See [`BOUNDARY.md`](./BOUNDARY.md) for the precise scope split.

## Reporting security issues

See [`SECURITY.md`](./SECURITY.md). Prefer GitHub Security Advisories for private disclosure.

## License

Apache-2.0. See [`LICENSE`](./LICENSE).
