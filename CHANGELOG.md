# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] — 2026-05-27 — governance graph + authority temporal validity

Adds bundle wire format **v0.2** and verifier Check #11 `authority_temporal_validity`. v0.1 bundles continue to verify unchanged; v0.2 bundles are rejected by pre-v0.4 verifiers (intentional — schema-hash mismatch).

### Added

- **Bundle v0.2 wire format** — see [`spec/h33-replay-bundle-v0.2.md`](./spec/h33-replay-bundle-v0.2.md).
  - `governance_events: Vec<GovernanceEvent>` — delegation + revocation events, hash-chained per `(subject, authority_scope)` tuple.
  - `governance_chain_tips: Vec<GovernanceChainTip>` — exporter-issued attestation of each chain's terminal hash + event count. Primary defense against trailing-event omission.
  - `TimelineEntry.requires_authority_scope: Option<String>` — actions declare which authority scope they relied on.
- **Check #11 — `authority_temporal_validity`** — four-phase check that confirms (a) state-after consistency, (b) per-chain hash recompute, (c) chain-tip integrity, (d) state-machine temporal validity per action.
- **`CheckResult.failure_mode: Option<String>`** — categorizes failures for UI/replay rendering. Well-known values for Check #11: `"temporal_violation"`, `"chain_integrity_violation"`.
- **Canonical demo fixtures** — `fixtures/tokenize-the-world-{happy,fraud}-bundle-v0.2.json`. Happy bundle PASSes all 11; fraud bundle PASSes 1–10 and FAILs #11 with `temporal_violation`.
- **Four new integration tests** covering happy + three adversarial variants (temporal, omission, chain tamper). Each asserts exit code AND `failure_mode` tag.

### Changed

- **`SUPPORTED_VERSIONS`** is now `["0.1", "0.2"]`. v0.1 bundles continue to verify under the v0.4 verifier; Check #11 is N/A → PASS for them.
- **`VERIFIER_VERSION`** bumped to `"0.4.0"`. v0.2 bundles require `verifier_min_version >= "0.4.0"`.
- **`SCHEMA_IDENTIFIER`** is now version-aware via `schema_hash_for_version(version)`. Legacy `schema_hash()` returns the v0.1 hash for backward compatibility.

### Notes

- v0.1 spec was superseded by v0.2 but not edited. Banner added to top of `spec/h33-replay-bundle-v0.1.md`.
- The fraud-mode split (`temporal_violation` vs `chain_integrity_violation`) is the verifier-side primitive behind the "what did replay catch?" UI in the [`/tokenize/`](https://h33.ai/tokenize/) demo.

### Test posture

- 28/28 tests pass (24 prior + 4 new v0.2).
- WASM build unchanged in surface; rebuilt against the new core.

[0.4.0]: https://github.com/H33ai/h33-replay-verifier/releases/tag/v0.4.0

## [0.3.0] — 2026-05-26 — first public release

This is the initial public extraction of the replay-bundle verifier from the H33 backend, alongside the [companion `h33-verify` v0.3.0](https://github.com/H33ai/h33-verifier) release. It establishes the public/proprietary boundary at the story-verification layer.

### Added

- **`h33-replay-verify-core` crate** — pure-Rust, WASM-friendly 10-check verifier protocol. Bundle, binding, and chain types. Zero infra dependencies.
- **`h33-replay-verify` CLI** — three modes:
  - plain bundle verify (`<bundle.json>` + optional `--payloads`, `--strict`)
  - sign-and-verify (`--sign` + optional `--key-dir`)
  - signed-transcript verify (`--verify-transcript`, with optional bundle cross-check)
- **`h33-replay-verify-wasm` crate** — wasm-bindgen wrapper around the core, ~223 KB optimized binary. Drives the browser playground.
- **Specs** — frozen v0.1 of the replay-bundle wire format and the signed-verification-report envelope.
- **Canonical fixtures** — synthetic-tenant case bundle that any conformant verifier must PASS, plus a signed-transcript example produced by the `playground-demo-key` identity.
- **Browser playground** — drag-and-drop HTML at [`playground/`](./playground/). Same Rust 10-check protocol via WebAssembly; ML-DSA-65 signature verification via [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum) in pure JS. No network call after the page loads.
- **Governance** — [`BOUNDARY.md`](./BOUNDARY.md), [`SECURITY.md`](./SECURITY.md), [`THREAT_MODEL.md`](./THREAT_MODEL.md).

### Test posture

24 tests pass on the workspace:

- 7 core unit tests (chain + binding)
- 5 signed-transcript unit tests
- 7 replay-verify integration tests (including the canonical real-case fixture lock)
- 5 signed-report integration tests (including the trust-flows-through-signed-payload guarantee)

Plus a clean WASM build via `wasm-pack build --target web --release`.

### Boundary

Verification artifacts are public; production computation infrastructure (bundle export pipeline, substrate signing orchestration, STARK provers, FHE engines, replay-frame storage, production keys, infrastructure) remains in private GitLab. See [`BOUNDARY.md`](./BOUNDARY.md) for the precise scope split.

[0.3.0]: https://github.com/H33ai/h33-replay-verifier/releases/tag/v0.3.0
