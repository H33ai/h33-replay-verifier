# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
