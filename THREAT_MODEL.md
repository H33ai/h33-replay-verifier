# Threat Model

This document states what `h33-replay-verify` is designed to protect against, what it does not protect against, and how a reviewer should reason about a PASS verdict.

It is intentionally readable by both humans and AI agents. If you're trying to decide whether to trust a verdict this tool emits, this is the document to read first.

## Scope

`h33-replay-verify` consumes one of two artifacts and emits a verdict:

1. A **replay bundle** — a JSON document exported by `api.h33.ai` containing a case's full operational lineage (agents, sessions, actions, proofs, frames, substrate bindings, continuity roots). The verifier runs 10 deterministic checks and emits PASS/FAIL. Spec: [`spec/h33-replay-bundle-v0.1.md`](./spec/h33-replay-bundle-v0.1.md).
2. A **signed verification report** — a JSON envelope wrapping a previously-produced VerifyReport in an ML-DSA-65 detached signature bound to a persistent verifier identity. The verifier checks the signature and emits SIGNED-PASS / SIGNED-FAIL. Spec: [`spec/h33-signed-verify-report-v0.1.md`](./spec/h33-signed-verify-report-v0.1.md).

Both flows run **entirely offline**. No network call. No daemon. No H33 dependency.

## What PASS proves

### Replay bundle PASS proves all of the following:

1. **Schema conformance** — the bundle decodes as a valid v0.1 envelope and every field is well-formed.
2. **Schema-hash binding** — `export_metadata.schema_hash` matches the deterministic schema identifier this verifier knows about. Silent schema drift between exporter and verifier is impossible.
3. **Timeline ordering** — every action timestamp is monotonic, and per-session `sequence_in_session` strictly increases.
4. **Receipt commitments** — every action's `this_action_hash` recomputes from `SHA3-256(prior_action_hash || receipt)`, walking each session's chain forward.
5. **Frame integrity** — every frame's claimed `action_ids` and `proof_ids` actually resolve to timeline entries.
6. **Continuity consistency** — the case's `continuity_hash_hex` matches the timeline's, so no orphaned case-level state.
7. **No orphans** — every `event_id`, `frame_id`, `binding_id` is unique; every action's `agent_id_hex` resolves to a known agent.
8. **Verifier-artifact recognition** — every `verifier_artifact_refs` entry uses a known prefix (`h33-pq-verify@`, `h33-zk-verify@`, `h33-replay-verify@`, `h33-substrate-verify@`). Unknown prefixes are FAIL in `--strict`.
9. **Same-scope isolation** — every substrate binding's `tenant_id` matches the bundle, and its `case_id` (if present) matches the bundle. Cross-tenant or cross-case rows are impossible.
10. **Substrate binding recomputation** — every binding's `verification_hash` recomputes deterministically from the canonical-serialized binding context per spec §6.1. Bindings cannot be tampered without invalidating this check.

Additionally, when `--payloads <dir>` is supplied:

11. **Sealed payload hashes match** — for every frame or evidence bundle that carries a `*_blob_ref`, the bytes at that reference hash to the stored `*_root_hash_hex`.

### Signed verification report SIGNED-PASS proves:

- The verifier whose ML-DSA-65 public key has fingerprint `verifier_public_key_fingerprint_hex` ran `verifier_version`...
- ...against a bundle whose `SHA3-256` is `bundle_sha3_256_hex`...
- ...at time `signed_at`...
- ...and produced exactly the per-check verdicts inside `signed_payload`.

The signature is FIPS-204 ML-DSA-65. Any conformant verifier (this tool, [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum), liboqs, BoringSSL fork, etc.) produces the same accept/reject decision against the same bytes. The embedded-bytes design means external verifiers do not need a canonical-JSON library — the exact signed bytes travel as base64 inside the envelope.

## What PASS does NOT prove

- **Completeness.** A bundle may be a truthful subset of a case's history — e.g., a date-range export. PASS does not assert "this is every event the case ever had." If completeness matters, your application layer must enforce it.
- **Receipt cryptographic validity.** The 74-byte H33 receipts referenced inside bundle entries are validated by the sibling tool [`h33-verify`](https://github.com/H33ai/h33-verifier). Use both for full coverage. `h33-replay-verify` only checks that the receipt's chain hash recomputes; it does not run the ML-DSA / FALCON / SPHINCS+ signature verification on the underlying substrate.
- **On-chain anchor presence or validity.** If a bundle was anchored to Polygon / Bitcoin / Solana, this tool does not look up the anchor transaction or check that the calldata equals the bundle's commitment. Pair with chain-specific verifiers.
- **Time of attestation against a trusted clock.** Timestamps inside bundles are checked for monotonicity but not for absolute correctness. The `signed_at` field on a signed report is the verifier's local wall-clock, not a notary timestamp.
- **Verifier identity provenance.** SIGNED-PASS confirms *some verifier* with this public-key fingerprint ran the verification. Whether that fingerprint belongs to the verifier you think it does is established out of band (allow-list, registry, attestation). The `playground-demo-key` identity shipped in `fixtures/example-signed-report.json` is for demonstration only — never accept it as a real audit signature.
- **Liveness, replay, or issuer authority.** A bundle can be replayed; a signed report can be re-presented. Time-binding is the consumer's responsibility.

## Trust model

The trust model has two distinct layers, and a reviewer should be explicit about which layer they are relying on:

### Layer 1: bundle verification

You trust the **algorithm in this repository**. You do not trust H33's infrastructure, distribution channel, or continued existence. To audit:

1. Read [`crates/h33-replay-verify-core/src/`](./crates/h33-replay-verify-core/src/) (5 files, ~700 lines total).
2. Re-run the canonical fixture: `cargo run -- fixtures/real-case-bundle-v0.1.json`. Expect PASS.
3. Cross-check the spec: [`spec/h33-replay-bundle-v0.1.md`](./spec/h33-replay-bundle-v0.1.md).

### Layer 2: signed-transcript verification

You trust the **algorithm in this repository PLUS the public key of the verifier instance that produced the transcript**. The public key travels inside the envelope; its fingerprint is `SHA3-256(public_key_bytes)`. To audit:

1. Confirm the embedded `verifier_public_key_fingerprint_hex` matches an allow-list you control (or that you accept the fingerprint as a one-time use).
2. The signature verification itself is FIPS 204 ML-DSA-65; you can independently re-verify with any conformant ML-DSA-65 implementation.

### What you never have to trust

- H33's infrastructure being online.
- H33 as a company being solvent.
- The distribution channel (this repo, GitHub Pages, h33.ai). The verifier is reproducible from source.
- Network access of any kind during verification.

## Threats the verifier defends against

- **Bundle tampering** — any byte-level edit to a verified bundle that affects schema, timeline ordering, chain hashes, frame refs, continuity, scope isolation, or binding hashes will FAIL one of the 10 checks. Demonstrated by `crates/h33-replay-verify-cli/tests/replay_verify_integration.rs` (`fail_bundle_tampered_chain_exits_1`, `fail_bundle_cross_tenant_exits_1`).
- **Schema drift** — if the bundle's `schema_hash` doesn't match the verifier's expected value, FAIL with a clear error. Demonstrated by check #1.
- **Verifier-version mismatch** — if the bundle requires a newer verifier than this one, FAIL with an "upgrade required" message rather than producing a misleading verdict.
- **Cross-tenant or cross-case row injection** — structurally impossible to PASS check #9. Even one cross-tenant binding fails the run.
- **Signed-transcript tamper** — modifying the `report` field of a signed envelope without re-signing does NOT change the signed-payload truth. Demonstrated by `signed_report_integration.rs::flipping_envelope_passed_field_does_not_fool_external_verifier`.
- **Signature replay onto a different key** — the public-key fingerprint is bound *inside* the signed payload, so a signature cannot be re-attached to a different identity.
- **Signature forgery without the private key** — bounded by FIPS 204 ML-DSA-65's security argument (lattice problems hard under quantum adversaries).

## Threats the verifier does NOT defend against

- **Operator-side identity-key compromise** — if someone steals your `identity.secret.b64`, they can sign anything as you. This is an operator-side incident, mitigated by the standard practices for any signing key.
- **Choice of verifier identity in your allow-list** — accepting an attacker's verifier-identity fingerprint into your allow-list and then trusting transcripts signed by that fingerprint. Out of scope for the tool; in scope for the relying party's policy.
- **A bundle that was never produced by H33 but that nonetheless conforms to the spec** — the verifier checks bytes against the spec; it does not check provenance. If you need provenance, pair with [`h33-verify`](https://github.com/H33ai/h33-verifier) (which validates the 74-byte receipts inside).
- **A bundle that was produced by H33 but describes events that did not actually occur in the real world** — the verifier proves internal consistency and PQ-attested hash chains; it does not corroborate against the external world. Out-of-band corroboration remains the relying party's job.
- **Side-channel attacks on the running verifier process** — timing, cache, power. The verifier is designed for offline correctness, not against side-channel adversaries with local execution access.

## Reproducibility

Every artifact in this repository is reproducible from source:

```bash
cd crates/h33-replay-verify-cli
cargo build --release
./target/release/h33-replay-verify ../../fixtures/real-case-bundle-v0.1.json
# Expect: exit 0, JSON report with "passed": true, 10 checks PASS
```

For the WASM playground:

```bash
cd crates/h33-replay-verify-wasm
wasm-pack build --target web --release
# Output: pkg/h33_replay_verify_wasm{.js, _bg.wasm, .d.ts}
# Identical (modulo metadata) to playground/wasm/.
```

Reproducible builds and signed releases are tracked under the project's release plan.

## Last reviewed

2026-05-26 — alongside v0.3.0 publication.
