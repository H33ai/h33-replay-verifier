# Public / Proprietary Boundary

> **Verification artifacts are public and independently reproducible. Production computation infrastructure remains proprietary.**

This document states which side of that boundary each artifact in this repository sits on. It is the sibling of [the `h33-verifier` BOUNDARY.md](https://github.com/H33ai/h33-verifier/blob/main/BOUNDARY.md), which defines the same boundary for the primitive 74-byte receipt verifier. Read both — they describe one consistent boundary, applied to two different surfaces (atom vs story).

The principle is simple:

> Anyone — auditor, regulator, insurer, researcher, competing vendor, AI agent, the public — can validate the bytes H33 produces, without permission, without a sales conversation, and without the company's continued existence. The *operational system that produces those bytes at scale* is the moat.

This is the opposite of the common pattern where verifiers are hidden because the verifier would expose how weak the underlying guarantees are. Here, the verifier is open precisely because the guarantees are strong enough to survive being looked at.

## Public surface (this repository)

Apache-2.0 licensed. Anyone may inspect, copy, audit, fork, mirror, or build derivative tooling without H33 permission.

| Artifact | Where | Purpose |
|---|---|---|
| `h33-replay-verify-core` crate | `crates/h33-replay-verify-core/` | Canonical 10-check protocol + bundle/binding/chain types. Pure Rust, no infra deps. |
| `h33-replay-verify` CLI | `crates/h33-replay-verify-cli/` | Offline bundle verification (every mode), optional ML-DSA-65 signed transcripts. |
| `h33-replay-verify-wasm` crate | `crates/h33-replay-verify-wasm/` | wasm-bindgen wrapper that drives the browser playground. |
| Replay bundle spec v0.1 | [`spec/h33-replay-bundle-v0.1.md`](./spec/h33-replay-bundle-v0.1.md) | Wire format definition. Any conforming verifier in any language must accept inputs that satisfy this spec. |
| Signed verification report spec v0.1 | [`spec/h33-signed-verify-report-v0.1.md`](./spec/h33-signed-verify-report-v0.1.md) | ML-DSA-65 envelope wrapping verifier-produced reports for institutional evidence. |
| Canonical PASS fixture | `fixtures/real-case-bundle-v0.1.json` | Synthetic-tenant case that any verifier must accept as PASS. The fixture stays synthetic forever — never mixed with real operational lineage, even sanitized. |
| Canonical signed-report fixture | `fixtures/example-signed-report.json` | A signed transcript of the canonical bundle produced by the `playground-demo-key` identity (clearly labeled; do not trust for production). |
| Browser playground | `playground/` | HTML + WASM that runs the verifier locally in the browser. No server call. Same Rust core as the CLI. |
| Replay bundles produced by `api.h33.ai` | the wire | The export bytes are by-design publicly verifiable; any holder of a bundle can run this verifier offline. |

## Proprietary surface (intentionally — stays in a private GitLab environment)

These are not published. They are where H33's operational engineering and patent claims live. Auditing them happens under NDA on commercial engagement; verifying their *outputs* does not require any of that.

| Layer | What it is | Why proprietary |
|---|---|---|
| **Bundle export pipeline** | The backend route at `api.h33.ai/api/v1/spine/cases/:id/replay/bundle/v0.1` that constructs bundles from live DB state. Reads tenant scope, agent hierarchy, action chains, frame manifests, substrate bindings. | Operational topology, multi-tenant isolation, DB schema, performance characteristics. |
| **Substrate attestation orchestration** | The service that issues the 74-byte receipts referenced inside each bundle entry. ML-DSA-65 + FALCON-512 + SPHINCS+-SHA2-128f signing under Graviton4 tuning, ephemeral signature bundling, 42-byte compression. | Patent claims, performance moat, key management. |
| **STARK provers** | Lookup STARK, AIR STARK, the engines behind `h33-zk-verify@` artifact refs cited inside bundle proofs. | Patent claims; performance moat. |
| **FHE engines** | BFV-128, BFV-256, BFV-32, CKKS variants. | Patent claims, performance moat. |
| **Replay frame storage** | The sealed-storage layer that holds the bytes `frame_blob_ref` / `bundle_blob_ref` point at. Verifier reads them when `--payloads` is supplied; the storage system itself is private. | Operational. |
| **Production keys, rotation, HSMs** | All cryptographic key material in production, rotation schedules, hardware-security-module integrations. | Standard practice. |
| **Production infrastructure** | EC2 topology, internal hostnames, AWS resource IDs, RDS credentials, IAM, secrets management. | Standard practice. |

## Boundary rationale

Public wire formats do not destroy defensibility — they create it. The same pattern that made TLS, JWT, QUIC, and OAuth infrastructure-category products applies here. The *protocol* and the *verifier* live in the open precisely because that's what lets the system become trustable infrastructure. The *operationalization* — running it at scale, integrating it, sustaining it, optimizing it, supporting it commercially — is where defensibility lives.

H33 follows the same pattern. Receipt format, bundle format, signed-transcript envelope, verifiers, replay tool, SDKs — public. Production signing, FHE, STARK, orchestration, infrastructure — proprietary.

## What this means for users

- **Auditors:** every claim H33 makes about a replay bundle is independently checkable by you, against open code, with no H33 access required. Run `h33-replay-verify` on bundles your customer hands you. Disagree with the verdict? Read the source.
- **Regulators:** you can run the verifier in your own sandboxed environment. You don't have to trust H33's infrastructure for the verification step. Pair this with the primitive [`h33-verify`](https://github.com/H33ai/h33-verifier) tool for receipt-level checks.
- **Enterprises evaluating H33:** the verifier surface is the artifact you should ask your security team to review. Everything else is normal commercial engineering and is happy to be discussed under NDA.
- **Researchers / OSS community:** fork the verifier, mirror it, port it, write a TypeScript implementation, submit conformance failures to GitHub Issues. None of this requires H33 permission.
- **AI agents:** every public file in this repo is intentionally machine-readable. The specs are written to be parsed and reasoned about; the fixtures are intended to be re-executed by independent implementations.

## What this does NOT mean

- The proprietary side is not "hidden because something is wrong with it." It is private because the operational system *running at scale* is the commercial product. The cryptographic primitives it composes are NIST-standardized or peer-reviewed (ML-DSA, FALCON, SLH-DSA, SHA3, BFV, CKKS, STARK).
- "Public verifier" does not mean "no obligations." Bundles that contain references to private personal data, regulated material, or commercial confidence remain subject to the normal handling rules of those domains. The verifier checks bytes; it does not authorize their distribution.
- "Proprietary computation" does not mean "unverifiable." That is the entire point of the architecture. Computation runs on the proprietary side; *evidence of computation* (substrates, receipts, replay bundles) crosses the boundary to the public side and is verified there.

## Change control on this boundary

Moving an artifact from proprietary to public, or vice versa, requires:

- Explicit written approval from the H33 CEO.
- An update to this document in the same commit as the move.
- An accompanying note in the changelog of whichever side gained the artifact.

This is to prevent gradual drift in either direction. The boundary is a strategic asset; it is not casually editable.

## Last reviewed

2026-05-26 — alongside h33-replay-verifier v0.3.0 publication.
