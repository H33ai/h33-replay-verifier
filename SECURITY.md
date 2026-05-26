# Security Policy

## Scope

This policy covers the `h33-replay-verify` binary, the `h33-replay-verify-core` library, the `h33-replay-verify-wasm` browser build, the published wire-format specifications ([`spec/h33-replay-bundle-v0.1.md`](./spec/h33-replay-bundle-v0.1.md) and [`spec/h33-signed-verify-report-v0.1.md`](./spec/h33-signed-verify-report-v0.1.md)), and the test fixtures shipped in this repository.

It does **not** cover H33's production infrastructure, the bundle export route at `api.h33.ai`, or the proprietary signing / FHE / STARK / biometric implementations that produce the receipts referenced inside the bundles this tool verifies. Those are out of scope here — for issues in those systems, contact H33 directly through normal support channels. See [`BOUNDARY.md`](./BOUNDARY.md) for the precise scope split.

## Reporting a vulnerability

**Preferred:** GitHub Security Advisories — <https://github.com/H33ai/h33-replay-verifier/security/advisories/new>. This keeps the report private until a fix ships.

**Alternative:** email `support@h33.ai` with subject line beginning `[h33-replay-verify security]`. We will route from there.

Please do not file public issues for security reports.

## What we want to hear about

- **Verification soundness bugs** — cases where the verifier returns `passed=true` for a bundle that should fail one of the 10 checks. Specifically: a bundle that drifts from [`spec/h33-replay-bundle-v0.1.md`](./spec/h33-replay-bundle-v0.1.md) and PASSes anyway.
- **Verification completeness bugs** — cases where the verifier returns `passed=false` for a bundle that conforms to the spec.
- **Signed-transcript bugs** — cases where `--verify-transcript` accepts a signature that should fail under FIPS 204 ML-DSA-65, or rejects a signature that a conformant verifier would accept. Also: failures of the fingerprint cross-check or the embedded-payload-hash cross-check.
- **Spec/implementation divergence** — cases where the verifier behaves differently from what the spec mandates.
- **Crash, hang, or memory-safety issues** in any of the three crates, especially when triggered by malformed JSON, malformed hex, malformed base64, or boundary-condition inputs.
- **Information leaks** — anywhere the verifier inadvertently writes, logs, or transmits anything beyond its declared JSON output. The CLI should be a pure files-to-stdout transformation; the WASM build should be a pure inputs-to-JsValue transformation. No telemetry, no phone-home, ever.
- **Browser playground sandbox escapes** — anything in the WASM build or its JS shim that touches the network, reads local storage beyond what's documented, or otherwise breaks the "no server call" guarantee.
- **Supply-chain concerns** — anything off about the published dependencies (notably `pqcrypto-mldsa`, `sha3`, `serde`, `clap`, `@noble/post-quantum`) or how this crate uses them.

## What is not a vulnerability here

- The verifier explicitly does **not** check the post-quantum signature validity of the 74-byte H33 receipts referenced inside bundles. Those receipts are validated by the sibling tool [`h33-verify`](https://github.com/H33ai/h33-verifier). The absence of that check in this tool is documented and intentional.
- The verifier explicitly does **not** check on-chain anchor presence. Bundles that reference a Polygon / Bitcoin / Solana TX are validated against the chain by separate chain-specific tooling, not this binary.
- The verifier explicitly does **not** check liveness, recency, replay, or issuer authenticity — those are application-layer concerns. See the "What PASS does not prove" section of each spec.
- The verifier identity stored at `~/.h33-replay-verify/keys/identity.{public,secret}.b64` is the operator's own keypair. Compromise of that keypair is an operator-side incident, not a vulnerability of this tool.
- Issues in the H33 bundle-export pipeline (DB queries, auth, tenant scoping) are out of scope for this repo. Report them to H33 directly.

## Disclosure timeline

For valid reports:

- We aim to acknowledge within 3 business days.
- We aim to ship a fix within 30 days of acknowledgement.
- We will credit reporters (unless they prefer otherwise) in the changelog and the GitHub Security Advisory.
- If a report requires coordinated disclosure across the H33 substrate or backend, we will keep the reporter looped in and time the public advisory accordingly.

## Supported versions

| Version | Status |
|---|---|
| 0.3.x   | Supported — current |
| < 0.3   | Not applicable (no pre-0.3 public release) |

Future major-version releases (v1.0 stable) will have separate security windows once released.

## Out-of-band questions

If you're not sure whether something is a vulnerability or a feature request, file a regular GitHub issue with the `question` label. Honest doubts about the verifier's correctness are exactly the kind of conversation we want to be having in the open.
