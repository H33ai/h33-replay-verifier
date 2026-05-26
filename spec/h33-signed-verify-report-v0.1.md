# H33 Signed Verification Report v0.1

**Status:** locked (2026-05-26)
**Envelope version:** `h33-signed-verify-report/0.1`
**Signature algorithm:** ML-DSA-65 (FIPS 204, NIST Level 3)
**Implementations:** `h33-replay-verify --sign` (signing), `h33-replay-verify --verify-transcript` (verification), any conformant ML-DSA-65 library (third-party verification)
**Companion spec:** [`h33-replay-bundle-v0.1.md`](h33-replay-bundle-v0.1.md)

---

## 1. Purpose

A `VerifyReport` produced by `h33-replay-verify` is a structured PASS/FAIL with
per-check evidence. A *signed* report binds that verdict to a long-lived
cryptographic identity (the verifier's ML-DSA-65 public key) and to the exact
bytes of the bundle that was verified. Third parties can then check the
signature offline with any standards-conformant ML-DSA-65 implementation —
no H33 service, no trust in our distribution channel.

The wedge this enables: regulators, auditors, and counterparties get
**verifier-signed institutional evidence** they can rely on without trusting
either the bundle exporter or the verifier distributor.

---

## 2. Trust model

- **The envelope's `report` field is INSPECTION ONLY.** It is a copy of the
  `VerifyReport` for humans to read. Trust does *not* flow through it.
- **The envelope's `signed_transcript.signed_payload_b64` is the canonical
  truth.** A relying party decodes those bytes, verifies the ML-DSA-65
  signature over them, and acts only on the assertions inside.
- **The bundle is bound by SHA3-256.** The signed payload contains the
  bundle's SHA3-256; a relying party can rehash any bundle file they hold
  and confirm the signed report describes that exact bundle.
- **The verifier identity is bound by SHA3-256.** The signed payload contains
  the verifier's public-key fingerprint; the envelope ships the public key
  itself; the verification routine refuses if either drifts.
- **Domain separation.** Every signed payload begins with
  `"domain": "h33-signed-verify-report/0.1"`. Signatures produced here
  cannot be replayed as signatures over any other H33 payload type.

---

## 3. Envelope (`SignedReport`)

```json
{
  "envelope_version": "h33-signed-verify-report/0.1",
  "report": { /* VerifyReport — INSPECTION ONLY */ },
  "signed_transcript": {
    "verifier_name": "h33-replay-verify",
    "verifier_version": "0.1.0",
    "signed_at": "2026-05-26T12:34:56Z",
    "bundle_sha3_256_hex": "<64 hex chars>",
    "signed_payload_b64": "<base64 of canonical bytes>",
    "signed_payload_sha3_256_hex": "<64 hex chars>",
    "signature_algorithm": "ML-DSA-65",
    "verifier_public_key_b64": "<base64 of 1952-byte key>",
    "verifier_public_key_fingerprint_hex": "<64 hex chars>",
    "signature_b64": "<base64 of 3309-byte signature>"
  }
}
```

**Field rules:**

- `envelope_version` MUST equal `"h33-signed-verify-report/0.1"`.
- `signed_payload_b64` MUST decode to a UTF-8 JSON document conforming to §4.
- `signed_payload_sha3_256_hex` MUST equal SHA3-256 of the decoded
  `signed_payload_b64` bytes (convenience hash; verifier rechecks).
- `verifier_public_key_b64` MUST decode to exactly 1,952 bytes (ML-DSA-65).
- `verifier_public_key_fingerprint_hex` MUST equal SHA3-256 of the decoded
  public key bytes.
- `signature_b64` MUST decode to exactly 3,309 bytes (ML-DSA-65 detached
  signature) and MUST verify under the public key against the decoded
  `signed_payload_b64` bytes.

---

## 4. Signed payload (the bytes inside `signed_payload_b64`)

```json
{
  "domain": "h33-signed-verify-report/0.1",
  "verifier_name": "h33-replay-verify",
  "verifier_version": "0.1.0",
  "verifier_public_key_fingerprint_hex": "<64 hex chars>",
  "bundle_sha3_256_hex": "<64 hex chars>",
  "bundle_version": "0.1",
  "tenant_id": "<uuid>",
  "case_id": "<uuid>",
  "passed": true,
  "strict": false,
  "checks": [
    { "check": "schema_parse",           "passed": true, "examined": 0 },
    { "check": "timeline_ordering",      "passed": true, "examined": 2 },
    { "check": "merkle_roots",           "passed": true, "examined": 0 },
    { "check": "receipt_commitments",    "passed": true, "examined": 4 },
    { "check": "frame_refs_resolve",     "passed": true, "examined": 1 },
    { "check": "continuity_consistency", "passed": true, "examined": 2 },
    { "check": "no_orphans",             "passed": true, "examined": 4 },
    { "check": "hash_algorithms_known",  "passed": true, "examined": 1 },
    { "check": "same_scope_isolation",   "passed": true, "examined": 5 },
    { "check": "substrate_bindings",     "passed": true, "examined": 0 }
  ],
  "signed_at": "2026-05-26T12:34:56Z"
}
```

**Why no free-form messages.** Per-check `message` strings are *not* included
in the signed payload — only `(check, passed, examined)`. This keeps the
signed payload stable across cosmetic verifier-message changes; the verbose
mirror lives in the envelope's `report` field.

**Field order.** The Rust producer relies on serde struct field order +
`serde_json::to_vec` for determinism. External signers must replicate this
exact order. A future v0.2 may switch to JCS (RFC 8785); the embedded-bytes
design means external *verifiers* never need a canonical-JSON library either
way.

---

## 5. Third-party verification recipe

Any party — using any language — can verify a `SignedReport` with five steps:

1. Parse the envelope JSON.
2. Confirm `envelope_version == "h33-signed-verify-report/0.1"` and
   `signature_algorithm == "ML-DSA-65"`.
3. Base64-decode `signed_payload_b64`, `signature_b64`, `verifier_public_key_b64`.
4. Confirm `SHA3-256(public_key_bytes)` equals
   `verifier_public_key_fingerprint_hex` (envelope) *and* the
   `verifier_public_key_fingerprint_hex` field *inside* the decoded payload.
5. Invoke `ML-DSA-65.verify(public_key, signed_payload_bytes, signature)`.
   PASS iff this returns true.

A relying party that also has the original bundle file:

6. Compute `SHA3-256(bundle_bytes)` and confirm it equals the payload's
   `bundle_sha3_256_hex`. (Without this step, the signed report describes
   *some* bundle — but possibly not the one in hand.)

---

## 6. Verifier identity persistence

A verifier's signing identity is generated once and reused. Default location:

- `$H33_REPLAY_VERIFY_KEY_DIR` env var, if set
- otherwise `$HOME/.h33-replay-verify/keys/`

Files in that directory:

| File | Content | Permission |
|------|---------|------------|
| `identity.public.b64` | base64 of 1952-byte ML-DSA-65 public key | default |
| `identity.secret.b64` | base64 of 4032-byte ML-DSA-65 secret key | `0600` on unix |

Operators who want institutional trust register their verifier's
`verifier_public_key_fingerprint_hex` with their relying parties out of band.
Relying parties then enforce a fingerprint allow-list. This gives the
verifier a stable, attributable identity without any central registry.

---

## 7. CLI surface (informational)

```text
# Sign
h33-replay-verify <bundle.json> --sign
h33-replay-verify <bundle.json> --sign --key-dir <dir>

# Verify
h33-replay-verify --verify-transcript <signed_report.json>

# Verify + cross-check bundle
h33-replay-verify <bundle.json> --verify-transcript <signed_report.json>
```

Exit codes:
- `0` = signature valid AND (if bundle supplied) bundle hash matches.
- `1` = signature invalid OR bundle hash mismatch.
- `2` = unreadable file, malformed JSON, invalid arg.

---

## 8. What a PASS proves and does NOT prove

### A signature-valid `SignedReport` PROVES:

- The verifier whose public key has this fingerprint…
- …ran v`verifier_version`…
- …against a bundle whose SHA3-256 is `bundle_sha3_256_hex`…
- …at time `signed_at`…
- …and produced exactly these per-check verdicts.

### A signature-valid `SignedReport` does NOT prove:

- That the underlying bundle's *cryptographic receipts* are valid. Those
  are verified by named registry artifacts (`h33-pq-verify@v2.1`,
  `h33-zk-verify@v3.0`, `h33-substrate-verify@v1.0`) — out of scope for the
  replay verifier; see [`h33-replay-bundle-v0.1.md`](h33-replay-bundle-v0.1.md) §11.
- That the verifier's identity belongs to whom you think it does. That is
  established out of band (allow-list, registry, attestation).
- That the events depicted in the bundle actually happened in the
  real world. The bundle proves *internal consistency* and *PQ-attested
  hash chains*; out-of-band corroboration remains the relying party's job.

---

## 9. Versioning

- v0.1 (this spec): ML-DSA-65, embedded-bytes signing payload.
- v0.x bumps: backward-compatible additions (e.g., countersignatures,
  notary timestamps).
- v1.0 trigger: a wire-breaking change. New `envelope_version` string;
  old verifiers refuse cleanly with `EnvelopeVersionMismatch`.

---

## 10. Security notes

- **Algorithm choice.** ML-DSA-65 is the FIPS-204 Level-3 default. Verifiable
  by every conformant PQ stack (Rust `pqcrypto-mldsa`, liboqs, BoringSSL fork,
  forthcoming OpenSSL ML-DSA). Level 5 (`ML-DSA-87`) is reserved for a future
  envelope version if relying parties require it.
- **No long-term secret pinning.** Verifier identity rotation is a
  fingerprint swap, not a protocol break. Relying parties update their
  allow-list out of band.
- **No timestamping authority.** `signed_at` is the verifier's local
  wall-clock and is not authenticated against a notary. A future
  countersignature field will pin to RFC 3161 TSAs / blockchain anchors.
- **Bundle hash binding is mandatory.** Without §5 step 6, the signature
  asserts a verdict about *some* bundle, possibly not yours. Always pair.
