# H33 Replay Bundle — v0.1

> **Superseded by [`h33-replay-bundle-v0.2.md`](h33-replay-bundle-v0.2.md) for governance-event and authority-temporal-validity support.** This document remains frozen as the canonical v0.1 reference. v0.1 bundles continue to verify under the v0.4.0+ verifier; new bundles SHOULD use v0.2.

**Status:** v0.1 frozen 2026-05-26
**Reference verifier:** `h33-replay-verify` (`src/bin/h33_replay_verify.rs`)
**Wire schema:** `src/replay/bundle.rs` (`ReplayBundle`)
**Verification algorithm:** `src/replay/verify.rs` (`verify`)
**Test fixtures:** `tests/replay_verify_integration.rs` (PASS + 3 FAIL variants)
**Signed transcript spec:** [`h33-signed-verify-report-v0.1.md`](h33-signed-verify-report-v0.1.md) — ML-DSA-65 wrapper around the report this verifier emits.

> **Architecture separation** (locked):
> `h33-verify` = primitive 74-byte H33 receipt verifier (the atom).
> `h33-replay-verify` = replay bundle verifier (the story).
> **One verifies the atom; one verifies the story.**

---

## 1. Purpose

A SCIF case generates events: agent sessions, actions, proofs, evidence bundles, substrate bindings. The spine exports a self-contained JSON document — the **replay bundle** — that captures everything an external party needs to reconstruct + verify the case's operational history WITHOUT contacting H33 servers or accessing the production database.

`h33-replay-verify` consumes a bundle and runs **10 deterministic checks** against it. The output is a JSON report; the exit code is the verdict.

---

## 2. Wire schema (JSON)

See `src/replay/bundle.rs` for the canonical Rust definitions. Top-level structure:

```jsonc
{
  "version": "0.1",
  "tenant_id": "<uuid>",
  "case_id": "<uuid>",
  "case": {
    "case_number": "string",
    "title": "string",
    "case_type": "string",       // §8.1 vocab
    "status": "string",          // §8.2 vocab
    "priority": "string",        // §8.3 vocab
    "severity": "string",        // §8.4 vocab
    "opened_by_human_id": "<uuid>",
    "assigned_human_id": "<uuid>|null",
    "continuity_hash_hex": "<64-char hex>",
    "predecessor_hash_hex": "<64-char hex>|null",
    "evidence_bundle_root_hex": "<64-char hex>|null",
    "created_at": "<rfc3339>",
    "closed_at": "<rfc3339>|null"
  },
  "agents":   [ /* AgentSnapshot[] */ ],
  "humans":   [ /* HumanSnapshot[] */ ],          // optional
  "timeline": { "continuity_hash_hex": "...", "entries": [ /* TimelineEntry[] */ ] },
  "frames":   [ /* FrameManifest[] */ ],
  "evidence_bundles":   [ /* EvidenceBundleManifest[] */ ],
  "substrate_bindings": [ /* SubstrateBindingSnapshot[] */ ],
  "verifier_artifact_refs": [ "h33-pq-verify@v2.1", "h33-zk-verify@v3.0/lookup" ]
}
```

All hex fields are lowercase, no `0x` prefix on output. 32-byte fields = 64 chars; 74-byte fields = 148 chars. (Matches SCIF API contract v1.1 §0.3.)

### TimelineEntry — load-bearing fields

```jsonc
{
  "event_kind": "action" | "proof",
  "event_id": "<uuid>",
  "session_id": "<uuid>|null",
  "sequence_in_session": <int|null>,
  "action_kind": "<§8.10 vocab>|null",
  "proof_kind":  "<§8.12 vocab>|null",
  "commitment_hex": "<64-char hex>",  // action: this_action_hash ; proof: statement_commitment
  "receipt_hex":    "<148-char hex>", // 74-byte H33 receipt
  "timestamp": "<rfc3339>",
  "agent_id_hex": "<64-char hex>|null",
  "prior_action_hash_hex": "<64-char hex>|null"  // null only for sequence 0
}
```

### SubstrateBindingSnapshot — MUST include `attributes`

```jsonc
{
  "binding_id": "<uuid>",
  "signing_message_hex": "<148-char hex>",
  "tenant_id": "<uuid>",
  "actor_kind": "agent" | "human",
  "agent_id_hex": "<64-char hex>|null",
  "human_id":    "<uuid>|null",
  "case_id":     "<uuid>|null",
  "verification_hash_hex": "<64-char hex>",
  "attributes": [ ["k1","v1"], ["k2","v2"] ],   // REQUIRED for verifier recompute
  "bound_at": "<rfc3339>"
}
```

Production API responses MAY redact `attributes` for privacy. Replay bundles intended for offline verification MUST include them — without them, the verifier cannot recompute `verification_hash` (check #10 fails).

---

## 3. The 10 checks (canonical order)

| # | Name | What it validates |
|---|---|---|
| 1 | `schema_parse` | Bundle JSON parses + version major is supported (currently only `0`) |
| 2 | `timeline_ordering` | Entry timestamps non-decreasing; per-session `sequence_in_session` strictly increasing (gaps allowed) |
| 3 | `merkle_roots` | For each frame/bundle with a `*_blob_ref` and `--payloads` dir supplied: SHA3-256(blob) == `*_root_hash_hex` |
| 4 | `receipt_commitments` | Per-session action chain: `this_action_hash = SHA3-256(prior_action_hash ‖ action_receipt)` recomputes correctly across every action |
| 5 | `frame_refs_resolve` | Every `frame.action_ids` / `frame.proof_ids` element exists in the timeline |
| 6 | `continuity_consistency` | `bundle.case.continuity_hash_hex == bundle.timeline.continuity_hash_hex` |
| 7 | `no_orphans` | event_ids / frame_ids / binding_ids unique; every `action.agent_id_hex` appears in `bundle.agents` |
| 8 | `hash_algorithms_known` | Every `verifier_artifact_refs` entry starts with a registered prefix (`h33-pq-verify@`, `h33-zk-verify@`, `h33-replay-verify@`, `h33-substrate-verify@`) |
| 9 | `same_scope_isolation` | Every `substrate_bindings[i].tenant_id == bundle.tenant_id`; if `binding.case_id` set, equals `bundle.case_id` |
| 10 | `substrate_bindings` | For each binding: recompute verification_hash per SCIF API contract §6.1's canonical-serialize algorithm; assert it equals stored `verification_hash_hex` |

**Verdict** = `passed == true` IFF every applicable check passed. In non-`--strict` mode, check #3 may report `passed=true` with a warning when no `--payloads` directory is provided; in `--strict` mode, this becomes a hard failure.

---

## 4. What PASS proves

**PASS** means:
- The bundle is **internally consistent** — every hash, chain reference, scope boundary, and structural relationship recomputes correctly.
- An adversary cannot have tampered with any timeline entry, frame manifest, or substrate binding without breaking the corresponding check.
- The case story is **bit-identical** to what H33 recorded at export time.
- **Tenant isolation is structurally enforced** within the bundle — no cross-tenant rows.

## 5. What PASS does NOT prove

PASS does **not** prove:
- **Completeness.** A bundle might be a truthful subset (e.g., a date-range export); PASS does not assert "this is every event the case ever had." For completeness assertions, the exporter must include a coverage manifest (deferred to v0.2).
- **Underlying cryptographic signature validity.** The 74-byte H33 receipts and STARK/PQ proofs are validated by the named `verifier_artifact_refs` (e.g., `h33-pq-verify@v2.1`). v0.1 of `h33-replay-verify` does NOT shell out to those tools — it only verifies the structural envelope. To prove signatures, pipe the receipts to `h33-verify`.
- **On-chain anchor existence.** If the bundle was anchored to a blockchain (Polygon/Bitcoin/Solana), v0.1 does not look up the anchor TX. Pair with the anchor-specific verifier.
- **Sealed payload integrity beyond Merkle root.** v0.1's check #3 hashes the entire blob and compares against `*_root_hash_hex`. This catches whole-blob tampering but does NOT validate the internal Merkle-tree structure that may be present in larger bundles. v0.2 will add a richer Merkle proof format.
- **Time of attestation.** Timestamps are checked for monotonicity but not against any trusted clock. For time-anchored proofs, pair with an attestation-time service (e.g., the H33 substrate attest endpoint).

The CLI prints both lists in the JSON report's free-form area when running with `--explain` (planned for v0.2). v0.1 prints only the machine-readable report.

---

## 6. Deterministic verification algorithm

Given a bundle `B`:

```
INPUT:  B (parsed ReplayBundle)
INPUT:  P (optional payloads directory)
INPUT:  S (strict flag, boolean)

OUTPUT: VerifyReport { passed, checks[], warnings[] }

1.  passed ← true
2.  For each check_id in [schema_parse, timeline_ordering, merkle_roots,
                          receipt_commitments, frame_refs_resolve,
                          continuity_consistency, no_orphans,
                          hash_algorithms_known, same_scope_isolation,
                          substrate_bindings]:
3.      (passed_i, message, examined) ← run_check(check_id, B, P, S)
4.      Append CheckResult{check_id, passed_i, message, examined} to report.checks
5.      If passed_i = false: passed ← false
6.  report.passed ← passed
7.  Return report
```

`run_check` implementations are in `src/replay/verify.rs` (one function per check). They are pure, deterministic, and side-effect-free except for reading from `P` (when supplied). Two invocations of `verify(B, opts)` against the same bundle + opts produce byte-identical reports.

---

## 7. Exit codes (CLI)

| Code | Meaning | Examples |
|---|---|---|
| **0** | PASS — every applicable check succeeded | well-formed bundle, no tampering |
| **1** | FAIL — one or more checks failed | tampered chain hash, cross-tenant binding, unresolved frame ref |
| **2** | ERROR — input could not be read or parsed | file missing, malformed JSON, unsupported version major |

The JSON `VerifyReport` is always written to stdout on exit codes 0 and 1. Exit code 2 prints a minimal `{error, message}` envelope to stderr.

---

## 8. Minimal PASS fixture

The canonical PASS fixture is built programmatically by
`tests/replay_verify_integration.rs::build_pass_bundle_json()` so that all
hashes recompute correctly. Run:

```bash
cargo test --test replay_verify_integration pass_bundle_exits_0
```

This produces a temporary bundle at `$TMPDIR/h33-replay-pass.json`. Inspect
that file for the canonical PASS shape with valid hashes.

Shape summary: 1 case, 1 agent, 1 session, 2 chained actions, 1 frame
referencing both actions, 1 substrate binding with correctly-computed
`verification_hash_hex`.

Expected output:

```json
{
  "bundle_version": "0.1",
  "tenant_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
  "case_id": "33333333-3333-3333-3333-333333333333",
  "passed": true,
  "strict": false,
  "checks": [
    {"check": "schema_parse",           "passed": true, "message": "schema v0.1 accepted", "examined": 1},
    {"check": "timeline_ordering",      "passed": true, "examined": 2},
    {"check": "merkle_roots",           "passed": true, "message": "skipped (non-strict)", "examined": 0},
    {"check": "receipt_commitments",    "passed": true, "examined": 2},
    {"check": "frame_refs_resolve",     "passed": true, "examined": 1},
    {"check": "continuity_consistency", "passed": true, "examined": 1},
    {"check": "no_orphans",             "passed": true, "examined": 4},
    {"check": "hash_algorithms_known",  "passed": true, "examined": 2},
    {"check": "same_scope_isolation",   "passed": true, "examined": 3},
    {"check": "substrate_bindings",     "passed": true, "examined": 1}
  ],
  "warnings": ["skipped — no --payloads directory (covers 1 frames + 0 bundles)"]
}
```

Exit code: `0`.

---

## 9. Minimal FAIL fixture (tampered chain hash)

Same as PASS, but `timeline.entries[1].commitment_hex` is corrupted to
`deadbeef00000000…`. The receipt_commitments check recomputes the chain
and detects the mismatch.

Built by `build_fail_bundle_json()` in the integration test.

Expected output highlight:

```json
{
  "passed": false,
  "checks": [
    /* ... */,
    {
      "check": "receipt_commitments",
      "passed": false,
      "message": "session 44444444-… event 22222222-… chain hash mismatch: stored=deadbeef00000000… recomputed=<correct hash>",
      "examined": 2
    },
    /* ... */
  ]
}
```

Exit code: `1`.

---

## 10. Cross-tenant FAIL fixture

Same as PASS, but `substrate_bindings[0].tenant_id` is set to a different UUID.
Detected by check #9 (`same_scope_isolation`). Exit code: `1`.

Built by `build_cross_tenant_fail_bundle_json()`.

---

## 11. Versioning

- **v0.1** (this spec) — 10 checks, single-blob Merkle, no signature verification, no on-chain lookup.
- **v0.2 (planned)** — coverage manifest, richer Merkle tree proofs, `--explain` mode, `--verify-receipts` flag that shells to `h33-verify`.
- Breaking changes bump the major.

The verifier checks `bundle.version`'s major against `SUPPORTED_VERSIONS`
(in `src/replay/verify.rs`). Unknown majors → exit 1 with `schema_parse` failure.

---

## 12. Pairs with

- **SCIF API contract v1.1** — `docs/api/scif-v009-v014-contract.md` (the canonical wire format for the spine endpoints whose outputs become bundles)
- **`h33-verify`** (primitive receipt verifier — the atom)
- **`h33-replay-verify`** (this; the story)
- **`scif-fe/src/lib/offline-verify.ts`** — TypeScript port of step 6 (substrate binding recompute); the broader frontend offline-verify protocol mirrors this spec's 10-check layout

---

## 13. Operational guidance

For audit / regulatory hand-off:

```bash
# Verify a bundle with default checks (Merkle check skipped — fast)
h33-replay-verify ./case-3782f9f3.bundle.json

# Verify with sealed payloads + strict mode (full audit)
h33-replay-verify ./case-3782f9f3.bundle.json \
  --payloads ./case-3782f9f3-blobs/ \
  --strict

# Pipe verdict into jq for downstream processing
h33-replay-verify ./bundle.json | jq '.checks[] | select(.passed == false)'
```

Recommended for any party who:
- received a bundle from an H33 customer and needs to confirm authenticity
- is performing an internal compliance audit of an H33-managed case
- is acting as a regulator / opposing counsel / insurer and needs structurally-verifiable case history without trusting H33's API
- is building tooling around the SCIF spine and needs a reference implementation of the 10-check protocol
