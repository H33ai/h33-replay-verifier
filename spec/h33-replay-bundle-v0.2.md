# H33 Replay Bundle — v0.2

**Status:** v0.2 — 2026-05-27
**Supersedes:** [`h33-replay-bundle-v0.1.md`](h33-replay-bundle-v0.1.md) (v0.1 remains valid; verifier accepts both versions)
**Reference verifier:** `h33-replay-verify` v0.4.0+ (`crates/h33-replay-verify-cli/`)
**Wire schema:** `crates/h33-replay-verify-core/src/bundle.rs`
**Verification algorithm:** `crates/h33-replay-verify-core/src/verify.rs`
**Schema identifier:** `"h33-replay-bundle-v0.2-schema"`
**Signed transcript spec:** [`h33-signed-verify-report-v0.1.md`](h33-signed-verify-report-v0.1.md) (unchanged from v0.1)

> **Architecture separation** (locked):
> `h33-verify` = primitive 74-byte H33 receipt verifier (the atom).
> `h33-replay-verify` = replay bundle verifier (the story).
> **One verifies the atom; one verifies the story.**

---

## 1. What changed from v0.1

v0.2 is a **purely additive** evolution. Every v0.1 bundle is a valid v0.2 input modulo the `version` field; v0.2 adds two optional top-level fields plus one optional field on actions, and one new verifier check.

| Addition | Where | Required? |
|---|---|---|
| `governance_events: Vec<GovernanceEvent>` | top-level | optional (default `[]`) |
| `governance_chain_tips: Vec<GovernanceChainTip>` | top-level | optional (default `[]`) |
| `requires_authority_scope: Option<String>` | per `TimelineEntry` action | optional (default `null`) |
| **Check #11** `authority_temporal_validity` | verifier | always runs; N/A → PASS |
| `failure_mode: Option<String>` | per `CheckResult` | optional; set on failure of #11 |

**Backward compatibility:** v0.1 bundles verify unchanged. Check #11 is N/A (returns PASS with informational message) when no action declares `requires_authority_scope` AND no `governance_events` are present.

**Forward compatibility risk:** Old verifiers (pre-v0.4.0) reject v0.2 bundles via the schema-hash mismatch in Check #1. This is intentional — a verifier that can't evaluate Check #11 must not silently pass v0.2 bundles. Operators upgrading bundles to v0.2 must upgrade verifiers in lockstep.

---

## 2. The governance graph

v0.2 introduces an event-sourced authority graph. Each `GovernanceEvent` is a **delegation** or **revocation** of a specific authority scope to a specific subject (agent or human). Events are hash-chained per `(subject, authority_scope)` tuple using the same SHA3-256(prior_event_hash || receipt) construction that already chains agent actions per session.

### 2.1 `GovernanceEvent`

```jsonc
{
  "event_id": "<uuid>",
  "event_kind": "authority_delegation" | "authority_revocation",
  "subject_actor_id_hex": "<64-hex-char agent id>",  // OR
  "subject_human_id": "<uuid>",                       // (exactly one must be set)
  "authority_scope": "approve_transfer:acme.treasury",
  "effective_at": "2026-05-27T10:00:00Z",
  "receipt_hex": "<148-hex-char (74-byte) H33 receipt>",
  "prior_event_hash_hex": null | "<64-hex-char>",     // null only for first event in chain
  "this_event_hash_hex": "<64-hex-char SHA3-256(prior || receipt)>",
  "authority_state_after": "delegated" | "revoked"    // optional UI hint, verifier confirms consistency
}
```

**Field rules:**
- `event_kind`: exactly one of `"authority_delegation"` or `"authority_revocation"`.
- `subject_actor_id_hex` XOR `subject_human_id`: exactly one must be set; the other null.
- `authority_scope`: free-form string. Exporter + verifier must agree byte-for-byte. Convention: `"<verb>:<noun>"`, e.g. `"approve_transfer:acme.treasury"`.
- `effective_at`: RFC 3339 UTC timestamp. Used for state-machine ordering by lexicographic = chronological compare (all timestamps MUST be normalized to Z).
- Chain hashing: identical to action chains. `this_event_hash = SHA3-256(prior_event_hash_bytes || receipt_bytes)`. First event in a `(subject, scope)` chain omits `prior_event_hash_hex` AND feeds only the receipt into the hash.
- `authority_state_after`: optional and redundant with `event_kind`. Verifier enforces consistency (delegation → "delegated", revocation → "revoked"). Present for visualization tooling.

### 2.2 `GovernanceChainTip`

Exporter-issued attestation of a single governance chain's terminal state at export time. **This is the primary defense against trailing-event omission attacks.**

```jsonc
{
  "subject_actor_id_hex": "<64-hex-char>",            // OR
  "subject_human_id": "<uuid>",                       // (exactly one must be set)
  "authority_scope": "approve_transfer:acme.treasury",
  "terminal_event_hash_hex": "<this_event_hash_hex of the chronologically-last event>",
  "event_count": 2
}
```

The verifier reconstructs each `(subject, scope)` chain from `governance_events`, sorts by `effective_at`, and confirms each tip matches the actual terminal hash AND event count. Mismatch → FAIL with `failure_mode="chain_integrity_violation"`.

If `governance_chain_tips` is empty, the verifier still recomputes chain hashes (catches tamper + middle-event omission via discontinuity) but cannot catch trailing-event omission. Bundles intending strong omission resistance MUST include tips.

### 2.3 New field on `TimelineEntry` (for actions)

```jsonc
{
  // ... all v0.1 fields unchanged ...
  "requires_authority_scope": "approve_transfer:acme.treasury" | null
}
```

When set on an action, the verifier looks up the governance graph entry for `(agent_id_hex, requires_authority_scope)` whose `effective_at` is the **latest** at-or-before the action's `timestamp`, and applies the state-machine rule (§3).

---

## 3. Check #11 — `authority_temporal_validity`

### 3.1 State-machine rule

For each `TimelineEntry` action A with `requires_authority_scope = S`, by subject `agent_id_hex = X`:

1. Filter `governance_events` to entries where `subject_actor_id_hex == X AND authority_scope == S AND effective_at <= A.timestamp`.
2. Sort by `effective_at` ascending.
3. Examine the **last** entry — the most recent effective governance state at or before action time:
   - **None** → `failure_mode="temporal_violation"`. (No authority existed at action time.)
   - **`authority_delegation`** → PASS for this action.
   - **`authority_revocation`** → `failure_mode="temporal_violation"`. (Authority had been revoked.)

**This is a "current state at action time" rule, not a "window" rule.** A revocation followed by re-delegation reinstates authority for actions after the re-delegation.

### 3.2 Phases (in order)

The check runs four phases. The first failure wins; subsequent phases are not evaluated.

| Phase | What | Failure mode |
|---|---|---|
| **1 — self-consistency** | `authority_state_after` (if set) matches `event_kind`; subject is exactly one of agent/human | `chain_integrity_violation` |
| **2 — chain hash recompute** | For each `(subject, scope)` chain, `this_event_hash_hex = SHA3-256(prior_event_hash \|\| receipt)`; `prior_event_hash_hex` links to the preceding event's `this_event_hash_hex`; first event has no prior | `chain_integrity_violation` |
| **3 — chain tip integrity** | For each entry in `governance_chain_tips`, reconstructed chain's terminal hash + event_count match | `chain_integrity_violation` |
| **4 — temporal validity** | State machine per §3.1 | `temporal_violation` |

### 3.3 N/A and strict-mode behavior

| Situation | Non-strict (default) | Strict (`--strict`) |
|---|---|---|
| No authority-scoped actions, no governance events | PASS ("no authority-scoped actions; governance graph empty") | PASS |
| No authority-scoped actions, governance events present | PASS (chain integrity still verified; events informational) | PASS |
| Authority-scoped actions present, no governance events | PASS with WARN in message | FAIL (`chain_integrity_violation`) |
| Authority-scoped action present, no matching governance event | FAIL (`temporal_violation`) | FAIL (`temporal_violation`) |

### 3.4 Failure mode taxonomy

`CheckResult.failure_mode` is a string. For Check #11, well-known values:

| Value | Means | Demo phrasing |
|---|---|---|
| `"temporal_violation"` | Authority was in some valid state before, but is not valid at action time | *"Independent replay detected that the approving authority had already been revoked at the time of authorization."* |
| `"chain_integrity_violation"` | Governance graph itself is tampered, malformed, omitted, or inconsistent | *"Independent replay detected that the governance graph backing this authorization is incomplete or has been altered."* |

UI consumers SHOULD render these two classes distinctly. The string is stable; future taxonomy growth uses additional values, never reassignment.

---

## 4. End-to-end example

See:
- `fixtures/tokenize-the-world-happy-bundle-v0.2.json` — Acme Treasury Fund transfer where the AI agent acted **before** Carol's authority was revoked. PASSes all 11 checks.
- `fixtures/tokenize-the-world-fraud-bundle-v0.2.json` — Same flow but the AI agent's action timestamp is **after** the revocation. PASSes checks 1–10; FAILs Check #11 with `failure_mode="temporal_violation"`.

Adversarial variants (omission, hash tamper) are constructed at test time from the happy fixture and tested in `crates/h33-replay-verify-cli/tests/replay_verify_integration.rs`.

---

## 5. Threat model additions

v0.2's contribution to the threat model is detecting governance fraud that production systems silently let through. The verifier specifically catches:

- **Temporal misuse** — actor with formerly-valid authority continued (or was used to continue) after revocation.
- **Mid-chain tamper** — `this_event_hash_hex` rewritten, `prior_event_hash_hex` pointer broken, event reordered, or event inserted.
- **Mid-chain omission** — removing an event in the middle of a chain breaks the next event's `prior_event_hash_hex` pointer.
- **Trailing omission** — removing the last event in a chain. Caught by `governance_chain_tips` mismatch when tips are present. Bundles without tips cannot defend against this attack.

v0.2 does NOT defend against:

- **Forgery of the entire governance graph by a trusted exporter.** If the exporter is the adversary, no number of internal cross-checks help; the signed-transcript layer ([`h33-signed-verify-report-v0.1.md`](h33-signed-verify-report-v0.1.md)) is what binds the bundle to a verifier identity. Out-of-band verifier-identity attestation closes this.
- **Authority that was never delegated through this graph.** Bundles MAY represent authority that originated outside the spine; those actions should not set `requires_authority_scope`.

---

## 6. Versioning + reserved future fields

- v0.3 reserved: explicit support for actions performed by humans (currently only agents have governance-graph subjects in this spec).
- v0.4 reserved: cross-chain attestation of governance events to external chains (Polygon / Bitcoin) — `external_anchor_hash_hex` per event.

Verifier MUST reject unknown bundle versions outside `["0.1", "0.2"]` at Check #1.

---

## 7. Reference implementation parity

| Surface | Repo / file |
|---|---|
| Types | `crates/h33-replay-verify-core/src/bundle.rs` (`GovernanceEvent`, `GovernanceChainTip`, `TimelineEntry::requires_authority_scope`) |
| Check algorithm | `crates/h33-replay-verify-core/src/verify.rs` (`check_authority_temporal_validity`) |
| Integration tests | `crates/h33-replay-verify-cli/tests/replay_verify_integration.rs` (v0_2_*) |
| Browser playground (same code, wasm32 target) | `crates/h33-replay-verify-wasm/`, `playground/` |
