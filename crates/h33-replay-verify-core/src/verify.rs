//! Replay bundle verification — the 10-check protocol.
//!
//! Pure, deterministic, side-effect-free except for reading blob files
//! from the optional `--payloads` directory passed by the CLI.
//!
//! Returns a structured `VerifyReport` that the CLI prints as JSON.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::binding::{compute_verification_hash, ActorRef, BindingContext};
use crate::bundle::{schema_hash_for_version, GovernanceEvent, ReplayBundle, TimelineEntry};
use crate::chain::compute_chain_hash;

/// Supported bundle version majors. Verifier accepts both v0.1 and v0.2.
/// v0.1 bundles have no `governance_events` → check #11 is N/A.
const SUPPORTED_VERSIONS: &[&str] = &["0.1", "0.2"];

/// This verifier's own version. Compared against bundle's verifier_min_version.
pub const VERIFIER_VERSION: &str = "0.4.0";

/// Known verifier artifact registry — only refs starting with these prefixes
/// are recognized at v0.1. Unknown refs trigger check #8 failure (or warning
/// in non-strict mode).
const KNOWN_VERIFIER_PREFIXES: &[&str] = &[
    "h33-pq-verify@",
    "h33-zk-verify@",
    "h33-replay-verify@",
    "h33-substrate-verify@",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckId {
    SchemaParse,           // #1
    TimelineOrdering,      // #2
    MerkleRoots,           // #3
    ReceiptCommitments,    // #4
    FrameRefsResolve,      // #5
    ContinuityConsistency, // #6
    NoOrphans,             // #7
    HashAlgorithmsKnown,   // #8
    SameScopeIsolation,    // #9
    SubstrateBindings,     // #10
    AuthorityTemporalValidity, // #11  — v0.2+ governance graph check
}

impl CheckId {
    pub fn as_str(self) -> &'static str {
        match self {
            CheckId::SchemaParse => "schema_parse",
            CheckId::TimelineOrdering => "timeline_ordering",
            CheckId::MerkleRoots => "merkle_roots",
            CheckId::ReceiptCommitments => "receipt_commitments",
            CheckId::FrameRefsResolve => "frame_refs_resolve",
            CheckId::ContinuityConsistency => "continuity_consistency",
            CheckId::NoOrphans => "no_orphans",
            CheckId::HashAlgorithmsKnown => "hash_algorithms_known",
            CheckId::SameScopeIsolation => "same_scope_isolation",
            CheckId::SubstrateBindings => "substrate_bindings",
            CheckId::AuthorityTemporalValidity => "authority_temporal_validity",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub check: CheckId,
    pub passed: bool,
    /// If passed = false: the reason. If passed = true and strict matters: notes.
    pub message: String,
    /// Optional failure-mode tag (v0.4+). For check #11 the well-known values are:
    ///   - `"temporal_violation"`        — authority was revoked before action time
    ///   - `"chain_integrity_violation"` — governance chain hash recompute failed,
    ///                                      predecessor pointer mismatch, tip
    ///                                      attestation mismatch, or chain
    ///                                      discontinuity (omission)
    /// Other checks may grow their own failure_mode taxonomy. None when passed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_mode: Option<String>,
    /// Number of items examined (timeline entries, frames, bindings, etc.).
    pub examined: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    pub bundle_version: String,
    pub tenant_id: uuid::Uuid,
    pub case_id: uuid::Uuid,
    /// Overall verdict — true iff every check passed (or every non-skipped check passed).
    pub passed: bool,
    /// `strict` was on if the CLI was invoked with --strict.
    pub strict: bool,
    /// Per-check results, ordered by CheckId discriminant.
    pub checks: Vec<CheckResult>,
    /// Free-form warnings for skipped checks (e.g., no --payloads dir).
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct VerifyOptions<'a> {
    /// If Some, frame_blob_ref/bundle_blob_ref bytes are loaded from this directory.
    /// If None, checks that require blob bytes are skipped (warning) or fail in strict.
    pub payloads_dir: Option<&'a Path>,
    /// If true, skipped checks fail the run; otherwise they pass with a warning.
    pub strict: bool,
}

/// Run all 10 checks. Always returns a report; the report indicates pass/fail.
pub fn verify(bundle: &ReplayBundle, opts: VerifyOptions<'_>) -> VerifyReport {
    let mut report = VerifyReport {
        bundle_version: bundle.version.clone(),
        tenant_id: bundle.tenant_id,
        case_id: bundle.case_id,
        passed: true,
        strict: opts.strict,
        checks: Vec::with_capacity(10),
        warnings: Vec::new(),
    };

    // Check 1 — schema parse: serde succeeded if we got here. Validate:
    //   (a) version major is supported,
    //   (b) export_metadata.schema_hash matches our canonical schema_hash(),
    //   (c) export_metadata.verifier_min_version <= VERIFIER_VERSION,
    //   (d) export_metadata.bundle_version matches top-level version,
    //   (e) export_metadata.case_id matches top-level case_id,
    //   (f) export_metadata.exporter_tenant_id matches top-level tenant_id.
    let major = bundle.version.split('.').next().unwrap_or("");
    let version_ok = SUPPORTED_VERSIONS.iter().any(|v| v.starts_with(&format!("{major}.")));
    let m = &bundle.export_metadata;
    let expected_hash = schema_hash_for_version(&bundle.version);
    let schema_ok = m.schema_hash == expected_hash;
    let bundle_version_ok = m.bundle_version == bundle.version;
    let case_ok = m.case_id == bundle.case_id;
    let tenant_ok = m.exporter_tenant_id == bundle.tenant_id;
    let verifier_ok = semver_at_least(VERIFIER_VERSION, &m.verifier_min_version);

    let (ok, msg) = if !version_ok {
        (false, format!("unsupported bundle version: {}", bundle.version))
    } else if !schema_ok {
        (false, format!("schema_hash mismatch: bundle={} verifier_expected={}", m.schema_hash, expected_hash))
    } else if !bundle_version_ok {
        (false, format!("export_metadata.bundle_version ({}) != bundle.version ({})", m.bundle_version, bundle.version))
    } else if !case_ok {
        (false, format!("export_metadata.case_id ({}) != bundle.case_id ({})", m.case_id, bundle.case_id))
    } else if !tenant_ok {
        (false, format!("export_metadata.exporter_tenant_id ({}) != bundle.tenant_id ({})", m.exporter_tenant_id, bundle.tenant_id))
    } else if !verifier_ok {
        (false, format!("verifier too old: this verifier is {}, bundle requires >= {}", VERIFIER_VERSION, m.verifier_min_version))
    } else {
        (true, format!("schema v{} + metadata consistent", bundle.version))
    };
    record(&mut report, CheckId::SchemaParse, ok, msg, 1);

    // Check 2 — timeline ordering: timestamps non-decreasing AND per-session
    // sequence_in_session strictly increasing (gaps OK).
    let r2 = check_timeline_ordering(&bundle.timeline.entries);
    let r2_passed = r2.is_none();
    record(&mut report, CheckId::TimelineOrdering, r2_passed,
        r2.unwrap_or_else(|| format!("ordering OK across {} entries", bundle.timeline.entries.len())),
        bundle.timeline.entries.len());

    // Check 3 — Merkle roots: hash each blob and compare. Skipped if no payloads dir.
    let (passed3, msg3, examined3, warn3) = check_merkle_roots(bundle, opts);
    record(&mut report, CheckId::MerkleRoots, passed3, msg3, examined3);
    if let Some(w) = warn3 { report.warnings.push(w); }

    // Check 4 — receipt commitments: per-session chain hash recompute.
    let r4 = check_receipt_commitments(&bundle.timeline.entries);
    let r4_passed = r4.is_none();
    let action_count = bundle.timeline.entries.iter().filter(|e| e.event_kind == "action").count();
    record(&mut report, CheckId::ReceiptCommitments, r4_passed,
        r4.unwrap_or_else(|| format!("chain integrity OK across {} action entries", action_count)),
        action_count);

    // Check 5 — frame refs resolve: every frame.action_ids ⊆ timeline action_ids,
    // every frame.proof_ids ⊆ timeline proof_ids.
    let r5 = check_frame_refs(bundle);
    let r5_passed = r5.is_none();
    record(&mut report, CheckId::FrameRefsResolve, r5_passed,
        r5.unwrap_or_else(|| format!("all frame refs resolve across {} frames", bundle.frames.len())),
        bundle.frames.len());

    // Check 6 — continuity consistency: case.continuity_hash_hex == timeline.continuity_hash_hex.
    let case_h = &bundle.case.continuity_hash_hex;
    let tl_h = &bundle.timeline.continuity_hash_hex;
    let r6_passed = case_h == tl_h;
    record(&mut report, CheckId::ContinuityConsistency, r6_passed,
        if r6_passed { format!("continuity_hash matches: {}", short_hex(case_h)) }
        else { format!("continuity_hash mismatch: case={} timeline={}", short_hex(case_h), short_hex(tl_h)) },
        1);

    // Check 7 — no orphans: every action's session_id resolves to a session
    // we know about (any agent has acted in it); every proof.action_id (when
    // present) resolves to an action in the timeline; every frame_id/binding_id
    // is unique.
    let r7 = check_no_orphans(bundle);
    let r7_passed = r7.is_none();
    record(&mut report, CheckId::NoOrphans, r7_passed,
        r7.unwrap_or_else(|| "no orphans".into()),
        bundle.timeline.entries.len() + bundle.frames.len() + bundle.substrate_bindings.len());

    // Check 8 — hash algorithms known.
    let r8 = check_known_verifiers(&bundle.verifier_artifact_refs);
    let r8_passed = r8.is_none();
    record(&mut report, CheckId::HashAlgorithmsKnown, r8_passed,
        r8.unwrap_or_else(|| format!("{} verifier refs all recognized", bundle.verifier_artifact_refs.len())),
        bundle.verifier_artifact_refs.len());

    // Check 9 — same-scope isolation.
    let r9 = check_same_scope(bundle);
    let r9_passed = r9.is_none();
    let scope_examined = bundle.timeline.entries.len() + bundle.substrate_bindings.len() + bundle.agents.len();
    record(&mut report, CheckId::SameScopeIsolation, r9_passed,
        r9.unwrap_or_else(|| "all rows same-tenant + same-case".into()),
        scope_examined);

    // Check 10 — substrate bindings recompute verification_hash.
    let r10 = check_substrate_bindings(bundle);
    let r10_passed = r10.is_none();
    record(&mut report, CheckId::SubstrateBindings, r10_passed,
        r10.unwrap_or_else(|| format!("{} bindings recompute correctly", bundle.substrate_bindings.len())),
        bundle.substrate_bindings.len());

    // Check 11 — authority temporal validity (v0.2+ governance graph).
    // For each action with requires_authority_scope set, the latest
    // governance event for (subject, scope) with effective_at <= action.timestamp
    // must be an authority_delegation (not authority_revocation or absent).
    // Also recompute the governance event chain hashes + tip attestations
    // to catch tampering and omission, with distinct failure_mode tags.
    let r11 = check_authority_temporal_validity(bundle, opts);
    let r11_passed = r11.err.is_none();
    record_with_mode(
        &mut report,
        CheckId::AuthorityTemporalValidity,
        r11_passed,
        r11.err.unwrap_or(r11.ok_msg),
        r11.examined,
        r11.failure_mode,
    );

    report
}

fn record(report: &mut VerifyReport, check: CheckId, passed: bool, message: String, examined: usize) {
    record_with_mode(report, check, passed, message, examined, None);
}

fn record_with_mode(
    report: &mut VerifyReport,
    check: CheckId,
    passed: bool,
    message: String,
    examined: usize,
    failure_mode: Option<String>,
) {
    if !passed { report.passed = false; }
    report.checks.push(CheckResult { check, passed, message, failure_mode, examined });
}

// ─────────────────────────────────────────────────────────────────────────────
// Individual checks
// ─────────────────────────────────────────────────────────────────────────────

fn check_timeline_ordering(entries: &[TimelineEntry]) -> Option<String> {
    // Timestamp non-decreasing across the whole timeline.
    for w in entries.windows(2) {
        if w[1].timestamp < w[0].timestamp {
            return Some(format!(
                "timestamp not monotonic at event_id={}: {} < {}",
                w[1].event_id, w[1].timestamp, w[0].timestamp
            ));
        }
    }
    // Per-session sequence strictly increasing.
    let mut last_seq: HashMap<uuid::Uuid, i64> = HashMap::new();
    for e in entries {
        if e.event_kind != "action" { continue; }
        let Some(sid) = e.session_id else { continue; };
        let Some(seq) = e.sequence_in_session else { continue; };
        if let Some(&prev) = last_seq.get(&sid) {
            if seq <= prev {
                return Some(format!(
                    "session {} sequence not strictly increasing: {} after {}",
                    sid, seq, prev
                ));
            }
        }
        last_seq.insert(sid, seq);
    }
    None
}

fn check_merkle_roots(
    bundle: &ReplayBundle,
    opts: VerifyOptions<'_>,
) -> (bool, String, usize, Option<String>) {
    let dir = match opts.payloads_dir {
        Some(d) => d,
        None => {
            let msg = format!("skipped — no --payloads directory (covers {} frames + {} bundles)",
                              bundle.frames.len(), bundle.evidence_bundles.len());
            if opts.strict {
                return (false, "strict mode: cannot skip Merkle roots without --payloads".into(), 0, None);
            }
            return (true, "skipped (non-strict)".into(), 0, Some(msg));
        }
    };
    let mut examined = 0;
    for f in &bundle.frames {
        let Some(ref rel) = f.frame_blob_ref else { continue; };
        let path = dir.join(rel);
        examined += 1;
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => return (false, format!("frame {} blob {} unreadable: {}", f.frame_id, path.display(), e), examined, None),
        };
        let mut h = Sha3_256::new();
        h.update(&bytes);
        let got = hex::encode(h.finalize());
        if got != f.frame_root_hash_hex {
            return (false, format!("frame {} root mismatch: stored={} computed={}", f.frame_id, f.frame_root_hash_hex, got), examined, None);
        }
    }
    for b in &bundle.evidence_bundles {
        let Some(ref rel) = b.bundle_blob_ref else { continue; };
        let path = dir.join(rel);
        examined += 1;
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => return (false, format!("bundle {} blob {} unreadable: {}", b.bundle_id, path.display(), e), examined, None),
        };
        let mut h = Sha3_256::new();
        h.update(&bytes);
        let got = hex::encode(h.finalize());
        if got != b.bundle_root_hash_hex {
            return (false, format!("bundle {} root mismatch: stored={} computed={}", b.bundle_id, b.bundle_root_hash_hex, got), examined, None);
        }
    }
    (true, format!("recomputed {} root hash(es) successfully", examined), examined, None)
}

fn check_receipt_commitments(entries: &[TimelineEntry]) -> Option<String> {
    // Group action entries by session, sort by sequence, walk the chain.
    let mut by_session: HashMap<uuid::Uuid, Vec<&TimelineEntry>> = HashMap::new();
    for e in entries {
        if e.event_kind != "action" { continue; }
        if let Some(sid) = e.session_id {
            by_session.entry(sid).or_default().push(e);
        }
    }
    for (sid, mut session_entries) in by_session {
        session_entries.sort_by_key(|e| e.sequence_in_session.unwrap_or(0));
        let mut expected_prior: Option<[u8; 32]> = None;
        for e in session_entries {
            let receipt = decode_hex_74(&e.receipt_hex).ok_or_else(|| ())
                .map_err(|_| format!("session {} event {} receipt malformed", sid, e.event_id))
                .err()
                .map(Some)
                .unwrap_or(None);
            if let Some(err) = receipt {
                return Some(err);
            }
            let receipt = decode_hex_74(&e.receipt_hex).unwrap();
            // Validate stored prior_action_hash matches what we expect
            if let Some(ref stored_prior_hex) = e.prior_action_hash_hex {
                let stored_prior = match decode_hex_32(stored_prior_hex) {
                    Some(b) => b,
                    None => return Some(format!("session {} event {} prior_action_hash malformed", sid, e.event_id)),
                };
                if Some(stored_prior) != expected_prior {
                    return Some(format!(
                        "session {} event {} prior_action_hash mismatch (expected {:?}, got {})",
                        sid, e.event_id, expected_prior.map(hex::encode), stored_prior_hex
                    ));
                }
            } else if expected_prior.is_some() {
                return Some(format!(
                    "session {} event {} missing prior_action_hash but predecessor exists",
                    sid, e.event_id
                ));
            }
            // Recompute chain hash
            let recomputed = compute_chain_hash(expected_prior, &receipt);
            let stored_this = match decode_hex_32(&e.commitment_hex) {
                Some(b) => b,
                None => return Some(format!("session {} event {} commitment_hex malformed", sid, e.event_id)),
            };
            if recomputed != stored_this {
                return Some(format!(
                    "session {} event {} chain hash mismatch: stored={} recomputed={}",
                    sid, e.event_id, e.commitment_hex, hex::encode(recomputed)
                ));
            }
            expected_prior = Some(recomputed);
        }
    }
    None
}

fn check_frame_refs(bundle: &ReplayBundle) -> Option<String> {
    let action_ids: HashSet<uuid::Uuid> = bundle.timeline.entries.iter()
        .filter(|e| e.event_kind == "action")
        .map(|e| e.event_id)
        .collect();
    let proof_ids: HashSet<uuid::Uuid> = bundle.timeline.entries.iter()
        .filter(|e| e.event_kind == "proof")
        .map(|e| e.event_id)
        .collect();
    for f in &bundle.frames {
        for aid in &f.action_ids {
            if !action_ids.contains(aid) {
                return Some(format!("frame {} references unknown action {}", f.frame_id, aid));
            }
        }
        for pid in &f.proof_ids {
            if !proof_ids.contains(pid) {
                return Some(format!("frame {} references unknown proof {}", f.frame_id, pid));
            }
        }
    }
    None
}

fn check_no_orphans(bundle: &ReplayBundle) -> Option<String> {
    // 1. event_ids unique across the timeline.
    let mut seen = HashSet::new();
    for e in &bundle.timeline.entries {
        if !seen.insert(e.event_id) {
            return Some(format!("duplicate timeline event_id: {}", e.event_id));
        }
    }
    // 2. frame_ids unique.
    let mut seen_frame = HashSet::new();
    for f in &bundle.frames {
        if !seen_frame.insert(f.frame_id) {
            return Some(format!("duplicate frame_id: {}", f.frame_id));
        }
    }
    // 3. binding_ids unique.
    let mut seen_b = HashSet::new();
    for b in &bundle.substrate_bindings {
        if !seen_b.insert(b.binding_id) {
            return Some(format!("duplicate binding_id: {}", b.binding_id));
        }
    }
    // 4. every action.agent_id_hex (when present) appears in bundle.agents.
    let known_agents: HashSet<String> = bundle.agents.iter().map(|a| a.agent_id_hex.clone()).collect();
    for e in &bundle.timeline.entries {
        if e.event_kind != "action" { continue; }
        if let Some(ref aid) = e.agent_id_hex {
            if !known_agents.contains(aid) {
                return Some(format!("action {} references agent {} not in bundle.agents", e.event_id, aid));
            }
        }
    }
    None
}

fn check_known_verifiers(refs: &[String]) -> Option<String> {
    for r in refs {
        let recognized = KNOWN_VERIFIER_PREFIXES.iter().any(|p| r.starts_with(p));
        if !recognized {
            return Some(format!(
                "unknown verifier artifact ref: {} (known prefixes: {})",
                r, KNOWN_VERIFIER_PREFIXES.join(", ")
            ));
        }
    }
    None
}

fn check_same_scope(bundle: &ReplayBundle) -> Option<String> {
    // Every substrate binding's tenant_id matches the bundle tenant.
    for b in &bundle.substrate_bindings {
        if b.tenant_id != bundle.tenant_id {
            return Some(format!(
                "binding {} tenant {} != bundle tenant {}",
                b.binding_id, b.tenant_id, bundle.tenant_id
            ));
        }
        if let Some(c) = b.case_id {
            if c != bundle.case_id {
                return Some(format!(
                    "binding {} case {} != bundle case {}",
                    b.binding_id, c, bundle.case_id
                ));
            }
        }
    }
    None
}

fn check_substrate_bindings(bundle: &ReplayBundle) -> Option<String> {
    for b in &bundle.substrate_bindings {
        let signing_message = match decode_hex_74(&b.signing_message_hex) {
            Some(s) => s,
            None => return Some(format!("binding {} signing_message malformed", b.binding_id)),
        };
        let stored_hash = match decode_hex_32(&b.verification_hash_hex) {
            Some(h) => h,
            None => return Some(format!("binding {} verification_hash malformed", b.binding_id)),
        };

        let actor = match b.actor_kind.as_str() {
            "agent" => {
                let Some(ref aid_hex) = b.agent_id_hex else {
                    return Some(format!("binding {} actor=agent missing agent_id_hex", b.binding_id));
                };
                let aid = match decode_hex_32(aid_hex) {
                    Some(a) => a,
                    None => return Some(format!("binding {} agent_id malformed", b.binding_id)),
                };
                ActorRef::Agent { agent_id: aid }
            }
            "human" => {
                let Some(hid) = b.human_id else {
                    return Some(format!("binding {} actor=human missing human_id", b.binding_id));
                };
                ActorRef::Human { human_id: hid }
            }
            other => return Some(format!("binding {} unknown actor_kind {}", b.binding_id, other)),
        };

        let ctx = BindingContext {
            signing_message,
            tenant_id: b.tenant_id,
            actor,
            case_id: b.case_id,
            attributes: b.attributes.clone(),
        };
        let recomputed = compute_verification_hash(&ctx);
        if recomputed != stored_hash {
            return Some(format!(
                "binding {} verification_hash mismatch: stored={} recomputed={}",
                b.binding_id, b.verification_hash_hex, hex::encode(recomputed)
            ));
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    let trimmed = s.trim_start_matches("0x");
    if trimmed.len() != 64 { return None; }
    let bytes = hex::decode(trimmed).ok()?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn decode_hex_74(s: &str) -> Option<[u8; 74]> {
    let trimmed = s.trim_start_matches("0x");
    if trimmed.len() != 148 { return None; }
    let bytes = hex::decode(trimmed).ok()?;
    let mut out = [0u8; 74];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn short_hex(s: &str) -> String {
    if s.len() > 16 { format!("{}…{}", &s[..8], &s[s.len()-8..]) } else { s.to_string() }
}

/// `actual >= required`? Naive semver compare on 3 dot-separated u32 parts.
/// Returns false if parsing fails. Adequate for v0.x bundles; richer compare
/// can land when needed.
fn semver_at_least(actual: &str, required: &str) -> bool {
    fn parse(s: &str) -> Option<(u32, u32, u32)> {
        let mut p = s.split('.');
        let a = p.next()?.parse().ok()?;
        let b = p.next()?.parse().ok()?;
        let c = p.next()?.parse().ok()?;
        if p.next().is_some() { return None; }
        Some((a, b, c))
    }
    let Some(a) = parse(actual) else { return false; };
    let Some(r) = parse(required) else { return false; };
    a >= r
}

// ─────────────────────────────────────────────────────────────────────────────
// Check #11 — authority_temporal_validity
//
// Verify that every action depending on a delegated authority scope was
// performed while that authority was in effect. State-machine rule:
//
//   For each action A with requires_authority_scope = S, by subject X
//   (agent_id_hex if action.agent_id_hex.is_some(), else N/A — actions
//   on humans aren't modeled in v0.2 timeline entries):
//
//     1. Filter governance_events to entries where (subject, scope) == (X, S)
//        and effective_at <= action.timestamp.
//     2. Sort by effective_at ascending.
//     3. Take the LAST entry (latest effective at or before action.timestamp):
//        - none      → FAIL: no authority existed at action time
//        - delegation → PASS
//        - revocation → FAIL: authority had been revoked
//
// This is a "current state at action time" rule, not a "window" rule —
// what matters is the most recent effective state. Revocation followed by
// re-delegation reinstates authority for subsequent actions.
//
// In strict mode, an action with requires_authority_scope set but NO
// governance_events anywhere in the bundle is treated as FAIL (defense in
// depth: claimed authority requires an audit trail). In non-strict mode it
// is treated as a warning recorded under the check's PASS message.
// ─────────────────────────────────────────────────────────────────────────────

/// Result of check #11. The `err`-Some + `failure_mode`-Some path distinguishes
/// the two demo-critical failure classes:
///   - `"temporal_violation"`        — revocation in effect at action time
///   - `"chain_integrity_violation"` — graph tamper / hash mismatch / omission
struct Check11Result {
    /// Some when the check failed; None when passed.
    err: Option<String>,
    /// PASS message (used when err is None).
    ok_msg: String,
    /// How many items the check inspected.
    examined: usize,
    /// Set iff the check failed; categorizes the failure for the UI/replay.
    failure_mode: Option<String>,
}

impl Check11Result {
    fn pass(ok_msg: String, examined: usize) -> Self {
        Self { err: None, ok_msg, examined, failure_mode: None }
    }
    fn fail_temporal(msg: String, examined: usize) -> Self {
        Self {
            err: Some(msg),
            ok_msg: String::new(),
            examined,
            failure_mode: Some("temporal_violation".into()),
        }
    }
    fn fail_integrity(msg: String, examined: usize) -> Self {
        Self {
            err: Some(msg),
            ok_msg: String::new(),
            examined,
            failure_mode: Some("chain_integrity_violation".into()),
        }
    }
}

/// Group key for governance chains: (subject_actor_id_hex OR subject_human_id_uuid, scope).
type ChainKey = (String, String);

fn governance_chain_key(ge: &GovernanceEvent) -> ChainKey {
    let subject = ge
        .subject_actor_id_hex
        .clone()
        .unwrap_or_else(|| ge.subject_human_id.map(|u| u.to_string()).unwrap_or_default());
    (subject, ge.authority_scope.clone())
}

fn tip_chain_key(tip: &crate::bundle::GovernanceChainTip) -> ChainKey {
    let subject = tip
        .subject_actor_id_hex
        .clone()
        .unwrap_or_else(|| tip.subject_human_id.map(|u| u.to_string()).unwrap_or_default());
    (subject, tip.authority_scope.clone())
}

fn check_authority_temporal_validity(
    bundle: &ReplayBundle,
    opts: VerifyOptions<'_>,
) -> Check11Result {
    // ── PHASE 1: authority_state_after self-consistency ──────────────────
    // If a governance event declares authority_state_after, it must agree
    // with the event_kind. Classified as chain_integrity_violation.
    for ge in &bundle.governance_events {
        if let Some(ref stated) = ge.authority_state_after {
            let derived = match ge.event_kind.as_str() {
                "authority_delegation" => "delegated",
                "authority_revocation" => "revoked",
                _ => "?",
            };
            if stated != derived {
                return Check11Result::fail_integrity(
                    format!(
                        "governance_event {} declares authority_state_after='{}' but \
                         event_kind='{}' implies '{}'",
                        ge.event_id, stated, ge.event_kind, derived
                    ),
                    bundle.governance_events.len(),
                );
            }
        }
        // Subject must be exactly one of agent / human.
        match (ge.subject_actor_id_hex.is_some(), ge.subject_human_id.is_some()) {
            (true, false) | (false, true) => {}
            (false, false) => {
                return Check11Result::fail_integrity(
                    format!(
                        "governance_event {} has no subject (neither subject_actor_id_hex nor subject_human_id set)",
                        ge.event_id
                    ),
                    bundle.governance_events.len(),
                );
            }
            (true, true) => {
                return Check11Result::fail_integrity(
                    format!(
                        "governance_event {} sets both subject_actor_id_hex AND subject_human_id; exactly one MUST be set",
                        ge.event_id
                    ),
                    bundle.governance_events.len(),
                );
            }
        }
    }

    // ── PHASE 2: chain hash recompute per (subject, scope) ───────────────
    // Group events by chain key, sort within group by effective_at, walk
    // each chain verifying:
    //   - first event: prior_event_hash_hex MUST be absent
    //   - subsequent: prior_event_hash_hex MUST equal previous event's
    //                 this_event_hash_hex
    //   - this_event_hash_hex MUST equal SHA3-256(prior || receipt)
    let mut chains: HashMap<ChainKey, Vec<&GovernanceEvent>> = HashMap::new();
    for ge in &bundle.governance_events {
        chains.entry(governance_chain_key(ge)).or_default().push(ge);
    }
    for (key, events) in chains.iter_mut() {
        events.sort_by(|a, b| a.effective_at.cmp(&b.effective_at));
        let mut prior_hex: Option<String> = None;
        for (i, ge) in events.iter().enumerate() {
            // (a) first event's prior_event_hash_hex MUST be None.
            if i == 0 {
                if ge.prior_event_hash_hex.is_some() {
                    return Check11Result::fail_integrity(
                        format!(
                            "governance chain ({}, {}) first event {} sets prior_event_hash_hex \
                             but the first event in a chain MUST omit it",
                            key.0, key.1, ge.event_id
                        ),
                        bundle.governance_events.len(),
                    );
                }
            } else {
                // (b) prior_event_hash_hex MUST link to previous event.
                let stated_prior = ge.prior_event_hash_hex.as_deref().unwrap_or("");
                let expected_prior = prior_hex.as_deref().unwrap_or("");
                if stated_prior != expected_prior {
                    return Check11Result::fail_integrity(
                        format!(
                            "governance chain ({}, {}) event {} prior_event_hash_hex={} \
                             does not match preceding event's this_event_hash_hex={} \
                             (chain discontinuity — event may have been inserted, removed, or reordered)",
                            key.0, key.1, ge.event_id, stated_prior, expected_prior
                        ),
                        bundle.governance_events.len(),
                    );
                }
            }
            // (c) recompute this_event_hash_hex.
            let receipt_bytes = match hex::decode(&ge.receipt_hex) {
                Ok(b) if b.len() == 74 => b,
                Ok(_) | Err(_) => {
                    return Check11Result::fail_integrity(
                        format!(
                            "governance_event {} receipt_hex is not a valid 74-byte hex string",
                            ge.event_id
                        ),
                        bundle.governance_events.len(),
                    );
                }
            };
            let prior_bytes: Option<[u8; 32]> = match ge.prior_event_hash_hex.as_deref() {
                None => None,
                Some(h) => match hex::decode(h) {
                    Ok(b) if b.len() == 32 => {
                        let mut a = [0u8; 32];
                        a.copy_from_slice(&b);
                        Some(a)
                    }
                    _ => {
                        return Check11Result::fail_integrity(
                            format!(
                                "governance_event {} prior_event_hash_hex is not a valid 32-byte hex string",
                                ge.event_id
                            ),
                            bundle.governance_events.len(),
                        );
                    }
                },
            };
            let receipt_arr: [u8; 74] = receipt_bytes.as_slice().try_into().unwrap();
            let recomputed = compute_chain_hash(prior_bytes, &receipt_arr);
            let recomputed_hex = hex::encode(recomputed);
            if recomputed_hex != ge.this_event_hash_hex {
                return Check11Result::fail_integrity(
                    format!(
                        "governance_event {} this_event_hash_hex={} does not recompute from prior+receipt (got {})",
                        ge.event_id, ge.this_event_hash_hex, recomputed_hex
                    ),
                    bundle.governance_events.len(),
                );
            }
            prior_hex = Some(ge.this_event_hash_hex.clone());
        }
    }

    // ── PHASE 3: chain tip attestation integrity ─────────────────────────
    // If governance_chain_tips is non-empty, each tip MUST match a chain
    // we just reconstructed — same terminal hash AND same event count.
    // This closes the "remove the trailing revocation" omission attack.
    for tip in &bundle.governance_chain_tips {
        let key = tip_chain_key(tip);
        match chains.get(&key) {
            None => {
                return Check11Result::fail_integrity(
                    format!(
                        "governance_chain_tips entry for (subject={}, scope={}) references a chain \
                         with no events — likely all events were removed; tip claims terminal={} count={}",
                        key.0, key.1, tip.terminal_event_hash_hex, tip.event_count
                    ),
                    bundle.governance_events.len(),
                );
            }
            Some(events) => {
                let actual_terminal = events.last().map(|e| &e.this_event_hash_hex);
                let actual_count = events.len() as u32;
                if actual_terminal != Some(&tip.terminal_event_hash_hex) {
                    return Check11Result::fail_integrity(
                        format!(
                            "governance_chain_tips entry (subject={}, scope={}) claims terminal_event_hash_hex={} \
                             but reconstructed chain ends at {} \
                             (a trailing event was likely removed)",
                            key.0,
                            key.1,
                            tip.terminal_event_hash_hex,
                            actual_terminal.map(|s| s.as_str()).unwrap_or("<empty>")
                        ),
                        bundle.governance_events.len(),
                    );
                }
                if actual_count != tip.event_count {
                    return Check11Result::fail_integrity(
                        format!(
                            "governance_chain_tips entry (subject={}, scope={}) claims event_count={} \
                             but reconstructed chain has {} event(s)",
                            key.0, key.1, tip.event_count, actual_count
                        ),
                        bundle.governance_events.len(),
                    );
                }
            }
        }
    }

    // ── PHASE 4: temporal validity of authority-scoped actions ───────────
    let scoped_actions: Vec<&TimelineEntry> = bundle
        .timeline
        .entries
        .iter()
        .filter(|e| e.event_kind == "action" && e.requires_authority_scope.is_some())
        .collect();

    if scoped_actions.is_empty() {
        let msg = if bundle.governance_events.is_empty() {
            "no authority-scoped actions; governance graph empty".to_string()
        } else {
            format!(
                "no authority-scoped actions; governance graph has {} event(s) (chain integrity OK)",
                bundle.governance_events.len()
            )
        };
        return Check11Result::pass(msg, bundle.governance_events.len());
    }

    if bundle.governance_events.is_empty() {
        if opts.strict {
            return Check11Result::fail_integrity(
                format!(
                    "{} action(s) declare requires_authority_scope but governance_events is empty \
                     (strict mode requires an audit trail for any claimed authority)",
                    scoped_actions.len()
                ),
                scoped_actions.len(),
            );
        } else {
            return Check11Result::pass(
                format!(
                    "WARN: {} action(s) declare requires_authority_scope but governance_events is empty \
                     (non-strict mode: passing; re-run with --strict to fail)",
                    scoped_actions.len()
                ),
                scoped_actions.len(),
            );
        }
    }

    // Walk each authority-scoped action and evaluate the state machine.
    for action in &scoped_actions {
        let action_subject: Option<&str> = action.agent_id_hex.as_deref();
        if action_subject.is_none() {
            return Check11Result::fail_integrity(
                format!(
                    "action {} declares requires_authority_scope but has no agent_id_hex \
                     (v0.2 governance graph requires an agent subject)",
                    action.event_id
                ),
                scoped_actions.len(),
            );
        }
        let scope = action.requires_authority_scope.as_deref().unwrap();
        let action_ts = &action.timestamp;

        let mut candidates: Vec<&GovernanceEvent> = bundle
            .governance_events
            .iter()
            .filter(|ge| {
                ge.authority_scope == scope
                    && ge.subject_actor_id_hex.as_deref() == action_subject
                    && ge.effective_at.as_str() <= action_ts.as_str()
            })
            .collect();
        candidates.sort_by(|a, b| a.effective_at.cmp(&b.effective_at));

        match candidates.last() {
            None => {
                return Check11Result::fail_temporal(
                    format!(
                        "action {} at {} by actor {} requires authority scope '{}' \
                         but no governance event for that subject+scope exists at or before action time",
                        action.event_id,
                        action_ts,
                        action_subject.unwrap(),
                        scope
                    ),
                    scoped_actions.len(),
                );
            }
            Some(ge) if ge.event_kind == "authority_delegation" => {
                // PASS for this action; continue.
            }
            Some(ge) if ge.event_kind == "authority_revocation" => {
                return Check11Result::fail_temporal(
                    format!(
                        "action {} at {} by actor {} used scope '{}' AFTER authority was revoked at {} \
                         (governance event {})",
                        action.event_id,
                        action_ts,
                        action_subject.unwrap(),
                        scope,
                        ge.effective_at,
                        ge.event_id
                    ),
                    scoped_actions.len(),
                );
            }
            Some(ge) => {
                return Check11Result::fail_integrity(
                    format!(
                        "action {} references governance event {} with unrecognized event_kind '{}'",
                        action.event_id, ge.event_id, ge.event_kind
                    ),
                    scoped_actions.len(),
                );
            }
        }
    }

    Check11Result::pass(
        format!(
            "all {} authority-scoped action(s) had effective authority at action time; \
             {} governance event(s) chain integrity verified",
            scoped_actions.len(),
            bundle.governance_events.len()
        ),
        scoped_actions.len(),
    )
}
