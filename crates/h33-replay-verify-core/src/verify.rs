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
use crate::bundle::{schema_hash, ReplayBundle, TimelineEntry};
use crate::chain::compute_chain_hash;

/// Supported bundle version majors. Verifier rejects unknown majors.
const SUPPORTED_VERSIONS: &[&str] = &["0.1"];

/// This verifier's own version. Compared against bundle's verifier_min_version.
pub const VERIFIER_VERSION: &str = "0.2.0";

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
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub check: CheckId,
    pub passed: bool,
    /// If passed = false: the reason. If passed = true and strict matters: notes.
    pub message: String,
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
    let expected_hash = schema_hash();
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

    report
}

fn record(report: &mut VerifyReport, check: CheckId, passed: bool, message: String, examined: usize) {
    if !passed { report.passed = false; }
    report.checks.push(CheckResult { check, passed, message, examined });
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
