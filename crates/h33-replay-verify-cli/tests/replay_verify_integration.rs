//! End-to-end CLI tests for h33-replay-verify.
//!
//! Builds synthetic bundles with correctly-computed hashes (PASS) and
//! deliberately-broken bundles (FAIL), runs the CLI as a subprocess, and
//! asserts exit codes + JSON envelope shape.
//!
//! Per the spec contract:
//!   exit 0 = PASS
//!   exit 1 = FAIL
//!   exit 2 = malformed input / read error
//!
//! These tests are also the canonical fixtures the spec references.

use sha3::{Digest, Sha3_256};
use std::path::PathBuf;
use std::process::Command;

use h33_replay_verify_core::chain::compute_chain_hash;
use h33_replay_verify_core::bundle::{schema_hash, VERIFIER_MIN_VERSION};
use h33_replay_verify_core::binding::{compute_verification_hash, ActorRef, BindingContext};

const BUNDLE_VERSION: &str = "0.1";

fn cargo_bin() -> PathBuf {
    // CARGO_BIN_EXE_<name> is set by Cargo when the test binary is built.
    PathBuf::from(env!("CARGO_BIN_EXE_h33-replay-verify"))
}

fn run_verifier(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(cargo_bin())
        .args(args)
        .output()
        .expect("spawn h33-replay-verify");
    let code = output.status.code().expect("exit code");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

// ─────────────────────────────────────────────────────────────────────────────
// Fixture builders
// ─────────────────────────────────────────────────────────────────────────────

fn sha3_32(input: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(input);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Build a self-consistent PASS bundle with:
///   - 1 case
///   - 1 agent
///   - 1 session with 2 actions (chained correctly)
///   - 1 frame referencing both actions
///   - 1 substrate binding with correctly-computed verification_hash
fn build_pass_bundle_json() -> String {
    let tenant_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let case_id = "33333333-3333-3333-3333-333333333333";
    let session_id = "44444444-4444-4444-4444-444444444444";
    let action_1_id = "11111111-1111-1111-1111-111111111111";
    let action_2_id = "22222222-2222-2222-2222-222222222222";
    let frame_id = "55555555-5555-5555-5555-555555555555";
    let binding_id = "66666666-6666-6666-6666-666666666666";
    let agent_hex = "aa".repeat(32);
    let receipt = [0x11u8; 74];
    let receipt_hex = hex::encode(receipt);

    // Per-session chain
    let h1 = compute_chain_hash(None, &receipt);
    let h2 = compute_chain_hash(Some(h1), &receipt);

    // Continuity hash is opaque to the verifier (check #6 only asserts case == timeline).
    let continuity = sha3_32(b"pass-bundle-continuity-v01");
    let continuity_hex = hex::encode(continuity);

    // Substrate binding — compute verification_hash deterministically
    let signing_message: [u8; 74] = [0xccu8; 74];
    let mut agent_id_bytes = [0u8; 32];
    hex::decode_to_slice(&agent_hex, &mut agent_id_bytes).unwrap();
    let ctx = BindingContext {
        signing_message,
        tenant_id: tenant_id.parse().unwrap(),
        actor: ActorRef::Agent { agent_id: agent_id_bytes },
        case_id: Some(case_id.parse().unwrap()),
        attributes: vec![("k1".into(), "v1".into())],
    };
    let vh = compute_verification_hash(&ctx);

    serde_json::json!({
        "version": BUNDLE_VERSION,
        "export_metadata": {
            "exported_at": "2026-05-26T00:00:00Z",
            "exporter_principal_kind": "tenant_user",
            "exporter_tenant_id": tenant_id,
            "case_id": case_id,
            "bundle_version": BUNDLE_VERSION,
            "schema_hash": schema_hash(),
            "verifier_min_version": VERIFIER_MIN_VERSION,
        },
        "tenant_id": tenant_id,
        "case_id": case_id,
        "case": {
            "case_number": "FIX-PASS-001",
            "title": "synthetic PASS fixture",
            "case_type": "claim",
            "status": "in_review",
            "priority": "normal",
            "severity": "moderate",
            "opened_by_human_id": "00000000-0000-0000-0000-000000000001",
            "assigned_human_id": null,
            "continuity_hash_hex": continuity_hex,
            "predecessor_hash_hex": null,
            "evidence_bundle_root_hex": null,
            "created_at": "2026-05-26T00:00:00Z",
            "closed_at": null
        },
        "agents": [{
            "agent_id_hex": agent_hex,
            "canonical_name": "fix.bot",
            "display_name": "Fixture Bot",
            "agent_type": "autonomous",
            "tier_depth": 0,
            "status": "active",
            "parent_agent_id_hex": null
        }],
        "humans": [],
        "timeline": {
            "continuity_hash_hex": continuity_hex,
            "evidence_bundle_root_hex": null,
            "entries": [
                {
                    "event_kind": "action",
                    "event_id": action_1_id,
                    "session_id": session_id,
                    "sequence_in_session": 0,
                    "action_kind": "tool_call",
                    "proof_kind": null,
                    "commitment_hex": hex::encode(h1),
                    "receipt_hex": receipt_hex,
                    "timestamp": "2026-05-26T00:00:01Z",
                    "agent_id_hex": agent_hex,
                    "prior_action_hash_hex": null
                },
                {
                    "event_kind": "action",
                    "event_id": action_2_id,
                    "session_id": session_id,
                    "sequence_in_session": 1,
                    "action_kind": "llm_completion",
                    "proof_kind": null,
                    "commitment_hex": hex::encode(h2),
                    "receipt_hex": receipt_hex,
                    "timestamp": "2026-05-26T00:00:02Z",
                    "agent_id_hex": agent_hex,
                    "prior_action_hash_hex": hex::encode(h1)
                }
            ]
        },
        "frames": [{
            "frame_id": frame_id,
            "frame_scope": "session",
            "snapshot_kind": "on_demand",
            "frame_root_hash_hex": hex::encode([0xaau8; 32]),
            "frame_receipt_hex": hex::encode([0xbbu8; 74]),
            "frame_blob_ref": null,
            "frame_size_bytes": 0,
            "created_at": "2026-05-26T00:00:03Z",
            "action_ids": [action_1_id, action_2_id],
            "proof_ids": []
        }],
        "evidence_bundles": [],
        "substrate_bindings": [{
            "binding_id": binding_id,
            "signing_message_hex": hex::encode(signing_message),
            "tenant_id": tenant_id,
            "actor_kind": "agent",
            "agent_id_hex": agent_hex,
            "human_id": null,
            "case_id": case_id,
            "verification_hash_hex": hex::encode(vh),
            "attributes": [["k1", "v1"]],
            "bound_at": "2026-05-26T00:00:00Z"
        }],
        "verifier_artifact_refs": ["h33-pq-verify@v2.1", "h33-zk-verify@v3.0/lookup"]
    }).to_string()
}

/// Build a FAIL bundle: tamper with one action's commitment_hex so chain
/// recompute fails.
fn build_fail_bundle_json() -> String {
    let pass = build_pass_bundle_json();
    let mut value: serde_json::Value = serde_json::from_str(&pass).unwrap();
    // Corrupt action 2's commitment_hex — flip one byte.
    let bad = "deadbeef".to_string() + &"00".repeat(28); // 64 chars, wrong hash
    value["timeline"]["entries"][1]["commitment_hex"] = serde_json::json!(bad);
    value.to_string()
}

/// Build a cross-tenant FAIL bundle: binding's tenant_id differs from bundle.tenant_id.
fn build_cross_tenant_fail_bundle_json() -> String {
    let pass = build_pass_bundle_json();
    let mut value: serde_json::Value = serde_json::from_str(&pass).unwrap();
    value["substrate_bindings"][0]["tenant_id"] =
        serde_json::json!("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
    value.to_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pass_bundle_exits_0() {
    let bundle = build_pass_bundle_json();
    let path = std::env::temp_dir().join("h33-replay-pass.json");
    std::fs::write(&path, &bundle).unwrap();

    let (code, stdout, stderr) = run_verifier(&[path.to_str().unwrap()]);
    assert_eq!(code, 0, "expected exit 0 (PASS), got {}\nstdout: {}\nstderr: {}", code, stdout, stderr);

    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("stdout not JSON: {}\n{}", e, stdout)
    });
    assert_eq!(report["passed"], serde_json::Value::Bool(true), "report.passed should be true");
    assert_eq!(report["bundle_version"], "0.1");

    // Every check entry has passed=true
    let checks = report["checks"].as_array().unwrap();
    assert!(!checks.is_empty(), "checks empty");
    for c in checks {
        assert_eq!(c["passed"], serde_json::Value::Bool(true),
            "check {:?} failed unexpectedly: {}", c["check"], c["message"]);
    }
}

#[test]
fn fail_bundle_tampered_chain_exits_1() {
    let bundle = build_fail_bundle_json();
    let path = std::env::temp_dir().join("h33-replay-fail-chain.json");
    std::fs::write(&path, &bundle).unwrap();

    let (code, stdout, _stderr) = run_verifier(&[path.to_str().unwrap()]);
    assert_eq!(code, 1, "expected exit 1 (FAIL), got {}", code);

    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["passed"], serde_json::Value::Bool(false));

    // The receipt_commitments check should be the one that failed
    let checks = report["checks"].as_array().unwrap();
    let receipt_check = checks.iter()
        .find(|c| c["check"] == "receipt_commitments")
        .expect("receipt_commitments check present");
    assert_eq!(receipt_check["passed"], serde_json::Value::Bool(false));
}

#[test]
fn fail_bundle_cross_tenant_exits_1() {
    let bundle = build_cross_tenant_fail_bundle_json();
    let path = std::env::temp_dir().join("h33-replay-fail-tenant.json");
    std::fs::write(&path, &bundle).unwrap();

    let (code, stdout, _stderr) = run_verifier(&[path.to_str().unwrap()]);
    assert_eq!(code, 1, "expected exit 1 (FAIL), got {}", code);

    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["passed"], serde_json::Value::Bool(false));
    let scope_check = report["checks"].as_array().unwrap().iter()
        .find(|c| c["check"] == "same_scope_isolation")
        .expect("same_scope_isolation check present");
    assert_eq!(scope_check["passed"], serde_json::Value::Bool(false));
}

#[test]
fn unreadable_bundle_exits_2() {
    let (code, _stdout, stderr) = run_verifier(&["/tmp/h33-replay-does-not-exist.json"]);
    assert_eq!(code, 2, "expected exit 2 (ERROR), got {}\nstderr: {}", code, stderr);
    assert!(stderr.contains("read_bundle"), "expected read_bundle error code in stderr: {}", stderr);
}

#[test]
fn malformed_json_exits_2() {
    let path = std::env::temp_dir().join("h33-replay-malformed.json");
    std::fs::write(&path, "{ this is not json").unwrap();

    let (code, _stdout, stderr) = run_verifier(&[path.to_str().unwrap()]);
    assert_eq!(code, 2, "expected exit 2 (ERROR), got {}", code);
    assert!(stderr.contains("parse_bundle"), "expected parse_bundle error in stderr: {}", stderr);
}

/// CI lock: the committed real-case fixture (captured from an actual
/// running scif-backend hitting the seeded scif_fe_smoke DB) MUST verify
/// PASS on every build. Drift in the exporter, the verifier, the
/// chain-hash primitive, or the substrate verification_hash algorithm
/// will fail this test.
///
/// Regenerate with:
///   ./target/release/h33-xeon-api  (with H33_SERVICE_REPLAYEXPORT_KEY set)
///   curl -H "X-API-Key: ..." http://localhost:8080/api/v1/spine/cases/<id>/replay/bundle/v0.1 \
///        > tests/fixtures/real-case-bundle-v0.1.json
#[test]
fn real_case_fixture_verifies_pass() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/real-case-bundle-v0.1.json");
    assert!(fixture.exists(), "real fixture missing: {}", fixture.display());

    let (code, stdout, _stderr) = run_verifier(&[fixture.to_str().unwrap()]);
    assert_eq!(code, 0, "real fixture must PASS — got exit {}\n{}", code, stdout);

    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["passed"], serde_json::Value::Bool(true));
    // Sanity: the fixture is the v0.1 shape with the expected verifier_min_version
    assert_eq!(report["bundle_version"], "0.1");
    // Every individual check passes
    for c in report["checks"].as_array().unwrap() {
        assert_eq!(c["passed"], serde_json::Value::Bool(true),
            "real-case fixture check {:?} regressed: {}", c["check"], c["message"]);
    }
}

#[test]
fn strict_mode_without_payloads_fails_merkle_check() {
    // PASS bundle has no frame_blob_ref, so check #3 normally skips.
    // In --strict mode, the skip becomes a failure... unless every frame has
    // null frame_blob_ref (then there's nothing to fail on). Let's add a
    // blob_ref pointing nowhere to force the failure path.
    let mut bundle: serde_json::Value = serde_json::from_str(&build_pass_bundle_json()).unwrap();
    bundle["frames"][0]["frame_blob_ref"] = serde_json::json!("nowhere/missing.bin");
    let path = std::env::temp_dir().join("h33-replay-strict.json");
    std::fs::write(&path, bundle.to_string()).unwrap();

    let (code, _stdout, _stderr) = run_verifier(&[path.to_str().unwrap(), "--strict"]);
    assert_eq!(code, 1, "strict mode with missing payloads should FAIL, got {}", code);
}

// ─────────────────────────────────────────────────────────────────────────────
// v0.2 — Tokenize the World demo bundles
//
// The four scenarios that drive the public demo's emotional payload:
//   - happy:    action BEFORE revocation, chain intact, tip matches → PASS
//   - temporal: action AFTER revocation                              → FAIL temporal_violation
//   - omission: revocation event removed (tip no longer matches)     → FAIL chain_integrity_violation
//   - tamper:   this_event_hash_hex rewritten                        → FAIL chain_integrity_violation
//
// Each test asserts exit code AND the failure_mode tag so the demo UI can
// render distinct error messaging per fraud class.
// ─────────────────────────────────────────────────────────────────────────────

fn demo_fixture(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("fixtures");
    p.push(name);
    p
}

fn run_and_parse(args: &[&str]) -> (i32, serde_json::Value) {
    let (code, stdout, _) = run_verifier(args);
    let report: serde_json::Value =
        serde_json::from_str(&stdout).expect("verifier stdout is JSON");
    (code, report)
}

fn check_11<'a>(report: &'a serde_json::Value) -> &'a serde_json::Value {
    report["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .find(|c| c["check"] == "authority_temporal_validity")
        .expect("check #11 present in report")
}

#[test]
fn v0_2_happy_bundle_passes_all_eleven_checks() {
    let fx = demo_fixture("tokenize-the-world-happy-bundle-v0.2.json");
    assert!(fx.exists(), "happy fixture missing: {}", fx.display());

    let (code, report) = run_and_parse(&[fx.to_str().unwrap()]);
    assert_eq!(code, 0, "happy v0.2 bundle must PASS, got exit {}", code);
    assert_eq!(report["passed"], serde_json::Value::Bool(true));
    assert_eq!(report["bundle_version"], "0.2");

    let c11 = check_11(&report);
    assert_eq!(c11["passed"], serde_json::Value::Bool(true));
    assert!(
        c11["failure_mode"].is_null(),
        "happy bundle must not set failure_mode; got {}",
        c11["failure_mode"]
    );
}

#[test]
fn v0_2_fraud_temporal_violation_caught_with_correct_failure_mode() {
    let fx = demo_fixture("tokenize-the-world-fraud-bundle-v0.2.json");
    assert!(fx.exists(), "fraud fixture missing: {}", fx.display());

    let (code, report) = run_and_parse(&[fx.to_str().unwrap()]);
    assert_eq!(code, 1, "temporal fraud must FAIL, got exit {}", code);
    assert_eq!(report["passed"], serde_json::Value::Bool(false));

    let c11 = check_11(&report);
    assert_eq!(c11["passed"], serde_json::Value::Bool(false));
    assert_eq!(
        c11["failure_mode"], "temporal_violation",
        "temporal fraud must tag failure_mode='temporal_violation', got {}",
        c11["failure_mode"]
    );
    let msg = c11["message"].as_str().unwrap();
    assert!(
        msg.contains("AFTER authority was revoked"),
        "temporal failure message must clearly describe the post-revocation use: {}",
        msg
    );

    // All OTHER checks must still PASS — only #11 fails. This is what makes
    // the demo land: the bundle looks structurally valid; only replay catches
    // the timing fraud.
    for c in report["checks"].as_array().unwrap() {
        if c["check"] != "authority_temporal_validity" {
            assert_eq!(
                c["passed"], serde_json::Value::Bool(true),
                "temporal fraud must not also break check {:?}: {}",
                c["check"], c["message"]
            );
        }
    }
}

#[test]
fn v0_2_fraud_omission_caught_by_chain_tip_integrity() {
    // Attack: take the happy bundle, remove the revocation event. The
    // remaining chain (just delegation) is internally valid by itself, so
    // chain-hash recompute passes. The chain_tip attestation is what
    // catches the omission — its claimed terminal hash + event_count no
    // longer match the reconstructed chain.
    let happy = demo_fixture("tokenize-the-world-happy-bundle-v0.2.json");
    let mut bundle: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&happy).unwrap()).unwrap();
    let events: Vec<serde_json::Value> = bundle["governance_events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["event_kind"] != "authority_revocation")
        .cloned()
        .collect();
    bundle["governance_events"] = serde_json::Value::Array(events);

    let path = std::env::temp_dir().join("h33-demo-omission-attack.json");
    std::fs::write(&path, bundle.to_string()).unwrap();

    let (code, report) = run_and_parse(&[path.to_str().unwrap()]);
    assert_eq!(code, 1, "omission attack must FAIL, got exit {}", code);

    let c11 = check_11(&report);
    assert_eq!(c11["failure_mode"], "chain_integrity_violation",
        "omission must tag chain_integrity_violation; got {}", c11["failure_mode"]);
    let msg = c11["message"].as_str().unwrap();
    assert!(
        msg.contains("governance_chain_tips"),
        "omission failure must reference chain-tip mismatch: {}",
        msg
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn v0_2_fraud_chain_tamper_caught_by_hash_recompute() {
    // Attack: take the happy bundle, rewrite the revocation event's
    // this_event_hash_hex to a bogus value. Hash-recompute catches the
    // discrepancy regardless of the chain_tip attestation.
    let happy = demo_fixture("tokenize-the-world-happy-bundle-v0.2.json");
    let mut bundle: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&happy).unwrap()).unwrap();
    bundle["governance_events"][1]["this_event_hash_hex"] =
        serde_json::Value::String("00".repeat(32));

    let path = std::env::temp_dir().join("h33-demo-tamper-attack.json");
    std::fs::write(&path, bundle.to_string()).unwrap();

    let (code, report) = run_and_parse(&[path.to_str().unwrap()]);
    assert_eq!(code, 1, "tamper attack must FAIL, got exit {}", code);

    let c11 = check_11(&report);
    assert_eq!(c11["failure_mode"], "chain_integrity_violation",
        "tamper must tag chain_integrity_violation; got {}", c11["failure_mode"]);
    let msg = c11["message"].as_str().unwrap();
    assert!(
        msg.contains("does not recompute from prior+receipt"),
        "tamper failure must reference hash recompute: {}",
        msg
    );

    std::fs::remove_file(&path).ok();
}

/// The `--version` flag must report the crate version from Cargo.toml,
/// not a hardcoded string that can drift (regression guard for the
/// 0.2.0/0.3.0 mismatch).
#[test]
fn version_flag_reports_cargo_pkg_version() {
    let (code, stdout, stderr) = run_verifier(&["--version"]);
    assert_eq!(code, 0, "expected exit 0 for --version, got {}\nstderr: {}", code, stderr);
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "--version stdout {:?} must contain crate version {:?}",
        stdout,
        env!("CARGO_PKG_VERSION"),
    );
}
