//! End-to-end integration tests for the signed-verification-report flow.
//!
//! Each test exercises the full surface across the public API of
//! `h33_replay_verify_core` + `h33_replay_verify` so
//! a regression in any of the three modules trips here, not weeks later in
//! the CLI.
//!
//! Spec: docs/specs/h33-signed-verify-report-v0.1.md

use h33_replay_verify_core::bundle::ReplayBundle;
use h33_replay_verify::signed_transcript::{
    sha3_256_hex, sign_report, verify_signed_report, SignedReport, SignedTranscriptError,
    ENVELOPE_VERSION, SIGNATURE_ALGORITHM, SIGNED_PAYLOAD_DOMAIN,
};
use h33_replay_verify::verifier_identity::load_or_create;
use h33_replay_verify_core::verify::{verify, VerifyOptions};

const REAL_BUNDLE: &str = "tests/fixtures/real-case-bundle-v0.1.json";

fn load_real_bundle() -> (ReplayBundle, Vec<u8>) {
    let bytes = std::fs::read(REAL_BUNDLE).expect("read fixture");
    let bundle: ReplayBundle = serde_json::from_slice(&bytes).expect("parse fixture");
    (bundle, bytes)
}

#[test]
fn real_fixture_passes_then_signs_then_round_trip_verifies() {
    let (bundle, bytes) = load_real_bundle();
    let report = verify(&bundle, VerifyOptions { payloads_dir: None, strict: false });
    assert!(report.passed, "real fixture must PASS at the report level first");

    let tmp = tempfile::tempdir().expect("tempdir");
    let id = load_or_create(&tmp.path().join("keys")).expect("identity");
    assert!(id.freshly_created);

    let envelope = sign_report(
        report,
        &bytes,
        &id.secret_key,
        &id.public_key,
        "2026-05-26T12:34:56Z".to_string(),
    )
    .expect("sign");

    assert_eq!(envelope.envelope_version, ENVELOPE_VERSION);
    assert_eq!(envelope.signed_transcript.signature_algorithm, SIGNATURE_ALGORITHM);
    assert_eq!(envelope.signed_transcript.bundle_sha3_256_hex, sha3_256_hex(&bytes));

    let payload = verify_signed_report(&envelope).expect("verify_signed_report");
    assert_eq!(payload.domain, SIGNED_PAYLOAD_DOMAIN);
    assert!(payload.passed);
    assert_eq!(payload.bundle_sha3_256_hex, sha3_256_hex(&bytes));
    assert_eq!(payload.checks.len(), 10);
}

#[test]
fn json_round_trip_through_disk_preserves_signature() {
    // Simulates: verifier writes signed.json → counterparty reads it → verifies.
    let (bundle, bytes) = load_real_bundle();
    let report = verify(&bundle, VerifyOptions { payloads_dir: None, strict: false });

    let tmp = tempfile::tempdir().expect("tempdir");
    let id = load_or_create(&tmp.path().join("keys")).expect("identity");
    let envelope = sign_report(
        report,
        &bytes,
        &id.secret_key,
        &id.public_key,
        "2026-05-26T12:34:56Z".to_string(),
    )
    .expect("sign");

    let path = tmp.path().join("signed.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();

    let raw = std::fs::read_to_string(&path).unwrap();
    let reloaded: SignedReport = serde_json::from_str(&raw).expect("reload");
    let payload = verify_signed_report(&reloaded).expect("verify after reload");
    assert!(payload.passed);
    assert_eq!(payload.bundle_sha3_256_hex, sha3_256_hex(&bytes));
}

#[test]
fn flipping_envelope_passed_field_does_not_fool_external_verifier() {
    // The envelope's `report` field is INSPECTION ONLY — trust flows through
    // the signed payload. Tampering with `envelope.report.passed` to "true"
    // when the signed payload says false must NOT change what a third-party
    // verifier reports.
    let (bundle, bytes) = load_real_bundle();
    let report = verify(&bundle, VerifyOptions { payloads_dir: None, strict: false });
    let tmp = tempfile::tempdir().expect("tempdir");
    let id = load_or_create(&tmp.path().join("keys")).expect("identity");

    // Sign a forged FALSE report so the signed payload says passed=false.
    let mut forged = report.clone();
    forged.passed = false;
    let mut envelope = sign_report(
        forged,
        &bytes,
        &id.secret_key,
        &id.public_key,
        "2026-05-26T12:34:56Z".to_string(),
    )
    .expect("sign");

    // Attacker flips the human-readable mirror back to true.
    envelope.report.passed = true;

    // Trusted verification recovers the truth from the signed payload.
    let payload = verify_signed_report(&envelope).expect("still verifies");
    assert!(!payload.passed, "trust must flow through signed payload, not the mirror");
}

#[test]
fn tampered_signed_payload_bytes_fail_signature() {
    let (bundle, bytes) = load_real_bundle();
    let report = verify(&bundle, VerifyOptions { payloads_dir: None, strict: false });
    let tmp = tempfile::tempdir().expect("tempdir");
    let id = load_or_create(&tmp.path().join("keys")).expect("identity");
    let mut envelope = sign_report(
        report,
        &bytes,
        &id.secret_key,
        &id.public_key,
        "2026-05-26T12:34:56Z".to_string(),
    )
    .expect("sign");

    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut payload_bytes = b64.decode(&envelope.signed_transcript.signed_payload_b64).unwrap();
    payload_bytes[0] ^= 0x01;
    envelope.signed_transcript.signed_payload_b64 = b64.encode(&payload_bytes);
    envelope.signed_transcript.signed_payload_sha3_256_hex = sha3_256_hex(&payload_bytes);

    let err = verify_signed_report(&envelope).unwrap_err();
    assert!(
        matches!(err, SignedTranscriptError::VerificationFailed
                    | SignedTranscriptError::PayloadNotJson),
        "tampering signed payload must fail signature check, got: {err:?}",
    );
}

#[test]
fn second_run_reuses_persisted_identity_so_fingerprint_is_stable() {
    let (bundle, bytes) = load_real_bundle();
    let report1 = verify(&bundle, VerifyOptions { payloads_dir: None, strict: false });
    let report2 = report1.clone();
    let tmp = tempfile::tempdir().expect("tempdir");
    let kd = tmp.path().join("keys");

    let id1 = load_or_create(&kd).expect("first");
    assert!(id1.freshly_created);
    let env1 = sign_report(report1, &bytes, &id1.secret_key, &id1.public_key,
                           "2026-05-26T12:00:00Z".into()).unwrap();

    let id2 = load_or_create(&kd).expect("second");
    assert!(!id2.freshly_created, "second call must reload, not regenerate");
    let env2 = sign_report(report2, &bytes, &id2.secret_key, &id2.public_key,
                           "2026-05-26T12:30:00Z".into()).unwrap();

    assert_eq!(
        env1.signed_transcript.verifier_public_key_fingerprint_hex,
        env2.signed_transcript.verifier_public_key_fingerprint_hex,
        "verifier identity must be stable across runs",
    );
}
