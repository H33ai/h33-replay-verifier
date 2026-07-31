//! `h33-replay-verify` — independent offline verifier for SCIF replay bundles.
//!
//! Modes:
//!
//!   # Plain verify — JSON report to stdout, PASS/FAIL exit code.
//!   h33-replay-verify <bundle.json>
//!   h33-replay-verify <bundle.json> --payloads <dir>
//!   h33-replay-verify <bundle.json> --payloads <dir> --strict
//!
//!   # Verify AND sign the report with the verifier's persistent identity.
//!   # First run auto-creates an ML-DSA-65 keypair in --key-dir
//!   # (default: $HOME/.h33-replay-verify/keys). Output is a SignedReport
//!   # envelope containing the report + the cryptographic transcript.
//!   h33-replay-verify <bundle.json> --sign
//!   h33-replay-verify <bundle.json> --sign --key-dir <dir>
//!
//!   # Verify a previously-emitted SignedReport file (no bundle re-run).
//!   # Exit 0 iff the embedded ML-DSA-65 signature verifies and all
//!   # cross-checks pass.
//!   h33-replay-verify --verify-transcript <signed_report.json>
//!
//!   # Verify a bundle AND cross-check a signed transcript against it
//!   # (same envelope must describe this exact bundle hash + same PASS/FAIL).
//!   h33-replay-verify <bundle.json> --verify-transcript <signed_report.json>
//!
//! Exit codes:
//!   0 = PASS  (bundle verifies and, if signed, signature verifies)
//!   1 = FAIL  (one or more checks or the signature failed)
//!   2 = ERROR (file unreadable, JSON parse failure, invalid CLI args)
//!
//! Output: JSON to stdout, suitable for piping into `jq`.
//!
//! Specs:
//!   docs/specs/h33-replay-bundle-v0.1.md
//!   docs/specs/h33-signed-verify-report-v0.1.md
//!
//! Note: this binary does NOT verify the underlying cryptographic signatures
//! of receipts referenced inside the bundle (those are verified by the named
//! `verifier_artifact_refs` like `h33-pq-verify@v2.1`). It verifies the
//! bundle's INTERNAL CONSISTENCY — that hashes recompute, timelines order,
//! frames reference real events, continuity chains hold, and no rows cross
//! tenant/case boundaries. With --sign it additionally emits a signed
//! transcript binding its OWN verifier identity to that PASS/FAIL verdict.
//!
//! See `h33-verify` for primitive 74-byte H33 receipt verification.

use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

use h33_replay_verify::signed_transcript::{
    sha3_256_hex, sign_report, verify_signed_report, SignedReport,
};
use h33_replay_verify::verifier_identity::{load_or_create, resolve_key_dir};
use h33_replay_verify_core::bundle::ReplayBundle;
use h33_replay_verify_core::verify::{verify, VerifyOptions, VerifyReport};

#[derive(Parser, Debug)]
#[command(name = "h33-replay-verify")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Independent offline verifier for SCIF replay bundles (v0.1) — verify + optionally sign reports with persistent verifier identity (ML-DSA-65)")]
struct Cli {
    /// Path to the replay bundle JSON file. Optional when --verify-transcript
    /// is supplied; required otherwise.
    bundle: Option<PathBuf>,

    /// Optional directory containing sealed-storage blobs referenced by
    /// `frame_blob_ref` / `bundle_blob_ref`.
    #[arg(long)]
    payloads: Option<PathBuf>,

    /// If set, skipped checks (e.g. missing --payloads dir, unknown verifier
    /// refs) FAIL the run instead of passing with a warning.
    #[arg(long)]
    strict: bool,

    /// Sign the verify report with the verifier's persistent ML-DSA-65
    /// identity. Output becomes a SignedReport envelope, not a plain report.
    #[arg(long)]
    sign: bool,

    /// Directory holding the verifier's identity keys (`identity.public.b64`
    /// + `identity.secret.b64`). Created on first --sign use. Defaults
    /// to `$H33_REPLAY_VERIFY_KEY_DIR` if set, else
    /// `$HOME/.h33-replay-verify/keys`.
    #[arg(long)]
    key_dir: Option<PathBuf>,

    /// Verify a previously-emitted SignedReport file. If a bundle is also
    /// supplied, cross-check that the transcript describes that exact
    /// bundle's bytes (SHA3-256).
    #[arg(long)]
    verify_transcript: Option<PathBuf>,
}

fn err_json(field: &str, msg: impl std::fmt::Display) -> ExitCode {
    eprintln!(r#"{{"error":"{field}","message":"{msg}"}}"#);
    ExitCode::from(2)
}

fn read_file(path: &PathBuf, label: &'static str) -> Result<String, ExitCode> {
    std::fs::read_to_string(path).map_err(|e| err_json(label, format!("{} : {}", path.display(), e)))
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // ───────────────────────────────────────────────────────────────
    // Mode 3 (and 4): --verify-transcript
    // ───────────────────────────────────────────────────────────────
    if let Some(tpath) = cli.verify_transcript.as_ref() {
        let raw = match read_file(tpath, "read_transcript") {
            Ok(s) => s,
            Err(c) => return c,
        };
        let envelope: SignedReport = match serde_json::from_str(&raw) {
            Ok(e) => e,
            Err(e) => return err_json("parse_transcript", e),
        };

        let payload = match verify_signed_report(&envelope) {
            Ok(p) => p,
            Err(e) => {
                let report = serde_json::json!({
                    "transcript_verified": false,
                    "error": e.to_string(),
                });
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
                return ExitCode::from(1);
            }
        };

        // Optional bundle cross-check.
        let mut bundle_cross_check: Option<serde_json::Value> = None;
        if let Some(bpath) = cli.bundle.as_ref() {
            let bytes = match std::fs::read(bpath) {
                Ok(b) => b,
                Err(e) => return err_json("read_bundle", format!("{} : {}", bpath.display(), e)),
            };
            let actual_hash = sha3_256_hex(&bytes);
            let matches = actual_hash == payload.bundle_sha3_256_hex;
            bundle_cross_check = Some(serde_json::json!({
                "bundle_path": bpath.display().to_string(),
                "bundle_sha3_256_hex_actual": actual_hash,
                "bundle_sha3_256_hex_in_transcript": payload.bundle_sha3_256_hex,
                "matches": matches,
            }));
            if !matches {
                let report = serde_json::json!({
                    "transcript_verified": true,
                    "bundle_cross_check": bundle_cross_check,
                    "error": "bundle_hash_mismatch",
                });
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
                return ExitCode::from(1);
            }
        }

        let out = serde_json::json!({
            "transcript_verified": true,
            "verifier_name": payload.verifier_name,
            "verifier_version": payload.verifier_version,
            "verifier_public_key_fingerprint_hex": payload.verifier_public_key_fingerprint_hex,
            "bundle_sha3_256_hex": payload.bundle_sha3_256_hex,
            "bundle_version": payload.bundle_version,
            "tenant_id": payload.tenant_id,
            "case_id": payload.case_id,
            "passed": payload.passed,
            "strict": payload.strict,
            "signed_at": payload.signed_at,
            "checks": payload.checks,
            "bundle_cross_check": bundle_cross_check,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return ExitCode::from(0);
    }

    // ───────────────────────────────────────────────────────────────
    // Modes 1 and 2: bundle verify (optionally + sign)
    // ───────────────────────────────────────────────────────────────
    let bundle_path = match cli.bundle.as_ref() {
        Some(p) => p,
        None => {
            return err_json(
                "missing_arg",
                "supply <bundle.json> or --verify-transcript <signed.json>",
            );
        }
    };

    let raw = match read_file(bundle_path, "read_bundle") {
        Ok(s) => s,
        Err(c) => return c,
    };
    let bundle: ReplayBundle = match serde_json::from_str(&raw) {
        Ok(b) => b,
        Err(e) => return err_json("parse_bundle", e),
    };

    let opts = VerifyOptions {
        payloads_dir: cli.payloads.as_deref(),
        strict: cli.strict,
    };

    let report: VerifyReport = verify(&bundle, opts);
    let passed = report.passed;

    if !cli.sign {
        let json = serde_json::to_string_pretty(&report).expect("serialize report");
        println!("{}", json);
        return if passed { ExitCode::from(0) } else { ExitCode::from(1) };
    }

    // --sign path: load/create identity, sign the report, emit SignedReport.
    let key_dir = match resolve_key_dir(cli.key_dir.as_deref()) {
        Ok(d) => d,
        Err(e) => return err_json("resolve_key_dir", e),
    };
    let identity = match load_or_create(&key_dir) {
        Ok(i) => i,
        Err(e) => return err_json("load_identity", e),
    };
    if identity.freshly_created {
        eprintln!(
            "h33-replay-verify: generated new ML-DSA-65 identity in {}",
            identity.key_dir.display()
        );
    }

    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let envelope = match sign_report(
        report,
        raw.as_bytes(),
        &identity.secret_key,
        &identity.public_key,
        now,
    ) {
        Ok(e) => e,
        Err(e) => return err_json("sign_report", e),
    };
    let json = serde_json::to_string_pretty(&envelope).expect("serialize envelope");
    println!("{}", json);
    if passed { ExitCode::from(0) } else { ExitCode::from(1) }
}
