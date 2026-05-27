//! Signed verification transcript (v0.1).
//!
//! After `verify()` produces a [`VerifyReport`], this module wraps the report
//! in a self-contained envelope that any third party can cryptographically
//! verify *without* re-running the verifier and *without* trusting our
//! distribution channel.
//!
//! ## Trust model
//!
//! The envelope contains:
//!   - A human-readable copy of the report (for inspection only — NOT trusted).
//!   - `signed_payload_b64`: the EXACT bytes that were signed.
//!   - `signature_b64`: ML-DSA-65 signature over those bytes.
//!   - `verifier_public_key_b64` + fingerprint.
//!   - `bundle_sha3_256_hex`: hash of the input bundle file bytes.
//!
//! To verify externally:
//!   1. Decode `signed_payload_b64` → bytes.
//!   2. Verify `signature_b64` against those bytes using `verifier_public_key_b64`
//!      (any standards-conformant ML-DSA-65 verifier — pqcrypto, liboqs, etc.).
//!   3. Parse the bytes (canonical JSON) for the per-check assertions.
//!   4. Optionally re-verify `bundle_sha3_256_hex` against the bundle file
//!      to confirm the signature describes the bundle you have in hand.
//!
//! No canonical-JSON library is required for verification — the signed bytes
//! are embedded verbatim. This sidesteps every cross-language canonicalization
//! ambiguity that has bitten signed-payload schemes historically.
//!
//! ## Why ML-DSA-65
//!
//! Standard FIPS 204 ML-DSA-65 — verifiable by any conformant PQ stack
//! (Rust pqcrypto, liboqs, BoringSSL fork, etc.). 1,952-byte public key,
//! 3,309-byte signature. NIST Level 3.
//!
//! Spec: docs/specs/h33-signed-verify-report-v0.1.md

use base64::Engine;
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use h33_replay_verify_core::verify::{CheckResult, VerifyReport, VERIFIER_VERSION};

/// Envelope version embedded in every signed transcript. Bump when the wire
/// shape breaks.
pub const ENVELOPE_VERSION: &str = "h33-signed-verify-report/0.1";

/// Domain-separation tag inside the canonical signed payload. Prevents any
/// signature produced here from being reinterpreted as a signature over some
/// other H33 payload type that happens to share a hash.
pub const SIGNED_PAYLOAD_DOMAIN: &str = "h33-signed-verify-report/0.1";

/// Algorithm string written into every envelope.
pub const SIGNATURE_ALGORITHM: &str = "ML-DSA-65";

/// Errors emitted by the signed-transcript layer.
#[derive(Debug, thiserror::Error)]
pub enum SignedTranscriptError {
    #[error("envelope version mismatch: expected {expected}, got {got}")]
    EnvelopeVersionMismatch { expected: String, got: String },

    #[error("signature algorithm mismatch: expected {expected}, got {got}")]
    AlgorithmMismatch { expected: String, got: String },

    #[error("base64 decode failed for {0}")]
    Base64(&'static str),

    #[error("hex decode failed for {0}")]
    Hex(&'static str),

    #[error("invalid public key length")]
    InvalidPublicKey,

    #[error("invalid signature length")]
    InvalidSignature,

    #[error("public key fingerprint mismatch: payload says {payload}, key hashes to {actual}")]
    FingerprintMismatch { payload: String, actual: String },

    #[error("signed payload does not parse as canonical JSON")]
    PayloadNotJson,

    #[error("signed payload domain mismatch: expected {expected}, got {got}")]
    PayloadDomainMismatch { expected: String, got: String },

    #[error("signed payload SHA3-256 mismatch (envelope vs recomputed)")]
    PayloadHashMismatch,

    #[error("signature verification failed")]
    VerificationFailed,
}

/// The per-check assertion as embedded in the signed payload. Lower-fidelity
/// than the full [`CheckResult`] (no free-form messages) so the payload is
/// stable across cosmetic verifier-message changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCheck {
    pub check: String,
    pub passed: bool,
    pub examined: usize,
}

impl From<&CheckResult> for SignedCheck {
    fn from(c: &CheckResult) -> Self {
        Self {
            check: c.check.as_str().to_string(),
            passed: c.passed,
            examined: c.examined,
        }
    }
}

/// The canonical signed payload — these are the bytes whose serialization is
/// what `signature_b64` covers. Field order is fixed by struct definition.
///
/// External verifiers DO NOT need to re-serialize this; the exact bytes are
/// embedded in the envelope as `signed_payload_b64`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPayload {
    /// Always `"h33-signed-verify-report/0.1"`. Domain separation.
    pub domain: String,
    /// Name of the verifier binary that produced this transcript.
    pub verifier_name: String,
    /// Semver of that verifier.
    pub verifier_version: String,
    /// SHA3-256 of the verifier's ML-DSA-65 public key (hex). Echoes the
    /// envelope-level fingerprint; included in the signed payload so a
    /// signature can never be re-attached to a different key.
    pub verifier_public_key_fingerprint_hex: String,
    /// SHA3-256 of the bundle file bytes that were verified (hex).
    pub bundle_sha3_256_hex: String,
    /// Echo of the bundle's `version` field.
    pub bundle_version: String,
    /// Tenant of the case in the bundle.
    pub tenant_id: uuid::Uuid,
    /// Case id covered by the bundle.
    pub case_id: uuid::Uuid,
    /// Overall verdict (mirror of `report.passed`).
    pub passed: bool,
    /// Whether `--strict` was on.
    pub strict: bool,
    /// Per-check verdicts.
    pub checks: Vec<SignedCheck>,
    /// RFC 3339 timestamp at signing time.
    pub signed_at: String,
}

/// The envelope around a signed report. This is what gets written to disk /
/// printed to stdout when `--sign` is in effect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedReport {
    /// Always `"h33-signed-verify-report/0.1"`.
    pub envelope_version: String,
    /// Human-readable copy of the report — INSPECTION ONLY, not trusted.
    /// Trust flows through `signed_payload_b64` + `signature_b64`.
    pub report: VerifyReport,
    /// The signed transcript proper.
    pub signed_transcript: SignedTranscript,
}

/// The trusted, cryptographically-bound assertion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTranscript {
    pub verifier_name: String,
    pub verifier_version: String,
    pub signed_at: String,
    pub bundle_sha3_256_hex: String,
    /// Base64 of the EXACT bytes that were signed (a [`SignedPayload`]
    /// serialized with serde_json::to_vec — deterministic from struct order).
    pub signed_payload_b64: String,
    /// SHA3-256 of `signed_payload` bytes (hex), as a convenience.
    pub signed_payload_sha3_256_hex: String,
    pub signature_algorithm: String,
    pub verifier_public_key_b64: String,
    pub verifier_public_key_fingerprint_hex: String,
    pub signature_b64: String,
}

/// Compute the SHA3-256 of arbitrary bytes (hex-encoded).
pub fn sha3_256_hex(bytes: &[u8]) -> String {
    let mut h = Sha3_256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Wrap a [`VerifyReport`] + the bytes of the bundle file into a
/// cryptographically-signed envelope.
///
/// The caller provides the [`mldsa65::SecretKey`] / [`mldsa65::PublicKey`] —
/// typically loaded via [`crate::verifier_identity`].
pub fn sign_report(
    report: VerifyReport,
    bundle_bytes: &[u8],
    secret_key: &mldsa65::SecretKey,
    public_key: &mldsa65::PublicKey,
    now_rfc3339: String,
) -> Result<SignedReport, SignedTranscriptError> {
    let pub_bytes = public_key.as_bytes();
    let fingerprint_hex = sha3_256_hex(pub_bytes);
    let bundle_hash_hex = sha3_256_hex(bundle_bytes);

    let payload = SignedPayload {
        domain: SIGNED_PAYLOAD_DOMAIN.to_string(),
        verifier_name: "h33-replay-verify".to_string(),
        verifier_version: VERIFIER_VERSION.to_string(),
        verifier_public_key_fingerprint_hex: fingerprint_hex.clone(),
        bundle_sha3_256_hex: bundle_hash_hex.clone(),
        bundle_version: report.bundle_version.clone(),
        tenant_id: report.tenant_id,
        case_id: report.case_id,
        passed: report.passed,
        strict: report.strict,
        checks: report.checks.iter().map(SignedCheck::from).collect(),
        signed_at: now_rfc3339.clone(),
    };

    let payload_bytes = serde_json::to_vec(&payload)
        .expect("SignedPayload is always serializable");
    let payload_hash_hex = sha3_256_hex(&payload_bytes);

    let sig = mldsa65::detached_sign(&payload_bytes, secret_key);

    let b64 = base64::engine::general_purpose::STANDARD;

    Ok(SignedReport {
        envelope_version: ENVELOPE_VERSION.to_string(),
        report,
        signed_transcript: SignedTranscript {
            verifier_name: "h33-replay-verify".to_string(),
            verifier_version: VERIFIER_VERSION.to_string(),
            signed_at: now_rfc3339,
            bundle_sha3_256_hex: bundle_hash_hex,
            signed_payload_b64: b64.encode(&payload_bytes),
            signed_payload_sha3_256_hex: payload_hash_hex,
            signature_algorithm: SIGNATURE_ALGORITHM.to_string(),
            verifier_public_key_b64: b64.encode(pub_bytes),
            verifier_public_key_fingerprint_hex: fingerprint_hex,
            signature_b64: b64.encode(sig.as_bytes()),
        },
    })
}

/// Verify the signature inside a [`SignedReport`] envelope.
///
/// Checks:
///   1. Envelope version matches.
///   2. Signature algorithm is ML-DSA-65.
///   3. Public key decodes + is 1952 bytes.
///   4. Public key SHA3-256 fingerprint matches the envelope field.
///   5. Signed payload bytes hash to `signed_payload_sha3_256_hex`.
///   6. Signed payload parses as JSON and its `verifier_public_key_fingerprint_hex`
///      matches the envelope.
///   7. Signed payload domain tag is correct.
///   8. ML-DSA-65 signature over the signed payload verifies under the key.
///
/// On success, returns the parsed [`SignedPayload`] so the caller can apply
/// trust policy (e.g. fingerprint allow-list, max age, expected case id).
pub fn verify_signed_report(
    envelope: &SignedReport,
) -> Result<SignedPayload, SignedTranscriptError> {
    if envelope.envelope_version != ENVELOPE_VERSION {
        return Err(SignedTranscriptError::EnvelopeVersionMismatch {
            expected: ENVELOPE_VERSION.to_string(),
            got: envelope.envelope_version.clone(),
        });
    }
    let t = &envelope.signed_transcript;
    if t.signature_algorithm != SIGNATURE_ALGORITHM {
        return Err(SignedTranscriptError::AlgorithmMismatch {
            expected: SIGNATURE_ALGORITHM.to_string(),
            got: t.signature_algorithm.clone(),
        });
    }

    let b64 = base64::engine::general_purpose::STANDARD;

    let pk_bytes = b64
        .decode(&t.verifier_public_key_b64)
        .map_err(|_| SignedTranscriptError::Base64("verifier_public_key_b64"))?;
    let sig_bytes = b64
        .decode(&t.signature_b64)
        .map_err(|_| SignedTranscriptError::Base64("signature_b64"))?;
    let payload_bytes = b64
        .decode(&t.signed_payload_b64)
        .map_err(|_| SignedTranscriptError::Base64("signed_payload_b64"))?;

    let pk = mldsa65::PublicKey::from_bytes(&pk_bytes)
        .map_err(|_| SignedTranscriptError::InvalidPublicKey)?;
    let sig = mldsa65::DetachedSignature::from_bytes(&sig_bytes)
        .map_err(|_| SignedTranscriptError::InvalidSignature)?;

    let pk_fp_actual = sha3_256_hex(&pk_bytes);
    if pk_fp_actual != t.verifier_public_key_fingerprint_hex {
        return Err(SignedTranscriptError::FingerprintMismatch {
            payload: t.verifier_public_key_fingerprint_hex.clone(),
            actual: pk_fp_actual,
        });
    }

    let payload_hash_actual = sha3_256_hex(&payload_bytes);
    if payload_hash_actual != t.signed_payload_sha3_256_hex {
        return Err(SignedTranscriptError::PayloadHashMismatch);
    }

    let payload: SignedPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|_| SignedTranscriptError::PayloadNotJson)?;

    if payload.domain != SIGNED_PAYLOAD_DOMAIN {
        return Err(SignedTranscriptError::PayloadDomainMismatch {
            expected: SIGNED_PAYLOAD_DOMAIN.to_string(),
            got: payload.domain.clone(),
        });
    }
    if payload.verifier_public_key_fingerprint_hex != t.verifier_public_key_fingerprint_hex {
        return Err(SignedTranscriptError::FingerprintMismatch {
            payload: payload.verifier_public_key_fingerprint_hex.clone(),
            actual: t.verifier_public_key_fingerprint_hex.clone(),
        });
    }

    mldsa65::verify_detached_signature(&sig, &payload_bytes, &pk)
        .map_err(|_| SignedTranscriptError::VerificationFailed)?;

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use h33_replay_verify_core::verify::{CheckId, CheckResult, VerifyReport};

    fn fake_report() -> VerifyReport {
        VerifyReport {
            bundle_version: "0.1".to_string(),
            tenant_id: uuid::Uuid::nil(),
            case_id: uuid::Uuid::nil(),
            passed: true,
            strict: false,
            checks: vec![CheckResult {
                check: CheckId::SchemaParse,
                passed: true,
                message: "ok".to_string(),
                failure_mode: None,
                examined: 1,
            }],
            warnings: vec![],
        }
    }

    #[test]
    fn round_trip_signs_and_verifies() {
        let (pk, sk) = mldsa65::keypair();
        let bundle_bytes = b"fake-bundle";
        let envelope = sign_report(
            fake_report(),
            bundle_bytes,
            &sk,
            &pk,
            "2026-05-26T00:00:00Z".to_string(),
        )
        .expect("sign");

        let payload = verify_signed_report(&envelope).expect("verify");
        assert_eq!(payload.domain, SIGNED_PAYLOAD_DOMAIN);
        assert!(payload.passed);
        assert_eq!(payload.checks.len(), 1);
        assert_eq!(payload.bundle_sha3_256_hex, sha3_256_hex(bundle_bytes));
    }

    #[test]
    fn tampered_signed_payload_fails() {
        let (pk, sk) = mldsa65::keypair();
        let mut envelope = sign_report(
            fake_report(),
            b"x",
            &sk,
            &pk,
            "2026-05-26T00:00:00Z".to_string(),
        )
        .expect("sign");

        // Re-encode a different payload but keep old signature.
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut payload: SignedPayload =
            serde_json::from_slice(&b64.decode(&envelope.signed_transcript.signed_payload_b64).unwrap()).unwrap();
        payload.passed = false;
        let new_bytes = serde_json::to_vec(&payload).unwrap();
        envelope.signed_transcript.signed_payload_b64 = b64.encode(&new_bytes);
        envelope.signed_transcript.signed_payload_sha3_256_hex = sha3_256_hex(&new_bytes);

        let err = verify_signed_report(&envelope).unwrap_err();
        assert!(matches!(err, SignedTranscriptError::VerificationFailed));
    }

    #[test]
    fn swapped_public_key_fails_fingerprint_check() {
        let (pk, sk) = mldsa65::keypair();
        let (other_pk, _) = mldsa65::keypair();
        let mut envelope = sign_report(
            fake_report(),
            b"x",
            &sk,
            &pk,
            "2026-05-26T00:00:00Z".to_string(),
        )
        .expect("sign");

        let b64 = base64::engine::general_purpose::STANDARD;
        envelope.signed_transcript.verifier_public_key_b64 = b64.encode(other_pk.as_bytes());

        let err = verify_signed_report(&envelope).unwrap_err();
        assert!(matches!(err, SignedTranscriptError::FingerprintMismatch { .. }));
    }
}
