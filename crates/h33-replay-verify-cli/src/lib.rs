//! `h33-replay-verify` — independent offline replay-bundle verifier.
//!
//! The 10-check protocol lives in [`h33_replay_verify_core`]; this crate adds:
//!
//!   - the CLI binary (`src/main.rs`),
//!   - the signed-transcript wrapper ([`signed_transcript`]) that wraps a
//!     [`h33_replay_verify_core::verify::VerifyReport`] in an ML-DSA-65 signature
//!     bound to a persistent verifier identity, and
//!   - the on-disk identity store ([`verifier_identity`]) where that keypair
//!     is generated and reused.
//!
//! Specs:
//!   - [Replay bundle wire format](https://github.com/H33ai/h33-replay-verifier/blob/main/spec/h33-replay-bundle-v0.1.md)
//!   - [Signed verification report envelope](https://github.com/H33ai/h33-replay-verifier/blob/main/spec/h33-signed-verify-report-v0.1.md)

#![forbid(unsafe_code)]

pub mod signed_transcript;
pub mod verifier_identity;
