//! H33 replay-bundle verifier — pure-Rust, WASM-friendly core.
//!
//! Same code drives:
//!   - `h33-replay-verify` CLI (in this workspace)
//!   - `h33-replay-verify-wasm` (in this workspace) — the browser playground
//!   - any third-party verifier implementation that depends on this crate
//!
//! Architecture separation (locked):
//!   - `h33-verify`         = primitive 74-byte H33 receipt verifier (the atom)
//!   - `h33-replay-verify`  = replay bundle verifier (the story)
//! One verifies the atom; one verifies the story.
//!
//! Specs:
//!   - [Bundle wire format](https://github.com/H33ai/h33-replay-verifier/blob/main/spec/h33-replay-bundle-v0.1.md)
//!   - [Signed transcript envelope](https://github.com/H33ai/h33-replay-verifier/blob/main/spec/h33-signed-verify-report-v0.1.md)

#![forbid(unsafe_code)]

pub mod binding;
pub mod bundle;
pub mod chain;
pub mod platform_bridge;
pub mod verify;
