//! H33 replay-bundle verifier — WASM bindings.
//!
//! Same Rust core as the `h33-replay-verify` CLI compiled to wasm32 so the
//! in-browser playground runs the exact same 10-check protocol the CLI does.
//! There is no JS reimplementation of the bundle verifier — that would
//! immediately break the "CLI is source of truth" principle.
//!
//! Signed-transcript (ML-DSA-65) verification is intentionally *not* in this
//! crate. It runs in pure JS via `@noble/post-quantum` so the WASM payload
//! stays small. The signed payload is bytes + signature + public key; any
//! conformant ML-DSA-65 verifier produces the same answer.

use h33_replay_verify_core::bundle::ReplayBundle;
use h33_replay_verify_core::verify::{verify as core_verify, VerifyOptions, VERIFIER_VERSION};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn _start() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Verifier version string (matches the CLI's `VERIFIER_VERSION`).
#[wasm_bindgen(js_name = verifierVersion)]
pub fn verifier_version() -> String {
    VERIFIER_VERSION.to_string()
}

/// Run the 10-check protocol over a JSON-encoded `ReplayBundle`.
///
/// Returns a `VerifyReport` serialized as a JS object. Throws a JS `Error`
/// if the JSON fails to parse — callers should treat that as a separate
/// failure mode (parse error vs verification fail).
///
/// `strict` mirrors the CLI's `--strict` flag. The browser has no payloads
/// directory, so check #3 (merkle_roots) is always skipped — in strict mode
/// the skip becomes a check failure.
#[wasm_bindgen(js_name = verifyBundle)]
pub fn verify_bundle(bundle_json: &str, strict: bool) -> Result<JsValue, JsError> {
    let bundle: ReplayBundle = serde_json::from_str(bundle_json)
        .map_err(|e| JsError::new(&format!("bundle parse error: {e}")))?;
    let report = core_verify(
        &bundle,
        VerifyOptions {
            payloads_dir: None,
            strict,
        },
    );
    serde_wasm_bindgen::to_value(&report)
        .map_err(|e| JsError::new(&format!("report serialization error: {e}")))
}

/// Compute SHA3-256 of a `Uint8Array` as a 64-char lowercase hex string.
///
/// Used by the browser playground to cross-check that a signed transcript
/// describes the exact bundle file the user dropped in. Mirrors the CLI's
/// `--verify-transcript <bundle.json>` cross-check semantics.
#[wasm_bindgen(js_name = sha3_256Hex)]
pub fn sha3_256_hex(bytes: &[u8]) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}
