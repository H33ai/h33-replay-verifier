#!/usr/bin/env node
// Verify a SignedReport envelope in Node using @noble/post-quantum.
//
// Demonstrates that the signed-transcript format is verifiable by any
// FIPS-204-conformant ML-DSA-65 implementation — no Rust, no this CLI,
// no H33 in the loop.
//
// Setup (one-time):
//   cd examples && npm install @noble/post-quantum @noble/hashes
//
// Run from this directory:
//   node verify-transcript.js ../fixtures/example-signed-report.json

import { readFileSync } from 'node:fs';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { sha3_256 } from '@noble/hashes/sha3';

const path = process.argv[2] ?? '../fixtures/example-signed-report.json';
const env = JSON.parse(readFileSync(path, 'utf8'));
const t = env.signed_transcript;

const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const hex = (bytes) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

const pk = b64(t.verifier_public_key_b64);
const sig = b64(t.signature_b64);
const payload = b64(t.signed_payload_b64);

// Cross-check the public-key fingerprint.
const fp_actual = hex(sha3_256(pk));
if (fp_actual !== t.verifier_public_key_fingerprint_hex) {
  console.error('FAIL: public-key fingerprint mismatch');
  process.exit(1);
}

// Cross-check the signed-payload hash.
const ph_actual = hex(sha3_256(payload));
if (ph_actual !== t.signed_payload_sha3_256_hex) {
  console.error('FAIL: signed-payload hash mismatch');
  process.exit(1);
}

// Verify the ML-DSA-65 signature.
const ok = ml_dsa65.verify(pk, payload, sig);
if (!ok) {
  console.error('FAIL: ML-DSA-65 signature invalid');
  process.exit(1);
}

const parsed = JSON.parse(new TextDecoder().decode(payload));
console.log('SIGNED-PASS');
console.log(`  verifier:          ${parsed.verifier_name} v${parsed.verifier_version}`);
console.log(`  fingerprint:       ${t.verifier_public_key_fingerprint_hex}`);
console.log(`  bundle SHA3-256:   ${parsed.bundle_sha3_256_hex}`);
console.log(`  passed:            ${parsed.passed}`);
console.log(`  signed at:         ${parsed.signed_at}`);
console.log(`  checks (10):       ${parsed.checks.filter((c) => c.passed).length} pass`);
