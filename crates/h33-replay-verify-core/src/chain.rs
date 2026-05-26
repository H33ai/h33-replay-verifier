//! Per-session action chain hashing — canonical definition.
//!
//! `this_action_hash = SHA3-256(prior_action_hash || receipt)`, with the
//! first action in a session omitting the prior. Used inside [`crate::verify`]
//! check #4. The H33 backend re-exports this function so both the producer
//! (bundle exporter) and the verifier compute identical chain hashes.

use sha3::{Digest, Sha3_256};

/// `this_action_hash = SHA3-256(prior_action_hash? || receipt)`.
pub fn compute_chain_hash(prior: Option<[u8; 32]>, receipt: &[u8; 74]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    if let Some(p) = prior {
        hasher.update(p);
    }
    hasher.update(receipt);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// One entry in an offline chain-verification walk.
#[derive(Debug, Clone, Copy)]
pub struct ChainEntry {
    pub prior: Option<[u8; 32]>,
    pub receipt: [u8; 74],
    pub this: [u8; 32],
}

/// Result of an offline chain walk that detected an inconsistency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainBreak {
    pub at_sequence: usize,
    pub reason: &'static str,
}

/// Walk an action chain offline and confirm continuity.
pub fn verify_chain(actions: &[ChainEntry]) -> Result<(), ChainBreak> {
    let mut expected_prior: Option<[u8; 32]> = None;
    for (i, entry) in actions.iter().enumerate() {
        if entry.prior != expected_prior {
            return Err(ChainBreak { at_sequence: i, reason: "prior_action_hash mismatch" });
        }
        let recomputed = compute_chain_hash(entry.prior, &entry.receipt);
        if recomputed != entry.this {
            return Err(ChainBreak { at_sequence: i, reason: "this_action_hash mismatch" });
        }
        expected_prior = Some(entry.this);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_action_excludes_prior() {
        let r = [0x11u8; 74];
        let h = compute_chain_hash(None, &r);
        let mut expected = Sha3_256::new();
        expected.update(r);
        let exp: [u8; 32] = expected.finalize().into();
        assert_eq!(h, exp);
    }

    #[test]
    fn second_action_includes_prior() {
        let r = [0x11u8; 74];
        let h0 = compute_chain_hash(None, &r);
        let h1 = compute_chain_hash(Some(h0), &r);
        assert_ne!(h0, h1);
    }

    #[test]
    fn verify_chain_round_trip() {
        let r = [0x22u8; 74];
        let h0 = compute_chain_hash(None, &r);
        let h1 = compute_chain_hash(Some(h0), &r);
        let chain = [
            ChainEntry { prior: None,     receipt: r, this: h0 },
            ChainEntry { prior: Some(h0), receipt: r, this: h1 },
        ];
        verify_chain(&chain).expect("clean chain");
    }

    #[test]
    fn verify_chain_detects_tamper() {
        let r = [0x22u8; 74];
        let h0 = compute_chain_hash(None, &r);
        let chain = [ChainEntry { prior: None, receipt: r, this: [0u8; 32] }];
        let err = verify_chain(&chain).unwrap_err();
        assert_eq!(err.at_sequence, 0);
        let _ = h0;
    }
}
