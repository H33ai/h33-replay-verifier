//! Substrate actor binding — canonical hash + offline verification.
//!
//! `verification_hash = SHA3-256(DOMAIN_TAG || canonical_serialize(context))`,
//! where the context binds the 74-byte signing_message to a tenant, an actor
//! (agent or human), an optional case, and a sorted attribute list.
//!
//! See [`spec/h33-replay-bundle-v0.1.md`](https://github.com/H33ai/h33-replay-verifier/blob/main/spec/h33-replay-bundle-v0.1.md)
//! §6 for the wire shape this hash is bound into.

use serde::Serialize;
use sha3::{Digest, Sha3_256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    Agent,
    Human,
}

impl ActorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ActorKind::Agent => "agent",
            ActorKind::Human => "human",
        }
    }
}

#[derive(Debug, Clone)]
pub enum ActorRef {
    Agent { agent_id: [u8; 32] },
    Human { human_id: uuid::Uuid },
}

impl ActorRef {
    pub fn kind(&self) -> ActorKind {
        match self {
            ActorRef::Agent { .. } => ActorKind::Agent,
            ActorRef::Human { .. } => ActorKind::Human,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BindingContext {
    pub signing_message: [u8; 74],
    pub tenant_id: uuid::Uuid,
    pub actor: ActorRef,
    pub case_id: Option<uuid::Uuid>,
    /// Tenant-defined attributes. Sorted by key for determinism before hashing.
    pub attributes: Vec<(String, String)>,
}

pub const DOMAIN_TAG: &[u8] = b"H33-SUBSTRATE-BINDING-V1";

/// Compute the 32-byte verification_hash for a binding context.
pub fn compute_verification_hash(ctx: &BindingContext) -> [u8; 32] {
    let mut sorted_attrs = ctx.attributes.clone();
    sorted_attrs.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = Sha3_256::new();
    hasher.update(DOMAIN_TAG);
    hasher.update(ctx.signing_message);
    hasher.update(ctx.tenant_id.as_bytes());
    match &ctx.actor {
        ActorRef::Agent { agent_id } => {
            hasher.update(b"A");
            hasher.update(agent_id);
        }
        ActorRef::Human { human_id } => {
            hasher.update(b"H");
            hasher.update(human_id.as_bytes());
        }
    }
    match ctx.case_id {
        Some(c) => {
            hasher.update(b"C");
            hasher.update(c.as_bytes());
        }
        None => hasher.update(b"-"),
    }
    hasher.update((sorted_attrs.len() as u32).to_be_bytes());
    for (k, v) in &sorted_attrs {
        hasher.update((k.len() as u32).to_be_bytes());
        hasher.update(k.as_bytes());
        hasher.update((v.len() as u32).to_be_bytes());
        hasher.update(v.as_bytes());
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    HashMismatch { expected: [u8; 32], computed: [u8; 32] },
}

/// Recompute the verification_hash and compare against the stored value.
pub fn verify_binding(stored: &[u8; 32], ctx: &BindingContext) -> Result<(), VerifyError> {
    let computed = compute_verification_hash(ctx);
    if &computed != stored {
        return Err(VerifyError::HashMismatch { expected: *stored, computed });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BindingContext {
        BindingContext {
            signing_message: [0x77u8; 74],
            tenant_id: uuid::Uuid::nil(),
            actor: ActorRef::Agent { agent_id: [0xaau8; 32] },
            case_id: Some(uuid::Uuid::nil()),
            attributes: vec![("a".into(), "1".into()), ("b".into(), "2".into())],
        }
    }

    #[test]
    fn attribute_order_does_not_affect_hash() {
        let mut a = sample();
        a.attributes = vec![("a".into(), "1".into()), ("b".into(), "2".into())];
        let mut b = sample();
        b.attributes = vec![("b".into(), "2".into()), ("a".into(), "1".into())];
        assert_eq!(compute_verification_hash(&a), compute_verification_hash(&b));
    }

    #[test]
    fn changing_actor_changes_hash() {
        let mut a = sample();
        let h1 = compute_verification_hash(&a);
        a.actor = ActorRef::Human { human_id: uuid::Uuid::nil() };
        let h2 = compute_verification_hash(&a);
        assert_ne!(h1, h2);
    }

    #[test]
    fn verify_binding_round_trip() {
        let ctx = sample();
        let h = compute_verification_hash(&ctx);
        verify_binding(&h, &ctx).expect("matches");
        let mut tampered = [0u8; 32];
        tampered[0] = 0x99;
        assert!(verify_binding(&tampered, &ctx).is_err());
    }
}
