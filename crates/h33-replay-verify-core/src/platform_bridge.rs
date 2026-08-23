//! Platform bridge · `h33_reference::LifecycleEvent` placed in Governance Replay.
//!
//! **Place-first · 2026-07-06.** The replay-bundle wire format owns
//! `GovernanceEvent` — a hash-chained authority delegation/revocation
//! event captured inside the bundle's authority-temporal-validity check.
//! The platform (`h33-reference`) owns `LifecycleEvent` — the typed
//! state-transition record produced by `References::advance` and returned
//! by `References::history`.
//!
//! Both types describe "an event that changed authority state." They live
//! at different abstraction levels: the bundle event is scoped to the
//! replay wire format (RFC 3339 time, 74-byte substrate receipt, chain
//! hashes); the LifecycleEvent is scoped to the platform's
//! `StateTransition` enum. Neither is a duplicate of the other.
//!
//! What this module does: gives `LifecycleEvent` a home in Governance
//! Replay. Any consumer that expects the platform primitive can be handed
//! one via [`to_platform_lifecycle_event`] from a bundle event. The wire
//! format stays untouched; the platform primitive placement is a projection.
//!
//! What this module does NOT do:
//! - Change the 11-check verification protocol.
//! - Alter the bundle's canonical event chain.
//! - Attempt a lossless round-trip. The projection maps the two known
//!   `event_kind` values ("authority_delegation", "authority_revocation")
//!   to their platform `StateTransition` counterparts and represents the
//!   subject as a string; the reverse projection is a follow-up.

pub use h33_reference::LifecycleEvent;

use crate::bundle::GovernanceEvent;
use h33_envelope::StateTransition;

/// Project a bundle `GovernanceEvent` into the platform's `LifecycleEvent`.
///
/// `to` is derived from `event_kind`:
///   - `"authority_delegation"` → `StateTransition::AuthorityAttached`
///   - `"authority_revocation"` → `StateTransition::Destroyed`
///   - anything else → `StateTransition::Governed` (fail-soft; the bundle
///     verifier already rejects unknown kinds at check #11, so this
///     branch is defensive)
///
/// `from` is set to `StateTransition::Governed` (the bundle does not
/// carry the prior state explicitly; a downstream consumer that needs
/// the exact prior state should walk the bundle's per-`(subject, scope)`
/// chain, which is preserved by `prior_event_hash_hex`).
///
/// `at` is derived by parsing `effective_at` (RFC 3339) into Unix
/// milliseconds. Returns `None` if the timestamp cannot be parsed.
pub fn to_platform_lifecycle_event(event: &GovernanceEvent) -> Option<LifecycleEvent> {
    let to = match event.event_kind.as_str() {
        "authority_delegation" => StateTransition::AuthorityAttached,
        "authority_revocation" => StateTransition::Destroyed,
        _ => StateTransition::Governed,
    };
    let at = parse_rfc3339_to_millis(&event.effective_at)?;
    let actor = if let Some(agent_hex) = &event.subject_actor_id_hex {
        format!("agent:{agent_hex}")
    } else if let Some(human) = event.subject_human_id {
        format!("human:{human}")
    } else {
        "unknown".to_string()
    };
    Some(LifecycleEvent {
        reference: event.authority_scope.clone(),
        from: StateTransition::Governed,
        to,
        at,
        actor,
    })
}

/// Parse an RFC 3339 timestamp into Unix milliseconds using chrono.
fn parse_rfc3339_to_millis(s: &str) -> Option<u64> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .and_then(|dt| dt.timestamp_millis().try_into().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::GovernanceEvent;

    fn sample_delegation_event() -> GovernanceEvent {
        GovernanceEvent {
            event_id: uuid::Uuid::from_u128(1),
            event_kind: "authority_delegation".to_string(),
            subject_actor_id_hex: Some("a".repeat(64)),
            subject_human_id: None,
            authority_scope: "approve_transfer:acme.treasury".to_string(),
            effective_at: "2026-07-06T12:00:00Z".to_string(),
            receipt_hex: "b".repeat(148),
            prior_event_hash_hex: None,
            this_event_hash_hex: "c".repeat(64),
            authority_state_after: Some("delegated".to_string()),
        }
    }

    #[test]
    fn platform_lifecycle_event_projection_binds_authority_scope_and_state() {
        // Place-first test · proves LifecycleEvent now has a home in
        // Governance Replay: a bundle GovernanceEvent projects to the
        // platform's typed LifecycleEvent, preserving the authority scope
        // + mapping the event kind to the correct StateTransition.
        let event = sample_delegation_event();
        let projected = to_platform_lifecycle_event(&event).expect("timestamp parses");

        assert_eq!(projected.reference, event.authority_scope);
        assert_eq!(projected.to, StateTransition::AuthorityAttached);
        assert_eq!(projected.from, StateTransition::Governed);
        assert_eq!(projected.at, 1_783_339_200_000);
        assert!(projected.actor.starts_with("agent:"));
    }

    #[test]
    fn revocation_projects_to_destroyed() {
        let mut event = sample_delegation_event();
        event.event_kind = "authority_revocation".to_string();
        event.authority_state_after = Some("revoked".to_string());
        let projected = to_platform_lifecycle_event(&event).expect("timestamp parses");
        assert_eq!(projected.to, StateTransition::Destroyed);
    }
}
