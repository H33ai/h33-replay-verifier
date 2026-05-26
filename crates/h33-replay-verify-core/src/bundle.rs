//! Replay bundle wire schema (v0.1).
//!
//! A replay bundle is a self-contained JSON document. Given the bundle
//! file (and optionally a sealed-payload directory), `h33-replay-verify`
//! can verify the entire case story offline — no H33 server, no DB, no
//! network.
//!
//! Field naming mirrors the SCIF API contract v1.1 (§1 + §2 + §6) — all
//! hex fields use the `_hex` suffix; 32-byte fields are 64 chars,
//! 74-byte fields are 148 chars. See docs/specs/h33-replay-bundle-v0.1.md.

use serde::{Deserialize, Serialize};

pub type Hex32 = String;   // 64 lowercase chars
pub type Hex74 = String;   // 148 lowercase chars

/// Provenance metadata about THIS export — who exported it, when, against
/// which schema. Locked field set per Eric May 26 2026.
///
/// `schema_hash` is the SHA3-256 of the canonical schema identifier string
/// (`h33-replay-bundle-v0.1-schema` for this version). Verifier compares
/// against its own expected value and refuses on mismatch with a clear
/// error — protects against silent schema drift between exporter + verifier.
///
/// `verifier_min_version` is a semver string. Verifier refuses bundles
/// requiring a newer verifier with a clear "upgrade required" error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportMetadata {
    pub exported_at: String,                       // RFC 3339
    pub exporter_principal_kind: String,           // "tenant_user" | "service" | "admin"
    pub exporter_tenant_id: uuid::Uuid,
    pub case_id: uuid::Uuid,
    pub bundle_version: String,                    // mirrors top-level version
    pub schema_hash: Hex32,                        // SHA3-256("h33-replay-bundle-v<X>-schema")
    pub verifier_min_version: String,              // semver, e.g. "0.1.0"
}

/// The canonical schema identifier hashed into `ExportMetadata.schema_hash`.
/// Bump this when the bundle wire-format breaks.
pub const SCHEMA_IDENTIFIER: &str = "h33-replay-bundle-v0.1-schema";

/// Minimum verifier version expected for v0.1 bundles.
pub const VERIFIER_MIN_VERSION: &str = "0.1.0";

/// Compute the deterministic schema_hash. Both exporter and verifier
/// call this; mismatch indicates one side drifted from the spec.
pub fn schema_hash() -> Hex32 {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(SCHEMA_IDENTIFIER.as_bytes());
    hex::encode(h.finalize())
}

/// The top-level bundle envelope.
///
/// Required version: "0.1". Future revisions will add fields backward-
/// compatibly when possible; breaking changes bump the version major.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayBundle {
    /// Bundle schema version (e.g., "0.1"). Verifier rejects unknown majors.
    pub version: String,

    /// Provenance metadata about THIS export. Locked field set.
    pub export_metadata: ExportMetadata,

    /// Tenant the bundle was exported from.
    pub tenant_id: uuid::Uuid,

    /// Case the bundle covers.
    pub case_id: uuid::Uuid,

    /// Case snapshot at export time.
    pub case: CaseSnapshot,

    /// All agents that acted within the case (denormalized for offline lookup).
    pub agents: Vec<AgentSnapshot>,

    /// Optional: human members (case_humans) — included so the verifier can
    /// resolve transition.transitioned_by_human_id without DB access.
    #[serde(default)]
    pub humans: Vec<HumanSnapshot>,

    /// Timeline of every action + proof in the case, ordered by timestamp.
    pub timeline: ReplayTimeline,

    /// Frame manifests (one per replay snapshot taken during the case).
    pub frames: Vec<FrameManifest>,

    /// Evidence-bundle manifests (one per evidence bundle attached to the case).
    pub evidence_bundles: Vec<EvidenceBundleManifest>,

    /// Substrate actor binding rows (signing_message → actor + verification_hash).
    /// MUST include the `attributes` payload because the verifier recomputes
    /// `verification_hash` per §6.1's canonical-serialize algorithm.
    pub substrate_bindings: Vec<SubstrateBindingSnapshot>,

    /// Distinct verifier artifact refs cited by any proof in the case.
    /// Verifier checks that all refs are in the recognized algorithm registry.
    pub verifier_artifact_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseSnapshot {
    pub case_number: String,
    pub title: String,
    pub case_type: String,
    pub status: String,
    pub priority: String,
    pub severity: String,
    pub opened_by_human_id: uuid::Uuid,
    pub assigned_human_id: Option<uuid::Uuid>,
    pub continuity_hash_hex: Hex32,
    pub predecessor_hash_hex: Option<Hex32>,
    pub evidence_bundle_root_hex: Option<Hex32>,
    pub created_at: String,                       // RFC 3339
    pub closed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSnapshot {
    pub agent_id_hex: Hex32,
    pub canonical_name: String,
    pub display_name: String,
    pub agent_type: String,
    pub tier_depth: i32,
    pub status: String,
    pub parent_agent_id_hex: Option<Hex32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanSnapshot {
    pub human_id: uuid::Uuid,
    pub display_name: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayTimeline {
    pub continuity_hash_hex: Hex32,
    pub evidence_bundle_root_hex: Option<Hex32>,
    pub entries: Vec<TimelineEntry>,
}

/// A single timeline entry — either an agent action or a proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub event_kind: String,            // "action" | "proof"
    pub event_id: uuid::Uuid,
    pub session_id: Option<uuid::Uuid>,
    pub sequence_in_session: Option<i64>,
    pub action_kind: Option<String>,
    pub proof_kind: Option<String>,
    /// For action: `this_action_hash` (the per-session chain hash AFTER this event).
    /// For proof: `statement_commitment`.
    pub commitment_hex: Hex32,
    /// 74-byte H33 receipt of the event itself.
    pub receipt_hex: Hex74,
    pub timestamp: String,             // RFC 3339
    /// For action: the agent that performed it (denormalized).
    pub agent_id_hex: Option<Hex32>,
    /// For action: the prior_action_hash from the same session, if any.
    /// Required for chain verification; absent only for sequence 0.
    pub prior_action_hash_hex: Option<Hex32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameManifest {
    pub frame_id: uuid::Uuid,
    pub frame_scope: String,           // "session" | "case" | "cross_case"
    pub snapshot_kind: String,
    pub frame_root_hash_hex: Hex32,
    pub frame_receipt_hex: Hex74,
    /// Sealed-storage reference. If present and a `--payloads` directory is
    /// supplied to the verifier, the bytes at `<payloads>/<frame_blob_ref>`
    /// are hashed and compared against `frame_root_hash_hex`.
    /// If absent, the verifier skips check #3 for this frame (or fails in
    /// `--strict` mode).
    pub frame_blob_ref: Option<String>,
    pub frame_size_bytes: i64,
    pub created_at: String,
    /// Optional: list of action_ids the frame asserts membership for.
    /// Used by check #5 (refs resolve) and check #7 (no orphans).
    #[serde(default)]
    pub action_ids: Vec<uuid::Uuid>,
    /// Optional: list of proof_ids the frame asserts membership for.
    #[serde(default)]
    pub proof_ids: Vec<uuid::Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundleManifest {
    pub bundle_id: uuid::Uuid,
    pub bundle_root_hash_hex: Hex32,
    pub bundle_receipt_hex: Hex74,
    pub bundle_blob_ref: Option<String>,
    pub bundle_size_bytes: i64,
    pub item_count: i32,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubstrateBindingSnapshot {
    pub binding_id: uuid::Uuid,
    pub signing_message_hex: Hex74,
    pub tenant_id: uuid::Uuid,
    pub actor_kind: String,             // "agent" | "human"
    pub agent_id_hex: Option<Hex32>,
    pub human_id: Option<uuid::Uuid>,
    pub case_id: Option<uuid::Uuid>,
    pub verification_hash_hex: Hex32,
    /// Canonical attributes used to compute verification_hash. Must be
    /// present for the verifier to recompute + compare.
    #[serde(default)]
    pub attributes: Vec<(String, String)>,
    pub bound_at: String,
}
