use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const EVENT_SCHEMA_VERSION: u16 = 2;
pub const TRUSTED_INGRESS_CONTRACT_VERSION: &str = "2026-06-05.v1";
pub const PRE_CONTAINMENT_PERSISTENCE_REASON_FAMILY: &str = "pre_containment_persistence";
pub const PRE_CONTAINMENT_PERSISTENCE_KIND_FIELD: &str = "persistence_kind";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub Uuid);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BaitId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExposureId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceKind {
    Docs,
    OpenApi,
    Route,
    Header,
    Token,
    Hostname,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaitClass {
    #[default]
    Docs,
    OpenApi,
    HiddenRoute,
    FakeCredentialToken,
    JsDiscoveredRoute,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedAction {
    pub method: String,
    pub path: String,
    pub header_name: Option<String>,
    pub header_value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bait {
    pub id: BaitId,
    #[serde(default)]
    pub bait_class: BaitClass,
    pub surface: String,
    pub surface_kind: SurfaceKind,
    pub expected_action: ExpectedAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    Proxy,
    SurfaceController,
    BaitEngine,
    TraceEngine,
    PolicyRouter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingDecision {
    ProtectedUpstream,
    EidolonOwned,
    RewrittenUpstream,
    ControlledReality,
    RateLimited,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeHeaderObservation {
    pub name: String,
    pub present: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngressIdentitySource {
    #[default]
    None,
    InternalScanner,
    LocalAllowlist,
    VerifiedBot,
    SignedAgent,
    PartnerAutomation,
    OperatorOverride,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngressTrustTier {
    #[default]
    None,
    WeaklyAsserted,
    Allowlisted,
    EdgeVerified,
    SignedAttested,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressIdentity {
    pub source: IngressIdentitySource,
    pub trust_tier: IngressTrustTier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngressVerificationStrength {
    #[default]
    None,
    Low,
    Medium,
    High,
    Cryptographic,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngressActorKind {
    #[default]
    Unknown,
    Crawler,
    Assistant,
    AutonomousAgent,
    AgenticBrowser,
    PartnerAutomation,
    InternalScanner,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressAdvisorySignals {
    #[serde(default, skip_serializing_if = "is_default")]
    pub verification_strength: IngressVerificationStrength,
    #[serde(default, skip_serializing_if = "is_default")]
    pub actor_kind: IngressActorKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_score: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_score_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_score_scale: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detection_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edge_action: Option<EdgeRecommendedAction>,
}

impl IngressAdvisorySignals {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryReconScore {
    #[serde(default, skip_serializing_if = "is_default")]
    pub repeated_discovery_score: u8,
    #[serde(default, skip_serializing_if = "is_default")]
    pub query_score: u8,
    #[serde(default, skip_serializing_if = "is_default")]
    pub legacy_openapi_query_score: u8,
    #[serde(default, skip_serializing_if = "is_default")]
    pub linked_bait_surface_score: u8,
    #[serde(default, skip_serializing_if = "is_default")]
    pub linked_bait_class_fanout_bonus: u8,
    #[serde(default, skip_serializing_if = "is_default")]
    pub decoy_write_probe_score: u8,
    #[serde(default, skip_serializing_if = "is_default")]
    pub decoy_write_probe_path_fanout_bonus: u8,
    #[serde(default, skip_serializing_if = "is_default")]
    pub detection_score: u8,
    #[serde(default, skip_serializing_if = "is_default")]
    pub total: u8,
    #[serde(default, skip_serializing_if = "is_default")]
    pub threshold: u8,
}

impl DiscoveryReconScore {
    pub fn is_empty(&self) -> bool {
        self.repeated_discovery_score == 0
            && self.query_score == 0
            && self.legacy_openapi_query_score == 0
            && self.linked_bait_surface_score == 0
            && self.linked_bait_class_fanout_bonus == 0
            && self.decoy_write_probe_score == 0
            && self.decoy_write_probe_path_fanout_bonus == 0
            && self.detection_score == 0
            && self.total == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreContainmentPersistenceKind {
    DiscoveryReconRetry,
    WriteReconRetry,
    SameBaitNearMissRetry,
}

impl PreContainmentPersistenceKind {
    pub const fn detail_code(self) -> &'static str {
        match self {
            Self::DiscoveryReconRetry => "discovery_recon_retry",
            Self::WriteReconRetry => "write_recon_retry",
            Self::SameBaitNearMissRetry => "same_bait_near_miss_retry",
        }
    }

    pub const fn marker(self) -> &'static str {
        match self {
            Self::DiscoveryReconRetry => "persistence_kind=discovery_recon_retry",
            Self::WriteReconRetry => "persistence_kind=write_recon_retry",
            Self::SameBaitNearMissRetry => "persistence_kind=same_bait_near_miss_retry",
        }
    }

    pub fn from_reason(reason: &str) -> Option<Self> {
        if let Some(detail_code) = reason
            .split_ascii_whitespace()
            .find_map(|field| field.strip_prefix("persistence_kind="))
        {
            return Self::from_detail_code(detail_code);
        }

        if reason.contains("rate-limited same-bait near miss retry moved session to blocked") {
            return Some(Self::SameBaitNearMissRetry);
        }

        if reason.contains("rate-limited discovery recon retry moved session to blocked") {
            if reason.contains("repeated_discovery_score=0")
                && reason.contains("decoy_write_probe_path_fanout_bonus=1")
            {
                return Some(Self::WriteReconRetry);
            }
            return Some(Self::DiscoveryReconRetry);
        }

        None
    }

    fn from_detail_code(detail_code: &str) -> Option<Self> {
        match detail_code {
            "discovery_recon_retry" => Some(Self::DiscoveryReconRetry),
            "write_recon_retry" => Some(Self::WriteReconRetry),
            "same_bait_near_miss_retry" => Some(Self::SameBaitNearMissRetry),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    RequestSeen {
        method: String,
        path: String,
        safe_headers: Vec<SafeHeaderObservation>,
        #[serde(default)]
        ingress_identity: IngressIdentity,
        #[serde(default, skip_serializing_if = "IngressAdvisorySignals::is_empty")]
        ingress_signals: IngressAdvisorySignals,
        #[serde(default, skip_serializing_if = "DiscoveryReconScore::is_empty")]
        discovery_recon_score: DiscoveryReconScore,
        routing_decision: RoutingDecision,
    },
    ResponseServed {
        status: u16,
        routing_decision: RoutingDecision,
    },
    BaitExposed {
        bait_id: BaitId,
        exposure_id: ExposureId,
        surface: String,
    },
    BaitActionObserved {
        bait_id: BaitId,
        exposure_id: Option<ExposureId>,
        method: String,
        path: String,
    },
    PolicyChanged {
        from: PolicyState,
        to: PolicyState,
        reason: String,
    },
    PolicyDecision {
        routing_decision: RoutingDecision,
        reason: String,
    },
    ControlledRealityEntered {
        reason: String,
    },
    RateLimitApplied {
        reason: String,
    },
    RealityEscapeAttempt {
        method: String,
        path: String,
        routing_decision: RoutingDecision,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub schema_version: u16,
    pub id: Uuid,
    pub session_id: SessionId,
    pub observed_at: DateTime<Utc>,
    pub source: EventSource,
    pub policy_state: PolicyState,
    pub kind: EventKind,
}

impl Event {
    pub fn new(
        session_id: SessionId,
        source: EventSource,
        policy_state: PolicyState,
        kind: EventKind,
    ) -> Self {
        Self {
            schema_version: EVENT_SCHEMA_VERSION,
            id: Uuid::new_v4(),
            session_id,
            observed_at: Utc::now(),
            source,
            policy_state,
            kind,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyState {
    Normal,
    Observe,
    Suspicious,
    ControlledReality,
    RateLimited,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceBand {
    Low,
    Medium,
    High,
    ConfirmedBaitDerivedChain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Score {
    pub points: i32,
    pub confidence: ConfidenceBand,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeRecommendedAction {
    Allow,
    Observe,
    RateLimit,
    Challenge,
    Block,
    PreserveEidolonRouting,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeRequestRef {
    pub method: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgePolicySnapshot {
    pub state: PolicyState,
    pub routing_decision: RoutingDecision,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeEvidenceRef {
    pub event_schema_version: u16,
    pub event_ids: Vec<Uuid>,
    pub bundle_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeRecommendation {
    pub action: EdgeRecommendedAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EidolonEdgeDecisionExport {
    pub contract_version: String,
    pub observed_at: DateTime<Utc>,
    pub session_id: SessionId,
    pub request: EdgeRequestRef,
    pub ingress_identity: IngressIdentity,
    #[serde(default, skip_serializing_if = "IngressAdvisorySignals::is_empty")]
    pub ingress_signals: IngressAdvisorySignals,
    #[serde(default, skip_serializing_if = "DiscoveryReconScore::is_empty")]
    pub discovery_recon_score: DiscoveryReconScore,
    pub policy: EdgePolicySnapshot,
    pub evidence: EdgeEvidenceRef,
    pub edge_recommendation: EdgeRecommendation,
}

fn is_default<T>(value: &T) -> bool
where
    T: Default + PartialEq,
{
    value == &T::default()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn must_ok<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{context}: {error}"),
        }
    }

    #[test]
    fn event_schema_version_is_the_m2_5_contract_version() {
        assert_eq!(EVENT_SCHEMA_VERSION, 2);
    }

    #[test]
    fn new_event_carries_contract_metadata() {
        let session_id = SessionId::new();
        let event = Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::Observe,
            EventKind::RequestSeen {
                method: "GET".to_string(),
                path: "/openapi.json".to_string(),
                safe_headers: vec![SafeHeaderObservation {
                    name: "user-agent".to_string(),
                    present: true,
                }],
                ingress_identity: IngressIdentity::default(),
                ingress_signals: IngressAdvisorySignals::default(),
                discovery_recon_score: DiscoveryReconScore::default(),
                routing_decision: RoutingDecision::ProtectedUpstream,
            },
        );

        assert_eq!(event.schema_version, EVENT_SCHEMA_VERSION);
        assert_eq!(event.session_id, session_id);
        assert_eq!(event.source, EventSource::Proxy);
        assert_eq!(event.policy_state, PolicyState::Observe);
    }

    #[test]
    fn event_serializes_stable_snake_case_contract() {
        let session_id = SessionId::new();
        let event = Event::new(
            session_id,
            EventSource::PolicyRouter,
            PolicyState::Suspicious,
            EventKind::PolicyChanged {
                from: PolicyState::Observe,
                to: PolicyState::Suspicious,
                reason: "bait action matched expected header and path".to_string(),
            },
        );

        let serialized = must_ok(serde_json::to_value(event), "event should serialize");

        assert_eq!(serialized["schema_version"], json!(EVENT_SCHEMA_VERSION));
        assert_eq!(serialized["source"], json!("policy_router"));
        assert_eq!(serialized["policy_state"], json!("suspicious"));
        assert_eq!(serialized["kind"]["type"], json!("policy_changed"));
        assert_eq!(serialized["kind"]["from"], json!("observe"));
        assert_eq!(serialized["kind"]["to"], json!("suspicious"));
    }

    #[test]
    fn request_seen_event_serializes_ingress_identity_fields() {
        let session_id = SessionId::new();
        let event = Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::Observe,
            EventKind::RequestSeen {
                method: "GET".to_string(),
                path: "/openapi.json".to_string(),
                safe_headers: vec![SafeHeaderObservation {
                    name: "user-agent".to_string(),
                    present: true,
                }],
                ingress_identity: IngressIdentity {
                    source: IngressIdentitySource::VerifiedBot,
                    trust_tier: IngressTrustTier::EdgeVerified,
                    label: Some("googlebot".to_string()),
                    expires_at: None,
                },
                ingress_signals: IngressAdvisorySignals {
                    verification_strength: IngressVerificationStrength::High,
                    actor_kind: IngressActorKind::Crawler,
                    verified_category: Some("AI Assistant".to_string()),
                    attestation_ref: None,
                    vendor_score: Some(12),
                    vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                    vendor_score_scale: Some("1-99".to_string()),
                    detection_ids: vec!["3355446".to_string()],
                    edge_action: Some(EdgeRecommendedAction::Allow),
                },
                discovery_recon_score: DiscoveryReconScore {
                    repeated_discovery_score: 2,
                    query_score: 1,
                    total: 3,
                    threshold: 3,
                    ..DiscoveryReconScore::default()
                },
                routing_decision: RoutingDecision::ProtectedUpstream,
            },
        );

        let serialized = must_ok(serde_json::to_value(event), "event should serialize");

        assert_eq!(
            serialized["kind"]["ingress_identity"]["source"],
            "verified_bot"
        );
        assert_eq!(
            serialized["kind"]["ingress_identity"]["trust_tier"],
            "edge_verified"
        );
        assert_eq!(serialized["kind"]["ingress_identity"]["label"], "googlebot");
        assert_eq!(
            serialized["kind"]["ingress_signals"]["verification_strength"],
            "high"
        );
        assert_eq!(
            serialized["kind"]["ingress_signals"]["actor_kind"],
            "crawler"
        );
        assert_eq!(serialized["kind"]["ingress_signals"]["vendor_score"], 12);
        assert_eq!(
            serialized["kind"]["ingress_signals"]["edge_action"],
            "allow"
        );
        assert_eq!(
            serialized["kind"]["discovery_recon_score"]["repeated_discovery_score"],
            2
        );
        assert_eq!(
            serialized["kind"]["discovery_recon_score"]["query_score"],
            1
        );
        assert_eq!(serialized["kind"]["discovery_recon_score"]["total"], 3);
        assert_eq!(serialized["kind"]["discovery_recon_score"]["threshold"], 3);
    }

    #[test]
    fn request_seen_event_deserializes_without_ingress_identity() {
        let session_id = SessionId::new();
        let event = json!({
            "schema_version": EVENT_SCHEMA_VERSION,
            "id": Uuid::new_v4(),
            "session_id": session_id,
            "observed_at": Utc::now(),
            "source": "proxy",
            "policy_state": "observe",
            "kind": {
                "type": "request_seen",
                "method": "GET",
                "path": "/openapi.json",
                "safe_headers": [],
                "routing_decision": "protected_upstream"
            }
        });

        let parsed: Event = must_ok(serde_json::from_value(event), "legacy event should parse");

        match parsed.kind {
            EventKind::RequestSeen {
                ingress_identity, ..
            } => assert_eq!(ingress_identity, IngressIdentity::default()),
            other => panic!("expected request_seen, got {other:?}"),
        }
    }

    #[test]
    fn request_seen_event_deserializes_without_ingress_signals() {
        let session_id = SessionId::new();
        let event = json!({
            "schema_version": EVENT_SCHEMA_VERSION,
            "id": Uuid::new_v4(),
            "session_id": session_id,
            "observed_at": Utc::now(),
            "source": "proxy",
            "policy_state": "observe",
            "kind": {
                "type": "request_seen",
                "method": "GET",
                "path": "/openapi.json",
                "safe_headers": [],
                "ingress_identity": {
                    "source": "verified_bot",
                    "trust_tier": "edge_verified"
                },
                "routing_decision": "protected_upstream"
            }
        });

        let parsed: Event = must_ok(serde_json::from_value(event), "legacy event should parse");

        match parsed.kind {
            EventKind::RequestSeen {
                ingress_signals, ..
            } => assert_eq!(ingress_signals, IngressAdvisorySignals::default()),
            other => panic!("expected request_seen, got {other:?}"),
        }
    }

    #[test]
    fn request_seen_event_deserializes_without_discovery_recon_score() {
        let session_id = SessionId::new();
        let event = json!({
            "schema_version": EVENT_SCHEMA_VERSION,
            "id": Uuid::new_v4(),
            "session_id": session_id,
            "observed_at": Utc::now(),
            "source": "proxy",
            "policy_state": "observe",
            "kind": {
                "type": "request_seen",
                "method": "GET",
                "path": "/openapi.json",
                "safe_headers": [],
                "ingress_identity": {
                    "source": "verified_bot",
                    "trust_tier": "edge_verified"
                },
                "routing_decision": "protected_upstream"
            }
        });

        let parsed: Event = must_ok(serde_json::from_value(event), "legacy event should parse");

        match parsed.kind {
            EventKind::RequestSeen {
                discovery_recon_score,
                ..
            } => assert_eq!(discovery_recon_score, DiscoveryReconScore::default()),
            other => panic!("expected request_seen, got {other:?}"),
        }
    }

    #[test]
    fn pre_containment_persistence_kind_parses_explicit_marker() {
        let reason = "rate-limited discovery recon retry moved session to blocked: path=/docs persistence_kind=discovery_recon_retry";

        assert_eq!(
            PreContainmentPersistenceKind::from_reason(reason),
            Some(PreContainmentPersistenceKind::DiscoveryReconRetry)
        );
    }

    #[test]
    fn pre_containment_persistence_kind_preserves_legacy_write_recon_fallback() {
        let reason = "rate-limited discovery recon retry moved session to blocked: path=/api/v2/import/validate repeated_discovery_score=0 decoy_write_probe_path_fanout_bonus=1";

        assert_eq!(
            PreContainmentPersistenceKind::from_reason(reason),
            Some(PreContainmentPersistenceKind::WriteReconRetry)
        );
    }

    #[test]
    fn policy_decision_event_serializes_actual_routing_decision() {
        let session_id = SessionId::new();
        let event = Event::new(
            session_id,
            EventSource::PolicyRouter,
            PolicyState::ControlledReality,
            EventKind::PolicyDecision {
                routing_decision: RoutingDecision::ProtectedUpstream,
                reason: "interventions disabled; forwarding to protected upstream".to_string(),
            },
        );

        let serialized = serde_json::to_value(event).expect("event should serialize");

        assert_eq!(serialized["source"], json!("policy_router"));
        assert_eq!(serialized["policy_state"], json!("controlled_reality"));
        assert_eq!(serialized["kind"]["type"], json!("policy_decision"));
        assert_eq!(
            serialized["kind"]["routing_decision"],
            json!("protected_upstream")
        );
        assert_eq!(
            serialized["kind"]["reason"],
            json!("interventions disabled; forwarding to protected upstream")
        );
    }

    #[test]
    fn bait_expected_action_round_trips() {
        let bait = Bait {
            id: BaitId("rel_2025_04_b7f2".to_string()),
            bait_class: BaitClass::Docs,
            surface: "/docs/legacy-import".to_string(),
            surface_kind: SurfaceKind::Docs,
            expected_action: ExpectedAction {
                method: "POST".to_string(),
                path: "/api/v2/import/reconcile".to_string(),
                header_name: Some("X-Migration-Trace".to_string()),
                header_value: Some("rel_2025_04_b7f2".to_string()),
            },
        };

        let serialized = serde_json::to_string(&bait).expect("bait should serialize");
        let deserialized: Bait = serde_json::from_str(&serialized).expect("bait should parse");

        assert_eq!(deserialized, bait);
    }

    #[test]
    fn bait_class_defaults_to_docs_for_older_bait_records() {
        let bait: Bait = serde_json::from_value(json!({
            "id": "older-bait",
            "surface": "/docs/older",
            "surface_kind": "docs",
            "expected_action": {
                "method": "POST",
                "path": "/api/v2/import/reconcile",
                "header_name": "X-Migration-Trace",
                "header_value": "older"
            }
        }))
        .expect("older bait record should parse");

        assert_eq!(bait.bait_class, BaitClass::Docs);
    }

    #[test]
    fn edge_decision_export_serializes_stable_snake_case_contract() {
        let session_id = SessionId::new();
        let export = EidolonEdgeDecisionExport {
            contract_version: TRUSTED_INGRESS_CONTRACT_VERSION.to_string(),
            observed_at: Utc::now(),
            session_id,
            request: EdgeRequestRef {
                method: "GET".to_string(),
                path: "/openapi.json".to_string(),
            },
            ingress_identity: IngressIdentity {
                source: IngressIdentitySource::VerifiedBot,
                trust_tier: IngressTrustTier::EdgeVerified,
                label: Some("googlebot".to_string()),
                expires_at: None,
            },
            ingress_signals: IngressAdvisorySignals {
                verification_strength: IngressVerificationStrength::High,
                actor_kind: IngressActorKind::Crawler,
                verified_category: Some("Search Engine".to_string()),
                attestation_ref: None,
                vendor_score: Some(12),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                vendor_score_scale: Some("1-99".to_string()),
                detection_ids: vec!["3355446".to_string()],
                edge_action: Some(EdgeRecommendedAction::Allow),
            },
            discovery_recon_score: DiscoveryReconScore {
                detection_score: 2,
                query_score: 1,
                total: 3,
                threshold: 3,
                ..DiscoveryReconScore::default()
            },
            policy: EdgePolicySnapshot {
                state: PolicyState::Observe,
                routing_decision: RoutingDecision::ProtectedUpstream,
                reason: "trusted ingress identity suppressed bait surface intervention before runtime suspicion was established".to_string(),
            },
            evidence: EdgeEvidenceRef {
                event_schema_version: EVENT_SCHEMA_VERSION,
                event_ids: vec![Uuid::new_v4()],
                bundle_ref: "session:ref".to_string(),
            },
            edge_recommendation: EdgeRecommendation {
                action: EdgeRecommendedAction::Allow,
                ttl_seconds: Some(300),
                reason_codes: vec!["trusted_identity".to_string(), "bait_softened".to_string()],
            },
        };

        let serialized = must_ok(serde_json::to_value(export), "edge export should serialize");

        assert_eq!(
            serialized["contract_version"],
            json!(TRUSTED_INGRESS_CONTRACT_VERSION)
        );
        assert_eq!(serialized["edge_recommendation"]["action"], json!("allow"));
        assert_eq!(
            serialized["ingress_identity"]["trust_tier"],
            json!("edge_verified")
        );
        assert_eq!(serialized["ingress_signals"]["vendor_score"], json!(12));
        assert_eq!(serialized["ingress_signals"]["edge_action"], json!("allow"));
        assert_eq!(
            serialized["discovery_recon_score"]["detection_score"],
            json!(2)
        );
        assert_eq!(serialized["discovery_recon_score"]["query_score"], json!(1));
        assert_eq!(serialized["discovery_recon_score"]["total"], json!(3));
        assert_eq!(serialized["discovery_recon_score"]["threshold"], json!(3));
    }
}
