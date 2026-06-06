use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const EVENT_SCHEMA_VERSION: u16 = 2;
pub const TRUSTED_INGRESS_CONTRACT_VERSION: &str = "2026-06-05.v1";

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    RequestSeen {
        method: String,
        path: String,
        safe_headers: Vec<SafeHeaderObservation>,
        #[serde(default)]
        ingress_identity: IngressIdentity,
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
    pub policy: EdgePolicySnapshot,
    pub evidence: EdgeEvidenceRef,
    pub edge_recommendation: EdgeRecommendation,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

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

        let serialized = serde_json::to_value(event).expect("event should serialize");

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
                routing_decision: RoutingDecision::ProtectedUpstream,
            },
        );

        let serialized = serde_json::to_value(event).expect("event should serialize");

        assert_eq!(
            serialized["kind"]["ingress_identity"]["source"],
            "verified_bot"
        );
        assert_eq!(
            serialized["kind"]["ingress_identity"]["trust_tier"],
            "edge_verified"
        );
        assert_eq!(serialized["kind"]["ingress_identity"]["label"], "googlebot");
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

        let parsed: Event = serde_json::from_value(event).expect("legacy event should parse");

        match parsed.kind {
            EventKind::RequestSeen {
                ingress_identity, ..
            } => assert_eq!(ingress_identity, IngressIdentity::default()),
            other => panic!("expected request_seen, got {other:?}"),
        }
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

        let serialized = serde_json::to_value(export).expect("edge export should serialize");

        assert_eq!(
            serialized["contract_version"],
            json!(TRUSTED_INGRESS_CONTRACT_VERSION)
        );
        assert_eq!(serialized["edge_recommendation"]["action"], json!("allow"));
        assert_eq!(
            serialized["ingress_identity"]["trust_tier"],
            json!("edge_verified")
        );
    }
}
