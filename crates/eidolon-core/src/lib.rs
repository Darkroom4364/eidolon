use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const EVENT_SCHEMA_VERSION: u16 = 1;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    RequestSeen {
        method: String,
        path: String,
        safe_headers: Vec<SafeHeaderObservation>,
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

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
}
