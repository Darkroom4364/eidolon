use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    RequestSeen {
        method: String,
        path: String,
    },
    BaitExposed {
        bait_id: BaitId,
        surface: String,
    },
    BaitActionObserved {
        bait_id: BaitId,
        method: String,
        path: String,
    },
    PolicyChanged {
        from: PolicyState,
        to: PolicyState,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub id: Uuid,
    pub session_id: SessionId,
    pub observed_at: DateTime<Utc>,
    pub kind: EventKind,
}

impl Event {
    pub fn new(session_id: SessionId, kind: EventKind) -> Self {
        Self {
            id: Uuid::new_v4(),
            session_id,
            observed_at: Utc::now(),
            kind,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyState {
    Normal,
    Observe,
    Suspicious,
    ControlledReality,
    RateLimited,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
