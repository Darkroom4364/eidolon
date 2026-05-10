use std::{
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
};

use eidolon_core::{PolicyState, SessionId};
use serde::{Deserialize, Serialize};

pub const POLICY_STORE_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone)]
pub struct PolicyStateStore {
    path: Option<PathBuf>,
    records: HashMap<SessionId, SessionPolicyRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPolicyRecord {
    pub policy_state: PolicyState,
    pub controlled_reality_depth: u32,
}

impl SessionPolicyRecord {
    pub fn new(policy_state: PolicyState) -> Self {
        Self {
            policy_state,
            controlled_reality_depth: 0,
        }
    }
}

impl Default for SessionPolicyRecord {
    fn default() -> Self {
        Self::new(crate::policy::initial_policy_state())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredPolicyState {
    schema_version: u16,
    sessions: Vec<StoredSessionPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredSessionPolicy {
    session_id: SessionId,
    policy_state: PolicyState,
    #[serde(default)]
    controlled_reality_depth: u32,
}

impl PolicyStateStore {
    pub fn in_memory() -> Self {
        Self {
            path: None,
            records: HashMap::new(),
        }
    }

    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let records = match fs::read(&path) {
            Ok(bytes) if bytes.is_empty() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("policy state store `{}` is empty", path.display()),
                ));
            }
            Ok(bytes) => deserialize_records(&bytes, &path)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => HashMap::new(),
            Err(error) => return Err(error),
        };

        Ok(Self {
            path: Some(path),
            records,
        })
    }

    pub fn policy_state(&self, session_id: SessionId) -> PolicyState {
        self.record(session_id).policy_state
    }

    pub fn record(&self, session_id: SessionId) -> SessionPolicyRecord {
        self.records.get(&session_id).copied().unwrap_or_default()
    }

    pub fn set_policy_state(
        &mut self,
        session_id: SessionId,
        policy_state: PolicyState,
    ) -> io::Result<()> {
        let mut record = self.record(session_id);
        if record.policy_state != policy_state {
            record.policy_state = policy_state;
            if policy_state != PolicyState::ControlledReality {
                record.controlled_reality_depth = 0;
            }
        }
        self.records.insert(session_id, record);
        self.persist()
    }

    pub fn increment_controlled_reality_depth(&mut self, session_id: SessionId) -> io::Result<u32> {
        let mut record = self.record(session_id);
        record.controlled_reality_depth = record.controlled_reality_depth.saturating_add(1);
        self.records.insert(session_id, record);
        self.persist()?;
        Ok(record.controlled_reality_depth)
    }

    fn persist(&self) -> io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };

        let mut sessions: Vec<StoredSessionPolicy> = self
            .records
            .iter()
            .map(|(session_id, record)| StoredSessionPolicy {
                session_id: *session_id,
                policy_state: record.policy_state,
                controlled_reality_depth: record.controlled_reality_depth,
            })
            .collect();
        sessions.sort_by_key(|record| record.session_id.0);

        let stored = StoredPolicyState {
            schema_version: POLICY_STORE_SCHEMA_VERSION,
            sessions,
        };
        let serialized = serde_json::to_vec_pretty(&stored).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to serialize policy state store: {error}"),
            )
        })?;
        let temp_path = path.with_extension("tmp");

        fs::write(&temp_path, serialized)?;
        fs::rename(temp_path, path)
    }
}

fn deserialize_records(
    bytes: &[u8],
    path: &Path,
) -> io::Result<HashMap<SessionId, SessionPolicyRecord>> {
    let stored: StoredPolicyState = serde_json::from_slice(bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "failed to parse policy state store `{}`: {error}",
                path.display()
            ),
        )
    })?;
    if stored.schema_version != POLICY_STORE_SCHEMA_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unsupported policy state store schema version {} in `{}`",
                stored.schema_version,
                path.display()
            ),
        ));
    }

    Ok(stored
        .sessions
        .into_iter()
        .map(|session| {
            (
                session.session_id,
                SessionPolicyRecord {
                    policy_state: session.policy_state,
                    controlled_reality_depth: session.controlled_reality_depth,
                },
            )
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use eidolon_core::PolicyState;

    use super::*;

    fn unique_temp_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos();

        env::temp_dir().join(format!(
            "eidolon-policy-store-{label}-{}-{nanos}.json",
            std::process::id()
        ))
    }

    #[test]
    fn missing_store_defaults_sessions_to_observe() {
        let store = PolicyStateStore::open(unique_temp_path("missing")).expect("store should open");

        assert_eq!(store.policy_state(SessionId::new()), PolicyState::Observe);
    }

    #[test]
    fn persists_policy_state_across_reopen() {
        let path = unique_temp_path("persist");
        let session_id = SessionId::new();

        let mut store = PolicyStateStore::open(&path).expect("store should open");
        store
            .set_policy_state(session_id, PolicyState::ControlledReality)
            .expect("state should persist");

        let reopened = PolicyStateStore::open(&path).expect("store should reopen");

        assert_eq!(
            reopened.policy_state(session_id),
            PolicyState::ControlledReality
        );
    }

    #[test]
    fn malformed_store_fails_closed() {
        let path = unique_temp_path("malformed");
        fs::write(&path, b"not-json").expect("malformed store should write");

        let error = PolicyStateStore::open(&path).expect_err("malformed store should fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("failed to parse"));
    }

    #[test]
    fn unsupported_store_schema_fails_closed() {
        let path = unique_temp_path("unsupported");
        fs::write(&path, br#"{"schema_version":999,"sessions":[]}"#)
            .expect("unsupported store should write");

        let error = PolicyStateStore::open(&path).expect_err("unsupported store should fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error
            .to_string()
            .contains("unsupported policy state store schema version"));
    }

    #[test]
    fn empty_store_file_fails_closed() {
        let path = unique_temp_path("empty");
        fs::write(&path, b"").expect("empty store should write");

        let error = PolicyStateStore::open(&path).expect_err("empty store should fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("is empty"));
    }

    #[test]
    fn increments_controlled_reality_depth() {
        let mut store = PolicyStateStore::in_memory();
        let session_id = SessionId::new();

        assert_eq!(
            store
                .increment_controlled_reality_depth(session_id)
                .expect("depth should increment"),
            1
        );
        assert_eq!(
            store
                .increment_controlled_reality_depth(session_id)
                .expect("depth should increment"),
            2
        );
        assert_eq!(store.record(session_id).controlled_reality_depth, 2);
    }
}
