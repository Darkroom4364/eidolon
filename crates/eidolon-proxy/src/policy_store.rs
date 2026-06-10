use std::{
    collections::HashMap,
    fs,
    io::{self, Write},
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
    #[serde(default)]
    pub reality_escape_attempt_count: u32,
    #[serde(default)]
    pub discovery_surface_fanout: crate::policy::DiscoverySurfaceFanout,
    #[serde(default)]
    pub discovery_request_count: u32,
    #[serde(default)]
    pub discovery_query_seen: bool,
    #[serde(default)]
    pub discovery_legacy_openapi_query_seen: bool,
}

impl SessionPolicyRecord {
    pub fn new(policy_state: PolicyState) -> Self {
        Self {
            policy_state,
            controlled_reality_depth: 0,
            reality_escape_attempt_count: 0,
            discovery_surface_fanout: crate::policy::DiscoverySurfaceFanout::default(),
            discovery_request_count: 0,
            discovery_query_seen: false,
            discovery_legacy_openapi_query_seen: false,
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
    #[serde(default)]
    reality_escape_attempt_count: u32,
    #[serde(default)]
    discovery_surface_fanout: crate::policy::DiscoverySurfaceFanout,
    #[serde(default)]
    discovery_request_count: u32,
    #[serde(default)]
    discovery_query_seen: bool,
    #[serde(default)]
    discovery_legacy_openapi_query_seen: bool,
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
                record.reality_escape_attempt_count = 0;
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

    pub fn note_reality_escape_attempt(&mut self, session_id: SessionId) -> io::Result<u32> {
        let mut record = self.record(session_id);
        record.reality_escape_attempt_count = record.reality_escape_attempt_count.saturating_add(1);
        self.records.insert(session_id, record);
        self.persist()?;
        Ok(record.reality_escape_attempt_count)
    }

    pub fn clear_reality_escape_attempts(&mut self, session_id: SessionId) -> io::Result<()> {
        let mut record = self.record(session_id);
        if record.reality_escape_attempt_count == 0 {
            return Ok(());
        }

        record.reality_escape_attempt_count = 0;
        self.records.insert(session_id, record);
        self.persist()
    }

    pub fn note_discovery_surface_request(
        &mut self,
        session_id: SessionId,
        kind: crate::policy::DiscoverySurfaceKind,
        query_present: bool,
        legacy_openapi_query_seen: bool,
    ) -> io::Result<crate::policy::DiscoveryReconState> {
        let mut record = self.record(session_id);
        record.discovery_surface_fanout = record.discovery_surface_fanout.mark(kind);
        record.discovery_request_count = record.discovery_request_count.saturating_add(1);
        record.discovery_query_seen |= query_present;
        record.discovery_legacy_openapi_query_seen |= legacy_openapi_query_seen;
        self.records.insert(session_id, record);
        self.persist()?;
        Ok(crate::policy::DiscoveryReconState {
            fanout: record.discovery_surface_fanout,
            request_count: record.discovery_request_count,
            query_seen: record.discovery_query_seen,
            legacy_openapi_query_seen: record.discovery_legacy_openapi_query_seen,
        })
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
                reality_escape_attempt_count: record.reality_escape_attempt_count,
                discovery_surface_fanout: record.discovery_surface_fanout,
                discovery_request_count: record.discovery_request_count,
                discovery_query_seen: record.discovery_query_seen,
                discovery_legacy_openapi_query_seen: record.discovery_legacy_openapi_query_seen,
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

        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temp_path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }

        file.write_all(&serialized)?;
        file.flush()?;
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
                    reality_escape_attempt_count: session.reality_escape_attempt_count,
                    discovery_surface_fanout: session.discovery_surface_fanout,
                    discovery_request_count: session.discovery_request_count,
                    discovery_query_seen: session.discovery_query_seen,
                    discovery_legacy_openapi_query_seen: session
                        .discovery_legacy_openapi_query_seen,
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
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn must_ok<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{context}: {error}"),
        }
    }

    fn unique_temp_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|error| panic!("system clock should be after epoch: {error}"))
            .as_nanos();

        env::temp_dir().join(format!(
            "eidolon-policy-store-{label}-{}-{nanos}.json",
            std::process::id()
        ))
    }

    #[test]
    fn policy_store_schema_version_matches_current_contract() {
        assert_eq!(POLICY_STORE_SCHEMA_VERSION, 1);
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

    #[cfg(unix)]
    #[test]
    fn persisted_policy_state_is_owner_only() {
        let path = unique_temp_path("owner-only");
        let session_id = SessionId::new();

        let mut store = must_ok(PolicyStateStore::open(&path), "store should open");
        store
            .set_policy_state(session_id, PolicyState::ControlledReality)
            .unwrap_or_else(|error| panic!("state should persist: {error}"));

        let mode = must_ok(fs::metadata(&path), "policy state metadata should read")
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(mode, 0o600);

        must_ok(fs::remove_file(path), "policy state should remove");
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

    #[test]
    fn leaving_controlled_reality_resets_depth() {
        let mut store = PolicyStateStore::in_memory();
        let session_id = SessionId::new();

        store
            .set_policy_state(session_id, PolicyState::ControlledReality)
            .expect("state should update");
        assert_eq!(
            store
                .note_reality_escape_attempt(session_id)
                .expect("escape attempts should increment"),
            1
        );
        assert_eq!(
            store
                .increment_controlled_reality_depth(session_id)
                .expect("depth should increment"),
            1
        );
        store
            .set_policy_state(session_id, PolicyState::Observe)
            .expect("state should update");

        let record = store.record(session_id);
        assert_eq!(record.policy_state, PolicyState::Observe);
        assert_eq!(record.controlled_reality_depth, 0);
        assert_eq!(record.reality_escape_attempt_count, 0);
    }

    #[test]
    fn reality_escape_attempts_increment_and_clear() {
        let mut store = PolicyStateStore::in_memory();
        let session_id = SessionId::new();

        assert_eq!(
            store
                .note_reality_escape_attempt(session_id)
                .expect("escape attempts should increment"),
            1
        );
        assert_eq!(
            store
                .note_reality_escape_attempt(session_id)
                .expect("escape attempts should increment"),
            2
        );
        assert_eq!(store.record(session_id).reality_escape_attempt_count, 2);

        store
            .clear_reality_escape_attempts(session_id)
            .expect("escape attempts should clear");
        assert_eq!(store.record(session_id).reality_escape_attempt_count, 0);
    }

    #[test]
    fn notes_and_persists_discovery_recon_state() {
        let path = unique_temp_path("fanout");
        let session_id = SessionId::new();

        let mut store = must_ok(PolicyStateStore::open(&path), "store should open");
        assert_eq!(
            must_ok(
                store.note_discovery_surface_request(
                    session_id,
                    crate::policy::DiscoverySurfaceKind::Docs,
                    true,
                    false,
                ),
                "docs should persist"
            ),
            crate::policy::DiscoveryReconState {
                fanout: crate::policy::DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: false,
                },
                request_count: 1,
                query_seen: true,
                legacy_openapi_query_seen: false,
            }
        );
        assert_eq!(
            must_ok(
                store.note_discovery_surface_request(
                    session_id,
                    crate::policy::DiscoverySurfaceKind::OpenApi,
                    true,
                    true,
                ),
                "openapi should persist"
            ),
            crate::policy::DiscoveryReconState {
                fanout: crate::policy::DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: true,
                },
                request_count: 2,
                query_seen: true,
                legacy_openapi_query_seen: true,
            }
        );

        let reopened = must_ok(PolicyStateStore::open(&path), "store should reopen");
        assert_eq!(
            reopened.record(session_id).discovery_surface_fanout,
            crate::policy::DiscoverySurfaceFanout {
                docs_seen: true,
                openapi_seen: true,
            }
        );
        assert_eq!(reopened.record(session_id).discovery_request_count, 2);
        assert!(reopened.record(session_id).discovery_query_seen);
        assert!(
            reopened
                .record(session_id)
                .discovery_legacy_openapi_query_seen
        );
    }

    #[test]
    fn older_store_without_discovery_fanout_defaults_cleanly() {
        let path = unique_temp_path("legacy-fanout");
        let session_id = SessionId::new();
        let legacy = format!(
            "{{\"schema_version\":1,\"sessions\":[{{\"session_id\":\"{}\",\"policy_state\":\"observe\",\"controlled_reality_depth\":0}}]}}",
            session_id.0
        );
        must_ok(fs::write(&path, legacy), "legacy store should write");

        let reopened = must_ok(PolicyStateStore::open(&path), "legacy store should reopen");
        assert_eq!(
            reopened.record(session_id).discovery_surface_fanout,
            crate::policy::DiscoverySurfaceFanout::default()
        );
        assert_eq!(reopened.record(session_id).reality_escape_attempt_count, 0);
        assert_eq!(reopened.record(session_id).discovery_request_count, 0);
        assert!(!reopened.record(session_id).discovery_query_seen);
        assert!(
            !reopened
                .record(session_id)
                .discovery_legacy_openapi_query_seen
        );
    }
}
