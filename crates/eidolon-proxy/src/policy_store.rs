use std::{
    collections::HashMap,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use eidolon_core::{PolicyState, SessionId};
use serde::{Deserialize, Serialize};

pub const POLICY_STORE_SCHEMA_VERSION: u16 = 2;
const MIN_SUPPORTED_POLICY_STORE_SCHEMA_VERSION: u16 = 1;

/// Maximum retained session policy records. If enforcement-only churn reaches
/// this bound, the store becomes fail-closed for unknown sessions before any
/// protected record is removed.
pub const MAX_POLICY_SESSIONS: usize = 8192;

/// Time after which a session record that never rose above `Suspicious` may
/// be evicted. Enforcement states are never TTL-evicted either (safety note:
/// eviction must not turn a known contained or blocked session into an
/// unqualified benign session).
pub const POLICY_SESSION_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// Policy states that must never be evicted, by TTL or cardinality.
fn is_eviction_protected(policy_state: PolicyState) -> bool {
    matches!(
        policy_state,
        PolicyState::RateLimited | PolicyState::ControlledReality | PolicyState::Blocked
    )
}

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[derive(Debug, Clone)]
pub struct PolicyStateStore {
    path: Option<PathBuf>,
    records: HashMap<SessionId, SessionPolicyRecord>,
    fail_closed_for_unknown_sessions: bool,
    last_eviction: EvictionStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPolicyRecord {
    pub policy_state: PolicyState,
    pub controlled_reality_depth: u32,
    #[serde(default)]
    pub last_seen_unix_secs: u64,
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
    #[serde(default)]
    pub discovery_linked_bait_surface_fanout: crate::policy::LinkedBaitSurfaceFanout,
    #[serde(default)]
    pub discovery_decoy_write_probe_count: u8,
    #[serde(default)]
    pub discovery_decoy_write_probe_fanout: crate::policy::DecoyWriteProbeFanout,
}

/// Outcome of one eviction pass, for operator visibility.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EvictionStats {
    pub ttl_evicted: usize,
    pub lru_evicted: usize,
    pub protected_fail_closed_evicted: usize,
    pub fail_closed_activated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolicyPersistOutcome {
    Durable,
    CommittedDurabilityUncertain,
}

impl EvictionStats {
    pub fn is_clean(&self) -> bool {
        self.ttl_evicted == 0
            && self.lru_evicted == 0
            && self.protected_fail_closed_evicted == 0
            && !self.fail_closed_activated
    }
}

impl SessionPolicyRecord {
    pub fn new(policy_state: PolicyState) -> Self {
        Self {
            policy_state,
            controlled_reality_depth: 0,
            last_seen_unix_secs: 0,
            reality_escape_attempt_count: 0,
            discovery_surface_fanout: crate::policy::DiscoverySurfaceFanout::default(),
            discovery_request_count: 0,
            discovery_query_seen: false,
            discovery_legacy_openapi_query_seen: false,
            discovery_linked_bait_surface_fanout: crate::policy::LinkedBaitSurfaceFanout::default(),
            discovery_decoy_write_probe_count: 0,
            discovery_decoy_write_probe_fanout: crate::policy::DecoyWriteProbeFanout::default(),
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
    #[serde(default)]
    fail_closed_for_unknown_sessions: bool,
    sessions: Vec<StoredSessionPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredSessionPolicy {
    session_id: SessionId,
    policy_state: PolicyState,
    #[serde(default)]
    controlled_reality_depth: u32,
    #[serde(default)]
    last_seen_unix_secs: u64,
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
    #[serde(default)]
    discovery_linked_bait_surface_fanout: crate::policy::LinkedBaitSurfaceFanout,
    #[serde(default)]
    discovery_decoy_write_probe_count: u8,
    #[serde(default)]
    discovery_decoy_write_probe_fanout: crate::policy::DecoyWriteProbeFanout,
    #[serde(default, skip_serializing)]
    discovery_decoy_write_probe_seen: bool,
    #[serde(default, skip_serializing)]
    discovery_linked_bait_surface_seen: bool,
}

impl PolicyStateStore {
    pub fn in_memory() -> Self {
        Self {
            path: None,
            records: HashMap::new(),
            fail_closed_for_unknown_sessions: false,
            last_eviction: EvictionStats::default(),
        }
    }

    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::open_at(path, current_unix_secs())
    }

    /// Open the store with an explicit "now" (test hook for eviction runs).
    pub fn open_at(path: impl AsRef<Path>, now: u64) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let (records, fail_closed_for_unknown_sessions, needs_schema_migration) =
            match fs::read(&path) {
                Ok(bytes) if bytes.is_empty() => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("policy state store `{}` is empty", path.display()),
                    ));
                }
                Ok(bytes) => deserialize_records(&bytes, &path)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    (HashMap::new(), false, false)
                }
                Err(error) => return Err(error),
            };
        let mut store = Self {
            path: Some(path),
            records,
            fail_closed_for_unknown_sessions,
            last_eviction: EvictionStats::default(),
        };

        // Legacy records written before last_seen tracking get one grace
        // window: they are grandfathered to now instead of being mass-evicted
        // on the first load after upgrade.
        for record in store.records.values_mut() {
            if record.last_seen_unix_secs == 0 {
                record.last_seen_unix_secs = now;
            }
        }

        let stats = store.evict(now);
        store.last_eviction = stats;
        if !stats.is_clean() || needs_schema_migration {
            store.persist()?;
        }

        Ok(store)
    }

    /// Eviction outcome from the last `open`/`open_at` call.
    pub fn last_eviction_stats(&self) -> EvictionStats {
        self.last_eviction
    }

    /// Evict TTL-expired lower-rung records and enforce cardinality oldest-
    /// first. If protected records alone exceed the bound, unknown sessions
    /// become fail-closed before the oldest protected records are removed.
    pub fn evict(&mut self, now: u64) -> EvictionStats {
        let mut stats = EvictionStats::default();

        self.records.retain(|_, record| {
            if is_eviction_protected(record.policy_state) {
                return true;
            }
            let fresh = record
                .last_seen_unix_secs
                .saturating_add(POLICY_SESSION_TTL_SECS)
                > now;
            if !fresh {
                stats.ttl_evicted += 1;
            }
            fresh
        });

        while self.records.len() > MAX_POLICY_SESSIONS {
            let Some(oldest) = self
                .records
                .iter()
                .filter(|(_, record)| !is_eviction_protected(record.policy_state))
                .min_by_key(|(session_id, record)| (record.last_seen_unix_secs, session_id.0))
                .map(|(session_id, _)| *session_id)
            else {
                break;
            };
            self.records.remove(&oldest);
            stats.lru_evicted += 1;
        }

        if self.activate_fail_closed_if_protected_saturated() {
            stats.fail_closed_activated = true;
        }
        if self.records.len() > MAX_POLICY_SESSIONS {
            while self.records.len() > MAX_POLICY_SESSIONS {
                let Some(oldest) = self
                    .records
                    .iter()
                    .min_by_key(|(session_id, record)| (record.last_seen_unix_secs, session_id.0))
                    .map(|(session_id, _)| *session_id)
                else {
                    break;
                };
                self.records.remove(&oldest);
                stats.protected_fail_closed_evicted += 1;
            }
        }

        stats
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn fail_closed_for_unknown_sessions(&self) -> bool {
        self.fail_closed_for_unknown_sessions || self.is_protected_saturated()
    }

    pub fn uses_fail_closed_fallback(&self, session_id: SessionId) -> bool {
        self.fail_closed_for_unknown_sessions() && !self.records.contains_key(&session_id)
    }

    pub fn policy_state(&self, session_id: SessionId) -> PolicyState {
        self.record(session_id).policy_state
    }

    pub fn record(&self, session_id: SessionId) -> SessionPolicyRecord {
        self.records.get(&session_id).copied().unwrap_or_else(|| {
            if self.fail_closed_for_unknown_sessions() {
                SessionPolicyRecord::new(PolicyState::Blocked)
            } else {
                SessionPolicyRecord::default()
            }
        })
    }

    /// Expire stale lower-rung sessions before refreshing the current session.
    ///
    /// Persisting eviction before the refresh prevents an old session from
    /// bypassing its TTL merely by returning after the window has elapsed.
    pub fn note_session_seen(&mut self, session_id: SessionId, now: u64) -> io::Result<()> {
        let stale = self.records.get(&session_id).is_some_and(|record| {
            !is_eviction_protected(record.policy_state)
                && record
                    .last_seen_unix_secs
                    .saturating_add(POLICY_SESSION_TTL_SECS)
                    <= now
        });
        if stale {
            let Some(previous_record) = self.records.remove(&session_id) else {
                return Ok(());
            };
            let previous_eviction = self.last_eviction;
            self.last_eviction = EvictionStats {
                ttl_evicted: 1,
                ..EvictionStats::default()
            };
            match self.persist() {
                Ok(
                    PolicyPersistOutcome::Durable
                    | PolicyPersistOutcome::CommittedDurabilityUncertain,
                ) => {}
                Err(error) => {
                    self.records.insert(session_id, previous_record);
                    self.last_eviction = previous_eviction;
                    eprintln!("eidolon persistence failure: policy state: {error}");
                    return Err(error);
                }
            }
            return Ok(());
        }
        if let Some(record) = self.records.get_mut(&session_id) {
            record.last_seen_unix_secs = now;
        }
        Ok(())
    }

    fn insert_record(&mut self, session_id: SessionId, record: SessionPolicyRecord) {
        let mut record = record;
        record.last_seen_unix_secs = current_unix_secs();
        let existed = match self.records.entry(session_id) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                entry.insert(record);
                true
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(record);
                false
            }
        };
        if existed {
            let mut stats = EvictionStats::default();
            if self.activate_fail_closed_if_protected_saturated() {
                stats.fail_closed_activated = true;
                eprintln!(
                    "eidolon policy store: protected capacity saturated; unknown sessions now fail closed"
                );
            }
            self.last_eviction = stats;
            return;
        }

        let mut stats = self.evict(current_unix_secs());
        if !self.records.contains_key(&session_id) {
            if !self.fail_closed_for_unknown_sessions {
                self.fail_closed_for_unknown_sessions = true;
                stats.fail_closed_activated = true;
            }
            eprintln!("eidolon policy store: capacity saturated; unknown sessions now fail closed");
        } else if stats.lru_evicted > 0 {
            eprintln!(
                "eidolon policy store: evicted {} least-recent sessions at capacity",
                stats.lru_evicted
            );
        }
        self.last_eviction = stats;
    }

    fn is_protected_saturated(&self) -> bool {
        self.records.len() >= MAX_POLICY_SESSIONS
            && self
                .records
                .values()
                .all(|record| is_eviction_protected(record.policy_state))
    }

    fn activate_fail_closed_if_protected_saturated(&mut self) -> bool {
        if self.fail_closed_for_unknown_sessions || !self.is_protected_saturated() {
            return false;
        }
        self.fail_closed_for_unknown_sessions = true;
        true
    }

    fn mutate_and_persist<T>(&mut self, mutate: impl FnOnce(&mut Self) -> T) -> io::Result<T> {
        self.mutate_and_persist_with(mutate, Self::persist)
    }

    fn mutate_and_persist_with<T>(
        &mut self,
        mutate: impl FnOnce(&mut Self) -> T,
        persist: impl FnOnce(&Self) -> io::Result<PolicyPersistOutcome>,
    ) -> io::Result<T> {
        let previous_records = self.records.clone();
        let previous_fail_closed = self.fail_closed_for_unknown_sessions;
        let previous_eviction = self.last_eviction;
        let result = mutate(self);
        match persist(self) {
            Ok(
                PolicyPersistOutcome::Durable | PolicyPersistOutcome::CommittedDurabilityUncertain,
            ) => Ok(result),
            Err(error) => {
                self.records = previous_records;
                self.fail_closed_for_unknown_sessions = previous_fail_closed;
                self.last_eviction = previous_eviction;
                eprintln!("eidolon persistence failure: policy state: {error}");
                Err(error)
            }
        }
    }

    pub fn set_policy_state(
        &mut self,
        session_id: SessionId,
        policy_state: PolicyState,
    ) -> io::Result<()> {
        self.mutate_and_persist(|store| {
            let mut record = store.record(session_id);
            if record.policy_state != policy_state {
                record.policy_state = policy_state;
                if policy_state != PolicyState::ControlledReality {
                    record.controlled_reality_depth = 0;
                    record.reality_escape_attempt_count = 0;
                }
            }
            store.insert_record(session_id, record);
        })
    }

    pub fn increment_controlled_reality_depth(&mut self, session_id: SessionId) -> io::Result<u32> {
        self.mutate_and_persist(|store| {
            let mut record = store.record(session_id);
            record.controlled_reality_depth = record.controlled_reality_depth.saturating_add(1);
            store.insert_record(session_id, record);
            record.controlled_reality_depth
        })
    }

    pub fn note_reality_escape_attempt(&mut self, session_id: SessionId) -> io::Result<u32> {
        self.mutate_and_persist(|store| {
            let mut record = store.record(session_id);
            record.reality_escape_attempt_count =
                record.reality_escape_attempt_count.saturating_add(1);
            store.insert_record(session_id, record);
            record.reality_escape_attempt_count
        })
    }

    pub fn clear_reality_escape_attempts(&mut self, session_id: SessionId) -> io::Result<()> {
        if self.record(session_id).reality_escape_attempt_count == 0 {
            return Ok(());
        }
        self.mutate_and_persist(|store| {
            let mut record = store.record(session_id);
            record.reality_escape_attempt_count = 0;
            store.insert_record(session_id, record);
        })
    }

    pub fn note_discovery_surface_request(
        &mut self,
        session_id: SessionId,
        kind: crate::policy::DiscoverySurfaceKind,
        query_present: bool,
        legacy_openapi_query_seen: bool,
    ) -> io::Result<crate::policy::DiscoveryReconState> {
        self.mutate_and_persist(|store| {
            let mut record = store.record(session_id);
            record.discovery_surface_fanout = record.discovery_surface_fanout.mark(kind);
            record.discovery_request_count = record.discovery_request_count.saturating_add(1);
            record.discovery_query_seen |= query_present;
            record.discovery_legacy_openapi_query_seen |= legacy_openapi_query_seen;
            store.insert_record(session_id, record);
            discovery_recon_state(record)
        })
    }

    pub fn note_linked_bait_surface_request(
        &mut self,
        session_id: SessionId,
        kind: crate::policy::LinkedBaitSurfaceKind,
    ) -> io::Result<crate::policy::DiscoveryReconState> {
        self.mutate_and_persist(|store| {
            let mut record = store.record(session_id);
            record.discovery_linked_bait_surface_fanout =
                record.discovery_linked_bait_surface_fanout.mark(kind);
            store.insert_record(session_id, record);
            discovery_recon_state(record)
        })
    }

    pub fn note_decoy_write_probe(
        &mut self,
        session_id: SessionId,
        kind: crate::policy::DecoyWriteProbePathKind,
    ) -> io::Result<crate::policy::DiscoveryReconState> {
        self.mutate_and_persist(|store| {
            let mut record = store.record(session_id);
            record.discovery_decoy_write_probe_count = record
                .discovery_decoy_write_probe_count
                .saturating_add(1)
                .min(crate::policy::discovery_recon_decoy_write_probe_count_cap());
            record.discovery_decoy_write_probe_fanout =
                record.discovery_decoy_write_probe_fanout.mark(kind);
            store.insert_record(session_id, record);
            discovery_recon_state(record)
        })
    }

    fn persist(&self) -> io::Result<PolicyPersistOutcome> {
        self.persist_with_parent_sync(sync_parent_directory)
    }

    fn persist_with_parent_sync(
        &self,
        sync_parent: impl FnOnce(&Path) -> io::Result<()>,
    ) -> io::Result<PolicyPersistOutcome> {
        let Some(path) = &self.path else {
            return Ok(PolicyPersistOutcome::Durable);
        };

        let mut sessions: Vec<StoredSessionPolicy> = self
            .records
            .iter()
            .map(|(session_id, record)| StoredSessionPolicy {
                session_id: *session_id,
                policy_state: record.policy_state,
                controlled_reality_depth: record.controlled_reality_depth,
                last_seen_unix_secs: record.last_seen_unix_secs,
                reality_escape_attempt_count: record.reality_escape_attempt_count,
                discovery_surface_fanout: record.discovery_surface_fanout,
                discovery_request_count: record.discovery_request_count,
                discovery_query_seen: record.discovery_query_seen,
                discovery_legacy_openapi_query_seen: record.discovery_legacy_openapi_query_seen,
                discovery_linked_bait_surface_fanout: record.discovery_linked_bait_surface_fanout,
                discovery_decoy_write_probe_count: record.discovery_decoy_write_probe_count,
                discovery_decoy_write_probe_fanout: record.discovery_decoy_write_probe_fanout,
                discovery_decoy_write_probe_seen: false,
                discovery_linked_bait_surface_seen: false,
            })
            .collect();
        sessions.sort_by_key(|record| record.session_id.0);

        let stored = StoredPolicyState {
            schema_version: POLICY_STORE_SCHEMA_VERSION,
            fail_closed_for_unknown_sessions: self.fail_closed_for_unknown_sessions,
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
        file.sync_all()?;
        fs::rename(temp_path, path)?;
        match sync_parent(path) {
            Ok(()) => Ok(PolicyPersistOutcome::Durable),
            Err(error) => {
                eprintln!(
                    "eidolon persistence failure: policy state rename committed but parent directory sync failed for `{}`: {error}",
                    path.display()
                );
                Ok(PolicyPersistOutcome::CommittedDurabilityUncertain)
            }
        }
    }
}

fn sync_parent_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn discovery_recon_state(record: SessionPolicyRecord) -> crate::policy::DiscoveryReconState {
    crate::policy::DiscoveryReconState {
        fanout: record.discovery_surface_fanout,
        request_count: record.discovery_request_count,
        query_seen: record.discovery_query_seen,
        legacy_openapi_query_seen: record.discovery_legacy_openapi_query_seen,
        linked_bait_surface_seen: record.discovery_linked_bait_surface_fanout.any_seen(),
        linked_bait_surface_classes: record
            .discovery_linked_bait_surface_fanout
            .distinct_surface_count(),
        decoy_write_probe_seen: record.discovery_decoy_write_probe_count > 0,
        decoy_write_probe_count: record.discovery_decoy_write_probe_count,
        decoy_write_probe_path_classes: record
            .discovery_decoy_write_probe_fanout
            .distinct_path_count(),
    }
}

fn deserialize_records(
    bytes: &[u8],
    path: &Path,
) -> io::Result<(HashMap<SessionId, SessionPolicyRecord>, bool, bool)> {
    let stored: StoredPolicyState = serde_json::from_slice(bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "failed to parse policy state store `{}`: {error}",
                path.display()
            ),
        )
    })?;
    if !(MIN_SUPPORTED_POLICY_STORE_SCHEMA_VERSION..=POLICY_STORE_SCHEMA_VERSION)
        .contains(&stored.schema_version)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unsupported policy state store schema version {} in `{}`",
                stored.schema_version,
                path.display()
            ),
        ));
    }

    let needs_schema_migration = stored.schema_version != POLICY_STORE_SCHEMA_VERSION;
    let fail_closed_for_unknown_sessions = if needs_schema_migration {
        false
    } else {
        stored.fail_closed_for_unknown_sessions
    };
    let records = stored
        .sessions
        .into_iter()
        .map(|session| {
            let mut linked_bait_surface_fanout = session.discovery_linked_bait_surface_fanout;
            if linked_bait_surface_fanout == crate::policy::LinkedBaitSurfaceFanout::default()
                && session.discovery_linked_bait_surface_seen
            {
                linked_bait_surface_fanout = crate::policy::LinkedBaitSurfaceFanout {
                    docs_seen: false,
                    assets_seen: false,
                    other_seen: true,
                };
            }
            let discovery_decoy_write_probe_count = if session.discovery_decoy_write_probe_count
                == 0
                && session.discovery_decoy_write_probe_seen
            {
                1
            } else {
                session
                    .discovery_decoy_write_probe_count
                    .min(crate::policy::discovery_recon_decoy_write_probe_count_cap())
            };
            let mut discovery_decoy_write_probe_fanout = session.discovery_decoy_write_probe_fanout;
            if discovery_decoy_write_probe_fanout == crate::policy::DecoyWriteProbeFanout::default()
                && discovery_decoy_write_probe_count > 0
            {
                discovery_decoy_write_probe_fanout = crate::policy::DecoyWriteProbeFanout {
                    reconcile_seen: false,
                    other_seen: true,
                };
            }
            (
                session.session_id,
                SessionPolicyRecord {
                    policy_state: session.policy_state,
                    controlled_reality_depth: session.controlled_reality_depth,
                    last_seen_unix_secs: session.last_seen_unix_secs,
                    reality_escape_attempt_count: session.reality_escape_attempt_count,
                    discovery_surface_fanout: session.discovery_surface_fanout,
                    discovery_request_count: session.discovery_request_count,
                    discovery_query_seen: session.discovery_query_seen,
                    discovery_legacy_openapi_query_seen: session
                        .discovery_legacy_openapi_query_seen,
                    discovery_linked_bait_surface_fanout: linked_bait_surface_fanout,
                    discovery_decoy_write_probe_count,
                    discovery_decoy_write_probe_fanout,
                },
            )
        })
        .collect();
    Ok((
        records,
        fail_closed_for_unknown_sessions,
        needs_schema_migration,
    ))
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
        assert_eq!(POLICY_STORE_SCHEMA_VERSION, 2);
    }

    fn store_with(records: Vec<(SessionId, PolicyState, u64)>) -> PolicyStateStore {
        PolicyStateStore {
            path: None,
            records: records
                .into_iter()
                .map(|(session_id, policy_state, last_seen)| {
                    (
                        session_id,
                        SessionPolicyRecord {
                            last_seen_unix_secs: last_seen,
                            ..SessionPolicyRecord::new(policy_state)
                        },
                    )
                })
                .collect(),
            fail_closed_for_unknown_sessions: false,
            last_eviction: EvictionStats::default(),
        }
    }

    #[test]
    fn eviction_removes_ttl_stale_low_rungs_but_never_enforcement_states() {
        let stale = 1_000;
        let now = stale + POLICY_SESSION_TTL_SECS + 10;
        let mut store = store_with(vec![
            (SessionId::new(), PolicyState::Normal, stale),
            (SessionId::new(), PolicyState::Observe, stale),
            (SessionId::new(), PolicyState::Suspicious, stale),
            (SessionId::new(), PolicyState::RateLimited, stale),
            (SessionId::new(), PolicyState::ControlledReality, stale),
            (SessionId::new(), PolicyState::Blocked, stale),
            (SessionId::new(), PolicyState::Normal, now),
        ]);

        let stats = store.evict(now);

        assert_eq!(stats.ttl_evicted, 3);
        assert_eq!(stats.lru_evicted, 0);
        assert_eq!(store.len(), 4);
        assert!(store
            .records
            .values()
            .all(|record| is_eviction_protected(record.policy_state)
                || record.last_seen_unix_secs == now));
    }

    #[test]
    fn cardinality_evicts_oldest_evictable_sessions_first() {
        let base = 2_000;
        let mut records: Vec<(SessionId, PolicyState, u64)> = Vec::new();
        let mut protected_ids = Vec::new();
        for index in 0..MAX_POLICY_SESSIONS + 2 {
            if index % 10 == 0 {
                let session_id = SessionId::new();
                protected_ids.push(session_id);
                records.push((session_id, PolicyState::Blocked, base + index as u64));
            } else {
                records.push((SessionId::new(), PolicyState::Observe, base + index as u64));
            }
        }
        let oldest_observe = records[1].0;
        let mut store = store_with(records);

        let stats = store.evict(base + 100_000);

        assert_eq!(store.len(), MAX_POLICY_SESSIONS);
        assert_eq!(stats.lru_evicted, 2);
        assert_eq!(stats.protected_fail_closed_evicted, 0);
        assert!(!stats.fail_closed_activated);
        assert!(!store.records.contains_key(&oldest_observe));
        assert!(protected_ids
            .iter()
            .all(|session_id| store.records.contains_key(session_id)));
    }

    #[test]
    fn enforcement_only_overflow_is_capped_and_unknown_sessions_fail_closed() {
        let base = 3_000;
        let records: Vec<(SessionId, PolicyState, u64)> = (0..MAX_POLICY_SESSIONS + 3)
            .map(|index| (SessionId::new(), PolicyState::Blocked, base + index as u64))
            .collect();
        let oldest = records[0].0;
        let mut store = store_with(records);

        let stats = store.evict(base + 100_000);

        assert_eq!(stats.lru_evicted, 0);
        assert_eq!(stats.ttl_evicted, 0);
        assert_eq!(stats.protected_fail_closed_evicted, 3);
        assert!(stats.fail_closed_activated);
        assert_eq!(store.len(), MAX_POLICY_SESSIONS);
        assert!(store.fail_closed_for_unknown_sessions());
        assert!(!store.records.contains_key(&oldest));
        assert_eq!(store.policy_state(oldest), PolicyState::Blocked);
        assert_eq!(store.policy_state(SessionId::new()), PolicyState::Blocked);
    }

    #[test]
    fn exact_protected_capacity_fails_closed_without_exceeding_the_bound() {
        let records = (0..MAX_POLICY_SESSIONS)
            .map(|index| (SessionId::new(), PolicyState::Blocked, 3_000 + index as u64))
            .collect();
        let mut store = store_with(records);

        let stats = store.evict(100_000);

        assert_eq!(store.len(), MAX_POLICY_SESSIONS);
        assert_eq!(stats.protected_fail_closed_evicted, 0);
        assert!(stats.fail_closed_activated);
        assert!(store.fail_closed_for_unknown_sessions());
        assert!(store.uses_fail_closed_fallback(SessionId::new()));
    }

    #[test]
    fn last_evictable_record_becoming_protected_activates_fail_closed() {
        let mutable_session = SessionId::new();
        let mut records = (0..MAX_POLICY_SESSIONS - 1)
            .map(|index| (SessionId::new(), PolicyState::Blocked, 4_000 + index as u64))
            .collect::<Vec<_>>();
        records.push((mutable_session, PolicyState::Observe, 10_000));
        let mut store = store_with(records);

        store
            .set_policy_state(mutable_session, PolicyState::Blocked)
            .expect("state should update");

        assert_eq!(store.len(), MAX_POLICY_SESSIONS);
        assert!(store.fail_closed_for_unknown_sessions());
        assert!(store.uses_fail_closed_fallback(SessionId::new()));
    }

    #[test]
    fn full_protected_store_rejects_new_lower_state_without_becoming_unbounded() {
        let records = (0..MAX_POLICY_SESSIONS)
            .map(|index| (SessionId::new(), PolicyState::Blocked, 4_000 + index as u64))
            .collect();
        let mut store = store_with(records);
        let new_session = SessionId::new();

        store
            .set_policy_state(new_session, PolicyState::Suspicious)
            .expect("in-memory mutation should succeed");

        assert_eq!(store.len(), MAX_POLICY_SESSIONS);
        assert!(store.fail_closed_for_unknown_sessions());
        assert!(!store.records.contains_key(&new_session));
        assert_eq!(store.policy_state(new_session), PolicyState::Blocked);
    }

    #[test]
    fn fail_closed_saturation_survives_restart() {
        let path = unique_temp_path("fail-closed-roundtrip");
        let records = (0..MAX_POLICY_SESSIONS)
            .map(|index| (SessionId::new(), PolicyState::Blocked, 5_000 + index as u64))
            .collect();
        let mut store = store_with(records);
        store.path = Some(path.clone());
        let stats = store.evict(100_000);
        assert!(stats.fail_closed_activated);
        store.persist().expect("saturated state should persist");

        let reopened = PolicyStateStore::open(&path).expect("saturated store should reopen");

        assert!(reopened.fail_closed_for_unknown_sessions());
        assert_eq!(
            reopened.policy_state(SessionId::new()),
            PolicyState::Blocked
        );
        fs::remove_file(path).expect("store should remove");
    }

    #[test]
    fn legacy_overlimit_protected_state_migrates_bounded_and_fail_closed() {
        let path = unique_temp_path("legacy-overlimit");
        let sessions = (0..MAX_POLICY_SESSIONS + 3)
            .map(|index| {
                serde_json::json!({
                    "session_id": SessionId::new().0,
                    "policy_state": "blocked",
                    "controlled_reality_depth": 0,
                    "last_seen_unix_secs": 6_000 + index as u64,
                })
            })
            .collect::<Vec<_>>();
        fs::write(
            &path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "schema_version": 1,
                "sessions": sessions,
            }))
            .expect("legacy state should serialize"),
        )
        .expect("legacy state should write");

        let migrated = PolicyStateStore::open_at(&path, 100_000).expect("legacy state should open");

        assert_eq!(migrated.len(), MAX_POLICY_SESSIONS);
        assert!(migrated.fail_closed_for_unknown_sessions());
        assert_eq!(
            migrated.policy_state(SessionId::new()),
            PolicyState::Blocked
        );
        let persisted: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("migrated state should read"))
                .expect("migrated state should parse");
        assert_eq!(persisted["schema_version"], POLICY_STORE_SCHEMA_VERSION);
        assert_eq!(persisted["fail_closed_for_unknown_sessions"], true);
        assert_eq!(
            persisted["sessions"]
                .as_array()
                .expect("sessions should be an array")
                .len(),
            MAX_POLICY_SESSIONS
        );
        fs::remove_file(path).expect("store should remove");
    }

    #[test]
    fn legacy_zero_timestamps_are_grandfathered_not_mass_evicted() {
        let path = unique_temp_path("legacy-zero-last-seen");
        let session_id = SessionId::new();
        let stored = serde_json::json!({
            "schema_version": 1,
            "sessions": [
                {
                    "session_id": session_id.0,
                    "policy_state": "observe",
                    "controlled_reality_depth": 0
                }
            ]
        });
        fs::write(
            &path,
            serde_json::to_vec_pretty(&stored).expect("stored should serialize"),
        )
        .expect("stored should write");

        let now = 4_000;
        let store = PolicyStateStore::open_at(&path, now).expect("store should open");

        assert_eq!(store.record(session_id).last_seen_unix_secs, now);
        assert_eq!(store.policy_state(session_id), PolicyState::Observe);
        let migrated: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("migrated store should read"))
                .expect("migrated store should parse");
        assert_eq!(migrated["schema_version"], POLICY_STORE_SCHEMA_VERSION);
    }

    #[test]
    fn mutations_refresh_last_seen_and_persist_it() {
        let path = unique_temp_path("last-seen-roundtrip");
        let session_id = SessionId::new();

        let mut store = PolicyStateStore::open(&path).expect("store should open");
        store
            .set_policy_state(session_id, PolicyState::Suspicious)
            .expect("state should persist");
        let seen = store.record(session_id).last_seen_unix_secs;
        assert!(seen > 0);

        let reopened = PolicyStateStore::open(&path).expect("store should reopen");
        assert_eq!(reopened.record(session_id).last_seen_unix_secs, seen);
    }

    #[test]
    fn note_session_seen_refreshes_freshness_in_memory_only() {
        let session_id = SessionId::new();
        let mut store = store_with(vec![(session_id, PolicyState::Observe, 100)]);

        store
            .note_session_seen(session_id, 500)
            .expect("freshness update should succeed");

        assert_eq!(store.record(session_id).last_seen_unix_secs, 500);
    }

    #[test]
    fn note_session_seen_expires_returning_stale_session_before_refresh() {
        let path = unique_temp_path("returning-stale-session");
        let session_id = SessionId::new();
        let mut store = store_with(vec![(session_id, PolicyState::Suspicious, 100)]);
        store.path = Some(path.clone());
        store.persist().expect("initial state should persist");
        let now = 100 + POLICY_SESSION_TTL_SECS;

        store
            .note_session_seen(session_id, now)
            .expect("stale eviction should persist");

        assert_eq!(store.len(), 0);
        assert_eq!(store.policy_state(session_id), PolicyState::Observe);
        let reopened = PolicyStateStore::open_at(&path, now).expect("store should reopen");
        assert_eq!(reopened.len(), 0);
        fs::remove_file(path).expect("store should remove");
    }

    #[test]
    fn stale_session_eviction_rolls_back_when_persistence_fails() {
        let parent = unique_temp_path("stale-eviction-removed-parent");
        fs::create_dir(&parent).expect("parent should create");
        let path = parent.join("policy.json");
        let session_id = SessionId::new();
        let mut store = store_with(vec![(session_id, PolicyState::Suspicious, 100)]);
        store.path = Some(path.clone());
        store.persist().expect("initial state should persist");
        fs::remove_file(path).expect("state should remove");
        fs::remove_dir(parent).expect("parent should remove");

        store
            .note_session_seen(session_id, 100 + POLICY_SESSION_TTL_SECS)
            .expect_err("stale eviction persistence should fail");

        assert_eq!(store.len(), 1);
        assert_eq!(store.policy_state(session_id), PolicyState::Suspicious);
        assert_eq!(store.record(session_id).last_seen_unix_secs, 100);
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
    fn failed_persist_rolls_back_in_memory_state() {
        let parent = unique_temp_path("removed-parent");
        fs::create_dir(&parent).expect("parent should create");
        let path = parent.join("policy.json");
        let mut store = PolicyStateStore::open(&path).expect("store should open");
        fs::remove_dir(&parent).expect("empty parent should remove");
        let session_id = SessionId::new();

        store
            .set_policy_state(session_id, PolicyState::Blocked)
            .expect_err("persistence should fail after parent removal");

        assert!(store.is_empty());
        assert_eq!(store.policy_state(session_id), PolicyState::Observe);
        assert!(!store.fail_closed_for_unknown_sessions());
    }

    #[test]
    fn committed_directory_sync_failure_keeps_policy_memory_and_disk_aligned() {
        let path = unique_temp_path("committed-directory-sync-failure");
        let session_id = SessionId::new();
        let mut store = PolicyStateStore::open(&path).expect("store should open");

        store
            .mutate_and_persist_with(
                |store| {
                    store.insert_record(session_id, SessionPolicyRecord::new(PolicyState::Blocked));
                },
                |store| {
                    store.persist_with_parent_sync(|_| {
                        Err(io::Error::other("directory sync failed"))
                    })
                },
            )
            .expect("committed mutation should remain active");

        assert_eq!(store.policy_state(session_id), PolicyState::Blocked);
        let reopened = PolicyStateStore::open(&path).expect("committed state should reopen");
        assert_eq!(reopened.policy_state(session_id), PolicyState::Blocked);
        fs::remove_file(path).expect("store should remove");
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
                linked_bait_surface_seen: false,
                linked_bait_surface_classes: 0,
                decoy_write_probe_seen: false,
                decoy_write_probe_count: 0,
                decoy_write_probe_path_classes: 0,
            }
        );
        assert_eq!(
            must_ok(
                store.note_linked_bait_surface_request(
                    session_id,
                    crate::policy::LinkedBaitSurfaceKind::Docs,
                ),
                "linked bait surface should persist"
            ),
            crate::policy::DiscoveryReconState {
                fanout: crate::policy::DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: false,
                },
                request_count: 1,
                query_seen: true,
                legacy_openapi_query_seen: false,
                linked_bait_surface_seen: true,
                linked_bait_surface_classes: 1,
                decoy_write_probe_seen: false,
                decoy_write_probe_count: 0,
                decoy_write_probe_path_classes: 0,
            }
        );
        assert_eq!(
            must_ok(
                store.note_linked_bait_surface_request(
                    session_id,
                    crate::policy::LinkedBaitSurfaceKind::Assets,
                ),
                "second linked bait surface should persist"
            ),
            crate::policy::DiscoveryReconState {
                fanout: crate::policy::DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: false,
                },
                request_count: 1,
                query_seen: true,
                legacy_openapi_query_seen: false,
                linked_bait_surface_seen: true,
                linked_bait_surface_classes: 2,
                decoy_write_probe_seen: false,
                decoy_write_probe_count: 0,
                decoy_write_probe_path_classes: 0,
            }
        );
        assert_eq!(
            must_ok(
                store.note_decoy_write_probe(
                    session_id,
                    crate::policy::DecoyWriteProbePathKind::Reconcile,
                ),
                "blind decoy write probe should persist"
            ),
            crate::policy::DiscoveryReconState {
                fanout: crate::policy::DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: false,
                },
                request_count: 1,
                query_seen: true,
                legacy_openapi_query_seen: false,
                linked_bait_surface_seen: true,
                linked_bait_surface_classes: 2,
                decoy_write_probe_seen: true,
                decoy_write_probe_count: 1,
                decoy_write_probe_path_classes: 1,
            }
        );
        assert_eq!(
            must_ok(
                store.note_decoy_write_probe(
                    session_id,
                    crate::policy::DecoyWriteProbePathKind::Other,
                ),
                "repeated blind decoy write probe should cap cleanly"
            ),
            crate::policy::DiscoveryReconState {
                fanout: crate::policy::DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: false,
                },
                request_count: 1,
                query_seen: true,
                legacy_openapi_query_seen: false,
                linked_bait_surface_seen: true,
                linked_bait_surface_classes: 2,
                decoy_write_probe_seen: true,
                decoy_write_probe_count: 2,
                decoy_write_probe_path_classes: 2,
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
                linked_bait_surface_seen: true,
                linked_bait_surface_classes: 2,
                decoy_write_probe_seen: true,
                decoy_write_probe_count: 2,
                decoy_write_probe_path_classes: 2,
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
        assert!(
            reopened
                .record(session_id)
                .discovery_linked_bait_surface_fanout
                .docs_seen
        );
        assert!(
            reopened
                .record(session_id)
                .discovery_linked_bait_surface_fanout
                .assets_seen
        );
        assert_eq!(
            reopened
                .record(session_id)
                .discovery_decoy_write_probe_count,
            2
        );
        assert!(
            reopened
                .record(session_id)
                .discovery_decoy_write_probe_fanout
                .reconcile_seen
        );
        assert!(
            reopened
                .record(session_id)
                .discovery_decoy_write_probe_fanout
                .other_seen
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
        assert_eq!(
            reopened
                .record(session_id)
                .discovery_decoy_write_probe_count,
            0
        );
        assert!(!reopened
            .record(session_id)
            .discovery_linked_bait_surface_fanout
            .any_seen());
    }

    #[test]
    fn older_store_with_legacy_linked_bait_seen_migrates_to_fanout() {
        let path = unique_temp_path("legacy-linked-bait");
        let session_id = SessionId::new();
        let legacy = format!(
            "{{\"schema_version\":1,\"sessions\":[{{\"session_id\":\"{}\",\"policy_state\":\"observe\",\"controlled_reality_depth\":0,\"discovery_linked_bait_surface_seen\":true}}]}}",
            session_id.0
        );
        must_ok(
            fs::write(&path, legacy),
            "legacy linked-bait store should write",
        );

        let reopened = must_ok(
            PolicyStateStore::open(&path),
            "legacy linked-bait store should reopen",
        );
        assert_eq!(
            reopened
                .record(session_id)
                .discovery_linked_bait_surface_fanout,
            crate::policy::LinkedBaitSurfaceFanout {
                docs_seen: false,
                assets_seen: false,
                other_seen: true,
            }
        );
    }

    #[test]
    fn older_store_with_legacy_decoy_write_probe_seen_migrates_to_count() {
        let path = unique_temp_path("legacy-decoy-write");
        let session_id = SessionId::new();
        let legacy = format!(
            "{{\"schema_version\":1,\"sessions\":[{{\"session_id\":\"{}\",\"policy_state\":\"observe\",\"controlled_reality_depth\":0,\"discovery_decoy_write_probe_seen\":true}}]}}",
            session_id.0
        );
        must_ok(
            fs::write(&path, legacy),
            "legacy decoy-write store should write",
        );

        let reopened = must_ok(
            PolicyStateStore::open(&path),
            "legacy decoy-write store should reopen",
        );

        assert_eq!(
            reopened
                .record(session_id)
                .discovery_decoy_write_probe_count,
            1
        );
        assert!(
            reopened
                .record(session_id)
                .discovery_decoy_write_probe_fanout
                .other_seen
        );
    }
}
