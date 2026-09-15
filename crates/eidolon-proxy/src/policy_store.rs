use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use eidolon_core::{
    ControlledRealityInteraction, ControlledRealityInteractionAction,
    ControlledRealityWorkflowState, Event, EventKind, EventSource, PolicyState, RequestId,
    RoutingDecision, SessionId, EVENT_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::controlled_reality::ControlledRealityResponder;

pub const POLICY_STORE_SCHEMA_VERSION: u16 = 3;
pub const MIN_SUPPORTED_POLICY_STORE_SCHEMA_VERSION: u16 = 1;

/// Maximum retained session policy records. If enforcement-only churn reaches
/// this bound, the store becomes fail-closed for unknown sessions before any
/// protected record is removed.
pub const MAX_POLICY_SESSIONS: usize = 8192;

/// Maximum serialized policy-state snapshot size. This leaves explicit
/// headroom above 8,192 fully populated production records while bounding
/// both startup reads and every replacement write.
pub const MAX_POLICY_STORE_BYTES: usize = 32 * 1024 * 1024;

const POLICY_STORE_READ_CHUNK_BYTES: usize = 8 * 1024;

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

fn oversized_policy_store_error(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "policy state store `{}` exceeds the fixed {} byte limit",
            path.display(),
            MAX_POLICY_STORE_BYTES
        ),
    )
}

fn oversized_serialized_policy_store_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "serialized policy state store exceeds the fixed {} byte limit",
            MAX_POLICY_STORE_BYTES
        ),
    )
}

fn invalid_pending_contract_error(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "policy state store `{}` contains an invalid pending controlled-reality contract",
            path.display()
        ),
    )
}

fn no_controlled_reality_interaction_sha256() -> [u8; 32] {
    // `None::<ControlledRealityInteraction>` has the fixed JSON encoding
    // `null`; use those canonical bytes without retaining response content.
    Sha256::digest(b"null").into()
}

fn controlled_reality_interaction_sha256(
    interaction: &Option<ControlledRealityInteraction>,
) -> Option<[u8; 32]> {
    serde_json::to_vec(interaction)
        .ok()
        .map(|serialized| Sha256::digest(serialized).into())
}

fn pending_interaction_kind(
    interaction: Option<&ControlledRealityInteraction>,
) -> Option<ControlledRealityPendingInteractionKind> {
    interaction.map(|interaction| match &interaction.action {
        ControlledRealityInteractionAction::JobSubmitted => {
            ControlledRealityPendingInteractionKind::JobSubmitted
        }
        ControlledRealityInteractionAction::StatusRead => {
            ControlledRealityPendingInteractionKind::StatusRead
        }
        ControlledRealityInteractionAction::ArtifactRead { .. } => {
            ControlledRealityPendingInteractionKind::ArtifactRead
        }
    })
}

fn read_policy_store_bytes(path: &Path) -> io::Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let advertised_len = file.metadata()?.len();
    read_policy_store_bytes_from_reader(file, path, advertised_len)
}

/// Read through a fixed-size stack buffer so both the bytes retained and each
/// allocation request stay at or below `MAX_POLICY_STORE_BYTES + 1`. The
/// metadata length is only an early rejection: the bounded read remains the
/// authority if a file grows after the metadata call.
fn read_policy_store_bytes_from_reader(
    mut reader: impl Read,
    path: &Path,
    advertised_len: u64,
) -> io::Result<Vec<u8>> {
    if advertised_len > MAX_POLICY_STORE_BYTES as u64 {
        return Err(oversized_policy_store_error(path));
    }

    let allocation_bound = MAX_POLICY_STORE_BYTES + 1;
    let initial_capacity = usize::try_from(advertised_len)
        .unwrap_or(allocation_bound)
        .saturating_add(1)
        .min(allocation_bound);
    let mut bytes = Vec::with_capacity(initial_capacity);
    let mut chunk = [0_u8; POLICY_STORE_READ_CHUNK_BYTES];

    loop {
        let remaining = allocation_bound - bytes.len();
        if remaining == 0 {
            return Err(oversized_policy_store_error(path));
        }
        let requested = remaining.min(POLICY_STORE_READ_CHUNK_BYTES);
        let read = loop {
            match reader.read(&mut chunk[..requested]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => break result?,
            }
        };
        if read > requested {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "policy state reader returned an invalid byte count",
            ));
        }
        if read == 0 {
            break;
        }

        let required = bytes.len() + read;
        if bytes.capacity() < required {
            let target_capacity = bytes
                .capacity()
                .saturating_mul(2)
                .max(POLICY_STORE_READ_CHUNK_BYTES)
                .max(required)
                .min(allocation_bound);
            bytes.reserve_exact(target_capacity - bytes.len());
            if bytes.capacity() < required {
                return Err(io::Error::other(
                    "policy state buffer did not satisfy its bounded reservation",
                ));
            }
        }
        bytes.extend_from_slice(&chunk[..read]);
    }

    if bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("policy state store `{}` is empty", path.display()),
        ));
    }
    Ok(bytes)
}

#[derive(Debug, Clone)]
pub struct PolicyStateStore {
    path: Option<PathBuf>,
    records: HashMap<SessionId, SessionPolicyRecord>,
    fail_closed_for_unknown_sessions: bool,
    last_eviction: EvictionStats,
    startup_persist_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPolicyRecord {
    pub policy_state: PolicyState,
    pub controlled_reality_depth: u32,
    #[serde(default)]
    pub controlled_reality_workflow_state: ControlledRealityWorkflowState,
    #[serde(default)]
    pub controlled_reality_origin_request_id: Option<RequestId>,
    #[serde(default)]
    pub controlled_reality_pending_update: Option<ControlledRealityPendingUpdate>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlledRealityProgress {
    pub depth: u32,
    pub from_state: ControlledRealityWorkflowState,
    pub to_state: ControlledRealityWorkflowState,
    pub origin_request_id: Option<RequestId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlledRealityPendingUpdate {
    pub request_id: RequestId,
    #[serde(default)]
    pub request_action: ControlledRealityRequestAction,
    pub previous_depth: u32,
    pub previous_state: ControlledRealityWorkflowState,
    pub previous_origin_request_id: Option<RequestId>,
    #[serde(default)]
    pub commit_policy_state: Option<PolicyState>,
    #[serde(default)]
    pub expected_policy_changed: Option<Event>,
    #[serde(default)]
    pub expected_response: Option<ControlledRealityPendingResponse>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlledRealityPendingResponse {
    pub event_id: Uuid,
    pub policy_state: PolicyState,
    pub status: u16,
    pub routing_decision: RoutingDecision,
    pub interaction_kind: Option<ControlledRealityPendingInteractionKind>,
    pub controlled_reality_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingControlledRealityRecoveryDecision {
    pub session_id: SessionId,
    pub request_id: RequestId,
    pub durable_response_seen: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlledRealityPendingInteractionKind {
    JobSubmitted,
    StatusRead,
    ArtifactRead,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlledRealityRequestAction {
    BranchRead,
    JobSubmitted,
    StatusRead,
    ArtifactRead,
    MethodRejected,
    #[default]
    UnknownResource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolicyPersistOutcome {
    Durable,
    CommittedDurabilityUncertain,
}

/// Serialization sink that retains at most the fixed limit plus one sentinel
/// byte. Once full it keeps accepting and discarding serializer output so a
/// large in-memory field cannot make the replacement buffer grow unbounded.
struct BoundedPolicyStoreSerialization {
    bytes: Vec<u8>,
}

#[derive(Default)]
struct CountingPolicyStoreSerialization {
    bytes: u64,
}

impl Write for CountingPolicyStoreSerialization {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let incoming = u64::try_from(buffer.len())
            .map_err(|_| io::Error::other("policy serialization length did not fit in u64"))?;
        self.bytes = self
            .bytes
            .checked_add(incoming)
            .ok_or_else(|| io::Error::other("policy serialization length overflow"))?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl BoundedPolicyStoreSerialization {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(POLICY_STORE_READ_CHUNK_BYTES),
        }
    }

    fn finish(self) -> io::Result<Vec<u8>> {
        if self.bytes.len() > MAX_POLICY_STORE_BYTES {
            return Err(oversized_serialized_policy_store_error());
        }
        Ok(self.bytes)
    }
}

impl Write for BoundedPolicyStoreSerialization {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let allocation_bound = MAX_POLICY_STORE_BYTES + 1;
        let retained = buffer.len().min(allocation_bound - self.bytes.len());
        let required = self.bytes.len() + retained;
        if self.bytes.capacity() < required {
            let target_capacity = self
                .bytes
                .capacity()
                .saturating_mul(2)
                .max(required)
                .min(allocation_bound);
            self.bytes.reserve_exact(target_capacity - self.bytes.len());
        }
        self.bytes.extend_from_slice(&buffer[..retained]);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
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
            controlled_reality_workflow_state: ControlledRealityWorkflowState::Ready,
            controlled_reality_origin_request_id: None,
            controlled_reality_pending_update: None,
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

impl StoredSessionPolicy {
    fn from_record(session_id: SessionId, record: &SessionPolicyRecord) -> Self {
        Self {
            session_id,
            policy_state: record.policy_state,
            controlled_reality_depth: record.controlled_reality_depth,
            controlled_reality_workflow_state: record.controlled_reality_workflow_state,
            controlled_reality_origin_request_id: record.controlled_reality_origin_request_id,
            controlled_reality_pending_update: record.controlled_reality_pending_update.clone(),
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
        }
    }
}

fn pending_update_for_reconciliation(
    record: &SessionPolicyRecord,
    request_id: RequestId,
    durable_response_seen: bool,
) -> io::Result<Option<ControlledRealityPendingUpdate>> {
    let Some(pending_update) = record.controlled_reality_pending_update.clone() else {
        return Ok(None);
    };
    if pending_update.request_id != request_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "controlled-reality workflow recovery request id did not match pending state",
        ));
    }
    if durable_response_seen && pending_update.expected_response.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "controlled-reality workflow cannot roll forward without a response contract",
        ));
    }
    if durable_response_seen
        && pending_update.commit_policy_state.is_some()
            != pending_update.expected_policy_changed.is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "controlled-reality policy transition contract was incomplete",
        ));
    }
    Ok(Some(pending_update))
}

fn apply_pending_reconciliation(
    record: &mut SessionPolicyRecord,
    pending_update: &ControlledRealityPendingUpdate,
    durable_response_seen: bool,
) {
    if !durable_response_seen {
        record.controlled_reality_depth = pending_update.previous_depth;
        record.controlled_reality_workflow_state = pending_update.previous_state;
        record.controlled_reality_origin_request_id = pending_update.previous_origin_request_id;
    } else if let Some(policy_state) = pending_update.commit_policy_state {
        record.policy_state = policy_state;
        if policy_state != PolicyState::ControlledReality {
            record.controlled_reality_depth = 0;
            record.controlled_reality_workflow_state = ControlledRealityWorkflowState::Ready;
            record.controlled_reality_origin_request_id = None;
            record.reality_escape_attempt_count = 0;
        }
    }
    record.controlled_reality_pending_update = None;
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
    controlled_reality_workflow_state: ControlledRealityWorkflowState,
    #[serde(default)]
    controlled_reality_origin_request_id: Option<RequestId>,
    #[serde(default)]
    controlled_reality_pending_update: Option<ControlledRealityPendingUpdate>,
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
            startup_persist_required: false,
        }
    }

    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::open_at(path, current_unix_secs())
    }

    /// Perform the bounded parse, snapshot-local validation, startup
    /// migration/eviction, and any required serialization without filesystem
    /// mutation. Production uses this before touching its lease file, then
    /// calls `open` again under the lease so the second read remains
    /// authoritative against path races.
    pub fn validate_without_mutation(path: impl AsRef<Path>) -> io::Result<()> {
        Self::load_at(path.as_ref().to_path_buf(), current_unix_secs(), false).map(drop)
    }

    /// Prepare the authoritative under-lease snapshot without mutating it.
    /// The caller can validate dependent durable inputs before committing any
    /// required startup migration or eviction with `finish_prepared_startup`.
    pub fn prepare_open(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::load_at(path.as_ref().to_path_buf(), current_unix_secs(), false)
    }

    pub fn finish_prepared_startup(mut self) -> io::Result<Self> {
        if self.startup_persist_required {
            self.persist()?;
            self.startup_persist_required = false;
        }
        Ok(self)
    }

    /// Open the store with an explicit "now" (test hook for eviction runs).
    pub fn open_at(path: impl AsRef<Path>, now: u64) -> io::Result<Self> {
        Self::load_at(path.as_ref().to_path_buf(), now, true)
    }

    fn load_at(path: PathBuf, now: u64, persist_changes: bool) -> io::Result<Self> {
        validate_policy_state_temp_without_mutation(&path)?;
        let (records, fail_closed_for_unknown_sessions, needs_schema_migration) =
            match read_policy_store_bytes(&path) {
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
            startup_persist_required: false,
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
        store.startup_persist_required = !stats.is_clean() || needs_schema_migration;
        if store.startup_persist_required {
            if persist_changes {
                store.persist()?;
                store.startup_persist_required = false;
            } else {
                store.serialize_current_state()?;
            }
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
        self.records.get(&session_id).cloned().unwrap_or_else(|| {
            if self.fail_closed_for_unknown_sessions() {
                SessionPolicyRecord::new(PolicyState::Blocked)
            } else {
                SessionPolicyRecord::default()
            }
        })
    }

    pub fn pending_controlled_reality_sessions(&self) -> Vec<SessionId> {
        let mut sessions = self
            .records
            .iter()
            .filter_map(|(session_id, record)| {
                record
                    .controlled_reality_pending_update
                    .is_some()
                    .then_some(*session_id)
            })
            .collect::<Vec<_>>();
        sessions.sort_by_key(|session_id| session_id.0);
        sessions
    }

    pub fn pending_event_log_recovery_coordinates(
        &self,
    ) -> Vec<(SessionId, RequestId, Option<Uuid>)> {
        let mut targets = self
            .records
            .iter()
            .filter_map(|(session_id, record)| {
                record
                    .controlled_reality_pending_update
                    .as_ref()
                    .map(|pending| {
                        (
                            *session_id,
                            pending.request_id,
                            pending
                                .expected_policy_changed
                                .as_ref()
                                .map(|event| event.id),
                        )
                    })
            })
            .collect::<Vec<_>>();
        targets.sort_by_key(|(session_id, _, _)| session_id.0);
        targets
    }

    /// Validate every policy snapshot that ordered startup reconciliation
    /// will persist. The initial current-schema file may be compact enough to
    /// read while its pretty canonical form is over the write limit, so this
    /// uses exact counting plus per-record canonical deltas instead of
    /// repeatedly materializing the complete store.
    pub fn validate_pending_reconciliation_plan_without_mutation(
        &self,
        decisions: &[PendingControlledRealityRecoveryDecision],
        reconciliation_unix_secs: u64,
    ) -> io::Result<()> {
        let pending_sessions = self.pending_controlled_reality_sessions();
        if decisions.len() != pending_sessions.len()
            || decisions
                .iter()
                .zip(&pending_sessions)
                .any(|(decision, session_id)| decision.session_id != *session_id)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "policy reconciliation plan did not match every pending workflow in order",
            ));
        }
        if decisions.is_empty() {
            return Ok(());
        }

        let mut planned_bytes = self.serialized_current_state_len()?;
        for decision in decisions {
            let record = self.records.get(&decision.session_id).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "policy reconciliation plan referenced an absent session",
                )
            })?;
            let pending = pending_update_for_reconciliation(
                record,
                decision.request_id,
                decision.durable_response_seen,
            )?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "policy reconciliation plan referenced a settled session",
                )
            })?;
            let before_bytes = self.serialized_record_envelope_len(decision.session_id, record)?;
            let mut reconciled = record.clone();
            apply_pending_reconciliation(&mut reconciled, &pending, decision.durable_response_seen);
            reconciled.last_seen_unix_secs = reconciliation_unix_secs;
            let after_bytes =
                self.serialized_record_envelope_len(decision.session_id, &reconciled)?;
            planned_bytes = planned_bytes
                .checked_sub(before_bytes)
                .and_then(|remaining| remaining.checked_add(after_bytes))
                .ok_or_else(|| io::Error::other("policy reconciliation size overflow"))?;
            if planned_bytes > MAX_POLICY_STORE_BYTES as u64 {
                return Err(oversized_serialized_policy_store_error());
            }
        }
        Ok(())
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
        self.insert_record_at(session_id, record, current_unix_secs());
    }

    fn insert_record_at(
        &mut self,
        session_id: SessionId,
        mut record: SessionPolicyRecord,
        now: u64,
    ) {
        record.last_seen_unix_secs = now;
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

        let mut stats = self.evict(now);
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
        let current = self.record(session_id);
        if current.controlled_reality_pending_update.is_some()
            && current.policy_state != policy_state
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "policy state cannot change while a controlled-reality response is pending",
            ));
        }

        self.mutate_and_persist(|store| {
            let mut record = store.record(session_id);
            if record.policy_state != policy_state {
                record.policy_state = policy_state;
                if policy_state != PolicyState::ControlledReality {
                    record.controlled_reality_depth = 0;
                    record.controlled_reality_workflow_state =
                        ControlledRealityWorkflowState::Ready;
                    record.controlled_reality_origin_request_id = None;
                    record.controlled_reality_pending_update = None;
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
            let depth = record.controlled_reality_depth;
            store.insert_record(session_id, record);
            depth
        })
    }

    pub fn note_controlled_reality_interaction(
        &mut self,
        session_id: SessionId,
        request_id: RequestId,
        action: ControlledRealityRequestAction,
        depth_limit: u32,
    ) -> io::Result<ControlledRealityProgress> {
        if self
            .record(session_id)
            .controlled_reality_pending_update
            .is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "controlled-reality workflow has an uncommitted evidence record",
            ));
        }

        self.mutate_and_persist(|store| {
            let mut record = store.record(session_id);
            let pending_update = ControlledRealityPendingUpdate {
                request_id,
                request_action: action,
                previous_depth: record.controlled_reality_depth,
                previous_state: record.controlled_reality_workflow_state,
                previous_origin_request_id: record.controlled_reality_origin_request_id,
                commit_policy_state: None,
                expected_policy_changed: None,
                expected_response: None,
            };
            record.controlled_reality_depth = record.controlled_reality_depth.saturating_add(1);
            let from_state = record.controlled_reality_workflow_state;
            let to_state = if record.controlled_reality_depth > depth_limit {
                from_state
            } else {
                match (from_state, action) {
                    (
                        ControlledRealityWorkflowState::Ready,
                        ControlledRealityRequestAction::JobSubmitted,
                    ) => {
                        record.controlled_reality_origin_request_id = Some(request_id);
                        ControlledRealityWorkflowState::Queued
                    }
                    (
                        ControlledRealityWorkflowState::Queued,
                        ControlledRealityRequestAction::StatusRead,
                    ) if record.controlled_reality_origin_request_id.is_some() => {
                        ControlledRealityWorkflowState::Completed
                    }
                    _ => from_state,
                }
            };
            record.controlled_reality_workflow_state = to_state;
            record.controlled_reality_pending_update = Some(pending_update);
            let depth = record.controlled_reality_depth;
            let origin_request_id = record.controlled_reality_origin_request_id;
            store.insert_record(session_id, record);
            ControlledRealityProgress {
                depth,
                from_state,
                to_state,
                origin_request_id,
            }
        })
    }

    pub fn commit_controlled_reality_interaction(
        &mut self,
        session_id: SessionId,
        request_id: RequestId,
    ) -> io::Result<bool> {
        let pending_update = match self.record(session_id).controlled_reality_pending_update {
            None => return Ok(false),
            Some(pending_update) if pending_update.request_id != request_id => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "controlled-reality workflow commit request id did not match pending state",
                ));
            }
            Some(pending_update) if pending_update.expected_response.is_none() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "controlled-reality workflow cannot commit without a response contract",
                ));
            }
            Some(pending_update) => pending_update,
        };
        if pending_update.commit_policy_state.is_some()
            != pending_update.expected_policy_changed.is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "controlled-reality policy transition contract was incomplete",
            ));
        }

        self.mutate_and_persist(|store| {
            let mut record = store.record(session_id);
            if let Some(policy_state) = pending_update.commit_policy_state {
                record.policy_state = policy_state;
                if policy_state != PolicyState::ControlledReality {
                    record.controlled_reality_depth = 0;
                    record.controlled_reality_workflow_state =
                        ControlledRealityWorkflowState::Ready;
                    record.controlled_reality_origin_request_id = None;
                    record.reality_escape_attempt_count = 0;
                }
            }
            record.controlled_reality_pending_update = None;
            store.insert_record(session_id, record);
            true
        })
    }

    pub fn stage_controlled_reality_policy_state(
        &mut self,
        session_id: SessionId,
        request_id: RequestId,
        policy_state: PolicyState,
        expected_policy_changed: Event,
    ) -> io::Result<bool> {
        let record = self.record(session_id);
        match record.controlled_reality_pending_update.as_ref() {
            None => return Ok(false),
            Some(pending_update) if pending_update.request_id != request_id => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "controlled-reality policy transition request id did not match pending state",
                ));
            }
            Some(_) if record.policy_state != PolicyState::ControlledReality => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "controlled-reality policy transition did not start from containment",
                ));
            }
            Some(_) if policy_state != PolicyState::Blocked => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "controlled-reality pending policy transition must fail closed to blocked",
                ));
            }
            Some(pending_update)
                if pending_update.commit_policy_state.is_some()
                    || pending_update.expected_policy_changed.is_some() =>
            {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "controlled-reality policy transition was already staged",
                ));
            }
            Some(_) => {}
        }
        if expected_policy_changed.session_id != session_id
            || expected_policy_changed.request_id != Some(request_id)
            || expected_policy_changed.source != EventSource::PolicyRouter
            || expected_policy_changed.policy_state != policy_state
            || !persistence_matches_controlled_reality_block_transition(&expected_policy_changed)
            || !matches!(
                &expected_policy_changed.kind,
                EventKind::PolicyChanged {
                    from: PolicyState::ControlledReality,
                    to: PolicyState::Blocked,
                    ..
                }
            )
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "controlled-reality staged policy event did not match the blocked transition",
            ));
        }

        self.mutate_and_persist(|store| {
            let mut record = store.record(session_id);
            let mut pending_update = record
                .controlled_reality_pending_update
                .expect("pending update was checked before mutation");
            pending_update.commit_policy_state = Some(policy_state);
            pending_update.expected_policy_changed = Some(expected_policy_changed);
            record.controlled_reality_pending_update = Some(pending_update);
            store.insert_record(session_id, record);
            true
        })
    }

    pub fn set_pending_controlled_reality_response(
        &mut self,
        session_id: SessionId,
        request_id: RequestId,
        expected_response: ControlledRealityPendingResponse,
    ) -> io::Result<bool> {
        let record = self.record(session_id);
        match record.controlled_reality_pending_update.as_ref() {
            None => return Ok(false),
            Some(pending_update) if pending_update.request_id != request_id => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "controlled-reality response request id did not match pending state",
                ));
            }
            Some(pending_update) if pending_update.expected_response == Some(expected_response) => {
                return Ok(true);
            }
            Some(pending_update) if pending_update.expected_response.is_some() => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "controlled-reality response contract was already registered",
                ));
            }
            Some(_) => {}
        }
        let expected_policy_state = record
            .controlled_reality_pending_update
            .as_ref()
            .and_then(|pending| pending.commit_policy_state)
            .unwrap_or(record.policy_state);
        if expected_response.policy_state != expected_policy_state {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "controlled-reality response policy state did not match pending state",
            ));
        }

        self.mutate_and_persist(|store| {
            let mut record = store.record(session_id);
            let mut pending_update = record
                .controlled_reality_pending_update
                .expect("pending update was checked before mutation");
            pending_update.expected_response = Some(expected_response);
            record.controlled_reality_pending_update = Some(pending_update);
            store.insert_record(session_id, record);
            true
        })
    }

    pub fn recover_pending_controlled_reality(
        &mut self,
        session_id: SessionId,
    ) -> io::Result<bool> {
        let Some(pending_update) = self.record(session_id).controlled_reality_pending_update else {
            return Ok(false);
        };

        self.reconcile_pending_controlled_reality(session_id, pending_update.request_id, false)
    }

    pub fn reconcile_pending_controlled_reality(
        &mut self,
        session_id: SessionId,
        request_id: RequestId,
        durable_response_seen: bool,
    ) -> io::Result<bool> {
        self.reconcile_pending_controlled_reality_at(
            session_id,
            request_id,
            durable_response_seen,
            current_unix_secs(),
        )
    }

    pub fn reconcile_pending_controlled_reality_at(
        &mut self,
        session_id: SessionId,
        request_id: RequestId,
        durable_response_seen: bool,
        reconciliation_unix_secs: u64,
    ) -> io::Result<bool> {
        let record = self.record(session_id);
        let Some(pending_update) =
            pending_update_for_reconciliation(&record, request_id, durable_response_seen)?
        else {
            return Ok(false);
        };

        self.mutate_and_persist(|store| {
            let mut record = store.record(session_id);
            apply_pending_reconciliation(&mut record, &pending_update, durable_response_seen);
            store.insert_record_at(session_id, record, reconciliation_unix_secs);
            true
        })
    }

    pub fn note_reality_escape_attempt(&mut self, session_id: SessionId) -> io::Result<u32> {
        self.mutate_and_persist(|store| {
            let mut record = store.record(session_id);
            record.reality_escape_attempt_count =
                record.reality_escape_attempt_count.saturating_add(1);
            let attempt_count = record.reality_escape_attempt_count;
            store.insert_record(session_id, record);
            attempt_count
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
            let state = discovery_recon_state(&record);
            store.insert_record(session_id, record);
            state
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
            let state = discovery_recon_state(&record);
            store.insert_record(session_id, record);
            state
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
            let state = discovery_recon_state(&record);
            store.insert_record(session_id, record);
            state
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

        let serialized = self.serialize_current_state()?;
        validate_policy_state_temp_without_mutation(path)?;
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

    fn current_stored_state(&self) -> StoredPolicyState {
        let mut sessions: Vec<StoredSessionPolicy> = self
            .records
            .iter()
            .map(|(session_id, record)| StoredSessionPolicy::from_record(*session_id, record))
            .collect();
        sessions.sort_by_key(|record| record.session_id.0);

        StoredPolicyState {
            schema_version: POLICY_STORE_SCHEMA_VERSION,
            fail_closed_for_unknown_sessions: self.fail_closed_for_unknown_sessions,
            sessions,
        }
    }

    fn serialize_current_state(&self) -> io::Result<Vec<u8>> {
        let stored = self.current_stored_state();
        let mut serialized = BoundedPolicyStoreSerialization::new();
        serde_json::to_writer_pretty(&mut serialized, &stored).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to serialize policy state store: {error}"),
            )
        })?;
        serialized.finish()
    }

    fn serialized_current_state_len(&self) -> io::Result<u64> {
        self.serialized_stored_state_len(&self.current_stored_state())
    }

    fn serialized_record_envelope_len(
        &self,
        session_id: SessionId,
        record: &SessionPolicyRecord,
    ) -> io::Result<u64> {
        self.serialized_stored_state_len(&StoredPolicyState {
            schema_version: POLICY_STORE_SCHEMA_VERSION,
            fail_closed_for_unknown_sessions: self.fail_closed_for_unknown_sessions,
            sessions: vec![StoredSessionPolicy::from_record(session_id, record)],
        })
    }

    fn serialized_stored_state_len(&self, stored: &StoredPolicyState) -> io::Result<u64> {
        let mut serialized = CountingPolicyStoreSerialization::default();
        serde_json::to_writer_pretty(&mut serialized, stored).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to serialize policy state store: {error}"),
            )
        })?;
        Ok(serialized.bytes)
    }
}

fn validate_policy_state_temp_without_mutation(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path.with_extension("tmp")) {
        Ok(metadata) if !metadata.is_file() => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "policy state temporary path is not a regular file",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
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

fn discovery_recon_state(record: &SessionPolicyRecord) -> crate::policy::DiscoveryReconState {
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

fn workflow_snapshot_is_valid(
    depth: u32,
    state: ControlledRealityWorkflowState,
    origin_request_id: Option<RequestId>,
) -> bool {
    match state {
        ControlledRealityWorkflowState::Ready => origin_request_id.is_none(),
        ControlledRealityWorkflowState::Queued => depth >= 1 && origin_request_id.is_some(),
        ControlledRealityWorkflowState::Completed => depth >= 2 && origin_request_id.is_some(),
    }
}

fn persistence_matches_controlled_reality_block_transition(event: &Event) -> bool {
    let is_controlled_reality_block = matches!(
        &event.kind,
        EventKind::PolicyChanged {
            from: PolicyState::ControlledReality,
            to: PolicyState::Blocked,
            ..
        }
    );
    let persistence_matches_transition = event.persistence.is_empty()
        || (event
            .persistence
            .is_compatible_with_policy_state(PolicyState::Blocked)
            && event.persistence.post_containment_kind().is_some());

    is_controlled_reality_block && persistence_matches_transition
}

fn expected_unlimited_pending_response(
    session: &StoredSessionPolicy,
    pending: &ControlledRealityPendingUpdate,
) -> Option<(
    u16,
    RoutingDecision,
    Option<ControlledRealityPendingInteractionKind>,
    [u8; 32],
)> {
    let expected = ControlledRealityResponder.expected_response(
        session.session_id,
        ControlledRealityProgress {
            depth: session.controlled_reality_depth,
            from_state: pending.previous_state,
            to_state: session.controlled_reality_workflow_state,
            origin_request_id: session.controlled_reality_origin_request_id,
        },
        pending.request_action,
        u32::MAX,
    );
    let interaction_kind = pending_interaction_kind(expected.interaction.as_ref());
    let interaction_sha256 = controlled_reality_interaction_sha256(&expected.interaction)?;
    Some((
        expected.status,
        expected.routing_decision,
        interaction_kind,
        interaction_sha256,
    ))
}

fn validate_stored_pending_contract(session: &StoredSessionPolicy, path: &Path) -> io::Result<()> {
    let Some(pending) = session.controlled_reality_pending_update.as_ref() else {
        return Ok(());
    };

    let depth_is_valid =
        session.controlled_reality_depth == pending.previous_depth.saturating_add(1);
    let current_workflow_is_valid = workflow_snapshot_is_valid(
        session.controlled_reality_depth,
        session.controlled_reality_workflow_state,
        session.controlled_reality_origin_request_id,
    );
    let previous_workflow_is_valid = workflow_snapshot_is_valid(
        pending.previous_depth,
        pending.previous_state,
        pending.previous_origin_request_id,
    );
    let workflow_unchanged = session.controlled_reality_workflow_state == pending.previous_state
        && session.controlled_reality_origin_request_id == pending.previous_origin_request_id;
    let workflow_normally_advances = matches!(
        (pending.previous_state, pending.request_action),
        (
            ControlledRealityWorkflowState::Ready,
            ControlledRealityRequestAction::JobSubmitted
        )
    ) || matches!(
        (pending.previous_state, pending.request_action),
        (
            ControlledRealityWorkflowState::Queued,
            ControlledRealityRequestAction::StatusRead
        )
    ) && pending.previous_origin_request_id.is_some();
    let workflow_advanced = match (pending.previous_state, pending.request_action) {
        (ControlledRealityWorkflowState::Ready, ControlledRealityRequestAction::JobSubmitted) => {
            session.controlled_reality_workflow_state == ControlledRealityWorkflowState::Queued
                && session.controlled_reality_origin_request_id == Some(pending.request_id)
        }
        (ControlledRealityWorkflowState::Queued, ControlledRealityRequestAction::StatusRead)
            if pending.previous_origin_request_id.is_some() =>
        {
            session.controlled_reality_workflow_state == ControlledRealityWorkflowState::Completed
                && session.controlled_reality_origin_request_id
                    == pending.previous_origin_request_id
        }
        _ => false,
    };
    let unlimited_workflow_is_valid = if workflow_normally_advances {
        workflow_advanced
    } else {
        workflow_unchanged
    };
    let transition_is_valid = match (
        pending.commit_policy_state,
        pending.expected_policy_changed.as_ref(),
    ) {
        (None, None) => true,
        (Some(PolicyState::Blocked), Some(event)) => {
            session.policy_state == PolicyState::ControlledReality
                && event.schema_version == EVENT_SCHEMA_VERSION
                && event.session_id == session.session_id
                && event.request_id == Some(pending.request_id)
                && event.source == EventSource::PolicyRouter
                && event.policy_state == PolicyState::Blocked
                && persistence_matches_controlled_reality_block_transition(event)
                && matches!(
                    &event.kind,
                    EventKind::PolicyChanged {
                        from: PolicyState::ControlledReality,
                        to: PolicyState::Blocked,
                        ..
                    }
                )
        }
        _ => false,
    };
    let transition_workflow_is_valid =
        pending.commit_policy_state != Some(PolicyState::Blocked) || workflow_unchanged;
    let expected_response_state = pending.commit_policy_state.unwrap_or(session.policy_state);
    let response_is_valid = match pending.expected_response {
        None => true,
        Some(response) if response.policy_state != expected_response_state => false,
        Some(response) if pending.commit_policy_state == Some(PolicyState::Blocked) => {
            response.status == 403
                && response.routing_decision == RoutingDecision::EidolonOwned
                && response.interaction_kind.is_none()
                && response.controlled_reality_sha256 == no_controlled_reality_interaction_sha256()
        }
        Some(response) if pending.commit_policy_state.is_none() => {
            let unlimited_response_is_valid = expected_unlimited_pending_response(session, pending)
                .is_some_and(
                    |(status, routing_decision, interaction_kind, interaction_sha256)| {
                        unlimited_workflow_is_valid
                            && response.status == status
                            && response.routing_decision == routing_decision
                            && response.interaction_kind == interaction_kind
                            && response.controlled_reality_sha256 == interaction_sha256
                    },
                );
            let rate_limited_response_is_valid = workflow_unchanged
                && response.status == 429
                && response.routing_decision == RoutingDecision::RateLimited
                && response.interaction_kind.is_none()
                && response.controlled_reality_sha256 == no_controlled_reality_interaction_sha256();
            unlimited_response_is_valid || rate_limited_response_is_valid
        }
        Some(_) => false,
    };
    let event_ids_are_distinct = match (
        pending.expected_policy_changed.as_ref(),
        pending.expected_response,
    ) {
        (Some(policy_event), Some(response)) => policy_event.id != response.event_id,
        _ => true,
    };

    if session.policy_state == PolicyState::ControlledReality
        && depth_is_valid
        && current_workflow_is_valid
        && previous_workflow_is_valid
        && (workflow_unchanged || workflow_advanced)
        && transition_is_valid
        && transition_workflow_is_valid
        && response_is_valid
        && event_ids_are_distinct
    {
        Ok(())
    } else {
        Err(invalid_pending_contract_error(path))
    }
}

fn deserialize_records(
    bytes: &[u8],
    path: &Path,
) -> io::Result<(HashMap<SessionId, SessionPolicyRecord>, bool, bool)> {
    let stored: StoredPolicyState = serde_json::from_slice(bytes).map_err(|error| {
        let classification = match error.classify() {
            serde_json::error::Category::Io => "policy-state JSON I/O failure",
            serde_json::error::Category::Syntax => "invalid JSON syntax",
            serde_json::error::Category::Data => "invalid policy-state data",
            serde_json::error::Category::Eof => "truncated JSON",
        };
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "failed to parse policy state store `{}`: {classification} at line {}, column {}",
                path.display(),
                error.line(),
                error.column()
            ),
        )
    })?;
    if !(MIN_SUPPORTED_POLICY_STORE_SCHEMA_VERSION..=POLICY_STORE_SCHEMA_VERSION)
        .contains(&stored.schema_version)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unsupported policy state store schema in `{}`; supported versions are {} through {}",
                path.display(),
                MIN_SUPPORTED_POLICY_STORE_SCHEMA_VERSION,
                POLICY_STORE_SCHEMA_VERSION
            ),
        ));
    }

    let needs_schema_migration = stored.schema_version != POLICY_STORE_SCHEMA_VERSION;
    let fail_closed_for_unknown_sessions = if needs_schema_migration {
        false
    } else {
        stored.fail_closed_for_unknown_sessions
    };
    let mut session_ids = HashSet::with_capacity(stored.sessions.len());
    for session in &stored.sessions {
        if !session_ids.insert(session.session_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "policy state store `{}` contains duplicate session_id entries",
                    path.display()
                ),
            ));
        }
    }
    for session in &stored.sessions {
        validate_stored_pending_contract(session, path)?;
    }
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
                    controlled_reality_workflow_state: session.controlled_reality_workflow_state,
                    controlled_reality_origin_request_id: session
                        .controlled_reality_origin_request_id,
                    controlled_reality_pending_update: session.controlled_reality_pending_update,
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
        io::{Cursor, Read},
        time::{SystemTime, UNIX_EPOCH},
    };

    use eidolon_core::{PersistenceMetadata, PolicyState, PreContainmentPersistenceClass};

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

    struct ShortReader {
        bytes: Cursor<Vec<u8>>,
        max_read: usize,
    }

    impl Read for ShortReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let limit = buffer.len().min(self.max_read);
            self.bytes.read(&mut buffer[..limit])
        }
    }

    struct InterruptedReader {
        bytes: Cursor<Vec<u8>>,
        interrupted_before_data: bool,
        interrupted_between_chunks: bool,
        interrupted_before_eof: bool,
    }

    impl Read for InterruptedReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted_before_data {
                self.interrupted_before_data = true;
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "injected interruption before data",
                ));
            }
            if self.bytes.position() > 0
                && self.bytes.position() < self.bytes.get_ref().len() as u64
                && !self.interrupted_between_chunks
            {
                self.interrupted_between_chunks = true;
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "injected interruption between chunks",
                ));
            }
            if self.bytes.position() == self.bytes.get_ref().len() as u64
                && !self.interrupted_before_eof
            {
                self.interrupted_before_eof = true;
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "injected interruption before EOF",
                ));
            }
            let limit = buffer.len().min(2);
            self.bytes.read(&mut buffer[..limit])
        }
    }

    struct ReadThenFail {
        served_prefix: bool,
    }

    impl Read for ReadThenFail {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.served_prefix {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected bounded-reader failure",
                ));
            }
            self.served_prefix = true;
            buffer[0] = b'{';
            Ok(1)
        }
    }

    struct OverreportingReader;

    impl Read for OverreportingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            Ok(buffer.len() + 1)
        }
    }

    struct FailsIfRead;

    impl Read for FailsIfRead {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other(
                "metadata precheck unexpectedly touched the reader",
            ))
        }
    }

    struct RepeatingByteReader {
        remaining: usize,
        byte: u8,
    }

    impl Read for RepeatingByteReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let read = buffer.len().min(self.remaining);
            buffer[..read].fill(self.byte);
            self.remaining -= read;
            Ok(read)
        }
    }

    fn empty_current_store_bytes() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema_version": POLICY_STORE_SCHEMA_VERSION,
            "sessions": [],
        }))
        .expect("empty current store should serialize")
    }

    /// Populate the widest valid staged-block production shape. Fields fixed
    /// by the blocked-response contract use their required values. Arbitrary
    /// loaded event strings remain governed by the total byte limit; this
    /// fixture proves headroom for state generated by production.
    fn widest_production_record(
        session_id: SessionId,
        request_id: RequestId,
        policy_event_id: Uuid,
        response_event_id: Uuid,
    ) -> SessionPolicyRecord {
        let depth_transition =
            crate::policy::transition_to_blocked_from_repeated_controlled_reality_depth_limit(
                PolicyState::ControlledReality,
                "route:controlled_follow_up",
                u32::MAX,
                u32::MAX - 2,
            )
            .expect("maximum production depth should block");
        let escape_transition =
            crate::policy::transition_to_blocked_from_repeated_reality_escape_attempt(
                PolicyState::ControlledReality,
                "route:controlled_follow_up",
                u32::MAX,
            )
            .expect("maximum production escape count should block");
        let mut depth_event =
            crate::policy::policy_changed_event(session_id, request_id, &depth_transition);
        let mut escape_event =
            crate::policy::policy_changed_event(session_id, request_id, &escape_transition);
        for event in [&mut depth_event, &mut escape_event] {
            event.observed_at = chrono::DateTime::<chrono::Utc>::MAX_UTC;
        }
        let mut expected_policy_changed = [depth_event, escape_event]
            .into_iter()
            .max_by_key(|event| {
                serde_json::to_vec(event)
                    .expect("production policy event should serialize")
                    .len()
            })
            .expect("production policy event candidates should not be empty");
        expected_policy_changed.id = policy_event_id;

        SessionPolicyRecord {
            policy_state: PolicyState::ControlledReality,
            controlled_reality_depth: u32::MAX,
            controlled_reality_workflow_state: ControlledRealityWorkflowState::Completed,
            controlled_reality_origin_request_id: Some(request_id),
            controlled_reality_pending_update: Some(ControlledRealityPendingUpdate {
                request_id,
                request_action: ControlledRealityRequestAction::UnknownResource,
                previous_depth: u32::MAX,
                previous_state: ControlledRealityWorkflowState::Completed,
                previous_origin_request_id: Some(request_id),
                commit_policy_state: Some(PolicyState::Blocked),
                expected_policy_changed: Some(expected_policy_changed),
                expected_response: Some(ControlledRealityPendingResponse {
                    event_id: response_event_id,
                    policy_state: PolicyState::Blocked,
                    status: 403,
                    routing_decision: RoutingDecision::EidolonOwned,
                    interaction_kind: None,
                    controlled_reality_sha256: no_controlled_reality_interaction_sha256(),
                }),
            }),
            last_seen_unix_secs: u64::MAX,
            reality_escape_attempt_count: u32::MAX,
            discovery_surface_fanout: crate::policy::DiscoverySurfaceFanout {
                docs_seen: false,
                openapi_seen: false,
            },
            discovery_request_count: u32::MAX,
            discovery_query_seen: false,
            discovery_legacy_openapi_query_seen: false,
            discovery_linked_bait_surface_fanout: crate::policy::LinkedBaitSurfaceFanout {
                docs_seen: false,
                assets_seen: false,
                other_seen: false,
            },
            discovery_decoy_write_probe_count:
                crate::policy::discovery_recon_decoy_write_probe_count_cap(),
            discovery_decoy_write_probe_fanout: crate::policy::DecoyWriteProbeFanout {
                reconcile_seen: false,
                other_seen: false,
            },
        }
    }

    fn test_response_contract(
        store: &PolicyStateStore,
        session_id: SessionId,
        request_id: RequestId,
        event_id: Uuid,
        depth_limit: u32,
    ) -> ControlledRealityPendingResponse {
        let record = store.record(session_id);
        let pending = record
            .controlled_reality_pending_update
            .as_ref()
            .expect("test response should have pending workflow state");
        assert_eq!(pending.request_id, request_id);
        let expected = ControlledRealityResponder.expected_response(
            session_id,
            ControlledRealityProgress {
                depth: record.controlled_reality_depth,
                from_state: pending.previous_state,
                to_state: record.controlled_reality_workflow_state,
                origin_request_id: record.controlled_reality_origin_request_id,
            },
            pending.request_action,
            depth_limit,
        );
        let controlled_reality_sha256 =
            controlled_reality_interaction_sha256(&expected.interaction)
                .expect("test interaction semantics should serialize");
        ControlledRealityPendingResponse {
            event_id,
            policy_state: pending.commit_policy_state.unwrap_or(record.policy_state),
            status: expected.status,
            routing_decision: expected.routing_decision,
            interaction_kind: pending_interaction_kind(expected.interaction.as_ref()),
            controlled_reality_sha256,
        }
    }

    fn set_test_response_contract(
        store: &mut PolicyStateStore,
        session_id: SessionId,
        request_id: RequestId,
        status: u16,
        interaction_kind: ControlledRealityPendingInteractionKind,
    ) {
        let response =
            test_response_contract(store, session_id, request_id, Uuid::new_v4(), u32::MAX);
        assert_eq!(response.status, status);
        assert_eq!(response.interaction_kind, Some(interaction_kind));
        store
            .set_pending_controlled_reality_response(session_id, request_id, response)
            .expect("response contract should persist");
    }

    fn test_blocked_policy_event(session_id: SessionId, request_id: RequestId) -> Event {
        Event::new(
            session_id,
            EventSource::PolicyRouter,
            PolicyState::Blocked,
            EventKind::PolicyChanged {
                from: PolicyState::ControlledReality,
                to: PolicyState::Blocked,
                reason: "test controlled-reality block".to_string(),
            },
        )
        .with_request_id(request_id)
    }

    #[test]
    fn policy_store_schema_version_matches_current_contract() {
        assert_eq!(POLICY_STORE_SCHEMA_VERSION, 3);
        assert_eq!(MIN_SUPPORTED_POLICY_STORE_SCHEMA_VERSION, 1);
        assert_eq!(MAX_POLICY_STORE_BYTES, 32 * 1024 * 1024);
        let no_interaction =
            serde_json::to_vec(&Option::<eidolon_core::ControlledRealityInteraction>::None)
                .expect("absent controlled-reality semantics should serialize");
        assert_eq!(no_interaction, b"null");
        let expected_digest: [u8; 32] = Sha256::digest(no_interaction).into();
        assert_eq!(no_controlled_reality_interaction_sha256(), expected_digest);
    }

    #[test]
    fn controlled_reality_block_persistence_accepts_only_legacy_or_post_containment_metadata() {
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let transition =
            crate::policy::transition_to_blocked_from_repeated_controlled_reality_depth_limit(
                PolicyState::ControlledReality,
                "route:controlled_follow_up",
                3,
                1,
            )
            .expect("repeated controlled-reality depth should block");
        let post_containment_event =
            crate::policy::policy_changed_event(session_id, request_id, &transition);
        assert!(persistence_matches_controlled_reality_block_transition(
            &post_containment_event
        ));

        let mut legacy_event = post_containment_event.clone();
        legacy_event.persistence = PersistenceMetadata::default();
        assert!(persistence_matches_controlled_reality_block_transition(
            &legacy_event
        ));

        let mut rate_limited_event = post_containment_event.clone();
        rate_limited_event.persistence =
            PersistenceMetadata::pre_containment(PreContainmentPersistenceClass::DiscoveryRecon);
        assert!(!persistence_matches_controlled_reality_block_transition(
            &rate_limited_event
        ));

        let mut pre_containment_retry_event = post_containment_event;
        pre_containment_retry_event.persistence = PersistenceMetadata::pre_containment_retry(
            PreContainmentPersistenceClass::DiscoveryRecon,
        );
        assert!(!persistence_matches_controlled_reality_block_transition(
            &pre_containment_retry_event
        ));
    }

    #[test]
    fn validation_preflight_is_read_only_for_missing_and_legacy_state() {
        let path = unique_temp_path("read-only-validation-preflight");

        PolicyStateStore::validate_without_mutation(&path)
            .expect("missing state should pass read-only validation");
        assert!(!path.exists());
        assert!(!path.with_extension("tmp").exists());

        let session_id = SessionId::new();
        let legacy = serde_json::to_vec(&serde_json::json!({
            "schema_version": MIN_SUPPORTED_POLICY_STORE_SCHEMA_VERSION,
            "sessions": [{
                "session_id": session_id.0,
                "policy_state": "blocked",
            }],
        }))
        .expect("legacy preflight fixture should serialize");
        fs::write(&path, &legacy).expect("legacy preflight fixture should write");

        PolicyStateStore::validate_without_mutation(&path)
            .expect("valid legacy state should pass read-only validation");
        assert_eq!(
            fs::read(&path).expect("validated legacy state should remain readable"),
            legacy
        );
        assert!(!path.with_extension("tmp").exists());

        let raced_invalid_state = b"{";
        fs::write(&path, raced_invalid_state)
            .expect("state should be replaceable after the preflight");
        let error = PolicyStateStore::open(&path)
            .expect_err("the authoritative open must reject a post-preflight change");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            fs::read(&path).expect("raced invalid state should remain readable"),
            raced_invalid_state
        );
        assert!(!path.with_extension("tmp").exists());

        fs::remove_file(path).expect("legacy preflight fixture should remove");
    }

    #[test]
    fn policy_temp_type_is_checked_during_preflight_and_repeated_before_persist() {
        let path = unique_temp_path("policy-temp-type-validation");
        let temp = path.with_extension("tmp");
        let legacy = serde_json::to_vec(&serde_json::json!({
            "schema_version": MIN_SUPPORTED_POLICY_STORE_SCHEMA_VERSION,
            "sessions": [],
        }))
        .expect("legacy temp-type fixture should serialize");
        fs::write(&path, &legacy).expect("legacy temp-type fixture should write");
        fs::create_dir(&temp).expect("nonregular policy temp should create");

        let error = PolicyStateStore::validate_without_mutation(&path)
            .expect_err("nonregular policy temp must fail read-only validation");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "policy state temporary path is not a regular file"
        );
        assert_eq!(fs::read(&path).unwrap(), legacy);
        assert!(fs::metadata(&temp).unwrap().is_dir());

        fs::remove_dir(&temp).expect("preflight temp directory should remove");
        let prepared = PolicyStateStore::prepare_open(&path)
            .expect("legacy state should prepare after temp correction");
        assert!(prepared.startup_persist_required);
        fs::create_dir(&temp).expect("raced nonregular policy temp should create");

        let error = prepared
            .finish_prepared_startup()
            .expect_err("persistence must repeat the policy temp type check");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "policy state temporary path is not a regular file"
        );
        assert_eq!(fs::read(&path).unwrap(), legacy);
        assert!(fs::metadata(&temp).unwrap().is_dir());

        fs::remove_dir(temp).expect("raced temp directory should remove");
        fs::remove_file(path).expect("legacy temp-type fixture should remove");
    }

    #[test]
    fn prepared_startup_defers_legacy_migration_until_explicit_finish() {
        let path = unique_temp_path("prepared-legacy-migration");
        let session_id = SessionId::new();
        let legacy = serde_json::to_vec(&serde_json::json!({
            "schema_version": MIN_SUPPORTED_POLICY_STORE_SCHEMA_VERSION,
            "sessions": [{
                "session_id": session_id.0,
                "policy_state": "blocked",
            }],
        }))
        .expect("legacy prepared fixture should serialize");
        fs::write(&path, &legacy).expect("legacy prepared fixture should write");

        let prepared = PolicyStateStore::prepare_open(&path)
            .expect("legacy snapshot should prepare without mutation");
        assert!(prepared.startup_persist_required);
        assert_eq!(prepared.policy_state(session_id), PolicyState::Blocked);
        assert_eq!(
            fs::read(&path).expect("prepared source should remain readable"),
            legacy
        );
        assert!(!path.with_extension("tmp").exists());

        let finished = prepared
            .finish_prepared_startup()
            .expect("explicit finish should persist migration");
        assert!(!finished.startup_persist_required);
        let migrated: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("migrated state should read"))
                .expect("migrated state should parse");
        assert_eq!(migrated["schema_version"], POLICY_STORE_SCHEMA_VERSION);
        assert_eq!(
            migrated["sessions"]
                .as_array()
                .expect("sessions should be an array")
                .len(),
            1
        );
        fs::remove_file(path).expect("prepared legacy fixture should remove");
    }

    #[test]
    fn prepared_startup_defers_ttl_eviction_and_missing_state_remains_absent() {
        let missing = unique_temp_path("prepared-missing-state");
        let missing_store = PolicyStateStore::prepare_open(&missing)
            .expect("missing snapshot should prepare without creation");
        assert!(!missing_store.startup_persist_required);
        missing_store
            .finish_prepared_startup()
            .expect("missing snapshot should finish without creation");
        assert!(!missing.exists());

        let path = unique_temp_path("prepared-ttl-eviction");
        let stale_session = SessionId::new();
        let stale = serde_json::to_vec(&serde_json::json!({
            "schema_version": POLICY_STORE_SCHEMA_VERSION,
            "sessions": [{
                "session_id": stale_session.0,
                "policy_state": "observe",
                "last_seen_unix_secs": 1,
            }],
        }))
        .expect("stale fixture should serialize");
        fs::write(&path, &stale).expect("stale fixture should write");

        let prepared = PolicyStateStore::prepare_open(&path)
            .expect("stale snapshot should prepare without mutation");
        assert!(prepared.startup_persist_required);
        assert_eq!(prepared.last_eviction_stats().ttl_evicted, 1);
        assert!(prepared.is_empty());
        assert_eq!(
            fs::read(&path).expect("stale source should remain readable"),
            stale
        );
        assert!(!path.with_extension("tmp").exists());

        let finished = prepared
            .finish_prepared_startup()
            .expect("explicit finish should persist eviction");
        assert!(!finished.startup_persist_required);
        let persisted: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("evicted state should read"))
                .expect("evicted state should parse");
        assert_eq!(persisted["sessions"], serde_json::json!([]));
        fs::remove_file(path).expect("prepared eviction fixture should remove");
    }

    #[test]
    fn pending_event_log_coordinates_are_selected_and_deterministically_sorted() {
        let first_session = SessionId(Uuid::from_u128(1));
        let second_session = SessionId(Uuid::from_u128(2));
        let settled_session = SessionId(Uuid::from_u128(3));
        let first_request = RequestId(Uuid::from_u128(11));
        let second_request = RequestId(Uuid::from_u128(12));
        let mut store = PolicyStateStore::in_memory();
        for session_id in [second_session, first_session] {
            store
                .set_policy_state(session_id, PolicyState::ControlledReality)
                .expect("controlled state should stage");
        }
        store
            .set_policy_state(settled_session, PolicyState::Suspicious)
            .expect("settled state should persist");
        store
            .note_controlled_reality_interaction(
                second_session,
                second_request,
                ControlledRealityRequestAction::BranchRead,
                4,
            )
            .expect("second pending workflow should stage");
        store
            .note_controlled_reality_interaction(
                first_session,
                first_request,
                ControlledRealityRequestAction::BranchRead,
                4,
            )
            .expect("first pending workflow should stage");
        let expected_policy = test_blocked_policy_event(first_session, first_request);
        let expected_policy_id = expected_policy.id;
        store
            .stage_controlled_reality_policy_state(
                first_session,
                first_request,
                PolicyState::Blocked,
                expected_policy,
            )
            .expect("first policy transition should stage");

        assert_eq!(
            store.pending_event_log_recovery_coordinates(),
            vec![
                (first_session, first_request, Some(expected_policy_id)),
                (second_session, second_request, None),
            ]
        );
    }

    #[test]
    fn maximum_widest_production_store_has_explicit_byte_headroom() {
        const REQUIRED_HEADROOM_BYTES: usize = 8 * 1024 * 1024;

        let records: HashMap<SessionId, SessionPolicyRecord> = (0..MAX_POLICY_SESSIONS)
            .map(|index| {
                let session_id = SessionId(Uuid::from_u128(index as u128 + 1));
                let request_id = RequestId(Uuid::from_u128(
                    MAX_POLICY_SESSIONS as u128 + index as u128 + 1,
                ));
                let event_id =
                    Uuid::from_u128((MAX_POLICY_SESSIONS * 2) as u128 + index as u128 + 1);
                let response_event_id =
                    Uuid::from_u128((MAX_POLICY_SESSIONS * 3) as u128 + index as u128 + 1);
                (
                    session_id,
                    widest_production_record(session_id, request_id, event_id, response_event_id),
                )
            })
            .collect();
        let widest_event = records
            .values()
            .next()
            .and_then(|record| record.controlled_reality_pending_update.as_ref())
            .and_then(|pending| pending.expected_policy_changed.as_ref())
            .expect("widest records should retain their policy-change event");
        assert_eq!(
            widest_event.observed_at,
            chrono::DateTime::<chrono::Utc>::MAX_UTC,
            "the headroom fixture must not depend on wall-clock timestamp width"
        );
        let store = PolicyStateStore {
            path: None,
            records,
            fail_closed_for_unknown_sessions: false,
            last_eviction: EvictionStats::default(),
            startup_persist_required: false,
        };

        let serialized = store
            .serialize_current_state()
            .expect("maximum supported populated store should remain serializable");
        let headroom = MAX_POLICY_STORE_BYTES - serialized.len();

        assert!(
            headroom >= REQUIRED_HEADROOM_BYTES,
            "widest production store used {} bytes and left only {headroom} bytes",
            serialized.len()
        );
    }

    #[test]
    fn ordered_reconciliation_size_plan_accepts_exact_limit_and_rejects_one_over() {
        let first_session = SessionId(Uuid::from_u128(1));
        let first_request = RequestId(Uuid::from_u128(2));
        let second_session = SessionId(Uuid::from_u128(3));
        let second_request = RequestId(Uuid::from_u128(4));
        let first_record = SessionPolicyRecord {
            policy_state: PolicyState::ControlledReality,
            controlled_reality_pending_update: Some(ControlledRealityPendingUpdate {
                request_id: first_request,
                request_action: ControlledRealityRequestAction::UnknownResource,
                previous_depth: 0,
                previous_state: ControlledRealityWorkflowState::Ready,
                previous_origin_request_id: None,
                commit_policy_state: None,
                expected_policy_changed: None,
                expected_response: None,
            }),
            ..SessionPolicyRecord::new(PolicyState::ControlledReality)
        };
        let mut second_record = widest_production_record(
            second_session,
            second_request,
            Uuid::from_u128(5),
            Uuid::from_u128(6),
        );
        let Some(Event {
            kind: EventKind::PolicyChanged { reason, .. },
            ..
        }) = second_record
            .controlled_reality_pending_update
            .as_mut()
            .and_then(|pending| pending.expected_policy_changed.as_mut())
        else {
            panic!("second recovery record should contain a policy event")
        };
        reason.clear();
        let mut store = PolicyStateStore {
            path: None,
            records: [
                (first_session, first_record),
                (second_session, second_record),
            ]
            .into_iter()
            .collect(),
            fail_closed_for_unknown_sessions: false,
            last_eviction: EvictionStats::default(),
            startup_persist_required: false,
        };
        let mut after_first = store.clone();
        assert!(after_first
            .reconcile_pending_controlled_reality_at(first_session, first_request, false, 9)
            .expect("empty-reason first workflow should reconcile"));
        let empty_reason_bytes = after_first
            .serialized_current_state_len()
            .expect("empty-reason state should count");
        let reason_bytes = (MAX_POLICY_STORE_BYTES as u64)
            .checked_sub(empty_reason_bytes)
            .and_then(|bytes| usize::try_from(bytes).ok())
            .expect("policy envelope should leave room for the exact-limit reason");
        let Some(Event {
            kind: EventKind::PolicyChanged { reason, .. },
            ..
        }) = store
            .records
            .get_mut(&second_session)
            .and_then(|record| record.controlled_reality_pending_update.as_mut())
            .and_then(|pending| pending.expected_policy_changed.as_mut())
        else {
            panic!("second recovery record should remain mutable")
        };
        *reason = "x".repeat(reason_bytes);

        let decisions = [
            PendingControlledRealityRecoveryDecision {
                session_id: first_session,
                request_id: first_request,
                durable_response_seen: false,
            },
            PendingControlledRealityRecoveryDecision {
                session_id: second_session,
                request_id: second_request,
                durable_response_seen: false,
            },
        ];
        let mut exact_after_first = store.clone();
        assert!(exact_after_first
            .reconcile_pending_controlled_reality_at(first_session, first_request, false, 9)
            .expect("first exact-limit workflow should reconcile"));
        assert_eq!(
            exact_after_first
                .serialized_current_state_len()
                .expect("exact-limit state should count"),
            MAX_POLICY_STORE_BYTES as u64
        );
        let exact_path = unique_temp_path("exact-reconciliation-snapshot");
        let mut exact_persisted = store.clone();
        exact_persisted.path = Some(exact_path.clone());
        assert!(exact_persisted
            .reconcile_pending_controlled_reality_at(first_session, first_request, false, 9)
            .expect("the exact-limit snapshot should persist"));
        assert_eq!(
            fs::metadata(&exact_path)
                .expect("exact-limit snapshot metadata should read")
                .len(),
            MAX_POLICY_STORE_BYTES as u64
        );
        fs::remove_file(&exact_path).expect("exact-limit snapshot should remove");
        store
            .validate_pending_reconciliation_plan_without_mutation(&decisions, 9)
            .expect("an exact-limit first snapshot should validate");
        let timestamp_error = store
            .validate_pending_reconciliation_plan_without_mutation(&decisions, 10)
            .expect_err("a wider persisted timestamp must be part of planning");
        assert_eq!(timestamp_error.kind(), io::ErrorKind::InvalidData);
        assert!(timestamp_error.to_string().contains("exceeds the fixed"));

        let mut oversized = store;
        let Some(Event {
            kind: EventKind::PolicyChanged { reason, .. },
            ..
        }) = oversized
            .records
            .get_mut(&second_session)
            .and_then(|record| record.controlled_reality_pending_update.as_mut())
            .and_then(|pending| pending.expected_policy_changed.as_mut())
        else {
            panic!("oversized recovery record should remain mutable")
        };
        reason.push('x');
        let error = oversized
            .validate_pending_reconciliation_plan_without_mutation(&decisions, 9)
            .expect_err("the first canonical snapshot one byte over must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeds the fixed"));
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
            startup_persist_required: false,
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
        let path = unique_temp_path("missing");
        let store = PolicyStateStore::open(&path).expect("store should open");

        assert_eq!(store.policy_state(SessionId::new()), PolicyState::Observe);
        assert!(
            !path.exists(),
            "opening missing state must not create a file"
        );
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
    fn oversized_serialization_preserves_disk_and_rolls_back_memory() {
        let path = unique_temp_path("oversized-write-rollback");
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let mut store = PolicyStateStore::open(&path).expect("store should open");
        store
            .set_policy_state(session_id, PolicyState::ControlledReality)
            .expect("controlled state should persist");
        store
            .note_controlled_reality_interaction(
                session_id,
                request_id,
                ControlledRealityRequestAction::BranchRead,
                4,
            )
            .expect("pending interaction should persist");
        let baseline = fs::read(&path).expect("baseline store should read");
        let mut oversized_event = test_blocked_policy_event(session_id, request_id);
        let EventKind::PolicyChanged { reason, .. } = &mut oversized_event.kind else {
            panic!("test event should be policy_changed");
        };
        *reason = "x".repeat(MAX_POLICY_STORE_BYTES);

        let error = store
            .stage_controlled_reality_policy_state(
                session_id,
                request_id,
                PolicyState::Blocked,
                oversized_event,
            )
            .expect_err("oversized current state must not persist");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeds the fixed"));
        assert_eq!(
            fs::read(&path).expect("last good state should remain readable"),
            baseline
        );
        assert!(
            !path.with_extension("tmp").exists(),
            "size rejection must happen before a temp file is opened"
        );
        let pending = store
            .record(session_id)
            .controlled_reality_pending_update
            .expect("pre-mutation pending state should be restored");
        assert_eq!(pending.commit_policy_state, None);
        assert_eq!(pending.expected_policy_changed, None);
        fs::remove_file(path).expect("store should remove");
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
    fn bounded_reader_handles_short_reads_and_propagates_io_failures() {
        let bytes = empty_current_store_bytes();
        let path = Path::new("synthetic-policy-state.json");
        let short = read_policy_store_bytes_from_reader(
            ShortReader {
                bytes: Cursor::new(bytes.clone()),
                max_read: 1,
            },
            path,
            bytes.len() as u64,
        )
        .expect("short reads should be reassembled");
        assert_eq!(short, bytes);

        let error = read_policy_store_bytes_from_reader(
            ReadThenFail {
                served_prefix: false,
            },
            path,
            1,
        )
        .expect_err("ordinary reader failures must propagate");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), "injected bounded-reader failure");
    }

    #[test]
    fn bounded_reader_retries_interruptions_before_between_and_after_chunks() {
        let bytes = empty_current_store_bytes();
        let path = Path::new("synthetic-interrupted-policy-state.json");

        let read = read_policy_store_bytes_from_reader(
            InterruptedReader {
                bytes: Cursor::new(bytes.clone()),
                interrupted_before_data: false,
                interrupted_between_chunks: false,
                interrupted_before_eof: false,
            },
            path,
            bytes.len() as u64,
        )
        .expect("interrupted reads should retry without losing retained bytes");

        assert_eq!(read, bytes);
    }

    #[test]
    fn bounded_reader_rejects_an_invalid_reported_byte_count_without_panicking() {
        let error = read_policy_store_bytes_from_reader(
            OverreportingReader,
            Path::new("synthetic-overreporting-policy-state.json"),
            0,
        )
        .expect_err("an invalid Read implementation must fail deterministically");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "policy state reader returned an invalid byte count"
        );
    }

    #[test]
    fn metadata_precheck_rejects_oversized_state_without_touching_the_reader() {
        let path = Path::new("synthetic-advertised-oversized-policy-state.json");
        let error = read_policy_store_bytes_from_reader(
            FailsIfRead,
            path,
            (MAX_POLICY_STORE_BYTES + 1) as u64,
        )
        .expect_err("oversized metadata should reject before a read attempt");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            format!(
                "policy state store `{}` exceeds the fixed {} byte limit",
                path.display(),
                MAX_POLICY_STORE_BYTES
            )
        );
    }

    #[test]
    fn bounded_reader_growth_uses_an_explicit_capped_reservation() {
        let expected_len = POLICY_STORE_READ_CHUNK_BYTES + 1;
        let bytes = read_policy_store_bytes_from_reader(
            RepeatingByteReader {
                remaining: expected_len,
                byte: b'x',
            },
            Path::new("synthetic-growing-within-limit-policy-state.json"),
            0,
        )
        .expect("bounded growth should reserve before extending");

        assert_eq!(bytes.len(), expected_len);
        assert!(bytes.capacity() <= MAX_POLICY_STORE_BYTES + 1);
    }

    #[test]
    fn bounded_read_catches_growth_after_a_small_metadata_result() {
        let path = Path::new("synthetic-growing-policy-state.json");
        let error = read_policy_store_bytes_from_reader(
            RepeatingByteReader {
                remaining: MAX_POLICY_STORE_BYTES + 1,
                byte: b' ',
            },
            path,
            0,
        )
        .expect_err("the bounded read must remain authoritative after metadata");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            format!(
                "policy state store `{}` exceeds the fixed {} byte limit",
                path.display(),
                MAX_POLICY_STORE_BYTES
            )
        );
    }

    #[test]
    fn widest_production_record_has_a_distinct_valid_recovery_contract() {
        let path = unique_temp_path("widest-valid-recovery");
        let session_id = SessionId(Uuid::from_u128(1));
        let request_id = RequestId(Uuid::from_u128(2));
        let policy_event_id = Uuid::from_u128(3);
        let response_event_id = Uuid::from_u128(4);
        let record =
            widest_production_record(session_id, request_id, policy_event_id, response_event_id);
        let pending = record
            .controlled_reality_pending_update
            .as_ref()
            .expect("widest record should have a recovery contract");
        let expected_policy_changed = pending
            .expected_policy_changed
            .as_ref()
            .expect("widest record should stage its policy event");
        assert_eq!(expected_policy_changed.id, policy_event_id);
        assert!(!expected_policy_changed.persistence.is_empty());
        assert!(expected_policy_changed
            .persistence
            .post_containment_kind()
            .is_some());
        assert_eq!(
            pending
                .expected_response
                .expect("widest record should stage its response")
                .event_id,
            response_event_id
        );
        assert_ne!(policy_event_id, response_event_id);

        let store = PolicyStateStore {
            path: None,
            records: HashMap::from([(session_id, record)]),
            fail_closed_for_unknown_sessions: false,
            last_eviction: EvictionStats::default(),
            startup_persist_required: false,
        };
        fs::write(
            &path,
            store
                .serialize_current_state()
                .expect("widest recovery contract should serialize"),
        )
        .expect("widest recovery contract should write");

        let mut reopened =
            PolicyStateStore::open(&path).expect("widest recovery contract should validate");
        assert!(reopened
            .reconcile_pending_controlled_reality(session_id, request_id, true)
            .expect("widest recovery contract should roll forward"));
        let recovered = reopened.record(session_id);
        assert_eq!(recovered.policy_state, PolicyState::Blocked);
        assert_eq!(recovered.controlled_reality_depth, 0);
        assert_eq!(recovered.controlled_reality_pending_update, None);

        fs::remove_file(path).expect("widest recovery fixture should remove");
    }

    #[test]
    fn legacy_omitted_persistence_block_contract_recovers_after_reopen() {
        let path = unique_temp_path("legacy-omitted-persistence-recovery");
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let mut store = PolicyStateStore::open(&path).expect("store should open");
        store
            .set_policy_state(session_id, PolicyState::ControlledReality)
            .expect("state should persist");
        store
            .note_controlled_reality_interaction(
                session_id,
                request_id,
                ControlledRealityRequestAction::BranchRead,
                u32::MAX,
            )
            .expect("branch read should stage");
        let legacy_event = test_blocked_policy_event(session_id, request_id);
        assert!(legacy_event.persistence.is_empty());
        store
            .stage_controlled_reality_policy_state(
                session_id,
                request_id,
                PolicyState::Blocked,
                legacy_event,
            )
            .expect("legacy block event should stage");
        store
            .set_pending_controlled_reality_response(
                session_id,
                request_id,
                ControlledRealityPendingResponse {
                    event_id: Uuid::new_v4(),
                    policy_state: PolicyState::Blocked,
                    status: 403,
                    routing_decision: RoutingDecision::EidolonOwned,
                    interaction_kind: None,
                    controlled_reality_sha256: no_controlled_reality_interaction_sha256(),
                },
            )
            .expect("legacy response contract should stage");
        drop(store);

        let mut reopened = PolicyStateStore::open(&path)
            .expect("legacy omitted persistence should remain supported");
        assert!(reopened
            .reconcile_pending_controlled_reality(session_id, request_id, true)
            .expect("durable legacy response should roll the block forward"));
        let recovered = reopened.record(session_id);
        assert_eq!(recovered.policy_state, PolicyState::Blocked);
        assert_eq!(recovered.controlled_reality_pending_update, None);

        fs::remove_file(path).expect("legacy recovery fixture should remove");
    }

    #[test]
    fn current_schema_with_trailing_whitespace_opens_at_limit_but_one_byte_over_fails() {
        let exact_path = unique_temp_path("exact-byte-limit");
        let mut exact = empty_current_store_bytes();
        exact.resize(MAX_POLICY_STORE_BYTES, b' ');
        fs::write(&exact_path, &exact).expect("exact-limit state should write");

        let store = PolicyStateStore::open(&exact_path)
            .expect("valid JSON exactly at the byte limit should open");
        assert!(store.is_empty());
        assert_eq!(
            fs::metadata(&exact_path)
                .expect("exact-limit metadata should read")
                .len(),
            MAX_POLICY_STORE_BYTES as u64
        );

        let oversized_path = unique_temp_path("max-plus-one");
        let oversized =
            fs::File::create(&oversized_path).expect("max-plus-one state should create");
        oversized
            .set_len((MAX_POLICY_STORE_BYTES + 1) as u64)
            .expect("max-plus-one state should resize");
        drop(oversized);
        let error = PolicyStateStore::open(&oversized_path)
            .expect_err("one byte over the fixed limit must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeds the fixed"));

        fs::remove_file(exact_path).expect("exact-limit state should remove");
        fs::remove_file(oversized_path).expect("oversized state should remove");
    }

    #[test]
    fn legacy_exact_limit_that_expands_during_migration_fails_before_temp_write() {
        let path = unique_temp_path("legacy-migration-expands-over-limit");
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let mut event = test_blocked_policy_event(session_id, request_id);
        let EventKind::PolicyChanged { reason, .. } = &mut event.kind else {
            panic!("test event should be policy_changed");
        };
        reason.clear();
        let serialize_legacy = |event: &Event| {
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 1,
                "sessions": [{
                    "session_id": session_id.0,
                    "policy_state": "controlled_reality",
                    "controlled_reality_depth": 1,
                    "controlled_reality_pending_update": {
                        "request_id": request_id.0,
                        "request_action": "unknown_resource",
                        "previous_depth": 0,
                        "previous_state": "ready",
                        "previous_origin_request_id": null,
                        "commit_policy_state": "blocked",
                        "expected_policy_changed": event,
                        "expected_response": null,
                    },
                }],
            }))
            .expect("legacy migration fixture should serialize")
        };
        let empty_reason_len = serialize_legacy(&event).len();
        let reason_len = MAX_POLICY_STORE_BYTES
            .checked_sub(empty_reason_len)
            .expect("legacy fixture envelope should fit below the byte limit");
        let EventKind::PolicyChanged { reason, .. } = &mut event.kind else {
            panic!("test event should remain policy_changed");
        };
        *reason = "x".repeat(reason_len);
        let exact = serialize_legacy(&event);
        assert_eq!(exact.len(), MAX_POLICY_STORE_BYTES);
        fs::write(&path, &exact).expect("exact-limit legacy state should write");
        let expected_error = format!(
            "serialized policy state store exceeds the fixed {} byte limit",
            MAX_POLICY_STORE_BYTES
        );

        let preflight_error = PolicyStateStore::validate_without_mutation(&path)
            .expect_err("read-only validation must simulate migration size");
        assert_eq!(preflight_error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(preflight_error.to_string(), expected_error);
        assert_eq!(
            fs::read(&path).expect("preflight-rejected legacy state should remain readable"),
            exact
        );
        assert!(!path.with_extension("tmp").exists());

        let error = PolicyStateStore::open(&path)
            .expect_err("a migration that cannot fit its current form must fail closed");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), expected_error);
        assert_eq!(
            fs::read(&path).expect("rejected legacy state should remain readable"),
            exact
        );
        assert!(
            !path.with_extension("tmp").exists(),
            "migration size rejection must happen before opening the temp file"
        );
        fs::remove_file(path).expect("legacy migration fixture should remove");
    }

    #[test]
    fn malformed_store_fails_closed() {
        let path = unique_temp_path("malformed");
        fs::write(&path, b"not-json").expect("malformed store should write");

        let error = PolicyStateStore::open(&path).expect_err("malformed store should fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("failed to parse"));
        assert!(!path.with_extension("tmp").exists());
        fs::remove_file(path).expect("malformed store should remove");
    }

    #[test]
    fn malformed_field_diagnostics_never_disclose_values_or_durable_ids() {
        const PRIVATE_VALUE: &str = "private-policy-state-value";

        let path = unique_temp_path("malformed-private-value");
        let session_id = SessionId::new();
        fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "schema_version": POLICY_STORE_SCHEMA_VERSION,
                "sessions": [{
                    "session_id": session_id.0,
                    "policy_state": PRIVATE_VALUE,
                }],
            }))
            .expect("private malformed fixture should serialize"),
        )
        .expect("private malformed fixture should write");

        let error = PolicyStateStore::open(&path).expect_err("invalid policy value should fail");
        let diagnostic = error.to_string();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(diagnostic.contains("invalid policy-state data at line"));
        assert!(!diagnostic.contains(PRIVATE_VALUE));
        assert!(!diagnostic.contains(&session_id.0.to_string()));
        fs::remove_file(path).expect("private malformed fixture should remove");
    }

    #[test]
    fn truncated_store_fails_without_rewriting_or_creating_a_temp_file() {
        let path = unique_temp_path("truncated");
        let mut truncated = empty_current_store_bytes();
        truncated.pop();
        fs::write(&path, &truncated).expect("truncated store should write");

        let error = PolicyStateStore::open(&path).expect_err("truncated store should fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("failed to parse"));
        assert_eq!(
            fs::read(&path).expect("truncated state should remain readable"),
            truncated
        );
        assert!(!path.with_extension("tmp").exists());
        fs::remove_file(path).expect("truncated store should remove");
    }

    #[test]
    fn duplicate_sessions_fail_with_one_order_independent_non_sensitive_error() {
        let path = unique_temp_path("duplicates");
        let session_id = SessionId::new();
        let expected_error = format!(
            "policy state store `{}` contains duplicate session_id entries",
            path.display()
        );

        for schema_version in
            MIN_SUPPORTED_POLICY_STORE_SCHEMA_VERSION..=POLICY_STORE_SCHEMA_VERSION
        {
            for (first, second) in [
                (PolicyState::Blocked, PolicyState::Blocked),
                (PolicyState::Observe, PolicyState::Blocked),
                (PolicyState::Blocked, PolicyState::Observe),
            ] {
                let bytes = serde_json::to_vec(&serde_json::json!({
                    "schema_version": schema_version,
                    "sessions": [
                        {"session_id": session_id.0, "policy_state": first},
                        {"session_id": session_id.0, "policy_state": second},
                    ],
                }))
                .expect("duplicate fixture should serialize");
                fs::write(&path, &bytes).expect("duplicate fixture should write");

                let error = PolicyStateStore::open(&path)
                    .expect_err("duplicate sessions must never select one policy by order");

                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                assert_eq!(error.to_string(), expected_error);
                assert!(!error.to_string().contains(&session_id.0.to_string()));
                assert_eq!(
                    fs::read(&path).expect("rejected fixture should remain readable"),
                    bytes
                );
                assert!(!path.with_extension("tmp").exists());
            }
        }

        fs::remove_file(path).expect("duplicate fixture should remove");
    }

    #[test]
    fn invalid_pending_contracts_fail_before_schema_migration_or_rewrite() {
        let path = unique_temp_path("invalid-pending-contract");
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let event_id = Uuid::from_u128(1);
        let response_event_id = Uuid::from_u128(2);
        let other_session_id = SessionId::new();
        let other_request_id = RequestId::new();
        let template_store = PolicyStateStore {
            path: None,
            records: HashMap::from([(
                session_id,
                widest_production_record(session_id, request_id, event_id, response_event_id),
            )]),
            fail_closed_for_unknown_sessions: false,
            last_eviction: EvictionStats::default(),
            startup_persist_required: false,
        };
        let template: serde_json::Value = serde_json::from_slice(
            &template_store
                .serialize_current_state()
                .expect("valid pending-contract template should serialize"),
        )
        .expect("valid pending-contract template should parse as JSON");
        let normal_request_id = RequestId::new();
        let mut normal_template_store = PolicyStateStore::in_memory();
        normal_template_store
            .set_policy_state(session_id, PolicyState::ControlledReality)
            .expect("normal template should enter controlled reality");
        normal_template_store
            .note_controlled_reality_interaction(
                session_id,
                normal_request_id,
                ControlledRealityRequestAction::JobSubmitted,
                u32::MAX,
            )
            .expect("normal template should stage a submission");
        let normal_response = test_response_contract(
            &normal_template_store,
            session_id,
            normal_request_id,
            Uuid::new_v4(),
            u32::MAX,
        );
        normal_template_store
            .set_pending_controlled_reality_response(session_id, normal_request_id, normal_response)
            .expect("normal template should stage its response");
        let normal_template: serde_json::Value = serde_json::from_slice(
            &normal_template_store
                .serialize_current_state()
                .expect("normal pending-contract template should serialize"),
        )
        .expect("normal pending-contract template should parse as JSON");

        let rate_limited_request_id = RequestId::new();
        let mut rate_limited_template_store = PolicyStateStore::in_memory();
        rate_limited_template_store
            .set_policy_state(session_id, PolicyState::ControlledReality)
            .expect("rate-limited template should enter controlled reality");
        rate_limited_template_store
            .note_controlled_reality_interaction(
                session_id,
                rate_limited_request_id,
                ControlledRealityRequestAction::JobSubmitted,
                0,
            )
            .expect("rate-limited template should stage an over-depth submission");
        let rate_limited_response = test_response_contract(
            &rate_limited_template_store,
            session_id,
            rate_limited_request_id,
            Uuid::new_v4(),
            0,
        );
        assert_eq!(rate_limited_response.status, 429);
        assert_eq!(
            rate_limited_response.routing_decision,
            RoutingDecision::RateLimited
        );
        assert_eq!(rate_limited_response.interaction_kind, None);
        rate_limited_template_store
            .set_pending_controlled_reality_response(
                session_id,
                rate_limited_request_id,
                rate_limited_response,
            )
            .expect("rate-limited template should stage its response");
        let rate_limited_template: serde_json::Value = serde_json::from_slice(
            &rate_limited_template_store
                .serialize_current_state()
                .expect("rate-limited pending-contract template should serialize"),
        )
        .expect("rate-limited pending-contract template should parse as JSON");
        let mut legacy_omitted_persistence_template = template.clone();
        legacy_omitted_persistence_template["sessions"][0]["controlled_reality_pending_update"]
            ["expected_policy_changed"]
            .as_object_mut()
            .expect("legacy policy event should be an object")
            .remove("persistence");
        let expected_error = format!(
            "policy state store `{}` contains an invalid pending controlled-reality contract",
            path.display()
        );

        for schema_version in
            MIN_SUPPORTED_POLICY_STORE_SCHEMA_VERSION..=POLICY_STORE_SCHEMA_VERSION
        {
            for (label, mut valid_fixture) in [
                ("blocked", template.clone()),
                (
                    "blocked with legacy omitted persistence",
                    legacy_omitted_persistence_template.clone(),
                ),
                ("normal", normal_template.clone()),
                ("rate limited", rate_limited_template.clone()),
            ] {
                valid_fixture["schema_version"] = serde_json::json!(schema_version);
                let valid_bytes = serde_json::to_vec(&valid_fixture)
                    .expect("valid pending-contract fixture should serialize");
                deserialize_records(&valid_bytes, &path).unwrap_or_else(|error| {
                    panic!("valid {label} schema {schema_version} failed: {error}")
                });
            }

            let mut wrong_current_depth = template.clone();
            wrong_current_depth["sessions"][0]["controlled_reality_depth"] = serde_json::json!(0);

            let mut wrong_current_workflow = template.clone();
            wrong_current_workflow["sessions"][0]["controlled_reality_workflow_state"] =
                serde_json::json!("ready");

            let mut wrong_current_origin = template.clone();
            wrong_current_origin["sessions"][0]["controlled_reality_origin_request_id"] =
                serde_json::json!(other_request_id.0);

            let mut impossible_rollback_workflow = normal_template.clone();
            impossible_rollback_workflow["sessions"][0]["controlled_reality_depth"] =
                serde_json::json!(1);
            impossible_rollback_workflow["sessions"][0]["controlled_reality_workflow_state"] =
                serde_json::json!("queued");
            impossible_rollback_workflow["sessions"][0]["controlled_reality_origin_request_id"] =
                serde_json::Value::Null;
            impossible_rollback_workflow["sessions"][0]["controlled_reality_pending_update"]
                ["request_action"] = serde_json::json!("branch_read");
            impossible_rollback_workflow["sessions"][0]["controlled_reality_pending_update"]
                ["previous_depth"] = serde_json::json!(0);
            impossible_rollback_workflow["sessions"][0]["controlled_reality_pending_update"]
                ["previous_state"] = serde_json::json!("queued");
            impossible_rollback_workflow["sessions"][0]["controlled_reality_pending_update"]
                ["previous_origin_request_id"] = serde_json::Value::Null;
            impossible_rollback_workflow["sessions"][0]["controlled_reality_pending_update"]
                ["expected_response"] = serde_json::Value::Null;

            let mut completed_too_early = normal_template.clone();
            completed_too_early["sessions"][0]["controlled_reality_depth"] = serde_json::json!(1);
            completed_too_early["sessions"][0]["controlled_reality_workflow_state"] =
                serde_json::json!("completed");
            completed_too_early["sessions"][0]["controlled_reality_pending_update"]
                ["previous_depth"] = serde_json::json!(0);
            completed_too_early["sessions"][0]["controlled_reality_pending_update"]
                ["previous_state"] = serde_json::json!("completed");
            completed_too_early["sessions"][0]["controlled_reality_pending_update"]
                ["previous_origin_request_id"] = serde_json::json!(normal_request_id.0);
            completed_too_early["sessions"][0]["controlled_reality_pending_update"]
                ["request_action"] = serde_json::json!("branch_read");
            completed_too_early["sessions"][0]["controlled_reality_pending_update"]
                ["expected_response"] = serde_json::Value::Null;

            let mut incomplete_transition = template.clone();
            incomplete_transition["sessions"][0]["controlled_reality_pending_update"]
                ["expected_policy_changed"] = serde_json::Value::Null;

            let mut missing_commit_state = template.clone();
            missing_commit_state["sessions"][0]["controlled_reality_pending_update"]
                ["commit_policy_state"] = serde_json::Value::Null;

            let mut wrong_record_state = template.clone();
            wrong_record_state["sessions"][0]["policy_state"] = serde_json::json!("blocked");

            let mut wrong_event_session = template.clone();
            wrong_event_session["sessions"][0]["controlled_reality_pending_update"]
                ["expected_policy_changed"]["session_id"] = serde_json::json!(other_session_id.0);

            let mut wrong_event_request = template.clone();
            wrong_event_request["sessions"][0]["controlled_reality_pending_update"]
                ["expected_policy_changed"]["request_id"] = serde_json::json!(other_request_id.0);

            let mut wrong_event_source = template.clone();
            wrong_event_source["sessions"][0]["controlled_reality_pending_update"]
                ["expected_policy_changed"]["source"] = serde_json::json!("proxy");

            let mut wrong_event_schema = template.clone();
            wrong_event_schema["sessions"][0]["controlled_reality_pending_update"]
                ["expected_policy_changed"]["schema_version"] =
                serde_json::json!(EVENT_SCHEMA_VERSION + 1);

            let mut wrong_event_policy_state = template.clone();
            wrong_event_policy_state["sessions"][0]["controlled_reality_pending_update"]
                ["expected_policy_changed"]["policy_state"] =
                serde_json::json!("controlled_reality");

            let mut wrong_event_transition = template.clone();
            wrong_event_transition["sessions"][0]["controlled_reality_pending_update"]
                ["expected_policy_changed"]["kind"]["from"] = serde_json::json!("observe");

            let mut wrong_event_persistence_destination = template.clone();
            wrong_event_persistence_destination["sessions"][0]
                ["controlled_reality_pending_update"]["expected_policy_changed"]["persistence"] = serde_json::json!({
                "pre_containment_persistence_class": "discovery_recon",
            });

            let mut wrong_event_persistence_transition = template.clone();
            wrong_event_persistence_transition["sessions"][0]
                ["controlled_reality_pending_update"]["expected_policy_changed"]["persistence"] = serde_json::json!({
                "pre_containment_persistence_class": "discovery_recon",
                "pre_containment_persistence_kind": "discovery_recon_retry",
            });

            let mut non_blocking_transition = template.clone();
            non_blocking_transition["sessions"][0]["controlled_reality_pending_update"]
                ["commit_policy_state"] = serde_json::json!("observe");

            let mut mismatched_response = template.clone();
            mismatched_response["sessions"][0]["controlled_reality_pending_update"]
                ["expected_response"]["policy_state"] = serde_json::json!("controlled_reality");

            let mut wrong_blocked_status = template.clone();
            wrong_blocked_status["sessions"][0]["controlled_reality_pending_update"]
                ["expected_response"]["status"] = serde_json::json!(u16::MAX);

            let mut wrong_blocked_routing = template.clone();
            wrong_blocked_routing["sessions"][0]["controlled_reality_pending_update"]
                ["expected_response"]["routing_decision"] = serde_json::json!("controlled_reality");

            let mut wrong_blocked_interaction = template.clone();
            wrong_blocked_interaction["sessions"][0]["controlled_reality_pending_update"]
                ["expected_response"]["interaction_kind"] = serde_json::json!("job_submitted");

            let mut wrong_blocked_semantics = template.clone();
            wrong_blocked_semantics["sessions"][0]["controlled_reality_pending_update"]
                ["expected_response"]["controlled_reality_sha256"] =
                serde_json::json!(vec![u8::MAX; 32]);

            let mut colliding_event_ids = template.clone();
            colliding_event_ids["sessions"][0]["controlled_reality_pending_update"]
                ["expected_response"]["event_id"] = serde_json::json!(event_id);

            let mut advanced_block_transition = normal_template.clone();
            advanced_block_transition["sessions"][0]["controlled_reality_pending_update"]
                ["commit_policy_state"] = serde_json::json!("blocked");
            let mut advanced_block_event = template["sessions"][0]
                ["controlled_reality_pending_update"]["expected_policy_changed"]
                .clone();
            advanced_block_event["request_id"] = serde_json::json!(normal_request_id.0);
            advanced_block_transition["sessions"][0]["controlled_reality_pending_update"]
                ["expected_policy_changed"] = advanced_block_event;
            advanced_block_transition["sessions"][0]["controlled_reality_pending_update"]
                ["expected_response"] = serde_json::Value::Null;

            let mut wrong_unstaged_status = normal_template.clone();
            wrong_unstaged_status["sessions"][0]["controlled_reality_pending_update"]
                ["expected_response"]["status"] = serde_json::json!(u16::MAX);

            let mut wrong_unstaged_routing = normal_template.clone();
            wrong_unstaged_routing["sessions"][0]["controlled_reality_pending_update"]
                ["expected_response"]["routing_decision"] = serde_json::json!("protected_upstream");

            let mut wrong_unstaged_interaction = normal_template.clone();
            wrong_unstaged_interaction["sessions"][0]["controlled_reality_pending_update"]
                ["expected_response"]["interaction_kind"] = serde_json::Value::Null;

            let mut wrong_unstaged_semantics = normal_template.clone();
            wrong_unstaged_semantics["sessions"][0]["controlled_reality_pending_update"]
                ["expected_response"]["controlled_reality_sha256"] =
                serde_json::json!(vec![u8::MAX; 32]);

            let mut normal_response_without_advance = normal_template.clone();
            normal_response_without_advance["sessions"][0]["controlled_reality_workflow_state"] =
                serde_json::json!("ready");
            normal_response_without_advance["sessions"][0]
                ["controlled_reality_origin_request_id"] = serde_json::Value::Null;
            normal_response_without_advance["sessions"][0]["controlled_reality_pending_update"]
                ["expected_response"]["status"] = serde_json::json!(409);
            normal_response_without_advance["sessions"][0]["controlled_reality_pending_update"]
                ["expected_response"]["interaction_kind"] = serde_json::Value::Null;
            normal_response_without_advance["sessions"][0]["controlled_reality_pending_update"]
                ["expected_response"]["controlled_reality_sha256"] =
                serde_json::json!(no_controlled_reality_interaction_sha256());

            let mut rate_limit_after_advance = rate_limited_template.clone();
            rate_limit_after_advance["sessions"][0]["controlled_reality_workflow_state"] =
                serde_json::json!("queued");
            rate_limit_after_advance["sessions"][0]["controlled_reality_origin_request_id"] =
                serde_json::json!(rate_limited_request_id.0);

            for (label, mut fixture) in [
                ("wrong current depth", wrong_current_depth),
                ("wrong current workflow", wrong_current_workflow),
                ("wrong current origin", wrong_current_origin),
                ("impossible rollback workflow", impossible_rollback_workflow),
                ("completed too early", completed_too_early),
                ("incomplete transition", incomplete_transition),
                ("missing commit state", missing_commit_state),
                ("wrong record state", wrong_record_state),
                ("wrong event session", wrong_event_session),
                ("wrong event request", wrong_event_request),
                ("wrong event source", wrong_event_source),
                ("wrong event schema", wrong_event_schema),
                ("wrong event policy state", wrong_event_policy_state),
                ("wrong event transition", wrong_event_transition),
                (
                    "wrong event persistence destination",
                    wrong_event_persistence_destination,
                ),
                (
                    "wrong event persistence transition",
                    wrong_event_persistence_transition,
                ),
                ("non-blocking transition", non_blocking_transition),
                ("mismatched response", mismatched_response),
                ("wrong blocked status", wrong_blocked_status),
                ("wrong blocked routing", wrong_blocked_routing),
                ("wrong blocked interaction", wrong_blocked_interaction),
                ("wrong blocked semantics", wrong_blocked_semantics),
                ("colliding event ids", colliding_event_ids),
                ("advanced block transition", advanced_block_transition),
                ("wrong unstaged status", wrong_unstaged_status),
                ("wrong unstaged routing", wrong_unstaged_routing),
                ("wrong unstaged interaction", wrong_unstaged_interaction),
                ("wrong unstaged semantics", wrong_unstaged_semantics),
                (
                    "normal response without workflow advance",
                    normal_response_without_advance,
                ),
                (
                    "rate limit after workflow advance",
                    rate_limit_after_advance,
                ),
            ] {
                fixture["schema_version"] = serde_json::json!(schema_version);
                let bytes = serde_json::to_vec(&fixture)
                    .unwrap_or_else(|error| panic!("{label} fixture should serialize: {error}"));
                fs::write(&path, &bytes)
                    .unwrap_or_else(|error| panic!("{label} fixture should write: {error}"));

                let error = match PolicyStateStore::open(&path) {
                    Ok(_) => panic!("{label} schema {schema_version} should fail"),
                    Err(error) => error,
                };

                assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{label}");
                assert_eq!(error.to_string(), expected_error, "{label}");
                assert!(!error.to_string().contains(&session_id.0.to_string()));
                assert!(!error.to_string().contains(&request_id.0.to_string()));
                assert!(!error.to_string().contains(&event_id.to_string()));
                assert!(!error.to_string().contains(&response_event_id.to_string()));
                assert_eq!(
                    fs::read(&path).expect("invalid pending state should remain readable"),
                    bytes,
                    "{label} schema {schema_version} was rewritten"
                );
                assert!(
                    !path.with_extension("tmp").exists(),
                    "{label} schema {schema_version} created a temp file"
                );
            }
        }

        fs::remove_file(path).expect("invalid pending fixture should remove");
    }

    #[test]
    fn unsupported_store_schema_fails_closed() {
        let path = unique_temp_path("unsupported");
        let unsupported = br#"{"schema_version":999,"sessions":[]}"#;
        fs::write(&path, unsupported).expect("unsupported store should write");

        let error = PolicyStateStore::open(&path).expect_err("unsupported store should fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            format!(
                "unsupported policy state store schema in `{}`; supported versions are {} through {}",
                path.display(),
                MIN_SUPPORTED_POLICY_STORE_SCHEMA_VERSION,
                POLICY_STORE_SCHEMA_VERSION
            )
        );
        assert!(!error.to_string().contains("999"));
        assert_eq!(
            fs::read(&path).expect("unsupported state should remain readable"),
            unsupported
        );
        assert!(!path.with_extension("tmp").exists());
        fs::remove_file(path).expect("unsupported store should remove");
    }

    #[test]
    fn empty_store_file_fails_closed() {
        let path = unique_temp_path("empty");
        fs::write(&path, b"").expect("empty store should write");

        let error = PolicyStateStore::open(&path).expect_err("empty store should fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("is empty"));
        assert!(!path.with_extension("tmp").exists());
        fs::remove_file(path).expect("empty store should remove");
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
    fn controlled_reality_workflow_is_bounded_and_survives_reopen() {
        let path = unique_temp_path("controlled-workflow");
        let session_id = SessionId::new();
        let origin_request_id = RequestId::new();
        let status_request_id = RequestId::new();
        let mut store = PolicyStateStore::open(&path).expect("store should open");
        store
            .set_policy_state(session_id, PolicyState::ControlledReality)
            .expect("state should persist");

        let submitted = store
            .note_controlled_reality_interaction(
                session_id,
                origin_request_id,
                ControlledRealityRequestAction::JobSubmitted,
                4,
            )
            .expect("submission should persist");
        assert_eq!(submitted.depth, 1);
        assert_eq!(submitted.from_state, ControlledRealityWorkflowState::Ready);
        assert_eq!(submitted.to_state, ControlledRealityWorkflowState::Queued);
        assert_eq!(submitted.origin_request_id, Some(origin_request_id));
        assert_eq!(
            store
                .record(session_id)
                .controlled_reality_pending_update
                .map(|pending| pending.request_id),
            Some(origin_request_id)
        );
        set_test_response_contract(
            &mut store,
            session_id,
            origin_request_id,
            202,
            ControlledRealityPendingInteractionKind::JobSubmitted,
        );
        assert!(store
            .commit_controlled_reality_interaction(session_id, origin_request_id)
            .expect("submission evidence should commit"));

        let mut reopened = PolicyStateStore::open(&path).expect("store should reopen");
        let status = reopened
            .note_controlled_reality_interaction(
                session_id,
                status_request_id,
                ControlledRealityRequestAction::StatusRead,
                4,
            )
            .expect("status should persist");
        assert_eq!(status.depth, 2);
        assert_eq!(status.from_state, ControlledRealityWorkflowState::Queued);
        assert_eq!(status.to_state, ControlledRealityWorkflowState::Completed);
        assert_eq!(status.origin_request_id, Some(origin_request_id));
        set_test_response_contract(
            &mut reopened,
            session_id,
            status_request_id,
            200,
            ControlledRealityPendingInteractionKind::StatusRead,
        );
        assert!(reopened
            .commit_controlled_reality_interaction(session_id, status_request_id)
            .expect("status evidence should commit"));

        let completed = PolicyStateStore::open(&path).expect("store should reopen");
        let record = completed.record(session_id);
        assert_eq!(
            record.controlled_reality_workflow_state,
            ControlledRealityWorkflowState::Completed
        );
        assert_eq!(
            record.controlled_reality_origin_request_id,
            Some(origin_request_id)
        );
        assert_eq!(record.controlled_reality_pending_update, None);
        fs::remove_file(path).expect("store should remove");
    }

    #[test]
    fn pending_workflow_stages_block_state_until_response_commit() {
        let mut store = PolicyStateStore::in_memory();
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        store
            .set_policy_state(session_id, PolicyState::ControlledReality)
            .expect("controlled state should persist");
        store
            .note_controlled_reality_interaction(
                session_id,
                request_id,
                ControlledRealityRequestAction::BranchRead,
                4,
            )
            .expect("pending interaction should persist");

        let error = store
            .set_policy_state(session_id, PolicyState::Blocked)
            .expect_err("ordinary policy updates must not clear pending workflow state");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(
            store.record(session_id).policy_state,
            PolicyState::ControlledReality
        );

        assert!(store
            .stage_controlled_reality_policy_state(
                session_id,
                request_id,
                PolicyState::Blocked,
                test_blocked_policy_event(session_id, request_id),
            )
            .expect("block state should stage"));
        store
            .set_pending_controlled_reality_response(
                session_id,
                request_id,
                ControlledRealityPendingResponse {
                    event_id: Uuid::new_v4(),
                    policy_state: PolicyState::Blocked,
                    status: 403,
                    routing_decision: RoutingDecision::EidolonOwned,
                    interaction_kind: None,
                    controlled_reality_sha256: no_controlled_reality_interaction_sha256(),
                },
            )
            .expect("blocked response contract should persist");
        assert!(store
            .commit_controlled_reality_interaction(session_id, request_id)
            .expect("durable response should commit the staged block"));

        let record = store.record(session_id);
        assert_eq!(record.policy_state, PolicyState::Blocked);
        assert_eq!(record.controlled_reality_depth, 0);
        assert_eq!(record.controlled_reality_pending_update, None);
    }

    #[test]
    fn staged_block_rolls_back_when_no_durable_response_exists() {
        let mut store = PolicyStateStore::in_memory();
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        store
            .set_policy_state(session_id, PolicyState::ControlledReality)
            .expect("controlled state should persist");
        store
            .note_controlled_reality_interaction(
                session_id,
                request_id,
                ControlledRealityRequestAction::BranchRead,
                4,
            )
            .expect("pending interaction should persist");
        store
            .stage_controlled_reality_policy_state(
                session_id,
                request_id,
                PolicyState::Blocked,
                test_blocked_policy_event(session_id, request_id),
            )
            .expect("block state should stage");

        assert!(store
            .reconcile_pending_controlled_reality(session_id, request_id, false)
            .expect("missing response should roll back"));

        let record = store.record(session_id);
        assert_eq!(record.policy_state, PolicyState::ControlledReality);
        assert_eq!(record.controlled_reality_depth, 0);
        assert_eq!(record.controlled_reality_pending_update, None);
    }

    #[test]
    fn uncommitted_workflow_state_recovers_to_ready_after_reopen() {
        let path = unique_temp_path("controlled-workflow-pending");
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let mut store = PolicyStateStore::open(&path).expect("store should open");
        store
            .set_policy_state(session_id, PolicyState::ControlledReality)
            .expect("state should persist");
        store
            .note_controlled_reality_interaction(
                session_id,
                request_id,
                ControlledRealityRequestAction::JobSubmitted,
                4,
            )
            .expect("pending submission should persist");
        set_test_response_contract(
            &mut store,
            session_id,
            request_id,
            202,
            ControlledRealityPendingInteractionKind::JobSubmitted,
        );

        let mut reopened = PolicyStateStore::open(&path).expect("store should reopen");
        assert_eq!(
            reopened
                .record(session_id)
                .controlled_reality_pending_update
                .map(|pending| pending.request_id),
            Some(request_id)
        );
        assert!(reopened
            .recover_pending_controlled_reality(session_id)
            .expect("pending workflow should recover"));

        let record = reopened.record(session_id);
        assert_eq!(record.controlled_reality_depth, 0);
        assert_eq!(
            record.controlled_reality_workflow_state,
            ControlledRealityWorkflowState::Ready
        );
        assert_eq!(record.controlled_reality_origin_request_id, None);
        assert_eq!(record.controlled_reality_pending_update, None);
        fs::remove_file(path).expect("store should remove");
    }

    #[test]
    fn durable_response_recovery_preserves_the_pending_transition() {
        let path = unique_temp_path("controlled-workflow-durable-response");
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let mut store = PolicyStateStore::open(&path).expect("store should open");
        store
            .set_policy_state(session_id, PolicyState::ControlledReality)
            .expect("state should persist");
        store
            .note_controlled_reality_interaction(
                session_id,
                request_id,
                ControlledRealityRequestAction::JobSubmitted,
                4,
            )
            .expect("pending submission should persist");
        set_test_response_contract(
            &mut store,
            session_id,
            request_id,
            202,
            ControlledRealityPendingInteractionKind::JobSubmitted,
        );

        let mut reopened = PolicyStateStore::open(&path).expect("store should reopen");
        assert!(reopened
            .reconcile_pending_controlled_reality(session_id, request_id, true)
            .expect("durable response should roll the transition forward"));

        let record = reopened.record(session_id);
        assert_eq!(record.controlled_reality_depth, 1);
        assert_eq!(
            record.controlled_reality_workflow_state,
            ControlledRealityWorkflowState::Queued
        );
        assert_eq!(
            record.controlled_reality_origin_request_id,
            Some(request_id)
        );
        assert_eq!(record.controlled_reality_pending_update, None);
        fs::remove_file(path).expect("store should remove");
    }

    #[test]
    fn uncommitted_status_restores_the_last_proven_queued_state() {
        let path = unique_temp_path("controlled-workflow-pending-status");
        let session_id = SessionId::new();
        let origin_request_id = RequestId::new();
        let status_request_id = RequestId::new();
        let mut store = PolicyStateStore::open(&path).expect("store should open");
        store
            .set_policy_state(session_id, PolicyState::ControlledReality)
            .expect("state should persist");
        store
            .note_controlled_reality_interaction(
                session_id,
                origin_request_id,
                ControlledRealityRequestAction::JobSubmitted,
                4,
            )
            .expect("submission should persist");
        set_test_response_contract(
            &mut store,
            session_id,
            origin_request_id,
            202,
            ControlledRealityPendingInteractionKind::JobSubmitted,
        );
        store
            .commit_controlled_reality_interaction(session_id, origin_request_id)
            .expect("submission evidence should commit");
        store
            .note_controlled_reality_interaction(
                session_id,
                status_request_id,
                ControlledRealityRequestAction::StatusRead,
                4,
            )
            .expect("pending status should persist");

        let mut reopened = PolicyStateStore::open(&path).expect("store should reopen");
        assert!(reopened
            .recover_pending_controlled_reality(session_id)
            .expect("pending status should recover"));

        let record = reopened.record(session_id);
        assert_eq!(record.controlled_reality_depth, 1);
        assert_eq!(
            record.controlled_reality_workflow_state,
            ControlledRealityWorkflowState::Queued
        );
        assert_eq!(
            record.controlled_reality_origin_request_id,
            Some(origin_request_id)
        );
        assert_eq!(record.controlled_reality_pending_update, None);
        fs::remove_file(path).expect("store should remove");
    }

    #[test]
    fn depth_limit_does_not_advance_controlled_reality_workflow() {
        let mut store = PolicyStateStore::in_memory();
        let session_id = SessionId::new();

        let progress = store
            .note_controlled_reality_interaction(
                session_id,
                RequestId::new(),
                ControlledRealityRequestAction::JobSubmitted,
                0,
            )
            .expect("depth should persist");

        assert_eq!(progress.depth, 1);
        assert_eq!(progress.from_state, ControlledRealityWorkflowState::Ready);
        assert_eq!(progress.to_state, ControlledRealityWorkflowState::Ready);
        assert_eq!(progress.origin_request_id, None);
    }

    #[test]
    fn failed_workflow_persist_rolls_back_phase_origin_and_depth() {
        let parent = unique_temp_path("workflow-removed-parent");
        fs::create_dir(&parent).expect("parent should create");
        let path = parent.join("policy.json");
        let session_id = SessionId::new();
        let mut store = PolicyStateStore::open(&path).expect("store should open");
        store
            .set_policy_state(session_id, PolicyState::ControlledReality)
            .expect("state should persist");
        fs::remove_file(&path).expect("store file should remove");
        fs::remove_dir(&parent).expect("parent should remove");

        store
            .note_controlled_reality_interaction(
                session_id,
                RequestId::new(),
                ControlledRealityRequestAction::JobSubmitted,
                4,
            )
            .expect_err("workflow persistence should fail");

        let record = store.record(session_id);
        assert_eq!(record.controlled_reality_depth, 0);
        assert_eq!(
            record.controlled_reality_workflow_state,
            ControlledRealityWorkflowState::Ready
        );
        assert_eq!(record.controlled_reality_origin_request_id, None);
        assert_eq!(record.controlled_reality_pending_update, None);
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
        assert_eq!(
            record.controlled_reality_workflow_state,
            ControlledRealityWorkflowState::Ready
        );
        assert_eq!(record.controlled_reality_origin_request_id, None);
        assert_eq!(record.controlled_reality_pending_update, None);
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
