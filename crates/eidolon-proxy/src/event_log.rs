use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use eidolon_core::{
    ControlledRealityInteraction, Event, EventKind, EventSource, PolicyState, RequestId,
    RoutingDecision, SessionId,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub type FileEventLogWriter = EventLogWriter<BufWriter<File>>;

/// Maximum size of one active or retained event-log segment.
pub const LOG_ROTATE_BYTES: u64 = 32 * 1024 * 1024;

/// Number of retained numeric archives in addition to the active segment.
pub const LOG_ARCHIVES_KEPT: usize = 3;

/// Maximum serialized size of one schema-v2 event, excluding its newline.
pub const MAX_EVENT_LOG_RECORD_BYTES: usize = 1024 * 1024;

/// Maximum bytes in the complete supported active-plus-archive family.
pub const MAX_EVENT_LOG_FAMILY_BYTES: u64 = LOG_ROTATE_BYTES * (LOG_ARCHIVES_KEPT as u64 + 1);

const EVENT_LOG_READ_CHUNK_BYTES: usize = 8 * 1024;
const EVENT_LOG_ARCHIVE_SUFFIX_DIGITS: usize = 39;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventLogRecoveryTarget {
    pub session_id: SessionId,
    pub request_id: RequestId,
    pub expected_policy_event_id: Option<Uuid>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EventLogRecoveryStats {
    pub archive_count: usize,
    pub segment_count: usize,
    pub record_count: usize,
    pub family_bytes: u64,
    pub active_bytes: u64,
    pub indexed_durable_response_count: usize,
    pub indexed_policy_event_count: usize,
}

fn open_event_log_sink(path: &Path) -> io::Result<BufWriter<File>> {
    open_event_log_sink_with_parent_sync(path, sync_parent_directory)
}

fn open_event_log_sink_with_parent_sync(
    path: &Path,
    sync_parent: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<BufWriter<File>> {
    let existed = path.try_exists()?;
    let file = OpenOptions::new().create(true).append(true).open(path)?;

    #[cfg(unix)]
    {
        use std::{fs, os::unix::fs::PermissionsExt};

        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }

    if !existed {
        file.sync_all()?;
        sync_parent(path)?;
    }

    Ok(BufWriter::new(file))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JsonlTailRepairOutcome {
    NotNeeded,
    AppendedNewline {
        previous_len: u64,
    },
    Truncated {
        original_len: u64,
        repaired_len: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableResponseMatch {
    Missing,
    Unique {
        event_id: Uuid,
        policy_state: PolicyState,
        status: u16,
        routing_decision: RoutingDecision,
        controlled_reality: Option<ControlledRealityInteraction>,
    },
}

#[derive(Debug, Default)]
struct EventLogRecoveryIndex {
    durable_responses: HashMap<(SessionId, RequestId), DurableResponseMatch>,
    durable_events: HashMap<Uuid, Event>,
    event_ids: HashSet<Uuid>,
    archive_event_ids: VecDeque<HashSet<Uuid>>,
    active_event_ids: HashSet<Uuid>,
    track_all_durable_matches: bool,
}

impl EventLogRecoveryIndex {
    fn tracking_all_durable_matches() -> Self {
        Self {
            track_all_durable_matches: true,
            ..Self::default()
        }
    }

    fn rotate_active(&mut self) {
        self.archive_event_ids
            .push_back(std::mem::take(&mut self.active_event_ids));
        while self.archive_event_ids.len() > LOG_ARCHIVES_KEPT {
            if let Some(pruned) = self.archive_event_ids.pop_front() {
                for event_id in pruned {
                    self.event_ids.remove(&event_id);
                    self.durable_events.remove(&event_id);
                }
                self.durable_responses.retain(|_, response| {
                    matches!(
                        response,
                        DurableResponseMatch::Unique { event_id, .. }
                            if self.event_ids.contains(event_id)
                    )
                });
            }
        }
    }

    fn add_active_event_ids(&mut self, events: &[&Event]) {
        for event in events {
            self.event_ids.insert(event.id);
            self.active_event_ids.insert(event.id);
            if !self.track_all_durable_matches {
                continue;
            }
            if let (Some(request_id), Some(response)) =
                (event.request_id, durable_response_match(event))
            {
                self.durable_responses
                    .insert((event.session_id, request_id), response);
            }
            if matches!(&event.kind, EventKind::PolicyChanged { .. }) {
                self.durable_events.insert(event.id, (*event).clone());
            }
        }
    }

    fn remove_workflow(&mut self, session_id: SessionId, request_id: RequestId) {
        self.durable_responses.remove(&(session_id, request_id));
        self.durable_events.retain(|_, event| {
            event.session_id != session_id || event.request_id != Some(request_id)
        });
    }

    fn rotation_would_prune_recovery_evidence(&self) -> bool {
        if self.archive_event_ids.len() < LOG_ARCHIVES_KEPT {
            return false;
        }
        let Some(oldest_event_ids) = self.archive_event_ids.front() else {
            return false;
        };
        self.durable_responses.values().any(|response| {
            matches!(
                response,
                DurableResponseMatch::Unique { event_id, .. }
                    if oldest_event_ids.contains(event_id)
            )
        }) || self
            .durable_events
            .keys()
            .any(|event_id| oldest_event_ids.contains(event_id))
    }
}

pub struct EventLogRecoveryScan {
    index: EventLogRecoveryIndex,
    family_snapshot: Vec<EventLogSegmentSnapshot>,
    active_snapshot: EventLogActiveSnapshot,
    pub stats: EventLogRecoveryStats,
    pub active_tail_repair: JsonlTailRepairOutcome,
    pub active_torn_tail_line: Option<usize>,
}

impl EventLogRecoveryScan {
    pub fn indexed_durable_response(
        &self,
        session_id: SessionId,
        request_id: RequestId,
    ) -> DurableResponseMatch {
        self.index
            .durable_responses
            .get(&(session_id, request_id))
            .cloned()
            .unwrap_or(DurableResponseMatch::Missing)
    }

    pub fn indexed_durable_event_by_id(
        &self,
        session_id: SessionId,
        request_id: RequestId,
        event_id: Uuid,
    ) -> io::Result<Option<Event>> {
        let Some(event) = self.index.durable_events.get(&event_id) else {
            return Ok(None);
        };
        if event.session_id != session_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "durable event id matched the wrong session",
            ));
        }
        if event.request_id != Some(request_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "durable event id matched the wrong request",
            ));
        }
        Ok(Some(event.clone()))
    }
}

fn durable_response_match(event: &Event) -> Option<DurableResponseMatch> {
    let EventKind::ResponseServed {
        status,
        routing_decision,
        controlled_reality,
    } = &event.kind
    else {
        return None;
    };
    Some(DurableResponseMatch::Unique {
        event_id: event.id,
        policy_state: event.policy_state,
        status: *status,
        routing_decision: *routing_decision,
        controlled_reality: controlled_reality.clone(),
    })
}

struct BoundedEventSerialization {
    bytes: Vec<u8>,
}

impl BoundedEventSerialization {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(EVENT_LOG_READ_CHUNK_BYTES),
        }
    }

    fn finish(self) -> io::Result<Vec<u8>> {
        if self.bytes.len() > MAX_EVENT_LOG_RECORD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "serialized event exceeds the fixed record limit",
            ));
        }
        Ok(self.bytes)
    }
}

impl Write for BoundedEventSerialization {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let allocation_bound = MAX_EVENT_LOG_RECORD_BYTES + 1;
        let remaining = allocation_bound.saturating_sub(self.bytes.len());
        let retained = buffer.len().min(remaining);
        let required = self.bytes.len() + retained;
        self.bytes.reserve_exact(required - self.bytes.len());
        self.bytes.extend_from_slice(&buffer[..retained]);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialize_event_bounded(event: &Event) -> io::Result<Vec<u8>> {
    let mut sink = BoundedEventSerialization::new();
    serde_json::to_writer(&mut sink, event).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "failed to serialize event as JSON",
        )
    })?;
    sink.finish()
}

pub struct EventLogWriter<W> {
    sink: W,
    reopen: Option<Box<dyn Fn() -> io::Result<W> + Send + Sync>>,
    path: Option<PathBuf>,
    current_len: u64,
    startup_tail_repair: JsonlTailRepairOutcome,
    unresolved_durable_responses: HashSet<(SessionId, RequestId)>,
    recovery_index: EventLogRecoveryIndex,
    unavailable_after_io_failure: bool,
}

impl FileEventLogWriter {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let recovery = scan_event_log_family_all(&path, |_| Ok(()))?;
        Self::open_with_recovery(path, recovery)
    }

    pub fn open_with_recovery(
        path: impl AsRef<Path>,
        recovery: EventLogRecoveryScan,
    ) -> io::Result<Self> {
        let path = path.as_ref();
        verify_event_log_family_snapshot(path, &recovery.family_snapshot)?;
        let startup_tail_repair = apply_event_log_tail_repair(
            path,
            recovery.active_snapshot,
            recovery.active_tail_repair,
        )?;
        report_jsonl_tail_repair("event", path, startup_tail_repair);

        let current_len = match std::fs::metadata(path) {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error),
        };
        let path = path.to_path_buf();
        let reopen_path = path.clone();
        let sink = open_event_log_sink(&path)?;

        Ok(Self {
            sink,
            reopen: Some(Box::new(move || open_event_log_sink(&reopen_path))),
            path: Some(path),
            current_len,
            startup_tail_repair,
            unresolved_durable_responses: HashSet::new(),
            recovery_index: recovery.index,
            unavailable_after_io_failure: false,
        })
    }

    pub fn sync_all(&mut self) -> io::Result<()> {
        self.ensure_available()?;
        let result = self
            .sink
            .flush()
            .and_then(|()| self.sink.get_ref().sync_all());
        if result.is_err() {
            self.unavailable_after_io_failure = true;
        }
        result
    }

    /// Check the durable log family while the caller holds the writer lock.
    ///
    /// This reconciles the narrow crash window after a workflow response is
    /// fsynced but before its pending policy-state update is committed.
    pub fn durable_response(
        &mut self,
        session_id: SessionId,
        request_id: RequestId,
    ) -> io::Result<DurableResponseMatch> {
        self.sync_all()?;
        let result = self
            .recovery_index
            .durable_responses
            .get(&(session_id, request_id))
            .cloned()
            .unwrap_or(DurableResponseMatch::Missing);
        if !matches!(result, DurableResponseMatch::Missing) {
            self.unresolved_durable_responses
                .insert((session_id, request_id));
        }
        Ok(result)
    }

    pub fn write_durable_response(&mut self, event: &Event) -> io::Result<()> {
        self.write_durable_response_transaction(event, None)
    }

    pub fn write_durable_response_transaction(
        &mut self,
        event: &Event,
        policy_changed: Option<&Event>,
    ) -> io::Result<()> {
        let request_id = event.request_id.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "durable response event must carry a request id",
            )
        })?;
        if !matches!(event.kind, EventKind::ResponseServed { .. }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "durable workflow event must be a response_served event",
            ));
        }
        if event.source != EventSource::Proxy {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "durable response event must have a proxy source",
            ));
        }
        if let Some(policy_changed) = policy_changed {
            if policy_changed.session_id != event.session_id
                || policy_changed.request_id != Some(request_id)
                || policy_changed.source != EventSource::PolicyRouter
                || !matches!(&policy_changed.kind, EventKind::PolicyChanged { .. })
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "durable workflow policy event did not match its response",
                ));
            }
        }
        if !self.unresolved_durable_responses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "event log has an unresolved durable workflow response",
            ));
        }
        if self
            .recovery_index
            .durable_responses
            .contains_key(&(event.session_id, request_id))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "multiple durable response events matched one request",
            ));
        }
        if !self.recovery_index.track_all_durable_matches
            && self.recovery_index.durable_responses.len()
                >= crate::policy_store::MAX_POLICY_SESSIONS
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "durable response index exceeds the policy session limit",
            ));
        }

        let mut events = vec![event];
        events.extend(policy_changed);
        let write_result = self.write_events_unchecked(&events);
        if let Err(error) = write_result {
            if self.unavailable_after_io_failure {
                self.unresolved_durable_responses
                    .insert((event.session_id, request_id));
            }
            return Err(error);
        }
        self.recovery_index.durable_responses.insert(
            (event.session_id, request_id),
            durable_response_match(event)
                .expect("validated response event must produce a durable match"),
        );
        if let Some(policy_changed) = policy_changed {
            self.recovery_index
                .durable_events
                .insert(policy_changed.id, policy_changed.clone());
        }
        self.unresolved_durable_responses
            .insert((event.session_id, request_id));
        self.sync_all()
    }

    pub fn durable_event_by_id(
        &mut self,
        session_id: SessionId,
        request_id: RequestId,
        event_id: Uuid,
    ) -> io::Result<Option<Event>> {
        self.sync_all()?;
        let Some(event) = self.recovery_index.durable_events.get(&event_id) else {
            return Ok(None);
        };
        if event.session_id != session_id || event.request_id != Some(request_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "durable event id matched the wrong workflow",
            ));
        }
        Ok(Some(event.clone()))
    }

    pub fn write_recovered_policy_event(&mut self, event: &Event) -> io::Result<()> {
        let request_id = event.request_id.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "recovered policy event must carry a request id",
            )
        })?;
        if event.source != EventSource::PolicyRouter
            || !matches!(&event.kind, EventKind::PolicyChanged { .. })
            || !self
                .unresolved_durable_responses
                .contains(&(event.session_id, request_id))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "recovered policy event did not match a pinned workflow response",
            ));
        }
        self.write_event_unchecked(event)?;
        self.recovery_index
            .durable_events
            .insert(event.id, event.clone());
        self.sync_all()
    }

    pub fn pin_durable_response(&mut self, session_id: SessionId, request_id: RequestId) {
        self.unresolved_durable_responses
            .insert((session_id, request_id));
    }

    pub fn resolve_durable_response(&mut self, session_id: SessionId, request_id: RequestId) {
        self.unresolved_durable_responses
            .remove(&(session_id, request_id));
        self.recovery_index.remove_workflow(session_id, request_id);
    }

    pub fn resolve_all_durable_responses(&mut self) {
        self.unresolved_durable_responses.clear();
        self.recovery_index.durable_responses.clear();
        self.recovery_index.durable_events.clear();
    }

    #[cfg(test)]
    pub fn unresolved_durable_response_count(&self) -> usize {
        self.unresolved_durable_responses.len()
    }
}

impl<W: Write> EventLogWriter<W> {
    pub fn new(sink: W) -> Self {
        Self {
            sink,
            reopen: None,
            path: None,
            current_len: 0,
            startup_tail_repair: JsonlTailRepairOutcome::NotNeeded,
            unresolved_durable_responses: HashSet::new(),
            recovery_index: EventLogRecoveryIndex::tracking_all_durable_matches(),
            unavailable_after_io_failure: false,
        }
    }

    pub fn startup_tail_repair(&self) -> JsonlTailRepairOutcome {
        self.startup_tail_repair
    }

    pub fn write_event(&mut self, event: &Event) -> io::Result<()> {
        if !self.unresolved_durable_responses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "event log has an unresolved durable workflow response",
            ));
        }
        self.write_event_unchecked(event)
    }

    fn write_event_unchecked(&mut self, event: &Event) -> io::Result<()> {
        self.write_events_unchecked(&[event])
    }

    fn write_events_unchecked(&mut self, events: &[&Event]) -> io::Result<()> {
        self.ensure_available()?;
        let serialized = events
            .iter()
            .map(|event| serialize_event_bounded(event))
            .collect::<io::Result<Vec<_>>>()?;
        let mut batch_ids = HashSet::with_capacity(events.len());
        let mut batch_responses = HashSet::with_capacity(events.len());
        for event in events {
            if event.schema_version != eidolon_core::EVENT_SCHEMA_VERSION {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "event writer received an unsupported schema version",
                ));
            }
            if self.recovery_index.event_ids.contains(&event.id) || !batch_ids.insert(event.id) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "event log contains a duplicate event id",
                ));
            }
            if let (Some(request_id), Some(_)) = (event.request_id, durable_response_match(event)) {
                if event.source != EventSource::Proxy {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "durable response event had a non-proxy source",
                    ));
                }
                let key = (event.session_id, request_id);
                if self.recovery_index.durable_responses.contains_key(&key)
                    || !batch_responses.insert(key)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "multiple durable response events matched one request",
                    ));
                }
            }
        }
        let incoming = serialized
            .iter()
            .try_fold(0_u64, |total, event| {
                total.checked_add(event.len() as u64 + 1)
            })
            .ok_or_else(|| io::Error::other("event batch length overflow"))?;
        if incoming > LOG_ROTATE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "serialized event batch exceeds the fixed segment limit",
            ));
        }
        if self.path.is_some()
            && self
                .current_len
                .checked_add(incoming)
                .is_none_or(|next| next > LOG_ROTATE_BYTES)
            && self.recovery_index.rotation_would_prune_recovery_evidence()
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "event log rotation would prune unresolved workflow evidence",
            ));
        }

        if let Err(error) = self.rotate_if_needed(incoming) {
            self.unavailable_after_io_failure = true;
            return Err(error);
        }
        for event in serialized {
            if let Err(error) = self
                .sink
                .write_all(&event)
                .and_then(|()| self.sink.write_all(b"\n"))
            {
                self.unavailable_after_io_failure = true;
                return Err(error);
            }
        }
        if let Err(error) = self.sink.flush() {
            self.unavailable_after_io_failure = true;
            return Err(error);
        }
        let Some(current_len) = self.current_len.checked_add(incoming) else {
            self.unavailable_after_io_failure = true;
            return Err(io::Error::other("event log length overflow"));
        };
        self.current_len = current_len;
        self.recovery_index.add_active_event_ids(events);
        Ok(())
    }

    fn ensure_available(&self) -> io::Result<()> {
        if self.unavailable_after_io_failure {
            return Err(io::Error::other(
                "event log writer is unavailable after an earlier I/O failure",
            ));
        }
        Ok(())
    }

    fn rotate_if_needed(&mut self, incoming: u64) -> io::Result<()> {
        let (Some(path), Some(reopen)) = (self.path.clone(), self.reopen.as_ref()) else {
            return Ok(());
        };
        if self
            .current_len
            .checked_add(incoming)
            .is_some_and(|next| next <= LOG_ROTATE_BYTES)
        {
            return Ok(());
        }

        self.sink.flush()?;
        let archive = rotate_log_now(&path)?;
        eprintln!(
            "eidolon log rotation: archived event log to {}",
            archive.display()
        );

        self.sink = reopen()?;
        self.current_len = 0;
        self.recovery_index.rotate_active();
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EventLogSegmentKind {
    Archive,
    Active,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EventLogActiveSnapshot {
    Missing,
    Present { bytes: u64 },
}

#[derive(Debug)]
struct EventLogSegment {
    path: PathBuf,
    kind: EventLogSegmentKind,
    advertised_len: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EventLogSegmentSnapshot {
    path: PathBuf,
    kind: EventLogSegmentKind,
    bytes: u64,
    sha256: [u8; 32],
}

struct EventLogSegmentScan {
    event_ids: HashSet<Uuid>,
    tail_repair: JsonlTailRepairOutcome,
    torn_tail_line: Option<usize>,
    bytes: u64,
    records: usize,
    sha256: [u8; 32],
}

enum RecoverySelection {
    All,
    Targets {
        workflows: HashSet<(SessionId, RequestId)>,
        policy_events: HashMap<Uuid, (SessionId, RequestId)>,
    },
}

impl RecoverySelection {
    fn targets(targets: &[EventLogRecoveryTarget]) -> io::Result<Self> {
        if targets.len() > crate::policy_store::MAX_POLICY_SESSIONS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "event log recovery target count exceeds the policy session limit",
            ));
        }
        let mut workflows = HashSet::with_capacity(targets.len());
        let mut policy_events = HashMap::with_capacity(targets.len());
        for target in targets {
            if !workflows.insert((target.session_id, target.request_id)) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "event log recovery contains a duplicate workflow target",
                ));
            }
            if let Some(event_id) = target.expected_policy_event_id {
                if policy_events
                    .insert(event_id, (target.session_id, target.request_id))
                    .is_some()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "event log recovery contains a duplicate policy event target",
                    ));
                }
            }
        }
        Ok(Self::Targets {
            workflows,
            policy_events,
        })
    }

    fn tracks_workflow(&self, session_id: SessionId, request_id: RequestId) -> bool {
        match self {
            Self::All => true,
            Self::Targets { workflows, .. } => workflows.contains(&(session_id, request_id)),
        }
    }

    fn tracked_policy_workflow(&self, event: &Event) -> Option<(SessionId, RequestId)> {
        match self {
            Self::All => matches!(event.kind, EventKind::PolicyChanged { .. })
                .then(|| {
                    event
                        .request_id
                        .map(|request_id| (event.session_id, request_id))
                })
                .flatten(),
            Self::Targets { policy_events, .. } => policy_events.get(&event.id).copied(),
        }
    }
}

pub fn validate_event_log_family_without_mutation(
    path: &Path,
) -> io::Result<EventLogRecoveryStats> {
    scan_event_log_family(path, &[], |_| Ok(())).map(|scan| scan.stats)
}

pub fn scan_event_log_family(
    path: &Path,
    targets: &[EventLogRecoveryTarget],
    on_event: impl FnMut(&Event) -> io::Result<()>,
) -> io::Result<EventLogRecoveryScan> {
    scan_event_log_family_with_selection(path, RecoverySelection::targets(targets)?, on_event)
}

fn scan_event_log_family_all(
    path: &Path,
    on_event: impl FnMut(&Event) -> io::Result<()>,
) -> io::Result<EventLogRecoveryScan> {
    scan_event_log_family_with_selection(path, RecoverySelection::All, on_event)
}

fn scan_event_log_family_with_selection(
    path: &Path,
    selection: RecoverySelection,
    mut on_event: impl FnMut(&Event) -> io::Result<()>,
) -> io::Result<EventLogRecoveryScan> {
    let segments = event_log_family_inventory(path)?;
    let mut active_snapshot = EventLogActiveSnapshot::Missing;
    let mut family_snapshot = Vec::with_capacity(segments.len());
    let mut index = if matches!(&selection, RecoverySelection::All) {
        EventLogRecoveryIndex::tracking_all_durable_matches()
    } else {
        EventLogRecoveryIndex::default()
    };
    let mut stats = EventLogRecoveryStats {
        archive_count: segments
            .iter()
            .filter(|segment| segment.kind == EventLogSegmentKind::Archive)
            .count(),
        segment_count: segments.len(),
        ..EventLogRecoveryStats::default()
    };
    let mut active_tail_repair = JsonlTailRepairOutcome::NotNeeded;
    let mut active_torn_tail_line = None;

    for segment in segments {
        let EventLogSegmentScan {
            event_ids,
            tail_repair,
            torn_tail_line,
            bytes,
            records,
            sha256,
        } = scan_event_log_segment(&segment, &selection, &mut index, &mut on_event)?;
        stats.family_bytes = stats
            .family_bytes
            .checked_add(bytes)
            .ok_or_else(|| io::Error::other("event log family byte count overflow"))?;
        if stats.family_bytes > MAX_EVENT_LOG_FAMILY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "event log family exceeds the fixed byte limit",
            ));
        }
        stats.record_count = stats
            .record_count
            .checked_add(records)
            .ok_or_else(|| io::Error::other("event log record count overflow"))?;
        family_snapshot.push(EventLogSegmentSnapshot {
            path: segment.path.clone(),
            kind: segment.kind,
            bytes,
            sha256,
        });
        match segment.kind {
            EventLogSegmentKind::Archive => index.archive_event_ids.push_back(event_ids),
            EventLogSegmentKind::Active => {
                index.active_event_ids = event_ids;
                active_snapshot = EventLogActiveSnapshot::Present { bytes };
                stats.active_bytes = bytes;
                active_tail_repair = tail_repair;
                active_torn_tail_line = torn_tail_line;
            }
        }
    }

    stats.indexed_durable_response_count = index.durable_responses.len();
    stats.indexed_policy_event_count = index.durable_events.len();

    Ok(EventLogRecoveryScan {
        index,
        family_snapshot,
        active_snapshot,
        stats,
        active_tail_repair,
        active_torn_tail_line,
    })
}

fn event_log_family_inventory(path: &Path) -> io::Result<Vec<EventLogSegment>> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let base = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "event log path has no UTF-8 file name",
            )
        })?;
    let archive_prefix = format!("{base}.");
    let mut archives = Vec::new();
    match std::fs::read_dir(parent) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry?;
                let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                    continue;
                };
                let Some(suffix) = name.strip_prefix(&archive_prefix) else {
                    continue;
                };
                if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
                    continue;
                }
                if suffix.len() != EVENT_LOG_ARCHIVE_SUFFIX_DIGITS {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "event log family contains a noncanonical numeric archive name",
                    ));
                }
                if archives.len() >= LOG_ARCHIVES_KEPT {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "event log family exceeds the fixed archive count",
                    ));
                }
                let candidate = entry.path();
                let metadata = std::fs::symlink_metadata(&candidate)?;
                validate_event_log_segment_metadata(&candidate, &metadata)?;
                archives.push((suffix.to_string(), candidate, metadata.len()));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    archives.sort_by(|(left, _, _), (right, _, _)| left.cmp(right));

    let mut segments = archives
        .into_iter()
        .map(|(_, path, advertised_len)| EventLogSegment {
            path,
            kind: EventLogSegmentKind::Archive,
            advertised_len,
        })
        .collect::<Vec<_>>();
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_event_log_segment_metadata(path, &metadata)?;
            segments.push(EventLogSegment {
                path: path.to_path_buf(),
                kind: EventLogSegmentKind::Active,
                advertised_len: metadata.len(),
            });
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(segments)
}

fn validate_event_log_segment_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> io::Result<()> {
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "event log family member `{}` is not a regular file",
                path.display()
            ),
        ));
    }
    if metadata.len() > LOG_ROTATE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "event log segment `{}` exceeds the fixed {} byte limit",
                path.display(),
                LOG_ROTATE_BYTES
            ),
        ));
    }
    Ok(())
}

fn scan_event_log_segment(
    segment: &EventLogSegment,
    selection: &RecoverySelection,
    index: &mut EventLogRecoveryIndex,
    on_event: &mut impl FnMut(&Event) -> io::Result<()>,
) -> io::Result<EventLogSegmentScan> {
    if segment.advertised_len > LOG_ROTATE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "event log segment exceeds the fixed byte limit",
        ));
    }
    let file = File::open(&segment.path)?;
    let opened_metadata = file.metadata()?;
    validate_event_log_segment_metadata(&segment.path, &opened_metadata)?;
    scan_event_log_reader(file, segment, selection, index, on_event)
}

fn scan_event_log_reader(
    mut reader: impl Read,
    segment: &EventLogSegment,
    selection: &RecoverySelection,
    index: &mut EventLogRecoveryIndex,
    on_event: &mut impl FnMut(&Event) -> io::Result<()>,
) -> io::Result<EventLogSegmentScan> {
    if segment.advertised_len > LOG_ROTATE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "event log segment exceeds the fixed byte limit",
        ));
    }
    let mut chunk = [0_u8; EVENT_LOG_READ_CHUNK_BYTES];
    let mut record = Vec::with_capacity(EVENT_LOG_READ_CHUNK_BYTES);
    let mut total_bytes = 0_u64;
    let mut consumed_bytes = 0_u64;
    let mut record_start = 0_u64;
    let mut line_number = 1_usize;
    let mut record_count = 0_usize;
    let mut segment_event_ids = HashSet::new();
    let mut sha256 = Sha256::new();

    loop {
        let remaining = (LOG_ROTATE_BYTES + 1).saturating_sub(total_bytes);
        if remaining == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "event log segment exceeds the fixed byte limit",
            ));
        }
        let requested = usize::try_from(remaining)
            .unwrap_or(EVENT_LOG_READ_CHUNK_BYTES)
            .min(EVENT_LOG_READ_CHUNK_BYTES);
        let read = loop {
            match reader.read(&mut chunk[..requested]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => break result?,
            }
        };
        if read > requested {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "event log reader returned an invalid byte count",
            ));
        }
        if read == 0 {
            break;
        }
        total_bytes = total_bytes
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("event log segment byte count overflow"))?;
        if total_bytes > LOG_ROTATE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "event log segment exceeds the fixed byte limit",
            ));
        }
        sha256.update(&chunk[..read]);

        for byte in &chunk[..read] {
            consumed_bytes += 1;
            if *byte == b'\n' {
                if !record.iter().all(u8::is_ascii_whitespace) {
                    let event = deserialize_event_record(&record, &segment.path, line_number)?;
                    process_recovery_event(
                        event,
                        selection,
                        index,
                        &mut segment_event_ids,
                        on_event,
                    )?;
                    record_count += 1;
                }
                record.clear();
                line_number += 1;
                record_start = consumed_bytes;
                continue;
            }
            if record.len() >= MAX_EVENT_LOG_RECORD_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "event log record at `{}` line {} exceeds the fixed {} byte limit",
                        segment.path.display(),
                        line_number,
                        MAX_EVENT_LOG_RECORD_BYTES
                    ),
                ));
            }
            record.push(*byte);
        }
    }

    let mut torn_tail_line = None;
    let tail_repair = if record.is_empty() {
        JsonlTailRepairOutcome::NotNeeded
    } else if record.iter().all(u8::is_ascii_whitespace) {
        if segment.kind == EventLogSegmentKind::Archive {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "event log archive has an unterminated final record",
            ));
        }
        if total_bytes == LOG_ROTATE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "event log active tail has no room for its newline repair",
            ));
        }
        JsonlTailRepairOutcome::AppendedNewline {
            previous_len: total_bytes,
        }
    } else {
        match serde_json::from_slice::<Event>(&record) {
            Ok(event) => {
                validate_event_schema(&event, &segment.path, line_number)?;
                if segment.kind == EventLogSegmentKind::Archive {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "event log archive has an unterminated final record",
                    ));
                }
                if total_bytes == LOG_ROTATE_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "event log active tail has no room for its newline repair",
                    ));
                }
                process_recovery_event(event, selection, index, &mut segment_event_ids, on_event)?;
                record_count += 1;
                JsonlTailRepairOutcome::AppendedNewline {
                    previous_len: total_bytes,
                }
            }
            Err(_) if segment.kind == EventLogSegmentKind::Active => {
                torn_tail_line = Some(line_number);
                JsonlTailRepairOutcome::Truncated {
                    original_len: total_bytes,
                    repaired_len: record_start,
                }
            }
            Err(error) => return Err(invalid_event_json_error(&segment.path, line_number, &error)),
        }
    };

    Ok(EventLogSegmentScan {
        event_ids: segment_event_ids,
        tail_repair,
        torn_tail_line,
        bytes: total_bytes,
        records: record_count,
        sha256: sha256.finalize().into(),
    })
}

fn verify_event_log_family_snapshot(
    path: &Path,
    expected: &[EventLogSegmentSnapshot],
) -> io::Result<()> {
    let current = event_log_family_inventory(path)?;
    if current.len() != expected.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "event log family membership changed after authoritative recovery scan",
        ));
    }

    for (segment, expected) in current.iter().zip(expected) {
        if segment.path != expected.path || segment.kind != expected.kind {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "event log family ordering changed after authoritative recovery scan",
            ));
        }
        let actual = fingerprint_event_log_segment(segment)?;
        if actual.bytes != expected.bytes || actual.sha256 != expected.sha256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "event log family contents changed after authoritative recovery scan",
            ));
        }
    }
    Ok(())
}

fn fingerprint_event_log_segment(segment: &EventLogSegment) -> io::Result<EventLogSegmentSnapshot> {
    let mut file = File::open(&segment.path)?;
    let metadata = file.metadata()?;
    validate_event_log_segment_metadata(&segment.path, &metadata)?;
    let mut chunk = [0_u8; EVENT_LOG_READ_CHUNK_BYTES];
    let mut bytes = 0_u64;
    let mut sha256 = Sha256::new();
    loop {
        let remaining = (LOG_ROTATE_BYTES + 1).saturating_sub(bytes);
        if remaining == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "event log segment exceeds the fixed byte limit",
            ));
        }
        let requested = usize::try_from(remaining)
            .unwrap_or(EVENT_LOG_READ_CHUNK_BYTES)
            .min(EVENT_LOG_READ_CHUNK_BYTES);
        let read = loop {
            match file.read(&mut chunk[..requested]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => break result?,
            }
        };
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("event log segment byte count overflow"))?;
        if bytes > LOG_ROTATE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "event log segment exceeds the fixed byte limit",
            ));
        }
        sha256.update(&chunk[..read]);
    }

    Ok(EventLogSegmentSnapshot {
        path: segment.path.clone(),
        kind: segment.kind,
        bytes,
        sha256: sha256.finalize().into(),
    })
}

fn deserialize_event_record(record: &[u8], path: &Path, line_number: usize) -> io::Result<Event> {
    let event: Event = serde_json::from_slice(record)
        .map_err(|error| invalid_event_json_error(path, line_number, &error))?;
    validate_event_schema(&event, path, line_number)?;
    Ok(event)
}

fn validate_event_schema(event: &Event, path: &Path, line_number: usize) -> io::Result<()> {
    if event.schema_version != eidolon_core::EVENT_SCHEMA_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "event log record at `{}` line {} has unsupported schema version {}; expected {}",
                path.display(),
                line_number,
                event.schema_version,
                eidolon_core::EVENT_SCHEMA_VERSION
            ),
        ));
    }
    Ok(())
}

fn invalid_event_json_error(
    path: &Path,
    line_number: usize,
    error: &serde_json::Error,
) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "invalid event JSON at `{}` line {} column {}",
            path.display(),
            line_number,
            error.column()
        ),
    )
}

fn process_recovery_event(
    event: Event,
    selection: &RecoverySelection,
    index: &mut EventLogRecoveryIndex,
    segment_event_ids: &mut HashSet<Uuid>,
    on_event: &mut impl FnMut(&Event) -> io::Result<()>,
) -> io::Result<()> {
    if !index.event_ids.insert(event.id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "event log family contains a duplicate event id",
        ));
    }
    segment_event_ids.insert(event.id);

    if let (Some(request_id), Some(response)) = (event.request_id, durable_response_match(&event)) {
        if selection.tracks_workflow(event.session_id, request_id) {
            if event.source != EventSource::Proxy {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "durable response event had a non-proxy source",
                ));
            }
            if index
                .durable_responses
                .insert((event.session_id, request_id), response)
                .is_some()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "multiple durable response events matched one request",
                ));
            }
        }
    }

    if let Some((session_id, request_id)) = selection.tracked_policy_workflow(&event) {
        if event.session_id != session_id || event.request_id != Some(request_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "durable event id matched the wrong workflow",
            ));
        }
        index.durable_events.insert(event.id, event.clone());
    }

    on_event(&event)
}

/// Repair an incomplete final JSONL record before the file is opened for
/// append. A valid final JSON value only needs its missing delimiter restored;
/// an invalid tail is discarded back to the previous complete line.
pub fn repair_jsonl_tail(path: &Path) -> io::Result<JsonlTailRepairOutcome> {
    repair_jsonl_tail_with(path, |record| {
        serde_json::from_slice::<serde_json::Value>(record).is_ok()
    })
}

fn apply_event_log_tail_repair(
    path: &Path,
    snapshot: EventLogActiveSnapshot,
    repair: JsonlTailRepairOutcome,
) -> io::Result<JsonlTailRepairOutcome> {
    let expected_len = match snapshot {
        EventLogActiveSnapshot::Missing => {
            return match std::fs::symlink_metadata(path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    if repair == JsonlTailRepairOutcome::NotNeeded {
                        Ok(repair)
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "event log recovery planned a repair for a missing active segment",
                        ))
                    }
                }
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "event log active segment appeared after authoritative recovery scan",
                )),
                Err(error) => Err(error),
            };
        }
        EventLogActiveSnapshot::Present { bytes } => bytes,
    };

    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "event log active segment disappeared after authoritative recovery scan",
            )
        } else {
            error
        }
    })?;
    validate_event_log_segment_metadata(path, &metadata)?;
    if metadata.len() != expected_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "event log active segment changed after authoritative recovery scan",
        ));
    }

    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let opened_metadata = file.metadata()?;
    validate_event_log_segment_metadata(path, &opened_metadata)?;
    if opened_metadata.len() != expected_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "event log active segment changed while applying its recovery plan",
        ));
    }

    match repair {
        JsonlTailRepairOutcome::NotNeeded => {}
        JsonlTailRepairOutcome::AppendedNewline { previous_len } => {
            if previous_len != expected_len || previous_len >= LOG_ROTATE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "event log newline repair does not match the authoritative scan",
                ));
            }
            file.seek(SeekFrom::End(0))?;
            file.write_all(b"\n")?;
            file.sync_data()?;
        }
        JsonlTailRepairOutcome::Truncated {
            original_len,
            repaired_len,
        } => {
            if original_len != expected_len || repaired_len > original_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "event log truncation repair does not match the authoritative scan",
                ));
            }
            file.set_len(repaired_len)?;
            file.sync_data()?;
        }
    }
    Ok(repair)
}

fn repair_jsonl_tail_with(
    path: &Path,
    is_valid_record: impl Fn(&[u8]) -> bool,
) -> io::Result<JsonlTailRepairOutcome> {
    let mut file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(JsonlTailRepairOutcome::NotNeeded);
        }
        Err(error) => return Err(error),
    };
    let original_len = file.metadata()?.len();
    if original_len == 0 {
        return Ok(JsonlTailRepairOutcome::NotNeeded);
    }

    let mut reader = BufReader::new(file.try_clone()?);
    let mut line = Vec::new();
    let mut line_start = 0_u64;
    let mut line_number = 1_usize;
    loop {
        line.clear();
        let bytes_read = reader.read_until(b'\n', &mut line)?;
        if bytes_read == 0 {
            return Ok(JsonlTailRepairOutcome::NotNeeded);
        }
        let terminated = line.ends_with(b"\n");
        let record = if terminated {
            &line[..line.len() - 1]
        } else {
            line.as_slice()
        };
        let valid = record.iter().all(u8::is_ascii_whitespace) || is_valid_record(record);
        if valid {
            if terminated {
                line_start = line_start.saturating_add(bytes_read as u64);
                line_number += 1;
                continue;
            }
            file.seek(SeekFrom::End(0))?;
            file.write_all(b"\n")?;
            file.sync_data()?;
            return Ok(JsonlTailRepairOutcome::AppendedNewline {
                previous_len: original_len,
            });
        }
        if terminated {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "invalid JSONL record at line {line_number} in `{}`",
                    path.display()
                ),
            ));
        }

        file.set_len(line_start)?;
        file.sync_data()?;
        return Ok(JsonlTailRepairOutcome::Truncated {
            original_len,
            repaired_len: line_start,
        });
    }
}

pub fn report_jsonl_tail_repair(log_name: &str, path: &Path, outcome: JsonlTailRepairOutcome) {
    match outcome {
        JsonlTailRepairOutcome::NotNeeded => {}
        JsonlTailRepairOutcome::AppendedNewline { previous_len } => eprintln!(
            "eidolon log tail repair: restored missing newline in {log_name} log `{}` after {previous_len} bytes",
            path.display()
        ),
        JsonlTailRepairOutcome::Truncated {
            original_len,
            repaired_len,
        } => eprintln!(
            "eidolon log tail repair: truncated invalid final fragment in {log_name} log `{}` from {original_len} to {repaired_len} bytes",
            path.display()
        ),
    }
}

/// Rotate `path` to a timestamped archive when its on-disk length already
/// exceeds the rotation budget (used at open time). Returns the archive
/// path when a rotation happened.
pub fn rotate_log_if_oversized(path: &Path) -> io::Result<Option<PathBuf>> {
    let oversized = match std::fs::metadata(path) {
        Ok(metadata) => metadata.len() >= LOG_ROTATE_BYTES,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error),
    };
    if !oversized {
        return Ok(None);
    }

    rotate_log_now(path).map(Some)
}

/// Rotate `path` unconditionally: rename it to `<path>.<unix_nanos>` and
/// prune archives beyond the retention budget. The caller reopens the
/// active path afterwards.
pub fn rotate_log_now(path: &Path) -> io::Result<PathBuf> {
    rotate_log_now_with_sync(path, sync_log_file, sync_parent_directory)
}

fn rotate_log_now_with_sync(
    path: &Path,
    sync_file: impl FnOnce(&Path) -> io::Result<()>,
    sync_parent: impl Fn(&Path) -> io::Result<()>,
) -> io::Result<PathBuf> {
    sync_file(path)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let archive = next_archive_path(path, now)?;
    std::fs::rename(path, &archive)?;
    sync_parent(path)?;
    prune_log_archives(path, &archive, LOG_ARCHIVES_KEPT)?;
    sync_parent(path)?;
    Ok(archive)
}

fn sync_log_file(path: &Path) -> io::Result<()> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?
        .sync_all()
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn next_archive_path(path: &Path, initial_stamp: u128) -> io::Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut suffix = format!("{initial_stamp:039}");
    match std::fs::read_dir(parent) {
        Ok(entries) => {
            for entry in entries {
                let candidate = entry?.path();
                let Some(existing) = archive_suffix(path, &candidate) else {
                    continue;
                };
                if existing >= suffix.as_str() {
                    suffix = increment_archive_suffix(existing)?;
                }
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    loop {
        let mut archive = path.as_os_str().to_os_string();
        archive.push(format!(".{suffix}"));
        let archive = PathBuf::from(archive);
        if !archive.try_exists()? {
            return Ok(archive);
        }
        suffix = increment_archive_suffix(&suffix)?;
    }
}

fn increment_archive_suffix(suffix: &str) -> io::Result<String> {
    let mut next = suffix.as_bytes().to_vec();
    for index in (0..next.len()).rev() {
        if next[index] != b'9' {
            next[index] += 1;
            next[index + 1..].fill(b'0');
            return String::from_utf8(next)
                .map_err(|_| io::Error::other("event log archive suffix became invalid UTF-8"));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "event log archive namespace is exhausted",
    ))
}

fn prune_log_archives(path: &Path, fresh_archive: &Path, keep: usize) -> io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };

    let mut archives = Vec::new();
    for entry in std::fs::read_dir(parent)? {
        let candidate = entry?.path();
        if candidate == fresh_archive {
            continue;
        }
        let Some(suffix) = archive_suffix(path, &candidate) else {
            continue;
        };
        let suffix = suffix.to_string();
        archives.push((candidate, suffix));
    }
    archives.sort_by(|(_, left), (_, right)| {
        left.len().cmp(&right.len()).then_with(|| left.cmp(right))
    });

    let old_archives_to_keep = keep.saturating_sub(1);
    let excess = archives.len().saturating_sub(old_archives_to_keep);
    for (stale, _) in archives.into_iter().take(excess) {
        std::fs::remove_file(stale)?;
    }
    if keep == 0 {
        std::fs::remove_file(fresh_archive)?;
    }

    Ok(())
}

fn archive_suffix<'a>(path: &Path, candidate: &'a Path) -> Option<&'a str> {
    let base = path.file_name()?.to_str()?;
    let candidate = candidate.file_name()?.to_str()?;
    let suffix = candidate.strip_prefix(base)?.strip_prefix('.')?;
    (suffix.len() == EVENT_LOG_ARCHIVE_SUFFIX_DIGITS
        && suffix.bytes().all(|byte| byte.is_ascii_digit()))
    .then_some(suffix)
}

#[cfg(test)]
fn event_log_family_paths(path: &Path) -> io::Result<Vec<PathBuf>> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut archives = Vec::new();
    for entry in std::fs::read_dir(parent)? {
        let candidate = entry?.path();
        let Some(suffix) = archive_suffix(path, &candidate) else {
            continue;
        };
        let suffix = suffix.to_string();
        archives.push((candidate, suffix));
    }
    archives.sort_by(|(_, left), (_, right)| {
        left.len().cmp(&right.len()).then_with(|| left.cmp(right))
    });

    let mut segments = archives
        .into_iter()
        .map(|(candidate, _)| candidate)
        .collect::<Vec<_>>();
    segments.push(path.to_path_buf());
    Ok(segments)
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Read, Write};

    use eidolon_core::{
        Event, EventKind, EventSource, IngressIdentity, PolicyState, RequestId, RoutingDecision,
        SafeHeaderObservation, SessionId,
    };
    use serde_json::Value;

    use super::{DurableResponseMatch, EventLogWriter, FileEventLogWriter, JsonlTailRepairOutcome};

    fn unique_temp_path(label: &str) -> std::path::PathBuf {
        use std::{
            env,
            time::{SystemTime, UNIX_EPOCH},
        };

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();

        env::temp_dir().join(format!(
            "eidolon-event-log-{label}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn archive_path(path: &std::path::Path, stamp: u128) -> std::path::PathBuf {
        let mut archive = path.as_os_str().to_os_string();
        archive.push(format!(".{stamp:039}"));
        archive.into()
    }

    fn event_jsonl(events: &[&Event]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for event in events {
            serde_json::to_writer(&mut bytes, event).expect("event should serialize");
            bytes.push(b'\n');
        }
        bytes
    }

    fn write_events(path: &std::path::Path, events: &[&Event]) {
        std::fs::write(path, event_jsonl(events)).expect("event fixture should write");
    }

    fn response_event(session_id: SessionId, request_id: RequestId, status: u16) -> Event {
        Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::ControlledReality,
            EventKind::ResponseServed {
                status,
                routing_decision: RoutingDecision::ControlledReality,
                controlled_reality: None,
            },
        )
        .with_request_id(request_id)
    }

    fn policy_event(session_id: SessionId, request_id: RequestId) -> Event {
        Event::new(
            session_id,
            EventSource::PolicyRouter,
            PolicyState::Blocked,
            EventKind::PolicyChanged {
                from: PolicyState::ControlledReality,
                to: PolicyState::Blocked,
                reason: "event-log recovery test".to_string(),
            },
        )
        .with_request_id(request_id)
    }

    fn event_with_serialized_len(target: usize) -> Event {
        let mut event = request_event("GET", "");
        let baseline = serde_json::to_vec(&event)
            .expect("baseline event should serialize")
            .len();
        assert!(target >= baseline, "target must fit the event envelope");
        let EventKind::RequestSeen { path, .. } = &mut event.kind else {
            unreachable!("request_event must produce request_seen")
        };
        *path = "x".repeat(target - baseline);
        assert_eq!(
            serde_json::to_vec(&event)
                .expect("sized event should serialize")
                .len(),
            target
        );
        event
    }

    struct ShortReader<R> {
        inner: R,
        maximum_read: usize,
    }

    impl<R: Read> Read for ShortReader<R> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let limit = buffer.len().min(self.maximum_read);
            self.inner.read(&mut buffer[..limit])
        }
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("synthetic event-log read failure"))
        }
    }

    struct FailsIfRead;

    impl Read for FailsIfRead {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            panic!("metadata precheck must reject before reading")
        }
    }

    struct RepeatingByteReader {
        remaining: u64,
        byte: u8,
    }

    impl Read for RepeatingByteReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let read = usize::try_from(self.remaining)
                .unwrap_or(buffer.len())
                .min(buffer.len());
            buffer[..read].fill(self.byte);
            self.remaining -= read as u64;
            Ok(read)
        }
    }

    struct TestFamily {
        path: std::path::PathBuf,
    }

    impl TestFamily {
        fn new(label: &str) -> Self {
            Self {
                path: unique_temp_path(label),
            }
        }

        fn archive(&self, stamp: u128) -> std::path::PathBuf {
            archive_path(&self.path, stamp)
        }
    }

    impl Drop for TestFamily {
        fn drop(&mut self) {
            let Some(parent) = self.path.parent() else {
                return;
            };
            let Some(base) = self.path.file_name().and_then(|name| name.to_str()) else {
                return;
            };
            let prefix = format!("{base}.");
            let Ok(entries) = std::fs::read_dir(parent) else {
                return;
            };
            for entry in entries.flatten() {
                let candidate = entry.path();
                let Some(name) = candidate.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                if name != base && !name.starts_with(&prefix) {
                    continue;
                }
                match std::fs::symlink_metadata(&candidate) {
                    Ok(metadata) if metadata.is_dir() => {
                        let _ = std::fs::remove_dir_all(candidate);
                    }
                    Ok(_) => {
                        let _ = std::fs::remove_file(candidate);
                    }
                    Err(_) => {}
                }
            }
        }
    }

    fn request_event(method: &str, path: &str) -> Event {
        Event::new(
            SessionId::new(),
            EventSource::Proxy,
            PolicyState::Observe,
            EventKind::RequestSeen {
                method: method.to_string(),
                path: path.to_string(),
                safe_headers: vec![
                    SafeHeaderObservation {
                        name: "user-agent".to_string(),
                        present: true,
                    },
                    SafeHeaderObservation {
                        name: "authorization".to_string(),
                        present: false,
                    },
                ],
                ingress_identity: IngressIdentity::default(),
                authenticated_ingress_rule_rejection: None,
                local_ingress_trust_scope_rejection: None,
                trusted_ingress_soften_match: None,
                ingress_signals: Default::default(),
                discovery_recon_score: Default::default(),
                routing_decision: RoutingDecision::ProtectedUpstream,
            },
        )
    }

    #[test]
    fn writes_one_event_as_one_newline_delimited_json_object() {
        let mut output = Vec::new();
        let mut writer = EventLogWriter::new(&mut output);
        let event = request_event("GET", "/openapi.json");

        writer.write_event(&event).expect("event should write");
        drop(writer);

        let rendered = String::from_utf8(output).expect("output should be utf8");
        assert!(rendered.ends_with('\n'));

        let lines = rendered.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 1);

        let value: Value = serde_json::from_str(lines[0]).expect("line should be valid json");
        assert_eq!(value["schema_version"], event.schema_version);
        assert_eq!(
            value["session_id"],
            serde_json::to_value(event.session_id).unwrap()
        );
        assert_eq!(value["source"], "proxy");
        assert_eq!(value["policy_state"], "observe");
        assert_eq!(value["kind"]["type"], "request_seen");
        assert_eq!(value["kind"]["method"], "GET");
        assert_eq!(value["kind"]["path"], "/openapi.json");
        assert_eq!(value["kind"]["safe_headers"][0]["name"], "user-agent");
        assert_eq!(value["kind"]["safe_headers"][0]["present"], true);
        assert_eq!(value["kind"]["safe_headers"][1]["name"], "authorization");
        assert_eq!(value["kind"]["safe_headers"][1]["present"], false);
    }

    #[test]
    fn multiple_events_append_as_multiple_lines() {
        let mut output = Vec::new();
        let mut writer = EventLogWriter::new(&mut output);

        writer
            .write_event(&request_event("GET", "/docs"))
            .expect("first event should write");
        writer
            .write_event(&request_event("POST", "/api/v1/import"))
            .expect("second event should write");
        drop(writer);

        let rendered = String::from_utf8(output).expect("output should be utf8");
        let lines = rendered.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);

        let first: Value = serde_json::from_str(lines[0]).expect("first line should be json");
        let second: Value = serde_json::from_str(lines[1]).expect("second line should be json");
        assert_eq!(first["kind"]["method"], "GET");
        assert_eq!(first["kind"]["path"], "/docs");
        assert_eq!(second["kind"]["method"], "POST");
        assert_eq!(second["kind"]["path"], "/api/v1/import");
    }

    #[test]
    fn write_errors_propagate() {
        let mut writer = EventLogWriter::new(FailingSink);

        let error = writer
            .write_event(&request_event("GET", "/docs"))
            .expect_err("sink error should propagate");

        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(error.to_string(), "sink closed");
    }

    #[cfg(unix)]
    #[test]
    fn file_event_log_open_sets_owner_only_permissions() {
        use std::{fs, os::unix::fs::PermissionsExt};

        let path = unique_temp_path("owner-only.jsonl");
        let _writer = FileEventLogWriter::open(&path).expect("event log should open");

        let mode = fs::metadata(&path)
            .expect("event log metadata should read")
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(mode, 0o600);

        fs::remove_file(path).expect("event log should remove");
    }

    #[test]
    fn valid_unterminated_json_is_delimited_before_append_and_stays_valid_after_restart() {
        use std::fs;

        let path = unique_temp_path("valid-unterminated.jsonl");
        let first = serde_json::to_vec(&request_event("GET", "/first"))
            .expect("first event should serialize");
        fs::write(&path, &first).expect("unterminated event should write");

        let mut writer = FileEventLogWriter::open(&path).expect("event log should repair");
        assert_eq!(
            writer.startup_tail_repair(),
            JsonlTailRepairOutcome::AppendedNewline {
                previous_len: first.len() as u64
            }
        );
        writer
            .write_event(&request_event("GET", "/second"))
            .expect("second event should append");
        drop(writer);

        let mut writer = FileEventLogWriter::open(&path).expect("event log should reopen");
        assert_eq!(
            writer.startup_tail_repair(),
            JsonlTailRepairOutcome::NotNeeded
        );
        writer
            .write_event(&request_event("GET", "/third"))
            .expect("third event should append");
        drop(writer);

        let lines = fs::read_to_string(&path)
            .expect("event log should read")
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("line should be valid JSON"))
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0]["kind"]["path"], "/first");
        assert_eq!(lines[1]["kind"]["path"], "/second");
        assert_eq!(lines[2]["kind"]["path"], "/third");

        fs::remove_file(path).expect("event log should remove");
    }

    #[test]
    fn invalid_tail_is_truncated_before_append_and_stays_valid_after_restart() {
        use std::fs;

        let path = unique_temp_path("invalid-tail.jsonl");
        let mut original =
            serde_json::to_vec(&request_event("GET", "/first")).expect("event should serialize");
        original.extend_from_slice(b"\n{\"schema_version\":");
        let repaired_len = original
            .iter()
            .rposition(|byte| *byte == b'\n')
            .expect("fixture should contain a newline")
            + 1;
        fs::write(&path, &original).expect("torn event log should write");

        let mut writer = FileEventLogWriter::open(&path).expect("event log should repair");
        assert_eq!(
            writer.startup_tail_repair(),
            JsonlTailRepairOutcome::Truncated {
                original_len: original.len() as u64,
                repaired_len: repaired_len as u64,
            }
        );
        writer
            .write_event(&request_event("GET", "/second"))
            .expect("second event should append");
        drop(writer);

        let mut writer = FileEventLogWriter::open(&path).expect("event log should reopen");
        assert_eq!(
            writer.startup_tail_repair(),
            JsonlTailRepairOutcome::NotNeeded
        );
        writer
            .write_event(&request_event("GET", "/third"))
            .expect("third event should append");
        drop(writer);

        let lines = fs::read_to_string(&path)
            .expect("event log should read")
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("line should be valid JSON"))
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0]["kind"]["path"], "/first");
        assert_eq!(lines[1]["kind"]["path"], "/second");
        assert_eq!(lines[2]["kind"]["path"], "/third");

        fs::remove_file(path).expect("event log should remove");
    }

    #[test]
    fn corrupt_complete_record_is_rejected_before_append() {
        use std::fs;

        let path = unique_temp_path("mid-file-corruption.jsonl");
        let valid =
            serde_json::to_string(&request_event("GET", "/first")).expect("event should serialize");
        fs::write(&path, format!("{valid}\n{{not json}}\n"))
            .expect("corrupt event log should write");

        let error = FileEventLogWriter::open(&path)
            .err()
            .expect("complete corrupt record must fail startup");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("line 2"));
        fs::remove_file(path).expect("event log should remove");
    }

    #[test]
    fn valid_json_that_is_not_an_event_is_rejected_before_append() {
        use std::fs;

        let path = unique_temp_path("invalid-event-record.jsonl");
        let valid =
            serde_json::to_string(&request_event("GET", "/first")).expect("event should serialize");
        fs::write(&path, format!("{valid}\n{{\"not\":\"an event\"}}\n"))
            .expect("invalid event log should write");

        let error = FileEventLogWriter::open(&path)
            .err()
            .expect("non-event JSON record must fail startup");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("line 2"));
        fs::remove_file(path).expect("event log should remove");
    }

    #[test]
    fn invalid_only_tail_is_truncated_to_empty_before_append() {
        use std::fs;

        let path = unique_temp_path("invalid-only-tail.jsonl");
        let torn = b"{\"schema_version\":";
        fs::write(&path, torn).expect("torn event log should write");

        let mut writer = FileEventLogWriter::open(&path).expect("event log should repair");
        assert_eq!(
            writer.startup_tail_repair(),
            JsonlTailRepairOutcome::Truncated {
                original_len: torn.len() as u64,
                repaired_len: 0,
            }
        );
        writer
            .write_event(&request_event("GET", "/replacement"))
            .expect("replacement event should append");
        drop(writer);

        let rendered = fs::read_to_string(&path).expect("event log should read");
        let lines = rendered.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 1);
        let value: Value = serde_json::from_str(lines[0]).expect("line should be valid JSON");
        assert_eq!(value["kind"]["path"], "/replacement");

        fs::remove_file(path).expect("event log should remove");
    }

    #[test]
    fn exact_limit_log_defers_rotation_until_append_and_keeps_bounded_archives() {
        use std::fs;

        let path = unique_temp_path("oversized.jsonl");
        let mut active = format!(
            "{}\n",
            serde_json::to_string(&request_event("GET", "/oversized"))
                .expect("event should serialize")
        )
        .into_bytes();
        active.resize(super::LOG_ROTATE_BYTES as usize, b'\n');
        fs::write(&path, active).expect("exact-limit log should write");
        for index in 0..2 {
            let archive = format!("{}.{index:039}", path.display());
            let archived_event = format!(
                "{}\n",
                serde_json::to_string(&request_event("GET", &format!("/archive-{index}")))
                    .expect("archive event should serialize")
            );
            fs::write(archive, archived_event).expect("archive should write");
        }

        let mut writer = FileEventLogWriter::open(&path).expect("event log should open");

        let active = fs::metadata(&path)
            .expect("active log metadata should read")
            .len();
        assert_eq!(
            active,
            super::LOG_ROTATE_BYTES,
            "startup must preserve recovery evidence until reconciliation"
        );
        assert_eq!(writer.recovery_index.archive_event_ids.len(), 2);
        writer
            .write_event(&request_event("GET", "/after-startup"))
            .expect("the first append should rotate the full active segment");
        assert_eq!(writer.recovery_index.archive_event_ids.len(), 3);

        let prefix = format!("{}.", path.display());
        let archives: Vec<_> = fs::read_dir(path.parent().expect("temp dir"))
            .expect("temp dir should read")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|candidate| {
                candidate.to_string_lossy().starts_with(&prefix) && candidate != &path
            })
            .collect();
        assert_eq!(
            archives.len(),
            super::LOG_ARCHIVES_KEPT,
            "archive budget must include the newly rotated segment"
        );
        let suffixes = archives
            .iter()
            .map(|archive| {
                super::archive_suffix(&path, archive)
                    .expect("archive suffix")
                    .to_string()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            suffixes.iter().filter(|suffix| suffix.len() == 39).count(),
            super::LOG_ARCHIVES_KEPT,
            "every retained archive must use the canonical suffix"
        );

        drop(writer);
        fs::remove_file(&path).expect("active log should remove");
        for archive in archives {
            fs::remove_file(archive).expect("archive should remove");
        }
    }

    #[test]
    fn oversized_corrupt_log_is_rejected_before_rotation() {
        use std::fs;

        let path = unique_temp_path("oversized-corrupt.jsonl");
        let mut corrupt = vec![b'x'; (super::LOG_ROTATE_BYTES + 1) as usize];
        *corrupt.last_mut().expect("fixture should not be empty") = b'\n';
        fs::write(&path, &corrupt).expect("corrupt log should write");

        let error = FileEventLogWriter::open(&path)
            .err()
            .expect("corrupt oversized log must fail startup");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            fs::metadata(&path)
                .expect("active corrupt log should remain")
                .len(),
            corrupt.len() as u64
        );
        let prefix = format!("{}.", path.display());
        assert!(
            fs::read_dir(path.parent().expect("temp dir"))
                .expect("temp dir should read")
                .filter_map(Result::ok)
                .all(|entry| !entry.path().to_string_lossy().starts_with(&prefix)),
            "corrupt active log must not be archived"
        );
        fs::remove_file(path).expect("corrupt log should remove");
    }

    #[test]
    fn archive_name_skips_an_existing_timestamp() {
        use std::fs;

        let path = unique_temp_path("archive-collision.jsonl");
        let occupied = super::next_archive_path(&path, 42).expect("archive path should resolve");
        fs::write(&occupied, b"occupied").expect("occupied archive should write");

        let candidate =
            super::next_archive_path(&path, 42).expect("next archive path should resolve");

        assert_ne!(candidate, occupied);
        assert!(candidate
            .to_string_lossy()
            .ends_with("000000000000000000000000000000000000043"));

        fs::remove_file(occupied).expect("occupied archive should remove");
    }

    #[test]
    fn archive_name_stays_monotonic_when_the_clock_moves_backward() {
        let family = TestFamily::new("archive-clock-regression.jsonl");
        let future = family.archive(1_000);
        std::fs::write(&future, b"").expect("future archive should write");

        let candidate = super::next_archive_path(&family.path, 42)
            .expect("clock regression should advance beyond retained archives");

        assert_eq!(candidate, family.archive(1_001));
    }

    #[test]
    fn exhausted_archive_namespace_fails_closed() {
        let family = TestFamily::new("archive-namespace-exhausted.jsonl");
        let exhausted = format!("{}.{}", family.path.display(), "9".repeat(39));
        std::fs::write(exhausted, b"").expect("maximum archive suffix should write");

        let error = super::next_archive_path(&family.path, 42)
            .expect_err("exhausted archive suffix must fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("namespace is exhausted"));
    }

    #[test]
    fn immediate_rotations_use_distinct_archive_names() {
        use std::fs;

        let path = unique_temp_path("distinct-archives.jsonl");
        fs::write(&path, b"first\n").expect("first active log should write");
        let first = super::rotate_log_now(&path).expect("first rotation should succeed");
        fs::write(&path, b"second\n").expect("second active log should write");
        let second = super::rotate_log_now(&path).expect("second rotation should succeed");

        assert_ne!(first, second);
        assert!(first.exists());
        assert!(second.exists());

        fs::remove_file(first).expect("first archive should remove");
        fs::remove_file(second).expect("second archive should remove");
    }

    #[test]
    fn write_beyond_budget_rotates_mid_run_and_keeps_appending() {
        use std::fs;

        let path = unique_temp_path("mid-run-rotate.jsonl");
        let mut writer = FileEventLogWriter::open(&path).expect("event log should open");
        writer.current_len = super::LOG_ROTATE_BYTES;

        writer
            .write_event(&request_event("GET", "/docs"))
            .expect("event should write and rotate");
        writer
            .write_event(&request_event("GET", "/openapi.json"))
            .expect("event should append after rotation");

        let active_content = fs::read_to_string(&path).expect("active log should read");
        assert!(active_content.contains("/docs"));
        assert!(active_content.contains("/openapi.json"));

        let prefix = format!("{}.", path.display());
        let archives: Vec<_> = fs::read_dir(path.parent().expect("temp dir"))
            .expect("temp dir should read")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|candidate| {
                candidate.to_string_lossy().starts_with(&prefix) && candidate != &path
            })
            .collect();
        assert_eq!(archives.len(), 1, "one rotated archive must exist");

        fs::remove_file(&path).expect("active log should remove");
        fs::remove_file(&archives[0]).expect("archive should remove");
    }

    #[test]
    fn durable_response_lookup_includes_rotated_archives() {
        use std::fs;

        let path = unique_temp_path("durable-response-archive.jsonl");
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let response = Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::ControlledReality,
            EventKind::ResponseServed {
                status: 202,
                routing_decision: RoutingDecision::ControlledReality,
                controlled_reality: None,
            },
        )
        .with_request_id(request_id);
        let mut writer = FileEventLogWriter::open(&path).expect("event log should open");
        writer
            .write_event(&response)
            .expect("response should write");
        writer.current_len = super::LOG_ROTATE_BYTES;
        writer
            .write_event(&request_event("GET", "/after-rotation"))
            .expect("next event should rotate the response");

        assert_eq!(
            writer
                .durable_response(session_id, request_id)
                .expect("durable response lookup should succeed"),
            DurableResponseMatch::Unique {
                event_id: response.id,
                policy_state: PolicyState::ControlledReality,
                status: 202,
                routing_decision: RoutingDecision::ControlledReality,
                controlled_reality: None
            }
        );

        let archives = super::event_log_family_paths(&path)
            .expect("event log family should list")
            .into_iter()
            .filter(|candidate| candidate != &path)
            .collect::<Vec<_>>();
        fs::remove_file(&path).expect("active log should remove");
        for archive in archives {
            fs::remove_file(archive).expect("archive should remove");
        }
    }

    #[test]
    fn duplicate_durable_responses_are_rejected() {
        use std::fs;

        let path = unique_temp_path("duplicate-durable-response.jsonl");
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let response = Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::ControlledReality,
            EventKind::ResponseServed {
                status: 202,
                routing_decision: RoutingDecision::ControlledReality,
                controlled_reality: None,
            },
        )
        .with_request_id(request_id);
        let mut writer = FileEventLogWriter::open(&path).expect("event log should open");
        writer
            .write_event(&response)
            .expect("first response should write");
        let error = writer
            .write_event(&response)
            .expect_err("duplicate response id must fail at write time");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(matches!(
            writer
                .durable_response(session_id, request_id)
                .expect("first response should remain indexed"),
            DurableResponseMatch::Unique { .. }
        ));
        drop(writer);
        fs::remove_file(path).expect("event log should remove");
    }

    #[test]
    fn duplicate_durable_policy_event_ids_are_rejected() {
        use std::fs;

        let path = unique_temp_path("duplicate-durable-policy-event.jsonl");
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let policy_event = Event::new(
            session_id,
            EventSource::PolicyRouter,
            PolicyState::Blocked,
            EventKind::PolicyChanged {
                from: PolicyState::ControlledReality,
                to: PolicyState::Blocked,
                reason: "test block".to_string(),
            },
        )
        .with_request_id(request_id);
        let mut writer = FileEventLogWriter::open(&path).expect("event log should open");
        writer
            .write_event(&policy_event)
            .expect("first policy event should write");
        let error = writer
            .write_event(&policy_event)
            .expect_err("duplicate policy event id must fail at write time");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            writer
                .durable_event_by_id(session_id, request_id, policy_event.id)
                .expect("first policy event should remain indexed"),
            Some(policy_event)
        );
        drop(writer);
        fs::remove_file(path).expect("event log should remove");
    }

    #[test]
    fn durable_response_and_policy_event_rotate_as_one_fsynced_batch() {
        use std::fs;

        let path = unique_temp_path("durable-batch-rotation.jsonl");
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let response = Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::Blocked,
            EventKind::ResponseServed {
                status: 403,
                routing_decision: RoutingDecision::EidolonOwned,
                controlled_reality: None,
            },
        )
        .with_request_id(request_id);
        let policy_event = Event::new(
            session_id,
            EventSource::PolicyRouter,
            PolicyState::Blocked,
            EventKind::PolicyChanged {
                from: PolicyState::ControlledReality,
                to: PolicyState::Blocked,
                reason: "test block".to_string(),
            },
        )
        .with_request_id(request_id);
        let response_len = serde_json::to_vec(&response)
            .expect("response should serialize")
            .len() as u64
            + 1;
        let mut writer = FileEventLogWriter::open(&path).expect("event log should open");
        writer
            .write_event(&request_event("GET", "/before-batch"))
            .expect("seed event should write");
        writer.current_len = super::LOG_ROTATE_BYTES - response_len;

        writer
            .write_durable_response_transaction(&response, Some(&policy_event))
            .expect("durable pair should rotate and fsync together");

        let active = fs::read_to_string(&path).expect("active log should read");
        assert!(active.contains(&response.id.to_string()));
        assert!(active.contains(&policy_event.id.to_string()));
        let archives = super::event_log_family_paths(&path)
            .expect("event log family should list")
            .into_iter()
            .filter(|candidate| candidate != &path)
            .collect::<Vec<_>>();
        assert_eq!(archives.len(), 1);
        let archive = fs::read_to_string(&archives[0]).expect("archive should read");
        assert!(!archive.contains(&response.id.to_string()));
        assert!(!archive.contains(&policy_event.id.to_string()));

        writer.resolve_durable_response(session_id, request_id);
        drop(writer);
        fs::remove_file(path).expect("active log should remove");
        for archive in archives {
            fs::remove_file(archive).expect("archive should remove");
        }
    }

    #[test]
    fn rotation_syncs_the_old_segment_before_renaming_and_syncs_directory_changes() {
        use std::{cell::RefCell, fs};

        let path = unique_temp_path("durable-rotation-order.jsonl");
        fs::write(&path, b"old segment\n").expect("seed segment should write");
        let stages = RefCell::new(Vec::new());

        let archive = super::rotate_log_now_with_sync(
            &path,
            |source| {
                assert!(source.exists(), "file sync must happen before rename");
                stages.borrow_mut().push("file");
                Ok(())
            },
            |source| {
                assert!(
                    !source.exists(),
                    "directory sync must happen after the rename"
                );
                stages.borrow_mut().push("directory");
                Ok(())
            },
        )
        .expect("rotation should succeed");

        assert_eq!(stages.into_inner(), vec!["file", "directory", "directory"]);
        assert_eq!(
            fs::read(&archive).expect("archive should read"),
            b"old segment\n"
        );
        fs::remove_file(archive).expect("archive should remove");
    }

    #[test]
    fn creating_a_new_active_segment_syncs_its_parent_directory() {
        use std::{cell::Cell, fs};

        let path = unique_temp_path("durable-active-create.jsonl");
        let sync_calls = Cell::new(0);
        let sink = super::open_event_log_sink_with_parent_sync(&path, |created| {
            assert!(
                created.exists(),
                "active file must exist before its directory is synced"
            );
            sync_calls.set(sync_calls.get() + 1);
            Ok(())
        })
        .expect("active segment should open");

        assert_eq!(sync_calls.get(), 1);
        drop(sink);
        fs::remove_file(path).expect("active segment should remove");
    }

    #[test]
    fn unresolved_durable_response_blocks_event_churn_until_resolved() {
        use std::fs;

        let path = unique_temp_path("pinned-durable-response.jsonl");
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let response = Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::ControlledReality,
            EventKind::ResponseServed {
                status: 202,
                routing_decision: RoutingDecision::ControlledReality,
                controlled_reality: None,
            },
        )
        .with_request_id(request_id);
        let mut writer = FileEventLogWriter::open(&path).expect("event log should open");
        writer
            .write_durable_response(&response)
            .expect("durable response should write and pin");
        writer.current_len = super::LOG_ROTATE_BYTES;

        let error = writer
            .write_event(&request_event("GET", "/must-not-rotate"))
            .expect_err("unresolved durable response must block event churn");

        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(writer.unresolved_durable_response_count(), 1);
        assert_eq!(
            super::event_log_family_paths(&path)
                .expect("event log family should list")
                .len(),
            1
        );
        writer.resolve_durable_response(session_id, request_id);
        writer
            .write_event(&request_event("GET", "/after-resolution"))
            .expect("event writes should resume after resolution");
        drop(writer);
        for segment in super::event_log_family_paths(&path).expect("event log family should list") {
            fs::remove_file(segment).expect("event log segment should remove");
        }
    }

    #[test]
    fn production_event_log_limits_and_runtime_event_headroom_are_explicit() {
        assert_eq!(super::LOG_ROTATE_BYTES, 33_554_432);
        assert_eq!(super::LOG_ARCHIVES_KEPT, 3);
        assert_eq!(super::MAX_EVENT_LOG_FAMILY_BYTES, 134_217_728);
        assert_eq!(super::MAX_EVENT_LOG_RECORD_BYTES, 1_048_576);

        let ingress_limit = crate::http_request::MAX_HTTP_HEADER_BYTES;
        let candidates = [
            request_event("GET", &"x".repeat(ingress_limit)),
            Event::new(
                SessionId::new(),
                EventSource::PolicyRouter,
                PolicyState::Blocked,
                EventKind::RealityEscapeAttempt {
                    method: "M".repeat(32),
                    path: "x".repeat(ingress_limit),
                    routing_decision: RoutingDecision::EidolonOwned,
                    reason: "production:controlled_reality_branch_escape".to_string(),
                },
            ),
        ];
        let widest = candidates
            .iter()
            .map(|event| {
                super::serialize_event_bounded(event)
                    .expect("widest bounded runtime event should serialize")
                    .len()
            })
            .max()
            .expect("candidate set should not be empty");
        assert!(
            super::MAX_EVENT_LOG_RECORD_BYTES - widest > 900_000,
            "widest bounded runtime fixture used {widest} bytes"
        );
    }

    #[test]
    fn family_inventory_accepts_absent_empty_archive_only_and_full_ordered_family() {
        let family = TestFamily::new("inventory-supported-shapes.jsonl");
        let absent = super::scan_event_log_family(&family.path, &[], |_| Ok(()))
            .expect("absent family should validate");
        assert_eq!(absent.stats, super::EventLogRecoveryStats::default());

        std::fs::write(&family.path, b"").expect("empty active should write");
        let empty = super::scan_event_log_family(&family.path, &[], |_| Ok(()))
            .expect("empty active should validate");
        assert_eq!(empty.stats.segment_count, 1);
        assert_eq!(empty.stats.active_bytes, 0);
        std::fs::remove_file(&family.path).expect("empty active should remove");

        let archive_one = request_event("GET", "/archive-1");
        let archive_two = request_event("GET", "/archive-2");
        let archive_three = request_event("GET", "/archive-3");
        for (stamp, event) in [(3, &archive_three), (1, &archive_one), (2, &archive_two)] {
            write_events(&family.archive(stamp), &[event]);
        }
        let mut observed = Vec::new();
        let archive_only = super::scan_event_log_family(&family.path, &[], |event| {
            let EventKind::RequestSeen { path, .. } = &event.kind else {
                panic!("fixture should contain request events")
            };
            observed.push(path.clone());
            Ok(())
        })
        .expect("archive-only crash window should validate");
        assert_eq!(archive_only.stats.archive_count, 3);
        assert_eq!(archive_only.stats.segment_count, 3);
        assert_eq!(archive_only.stats.record_count, 3);
        assert_eq!(observed, ["/archive-1", "/archive-2", "/archive-3"]);

        let active = request_event("GET", "/active");
        write_events(&family.path, &[&active]);
        observed.clear();
        let full = super::scan_event_log_family(&family.path, &[], |event| {
            let EventKind::RequestSeen { path, .. } = &event.kind else {
                panic!("fixture should contain request events")
            };
            observed.push(path.clone());
            Ok(())
        })
        .expect("active plus three archives should validate");
        assert_eq!(full.stats.archive_count, 3);
        assert_eq!(full.stats.segment_count, 4);
        assert_eq!(full.stats.record_count, 4);
        assert_eq!(
            observed,
            ["/archive-1", "/archive-2", "/archive-3", "/active"]
        );
    }

    #[test]
    fn family_inventory_rejects_fourth_and_noncanonical_numeric_archives() {
        let too_many = TestFamily::new("inventory-four-archives.jsonl");
        for stamp in 1..=4 {
            std::fs::write(too_many.archive(stamp), b"").expect("archive should write");
        }
        let error = super::scan_event_log_family(&too_many.path, &[], |_| Ok(()))
            .err()
            .expect("fourth archive must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("archive count"));

        let noncanonical = TestFamily::new("inventory-noncanonical.jsonl");
        let short_numeric = format!("{}.1", noncanonical.path.display());
        std::fs::write(&short_numeric, b"").expect("short numeric neighbor should write");
        let error = super::scan_event_log_family(&noncanonical.path, &[], |_| Ok(()))
            .err()
            .expect("all-digit noncanonical suffix must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("noncanonical"));
    }

    #[test]
    fn family_inventory_ignores_unrelated_nonnumeric_neighbors() {
        let family = TestFamily::new("inventory-neighbors.jsonl");
        let event = request_event("GET", "/active");
        write_events(&family.path, &[&event]);
        for suffix in [
            "backup",
            "123x",
            "",
            "00000000000000000000000000000000000000x",
        ] {
            let neighbor = format!("{}.{}", family.path.display(), suffix);
            std::fs::write(neighbor, b"not an event").expect("neighbor should write");
        }

        let scan = super::scan_event_log_family(&family.path, &[], |_| Ok(()))
            .expect("nonnumeric neighbors should be ignored");
        assert_eq!(scan.stats.archive_count, 0);
        assert_eq!(scan.stats.segment_count, 1);
        assert_eq!(scan.stats.record_count, 1);
    }

    #[cfg(unix)]
    #[test]
    fn family_inventory_rejects_symlinks_and_nonregular_members() {
        let symlink_family = TestFamily::new("inventory-symlink.jsonl");
        let target = unique_temp_path("inventory-symlink-target.jsonl");
        std::fs::write(&target, b"").expect("symlink target should write");
        std::os::unix::fs::symlink(&target, &symlink_family.path)
            .expect("active symlink should create");
        let error = super::scan_event_log_family(&symlink_family.path, &[], |_| Ok(()))
            .err()
            .expect("active symlink must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("not a regular file"));
        std::fs::remove_file(target).expect("symlink target should remove");

        let directory_family = TestFamily::new("inventory-directory.jsonl");
        std::fs::create_dir(directory_family.archive(1)).expect("archive directory should create");
        let error = super::scan_event_log_family(&directory_family.path, &[], |_| Ok(()))
            .err()
            .expect("archive directory must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("not a regular file"));
    }

    #[test]
    fn streaming_scanner_handles_short_reads_and_propagates_io_failures() {
        let event = request_event("GET", "/short-reads");
        let bytes = event_jsonl(&[&event]);
        let segment = super::EventLogSegment {
            path: unique_temp_path("synthetic-reader.jsonl"),
            kind: super::EventLogSegmentKind::Active,
            advertised_len: bytes.len() as u64,
        };
        let selection = super::RecoverySelection::targets(&[]).expect("empty selection");
        let mut index = super::EventLogRecoveryIndex::default();
        let mut observed = 0;
        let scan = super::scan_event_log_reader(
            ShortReader {
                inner: Cursor::new(bytes.clone()),
                maximum_read: 3,
            },
            &segment,
            &selection,
            &mut index,
            &mut |_| {
                observed += 1;
                Ok(())
            },
        )
        .expect("short reads should be reassembled");
        assert_eq!(scan.bytes, bytes.len() as u64);
        assert_eq!(scan.records, 1);
        assert_eq!(observed, 1);

        let mut index = super::EventLogRecoveryIndex::default();
        let error = super::scan_event_log_reader(
            FailingReader,
            &segment,
            &selection,
            &mut index,
            &mut |_| Ok(()),
        )
        .err()
        .expect("ordinary read errors must propagate");
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(error.to_string(), "synthetic event-log read failure");

        let oversized_metadata = super::EventLogSegment {
            advertised_len: super::LOG_ROTATE_BYTES + 1,
            ..segment
        };
        let mut index = super::EventLogRecoveryIndex::default();
        let error = super::scan_event_log_reader(
            FailsIfRead,
            &oversized_metadata,
            &selection,
            &mut index,
            &mut |_| Ok(()),
        )
        .err()
        .expect("oversized metadata must reject before reading");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn authoritative_segment_read_rejects_limit_plus_one_despite_small_metadata() {
        let segment = super::EventLogSegment {
            path: unique_temp_path("synthetic-growth.jsonl"),
            kind: super::EventLogSegmentKind::Active,
            advertised_len: 0,
        };
        let selection = super::RecoverySelection::targets(&[]).expect("empty selection");
        let mut index = super::EventLogRecoveryIndex::default();
        let error = super::scan_event_log_reader(
            RepeatingByteReader {
                remaining: super::LOG_ROTATE_BYTES + 1,
                byte: b'\n',
            },
            &segment,
            &selection,
            &mut index,
            &mut |_| Ok(()),
        )
        .err()
        .expect("limit-plus-one authoritative read must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("segment"));
    }

    #[test]
    fn exact_segment_limit_is_accepted_and_limit_plus_one_is_rejected() {
        let exact = TestFamily::new("segment-exact.jsonl");
        let mut file = std::io::BufWriter::new(
            std::fs::File::create(&exact.path).expect("exact segment should create"),
        );
        let block = vec![b'\n'; super::EVENT_LOG_READ_CHUNK_BYTES];
        for _ in 0..super::LOG_ROTATE_BYTES / block.len() as u64 {
            file.write_all(&block).expect("blank block should write");
        }
        file.flush().expect("exact segment should flush");
        drop(file);
        let scan = super::scan_event_log_family(&exact.path, &[], |_| Ok(()))
            .expect("exact segment limit should validate");
        assert_eq!(scan.stats.family_bytes, super::LOG_ROTATE_BYTES);
        assert_eq!(scan.stats.active_bytes, super::LOG_ROTATE_BYTES);

        let over = TestFamily::new("segment-over.jsonl");
        let file = std::fs::File::create(&over.path).expect("over-limit segment should create");
        file.set_len(super::LOG_ROTATE_BYTES + 1)
            .expect("over-limit segment should size");
        let error = super::scan_event_log_family(&over.path, &[], |_| Ok(()))
            .err()
            .expect("segment limit plus one must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("segment"));
    }

    #[test]
    fn exact_record_limit_is_accepted_and_limit_plus_one_is_rejected() {
        let exact = TestFamily::new("record-exact.jsonl");
        let exact_event = event_with_serialized_len(super::MAX_EVENT_LOG_RECORD_BYTES);
        write_events(&exact.path, &[&exact_event]);
        let scan = super::scan_event_log_family(&exact.path, &[], |_| Ok(()))
            .expect("exact record limit should validate");
        assert_eq!(scan.stats.record_count, 1);

        let over = TestFamily::new("record-over.jsonl");
        let over_event = event_with_serialized_len(super::MAX_EVENT_LOG_RECORD_BYTES + 1);
        write_events(&over.path, &[&over_event]);
        let error = super::scan_event_log_family(&over.path, &[], |_| Ok(()))
            .err()
            .expect("record limit plus one must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("record"));

        let written = TestFamily::new("record-exact-writer.jsonl");
        let mut writer = FileEventLogWriter::open(&written.path).expect("writer should open");
        writer
            .write_event(&exact_event)
            .expect("writer should accept an exact-limit record");
        assert_eq!(
            std::fs::metadata(&written.path)
                .expect("written segment should have metadata")
                .len(),
            super::MAX_EVENT_LOG_RECORD_BYTES as u64 + 1
        );
    }

    #[test]
    fn invalid_utf8_blank_lines_and_active_tail_rules_are_strict() {
        let complete_invalid = TestFamily::new("utf8-complete.jsonl");
        std::fs::write(&complete_invalid.path, [0xff, b'\n'])
            .expect("invalid complete record should write");
        let error = super::scan_event_log_family(&complete_invalid.path, &[], |_| Ok(()))
            .err()
            .expect("invalid UTF-8 complete record must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("line 1 column"));

        let torn = TestFamily::new("utf8-torn-active.jsonl");
        std::fs::write(&torn.path, [0xff]).expect("invalid active tail should write");
        let scan = super::scan_event_log_family(&torn.path, &[], |_| Ok(()))
            .expect("invalid final active fragment should produce a repair plan");
        assert_eq!(
            scan.active_tail_repair,
            JsonlTailRepairOutcome::Truncated {
                original_len: 1,
                repaired_len: 0,
            }
        );
        let writer = FileEventLogWriter::open_with_recovery(&torn.path, scan)
            .expect("authoritative active-tail repair should apply");
        assert_eq!(
            writer.startup_tail_repair(),
            JsonlTailRepairOutcome::Truncated {
                original_len: 1,
                repaired_len: 0,
            }
        );
        assert_eq!(
            std::fs::metadata(&torn.path)
                .expect("repaired active should exist")
                .len(),
            0
        );
        drop(writer);

        let blanks = TestFamily::new("blank-lines.jsonl");
        let event = request_event("GET", "/after-blanks");
        let mut bytes = b"\n \t\r\n".to_vec();
        bytes.extend(event_jsonl(&[&event]));
        bytes.extend_from_slice(b"\n\t \n");
        std::fs::write(&blanks.path, bytes).expect("blank-line fixture should write");
        let scan = super::scan_event_log_family(&blanks.path, &[], |_| Ok(()))
            .expect("blank lines should be ignored");
        assert_eq!(scan.stats.record_count, 1);
        assert_eq!(scan.active_tail_repair, JsonlTailRepairOutcome::NotNeeded);
    }

    #[test]
    fn archives_reject_unterminated_records_and_invalid_tails() {
        let valid_unterminated = TestFamily::new("archive-valid-unterminated.jsonl");
        let event = request_event("GET", "/archive-tail");
        std::fs::write(
            valid_unterminated.archive(1),
            serde_json::to_vec(&event).expect("event should serialize"),
        )
        .expect("unterminated archive should write");
        let error = super::scan_event_log_family(&valid_unterminated.path, &[], |_| Ok(()))
            .err()
            .expect("unterminated valid archive record must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("unterminated"));

        let invalid_unterminated = TestFamily::new("archive-invalid-unterminated.jsonl");
        std::fs::write(invalid_unterminated.archive(1), [0xff])
            .expect("invalid archive tail should write");
        let error = super::scan_event_log_family(&invalid_unterminated.path, &[], |_| Ok(()))
            .err()
            .expect("invalid archive tail must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("line 1 column"));
    }

    #[test]
    fn unsupported_schema_and_duplicate_ids_across_segments_are_rejected() {
        let unsupported = TestFamily::new("unsupported-schema.jsonl");
        let mut event = request_event("GET", "/old-schema");
        event.schema_version = eidolon_core::EVENT_SCHEMA_VERSION - 1;
        write_events(&unsupported.path, &[&event]);
        let error = super::scan_event_log_family(&unsupported.path, &[], |_| Ok(()))
            .err()
            .expect("unsupported schema must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("unsupported schema"));

        let duplicate = TestFamily::new("duplicate-cross-segment.jsonl");
        let event = request_event("GET", "/duplicate");
        write_events(&duplicate.archive(1), &[&event]);
        write_events(&duplicate.path, &[&event]);
        let error = super::scan_event_log_family(&duplicate.path, &[], |_| Ok(()))
            .err()
            .expect("duplicate family event id must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("duplicate event id"));
        assert!(
            !error.to_string().contains(&event.id.to_string()),
            "diagnostic must not disclose a durable identifier"
        );
    }

    #[test]
    fn one_scan_builds_selected_response_and_policy_indexes_across_archives() {
        let family = TestFamily::new("selected-recovery-index.jsonl");
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let response = response_event(session_id, request_id, 202);
        let policy = policy_event(session_id, request_id);
        write_events(&family.archive(1), &[&response]);
        write_events(&family.path, &[&policy]);
        let targets = [super::EventLogRecoveryTarget {
            session_id,
            request_id,
            expected_policy_event_id: Some(policy.id),
        }];
        let mut callback_count = 0;
        let scan = super::scan_event_log_family(&family.path, &targets, |_| {
            callback_count += 1;
            Ok(())
        })
        .expect("selected recovery scan should succeed");
        assert_eq!(callback_count, 2, "each record must be visited once");
        assert_eq!(scan.stats.record_count, 2);
        assert_eq!(scan.stats.indexed_durable_response_count, 1);
        assert_eq!(scan.stats.indexed_policy_event_count, 1);

        let mut writer = FileEventLogWriter::open_with_recovery(&family.path, scan)
            .expect("writer should consume the scanned index");
        assert_eq!(
            writer
                .durable_response(session_id, request_id)
                .expect("response lookup should use the index"),
            DurableResponseMatch::Unique {
                event_id: response.id,
                policy_state: PolicyState::ControlledReality,
                status: 202,
                routing_decision: RoutingDecision::ControlledReality,
                controlled_reality: None,
            }
        );
        assert_eq!(
            writer
                .durable_event_by_id(session_id, request_id, policy.id)
                .expect("policy lookup should use the index"),
            Some(policy.clone())
        );
        let wrong_session = writer
            .durable_event_by_id(SessionId::new(), request_id, policy.id)
            .expect_err("policy lookup must reject a wrong session alone");
        assert_eq!(wrong_session.kind(), io::ErrorKind::InvalidData);
        let wrong_request = writer
            .durable_event_by_id(session_id, RequestId::new(), policy.id)
            .expect_err("policy lookup must reject a wrong request alone");
        assert_eq!(wrong_request.kind(), io::ErrorKind::InvalidData);
        writer.resolve_durable_response(session_id, request_id);
    }

    #[test]
    fn conflicting_selected_recovery_matches_fail_independent_of_creation_order() {
        let family = TestFamily::new("conflicting-recovery-index.jsonl");
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let later = response_event(session_id, request_id, 203);
        let earlier = response_event(session_id, request_id, 202);
        write_events(&family.archive(2), &[&later]);
        write_events(&family.archive(1), &[&earlier]);
        let targets = [super::EventLogRecoveryTarget {
            session_id,
            request_id,
            expected_policy_event_id: None,
        }];
        let error = super::scan_event_log_family(&family.path, &targets, |_| Ok(()))
            .err()
            .expect("conflicting durable responses must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("multiple durable response"));
        assert!(!error.to_string().contains(&earlier.id.to_string()));
        assert!(!error.to_string().contains(&later.id.to_string()));

        let mismatched = TestFamily::new("mismatched-policy-index.jsonl");
        let policy = policy_event(SessionId::new(), RequestId::new());
        write_events(&mismatched.path, &[&policy]);
        let targets = [super::EventLogRecoveryTarget {
            session_id,
            request_id,
            expected_policy_event_id: Some(policy.id),
        }];
        let error = super::scan_event_log_family(&mismatched.path, &targets, |_| Ok(()))
            .err()
            .expect("policy event for the wrong workflow must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("wrong workflow"));
        assert!(!error.to_string().contains(&policy.id.to_string()));
    }

    #[test]
    fn recovery_target_count_is_bounded_at_policy_session_capacity() {
        let family = TestFamily::new("recovery-target-bound.jsonl");
        let mut targets = (0..crate::policy_store::MAX_POLICY_SESSIONS)
            .map(|_| super::EventLogRecoveryTarget {
                session_id: SessionId::new(),
                request_id: RequestId::new(),
                expected_policy_event_id: None,
            })
            .collect::<Vec<_>>();
        let scan = super::scan_event_log_family(&family.path, &targets, |_| Ok(()))
            .expect("exact pending-session capacity should validate");
        assert_eq!(scan.stats, super::EventLogRecoveryStats::default());

        targets.push(super::EventLogRecoveryTarget {
            session_id: SessionId::new(),
            request_id: RequestId::new(),
            expected_policy_event_id: None,
        });
        let error = super::scan_event_log_family(&family.path, &targets, |_| Ok(()))
            .err()
            .expect("pending-session capacity plus one must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("target count"));

        let duplicate = [targets[0], targets[0]];
        let error = super::scan_event_log_family(&family.path, &duplicate, |_| Ok(()))
            .err()
            .expect("duplicate workflow targets must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("duplicate workflow target"));
    }

    #[test]
    fn archive_only_index_survives_the_post_rename_missing_active_window() {
        let family = TestFamily::new("archive-only-index.jsonl");
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let response = response_event(session_id, request_id, 202);
        write_events(&family.archive(1), &[&response]);
        let targets = [super::EventLogRecoveryTarget {
            session_id,
            request_id,
            expected_policy_event_id: None,
        }];
        let scan = super::scan_event_log_family(&family.path, &targets, |_| Ok(()))
            .expect("archive-only family should scan");
        assert_eq!(scan.stats.archive_count, 1);
        assert_eq!(scan.stats.segment_count, 1);

        let mut writer = FileEventLogWriter::open_with_recovery(&family.path, scan)
            .expect("writer should create the missing active only after validation");
        assert!(family.path.is_file());
        assert_eq!(
            writer
                .durable_response(session_id, request_id)
                .expect("archived response should remain indexed"),
            DurableResponseMatch::Unique {
                event_id: response.id,
                policy_state: PolicyState::ControlledReality,
                status: 202,
                routing_decision: RoutingDecision::ControlledReality,
                controlled_reality: None,
            }
        );
        writer.resolve_durable_response(session_id, request_id);
    }

    #[test]
    fn full_active_defers_rotation_until_selected_oldest_archive_evidence_is_resolved() {
        let family = TestFamily::new("full-active-selected-oldest-evidence.jsonl");
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let response = response_event(session_id, request_id, 202);
        write_events(&family.archive(1), &[&response]);
        write_events(&family.archive(2), &[&request_event("GET", "/archive-two")]);
        write_events(
            &family.archive(3),
            &[&request_event("GET", "/archive-three")],
        );
        std::fs::write(&family.path, vec![b'\n'; super::LOG_ROTATE_BYTES as usize])
            .expect("exact-limit active should write");
        let targets = [super::EventLogRecoveryTarget {
            session_id,
            request_id,
            expected_policy_event_id: None,
        }];
        let scan = super::scan_event_log_family(&family.path, &targets, |_| Ok(()))
            .expect("full family should scan");
        let mut writer = FileEventLogWriter::open_with_recovery(&family.path, scan)
            .expect("opening must not rotate selected recovery evidence away");
        assert_eq!(writer.recovery_index.archive_event_ids.len(), 3);
        assert_eq!(
            std::fs::metadata(&family.path)
                .expect("active metadata should read")
                .len(),
            super::LOG_ROTATE_BYTES
        );
        assert!(matches!(
            writer
                .durable_response(session_id, request_id)
                .expect("oldest archived response should remain indexed"),
            DurableResponseMatch::Unique { event_id, .. } if event_id == response.id
        ));

        let noncanonical_neighbor = family.path.with_file_name(format!(
            "{}.7",
            family.path.file_name().unwrap().to_string_lossy()
        ));
        std::fs::write(&noncanonical_neighbor, b"unrelated")
            .expect("runtime noncanonical neighbor should write");
        let blocked = writer
            .write_recovered_policy_event(&policy_event(session_id, request_id))
            .expect_err("rotation must not prune unresolved recovery evidence");
        assert_eq!(blocked.kind(), io::ErrorKind::WouldBlock);
        assert!(!writer.unavailable_after_io_failure);
        assert_eq!(writer.recovery_index.archive_event_ids.len(), 3);

        writer.resolve_durable_response(session_id, request_id);
        writer
            .write_event(&request_event("GET", "/after-recovery"))
            .expect("rotation should proceed after durable recovery resolves");
        assert_eq!(writer.recovery_index.archive_event_ids.len(), 3);
        assert!(noncanonical_neighbor.is_file());
        let canonical_archives = super::event_log_family_paths(&family.path)
            .expect("canonical family should enumerate")
            .into_iter()
            .filter(|path| path != &family.path)
            .collect::<Vec<_>>();
        assert_eq!(canonical_archives.len(), super::LOG_ARCHIVES_KEPT);
        assert!(canonical_archives
            .iter()
            .all(|path| super::archive_suffix(&family.path, path).is_some()));
    }

    #[test]
    fn authoritative_scan_detects_active_path_changes_before_repair_or_creation() {
        let changed = TestFamily::new("active-changed-after-scan.jsonl");
        std::fs::write(&changed.path, b"").expect("empty active should write");
        let scan = super::scan_event_log_family(&changed.path, &[], |_| Ok(()))
            .expect("empty active should scan");
        std::fs::write(&changed.path, b"\n").expect("active should change after scan");
        let error = FileEventLogWriter::open_with_recovery(&changed.path, scan)
            .err()
            .expect("changed active must fail before mutation");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("changed"));
        assert_eq!(
            std::fs::read(&changed.path).expect("active should read"),
            b"\n"
        );

        let appeared = TestFamily::new("active-appeared-after-scan.jsonl");
        let scan = super::scan_event_log_family(&appeared.path, &[], |_| Ok(()))
            .expect("missing active should scan");
        std::fs::write(&appeared.path, b"").expect("active should appear after scan");
        let error = FileEventLogWriter::open_with_recovery(&appeared.path, scan)
            .err()
            .expect("appeared active must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("membership changed"));

        let same_length = TestFamily::new("active-same-length-change.jsonl");
        let original_event = request_event("GET", "/before");
        let mut replacement_event = original_event.clone();
        replacement_event.id = uuid::Uuid::new_v4();
        let EventKind::RequestSeen { path, .. } = &mut replacement_event.kind else {
            unreachable!("request fixture should remain a request event")
        };
        *path = "/after-".to_string();
        let original = format!(
            "{}\n",
            serde_json::to_string(&original_event).expect("original event should serialize")
        )
        .into_bytes();
        let replacement = format!(
            "{}\n",
            serde_json::to_string(&replacement_event).expect("replacement event should serialize")
        )
        .into_bytes();
        assert_eq!(original.len(), replacement.len());
        std::fs::write(&same_length.path, &original).expect("original active should write");
        let scan = super::scan_event_log_family(&same_length.path, &[], |_| Ok(()))
            .expect("original active should scan");
        std::fs::write(&same_length.path, &replacement)
            .expect("same-length replacement should write");
        let error = FileEventLogWriter::open_with_recovery(&same_length.path, scan)
            .err()
            .expect("same-length active replacement must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("contents changed"));
        assert_eq!(
            std::fs::read(&same_length.path).expect("replacement active should read"),
            replacement
        );

        let archive_changed = TestFamily::new("archive-same-length-change.jsonl");
        let archive = archive_changed.archive(1);
        std::fs::write(&archive, &original).expect("original archive should write");
        let scan = super::scan_event_log_family(&archive_changed.path, &[], |_| Ok(()))
            .expect("original archive should scan");
        std::fs::write(&archive, &replacement).expect("replacement archive should write");
        let error = FileEventLogWriter::open_with_recovery(&archive_changed.path, scan)
            .err()
            .expect("same-length archive replacement must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("contents changed"));
        assert!(
            !archive_changed.path.exists(),
            "rejected archive replacement must not create the active segment"
        );

        std::fs::remove_file(&appeared.path).expect("appeared active should remove");
        let corrected = super::scan_event_log_family(&appeared.path, &[], |_| Ok(()))
            .expect("corrected path should rescan");
        let writer = FileEventLogWriter::open_with_recovery(&appeared.path, corrected)
            .expect("same path should open after correction");
        assert!(appeared.path.is_file());
        drop(writer);
    }

    #[test]
    fn oversized_serialization_has_no_writer_or_rotation_side_effects() {
        let family = TestFamily::new("oversized-write-no-effects.jsonl");
        let mut writer = FileEventLogWriter::open(&family.path).expect("writer should open");
        let mut event = event_with_serialized_len(super::MAX_EVENT_LOG_RECORD_BYTES + 1);
        let event_id = event.id;
        let error = writer
            .write_event(&event)
            .expect_err("oversized event must fail before append or rotation");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(writer.current_len, 0);
        assert!(!writer.recovery_index.event_ids.contains(&event_id));
        assert_eq!(
            std::fs::metadata(&family.path)
                .expect("active should remain")
                .len(),
            0
        );
        assert_eq!(
            super::event_log_family_paths(&family.path)
                .expect("family should enumerate")
                .len(),
            1
        );

        let EventKind::RequestSeen { path, .. } = &mut event.kind else {
            unreachable!("sized event should remain a request")
        };
        *path = "/corrected".to_string();
        writer
            .write_event(&event)
            .expect("rejected event id must remain available after correction");
        assert!(writer.recovery_index.event_ids.contains(&event_id));
        assert!(writer.current_len > 0);
    }

    #[test]
    fn selected_live_index_ignores_ordinary_events_and_releases_resolved_workflows() {
        let family = TestFamily::new("selected-live-index-scope.jsonl");
        let scan = super::scan_event_log_family(&family.path, &[], |_| Ok(()))
            .expect("empty selected family should scan");
        let mut writer = FileEventLogWriter::open_with_recovery(&family.path, scan)
            .expect("selected writer should open");

        for _ in 0..=crate::policy_store::MAX_POLICY_SESSIONS {
            let response = response_event(SessionId::new(), RequestId::new(), 200);
            writer
                .write_event(&response)
                .expect("ordinary response should append without entering recovery index");
        }
        assert!(writer.recovery_index.durable_responses.is_empty());
        assert!(writer.recovery_index.durable_events.is_empty());

        for _ in 0..4 {
            let session_id = SessionId::new();
            let request_id = RequestId::new();
            let response = response_event(session_id, request_id, 202);
            let policy = policy_event(session_id, request_id);
            writer
                .write_durable_response_transaction(&response, Some(&policy))
                .expect("durable workflow should append and pin");
            assert_eq!(writer.recovery_index.durable_responses.len(), 1);
            assert_eq!(writer.recovery_index.durable_events.len(), 1);
            writer.resolve_durable_response(session_id, request_id);
            assert!(writer.recovery_index.durable_responses.is_empty());
            assert!(writer.recovery_index.durable_events.is_empty());
        }
    }

    #[test]
    fn durable_transaction_pre_io_rejections_leave_recovery_state_unchanged() {
        let family = TestFamily::new("durable-pre-io-rejection.jsonl");
        let scan = super::scan_event_log_family(&family.path, &[], |_| Ok(()))
            .expect("empty selected family should scan");
        let mut writer = FileEventLogWriter::open_with_recovery(&family.path, scan)
            .expect("selected writer should open");
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let response = response_event(session_id, request_id, 202);
        let mut oversized_policy = policy_event(session_id, request_id);
        let EventKind::PolicyChanged { reason, .. } = &mut oversized_policy.kind else {
            unreachable!("policy fixture should be policy_changed")
        };
        *reason = "x".repeat(super::MAX_EVENT_LOG_RECORD_BYTES);

        let error = writer
            .write_durable_response_transaction(&response, Some(&oversized_policy))
            .expect_err("oversized durable policy event must be rejected before I/O");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(writer.current_len, 0);
        assert_eq!(writer.unresolved_durable_response_count(), 0);
        assert!(writer.recovery_index.event_ids.is_empty());
        assert!(writer.recovery_index.durable_responses.is_empty());
        assert!(writer.recovery_index.durable_events.is_empty());
        assert!(!writer.unavailable_after_io_failure);

        let mut unsupported = response.clone();
        unsupported.schema_version = eidolon_core::EVENT_SCHEMA_VERSION - 1;
        let error = writer
            .write_durable_response(&unsupported)
            .expect_err("unsupported durable response schema must be rejected before I/O");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(writer.current_len, 0);
        assert_eq!(writer.unresolved_durable_response_count(), 0);
        assert!(!writer.unavailable_after_io_failure);

        let seed = request_event("GET", "/seed-duplicate-id");
        writer.write_event(&seed).expect("seed event should append");
        let stable_len = writer.current_len;
        let mut duplicate = response.clone();
        duplicate.id = seed.id;
        let error = writer
            .write_durable_response(&duplicate)
            .expect_err("duplicate durable response id must be rejected before I/O");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(writer.current_len, stable_len);
        assert_eq!(writer.unresolved_durable_response_count(), 0);
        assert!(writer.recovery_index.durable_responses.is_empty());
        assert!(writer.recovery_index.durable_events.is_empty());
        assert!(!writer.unavailable_after_io_failure);

        writer
            .write_durable_response(&response)
            .expect("corrected durable response should remain appendable");
        assert_eq!(writer.unresolved_durable_response_count(), 1);
        writer.resolve_durable_response(session_id, request_id);
    }

    #[test]
    fn partial_write_and_flush_failures_poison_the_writer_before_future_appends() {
        let first = request_event("GET", "/first");
        let second = request_event("GET", "/second");
        let mut partial = EventLogWriter::new(PartialThenFail {
            bytes: Vec::new(),
            remaining_before_failure: 16,
        });

        let error = partial
            .write_event(&first)
            .expect_err("partial write must propagate");
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(partial.unavailable_after_io_failure);
        assert_eq!(partial.current_len, 0);
        assert!(partial.recovery_index.event_ids.is_empty());
        let partial_bytes = partial.sink.bytes.clone();
        let retry = partial
            .write_event(&second)
            .expect_err("poisoned writer must reject future appends");
        assert_eq!(retry.kind(), io::ErrorKind::Other);
        assert_eq!(partial.sink.bytes, partial_bytes);

        let mut flush = EventLogWriter::new(FlushFailingSink { bytes: Vec::new() });
        let error = flush
            .write_event(&first)
            .expect_err("flush failure must propagate");
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(flush.unavailable_after_io_failure);
        assert_eq!(flush.current_len, 0);
        assert!(flush.recovery_index.event_ids.is_empty());
        let flushed_bytes = flush.sink.bytes.clone();
        let retry = flush
            .write_event(&second)
            .expect_err("flush-failed writer must reject future appends");
        assert_eq!(retry.kind(), io::ErrorKind::Other);
        assert_eq!(flush.sink.bytes, flushed_bytes);
    }

    struct PartialThenFail {
        bytes: Vec<u8>,
        remaining_before_failure: usize,
    }

    impl Write for PartialThenFail {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if self.remaining_before_failure == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "synthetic partial write failure",
                ));
            }
            let written = buffer.len().min(self.remaining_before_failure);
            self.bytes.extend_from_slice(&buffer[..written]);
            self.remaining_before_failure -= written;
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FlushFailingSink {
        bytes: Vec<u8>,
    }

    impl Write for FlushFailingSink {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "synthetic flush failure",
            ))
        }
    }

    struct FailingSink;

    impl Write for FailingSink {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "sink closed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
