//! Shared proxy runtime state and per-session evidence stores.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    io::{self, BufRead, BufReader},
    net::{TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use eidolon_bait::BaitRegistry;
use eidolon_core::{
    BaitHeaderValueMintStatus, BaitId, Event, EventKind, ExposureId, SessionId,
    EVENT_SCHEMA_VERSION,
};
use serde_json::Value;

use crate::{
    controlled_reality::{ControlledRealityConfig, ControlledRealityResponder},
    debug_log::FileDebugLogWriter,
    event_log::FileEventLogWriter,
    http::{invalid_data, UpstreamTarget},
    ingress_identity::IngressIdentityResolver,
    policy_store::PolicyStateStore,
    session_auth::SessionAuthority,
    surface::SurfaceController,
    surface_content::BaitContentOverrides,
};

pub const CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(30);
pub const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const UPSTREAM_IO_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_CONCURRENT_CONNECTIONS: usize = 64;
pub const MAX_BAIT_EXPOSURES: usize = 4096;

pub fn configure_stream_timeouts(
    stream: &TcpStream,
    read_timeout: Duration,
    write_timeout: Duration,
) -> io::Result<()> {
    stream.set_read_timeout(Some(read_timeout))?;
    stream.set_write_timeout(Some(write_timeout))?;
    Ok(())
}

pub fn configure_client_stream(stream: &TcpStream) -> io::Result<()> {
    configure_stream_timeouts(stream, CLIENT_IO_TIMEOUT, CLIENT_IO_TIMEOUT)
}

pub fn configure_upstream_stream(stream: &TcpStream) -> io::Result<()> {
    configure_stream_timeouts(stream, UPSTREAM_IO_TIMEOUT, UPSTREAM_IO_TIMEOUT)
}

pub fn connect_upstream(upstream: &UpstreamTarget) -> io::Result<TcpStream> {
    let mut last_error = None;

    for addr in upstream.connect_addr.to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, UPSTREAM_CONNECT_TIMEOUT) {
            Ok(stream) => {
                configure_upstream_stream(&stream)?;
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| {
        invalid_data(format!(
            "upstream target `{}` resolved to no socket addresses",
            upstream.connect_addr
        ))
    }))
}

#[derive(Clone)]
pub struct ConnectionLimiter {
    active: Arc<AtomicUsize>,
    pub limit: usize,
}

impl ConnectionLimiter {
    pub fn new(limit: usize) -> Self {
        assert!(limit > 0, "connection limit must be positive");

        Self {
            active: Arc::new(AtomicUsize::new(0)),
            limit,
        }
    }

    pub fn try_acquire(&self) -> Option<ConnectionPermit> {
        let mut active = self.active.load(Ordering::Acquire);
        loop {
            if active >= self.limit {
                return None;
            }

            match self.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(ConnectionPermit {
                        active: Arc::clone(&self.active),
                    });
                }
                Err(current) => active = current,
            }
        }
    }

    #[doc(hidden)]
    pub fn active_for_test(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }
}

pub struct ConnectionPermit {
    pub active: Arc<AtomicUsize>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let previous = self.active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "connection permit underflow");
    }
}

#[derive(Clone)]
pub struct ProxyRuntime {
    pub upstream: UpstreamTarget,
    pub event_log: Arc<Mutex<FileEventLogWriter>>,
    pub debug_log: Option<Arc<Mutex<FileDebugLogWriter>>>,
    pub intervention_control_path: PathBuf,
    pub policy_store: Arc<Mutex<PolicyStateStore>>,
    pub session_authority: Arc<Mutex<SessionAuthority>>,
    pub controlled_reality_config: ControlledRealityConfig,
    pub controlled_reality: Arc<ControlledRealityResponder>,
    pub surface_controller: Arc<dyn SurfaceController + Send + Sync>,
    pub ingress_identity_resolver: Arc<IngressIdentityResolver>,
    pub ingress_transport_auth_secret: Option<Arc<str>>,
    pub bait_signing_secret: Option<Arc<str>>,
    pub trusted_bait_soften_path_prefixes: Vec<String>,
    pub bait_registry: Arc<BaitRegistry>,
    pub bait_content: BaitContentOverrides,
    pub bait_exposures: Arc<Mutex<BaitExposureStore>>,
    pub bait_action_replays: Arc<Mutex<BaitActionReplayStore>>,
}

#[derive(Debug, Default)]
pub struct BaitExposureStore {
    pub exposures: HashMap<(SessionId, BaitId), ExposureId>,
    pub exposure_order: VecDeque<(SessionId, BaitId)>,
}

#[derive(Debug, Default)]
pub struct BaitActionReplayStore {
    pub consumed: HashSet<(SessionId, BaitId)>,
    pub consumed_order: VecDeque<(SessionId, BaitId)>,
}

impl BaitExposureStore {
    pub fn from_event_log(path: &Path) -> io::Result<Self> {
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(error),
        };

        Self::from_event_log_reader(BufReader::new(file))
    }

    pub fn from_event_log_reader(reader: impl BufRead) -> io::Result<Self> {
        let mut store = Self::default();

        for (line_index, line) in reader.lines().enumerate() {
            let line_number = line_index + 1;
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            let value: Value = serde_json::from_str(&line).map_err(|error| {
                invalid_data(format!(
                    "could not rebuild bait exposure store from event log line {line_number}: {error}"
                ))
            })?;
            let schema_version = value
                .get("schema_version")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    invalid_data(format!(
                        "could not rebuild bait exposure store from event log line {line_number}: missing schema_version"
                    ))
                })?;
            if schema_version != u64::from(EVENT_SCHEMA_VERSION) {
                return Err(invalid_data(format!(
                    "could not rebuild bait exposure store from event log line {line_number}: unsupported schema_version {schema_version}; expected {EVENT_SCHEMA_VERSION}"
                )));
            }

            let event: Event = serde_json::from_value(value).map_err(|error| {
                invalid_data(format!(
                    "could not rebuild bait exposure store from event log line {line_number}: {error}"
                ))
            })?;

            if let EventKind::BaitExposed {
                bait_id,
                exposure_id,
                ..
            } = event.kind
            {
                store.record_exposure(event.session_id, bait_id, exposure_id);
            }
        }

        Ok(store)
    }

    pub fn len(&self) -> usize {
        self.exposures.len()
    }

    pub fn is_empty(&self) -> bool {
        self.exposures.is_empty()
    }

    pub fn record_exposure(
        &mut self,
        session_id: SessionId,
        bait_id: BaitId,
        exposure_id: ExposureId,
    ) {
        let key = (session_id, bait_id);
        if self.exposures.insert(key.clone(), exposure_id).is_some() {
            self.exposure_order.retain(|existing| existing != &key);
        }
        self.exposure_order.push_back(key);

        while self.exposures.len() > MAX_BAIT_EXPOSURES {
            if let Some(oldest) = self.exposure_order.pop_front() {
                self.exposures.remove(&oldest);
            }
        }
    }

    pub fn exposure_for_action(
        &self,
        session_id: SessionId,
        bait_id: &BaitId,
    ) -> Option<ExposureId> {
        self.exposures.get(&(session_id, bait_id.clone())).cloned()
    }
}

impl BaitActionReplayStore {
    pub fn from_event_log(path: &Path) -> io::Result<Self> {
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(error),
        };

        Self::from_event_log_reader(BufReader::new(file))
    }

    pub fn from_event_log_reader(reader: impl BufRead) -> io::Result<Self> {
        let mut store = Self::default();

        for (line_index, line) in reader.lines().enumerate() {
            let line_number = line_index + 1;
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            let value: Value = serde_json::from_str(&line).map_err(|error| {
                invalid_data(format!(
                    "could not rebuild bait replay store from event log line {line_number}: {error}"
                ))
            })?;
            let schema_version = value
                .get("schema_version")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    invalid_data(format!(
                        "could not rebuild bait replay store from event log line {line_number}: missing schema_version"
                    ))
                })?;
            if schema_version != u64::from(EVENT_SCHEMA_VERSION) {
                return Err(invalid_data(format!(
                    "could not rebuild bait replay store from event log line {line_number}: unsupported schema_version {schema_version}; expected {EVENT_SCHEMA_VERSION}"
                )));
            }

            let event: Event = serde_json::from_value(value).map_err(|error| {
                invalid_data(format!(
                    "could not rebuild bait replay store from event log line {line_number}: {error}"
                ))
            })?;

            if let EventKind::BaitActionObserved {
                bait_id,
                header_value_mint,
                header_value_mint_status,
                ..
            } = event.kind
            {
                if header_value_mint.is_some()
                    && matches!(
                        header_value_mint_status,
                        Some(BaitHeaderValueMintStatus::MatchedSessionValue)
                            | Some(BaitHeaderValueMintStatus::ReplaySeen)
                    )
                {
                    store.record_consumed(event.session_id, bait_id);
                }
            }
        }

        Ok(store)
    }

    pub fn record_consumed(&mut self, session_id: SessionId, bait_id: BaitId) {
        let key = (session_id, bait_id);
        if self.consumed.insert(key.clone()) {
            self.consumed_order.push_back(key);
        }

        while self.consumed.len() > MAX_BAIT_EXPOSURES {
            if let Some(oldest) = self.consumed_order.pop_front() {
                self.consumed.remove(&oldest);
            }
        }
    }

    pub fn mark_and_check_replay(&mut self, session_id: SessionId, bait_id: BaitId) -> bool {
        let already_consumed = self.consumed.contains(&(session_id, bait_id.clone()));
        self.record_consumed(session_id, bait_id);
        already_consumed
    }
}
