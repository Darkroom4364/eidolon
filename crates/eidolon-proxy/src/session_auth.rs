//! Integrity-protected session identity for the Shield runtime.
//!
//! This module implements the session side of GitHub issue `#207`:
//!
//! - session cookies carry an HMAC-SHA256 proof over an explicit format
//!   version, key version, issue time, and session UUID, so clients can no
//!   longer choose or forge authoritative session IDs;
//! - invalid, tampered, stale, or unknown cookies are classified into
//!   deterministic [`CookieOutcome`] audit outcomes instead of being silently
//!   ignored or adopted;
//! - cookie discard/rotation is absorbed by a bounded continuity map keyed by
//!   an HMAC-minimized trusted-ingress identity, or by a hashed direct peer in
//!   explicit Lab mode, and carries an enforcement floor;
//!   authenticated-ingress recoveries preserve the stable session through the
//!   cooldown, while explicit Lab peer recoveries mint distinct sessions so
//!   shared peers are not merged;
//! - key rotation is explicit: cookies signed by retired key versions still
//!   verify and are transparently re-minted under the active version.
//!
//! Continuity is capacity- and TTL-bounded. Authenticated-ingress mappings can
//! be persisted as HMAC-minimized sidecar records; raw identities and Lab peer
//! keys are never written. It remains an enforcement safety net, not a general
//! identity primitive.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use eidolon_core::{PolicyState, SessionId};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::session::{SESSION_COOKIE_ATTRIBUTES, SESSION_COOKIE_NAME};
use crate::session_continuity_store::{
    self, IntegrityKey, StateCommitOutcome, StoredContinuityRecord, StoredContinuityState,
};

type SessionMac = Hmac<Sha256>;

/// Cookie payload format tag. Bump when the payload layout changes.
pub const COOKIE_FORMAT_TAG: &str = "v1";

/// Default server-side cookie lifetime: 7 days.
pub const DEFAULT_COOKIE_LIFETIME_SECS: u64 = 7 * 24 * 60 * 60;

/// Default continuity record lifetime: 24 hours without a fresh request.
pub const DEFAULT_CONTINUITY_TTL_SECS: u64 = 24 * 60 * 60;

/// Minimum gap between continuity recoveries for one peer.
///
/// The first cookie-less or invalid-cookie request inside the gap re-binds to
/// the continuity identity's existing session. Further authenticated-ingress
/// requests preserve that stable session so cookie loss or forgery cannot
/// split its evidence identity. Further explicit Lab peer requests mint fresh
/// sessions that still inherit the peer's enforcement floor, so unrelated
/// clients sharing one peer are not merged.
pub const CONTINUITY_RECOVERY_COOLDOWN_SECS: u64 = 60;

/// Default bound on tracked continuity identities.
pub const DEFAULT_CONTINUITY_CAPACITY: usize = 4096;

/// Maximum delay before last-seen-only continuity changes are checkpointed.
pub const CONTINUITY_CHECKPOINT_INTERVAL_SECS: u64 = 60;

/// Rolling window used to bound synchronous durable mapping creation.
pub const DURABLE_CONTINUITY_INSERT_WINDOW_SECS: u64 = 60;

/// Maximum new authenticated mappings durably admitted per rolling window.
pub const MAX_DURABLE_CONTINUITY_INSERTS_PER_WINDOW: usize = 64;

/// Tolerance for cookies whose issue time is slightly ahead of the proxy clock.
pub const MAX_FUTURE_SKEW_SECS: u64 = 300;

const MAC_HEX_CHARS: usize = 64;
const SESSION_KEY_BYTES: usize = 32;
const CONTINUITY_HASH_DOMAIN_INGRESS: &[u8] = b"eidolon-continuity:trusted-ingress:v1\0";
const CONTINUITY_HASH_DOMAIN_LAB_PEER: &[u8] = b"eidolon-continuity:lab-peer:v1\0";
const CONTINUITY_STATE_KEY_ID_DOMAIN: &[u8] = b"eidolon-continuity:transport-key-id:v1\0";

/// Authenticated source used to derive a minimized continuity key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContinuitySource {
    /// Opaque identity asserted by the authenticated trusted-ingress transport.
    AuthenticatedIngress,
    /// Direct TCP peer identity used only by explicit Lab callers.
    LabPeer,
}

impl ContinuitySource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticatedIngress => "authenticated_ingress",
            Self::LabPeer => "lab_peer",
        }
    }
}

/// Domain-separated minimized key used for bounded continuity storage.
///
/// Trusted-ingress identities use HMAC-SHA256 under the continuity key.
/// Raw ingress identities and peer addresses never enter the continuity map.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContinuityKey {
    source: ContinuitySource,
    digest: [u8; 32],
}

impl ContinuityKey {
    pub(crate) fn authenticated_ingress(raw: &str, continuity_key: &str) -> Self {
        let mut mac = <SessionMac as Mac>::new_from_slice(continuity_key.as_bytes())
            .expect("HMAC-SHA256 accepts any continuity key length");
        mac.update(CONTINUITY_HASH_DOMAIN_INGRESS);
        mac.update(raw.as_bytes());
        Self {
            source: ContinuitySource::AuthenticatedIngress,
            digest: mac.finalize().into_bytes().into(),
        }
    }

    pub(crate) fn lab_peer(peer_ip: IpAddr) -> Self {
        Self::derive(
            ContinuitySource::LabPeer,
            CONTINUITY_HASH_DOMAIN_LAB_PEER,
            peer_ip.to_string().as_bytes(),
        )
    }

    pub fn source(self) -> ContinuitySource {
        self.source
    }

    fn authenticated_from_digest(digest: [u8; 32]) -> Self {
        Self {
            source: ContinuitySource::AuthenticatedIngress,
            digest,
        }
    }

    fn digest(self) -> [u8; 32] {
        self.digest
    }

    fn derive(source: ContinuitySource, domain: &[u8], value: &[u8]) -> Self {
        let mut digest = Sha256::new();
        digest.update(domain);
        digest.update(value);
        Self {
            source,
            digest: digest.finalize().into(),
        }
    }
}

impl fmt::Debug for ContinuityKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContinuityKey")
            .field("source", &self.source)
            .field("digest", &"<redacted>")
            .finish()
    }
}

/// Deterministic audit outcome for the presented session cookie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieOutcome {
    /// No session cookie was present on the request.
    Absent,
    /// The cookie carried a valid proof and an acceptable age.
    Valid,
    /// The cookie value could not be parsed into the expected shape.
    Malformed,
    /// The cookie named a key version the proxy does not hold.
    UnknownKeyVersion,
    /// The cookie proof did not verify under the named key version.
    BadSignature,
    /// The cookie was validly signed but older than the configured lifetime.
    Expired,
}

impl CookieOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Valid => "valid",
            Self::Malformed => "malformed",
            Self::UnknownKeyVersion => "unknown_key_version",
            Self::BadSignature => "bad_signature",
            Self::Expired => "expired",
        }
    }
}

/// Relationship between the key version that signed a valid cookie and the
/// currently active signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    /// The cookie was signed with the active key version.
    Active,
    /// The cookie was signed with a retired (previous) key version and is
    /// re-minted under the active version on the response.
    Previous,
}

impl KeyStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Previous => "previous",
        }
    }
}

/// Outcome of bounded continuity recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinuityOutcome {
    /// A valid cookie made continuity recovery unnecessary.
    NotApplicable,
    /// No fresh continuity record existed for the continuity identity.
    NoRecord,
    /// A valid cookie named a different session than the continuity record.
    /// The stable continuity session won and a replacement cookie was issued.
    ContinuitySessionPreserved,
    /// A valid cookie's session was already bound to another continuity key.
    /// A distinct session was minted for the new continuity identity.
    CookieSessionAlreadyBound,
    /// The identity was re-bound to its existing session after the cookie was
    /// missing, invalid, tampered, stale, or unknown.
    Recovered,
    /// An authenticated-ingress recovery was attempted inside the cooldown
    /// window. The stable continuity session was preserved and re-issued.
    CooldownSessionPreserved,
    /// A recovery already happened inside the cooldown window, so a fresh
    /// Lab session was minted that still inherits the peer's enforcement
    /// floor.
    CooldownLimited,
    /// Capacity was exhausted by protected records. The unknown identity was
    /// assigned a fresh blocked session without inserting a continuity record.
    CapacityFailClosed,
    /// Historical state exists but no continuity sidecar was available to
    /// recover an unauthenticated session binding.
    MigrationQuarantineFailClosed,
    /// A continuity mutation could not be durably committed before routing.
    StorageUnavailable,
    /// New durable mappings exceeded the bounded synchronous-write budget.
    AdmissionRateFailClosed,
}

impl ContinuityOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::NoRecord => "no_record",
            Self::ContinuitySessionPreserved => "continuity_session_preserved",
            Self::CookieSessionAlreadyBound => "cookie_session_already_bound",
            Self::Recovered => "recovered",
            Self::CooldownSessionPreserved => "cooldown_session_preserved",
            Self::CooldownLimited => "cooldown_limited",
            Self::CapacityFailClosed => "capacity_fail_closed",
            Self::MigrationQuarantineFailClosed => "migration_quarantine_fail_closed",
            Self::StorageUnavailable => "storage_unavailable",
            Self::AdmissionRateFailClosed => "admission_rate_fail_closed",
        }
    }

    pub fn is_fail_closed(self) -> bool {
        matches!(
            self,
            Self::CapacityFailClosed
                | Self::MigrationQuarantineFailClosed
                | Self::StorageUnavailable
                | Self::AdmissionRateFailClosed
        )
    }
}

/// Result of resolving one request's session identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionResolution {
    pub session_id: SessionId,
    pub cookie_outcome: CookieOutcome,
    /// Signing-key relationship for valid cookies; `None` otherwise.
    pub key_status: Option<KeyStatus>,
    /// Key version named by the cookie when it could be parsed.
    pub presented_key_version: Option<u32>,
    /// Key version the proxy currently mints with.
    pub active_key_version: u32,
    pub continuity_outcome: ContinuityOutcome,
    /// Authenticated source used for continuity, without exposing its value.
    pub continuity_source: Option<ContinuitySource>,
    /// Minimum enforcement state carried over continuity. Applied by the
    /// caller against freshly loaded policy state so rotation cannot reset
    /// enforcement.
    pub enforcement_floor: Option<PolicyState>,
    /// Full `Set-Cookie` header value to attach to the response, if any.
    pub set_cookie_value: Option<String>,
}

impl SessionResolution {
    /// Whether the session came from a valid authenticated cookie.
    pub fn from_cookie(&self) -> bool {
        matches!(self.cookie_outcome, CookieOutcome::Valid)
            && matches!(self.continuity_outcome, ContinuityOutcome::NotApplicable)
    }
}

/// One versioned HMAC signing key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionKeyVersion {
    pub version: u32,
    pub key: [u8; SESSION_KEY_BYTES],
}

impl fmt::Debug for SessionKeyVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionKeyVersion")
            .field("version", &self.version)
            .field("key", &"<redacted>")
            .finish()
    }
}

/// JSON key-file shape for `--session-signing-key-file`:
///
/// ```json
/// {
///   "active_key_version": 2,
///   "keys": [
///     {"version": 1, "key_hex": "<64 lowercase hex chars>"},
///     {"version": 2, "key_hex": "<64 lowercase hex chars>"}
///   ]
/// }
/// ```
///
/// All listed versions verify cookies; only `active_key_version` mints.
/// Rotate by adding the new version, marking it active, and removing retired
/// versions once their cookies have aged out of the cookie lifetime.
#[derive(Deserialize)]
pub struct SessionKeyFile {
    pub active_key_version: u32,
    pub keys: Vec<SessionKeyFileEntry>,
}

impl fmt::Debug for SessionKeyFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionKeyFile")
            .field("active_key_version", &self.active_key_version)
            .field("keys", &self.keys)
            .finish()
    }
}

#[derive(Deserialize)]
pub struct SessionKeyFileEntry {
    pub version: u32,
    pub key_hex: String,
}

impl fmt::Debug for SessionKeyFileEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionKeyFileEntry")
            .field("version", &self.version)
            .field("key_hex", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContinuityRecord {
    session_id: SessionId,
    floor: Option<PolicyState>,
    last_seen: u64,
    last_recovery_at: Option<u64>,
    recovery_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContinuityInsertOutcome {
    Inserted,
    CapacityFailClosed,
    AdmissionRateFailClosed,
}

/// Issues, verifies, and recovers session identities.
#[derive(Clone)]
pub struct SessionAuthority {
    keys: Vec<SessionKeyVersion>,
    active_key_version: u32,
    cookie_lifetime_secs: u64,
    continuity_ttl_secs: u64,
    continuity_capacity: usize,
    continuity: HashMap<ContinuityKey, ContinuityRecord>,
    continuity_order: VecDeque<ContinuityKey>,
    continuity_state_path: Option<PathBuf>,
    continuity_state_key_id_hex: Option<String>,
    continuity_integrity_key: Option<IntegrityKey>,
    continuity_migration_quarantine_until: Option<u64>,
    continuity_last_checkpoint_at: u64,
    continuity_dirty: bool,
    continuity_checkpoint_dirty: bool,
    continuity_security_revision: u64,
    continuity_metadata_revision: u64,
    durable_continuity_insert_times: VecDeque<u64>,
}

impl fmt::Debug for SessionAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionAuthority")
            .field("active_key_version", &self.active_key_version)
            .field("keys", &self.keys)
            .field("cookie_lifetime_secs", &self.cookie_lifetime_secs)
            .field("continuity_ttl_secs", &self.continuity_ttl_secs)
            .field("continuity_capacity", &self.continuity_capacity)
            .field("continuity_records", &self.continuity.len())
            .field("continuity_state_path", &self.continuity_state_path)
            .field(
                "continuity_state_key_id_hex",
                &self
                    .continuity_state_key_id_hex
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field("continuity_integrity_key", &self.continuity_integrity_key)
            .field(
                "continuity_migration_quarantine_until",
                &self.continuity_migration_quarantine_until,
            )
            .field(
                "continuity_security_revision",
                &self.continuity_security_revision,
            )
            .field(
                "continuity_metadata_revision",
                &self.continuity_metadata_revision,
            )
            .field(
                "durable_continuity_insert_times",
                &self.durable_continuity_insert_times.len(),
            )
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableContinuityStartup {
    pub path: PathBuf,
    pub restored_record_count: usize,
    pub ttl_evicted_record_count: usize,
    pub migration_quarantine_until: Option<u64>,
}

impl SessionAuthority {
    /// Build an authority from an explicit key set. `active_key_version` must
    /// be present in `keys`; every listed version verifies cookies.
    pub fn new(keys: Vec<SessionKeyVersion>, active_key_version: u32) -> io::Result<Self> {
        if keys.is_empty() {
            return Err(invalid_data("session signing key set must not be empty"));
        }
        let mut versions: Vec<u32> = keys.iter().map(|key| key.version).collect();
        versions.sort_unstable();
        versions.dedup();
        if versions.len() != keys.len() {
            return Err(invalid_data("session signing key versions must be unique"));
        }
        if !keys.iter().any(|key| key.version == active_key_version) {
            return Err(invalid_data(format!(
                "active session signing key version {active_key_version} is not present in the key set"
            )));
        }

        Ok(Self {
            keys,
            active_key_version,
            cookie_lifetime_secs: DEFAULT_COOKIE_LIFETIME_SECS,
            continuity_ttl_secs: DEFAULT_CONTINUITY_TTL_SECS,
            continuity_capacity: DEFAULT_CONTINUITY_CAPACITY,
            continuity: HashMap::new(),
            continuity_order: VecDeque::new(),
            continuity_state_path: None,
            continuity_state_key_id_hex: None,
            continuity_integrity_key: None,
            continuity_migration_quarantine_until: None,
            continuity_last_checkpoint_at: 0,
            continuity_dirty: false,
            continuity_checkpoint_dirty: false,
            continuity_security_revision: 0,
            continuity_metadata_revision: 0,
            durable_continuity_insert_times: VecDeque::new(),
        })
    }

    /// Parse and validate a JSON key file. See [`SessionKeyFile`] for the
    /// expected shape.
    pub fn from_key_file_json(bytes: &[u8]) -> io::Result<Self> {
        let key_file: SessionKeyFile = serde_json::from_slice(bytes).map_err(|error| {
            invalid_data(format!("could not parse session signing key file: {error}"))
        })?;
        let mut keys = Vec::with_capacity(key_file.keys.len());
        for entry in &key_file.keys {
            keys.push(SessionKeyVersion {
                version: entry.version,
                key: decode_key_hex(&entry.key_hex).ok_or_else(|| {
                    invalid_data(format!(
                        "session signing key version {} must be 64 hex characters",
                        entry.version
                    ))
                })?,
            });
        }

        Self::new(keys, key_file.active_key_version)
    }

    /// Build an authority with a random ephemeral key. Cookies minted under an
    /// ephemeral key stop verifying when the process restarts; deployments
    /// that need restart-stable sessions must configure a key file.
    pub fn ephemeral() -> Self {
        let mut key = [0u8; SESSION_KEY_BYTES];
        key[..16].copy_from_slice(&SessionId::new().0.into_bytes());
        key[16..].copy_from_slice(&SessionId::new().0.into_bytes());
        Self::new(vec![SessionKeyVersion { version: 1, key }], 1)
            .expect("ephemeral single-key authority is always valid")
    }

    pub fn active_key_version(&self) -> u32 {
        self.active_key_version
    }

    pub fn key_version_count(&self) -> usize {
        self.keys.len()
    }

    /// Configure the maximum number of continuity identities retained.
    ///
    /// Capacity must be configured before the authority has observed any
    /// continuity identity so changing the bound cannot silently evict or
    /// reinterpret live enforcement state.
    pub fn set_continuity_capacity(&mut self, capacity: usize) -> io::Result<()> {
        if capacity == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "continuity capacity must be greater than zero",
            ));
        }
        if !self.continuity.is_empty() || !self.continuity_order.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "continuity capacity must be configured before records exist",
            ));
        }
        self.continuity_capacity = capacity;
        Ok(())
    }

    /// Load and enable restart-safe authenticated-ingress continuity.
    ///
    /// A missing sidecar on a deployment with prior state enters a bounded
    /// migration quarantine because raw continuity identities are
    /// intentionally unavailable for reconstruction.
    pub fn enable_durable_continuity(
        &mut self,
        path: &Path,
        continuity_key: &str,
        history_exists: bool,
        now: u64,
    ) -> io::Result<DurableContinuityStartup> {
        if self.continuity_state_path.is_some()
            || !self.continuity.is_empty()
            || !self.continuity_order.is_empty()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "durable continuity must be enabled before continuity records exist",
            ));
        }
        let continuity_key = continuity_key.trim();
        if continuity_key.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "durable continuity requires a non-empty continuity key",
            ));
        }

        let expected_key_id = continuity_state_key_id_hex(continuity_key);
        let integrity_key = IntegrityKey::derive(continuity_key)?;
        let loaded = session_continuity_store::load_state(path, &integrity_key, &expected_key_id)?;
        let mut ttl_evicted_record_count = 0;
        let mut restored_record_count = 0;
        let mut migration_quarantine_until = None;

        if let Some(stored) = loaded {
            let active_quarantine = stored
                .migration_quarantine_until
                .filter(|until| *until > now);
            if stored
                .records
                .iter()
                .any(|record| record.last_seen > now.saturating_add(MAX_FUTURE_SKEW_SECS))
            {
                return Err(invalid_data(
                    "continuity state contains a future-dated last-seen timestamp",
                ));
            }
            if active_quarantine
                .is_some_and(|until| until.saturating_sub(now) > self.continuity_ttl_secs)
            {
                return Err(invalid_data(
                    "continuity migration quarantine exceeds the maximum continuity lifetime",
                ));
            }
            migration_quarantine_until = active_quarantine;

            for record in stored.records {
                if record.last_seen.saturating_add(self.continuity_ttl_secs) <= now {
                    ttl_evicted_record_count += 1;
                    continue;
                }
                if restored_record_count >= self.continuity_capacity {
                    return Err(invalid_data(
                        "active continuity state exceeds configured capacity",
                    ));
                }
                let digest = decode_key_hex(&record.key_digest_hex).ok_or_else(|| {
                    invalid_data(
                        "continuity state key digest must contain exactly 64 hexadecimal characters",
                    )
                })?;
                let key = ContinuityKey::authenticated_from_digest(digest);
                self.continuity.insert(
                    key,
                    ContinuityRecord {
                        session_id: record.session_id,
                        floor: record.enforcement_floor,
                        last_seen: record.last_seen,
                        last_recovery_at: record.last_recovery_at,
                        recovery_count: record.recovery_count,
                    },
                );
                self.continuity_order.push_back(key);
                restored_record_count += 1;
            }
        } else if history_exists {
            migration_quarantine_until = Some(now.saturating_add(self.continuity_ttl_secs));
        }

        self.continuity_state_path = Some(path.to_path_buf());
        self.continuity_state_key_id_hex = Some(expected_key_id);
        self.continuity_integrity_key = Some(integrity_key);
        self.continuity_migration_quarantine_until = migration_quarantine_until;
        self.continuity_last_checkpoint_at = now;
        self.continuity_dirty = true;
        self.continuity_checkpoint_dirty = true;
        self.persist_continuity_state_durably()?;

        Ok(DurableContinuityStartup {
            path: path.to_path_buf(),
            restored_record_count,
            ttl_evicted_record_count,
            migration_quarantine_until,
        })
    }

    /// Reconcile restored continuity floors against the authoritative policy
    /// store, then durably checkpoint the result before serving traffic.
    pub fn reconcile_durable_continuity_floors(
        &mut self,
        mut policy_state_for_session: impl FnMut(SessionId) -> PolicyState,
    ) -> io::Result<usize> {
        let mut changed = 0;
        for (key, record) in &mut self.continuity {
            if key.source() != ContinuitySource::AuthenticatedIngress {
                continue;
            }
            let policy_state = policy_state_for_session(record.session_id);
            if record
                .floor
                .is_none_or(|floor| enforcement_rank(policy_state) > enforcement_rank(floor))
            {
                record.floor = Some(policy_state);
                changed += 1;
            }
        }
        if changed > 0 {
            self.mark_authenticated_security_change();
        }
        self.persist_continuity_state_durably()?;
        Ok(changed)
    }

    pub fn continuity_migration_quarantine_until(&self) -> Option<u64> {
        self.continuity_migration_quarantine_until
    }

    /// Mint the opaque cookie value (without attributes) for a session.
    pub fn mint_cookie_value(&self, session_id: SessionId, iat: u64) -> String {
        let payload = format!(
            "{}.{}.{}.{}",
            COOKIE_FORMAT_TAG, self.active_key_version, iat, session_id.0
        );
        format!(
            "{}.{}",
            payload,
            self.sign_with(self.active_key_version, &payload)
        )
    }

    /// Mint the full `Set-Cookie` header value for a session.
    pub fn mint_set_cookie_value(&self, session_id: SessionId, iat: u64) -> String {
        format!(
            "{}={}; {}",
            SESSION_COOKIE_NAME,
            self.mint_cookie_value(session_id, iat),
            SESSION_COOKIE_ATTRIBUTES
        )
    }

    /// Resolve the session identity for one request.
    ///
    /// This compatibility entry point explicitly uses the direct TCP peer as
    /// a Lab continuity key. Production callers use
    /// [`Self::resolve_with_continuity`].
    pub fn resolve<I, N, V>(
        &mut self,
        headers: I,
        peer_ip: Option<IpAddr>,
        now: u64,
    ) -> SessionResolution
    where
        I: IntoIterator<Item = (N, V)>,
        N: AsRef<str>,
        V: AsRef<str>,
    {
        self.resolve_with_continuity(headers, peer_ip.map(ContinuityKey::lab_peer), now)
    }

    /// Resolve with an already authenticated and minimized continuity key.
    pub fn resolve_with_continuity<I, N, V>(
        &mut self,
        headers: I,
        continuity_key: Option<ContinuityKey>,
        now: u64,
    ) -> SessionResolution
    where
        I: IntoIterator<Item = (N, V)>,
        N: AsRef<str>,
        V: AsRef<str>,
    {
        self.evict_expired_continuity(now);

        let previous_quarantine = self.continuity_migration_quarantine_until;
        let previous_dirty = self.continuity_dirty;
        let previous_checkpoint_dirty = self.continuity_checkpoint_dirty;
        let previous_checkpoint = self.continuity_last_checkpoint_at;
        let previous_security_revision = self.continuity_security_revision;
        let previous_metadata_revision = self.continuity_metadata_revision;
        let previous_record = continuity_key.and_then(|key| self.continuity.get(&key).copied());
        let evicted_candidate = continuity_key
            .filter(|key| !self.continuity.contains_key(key))
            .filter(|_| self.continuity.len() >= self.continuity_capacity)
            .and_then(|key| self.oldest_unprotected_continuity(key.source()));

        if self
            .continuity_migration_quarantine_until
            .is_some_and(|until| until <= now)
        {
            self.continuity_migration_quarantine_until = None;
            self.mark_authenticated_security_change();
        }

        let resolution = self.resolve_with_continuity_in_memory(headers, continuity_key, now);
        if self.continuity_state_path.is_none() {
            return resolution;
        }

        let security_changed = previous_security_revision != self.continuity_security_revision;
        let metadata_changed = previous_metadata_revision != self.continuity_metadata_revision;
        let checkpoint_due = now
            >= self
                .continuity_last_checkpoint_at
                .saturating_add(CONTINUITY_CHECKPOINT_INTERVAL_SECS);
        if !(self.continuity_dirty || self.continuity_checkpoint_dirty && checkpoint_due) {
            return resolution;
        }

        match self.persist_continuity_state() {
            Ok(StateCommitOutcome::Durable) => {
                self.continuity_dirty = false;
                self.continuity_checkpoint_dirty = false;
                self.continuity_last_checkpoint_at = now;
                resolution
            }
            Ok(StateCommitOutcome::CommittedDurabilityUncertain) => {
                self.continuity_dirty = true;
                self.continuity_checkpoint_dirty = true;
                self.storage_unavailable_resolution(resolution)
            }
            Err(error) => {
                if security_changed || metadata_changed {
                    if let Some(key) = continuity_key {
                        match previous_record {
                            Some(record) => {
                                self.continuity.insert(key, record);
                            }
                            None => {
                                self.continuity.remove(&key);
                                self.continuity_order.retain(|candidate| *candidate != key);
                            }
                        }
                    }
                    if let Some((index, key, record)) = evicted_candidate {
                        if let std::collections::hash_map::Entry::Vacant(entry) =
                            self.continuity.entry(key)
                        {
                            entry.insert(record);
                            self.continuity_order
                                .insert(index.min(self.continuity_order.len()), key);
                        }
                    }
                }
                self.continuity_migration_quarantine_until = previous_quarantine;
                self.continuity_dirty = previous_dirty;
                self.continuity_checkpoint_dirty = previous_checkpoint_dirty;
                self.continuity_last_checkpoint_at = previous_checkpoint;
                self.continuity_security_revision = previous_security_revision;
                self.continuity_metadata_revision = previous_metadata_revision;
                eprintln!("eidolon persistence failure: session continuity state: {error}");
                self.storage_unavailable_resolution(resolution)
            }
        }
    }

    fn resolve_with_continuity_in_memory<I, N, V>(
        &mut self,
        headers: I,
        continuity_key: Option<ContinuityKey>,
        now: u64,
    ) -> SessionResolution
    where
        I: IntoIterator<Item = (N, V)>,
        N: AsRef<str>,
        V: AsRef<str>,
    {
        let raw_cookie = session_cookie_value(headers);
        if let Some(continuity_key) = continuity_key.filter(|key| {
            key.source() == ContinuitySource::AuthenticatedIngress
                && !self.continuity.contains_key(key)
                && self
                    .continuity_migration_quarantine_until
                    .is_some_and(|until| until > now)
        }) {
            let (cookie_outcome, presented_key_version) = match raw_cookie.as_deref() {
                Some(raw_cookie) => match self.verify(raw_cookie, now) {
                    Ok(verified) => (CookieOutcome::Valid, Some(verified.key_version)),
                    Err(result) => result,
                },
                None => (CookieOutcome::Absent, None),
            };
            return self.migration_quarantine_fail_closed(
                continuity_key,
                cookie_outcome,
                presented_key_version,
            );
        }
        let Some(raw_cookie) = raw_cookie else {
            return self.recover_or_mint(continuity_key, now, CookieOutcome::Absent, None);
        };

        match self.verify(&raw_cookie, now) {
            Ok(verified) => self.resolve_verified_cookie(verified, continuity_key, now),
            Err((outcome, presented_key_version)) => {
                self.recover_or_mint(continuity_key, now, outcome, presented_key_version)
            }
        }
    }

    fn resolve_verified_cookie(
        &mut self,
        verified: VerifiedCookie,
        continuity_key: Option<ContinuityKey>,
        now: u64,
    ) -> SessionResolution {
        let key_status = if verified.key_version == self.active_key_version {
            KeyStatus::Active
        } else {
            KeyStatus::Previous
        };
        let Some(continuity_key) = continuity_key else {
            return SessionResolution {
                session_id: verified.session_id,
                cookie_outcome: CookieOutcome::Valid,
                key_status: Some(key_status),
                presented_key_version: Some(verified.key_version),
                active_key_version: self.active_key_version,
                continuity_outcome: ContinuityOutcome::NotApplicable,
                continuity_source: None,
                enforcement_floor: None,
                set_cookie_value: match key_status {
                    KeyStatus::Active => None,
                    KeyStatus::Previous => {
                        Some(self.mint_set_cookie_value(verified.session_id, now))
                    }
                },
            };
        };

        if let Some(record) = self.continuity.get(&continuity_key).copied() {
            if continuity_key.source() == ContinuitySource::LabPeer
                && record.session_id != verified.session_id
            {
                let current = self
                    .continuity
                    .get_mut(&continuity_key)
                    .expect("continuity record was read above");
                current.session_id = verified.session_id;
                current.floor = None;
                current.last_seen = now;
                current.last_recovery_at = None;
                current.recovery_count = 0;
                return SessionResolution {
                    session_id: verified.session_id,
                    cookie_outcome: CookieOutcome::Valid,
                    key_status: Some(key_status),
                    presented_key_version: Some(verified.key_version),
                    active_key_version: self.active_key_version,
                    continuity_outcome: ContinuityOutcome::NotApplicable,
                    continuity_source: Some(continuity_key.source()),
                    enforcement_floor: None,
                    set_cookie_value: match key_status {
                        KeyStatus::Active => None,
                        KeyStatus::Previous => {
                            Some(self.mint_set_cookie_value(verified.session_id, now))
                        }
                    },
                };
            }

            if let Some(current) = self.continuity.get_mut(&continuity_key) {
                current.last_seen = now;
                if current.session_id == verified.session_id {
                    current.last_recovery_at = None;
                    current.recovery_count = 0;
                }
                if continuity_key.source() == ContinuitySource::AuthenticatedIngress {
                    self.mark_authenticated_metadata_change();
                }
            }

            if record.session_id != verified.session_id {
                return SessionResolution {
                    session_id: record.session_id,
                    cookie_outcome: CookieOutcome::Valid,
                    key_status: Some(key_status),
                    presented_key_version: Some(verified.key_version),
                    active_key_version: self.active_key_version,
                    continuity_outcome: ContinuityOutcome::ContinuitySessionPreserved,
                    continuity_source: Some(continuity_key.source()),
                    enforcement_floor: record.floor,
                    set_cookie_value: Some(self.mint_set_cookie_value(record.session_id, now)),
                };
            }

            return SessionResolution {
                session_id: verified.session_id,
                cookie_outcome: CookieOutcome::Valid,
                key_status: Some(key_status),
                presented_key_version: Some(verified.key_version),
                active_key_version: self.active_key_version,
                continuity_outcome: ContinuityOutcome::NotApplicable,
                continuity_source: Some(continuity_key.source()),
                enforcement_floor: record.floor,
                set_cookie_value: match key_status {
                    KeyStatus::Active => None,
                    KeyStatus::Previous => {
                        Some(self.mint_set_cookie_value(verified.session_id, now))
                    }
                },
            };
        }

        let session_already_bound = continuity_key.source()
            == ContinuitySource::AuthenticatedIngress
            && self.continuity.iter().any(|(bound_key, record)| {
                bound_key.source() == ContinuitySource::AuthenticatedIngress
                    && *bound_key != continuity_key
                    && record.session_id == verified.session_id
            });
        let (session_id, continuity_outcome) = if session_already_bound {
            (
                SessionId::new(),
                ContinuityOutcome::CookieSessionAlreadyBound,
            )
        } else {
            (verified.session_id, ContinuityOutcome::NotApplicable)
        };

        match self.insert_continuity(continuity_key, session_id, now) {
            ContinuityInsertOutcome::Inserted => {}
            ContinuityInsertOutcome::CapacityFailClosed => {
                return self.capacity_fail_closed(
                    continuity_key,
                    now,
                    CookieOutcome::Valid,
                    Some(key_status),
                    Some(verified.key_version),
                );
            }
            ContinuityInsertOutcome::AdmissionRateFailClosed => {
                return self.admission_rate_fail_closed(
                    continuity_key,
                    CookieOutcome::Valid,
                    Some(key_status),
                    Some(verified.key_version),
                );
            }
        }

        let replace_cookie = session_id != verified.session_id || key_status == KeyStatus::Previous;
        SessionResolution {
            session_id,
            cookie_outcome: CookieOutcome::Valid,
            key_status: Some(key_status),
            presented_key_version: Some(verified.key_version),
            active_key_version: self.active_key_version,
            continuity_outcome,
            continuity_source: Some(continuity_key.source()),
            enforcement_floor: None,
            set_cookie_value: replace_cookie.then(|| self.mint_set_cookie_value(session_id, now)),
        }
    }

    /// Record the Lab peer's current enforcement state so a later cookie rotation
    /// re-inherits at least this state through the enforcement floor.
    ///
    /// The floor is monotonic for the lifetime of the continuity record: it
    /// never decreases while the record is fresh.
    pub fn note_enforcement(
        &mut self,
        peer_ip: Option<IpAddr>,
        session_id: SessionId,
        state: PolicyState,
        now: u64,
    ) {
        self.note_enforcement_with_continuity(
            peer_ip.map(ContinuityKey::lab_peer),
            session_id,
            state,
            now,
        );
    }

    pub fn note_enforcement_with_continuity(
        &mut self,
        continuity_key: Option<ContinuityKey>,
        session_id: SessionId,
        state: PolicyState,
        now: u64,
    ) {
        let Some(continuity_key) = continuity_key else {
            return;
        };
        self.evict_expired_continuity(now);
        if !self.continuity.contains_key(&continuity_key) {
            match self.insert_continuity(continuity_key, session_id, now) {
                ContinuityInsertOutcome::Inserted => {}
                ContinuityInsertOutcome::CapacityFailClosed
                | ContinuityInsertOutcome::AdmissionRateFailClosed => return,
            }
        }
        let record = self
            .continuity
            .get_mut(&continuity_key)
            .expect("existing or newly inserted continuity record must be present");
        if record.session_id != session_id {
            return;
        }
        record.last_seen = now;
        record.floor = Some(match record.floor {
            Some(existing) if enforcement_rank(existing) >= enforcement_rank(state) => existing,
            _ => state,
        });
        if continuity_key.source() == ContinuitySource::AuthenticatedIngress {
            // The policy store is authoritative and restores this floor at
            // startup, so sidecar floor refreshes can use the bounded
            // metadata checkpoint instead of forcing another fsync.
            self.mark_authenticated_metadata_change();
        }
    }

    fn recover_or_mint(
        &mut self,
        continuity_key: Option<ContinuityKey>,
        now: u64,
        cookie_outcome: CookieOutcome,
        presented_key_version: Option<u32>,
    ) -> SessionResolution {
        if let Some(continuity_key) = continuity_key {
            if let Some(record) = self.continuity.get(&continuity_key).copied() {
                if record.last_seen + self.continuity_ttl_secs > now {
                    let recovery_open = match record.last_recovery_at {
                        Some(last_recovery_at) => {
                            now >= last_recovery_at + CONTINUITY_RECOVERY_COOLDOWN_SECS
                        }
                        None => true,
                    };
                    if recovery_open {
                        let recovery_count = record.recovery_count.saturating_add(1);
                        self.continuity.insert(
                            continuity_key,
                            ContinuityRecord {
                                last_seen: now,
                                last_recovery_at: Some(now),
                                recovery_count,
                                ..record
                            },
                        );
                        if continuity_key.source() == ContinuitySource::AuthenticatedIngress {
                            self.mark_authenticated_metadata_change();
                        }
                        return SessionResolution {
                            session_id: record.session_id,
                            cookie_outcome,
                            key_status: None,
                            presented_key_version,
                            active_key_version: self.active_key_version,
                            continuity_outcome: ContinuityOutcome::Recovered,
                            continuity_source: Some(continuity_key.source()),
                            enforcement_floor: record.floor,
                            set_cookie_value: Some(
                                self.mint_set_cookie_value(record.session_id, now),
                            ),
                        };
                    }

                    if continuity_key.source() == ContinuitySource::AuthenticatedIngress {
                        let current = self
                            .continuity
                            .get_mut(&continuity_key)
                            .expect("fresh continuity record was read above");
                        current.last_seen = now;
                        self.mark_authenticated_metadata_change();
                        return SessionResolution {
                            session_id: record.session_id,
                            cookie_outcome,
                            key_status: None,
                            presented_key_version,
                            active_key_version: self.active_key_version,
                            continuity_outcome: ContinuityOutcome::CooldownSessionPreserved,
                            continuity_source: Some(continuity_key.source()),
                            enforcement_floor: record.floor,
                            set_cookie_value: Some(
                                self.mint_set_cookie_value(record.session_id, now),
                            ),
                        };
                    }

                    // A direct Lab peer can represent multiple clients.
                    // Preserve its existing distinct-session behavior while
                    // carrying the monotonic enforcement floor forward.
                    let session_id = SessionId::new();
                    self.continuity.insert(
                        continuity_key,
                        ContinuityRecord {
                            session_id,
                            last_seen: now,
                            ..record
                        },
                    );
                    return SessionResolution {
                        session_id,
                        cookie_outcome,
                        key_status: None,
                        presented_key_version,
                        active_key_version: self.active_key_version,
                        continuity_outcome: ContinuityOutcome::CooldownLimited,
                        continuity_source: Some(continuity_key.source()),
                        enforcement_floor: record.floor,
                        set_cookie_value: Some(self.mint_set_cookie_value(session_id, now)),
                    };
                }
            }
        }

        let session_id = SessionId::new();
        if let Some(continuity_key) = continuity_key {
            match self.insert_continuity(continuity_key, session_id, now) {
                ContinuityInsertOutcome::Inserted => {}
                ContinuityInsertOutcome::CapacityFailClosed => {
                    return self.capacity_fail_closed(
                        continuity_key,
                        now,
                        cookie_outcome,
                        None,
                        presented_key_version,
                    );
                }
                ContinuityInsertOutcome::AdmissionRateFailClosed => {
                    return self.admission_rate_fail_closed(
                        continuity_key,
                        cookie_outcome,
                        None,
                        presented_key_version,
                    );
                }
            }
        }
        SessionResolution {
            session_id,
            cookie_outcome,
            key_status: None,
            presented_key_version,
            active_key_version: self.active_key_version,
            continuity_outcome: ContinuityOutcome::NoRecord,
            continuity_source: continuity_key.map(ContinuityKey::source),
            enforcement_floor: None,
            set_cookie_value: Some(self.mint_set_cookie_value(session_id, now)),
        }
    }

    fn verify(&self, raw: &str, now: u64) -> Result<VerifiedCookie, (CookieOutcome, Option<u32>)> {
        let mut parts = raw.split('.');
        let (Some(tag), Some(version), Some(iat), Some(uuid), Some(mac), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return Err((CookieOutcome::Malformed, None));
        };
        if tag != COOKIE_FORMAT_TAG {
            return Err((CookieOutcome::Malformed, None));
        }
        let key_version: u32 = version
            .parse()
            .map_err(|_| (CookieOutcome::Malformed, None))?;
        let presented_key_version = Some(key_version);
        let iat: u64 = iat
            .parse()
            .map_err(|_| (CookieOutcome::Malformed, presented_key_version))?;
        let session_uuid = uuid::Uuid::parse_str(uuid)
            .map_err(|_| (CookieOutcome::Malformed, presented_key_version))?;
        let mac_bytes =
            decode_mac_hex(mac).ok_or((CookieOutcome::Malformed, presented_key_version))?;

        let Some(key) = self
            .keys
            .iter()
            .find(|key| key.version == key_version)
            .map(|key| key.key)
        else {
            return Err((CookieOutcome::UnknownKeyVersion, presented_key_version));
        };

        let payload = format!("{tag}.{key_version}.{iat}.{session_uuid}");
        let mut mac_verifier =
            <SessionMac as Mac>::new_from_slice(&key).expect("HMAC-SHA256 accepts any key length");
        mac_verifier.update(b"eidolon-session:");
        mac_verifier.update(payload.as_bytes());
        if mac_verifier.verify_slice(&mac_bytes).is_err() {
            return Err((CookieOutcome::BadSignature, presented_key_version));
        }

        if iat > now + MAX_FUTURE_SKEW_SECS {
            return Err((CookieOutcome::Malformed, presented_key_version));
        }
        if now > iat + self.cookie_lifetime_secs {
            return Err((CookieOutcome::Expired, presented_key_version));
        }

        Ok(VerifiedCookie {
            session_id: SessionId(session_uuid),
            key_version,
        })
    }

    fn sign_with(&self, key_version: u32, payload: &str) -> String {
        let key = self
            .keys
            .iter()
            .find(|key| key.version == key_version)
            .expect("signing requires a known key version")
            .key;
        let mut mac =
            <SessionMac as Mac>::new_from_slice(&key).expect("HMAC-SHA256 accepts any key length");
        Mac::update(&mut mac, b"eidolon-session:");
        Mac::update(&mut mac, payload.as_bytes());
        let bytes = mac.finalize().into_bytes();
        encode_hex(&bytes)
    }

    fn insert_continuity(
        &mut self,
        continuity_key: ContinuityKey,
        session_id: SessionId,
        now: u64,
    ) -> ContinuityInsertOutcome {
        if self.continuity.contains_key(&continuity_key) {
            return ContinuityInsertOutcome::CapacityFailClosed;
        }
        if !self.durable_authenticated_insert_allowed(continuity_key, now) {
            return ContinuityInsertOutcome::AdmissionRateFailClosed;
        }

        while self.continuity.len() >= self.continuity_capacity {
            if !self.evict_oldest_unprotected_continuity(continuity_key.source()) {
                return ContinuityInsertOutcome::CapacityFailClosed;
            }
        }
        self.continuity.insert(
            continuity_key,
            ContinuityRecord {
                session_id,
                floor: None,
                last_seen: now,
                last_recovery_at: None,
                recovery_count: 0,
            },
        );
        self.continuity_order.push_back(continuity_key);
        if continuity_key.source() == ContinuitySource::AuthenticatedIngress {
            if self.continuity_state_path.is_some() {
                self.durable_continuity_insert_times.push_back(now);
            }
            self.mark_authenticated_security_change();
        }
        ContinuityInsertOutcome::Inserted
    }

    fn durable_authenticated_insert_allowed(
        &mut self,
        continuity_key: ContinuityKey,
        now: u64,
    ) -> bool {
        if continuity_key.source() != ContinuitySource::AuthenticatedIngress
            || self.continuity_state_path.is_none()
        {
            return true;
        }
        let cutoff = now.saturating_sub(DURABLE_CONTINUITY_INSERT_WINDOW_SECS);
        self.durable_continuity_insert_times
            .retain(|timestamp| *timestamp > cutoff);
        self.durable_continuity_insert_times.len() < MAX_DURABLE_CONTINUITY_INSERTS_PER_WINDOW
    }

    fn oldest_unprotected_continuity(
        &self,
        incoming_source: ContinuitySource,
    ) -> Option<(usize, ContinuityKey, ContinuityRecord)> {
        self.continuity_order
            .iter()
            .enumerate()
            .find_map(|(index, key)| {
                if incoming_source == ContinuitySource::LabPeer
                    && key.source() != ContinuitySource::LabPeer
                {
                    return None;
                }
                self.continuity
                    .get(key)
                    .copied()
                    .filter(|record| {
                        record.floor.is_none_or(|floor| {
                            enforcement_rank(floor) < enforcement_rank(PolicyState::Suspicious)
                        })
                    })
                    .map(|record| (index, *key, record))
            })
    }

    fn evict_oldest_unprotected_continuity(&mut self, incoming_source: ContinuitySource) -> bool {
        let Some((index, continuity_key, _)) = self.oldest_unprotected_continuity(incoming_source)
        else {
            return false;
        };
        self.continuity_order
            .remove(index)
            .expect("position came from the continuity order");
        self.continuity.remove(&continuity_key);
        if continuity_key.source() == ContinuitySource::AuthenticatedIngress {
            self.mark_authenticated_security_change();
        }
        true
    }

    fn capacity_fail_closed(
        &self,
        continuity_key: ContinuityKey,
        now: u64,
        cookie_outcome: CookieOutcome,
        key_status: Option<KeyStatus>,
        presented_key_version: Option<u32>,
    ) -> SessionResolution {
        let session_id = SessionId::new();
        SessionResolution {
            session_id,
            cookie_outcome,
            key_status,
            presented_key_version,
            active_key_version: self.active_key_version,
            continuity_outcome: ContinuityOutcome::CapacityFailClosed,
            continuity_source: Some(continuity_key.source()),
            enforcement_floor: Some(PolicyState::Blocked),
            set_cookie_value: Some(self.mint_set_cookie_value(session_id, now)),
        }
    }

    fn admission_rate_fail_closed(
        &self,
        continuity_key: ContinuityKey,
        cookie_outcome: CookieOutcome,
        key_status: Option<KeyStatus>,
        presented_key_version: Option<u32>,
    ) -> SessionResolution {
        SessionResolution {
            session_id: SessionId::new(),
            cookie_outcome,
            key_status,
            presented_key_version,
            active_key_version: self.active_key_version,
            continuity_outcome: ContinuityOutcome::AdmissionRateFailClosed,
            continuity_source: Some(continuity_key.source()),
            enforcement_floor: Some(PolicyState::Blocked),
            set_cookie_value: None,
        }
    }

    fn migration_quarantine_fail_closed(
        &self,
        continuity_key: ContinuityKey,
        cookie_outcome: CookieOutcome,
        presented_key_version: Option<u32>,
    ) -> SessionResolution {
        let session_id = SessionId::new();
        SessionResolution {
            session_id,
            cookie_outcome,
            key_status: None,
            presented_key_version,
            active_key_version: self.active_key_version,
            continuity_outcome: ContinuityOutcome::MigrationQuarantineFailClosed,
            continuity_source: Some(continuity_key.source()),
            enforcement_floor: Some(PolicyState::Blocked),
            set_cookie_value: None,
        }
    }

    fn storage_unavailable_resolution(
        &self,
        mut resolution: SessionResolution,
    ) -> SessionResolution {
        resolution.continuity_outcome = ContinuityOutcome::StorageUnavailable;
        resolution.enforcement_floor = Some(PolicyState::Blocked);
        resolution.set_cookie_value = None;
        resolution
    }

    fn mark_authenticated_security_change(&mut self) {
        self.continuity_dirty = true;
        self.continuity_checkpoint_dirty = true;
        self.continuity_security_revision = self.continuity_security_revision.wrapping_add(1);
    }

    fn mark_authenticated_metadata_change(&mut self) {
        self.continuity_checkpoint_dirty = true;
        self.continuity_metadata_revision = self.continuity_metadata_revision.wrapping_add(1);
    }

    fn stored_continuity_state(&self) -> io::Result<StoredContinuityState> {
        let transport_key_id_hex = self
            .continuity_state_key_id_hex
            .clone()
            .ok_or_else(|| invalid_data("durable continuity state key identifier is missing"))?;
        let mut records = Vec::new();
        for key in &self.continuity_order {
            if key.source() != ContinuitySource::AuthenticatedIngress {
                continue;
            }
            let Some(record) = self.continuity.get(key) else {
                continue;
            };
            records.push(StoredContinuityRecord {
                key_digest_hex: encode_hex(&key.digest()),
                session_id: record.session_id,
                enforcement_floor: record.floor,
                last_seen: record.last_seen,
                last_recovery_at: record.last_recovery_at,
                recovery_count: record.recovery_count,
            });
        }
        Ok(StoredContinuityState {
            schema_version: 1,
            transport_key_id_hex,
            migration_quarantine_until: self.continuity_migration_quarantine_until,
            records,
            integrity_mac_hex: String::new(),
        })
    }

    fn persist_continuity_state(&self) -> io::Result<StateCommitOutcome> {
        let Some(path) = &self.continuity_state_path else {
            return Ok(StateCommitOutcome::Durable);
        };
        let integrity_key = self
            .continuity_integrity_key
            .as_ref()
            .ok_or_else(|| invalid_data("durable continuity integrity key is missing"))?;
        session_continuity_store::persist_state(
            path,
            &self.stored_continuity_state()?,
            integrity_key,
        )
    }

    fn persist_continuity_state_durably(&mut self) -> io::Result<()> {
        match self.persist_continuity_state()? {
            StateCommitOutcome::Durable => {
                self.continuity_dirty = false;
                self.continuity_checkpoint_dirty = false;
                Ok(())
            }
            StateCommitOutcome::CommittedDurabilityUncertain => Err(io::Error::other(
                "continuity state was committed but parent-directory durability is uncertain",
            )),
        }
    }

    fn evict_expired_continuity(&mut self, now: u64) {
        let ttl = self.continuity_ttl_secs;
        let mut removed_authenticated = false;
        self.continuity.retain(|key, record| {
            let keep = record.last_seen.saturating_add(ttl) > now;
            removed_authenticated |=
                !keep && key.source() == ContinuitySource::AuthenticatedIngress;
            keep
        });
        self.continuity_order
            .retain(|peer| self.continuity.contains_key(peer));
        if removed_authenticated {
            self.mark_authenticated_metadata_change();
        }
    }
}

struct VerifiedCookie {
    session_id: SessionId,
    key_version: u32,
}

/// Extract the first `eidolon_session` cookie value from request headers.
///
/// Only the first occurrence is considered; additional duplicates are
/// ignored, which keeps ambiguous repeated cookies deterministic.
fn session_cookie_value<I, N, V>(headers: I) -> Option<String>
where
    I: IntoIterator<Item = (N, V)>,
    N: AsRef<str>,
    V: AsRef<str>,
{
    for (name, value) in headers {
        if !name.as_ref().eq_ignore_ascii_case("cookie") {
            continue;
        }
        for pair in value.as_ref().split(';') {
            let pair = pair.trim();
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            if name.trim() == SESSION_COOKIE_NAME && !value.trim().is_empty() {
                return Some(value.trim().to_string());
            }
        }
    }

    None
}

/// Total ordering of policy states for enforcement-floor comparison.
///
/// `Blocked` outranks every other state; `ControlledReality` is treated as
/// deeper containment than `RateLimited`. The floor never downgrades a
/// session, so ties and parallel rungs resolve to the already-loaded state.
pub fn enforcement_rank(state: PolicyState) -> u8 {
    match state {
        PolicyState::Normal => 0,
        PolicyState::Observe => 1,
        PolicyState::Suspicious => 2,
        PolicyState::RateLimited => 3,
        PolicyState::ControlledReality => 4,
        PolicyState::Blocked => 5,
    }
}

fn continuity_state_key_id_hex(continuity_key: &str) -> String {
    let mut mac = <SessionMac as Mac>::new_from_slice(continuity_key.as_bytes())
        .expect("HMAC-SHA256 accepts any continuity key length");
    mac.update(CONTINUITY_STATE_KEY_ID_DOMAIN);
    encode_hex(&mac.finalize().into_bytes())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex_nibble(char: u8) -> Option<u8> {
    match char {
        b'0'..=b'9' => Some(char - b'0'),
        b'a'..=b'f' => Some(char - b'a' + 10),
        b'A'..=b'F' => Some(char - b'A' + 10),
        _ => None,
    }
}

fn decode_key_hex(raw: &str) -> Option<[u8; SESSION_KEY_BYTES]> {
    let bytes = raw.as_bytes();
    if bytes.len() != SESSION_KEY_BYTES * 2 {
        return None;
    }
    let mut key = [0u8; SESSION_KEY_BYTES];
    for (index, chunk) in bytes.chunks_exact(2).enumerate() {
        key[index] = (decode_hex_nibble(chunk[0])? << 4) | decode_hex_nibble(chunk[1])?;
    }
    Some(key)
}

fn decode_mac_hex(raw: &str) -> Option<Vec<u8>> {
    let bytes = raw.as_bytes();
    if bytes.len() != MAC_HEX_CHARS {
        return None;
    }
    let mut out = Vec::with_capacity(MAC_HEX_CHARS / 2);
    for chunk in bytes.chunks_exact(2) {
        out.push((decode_hex_nibble(chunk[0])? << 4) | decode_hex_nibble(chunk[1])?);
    }
    Some(out)
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    const NOW: u64 = 1_750_000_000;

    fn test_key(fill: u8) -> [u8; SESSION_KEY_BYTES] {
        [fill; SESSION_KEY_BYTES]
    }

    fn test_authority() -> SessionAuthority {
        SessionAuthority::new(
            vec![SessionKeyVersion {
                version: 1,
                key: test_key(0x42),
            }],
            1,
        )
        .expect("test authority should build")
    }

    fn peer() -> IpAddr {
        "127.0.0.1".parse().expect("peer IP should parse")
    }

    #[test]
    fn session_key_version_debug_redacts_key_bytes() {
        let key = SessionKeyVersion {
            version: 7,
            key: test_key(0x42),
        };
        let rendered = format!("{key:?}");
        assert!(rendered.contains("version: 7"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains("[66, 66"), "{rendered}");
    }

    #[test]
    fn session_key_file_debug_redacts_key_hex() {
        let key_hex = "4242424242424242424242424242424242424242424242424242424242424242";
        let document = format!(
            r#"{{"active_key_version":2,"keys":[{{"version":1,"key_hex":"{key_hex}"}},{{"version":2,"key_hex":"{key_hex}"}}]}}"#
        );
        let key_file: SessionKeyFile =
            serde_json::from_str(&document).expect("key file should parse");
        let rendered = format!("{key_file:?}");
        assert!(rendered.contains("active_key_version: 2"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains(key_hex), "{rendered}");
    }

    #[test]
    fn session_authority_debug_redacts_key_material() {
        let authority = test_authority();
        let rendered = format!("{authority:?}");
        assert!(rendered.contains("active_key_version: 1"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains("[66, 66"), "{rendered}");
        assert!(!rendered.contains("0x42"), "{rendered}");
    }

    fn peer_key() -> ContinuityKey {
        ContinuityKey::lab_peer(peer())
    }

    fn ingress_key(raw: &str) -> ContinuityKey {
        ContinuityKey::authenticated_ingress(raw, "edge-secret")
    }

    fn cookie_header(value: &str) -> [(&'static str, String); 1] {
        [("Cookie", format!("{}={}", SESSION_COOKIE_NAME, value))]
    }

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "eidolon-session-continuity-test-{}",
                uuid::Uuid::new_v4()
            ));
            fs::create_dir(&path).expect("test directory should be created");
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn minted_cookie_roundtrips() {
        let mut authority = test_authority();
        let session_id = SessionId::new();
        let value = authority.mint_cookie_value(session_id, NOW);

        let resolution = authority.resolve(cookie_header(&value), Some(peer()), NOW + 10);

        assert_eq!(resolution.session_id, session_id);
        assert_eq!(resolution.cookie_outcome, CookieOutcome::Valid);
        assert_eq!(resolution.key_status, Some(KeyStatus::Active));
        assert_eq!(resolution.presented_key_version, Some(1));
        assert_eq!(resolution.active_key_version, 1);
        assert_eq!(
            resolution.continuity_outcome,
            ContinuityOutcome::NotApplicable
        );
        assert_eq!(resolution.enforcement_floor, None);
        assert_eq!(resolution.set_cookie_value, None);
        assert!(resolution.from_cookie());
    }

    #[test]
    fn previous_key_version_verifies_and_is_reminted() {
        let mut authority = SessionAuthority::new(
            vec![
                SessionKeyVersion {
                    version: 1,
                    key: test_key(0x42),
                },
                SessionKeyVersion {
                    version: 2,
                    key: test_key(0x43),
                },
            ],
            2,
        )
        .expect("two-version authority should build");
        let session_id = SessionId::new();
        let old_value = {
            let payload = format!("{}.{}.{}.{}", COOKIE_FORMAT_TAG, 1, NOW, session_id.0);
            format!("{}.{}", payload, authority.sign_with(1, &payload))
        };

        let resolution = authority.resolve(cookie_header(&old_value), Some(peer()), NOW + 10);

        assert_eq!(resolution.session_id, session_id);
        assert_eq!(resolution.cookie_outcome, CookieOutcome::Valid);
        assert_eq!(resolution.key_status, Some(KeyStatus::Previous));
        assert_eq!(resolution.presented_key_version, Some(1));
        assert_eq!(resolution.active_key_version, 2);
        let set_cookie = resolution
            .set_cookie_value
            .expect("previous-key cookie should be re-minted");
        assert!(set_cookie.contains(&format!("{}.", COOKIE_FORMAT_TAG)));
        assert!(set_cookie.contains(".2."));
    }

    #[test]
    fn forged_session_id_is_not_adopted() {
        let mut authority = test_authority();
        let forged = format!(
            "{}.1.{}.{}.{}",
            COOKIE_FORMAT_TAG,
            NOW,
            SessionId::new().0,
            "0".repeat(MAC_HEX_CHARS)
        );

        let resolution = authority.resolve(cookie_header(&forged), Some(peer()), NOW);

        assert_eq!(resolution.cookie_outcome, CookieOutcome::BadSignature);
        assert_ne!(resolution.session_id.0.to_string(), forged);
        assert!(!resolution.from_cookie());
        assert!(resolution.set_cookie_value.is_some());
    }

    #[test]
    fn unsigned_legacy_uuid_cookie_is_malformed() {
        let mut authority = test_authority();
        let legacy = SessionId::new().0.to_string();

        let resolution = authority.resolve(cookie_header(&legacy), Some(peer()), NOW);

        assert_eq!(resolution.cookie_outcome, CookieOutcome::Malformed);
        assert_ne!(resolution.session_id.0.to_string(), legacy);
    }

    #[test]
    fn unknown_key_version_is_reported() {
        let mut authority = test_authority();
        let session_id = SessionId::new();
        let payload = format!("{}.9.{}.{}", COOKIE_FORMAT_TAG, NOW, session_id.0);
        let value = format!("{}.{}", payload, authority.sign_with(1, &payload));

        let resolution = authority.resolve(cookie_header(&value), Some(peer()), NOW);

        assert_eq!(resolution.cookie_outcome, CookieOutcome::UnknownKeyVersion);
        assert_eq!(resolution.presented_key_version, Some(9));
    }

    #[test]
    fn expired_cookie_is_reported_and_not_adopted() {
        let mut authority = test_authority();
        let session_id = SessionId::new();
        let stale_iat = NOW - DEFAULT_COOKIE_LIFETIME_SECS - 10;
        let value = authority.mint_cookie_value(session_id, stale_iat);

        let resolution = authority.resolve(cookie_header(&value), Some(peer()), NOW);

        assert_eq!(resolution.cookie_outcome, CookieOutcome::Expired);
        assert_ne!(resolution.session_id, session_id);
    }

    #[test]
    fn future_dated_cookie_is_malformed() {
        let mut authority = test_authority();
        let session_id = SessionId::new();
        let value = authority.mint_cookie_value(session_id, NOW + MAX_FUTURE_SKEW_SECS + 60);

        let resolution = authority.resolve(cookie_header(&value), Some(peer()), NOW);

        assert_eq!(resolution.cookie_outcome, CookieOutcome::Malformed);
        assert_ne!(resolution.session_id, session_id);
    }

    #[test]
    fn absent_cookie_mints_new_session() {
        let mut authority = test_authority();

        let resolution = authority.resolve([("Host", "proxy.local")], Some(peer()), NOW);

        assert_eq!(resolution.cookie_outcome, CookieOutcome::Absent);
        assert_eq!(resolution.continuity_outcome, ContinuityOutcome::NoRecord);
        assert!(resolution.set_cookie_value.is_some());
    }

    #[test]
    fn discarded_cookie_recovers_existing_peer_session() {
        let mut authority = test_authority();
        let original = authority.resolve([("Host", "proxy.local")], Some(peer()), NOW);
        assert_eq!(original.continuity_outcome, ContinuityOutcome::NoRecord);

        let rotated = authority.resolve([("Host", "proxy.local")], Some(peer()), NOW + 5);

        assert_eq!(rotated.session_id, original.session_id);
        assert_eq!(rotated.cookie_outcome, CookieOutcome::Absent);
        assert_eq!(rotated.continuity_outcome, ContinuityOutcome::Recovered);
        assert!(rotated.set_cookie_value.is_some());
    }

    #[test]
    fn rapid_second_discard_mints_fresh_session_but_keeps_enforcement_floor() {
        let mut authority = test_authority();
        let original = authority.resolve([("Host", "proxy.local")], Some(peer()), NOW);
        authority.note_enforcement(
            Some(peer()),
            original.session_id,
            PolicyState::Blocked,
            NOW + 1,
        );

        let first = authority.resolve([("Host", "proxy.local")], Some(peer()), NOW + 5);
        assert_eq!(first.continuity_outcome, ContinuityOutcome::Recovered);
        assert_eq!(first.session_id, original.session_id);
        assert_eq!(first.enforcement_floor, Some(PolicyState::Blocked));

        let second = authority.resolve([("Host", "proxy.local")], Some(peer()), NOW + 6);
        assert_eq!(
            second.continuity_outcome,
            ContinuityOutcome::CooldownLimited
        );
        assert_ne!(second.session_id, original.session_id);
        assert_eq!(second.enforcement_floor, Some(PolicyState::Blocked));
        assert!(second.set_cookie_value.is_some());
        assert_eq!(authority.continuity.len(), 1);
        assert_eq!(
            authority
                .continuity
                .get(&ContinuityKey::lab_peer(peer()))
                .map(|record| record.session_id),
            Some(second.session_id)
        );
    }

    #[test]
    fn authenticated_cooldown_preserves_session_across_repeated_cookie_failures() {
        let mut authority = test_authority();
        let continuity_key = ingress_key("client_A_0123456789abcdef");
        let original =
            authority.resolve_with_continuity([("Host", "proxy.local")], Some(continuity_key), NOW);
        authority.note_enforcement_with_continuity(
            Some(continuity_key),
            original.session_id,
            PolicyState::Blocked,
            NOW + 1,
        );

        let recovered = authority.resolve_with_continuity(
            [("Host", "proxy.local")],
            Some(continuity_key),
            NOW + 5,
        );
        assert_eq!(recovered.continuity_outcome, ContinuityOutcome::Recovered);
        assert_eq!(recovered.session_id, original.session_id);

        let forged = format!(
            "{}.1.{}.{}.{}",
            COOKIE_FORMAT_TAG,
            NOW,
            SessionId::new().0,
            "f".repeat(MAC_HEX_CHARS)
        );
        let failures = [
            authority.resolve_with_continuity(
                [("Host", "proxy.local")],
                Some(continuity_key),
                NOW + 6,
            ),
            authority.resolve_with_continuity(
                cookie_header("malformed"),
                Some(continuity_key),
                NOW + 7,
            ),
            authority.resolve_with_continuity(
                cookie_header(&forged),
                Some(continuity_key),
                NOW + 8,
            ),
        ];

        assert_eq!(failures[0].cookie_outcome, CookieOutcome::Absent);
        assert_eq!(failures[1].cookie_outcome, CookieOutcome::Malformed);
        assert_eq!(failures[2].cookie_outcome, CookieOutcome::BadSignature);
        for failure in failures {
            assert_eq!(failure.session_id, original.session_id);
            assert_eq!(
                failure.continuity_outcome,
                ContinuityOutcome::CooldownSessionPreserved
            );
            assert_eq!(failure.enforcement_floor, Some(PolicyState::Blocked));
            assert!(failure
                .set_cookie_value
                .as_deref()
                .is_some_and(|cookie| cookie.contains(&original.session_id.0.to_string())));
        }

        assert_eq!(authority.continuity.len(), 1);
        let record = authority
            .continuity
            .get(&continuity_key)
            .expect("authenticated continuity record remains present");
        assert_eq!(record.session_id, original.session_id);
        assert_eq!(record.floor, Some(PolicyState::Blocked));
        assert_eq!(record.last_recovery_at, Some(NOW + 5));
        assert_eq!(record.recovery_count, 1);
    }

    #[test]
    fn recovery_reopens_after_cooldown_window() {
        let mut authority = test_authority();
        let original = authority.resolve([("Host", "proxy.local")], Some(peer()), NOW);

        let first = authority.resolve([("Host", "proxy.local")], Some(peer()), NOW + 5);
        assert_eq!(first.continuity_outcome, ContinuityOutcome::Recovered);

        let limited = authority.resolve([("Host", "proxy.local")], Some(peer()), NOW + 6);
        assert_eq!(
            limited.continuity_outcome,
            ContinuityOutcome::CooldownLimited
        );

        let reopened = authority.resolve(
            [("Host", "proxy.local")],
            Some(peer()),
            NOW + 6 + CONTINUITY_RECOVERY_COOLDOWN_SECS,
        );
        assert_eq!(reopened.continuity_outcome, ContinuityOutcome::Recovered);
        assert_eq!(reopened.session_id, limited.session_id);
        assert_ne!(reopened.session_id, original.session_id);
    }

    #[test]
    fn forged_cookie_after_rotation_recovers_original_session() {
        let mut authority = test_authority();
        let original = authority.resolve([("Host", "proxy.local")], Some(peer()), NOW);
        let forged = format!(
            "{}.1.{}.{}.{}",
            COOKIE_FORMAT_TAG,
            NOW,
            SessionId::new().0,
            "f".repeat(MAC_HEX_CHARS)
        );

        let resolution = authority.resolve(cookie_header(&forged), Some(peer()), NOW + 5);

        assert_eq!(resolution.cookie_outcome, CookieOutcome::BadSignature);
        assert_eq!(resolution.continuity_outcome, ContinuityOutcome::Recovered);
        assert_eq!(resolution.session_id, original.session_id);
    }

    #[test]
    fn enforcement_floor_is_monotonic_and_survives_rotation() {
        let mut authority = test_authority();
        let original = authority.resolve([("Host", "proxy.local")], Some(peer()), NOW);
        authority.note_enforcement(
            Some(peer()),
            original.session_id,
            PolicyState::Blocked,
            NOW + 1,
        );
        authority.note_enforcement(
            Some(peer()),
            original.session_id,
            PolicyState::Observe,
            NOW + 2,
        );

        let rotated = authority.resolve([("Host", "proxy.local")], Some(peer()), NOW + 5);

        assert_eq!(rotated.session_id, original.session_id);
        assert_eq!(rotated.enforcement_floor, Some(PolicyState::Blocked));
    }

    #[test]
    fn enforcement_floor_applies_to_new_session_after_ttl_expiry() {
        let mut authority = test_authority();
        let original = authority.resolve([("Host", "proxy.local")], Some(peer()), NOW);
        authority.note_enforcement(
            Some(peer()),
            original.session_id,
            PolicyState::Blocked,
            NOW + 1,
        );

        let after_expiry = authority.resolve(
            [("Host", "proxy.local")],
            Some(peer()),
            NOW + DEFAULT_CONTINUITY_TTL_SECS + 10,
        );

        assert_eq!(after_expiry.continuity_outcome, ContinuityOutcome::NoRecord);
        assert_ne!(after_expiry.session_id, original.session_id);
        assert_eq!(after_expiry.enforcement_floor, None);
    }

    #[test]
    fn distinct_peers_do_not_share_continuity() {
        let mut authority = test_authority();
        let first = authority.resolve([("Host", "proxy.local")], Some(peer()), NOW);
        let other_peer: IpAddr = "127.0.0.2".parse().expect("peer IP should parse");

        let second = authority.resolve([("Host", "proxy.local")], Some(other_peer), NOW + 1);

        assert_ne!(second.session_id, first.session_id);
        assert_eq!(second.continuity_outcome, ContinuityOutcome::NoRecord);
    }

    #[test]
    fn none_peer_ip_disables_continuity() {
        let mut authority = test_authority();
        let first = authority.resolve([("Host", "proxy.local")], None, NOW);
        let second = authority.resolve([("Host", "proxy.local")], None, NOW + 1);

        assert_eq!(first.continuity_outcome, ContinuityOutcome::NoRecord);
        assert_eq!(second.continuity_outcome, ContinuityOutcome::NoRecord);
        assert_ne!(second.session_id, first.session_id);
    }

    #[test]
    fn continuity_capacity_must_be_positive_and_configured_before_use() {
        let mut authority = test_authority();

        let zero = authority
            .set_continuity_capacity(0)
            .expect_err("zero capacity must be rejected");
        assert_eq!(zero.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(authority.continuity_capacity, DEFAULT_CONTINUITY_CAPACITY);

        authority
            .set_continuity_capacity(2)
            .expect("empty authority accepts positive capacity");
        authority.resolve([("Host", "proxy.local")], Some(peer()), NOW);

        let live = authority
            .set_continuity_capacity(3)
            .expect_err("live continuity state must prevent reconfiguration");
        assert_eq!(live.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(authority.continuity_capacity, 2);
        assert_eq!(authority.continuity.len(), 1);
    }

    #[test]
    fn continuity_map_is_capacity_bounded() {
        let mut authority = test_authority();
        authority
            .set_continuity_capacity(2)
            .expect("empty authority accepts positive capacity");
        let peer_a = peer();
        let peer_b: IpAddr = "127.0.0.2".parse().expect("peer IP should parse");
        let peer_c: IpAddr = "127.0.0.3".parse().expect("peer IP should parse");

        authority.resolve([("Host", "proxy.local")], Some(peer_a), NOW);
        authority.resolve([("Host", "proxy.local")], Some(peer_b), NOW + 1);
        authority.resolve([("Host", "proxy.local")], Some(peer_c), NOW + 2);

        assert_eq!(authority.continuity.len(), 2);
        assert!(!authority
            .continuity
            .contains_key(&ContinuityKey::lab_peer(peer_a)));

        let recovered_b = authority.resolve([("Host", "proxy.local")], Some(peer_b), NOW + 3);
        assert_eq!(recovered_b.continuity_outcome, ContinuityOutcome::Recovered);
    }

    #[test]
    fn capacity_evicts_only_records_below_suspicious() {
        let mut authority = test_authority();
        authority
            .set_continuity_capacity(2)
            .expect("empty authority accepts positive capacity");
        let protected_key = ingress_key("protected_0123456789abcdef");
        let evictable_key = ingress_key("evictable_0123456789abcdef");
        let new_key = ingress_key("new_client_0123456789abcdef");
        let protected =
            authority.resolve_with_continuity([("Host", "proxy.local")], Some(protected_key), NOW);
        let evictable = authority.resolve_with_continuity(
            [("Host", "proxy.local")],
            Some(evictable_key),
            NOW + 1,
        );
        authority.note_enforcement_with_continuity(
            Some(protected_key),
            protected.session_id,
            PolicyState::Suspicious,
            NOW + 2,
        );
        authority.note_enforcement_with_continuity(
            Some(evictable_key),
            evictable.session_id,
            PolicyState::Observe,
            NOW + 2,
        );

        let inserted =
            authority.resolve_with_continuity([("Host", "proxy.local")], Some(new_key), NOW + 3);

        assert_eq!(inserted.continuity_outcome, ContinuityOutcome::NoRecord);
        assert!(authority.continuity.contains_key(&protected_key));
        assert!(!authority.continuity.contains_key(&evictable_key));
        assert!(authority.continuity.contains_key(&new_key));
    }

    #[test]
    fn protected_capacity_fails_unknown_identity_closed_without_insertion() {
        let mut authority = test_authority();
        authority
            .set_continuity_capacity(2)
            .expect("empty authority accepts positive capacity");
        let key_a = ingress_key("protected_A_0123456789abcdef");
        let key_b = ingress_key("protected_B_0123456789abcdef");
        let unknown_key = ingress_key("unknown_0123456789abcdef");
        let first = authority.resolve_with_continuity([("Host", "proxy.local")], Some(key_a), NOW);
        let second =
            authority.resolve_with_continuity([("Host", "proxy.local")], Some(key_b), NOW + 1);
        authority.note_enforcement_with_continuity(
            Some(key_a),
            first.session_id,
            PolicyState::Suspicious,
            NOW + 2,
        );
        authority.note_enforcement_with_continuity(
            Some(key_b),
            second.session_id,
            PolicyState::Blocked,
            NOW + 2,
        );
        let valid_unknown_session = SessionId::new();
        let valid_unknown_cookie = authority.mint_cookie_value(valid_unknown_session, NOW + 3);

        let rejected = authority.resolve_with_continuity(
            cookie_header(&valid_unknown_cookie),
            Some(unknown_key),
            NOW + 3,
        );

        assert_ne!(rejected.session_id, valid_unknown_session);
        assert_eq!(rejected.cookie_outcome, CookieOutcome::Valid);
        assert_eq!(
            rejected.continuity_outcome,
            ContinuityOutcome::CapacityFailClosed
        );
        assert_eq!(rejected.enforcement_floor, Some(PolicyState::Blocked));
        assert!(!rejected.from_cookie());
        assert!(rejected.set_cookie_value.is_some());
        assert_eq!(authority.continuity.len(), 2);
        assert!(authority.continuity.contains_key(&key_a));
        assert!(authority.continuity.contains_key(&key_b));
        assert!(!authority.continuity.contains_key(&unknown_key));
    }

    #[test]
    fn authenticated_continuity_is_secret_keyed_capacity_and_ttl_bounded() {
        let mut authority = SessionAuthority {
            continuity_ttl_secs: 10,
            ..test_authority()
        };
        authority
            .set_continuity_capacity(2)
            .expect("empty authority accepts positive capacity");
        let key_a = ingress_key("client_A_0123456789abcdef");
        let key_b = ingress_key("client_B_0123456789abcdef");
        let key_c = ingress_key("client_C_0123456789abcdef");
        assert_ne!(
            key_a,
            ContinuityKey::authenticated_ingress("client_A_0123456789abcdef", "different-secret")
        );

        let first = authority.resolve_with_continuity([("Host", "proxy.local")], Some(key_a), NOW);
        authority.resolve_with_continuity([("Host", "proxy.local")], Some(key_b), NOW + 1);
        authority.resolve_with_continuity([("Host", "proxy.local")], Some(key_c), NOW + 2);
        assert_eq!(authority.continuity.len(), 2);
        assert!(!authority.continuity.contains_key(&key_a));

        let after_ttl =
            authority.resolve_with_continuity([("Host", "proxy.local")], Some(key_a), NOW + 20);
        assert_ne!(after_ttl.session_id, first.session_id);
        assert_eq!(after_ttl.continuity_outcome, ContinuityOutcome::NoRecord);
        assert_eq!(authority.continuity.len(), 1);
    }

    #[test]
    fn valid_alternate_cookie_cannot_reanchor_existing_continuity() {
        let mut authority = test_authority();
        let continuity_key = ingress_key("client_A_0123456789abcdef");
        let original =
            authority.resolve_with_continuity([("Host", "proxy.local")], Some(continuity_key), NOW);
        authority.note_enforcement_with_continuity(
            Some(continuity_key),
            original.session_id,
            PolicyState::Blocked,
            NOW + 1,
        );
        let alternate_session = SessionId::new();
        let alternate_cookie = authority.mint_cookie_value(alternate_session, NOW + 2);

        let resolved = authority.resolve_with_continuity(
            cookie_header(&alternate_cookie),
            Some(continuity_key),
            NOW + 3,
        );

        assert_eq!(resolved.session_id, original.session_id);
        assert_eq!(resolved.cookie_outcome, CookieOutcome::Valid);
        assert_eq!(
            resolved.continuity_outcome,
            ContinuityOutcome::ContinuitySessionPreserved
        );
        assert_eq!(resolved.enforcement_floor, Some(PolicyState::Blocked));
        assert!(!resolved.from_cookie());
        assert!(resolved
            .set_cookie_value
            .as_deref()
            .is_some_and(|cookie| cookie.contains(&original.session_id.0.to_string())));
        assert_eq!(
            authority
                .continuity
                .get(&continuity_key)
                .map(|record| (record.session_id, record.floor)),
            Some((original.session_id, Some(PolicyState::Blocked)))
        );
    }

    #[test]
    fn one_valid_cookie_cannot_bind_multiple_continuity_keys() {
        let mut authority = test_authority();
        let session_id = SessionId::new();
        let cookie = authority.mint_cookie_value(session_id, NOW);
        let key_a = ingress_key("client_A_0123456789abcdef");
        let key_b = ingress_key("client_B_0123456789abcdef");

        let first = authority.resolve_with_continuity(cookie_header(&cookie), Some(key_a), NOW + 1);
        let second =
            authority.resolve_with_continuity(cookie_header(&cookie), Some(key_b), NOW + 2);

        assert_eq!(first.session_id, session_id);
        assert!(first.from_cookie());
        assert_ne!(second.session_id, session_id);
        assert_eq!(
            second.continuity_outcome,
            ContinuityOutcome::CookieSessionAlreadyBound
        );
        assert!(!second.from_cookie());
        assert!(second.set_cookie_value.is_some());
        assert_eq!(
            authority
                .continuity
                .get(&key_a)
                .map(|record| record.session_id),
            Some(session_id)
        );
        assert_eq!(
            authority
                .continuity
                .get(&key_b)
                .map(|record| record.session_id),
            Some(second.session_id)
        );
    }

    #[test]
    fn first_cookie_occurrence_wins_over_duplicates() {
        let mut authority = test_authority();
        let session_id = SessionId::new();
        let valid = authority.mint_cookie_value(session_id, NOW);
        let headers = [(
            "Cookie",
            format!(
                "{}=garbage; {}={}",
                SESSION_COOKIE_NAME, SESSION_COOKIE_NAME, valid
            ),
        )];

        let resolution = authority.resolve(headers, Some(peer()), NOW);

        assert_eq!(resolution.cookie_outcome, CookieOutcome::Malformed);
        assert_ne!(resolution.session_id, session_id);
    }

    #[test]
    fn key_file_roundtrip_and_validation() {
        let json = br#"{
            "active_key_version": 2,
            "keys": [
                {"version": 1, "key_hex": "4242424242424242424242424242424242424242424242424242424242424242"},
                {"version": 2, "key_hex": "4343434343434343434343434343434343434343434343434343434343434343"}
            ]
        }"#;
        let authority =
            SessionAuthority::from_key_file_json(json).expect("valid key file should parse");
        assert_eq!(authority.active_key_version(), 2);
        assert_eq!(authority.key_version_count(), 2);

        let missing_active = br#"{
            "active_key_version": 3,
            "keys": [
                {"version": 1, "key_hex": "4242424242424242424242424242424242424242424242424242424242424242"}
            ]
        }"#;
        assert!(SessionAuthority::from_key_file_json(missing_active).is_err());

        let bad_hex = br#"{
            "active_key_version": 1,
            "keys": [
                {"version": 1, "key_hex": "not-hex"}
            ]
        }"#;
        assert!(SessionAuthority::from_key_file_json(bad_hex).is_err());

        let duplicates = br#"{
            "active_key_version": 1,
            "keys": [
                {"version": 1, "key_hex": "4242424242424242424242424242424242424242424242424242424242424242"},
                {"version": 1, "key_hex": "4343434343434343434343434343434343434343434343434343434343434343"}
            ]
        }"#;
        assert!(SessionAuthority::from_key_file_json(duplicates).is_err());
    }

    #[test]
    fn set_cookie_value_carries_stable_attributes() {
        let authority = test_authority();
        let session_id = SessionId::new();

        let value = authority.mint_set_cookie_value(session_id, NOW);

        assert!(value.starts_with(&format!("{}={}.1.", SESSION_COOKIE_NAME, COOKIE_FORMAT_TAG)));
        assert!(value.contains("Path=/"));
        assert!(value.contains("HttpOnly"));
        assert!(value.contains("SameSite=Lax"));
        assert!(!value.contains("Domain="));
        assert!(!value.contains("Secure"));
    }

    #[test]
    fn documented_constant_values_are_pinned() {
        assert_eq!(DEFAULT_COOKIE_LIFETIME_SECS, 604_800);
        assert_eq!(DEFAULT_CONTINUITY_TTL_SECS, 86_400);
        assert_eq!(CONTINUITY_RECOVERY_COOLDOWN_SECS, 60);
        assert_eq!(DEFAULT_CONTINUITY_CAPACITY, 4096);
        assert_eq!(CONTINUITY_CHECKPOINT_INTERVAL_SECS, 60);
        assert_eq!(DURABLE_CONTINUITY_INSERT_WINDOW_SECS, 60);
        assert_eq!(MAX_DURABLE_CONTINUITY_INSERTS_PER_WINDOW, 64);
        assert_eq!(MAX_FUTURE_SKEW_SECS, 300);
    }

    #[test]
    fn empty_key_set_is_rejected() {
        let error = SessionAuthority::new(vec![], 1).expect_err("empty key set must fail");

        assert!(
            error.to_string().contains("must not be empty"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn non_adjacent_duplicate_key_versions_are_rejected() {
        let result = SessionAuthority::new(
            vec![
                SessionKeyVersion {
                    version: 1,
                    key: test_key(0x42),
                },
                SessionKeyVersion {
                    version: 2,
                    key: test_key(0x43),
                },
                SessionKeyVersion {
                    version: 1,
                    key: test_key(0x44),
                },
            ],
            1,
        );

        assert!(result.is_err());
    }

    #[test]
    fn ephemeral_authority_roundtrips_and_distinct_instances_diverge() {
        let mut authority = SessionAuthority::ephemeral();
        let mut other = SessionAuthority::ephemeral();

        assert_eq!(authority.active_key_version(), 1);
        assert_eq!(authority.key_version_count(), 1);
        assert_ne!(authority.keys[0].key[..16], [0u8; 16]);
        assert_ne!(authority.keys[0].key[16..], [0u8; 16]);
        assert_ne!(authority.keys[0].key, other.keys[0].key);

        let session_id = SessionId::new();
        let cookie = authority.mint_cookie_value(session_id, NOW);

        let own = authority.resolve(cookie_header(&cookie), Some(peer()), NOW);
        assert_eq!(own.cookie_outcome, CookieOutcome::Valid);
        assert_eq!(own.session_id, session_id);

        let foreign = other.resolve(cookie_header(&cookie), Some(peer()), NOW);
        assert_eq!(foreign.cookie_outcome, CookieOutcome::BadSignature);
        assert_ne!(foreign.session_id, session_id);
    }

    #[test]
    fn valid_cookie_reanchors_lab_peer_without_inheriting_another_sessions_floor() {
        let mut authority = test_authority();
        let session_a = SessionId::new();
        let session_b = SessionId::new();
        let cookie_a = authority.mint_cookie_value(session_a, NOW);
        let cookie_b = authority.mint_cookie_value(session_b, NOW);

        let presented_a = authority.resolve(cookie_header(&cookie_a), Some(peer()), NOW);
        assert_eq!(presented_a.cookie_outcome, CookieOutcome::Valid);
        authority.note_enforcement(Some(peer()), session_a, PolicyState::Blocked, NOW + 1);

        let presented_b = authority.resolve(cookie_header(&cookie_b), Some(peer()), NOW + 2);
        assert_eq!(presented_b.cookie_outcome, CookieOutcome::Valid);
        assert_eq!(presented_b.session_id, session_b);
        assert_eq!(
            presented_b.continuity_outcome,
            ContinuityOutcome::NotApplicable
        );
        assert_eq!(presented_b.enforcement_floor, None);
        assert!(presented_b.from_cookie());

        let after_cooldown = authority.resolve(
            [("Host", "proxy.local")],
            Some(peer()),
            NOW + 1 + CONTINUITY_RECOVERY_COOLDOWN_SECS,
        );
        assert_eq!(
            after_cooldown.continuity_outcome,
            ContinuityOutcome::Recovered
        );
        assert_eq!(after_cooldown.session_id, session_b);
    }

    #[test]
    fn conflicting_valid_cookie_refreshes_stable_continuity_freshness() {
        let mut authority = test_authority();
        let continuity_key = ingress_key("client_A_0123456789abcdef");
        let original =
            authority.resolve_with_continuity([("Host", "proxy.local")], Some(continuity_key), NOW);
        authority.resolve_with_continuity([("Host", "proxy.local")], Some(continuity_key), NOW + 1);

        let session_b = SessionId::new();
        let cookie_b = authority.mint_cookie_value(session_b, NOW + 2);
        let presented_b = authority.resolve_with_continuity(
            cookie_header(&cookie_b),
            Some(continuity_key),
            NOW + 2,
        );
        assert_eq!(presented_b.cookie_outcome, CookieOutcome::Valid);
        assert_eq!(presented_b.session_id, original.session_id);
        assert_eq!(
            presented_b.continuity_outcome,
            ContinuityOutcome::ContinuitySessionPreserved
        );

        // Just before the TTL horizon measured from the conflict, the stable
        // record must still be fresh without adopting the cookie's session.
        let late = authority.resolve_with_continuity(
            [("Host", "proxy.local")],
            Some(continuity_key),
            NOW + 2 + DEFAULT_CONTINUITY_TTL_SECS - 1,
        );
        assert_eq!(late.continuity_outcome, ContinuityOutcome::Recovered);
        assert_eq!(late.session_id, original.session_id);
    }

    #[test]
    fn minted_cookie_matches_golden_vector() {
        let authority = SessionAuthority::from_key_file_json(
            br#"{
                "active_key_version": 1,
                "keys": [
                    {"version": 1, "key_hex": "4242424242424242424242424242424242424242424242424242424242424242"}
                ]
            }"#,
        )
        .expect("golden key file should parse");
        let session_id = SessionId(
            uuid::Uuid::parse_str("11111111-1111-4111-8111-111111111111")
                .expect("fixed uuid should parse"),
        );

        let cookie = authority.mint_cookie_value(session_id, NOW);

        assert_eq!(
            cookie,
            "v1.1.1750000000.11111111-1111-4111-8111-111111111111.\
             37975ff83d3bc77fdbbd41755a89f1b228e1bd746ef1d754f7a6d54b72cb3646"
        );
    }

    #[test]
    fn continuity_ttl_boundary_is_exact() {
        let mut at_boundary = test_authority();
        let original = at_boundary.resolve([("Host", "proxy.local")], Some(peer()), NOW);

        let expired = at_boundary.resolve(
            [("Host", "proxy.local")],
            Some(peer()),
            NOW + DEFAULT_CONTINUITY_TTL_SECS,
        );
        assert_eq!(expired.continuity_outcome, ContinuityOutcome::NoRecord);
        assert_ne!(expired.session_id, original.session_id);

        let mut just_before = test_authority();
        let original = just_before.resolve([("Host", "proxy.local")], Some(peer()), NOW);

        let still_valid = just_before.resolve(
            [("Host", "proxy.local")],
            Some(peer()),
            NOW + DEFAULT_CONTINUITY_TTL_SECS - 1,
        );
        assert_eq!(still_valid.continuity_outcome, ContinuityOutcome::Recovered);
        assert_eq!(still_valid.session_id, original.session_id);
    }

    #[test]
    fn wrong_format_tag_is_malformed_even_with_a_valid_signature() {
        let mut authority = test_authority();
        let session_id = SessionId::new();
        let payload = format!("v2.1.{}.{}", NOW, session_id.0);
        let cookie = format!("{}.{}", payload, authority.sign_with(1, &payload));

        let resolution = authority.resolve(cookie_header(&cookie), Some(peer()), NOW);

        assert_eq!(resolution.cookie_outcome, CookieOutcome::Malformed);
        assert_ne!(resolution.session_id, session_id);
    }

    #[test]
    fn non_hex_mac_is_malformed_not_bad_signature() {
        let mut authority = test_authority();
        let session_id = SessionId::new();
        let cookie = format!(
            "{}.1.{}.{}.{}",
            COOKIE_FORMAT_TAG,
            NOW,
            session_id.0,
            "z".repeat(MAC_HEX_CHARS)
        );

        let resolution = authority.resolve(cookie_header(&cookie), Some(peer()), NOW);

        assert_eq!(resolution.cookie_outcome, CookieOutcome::Malformed);
    }

    #[test]
    fn wrong_length_hex_mac_is_malformed() {
        let mut authority = test_authority();
        let session_id = SessionId::new();
        let short_mac = format!(
            "{}.1.{}.{}.{}",
            COOKIE_FORMAT_TAG,
            NOW,
            session_id.0,
            "a".repeat(MAC_HEX_CHARS - 1)
        );

        let resolution = authority.resolve(cookie_header(&short_mac), Some(peer()), NOW);

        assert_eq!(resolution.cookie_outcome, CookieOutcome::Malformed);
    }

    #[test]
    fn non_hex_key_in_key_file_is_rejected() {
        let json = br#"{
            "active_key_version": 1,
            "keys": [
                {"version": 1, "key_hex": "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}
            ]
        }"#;

        assert!(SessionAuthority::from_key_file_json(json).is_err());
    }

    #[test]
    fn wrong_length_key_in_key_file_is_rejected() {
        let json = br#"{
            "active_key_version": 1,
            "keys": [
                {"version": 1, "key_hex": "4242"}
            ]
        }"#;

        assert!(SessionAuthority::from_key_file_json(json).is_err());
    }

    #[test]
    fn hex_codec_decodes_both_cases_and_rejects_non_hex() {
        assert_eq!(decode_hex_nibble(b'0'), Some(0));
        assert_eq!(decode_hex_nibble(b'9'), Some(9));
        assert_eq!(decode_hex_nibble(b'a'), Some(10));
        assert_eq!(decode_hex_nibble(b'f'), Some(15));
        assert_eq!(decode_hex_nibble(b'A'), Some(10));
        assert_eq!(decode_hex_nibble(b'F'), Some(15));
        assert_eq!(decode_hex_nibble(b'g'), None);
        assert_eq!(decode_hex_nibble(b' '), None);

        let bytes = [0x00, 0xab, 0xff, 0x10];
        assert_eq!(encode_hex(&bytes), "00abff10");
        assert_eq!(
            decode_mac_hex("00abff10"),
            None,
            "short inputs must not decode as a mac"
        );
    }

    #[test]
    fn enforcement_ranks_are_strictly_ordered() {
        let ladder = [
            PolicyState::Normal,
            PolicyState::Observe,
            PolicyState::Suspicious,
            PolicyState::RateLimited,
            PolicyState::ControlledReality,
            PolicyState::Blocked,
        ];

        for pair in ladder.windows(2) {
            assert!(
                enforcement_rank(pair[0]) < enforcement_rank(pair[1]),
                "{:?} must outrank {:?}",
                pair[1],
                pair[0]
            );
        }
    }

    #[test]
    fn cookie_pairs_in_non_cookie_headers_are_ignored() {
        let mut authority = test_authority();
        let session_id = SessionId::new();
        let cookie = authority.mint_cookie_value(session_id, NOW);

        let resolution = authority.resolve(
            [("X-Forwarded-Cookie", format!("eidolon_session={cookie}"))],
            Some(peer()),
            NOW,
        );

        assert_eq!(resolution.cookie_outcome, CookieOutcome::Absent);
        assert_ne!(resolution.session_id, session_id);
    }

    #[test]
    fn note_enforcement_creates_a_record_for_an_unseen_peer() {
        let mut authority = test_authority();
        let session_id = SessionId::new();

        authority.note_enforcement(Some(peer()), session_id, PolicyState::RateLimited, NOW);

        let resolution = authority.resolve([("Host", "proxy.local")], Some(peer()), NOW + 1);
        assert_eq!(resolution.continuity_outcome, ContinuityOutcome::Recovered);
        assert_eq!(resolution.session_id, session_id);
        assert_eq!(resolution.enforcement_floor, Some(PolicyState::RateLimited));
    }

    #[test]
    fn note_enforcement_does_not_rebind_existing_continuity() {
        let mut authority = test_authority();
        let continuity_key = ingress_key("client_A_0123456789abcdef");
        let original =
            authority.resolve_with_continuity([("Host", "proxy.local")], Some(continuity_key), NOW);
        let unrelated_session = SessionId::new();

        authority.note_enforcement_with_continuity(
            Some(continuity_key),
            unrelated_session,
            PolicyState::Blocked,
            NOW + 1,
        );

        let record = authority
            .continuity
            .get(&continuity_key)
            .expect("continuity record should remain present");
        assert_eq!(record.session_id, original.session_id);
        assert_eq!(record.floor, None);
        let recovered = authority.resolve_with_continuity(
            [("Host", "proxy.local")],
            Some(continuity_key),
            NOW + 2,
        );
        assert_eq!(recovered.session_id, original.session_id);
        assert_eq!(recovered.enforcement_floor, None);
    }

    #[test]
    fn expired_continuity_records_are_evicted_from_the_map() {
        let mut authority = test_authority();
        let stale_peer: IpAddr = "127.0.0.9".parse().expect("peer IP should parse");
        authority.resolve([("Host", "proxy.local")], Some(stale_peer), NOW);
        authority.resolve([("Host", "proxy.local")], Some(peer()), NOW);
        assert_eq!(authority.continuity.len(), 2);

        let after_expiry = NOW + DEFAULT_CONTINUITY_TTL_SECS + 10;
        authority.resolve([("Host", "proxy.local")], Some(peer()), after_expiry);

        let stale_key = ContinuityKey::lab_peer(stale_peer);
        assert!(!authority.continuity.contains_key(&stale_key));
        assert_eq!(authority.continuity.len(), 1);
        assert_eq!(
            authority.continuity_order.len(),
            authority.continuity.len(),
            "eviction must keep the FIFO order deque in sync with the map"
        );
        assert!(!authority.continuity_order.contains(&stale_key));

        authority.resolve([("Host", "proxy.local")], Some(stale_peer), NOW + 1);
        assert_eq!(authority.continuity.len(), 2);
        authority.note_enforcement(
            Some(peer()),
            SessionId::new(),
            PolicyState::Observe,
            after_expiry,
        );
        assert!(!authority.continuity.contains_key(&stale_key));
    }

    #[test]
    fn durable_authenticated_continuity_survives_restart_without_raw_identity_storage() {
        let dir = TestDir::new();
        let state_path = dir.path("continuity.json");
        let continuity_key = ingress_key("signed-agent-primary");
        let mut authority = test_authority();
        authority
            .enable_durable_continuity(&state_path, "edge-secret", false, NOW)
            .expect("durable continuity should initialize");

        let first = authority.resolve_with_continuity(
            [("Host", "proxy.local")],
            Some(continuity_key),
            NOW + 1,
        );
        authority.note_enforcement_with_continuity(
            Some(continuity_key),
            first.session_id,
            PolicyState::ControlledReality,
            NOW + 2,
        );
        let checkpointed = authority.resolve_with_continuity(
            [("Host", "proxy.local")],
            Some(continuity_key),
            NOW + CONTINUITY_CHECKPOINT_INTERVAL_SECS + 2,
        );
        assert_eq!(checkpointed.session_id, first.session_id);
        assert_eq!(
            checkpointed.enforcement_floor,
            Some(PolicyState::ControlledReality)
        );

        let serialized =
            fs::read_to_string(&state_path).expect("continuity sidecar should be readable");
        assert!(!serialized.contains("signed-agent-primary"));
        assert!(!serialized.contains("edge-secret"));

        let mut restored = test_authority();
        let startup = restored
            .enable_durable_continuity(
                &state_path,
                "edge-secret",
                true,
                NOW + CONTINUITY_CHECKPOINT_INTERVAL_SECS + 3,
            )
            .expect("continuity state should restore");
        assert_eq!(startup.restored_record_count, 1);
        let after_restart = restored.resolve_with_continuity(
            [("Host", "proxy.local")],
            Some(continuity_key),
            NOW + CONTINUITY_CHECKPOINT_INTERVAL_SECS + 4,
        );
        assert_eq!(after_restart.session_id, first.session_id);
        assert_eq!(
            after_restart.enforcement_floor,
            Some(PolicyState::ControlledReality)
        );
    }

    #[test]
    fn migration_quarantine_rejects_unknown_identity_with_or_without_valid_cookie() {
        let dir = TestDir::new();
        let state_path = dir.path("continuity.json");
        let continuity_key = ingress_key("unknown-after-upgrade");
        let mut authority = test_authority();
        let startup = authority
            .enable_durable_continuity(&state_path, "edge-secret", true, NOW)
            .expect("missing historical sidecar should enter quarantine");
        assert_eq!(
            startup.migration_quarantine_until,
            Some(NOW + DEFAULT_CONTINUITY_TTL_SECS)
        );

        let valid_cookie = authority.mint_cookie_value(SessionId::new(), NOW);
        let with_cookie = authority.resolve_with_continuity(
            cookie_header(&valid_cookie),
            Some(continuity_key),
            NOW + 1,
        );
        assert_eq!(
            with_cookie.continuity_outcome,
            ContinuityOutcome::MigrationQuarantineFailClosed
        );
        assert_eq!(with_cookie.cookie_outcome, CookieOutcome::Valid);
        assert_eq!(with_cookie.set_cookie_value, None);
        assert!(!authority.continuity.contains_key(&continuity_key));

        let without_cookie = authority.resolve_with_continuity(
            [("Host", "proxy.local")],
            Some(continuity_key),
            NOW + 2,
        );
        assert_eq!(
            without_cookie.continuity_outcome,
            ContinuityOutcome::MigrationQuarantineFailClosed
        );
        assert_eq!(without_cookie.set_cookie_value, None);
        assert!(!authority.continuity.contains_key(&continuity_key));
    }

    #[test]
    fn durable_continuity_rejects_continuity_key_mismatch() {
        let dir = TestDir::new();
        let state_path = dir.path("continuity.json");
        let mut authority = test_authority();
        authority
            .enable_durable_continuity(&state_path, "edge-secret", false, NOW)
            .expect("durable continuity should initialize");
        authority.resolve_with_continuity(
            [("Host", "proxy.local")],
            Some(ingress_key("signed-agent-primary")),
            NOW + 1,
        );

        let mut mismatched = test_authority();
        let error = mismatched
            .enable_durable_continuity(&state_path, "rotated-edge-secret", true, NOW + 2)
            .expect_err("active continuity cannot silently change continuity keys");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("does not match"));
    }

    #[test]
    fn durable_mapping_admission_is_temporally_bounded_and_recovers() {
        let dir = TestDir::new();
        let state_path = dir.path("continuity.json");
        let mut authority = test_authority();
        authority
            .enable_durable_continuity(&state_path, "edge-secret", false, NOW)
            .expect("durable continuity should initialize");

        for index in 0..MAX_DURABLE_CONTINUITY_INSERTS_PER_WINDOW {
            let resolution = authority.resolve_with_continuity(
                [("Host", "proxy.local")],
                Some(ingress_key(&format!("admitted-agent-{index}"))),
                NOW + 1,
            );
            assert_eq!(resolution.continuity_outcome, ContinuityOutcome::NoRecord);
        }

        let rejected_key = ingress_key("rate-limited-agent");
        let rejected = authority.resolve_with_continuity(
            [("Host", "proxy.local")],
            Some(rejected_key),
            NOW + 1,
        );
        assert_eq!(
            rejected.continuity_outcome,
            ContinuityOutcome::AdmissionRateFailClosed
        );
        assert_eq!(rejected.set_cookie_value, None);
        assert!(!authority.continuity.contains_key(&rejected_key));

        let admitted_after_window = authority.resolve_with_continuity(
            [("Host", "proxy.local")],
            Some(rejected_key),
            NOW + 1 + DURABLE_CONTINUITY_INSERT_WINDOW_SECS,
        );
        assert_eq!(
            admitted_after_window.continuity_outcome,
            ContinuityOutcome::NoRecord
        );
        assert!(authority.continuity.contains_key(&rejected_key));
    }

    #[test]
    fn pre_rename_storage_failure_rolls_back_new_mapping_and_suppresses_cookie() {
        let dir = TestDir::new();
        let state_path = dir.path("continuity.json");
        let mut authority = test_authority();
        authority
            .enable_durable_continuity(&state_path, "edge-secret", false, NOW)
            .expect("durable continuity should initialize");

        let mut temp_path = state_path.as_os_str().to_os_string();
        temp_path.push(".tmp");
        let temp_path = PathBuf::from(temp_path);
        fs::create_dir(&temp_path).expect("blocking temp directory should be created");

        let continuity_key = ingress_key("write-failure-agent");
        let failed = authority.resolve_with_continuity(
            [("Host", "proxy.local")],
            Some(continuity_key),
            NOW + 1,
        );
        assert_eq!(
            failed.continuity_outcome,
            ContinuityOutcome::StorageUnavailable
        );
        assert_eq!(failed.set_cookie_value, None);
        assert!(!authority.continuity.contains_key(&continuity_key));

        fs::remove_dir(&temp_path).expect("blocking temp directory should be removed");
        let retried = authority.resolve_with_continuity(
            [("Host", "proxy.local")],
            Some(continuity_key),
            NOW + 2,
        );
        assert_eq!(retried.continuity_outcome, ContinuityOutcome::NoRecord);
        assert!(authority.continuity.contains_key(&continuity_key));
    }

    #[test]
    fn recovery_count_tracks_recoveries_and_resets_on_valid_cookie() {
        let mut authority = test_authority();
        authority.resolve([("Host", "proxy.local")], Some(peer()), NOW);

        let first = authority.resolve([("Host", "proxy.local")], Some(peer()), NOW + 5);
        assert_eq!(first.continuity_outcome, ContinuityOutcome::Recovered);
        assert_eq!(
            authority
                .continuity
                .get(&peer_key())
                .map(|record| record.recovery_count),
            Some(1)
        );

        let limited = authority.resolve([("Host", "proxy.local")], Some(peer()), NOW + 6);
        assert_eq!(
            limited.continuity_outcome,
            ContinuityOutcome::CooldownLimited
        );
        assert_eq!(
            authority
                .continuity
                .get(&peer_key())
                .map(|record| record.recovery_count),
            Some(1),
            "cooldown-limited mints must not count as recoveries"
        );

        let cookie = authority.mint_cookie_value(limited.session_id, NOW + 7);
        let presented = authority.resolve(cookie_header(&cookie), Some(peer()), NOW + 7);
        assert_eq!(presented.cookie_outcome, CookieOutcome::Valid);
        assert_eq!(
            authority
                .continuity
                .get(&peer_key())
                .map(|record| record.recovery_count),
            Some(0),
            "a valid cookie matching the stable session resets recovery count"
        );
    }
}
