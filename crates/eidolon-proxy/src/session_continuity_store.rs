//! Durable sidecar storage for authenticated-ingress session continuity.
//!
//! The schema intentionally stores only keyed continuity digests. Raw ingress
//! identity and Lab peer continuity are not representable.

use std::{
    collections::HashSet,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use eidolon_core::{PolicyState, SessionId};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SESSION_CONTINUITY_SCHEMA_VERSION: u16 = 2;
pub const MIN_SUPPORTED_SESSION_CONTINUITY_SCHEMA_VERSION: u16 = 1;
pub const MAX_CONTINUITY_RECORDS: usize = 4096;
pub const MAX_CONTINUITY_STORE_BYTES: usize = 2 * 1024 * 1024;

const SHA256_HEX_LEN: usize = 64;
const INTEGRITY_KEY_DOMAIN: &[u8] = b"eidolon-continuity:sidecar-integrity-key:v1\0";
const INTEGRITY_MAC_DOMAIN: &[u8] = b"eidolon-continuity:sidecar-state:v1\0";

type StoreMac = Hmac<Sha256>;

/// Domain-separated key used only to authenticate the continuity sidecar.
///
/// The configured continuity key is never retained. Debug output is
/// intentionally redacted because this derived key can authenticate state.
#[derive(Clone, PartialEq, Eq)]
pub struct IntegrityKey([u8; 32]);

impl IntegrityKey {
    pub fn derive(continuity_key: &str) -> io::Result<Self> {
        if continuity_key.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "continuity integrity key requires a non-empty continuity key",
            ));
        }
        let mut mac = <StoreMac as KeyInit>::new_from_slice(continuity_key.as_bytes())
            .expect("HMAC-SHA256 accepts any continuity key length");
        mac.update(INTEGRITY_KEY_DOMAIN);
        Ok(Self(mac.finalize().into_bytes().into()))
    }
}

impl fmt::Debug for IntegrityKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IntegrityKey(<redacted>)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub schema_version: u16,
    /// Historical schema field name for the domain-separated key identifier
    /// used to derive continuity digests and authenticate this sidecar.
    pub transport_key_id_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration_quarantine_until: Option<u64>,
    /// Records preserve the authority's continuity eviction order.
    pub records: Vec<Record>,
    /// HMAC-SHA256 over every preceding semantic field in canonical form.
    pub integrity_mac_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// Lowercase SHA-256/HMAC digest. Never a raw ingress identity.
    pub key_digest_hex: String,
    /// Domain-separated identifier for the key that derived this binding.
    /// Schema v1 records omit it and inherit the state-level key identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuity_key_id_hex: Option<String>,
    pub session_id: SessionId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforcement_floor: Option<PolicyState>,
    pub last_seen: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_recovery_at: Option<u64>,
    pub recovery_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitOutcome {
    Durable,
    /// The replacement was renamed into place, but syncing its parent
    /// directory failed. The caller must treat the write as committed.
    CommittedDurabilityUncertain,
}

pub type StoredContinuityState = State;
pub type StoredContinuityRecord = Record;
pub type StateCommitOutcome = CommitOutcome;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotFingerprint {
    metadata: Option<FileFingerprint>,
    temp_metadata: Option<FileFingerprint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileFingerprint {
    len: u64,
    sha256: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct PreparedContinuityStartup {
    pub path: PathBuf,
    pub loaded: Option<State>,
    pub fingerprint: SnapshotFingerprint,
}

pub fn prepare_startup(
    path: impl AsRef<Path>,
    key_candidates: &[(&str, &IntegrityKey)],
) -> io::Result<PreparedContinuityStartup> {
    let path = path.as_ref();
    validate_temporary_path(path)?;
    let (loaded, metadata) = load_snapshot_with_key_candidates(path, key_candidates)?;
    let fingerprint = SnapshotFingerprint {
        metadata,
        temp_metadata: file_fingerprint(&temporary_path(path)?)?,
    };
    Ok(PreparedContinuityStartup {
        path: path.to_path_buf(),
        loaded,
        fingerprint,
    })
}

pub fn verify_prepared_snapshot(prepared: &PreparedContinuityStartup) -> io::Result<()> {
    validate_temporary_path(&prepared.path)?;
    let current = snapshot_fingerprint(&prepared.path)?;
    if current != prepared.fingerprint {
        return Err(invalid_data(
            "session continuity store changed after startup preparation",
        ));
    }
    Ok(())
}

pub fn commit_prepared_startup(
    prepared: &PreparedContinuityStartup,
    state: &State,
    integrity_key: &IntegrityKey,
) -> io::Result<CommitOutcome> {
    verify_prepared_snapshot(prepared)?;
    let _ = serialize(state, integrity_key)?;
    persist(&prepared.path, state, integrity_key)
}

pub fn validate_canonical_state(state: &State, integrity_key: &IntegrityKey) -> io::Result<()> {
    serialize(state, integrity_key).map(drop)
}

pub fn load(
    path: impl AsRef<Path>,
    integrity_key: &IntegrityKey,
    expected_transport_key_id_hex: &str,
) -> io::Result<Option<State>> {
    load_with_key_candidates(path, &[(expected_transport_key_id_hex, integrity_key)])
}

/// Read one snapshot and verify it with the exactly matching configured key.
///
/// The state-level identifier selects the candidate before MAC verification;
/// the loader never treats a failed MAC under one key as permission to try an
/// unrelated key.
pub fn load_with_key_candidates(
    path: impl AsRef<Path>,
    key_candidates: &[(&str, &IntegrityKey)],
) -> io::Result<Option<State>> {
    load_snapshot_with_key_candidates(path.as_ref(), key_candidates).map(|(state, _)| state)
}

fn load_snapshot_with_key_candidates(
    path: &Path,
    key_candidates: &[(&str, &IntegrityKey)],
) -> io::Result<(Option<State>, Option<FileFingerprint>)> {
    let _path_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => metadata,
        Ok(_) => {
            return Err(invalid_data(format!(
                "session continuity store path `{}` is not a regular file",
                path.display()
            )));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok((None, None)),
        Err(error) => return Err(error),
    };
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid_data(format!(
            "session continuity store path `{}` is not a regular file",
            path.display()
        )));
    }

    let mut bytes = Vec::new();
    file.take((MAX_CONTINUITY_STORE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() {
        return Err(invalid_data(format!(
            "session continuity store `{}` is empty",
            path.display()
        )));
    }
    if bytes.len() > MAX_CONTINUITY_STORE_BYTES {
        return Err(invalid_data(format!(
            "session continuity store `{}` exceeds {} bytes",
            path.display(),
            MAX_CONTINUITY_STORE_BYTES
        )));
    }

    let state: State = serde_json::from_slice(&bytes).map_err(|error| {
        invalid_data(format!(
            "could not parse session continuity store `{}`: {error}",
            path.display()
        ))
    })?;
    validate_signed(&state)?;

    if key_candidates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "at least one continuity state integrity key is required",
        ));
    }
    let mut matching = key_candidates
        .iter()
        .filter(|(key_id_hex, _)| *key_id_hex == state.transport_key_id_hex);
    let Some((_, integrity_key)) = matching.next() else {
        return Err(invalid_data(
            "continuity state key identifier does not match the configured continuity key",
        ));
    };
    if matching.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "configured continuity state key identifiers must be unique",
        ));
    }
    verify_integrity(&state, integrity_key)?;
    let fingerprint = FileFingerprint {
        len: bytes.len() as u64,
        sha256: Sha256::digest(&bytes).into(),
    };
    Ok((Some(state), Some(fingerprint)))
}

pub fn persist(
    path: impl AsRef<Path>,
    state: &State,
    integrity_key: &IntegrityKey,
) -> io::Result<CommitOutcome> {
    persist_with(
        path.as_ref(),
        state,
        integrity_key,
        |file, bytes| file.write_all(bytes),
        sync_parent,
    )
}

pub fn load_state(
    path: impl AsRef<Path>,
    integrity_key: &IntegrityKey,
    expected_transport_key_id_hex: &str,
) -> io::Result<Option<State>> {
    load(path, integrity_key, expected_transport_key_id_hex)
}

pub fn persist_state(
    path: impl AsRef<Path>,
    state: &State,
    integrity_key: &IntegrityKey,
) -> io::Result<CommitOutcome> {
    persist(path, state, integrity_key)
}

fn validate_semantics(state: &State) -> io::Result<()> {
    if !(MIN_SUPPORTED_SESSION_CONTINUITY_SCHEMA_VERSION..=SESSION_CONTINUITY_SCHEMA_VERSION)
        .contains(&state.schema_version)
    {
        return Err(invalid_data(format!(
            "unsupported session continuity schema version {}; expected {}..={}",
            state.schema_version,
            MIN_SUPPORTED_SESSION_CONTINUITY_SCHEMA_VERSION,
            SESSION_CONTINUITY_SCHEMA_VERSION
        )));
    }
    validate_lower_hex(&state.transport_key_id_hex, "transport_key_id_hex")?;
    if state.migration_quarantine_until == Some(0) {
        return Err(invalid_data(
            "migration_quarantine_until must be a non-zero Unix timestamp",
        ));
    }
    if state.records.len() > MAX_CONTINUITY_RECORDS {
        return Err(invalid_data(format!(
            "session continuity store has {} records; maximum is {}",
            state.records.len(),
            MAX_CONTINUITY_RECORDS
        )));
    }

    let mut digests = HashSet::with_capacity(state.records.len());
    let mut sessions = HashSet::with_capacity(state.records.len());
    for record in &state.records {
        validate_lower_hex(&record.key_digest_hex, "key_digest_hex")?;
        match (
            state.schema_version,
            record.continuity_key_id_hex.as_deref(),
        ) {
            (1, None) => {}
            (1, Some(_)) => {
                return Err(invalid_data(
                    "schema-v1 continuity records must not contain a key identifier",
                ));
            }
            (_, Some(key_id_hex)) => {
                validate_lower_hex(key_id_hex, "continuity_key_id_hex")?;
            }
            (_, None) => {
                return Err(invalid_data(
                    "schema-v2 continuity records require a key identifier",
                ));
            }
        }
        if !digests.insert(record.key_digest_hex.as_str()) {
            return Err(invalid_data("duplicate continuity digest"));
        }
        if !sessions.insert(record.session_id) {
            return Err(invalid_data("duplicate continuity session id"));
        }
        if record.last_seen == 0 {
            return Err(invalid_data("record last_seen must be non-zero"));
        }
        match (record.last_recovery_at, record.recovery_count) {
            (None, 0) => {}
            (Some(recovered_at), count)
                if recovered_at > 0 && recovered_at <= record.last_seen && count > 0 => {}
            (Some(_), 0) => {
                return Err(invalid_data(
                    "record with last_recovery_at must have a recovery_count",
                ));
            }
            (None, _) => {
                return Err(invalid_data(
                    "record with recovery_count must have last_recovery_at",
                ));
            }
            (Some(_), _) => {
                return Err(invalid_data(
                    "record last_recovery_at must be non-zero and not after last_seen",
                ));
            }
        }
    }
    Ok(())
}

fn validate_signed(state: &State) -> io::Result<()> {
    validate_semantics(state)?;
    validate_lower_hex(&state.integrity_mac_hex, "integrity_mac_hex")
}

fn validate_lower_hex(value: &str, field: &str) -> io::Result<()> {
    if value.len() != SHA256_HEX_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_data(format!(
            "{field} must be exactly {SHA256_HEX_LEN} lowercase hex characters"
        )));
    }
    Ok(())
}

#[derive(Serialize)]
struct IntegrityPayload<'a> {
    schema_version: u16,
    transport_key_id_hex: &'a str,
    migration_quarantine_until: Option<u64>,
    records: &'a [Record],
}

fn integrity_payload(state: &State) -> io::Result<Vec<u8>> {
    validate_semantics(state)?;
    serde_json::to_vec(&IntegrityPayload {
        schema_version: state.schema_version,
        transport_key_id_hex: &state.transport_key_id_hex,
        migration_quarantine_until: state.migration_quarantine_until,
        records: &state.records,
    })
    .map_err(|error| {
        invalid_data(format!(
            "could not serialize session continuity integrity payload: {error}"
        ))
    })
}

fn integrity_mac(state: &State, integrity_key: &IntegrityKey) -> io::Result<[u8; 32]> {
    let payload = integrity_payload(state)?;
    let mut mac = <StoreMac as KeyInit>::new_from_slice(&integrity_key.0)
        .expect("HMAC-SHA256 accepts a 32-byte integrity key");
    mac.update(INTEGRITY_MAC_DOMAIN);
    mac.update(&(payload.len() as u64).to_be_bytes());
    mac.update(&payload);
    Ok(mac.finalize().into_bytes().into())
}

fn sign_state(state: &State, integrity_key: &IntegrityKey) -> io::Result<State> {
    let mut signed = state.clone();
    signed.integrity_mac_hex = encode_hex(&integrity_mac(&signed, integrity_key)?);
    Ok(signed)
}

fn verify_integrity(state: &State, integrity_key: &IntegrityKey) -> io::Result<()> {
    let presented = decode_sha256_hex(&state.integrity_mac_hex).ok_or_else(|| {
        invalid_data("integrity_mac_hex must be exactly 64 lowercase hex characters")
    })?;
    let mut verifier = <StoreMac as KeyInit>::new_from_slice(&integrity_key.0)
        .expect("HMAC-SHA256 accepts a 32-byte integrity key");
    verifier.update(INTEGRITY_MAC_DOMAIN);
    let payload = integrity_payload(state)?;
    verifier.update(&(payload.len() as u64).to_be_bytes());
    verifier.update(&payload);
    verifier
        .verify_slice(&presented)
        .map_err(|_| invalid_data("session continuity store integrity verification failed"))?;
    Ok(())
}

fn serialize(state: &State, integrity_key: &IntegrityKey) -> io::Result<Vec<u8>> {
    let signed = sign_state(state, integrity_key)?;
    validate_signed(&signed)?;
    let mut bytes = serde_json::to_vec_pretty(&signed).map_err(|error| {
        invalid_data(format!(
            "could not serialize session continuity store: {error}"
        ))
    })?;
    bytes.push(b'\n');
    if bytes.len() > MAX_CONTINUITY_STORE_BYTES {
        return Err(invalid_data(format!(
            "serialized session continuity store exceeds {} bytes",
            MAX_CONTINUITY_STORE_BYTES
        )));
    }
    Ok(bytes)
}

fn persist_with(
    path: &Path,
    state: &State,
    integrity_key: &IntegrityKey,
    write_payload: impl FnOnce(&mut File, &[u8]) -> io::Result<()>,
    sync_parent_directory: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<CommitOutcome> {
    let bytes = serialize(state, integrity_key)?;
    let temp_path = temporary_path(path)?;
    match fs::remove_file(&temp_path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut renamed = false;

    let result = (|| {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp_path)?;
        write_payload(&mut file, &bytes)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);

        fs::rename(&temp_path, path)?;
        renamed = true;
        match sync_parent_directory(path) {
            Ok(()) => Ok(CommitOutcome::Durable),
            Err(_) => Ok(CommitOutcome::CommittedDurabilityUncertain),
        }
    })();

    if !renamed {
        let _ = fs::remove_file(temp_path);
    }
    result
}

fn temporary_path(path: &Path) -> io::Result<PathBuf> {
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "session continuity store path must name a file",
        )
    })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut name = file_name.to_os_string();
    name.push(".tmp");
    Ok(parent.join(name))
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn snapshot_fingerprint(path: &Path) -> io::Result<SnapshotFingerprint> {
    Ok(SnapshotFingerprint {
        metadata: file_fingerprint(path)?,
        temp_metadata: file_fingerprint(&temporary_path(path)?)?,
    })
}

fn file_fingerprint(path: &Path) -> io::Result<Option<FileFingerprint>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                return Err(invalid_data(format!(
                    "session continuity store path `{}` is not a regular file",
                    path.display()
                )));
            }
            let file = File::open(path)?;
            let mut bytes = Vec::new();
            file.take((MAX_CONTINUITY_STORE_BYTES + 1) as u64)
                .read_to_end(&mut bytes)?;
            if bytes.len() > MAX_CONTINUITY_STORE_BYTES {
                return Err(invalid_data(format!(
                    "session continuity store `{}` exceeds {} bytes",
                    path.display(),
                    MAX_CONTINUITY_STORE_BYTES
                )));
            }
            let sha256 = Sha256::digest(&bytes).into();
            Ok(Some(FileFingerprint {
                len: metadata.len(),
                sha256,
            }))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn validate_temporary_path(path: &Path) -> io::Result<()> {
    let temp_path = temporary_path(path)?;
    match fs::symlink_metadata(&temp_path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(invalid_data(
            "session continuity temporary path is not a regular file",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn decode_sha256_hex(raw: &str) -> Option<[u8; 32]> {
    if raw.len() != SHA256_HEX_LEN {
        return None;
    }
    let mut decoded = [0u8; 32];
    for (index, chunk) in raw.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (decode_hex_nibble(chunk[0])? << 4) | decode_hex_nibble(chunk[1])?;
    }
    Some(decoded)
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use uuid::Uuid;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("eidolon-continuity-store-test-{}", Uuid::new_v4()));
            fs::create_dir(&path).expect("create test directory");
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

    fn record(byte: u8, session: u128) -> Record {
        Record {
            key_digest_hex: format!("{byte:02x}").repeat(32),
            continuity_key_id_hex: Some("ab".repeat(32)),
            session_id: SessionId(Uuid::from_u128(session)),
            enforcement_floor: Some(PolicyState::Blocked),
            last_seen: 200,
            last_recovery_at: Some(100),
            recovery_count: 1,
        }
    }

    fn state() -> State {
        State {
            schema_version: SESSION_CONTINUITY_SCHEMA_VERSION,
            transport_key_id_hex: "ab".repeat(32),
            migration_quarantine_until: Some(300),
            records: vec![record(1, 1), record(2, 2)],
            integrity_mac_hex: String::new(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn prepared_startup_rejects_a_symlinked_committed_path() {
        use std::os::unix::fs::symlink;

        let dir = TestDir::new();
        let victim = dir.path("victim.json");
        let path = dir.path("continuity.json");
        let key = IntegrityKey::derive("continuity-key").unwrap();
        persist(&victim, &state(), &key).expect("victim fixture should persist");
        let victim_before = fs::read(&victim).expect("victim fixture should read");
        symlink(&victim, &path).expect("committed sidecar symlink should create");

        let error = prepare_startup(&path, &[("ab", &key)])
            .expect_err("committed sidecar symlink must fail closed");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("not a regular file"));
        assert_eq!(fs::read(&victim).unwrap(), victim_before);
        assert!(fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    fn v1_state() -> State {
        let mut state = state();
        state.schema_version = 1;
        for record in &mut state.records {
            record.continuity_key_id_hex = None;
        }
        state
    }

    fn integrity_key() -> IntegrityKey {
        IntegrityKey::derive("test-transport-secret").expect("derive integrity key")
    }

    fn load_test(path: &Path) -> io::Result<Option<State>> {
        load(path, &integrity_key(), &"ab".repeat(32))
    }

    fn persist_test(path: &Path, state: &State) -> io::Result<CommitOutcome> {
        persist(path, state, &integrity_key())
    }

    fn prepare_test(path: &Path) -> io::Result<PreparedContinuityStartup> {
        prepare_startup(path, &[(&"ab".repeat(32), &integrity_key())])
    }

    fn verified_state(path: &Path) -> State {
        load_test(path)
            .expect("load verified state")
            .expect("state should exist")
    }

    fn assert_tamper_rejected(mutate: impl FnOnce(&mut State)) {
        let dir = TestDir::new();
        let path = dir.path("continuity.json");
        persist_test(&path, &state()).expect("persist baseline");
        let mut tampered = verified_state(&path);
        mutate(&mut tampered);
        fs::write(
            &path,
            serde_json::to_vec_pretty(&tampered).expect("serialize tampered state"),
        )
        .expect("write tampered state");
        let error = load_test(&path).expect_err("tampered state must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn prepared_startup_is_read_only_for_missing_valid_v1_and_stale_regular_temp() {
        let dir = TestDir::new();
        let path = dir.path("continuity.json");
        let temp_path = dir.path("continuity.json.tmp");

        let missing = prepare_test(&path).expect("missing state should prepare");
        assert_eq!(missing.loaded, None);
        assert!(!path.exists());
        assert!(!temp_path.exists());

        persist_test(&path, &v1_state()).expect("persist v1 state");
        let original = fs::read(&path).expect("read v1 state");
        let prepared = prepare_test(&path).expect("v1 state should prepare without rewrite");
        assert_eq!(prepared.loaded.as_ref().unwrap().schema_version, 1);
        assert_eq!(fs::read(&path).expect("reread v1 state"), original);
        assert!(!temp_path.exists());

        fs::write(&temp_path, b"stale crash residue").expect("write stale regular temp");
        let temp_original = fs::read(&temp_path).expect("read stale temp");
        prepare_test(&path).expect("regular stale temp should prepare without deletion");
        assert_eq!(fs::read(&path).expect("reread v1 state"), original);
        assert_eq!(
            fs::read(&temp_path).expect("reread stale temp"),
            temp_original
        );
    }

    #[test]
    fn prepared_startup_rejects_nonregular_temp_without_mutation() {
        let dir = TestDir::new();
        let path = dir.path("continuity.json");
        let temp_path = dir.path("continuity.json.tmp");
        persist_test(&path, &state()).expect("persist state");
        let original = fs::read(&path).expect("read state");

        fs::create_dir(&temp_path).expect("create temp directory");
        let error = prepare_test(&path).expect_err("directory temp must fail prepare");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "session continuity temporary path is not a regular file"
        );
        assert_eq!(fs::read(&path).expect("reread state"), original);
        assert!(fs::metadata(&temp_path).unwrap().is_dir());
        fs::remove_dir(&temp_path).expect("remove temp directory");

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(&path, &temp_path).expect("create temp symlink");
            let error = prepare_test(&path).expect_err("symlink temp must fail prepare");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(
                error.to_string(),
                "session continuity temporary path is not a regular file"
            );
            assert_eq!(
                fs::read(&path).expect("reread state after symlink"),
                original
            );
            assert!(fs::symlink_metadata(&temp_path)
                .expect("temp symlink metadata")
                .file_type()
                .is_symlink());
        }
    }

    #[test]
    fn prepared_commit_detects_sidecar_and_temp_races_before_replacement() {
        let dir = TestDir::new();
        let path = dir.path("continuity.json");
        let temp_path = dir.path("continuity.json.tmp");
        persist_test(&path, &state()).expect("persist state");
        let original = fs::read(&path).expect("read state");
        let prepared = prepare_test(&path).expect("prepare state");
        let mut equal_length_replacement = original.clone();
        let first = equal_length_replacement
            .iter_mut()
            .find(|byte| **byte == b'{')
            .expect("json should contain object start");
        *first = b' ';
        assert_eq!(equal_length_replacement.len(), original.len());
        fs::write(&path, &equal_length_replacement).expect("write equal-length replacement");

        let error = commit_prepared_startup(&prepared, &state(), &integrity_key())
            .expect_err("equal-length replacement must fail commit");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "session continuity store changed after startup preparation"
        );
        assert_eq!(
            fs::read(&path).expect("replacement remains"),
            equal_length_replacement
        );
        assert!(!temp_path.exists());

        persist_test(&path, &state()).expect("restore valid state");
        let prepared = prepare_test(&path).expect("prepare state again");
        fs::write(&temp_path, b"late stale temp").expect("create temp after prepare");
        let error = commit_prepared_startup(&prepared, &state(), &integrity_key())
            .expect_err("temp membership change must fail commit");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "session continuity store changed after startup preparation"
        );
        assert_eq!(
            fs::read(&temp_path).expect("late temp remains"),
            b"late stale temp"
        );
    }

    #[test]
    fn prepared_commit_repeats_nonregular_temp_rejection() {
        let dir = TestDir::new();
        let path = dir.path("continuity.json");
        let temp_path = dir.path("continuity.json.tmp");
        persist_test(&path, &state()).expect("persist state");
        let original = fs::read(&path).expect("read state");
        let prepared = prepare_test(&path).expect("prepare state");
        fs::create_dir(&temp_path).expect("create raced temp directory");

        let error = commit_prepared_startup(&prepared, &state(), &integrity_key())
            .expect_err("nonregular temp must fail commit");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "session continuity temporary path is not a regular file"
        );
        assert_eq!(fs::read(&path).expect("original state remains"), original);
        assert!(fs::metadata(&temp_path).unwrap().is_dir());
    }

    #[test]
    fn missing_file_is_distinct_and_valid_state_round_trips() {
        let dir = TestDir::new();
        let path = dir.path("continuity.json");
        assert_eq!(load_test(&path).expect("missing load"), None);

        assert_eq!(
            persist_test(&path, &state()).expect("persist"),
            CommitOutcome::Durable
        );
        let loaded = verified_state(&path);
        assert_eq!(
            loaded.integrity_mac_hex,
            sign_state(&state(), &integrity_key())
                .expect("sign expected state")
                .integrity_mac_hex
        );
    }

    #[test]
    fn rejects_empty_corrupt_and_unsupported_state() {
        let dir = TestDir::new();
        let path = dir.path("continuity.json");

        fs::write(&path, []).expect("write empty");
        assert_eq!(
            load_test(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        fs::write(&path, b"{broken").expect("write corrupt");
        assert_eq!(
            load_test(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut unsupported = state();
        unsupported.schema_version += 1;
        fs::write(
            &path,
            serde_json::to_vec(&unsupported).expect("serialize unsupported"),
        )
        .expect("write unsupported");
        assert_eq!(
            load_test(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn schema_v1_is_readable_but_record_key_provenance_is_v2_only() {
        let dir = TestDir::new();
        let path = dir.path("continuity-v1.json");
        persist_test(&path, &v1_state()).expect("schema-v1 state should persist");
        let loaded = verified_state(&path);
        assert_eq!(loaded.schema_version, 1);
        assert!(loaded
            .records
            .iter()
            .all(|record| record.continuity_key_id_hex.is_none()));

        let mut invalid_v1 = v1_state();
        invalid_v1.records[0].continuity_key_id_hex = Some("ab".repeat(32));
        assert!(validate_semantics(&invalid_v1).is_err());

        let mut invalid_v2 = state();
        invalid_v2.records[0].continuity_key_id_hex = None;
        assert!(validate_semantics(&invalid_v2).is_err());

        for unsupported in [0, SESSION_CONTINUITY_SCHEMA_VERSION + 1] {
            let mut invalid = state();
            invalid.schema_version = unsupported;
            assert!(validate_semantics(&invalid).is_err());
        }
    }

    #[test]
    fn key_candidates_select_exactly_one_state_signer_before_verification() {
        let dir = TestDir::new();
        let path = dir.path("continuity-overlap.json");
        let active_key = IntegrityKey::derive("active-continuity-key").expect("active key");
        let previous_key = IntegrityKey::derive("previous-continuity-key").expect("previous key");
        let active_id = "ab".repeat(32);
        let previous_id = "cd".repeat(32);
        let mut previous_state = state();
        previous_state.transport_key_id_hex = previous_id.clone();
        for record in &mut previous_state.records {
            record.continuity_key_id_hex = Some(previous_id.clone());
        }
        persist(&path, &previous_state, &previous_key).expect("previous state should persist");

        let loaded = load_with_key_candidates(
            &path,
            &[
                (active_id.as_str(), &active_key),
                (previous_id.as_str(), &previous_key),
            ],
        )
        .expect("the exact previous candidate should verify")
        .expect("state should exist");
        assert_eq!(loaded.transport_key_id_hex, previous_id);

        let error = load_with_key_candidates(
            &path,
            &[
                (previous_id.as_str(), &active_key),
                (active_id.as_str(), &previous_key),
            ],
        )
        .expect_err("a matching identifier with the wrong key must not fall back");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("integrity verification failed"));

        let error = load_with_key_candidates(
            &path,
            &[
                (previous_id.as_str(), &previous_key),
                (previous_id.as_str(), &active_key),
            ],
        )
        .expect_err("duplicate candidate identifiers must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn rejects_oversized_state_before_parsing() {
        let dir = TestDir::new();
        let path = dir.path("continuity.json");
        fs::write(&path, vec![b' '; MAX_CONTINUITY_STORE_BYTES + 1]).expect("write oversized");
        assert_eq!(
            load_test(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn prepared_startup_covers_exact_record_bound_and_rejects_plus_one() {
        let dir = TestDir::new();
        let path = dir.path("continuity.json");
        let mut bounded = state();
        bounded.records = (0..MAX_CONTINUITY_RECORDS)
            .map(|index| Record {
                key_digest_hex: format!("{index:064x}"),
                continuity_key_id_hex: Some("ab".repeat(32)),
                session_id: SessionId(Uuid::from_u128(index as u128 + 1)),
                enforcement_floor: None,
                last_seen: 200,
                last_recovery_at: None,
                recovery_count: 0,
            })
            .collect();
        persist_test(&path, &bounded).expect("exact record bound should persist");
        let prepared = prepare_test(&path).expect("exact record bound should prepare");
        assert_eq!(
            prepared
                .loaded
                .as_ref()
                .expect("prepared state")
                .records
                .len(),
            MAX_CONTINUITY_RECORDS
        );

        let mut over_bound = bounded;
        over_bound.records.push(Record {
            key_digest_hex: format!("{:064x}", MAX_CONTINUITY_RECORDS),
            continuity_key_id_hex: Some("ab".repeat(32)),
            session_id: SessionId(Uuid::from_u128(MAX_CONTINUITY_RECORDS as u128 + 1)),
            enforcement_floor: None,
            last_seen: 200,
            last_recovery_at: None,
            recovery_count: 0,
        });
        over_bound.integrity_mac_hex = "00".repeat(32);
        fs::write(
            &path,
            serde_json::to_vec(&over_bound).expect("serialize over-bound state"),
        )
        .expect("write over-bound state");
        let error = prepare_test(&path).expect_err("record bound plus one must fail prepare");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            format!(
                "session continuity store has {} records; maximum is {}",
                MAX_CONTINUITY_RECORDS + 1,
                MAX_CONTINUITY_RECORDS
            )
        );
    }

    #[test]
    fn rejects_invalid_hex_duplicates_and_incoherent_timestamps() {
        let mut invalid_hex = state();
        invalid_hex.transport_key_id_hex = "AB".repeat(32);
        assert!(validate_semantics(&invalid_hex).is_err());

        let mut duplicate_digest = state();
        duplicate_digest.records[1].key_digest_hex =
            duplicate_digest.records[0].key_digest_hex.clone();
        assert!(validate_semantics(&duplicate_digest).is_err());

        let mut duplicate_session = state();
        duplicate_session.records[1].session_id = duplicate_session.records[0].session_id;
        assert!(validate_semantics(&duplicate_session).is_err());

        let mut incoherent = state();
        incoherent.records[0].last_recovery_at = Some(201);
        assert!(validate_semantics(&incoherent).is_err());
    }

    #[test]
    fn rejects_more_than_the_record_bound() {
        let records = (0..=MAX_CONTINUITY_RECORDS)
            .map(|index| Record {
                key_digest_hex: format!("{index:064x}"),
                continuity_key_id_hex: Some("ab".repeat(32)),
                session_id: SessionId(Uuid::from_u128(index as u128 + 1)),
                enforcement_floor: None,
                last_seen: 1,
                last_recovery_at: None,
                recovery_count: 0,
            })
            .collect();
        let oversized = State { records, ..state() };
        assert!(validate_semantics(&oversized).is_err());
    }

    #[test]
    fn deterministic_mac_rejects_validly_shaped_semantic_tampering() {
        assert_eq!(
            sign_state(&state(), &integrity_key())
                .expect("first signature")
                .integrity_mac_hex,
            sign_state(&state(), &integrity_key())
                .expect("second signature")
                .integrity_mac_hex
        );

        assert_tamper_rejected(|state| {
            state.records[0].session_id = SessionId(Uuid::from_u128(99));
        });
        assert_tamper_rejected(|state| {
            state.records[0].enforcement_floor = Some(PolicyState::Observe);
        });
        assert_tamper_rejected(|state| {
            state.records[0].continuity_key_id_hex = Some("cd".repeat(32));
        });
        assert_tamper_rejected(|state| {
            state.records[0].last_seen += 1;
        });
        assert_tamper_rejected(|state| {
            state.migration_quarantine_until = Some(299);
        });
        assert_tamper_rejected(|state| {
            state.records.swap(0, 1);
        });
        assert_tamper_rejected(|state| {
            state.records.pop();
        });
    }

    #[test]
    fn transport_key_mismatch_never_trusts_unverified_state() {
        let dir = TestDir::new();
        let path = dir.path("continuity.json");
        persist_test(&path, &state()).expect("persist old-key state");

        let rotated_key = IntegrityKey::derive("rotated-transport-secret").expect("derive key");
        let error = load(&path, &rotated_key, &"cd".repeat(32))
            .expect_err("unverified old-key state must always block rotation");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn integrity_key_debug_is_redacted() {
        let debug = format!("{:?}", integrity_key());
        assert_eq!(debug, "IntegrityKey(<redacted>)");
        assert!(!debug.contains("test-transport-secret"));
    }

    #[test]
    fn partial_write_preserves_the_previous_state() {
        let dir = TestDir::new();
        let path = dir.path("continuity.json");
        persist_test(&path, &state()).expect("persist baseline");

        let mut replacement = state();
        replacement.migration_quarantine_until = Some(400);
        let error = persist_with(
            &path,
            &replacement,
            &integrity_key(),
            |file, bytes| {
                file.write_all(&bytes[..bytes.len() / 2])?;
                Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "injected partial write",
                ))
            },
            sync_parent,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
        assert_eq!(
            verified_state(&path).migration_quarantine_until,
            state().migration_quarantine_until
        );

        let entries = fs::read_dir(&dir.0)
            .expect("read test directory")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect entries");
        assert_eq!(entries.len(), 1, "temporary file must be removed");
    }

    #[test]
    fn stale_fixed_temporary_file_is_replaced_without_accumulating_files() {
        let dir = TestDir::new();
        let path = dir.path("continuity.json");
        let temp_path = dir.path("continuity.json.tmp");
        fs::write(&temp_path, b"stale partial state").expect("write stale temp");

        persist_test(&path, &state()).expect("persist over stale temp");

        assert_eq!(verified_state(&path).records, state().records);
        assert!(!temp_path.exists(), "fixed temporary file must be renamed");
        let entries = fs::read_dir(&dir.0)
            .expect("read test directory")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect entries");
        assert_eq!(entries.len(), 1, "writes must not accumulate temp files");
    }

    #[test]
    fn temporary_path_is_fixed_and_adjacent_to_the_sidecar() {
        let dir = TestDir::new();
        let path = dir.path("continuity.json");

        assert_eq!(
            temporary_path(&path).expect("temporary path"),
            dir.path("continuity.json.tmp")
        );
        assert_eq!(
            temporary_path(&path).expect("same temporary path"),
            dir.path("continuity.json.tmp")
        );
    }

    #[test]
    fn reports_directory_sync_uncertainty_after_rename() {
        let dir = TestDir::new();
        let path = dir.path("continuity.json");
        let outcome = persist_with(
            &path,
            &state(),
            &integrity_key(),
            |file, bytes| file.write_all(bytes),
            |_| Err(io::Error::other("injected directory sync failure")),
        )
        .expect("rename commits");
        assert!(matches!(
            outcome,
            CommitOutcome::CommittedDurabilityUncertain
        ));
        assert_eq!(verified_state(&path).records, state().records);
    }

    #[cfg(unix)]
    #[test]
    fn persisted_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TestDir::new();
        let path = dir.path("continuity.json");
        persist_test(&path, &state()).expect("persist");
        assert_eq!(
            fs::metadata(path).expect("metadata").permissions().mode() & 0o777,
            0o600
        );
    }
}
