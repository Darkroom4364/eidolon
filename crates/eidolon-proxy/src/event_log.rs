use std::{
    fs::{File, OpenOptions},
    io::{self, BufRead, BufWriter, Write},
    path::{Path, PathBuf},
};

use eidolon_core::Event;

pub type FileEventLogWriter = EventLogWriter<BufWriter<File>>;

pub struct EventLogWriter<W> {
    sink: W,
    reopen: Option<Box<dyn Fn() -> io::Result<W> + Send + Sync>>,
    path: Option<PathBuf>,
    current_len: u64,
}

impl FileEventLogWriter {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        if let Some(archive) = rotate_log_if_oversized(path.as_ref())? {
            eprintln!(
                "eidolon log rotation: archived oversized event log to {}",
                archive.display()
            );
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())?;

        #[cfg(unix)]
        {
            use std::{fs, os::unix::fs::PermissionsExt};

            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }

        let current_len = std::fs::metadata(path.as_ref())
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        let path = path.as_ref().to_path_buf();
        let reopen_path = path.clone();

        Ok(Self {
            sink: BufWriter::new(file),
            reopen: Some(Box::new(move || {
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&reopen_path)?;

                #[cfg(unix)]
                {
                    use std::{fs, os::unix::fs::PermissionsExt};

                    file.set_permissions(fs::Permissions::from_mode(0o600))?;
                }

                Ok(BufWriter::new(file))
            })),
            path: Some(path),
            current_len,
        })
    }
}

impl<W: Write> EventLogWriter<W> {
    pub fn new(sink: W) -> Self {
        Self {
            sink,
            reopen: None,
            path: None,
            current_len: 0,
        }
    }

    pub fn write_event(&mut self, event: &Event) -> io::Result<()> {
        let serialized = serde_json::to_vec(event).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to serialize event as JSON: {err}"),
            )
        })?;

        self.rotate_if_needed(serialized.len() as u64 + 1)?;
        self.sink.write_all(&serialized)?;
        self.sink.write_all(b"\n")?;
        self.current_len += serialized.len() as u64 + 1;
        self.sink.flush()
    }

    fn rotate_if_needed(&mut self, incoming: u64) -> io::Result<()> {
        let (Some(path), Some(reopen)) = (self.path.clone(), self.reopen.as_ref()) else {
            return Ok(());
        };
        if self.current_len + incoming <= LOG_ROTATE_BYTES {
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
        Ok(())
    }
}

/// Line source for startup reconstruction of a JSONL log.
///
/// The whole file is buffered once (reconstruction reads it fully anyway),
/// which lets a crash-torn final line be distinguished from corruption
/// elsewhere: only the last non-empty line of a file without a trailing
/// newline may be a torn tail.
pub struct JsonlReconstructionSource {
    pub lines: Vec<String>,
    pub last_non_empty_index: Option<usize>,
    pub ends_with_newline: bool,
}

impl JsonlReconstructionSource {
    /// Whether the given zero-based line index may be a crash-torn tail
    /// rather than corruption: the final non-empty line of a file that does
    /// not end with a newline.
    pub fn is_torn_tail(&self, index: usize) -> bool {
        Some(index) == self.last_non_empty_index && !self.ends_with_newline
    }
}

pub fn read_jsonl_reconstruction(reader: impl BufRead) -> io::Result<JsonlReconstructionSource> {
    let mut text = String::new();
    let mut reader = reader;
    reader.read_to_string(&mut text)?;

    let lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    let last_non_empty_index = lines.iter().rposition(|line| !line.trim().is_empty());

    Ok(JsonlReconstructionSource {
        ends_with_newline: text.ends_with('\n'),
        lines,
        last_non_empty_index,
    })
}

/// Disk budget for the append-only JSONL logs (event and debug): the active
/// segment rotates once it reaches this size.
pub const LOG_ROTATE_BYTES: u64 = 32 * 1024 * 1024;

/// Number of rotated archives retained per log in addition to the active
/// segment. Older archives are pruned on rotation, bounding total disk use
/// to roughly `LOG_ROTATE_BYTES * (LOG_ARCHIVES_KEPT + 1)` per log.
pub const LOG_ARCHIVES_KEPT: usize = 3;

/// Rotate `path` to a timestamped archive when its on-disk length already
/// exceeds the rotation budget (used at open time). Returns the archive
/// path when a rotation happened.
pub fn rotate_log_if_oversized(path: &Path) -> io::Result<Option<PathBuf>> {
    let oversized = std::fs::metadata(path)
        .map(|metadata| metadata.len() >= LOG_ROTATE_BYTES)
        .unwrap_or(false);
    if !oversized {
        return Ok(None);
    }

    rotate_log_now(path).map(Some)
}

/// Rotate `path` unconditionally: rename it to `<path>.<unix_secs>` and
/// prune archives beyond the retention budget. The caller reopens the
/// active path afterwards.
pub fn rotate_log_now(path: &Path) -> io::Result<PathBuf> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    let archive = std::path::PathBuf::from(format!("{}.{now}", path.display()));
    std::fs::rename(path, &archive)?;
    prune_log_archives(path, &archive, LOG_ARCHIVES_KEPT)?;
    Ok(archive)
}

fn prune_log_archives(path: &Path, fresh_archive: &Path, keep: usize) -> io::Result<()> {
    let prefix = format!("{}.", path.display());
    let Some(parent) = path.parent() else {
        return Ok(());
    };

    let mut archives: Vec<PathBuf> = std::fs::read_dir(parent)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|candidate| {
            candidate.to_string_lossy().starts_with(&prefix) && candidate != fresh_archive
        })
        .collect();
    archives.sort();

    let excess = archives.len().saturating_sub(keep);
    for stale in archives.into_iter().take(excess) {
        std::fs::remove_file(stale)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use eidolon_core::{
        Event, EventKind, EventSource, IngressIdentity, PolicyState, RoutingDecision,
        SafeHeaderObservation, SessionId,
    };
    use serde_json::Value;

    use super::{EventLogWriter, FileEventLogWriter};

    #[cfg(unix)]
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
    fn oversized_log_rotates_on_open_and_keeps_only_bounded_archives() {
        use std::fs;

        let path = unique_temp_path("oversized.jsonl");
        let oversized = vec![b'x'; (super::LOG_ROTATE_BYTES + 1) as usize];
        fs::write(&path, &oversized).expect("oversized log should write");
        for index in 0..5 {
            fs::write(
                format!("{}.10000000{index}", path.display()),
                b"stale archive",
            )
            .expect("stale archive should write");
        }

        let _writer = FileEventLogWriter::open(&path).expect("event log should open");

        let active = fs::metadata(&path)
            .expect("active log metadata should read")
            .len();
        assert_eq!(active, 0, "oversized log must rotate to a fresh segment");

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
            super::LOG_ARCHIVES_KEPT + 1,
            "archives must stay within the retention budget (kept archives plus the fresh one)"
        );

        fs::remove_file(&path).expect("active log should remove");
        for archive in archives {
            fs::remove_file(archive).expect("archive should remove");
        }
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
