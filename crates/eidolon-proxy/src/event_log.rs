use std::{
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, BufWriter, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use eidolon_core::Event;

pub type FileEventLogWriter = EventLogWriter<BufWriter<File>>;

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

pub struct EventLogWriter<W> {
    sink: W,
    reopen: Option<Box<dyn Fn() -> io::Result<W> + Send + Sync>>,
    path: Option<PathBuf>,
    current_len: u64,
    startup_tail_repair: JsonlTailRepairOutcome,
}

impl FileEventLogWriter {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let startup_tail_repair = repair_event_log_tail(path.as_ref())?;
        report_jsonl_tail_repair("event", path.as_ref(), startup_tail_repair);

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
            startup_tail_repair,
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
            startup_tail_repair: JsonlTailRepairOutcome::NotNeeded,
        }
    }

    pub fn startup_tail_repair(&self) -> JsonlTailRepairOutcome {
        self.startup_tail_repair
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

/// Repair an incomplete final JSONL record before the file is opened for
/// append. A valid final JSON value only needs its missing delimiter restored;
/// an invalid tail is discarded back to the previous complete line.
pub fn repair_jsonl_tail(path: &Path) -> io::Result<JsonlTailRepairOutcome> {
    repair_jsonl_tail_with(path, |record| {
        serde_json::from_slice::<serde_json::Value>(record).is_ok()
    })
}

fn repair_event_log_tail(path: &Path) -> io::Result<JsonlTailRepairOutcome> {
    repair_jsonl_tail_with(path, |record| {
        serde_json::from_slice::<Event>(record).is_ok()
    })
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
    let oversized = std::fs::metadata(path)
        .map(|metadata| metadata.len() >= LOG_ROTATE_BYTES)
        .unwrap_or(false);
    if !oversized {
        return Ok(None);
    }

    rotate_log_now(path).map(Some)
}

/// Rotate `path` unconditionally: rename it to `<path>.<unix_nanos>` and
/// prune archives beyond the retention budget. The caller reopens the
/// active path afterwards.
pub fn rotate_log_now(path: &Path) -> io::Result<PathBuf> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let archive = next_archive_path(path, now);
    std::fs::rename(path, &archive)?;
    prune_log_archives(path, &archive, LOG_ARCHIVES_KEPT)?;
    Ok(archive)
}

fn next_archive_path(path: &Path, initial_stamp: u128) -> PathBuf {
    let mut stamp = initial_stamp;
    loop {
        let mut archive = path.as_os_str().to_os_string();
        archive.push(format!(".{stamp:039}"));
        let archive = PathBuf::from(archive);
        if !archive.exists() {
            return archive;
        }
        stamp = stamp.saturating_add(1);
    }
}

fn prune_log_archives(path: &Path, fresh_archive: &Path, keep: usize) -> io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };

    let mut archives: Vec<(PathBuf, String)> = std::fs::read_dir(parent)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter_map(|candidate| {
            if candidate == fresh_archive {
                return None;
            }
            let suffix = archive_suffix(path, &candidate)?.to_string();
            Some((candidate, suffix))
        })
        .collect();
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
    (!suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())).then_some(suffix)
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use eidolon_core::{
        Event, EventKind, EventSource, IngressIdentity, PolicyState, RoutingDecision,
        SafeHeaderObservation, SessionId,
    };
    use serde_json::Value;

    use super::{EventLogWriter, FileEventLogWriter, JsonlTailRepairOutcome};

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
    fn oversized_log_rotates_on_open_and_keeps_only_bounded_archives() {
        use std::fs;

        let path = unique_temp_path("oversized.jsonl");
        let event_line = format!(
            "{}\n",
            serde_json::to_string(&request_event("GET", "/oversized"))
                .expect("event should serialize")
        );
        let repetitions = (super::LOG_ROTATE_BYTES as usize / event_line.len()) + 1;
        fs::write(&path, event_line.repeat(repetitions)).expect("oversized log should write");
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
        for stale in ["100000000", "100000001", "100000002"] {
            assert!(
                !suffixes.iter().any(|suffix| suffix == stale),
                "old archive {stale} should be pruned"
            );
        }
        for retained in ["100000003", "100000004"] {
            assert!(
                suffixes.iter().any(|suffix| suffix == retained),
                "new archive {retained} should be retained"
            );
        }
        assert_eq!(
            suffixes.iter().filter(|suffix| suffix.len() == 39).count(),
            1,
            "the fresh nanosecond archive must be retained"
        );

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
        let occupied = super::next_archive_path(&path, 42);
        fs::write(&occupied, b"occupied").expect("occupied archive should write");

        let candidate = super::next_archive_path(&path, 42);

        assert_ne!(candidate, occupied);
        assert!(candidate
            .to_string_lossy()
            .ends_with("000000000000000000000000000000000000043"));

        fs::remove_file(occupied).expect("occupied archive should remove");
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
