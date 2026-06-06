use std::{
    fs::{File, OpenOptions},
    io::{self, BufWriter, Write},
    path::Path,
};

use eidolon_core::Event;

pub type FileEventLogWriter = EventLogWriter<BufWriter<File>>;

pub struct EventLogWriter<W> {
    sink: W,
}

impl FileEventLogWriter {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;

        #[cfg(unix)]
        {
            use std::{fs, os::unix::fs::PermissionsExt};

            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }

        Ok(Self::new(BufWriter::new(file)))
    }
}

impl<W: Write> EventLogWriter<W> {
    pub fn new(sink: W) -> Self {
        Self { sink }
    }

    pub fn write_event(&mut self, event: &Event) -> io::Result<()> {
        let serialized = serde_json::to_vec(event).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to serialize event as JSON: {err}"),
            )
        })?;

        self.sink.write_all(&serialized)?;
        self.sink.write_all(b"\n")?;
        self.sink.flush()
    }
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
