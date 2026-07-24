use std::{
    error::Error,
    fmt,
    fs::{self, File},
    io::{self, BufRead, BufReader},
    path::{Path, PathBuf},
};

use eidolon_core::{Event, EVENT_SCHEMA_VERSION};
use serde_json::Value;

use crate::TimelineEvent;

const EVENT_LOG_SNAPSHOT_ATTEMPTS: usize = 8;

pub fn read_events_jsonl_file(
    path: impl AsRef<Path>,
) -> Result<Vec<TimelineEvent>, TraceReadError> {
    let path = path.as_ref();
    let file = File::open(path).map_err(|source| TraceReadError::Open {
        path: path.to_path_buf(),
        source,
    })?;

    read_events_jsonl_with_path(BufReader::new(file), Some(path.to_path_buf()))
}

pub fn read_events_jsonl_file_with_archives(
    path: impl AsRef<Path>,
) -> Result<Vec<TimelineEvent>, TraceReadError> {
    read_events_jsonl_file_with_archives_and_hook(path.as_ref(), |_| {})
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EventLogSegmentSnapshot {
    path: PathBuf,
    len: u64,
}

fn read_events_jsonl_file_with_archives_and_hook(
    path: &Path,
    mut after_snapshot: impl FnMut(usize),
) -> Result<Vec<TimelineEvent>, TraceReadError> {
    for attempt in 0..EVENT_LOG_SNAPSHOT_ATTEMPTS {
        let before = match event_log_segment_snapshot(path) {
            Ok(snapshot) => snapshot,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                std::thread::yield_now();
                continue;
            }
            Err(source) => {
                return Err(TraceReadError::Open {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        after_snapshot(attempt);

        let read_result = read_event_log_snapshot(&before);
        let after = match event_log_segment_snapshot(path) {
            Ok(snapshot) => snapshot,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                std::thread::yield_now();
                continue;
            }
            Err(source) => {
                return Err(TraceReadError::Open {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        if before == after {
            return read_result;
        }
        std::thread::yield_now();
    }

    Err(TraceReadError::UnstableEventLogSnapshot {
        path: path.to_path_buf(),
        attempts: EVENT_LOG_SNAPSHOT_ATTEMPTS,
    })
}

fn read_event_log_snapshot(
    segments: &[EventLogSegmentSnapshot],
) -> Result<Vec<TimelineEvent>, TraceReadError> {
    let mut events = Vec::new();
    for segment in segments {
        for mut event in read_events_jsonl_file(&segment.path)? {
            event.file_order = events.len();
            events.push(event);
        }
    }
    Ok(events)
}

fn event_log_segment_snapshot(path: &Path) -> io::Result<Vec<EventLogSegmentSnapshot>> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let base = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let entries = fs::read_dir(parent)?;
    let mut archives = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(suffix) = event_log_archive_suffix(base, name) else {
            continue;
        };
        archives.push((entry.path(), suffix.to_string()));
    }
    archives.sort_by(|(_, left), (_, right)| {
        left.len().cmp(&right.len()).then_with(|| left.cmp(right))
    });

    let mut segments = archives
        .into_iter()
        .map(|(path, _)| path)
        .collect::<Vec<_>>();
    segments.push(path.to_path_buf());
    segments
        .into_iter()
        .map(|segment| {
            let len = fs::metadata(&segment)?.len();
            Ok(EventLogSegmentSnapshot { path: segment, len })
        })
        .collect()
}

pub fn read_events_jsonl<R>(reader: R) -> Result<Vec<TimelineEvent>, TraceReadError>
where
    R: BufRead,
{
    read_events_jsonl_with_path(reader, None)
}

fn read_events_jsonl_with_path<R>(
    reader: R,
    path: Option<PathBuf>,
) -> Result<Vec<TimelineEvent>, TraceReadError>
where
    R: BufRead,
{
    let mut events = Vec::new();

    for (line_index, line) in reader.lines().enumerate() {
        let line_number = line_index + 1;
        let line = line.map_err(|source| TraceReadError::ReadLine {
            path: path.clone(),
            line_number,
            source,
        })?;
        let value: Value =
            serde_json::from_str(&line).map_err(|source| TraceReadError::ParseLine {
                path: path.clone(),
                line_number,
                source,
            })?;

        let schema_version =
            event_schema_version(&value).ok_or_else(|| TraceReadError::MissingSchemaVersion {
                path: path.clone(),
                line_number,
            })?;
        if schema_version != EVENT_SCHEMA_VERSION {
            return Err(TraceReadError::UnsupportedSchemaVersion {
                path: path.clone(),
                line_number,
                schema_version,
                expected_schema_version: EVENT_SCHEMA_VERSION,
            });
        }

        let event: Event =
            serde_json::from_value(value).map_err(|source| TraceReadError::ParseLine {
                path: path.clone(),
                line_number,
                source,
            })?;

        events.push(TimelineEvent {
            file_order: events.len(),
            line_number,
            event,
        });
    }

    Ok(events)
}

#[derive(Debug)]
pub enum TraceReadError {
    Open {
        path: PathBuf,
        source: io::Error,
    },
    ReadLine {
        path: Option<PathBuf>,
        line_number: usize,
        source: io::Error,
    },
    ParseLine {
        path: Option<PathBuf>,
        line_number: usize,
        source: serde_json::Error,
    },
    MissingSchemaVersion {
        path: Option<PathBuf>,
        line_number: usize,
    },
    UnsupportedSchemaVersion {
        path: Option<PathBuf>,
        line_number: usize,
        schema_version: u16,
        expected_schema_version: u16,
    },
    UnstableEventLogSnapshot {
        path: PathBuf,
        attempts: usize,
    },
}

impl fmt::Display for TraceReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open { path, source } => {
                write!(formatter, "could not open `{}`: {source}", path.display())
            }
            Self::ReadLine {
                path,
                line_number,
                source,
            } => write!(
                formatter,
                "could not read {}: {source}",
                line_location(path.as_deref(), *line_number)
            ),
            Self::ParseLine {
                path,
                line_number,
                source,
            } => write!(
                formatter,
                "could not parse event JSON on {}: {source}",
                line_location(path.as_deref(), *line_number)
            ),
            Self::MissingSchemaVersion { path, line_number } => write!(
                formatter,
                "event JSON on {} is missing numeric schema_version",
                line_location(path.as_deref(), *line_number)
            ),
            Self::UnsupportedSchemaVersion {
                path,
                line_number,
                schema_version,
                expected_schema_version,
            } => write!(
                formatter,
                "unsupported event schema version {schema_version} on {}; expected {expected_schema_version}",
                line_location(path.as_deref(), *line_number)
            ),
            Self::UnstableEventLogSnapshot { path, attempts } => write!(
                formatter,
                "event log family `{}` changed during all {attempts} snapshot attempts",
                path.display()
            ),
        }
    }
}

impl Error for TraceReadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Open { source, .. } | Self::ReadLine { source, .. } => Some(source),
            Self::ParseLine { source, .. } => Some(source),
            Self::MissingSchemaVersion { .. }
            | Self::UnsupportedSchemaVersion { .. }
            | Self::UnstableEventLogSnapshot { .. } => None,
        }
    }
}

fn event_schema_version(value: &Value) -> Option<u16> {
    value
        .get("schema_version")?
        .as_u64()
        .and_then(|version| u16::try_from(version).ok())
}

fn line_location(path: Option<&Path>, line_number: usize) -> String {
    match path {
        Some(path) => format!("`{}` line {line_number}", path.display()),
        None => format!("line {line_number}"),
    }
}

fn event_log_archive_suffix<'a>(base: &str, candidate: &'a str) -> Option<&'a str> {
    let suffix = candidate.strip_prefix(base)?.strip_prefix('.')?;
    (!suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())).then_some(suffix)
}

#[cfg(test)]
mod tests {
    use eidolon_core::{
        ControlledRealityBranch, ControlledRealityInteraction, ControlledRealityInteractionAction,
        ControlledRealityJobId, ControlledRealityWorkflowState, EventKind, EventSource,
        IngressIdentity, PolicyState, RequestId, RoutingDecision, SessionId,
    };

    use super::*;

    fn event(session_id: SessionId, path: &str) -> Event {
        Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::Observe,
            EventKind::RequestSeen {
                method: "GET".to_string(),
                path: path.to_string(),
                safe_headers: Vec::new(),
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
    fn read_events_jsonl_preserves_file_order_and_line_numbers() {
        let session_id = SessionId::new();
        let first = serde_json::to_string(&event(session_id, "/first")).unwrap();
        let second = serde_json::to_string(&event(session_id, "/second")).unwrap();
        let input = format!("{first}\n{second}\n");

        let events = read_events_jsonl(input.as_bytes()).expect("events should parse");

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].file_order, 0);
        assert_eq!(events[0].line_number, 1);
        assert_eq!(events[1].file_order, 1);
        assert_eq!(events[1].line_number, 2);
    }

    #[test]
    fn schema_v2_reader_roundtrips_controlled_reality_response_metadata() {
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let origin_request_id = RequestId::new();
        let event = Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::ControlledReality,
            EventKind::ResponseServed {
                status: 202,
                routing_decision: RoutingDecision::ControlledReality,
                controlled_reality: Some(ControlledRealityInteraction {
                    branch: ControlledRealityBranch::ImportReconcile,
                    origin_request_id,
                    from_state: ControlledRealityWorkflowState::Ready,
                    to_state: ControlledRealityWorkflowState::Queued,
                    job_id: ControlledRealityJobId::new("job_0123456789abcdef")
                        .expect("job id should be valid"),
                    action: ControlledRealityInteractionAction::JobSubmitted,
                }),
            },
        )
        .with_request_id(request_id);
        let input = serde_json::to_string(&event).expect("event should serialize");

        let events = read_events_jsonl(input.as_bytes()).expect("event should parse");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, event);
    }

    #[test]
    fn archived_request_and_active_response_remain_one_verifiable_workflow() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "eidolon-trace-rotated-reader-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&dir).expect("temp directory should create");
        let active = dir.join("events.jsonl");
        let archive = PathBuf::from(format!("{}.{:039}", active.display(), 1));
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let job_id =
            ControlledRealityJobId::new("job_0123456789abcdef").expect("job id should be valid");
        let request = Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::ControlledReality,
            EventKind::RequestSeen {
                method: "POST".to_string(),
                path: "/api/v2/import/reconcile".to_string(),
                safe_headers: Vec::new(),
                ingress_identity: IngressIdentity::default(),
                authenticated_ingress_rule_rejection: None,
                local_ingress_trust_scope_rejection: None,
                trusted_ingress_soften_match: None,
                ingress_signals: Default::default(),
                discovery_recon_score: Default::default(),
                routing_decision: RoutingDecision::ControlledReality,
            },
        )
        .with_request_id(request_id);
        let response = Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::ControlledReality,
            EventKind::ResponseServed {
                status: 202,
                routing_decision: RoutingDecision::ControlledReality,
                controlled_reality: Some(ControlledRealityInteraction {
                    branch: ControlledRealityBranch::ImportReconcile,
                    origin_request_id: request_id,
                    from_state: ControlledRealityWorkflowState::Ready,
                    to_state: ControlledRealityWorkflowState::Queued,
                    job_id,
                    action: ControlledRealityInteractionAction::JobSubmitted,
                }),
            },
        )
        .with_request_id(request_id);
        fs::write(
            &archive,
            format!(
                "{}\n",
                serde_json::to_string(&request).expect("request should serialize")
            ),
        )
        .expect("archive should write");
        fs::write(
            &active,
            format!(
                "{}\n",
                serde_json::to_string(&response).expect("response should serialize")
            ),
        )
        .expect("active log should write");
        fs::write(dir.join("events.jsonl.backup"), "not json\n").expect("lookalike should write");

        let events =
            read_events_jsonl_file_with_archives(&active).expect("log family should parse");
        let timelines = crate::build_session_timelines(events);
        let bundle = crate::evidence_bundle_for_timeline(&timelines[0]);

        assert_eq!(timelines[0].events.len(), 2);
        assert_eq!(timelines[0].events[0].file_order, 0);
        assert_eq!(timelines[0].events[1].file_order, 1);
        assert_eq!(bundle.controlled_reality_interactions.len(), 1);
        fs::remove_dir_all(dir).expect("temp directory should remove");
    }

    #[test]
    fn rotation_during_snapshot_is_retried_without_losing_a_segment() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "eidolon-trace-snapshot-rotation-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&dir).expect("temp directory should create");
        let active = dir.join("events.jsonl");
        let archive = PathBuf::from(format!("{}.{:039}", active.display(), 1));
        let session_id = SessionId::new();
        let first = event(session_id, "/before-rotation");
        let second = event(session_id, "/after-rotation");
        fs::write(
            &active,
            format!(
                "{}\n",
                serde_json::to_string(&first).expect("first event should serialize")
            ),
        )
        .expect("active log should write");
        let mut rotated = false;

        let events = read_events_jsonl_file_with_archives_and_hook(&active, |_| {
            if rotated {
                return;
            }
            rotated = true;
            fs::rename(&active, &archive).expect("active log should rotate");
            fs::write(
                &active,
                format!(
                    "{}\n",
                    serde_json::to_string(&second).expect("second event should serialize")
                ),
            )
            .expect("new active log should write");
        })
        .expect("reader should retry the rotated snapshot");

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event, first);
        assert_eq!(events[1].event, second);
        fs::remove_dir_all(dir).expect("temp directory should remove");
    }

    #[test]
    fn continuously_changing_log_fails_instead_of_returning_a_partial_snapshot() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "eidolon-trace-unstable-snapshot-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&dir).expect("temp directory should create");
        let active = dir.join("events.jsonl");
        let session_id = SessionId::new();
        fs::write(
            &active,
            format!(
                "{}\n",
                serde_json::to_string(&event(session_id, "/initial"))
                    .expect("event should serialize")
            ),
        )
        .expect("active log should write");
        let mut append_index = 0;

        let error = read_events_jsonl_file_with_archives_and_hook(&active, |_| {
            append_index += 1;
            let mut content = fs::read_to_string(&active).expect("active log should read");
            content.push_str(
                &serde_json::to_string(&event(session_id, &format!("/append-{append_index}")))
                    .expect("event should serialize"),
            );
            content.push('\n');
            fs::write(&active, content).expect("active log should change");
        })
        .expect_err("unstable log must not produce a partial snapshot");

        assert!(matches!(
            error,
            TraceReadError::UnstableEventLogSnapshot {
                attempts: EVENT_LOG_SNAPSHOT_ATTEMPTS,
                ..
            }
        ));
        fs::remove_dir_all(dir).expect("temp directory should remove");
    }

    #[test]
    fn read_events_jsonl_returns_line_numbered_parse_errors() {
        let session_id = SessionId::new();
        let first = serde_json::to_string(&event(session_id, "/first")).unwrap();
        let input = format!("{first}\nnot json\n");

        let error = read_events_jsonl(input.as_bytes()).expect_err("line two should fail");

        match error {
            TraceReadError::ParseLine { line_number, .. } => assert_eq!(line_number, 2),
            other => panic!("expected parse error, got {other:?}"),
        }
    }

    #[test]
    fn read_events_jsonl_rejects_unsupported_schema_versions() {
        let mut value = serde_json::to_value(event(SessionId::new(), "/old")).unwrap();
        value["schema_version"] = serde_json::json!(0);
        let input = serde_json::to_string(&value).unwrap();

        let error = read_events_jsonl(input.as_bytes()).expect_err("old schema should fail");

        match error {
            TraceReadError::UnsupportedSchemaVersion {
                line_number,
                schema_version,
                expected_schema_version,
                ..
            } => {
                assert_eq!(line_number, 1);
                assert_eq!(schema_version, 0);
                assert_eq!(expected_schema_version, EVENT_SCHEMA_VERSION);
            }
            other => panic!("expected unsupported schema error, got {other:?}"),
        }
    }

    #[test]
    fn read_events_jsonl_rejects_unsupported_schema_before_unknown_kind_parse() {
        let session_id = SessionId::new();
        let mut value = serde_json::to_value(event(session_id, "/future")).unwrap();
        value["schema_version"] = serde_json::json!(EVENT_SCHEMA_VERSION + 1);
        value["kind"] = serde_json::json!({
            "type": "future_event_kind",
            "field": "not supported by this reader"
        });
        let input = serde_json::to_string(&value).unwrap();

        let error = read_events_jsonl(input.as_bytes()).expect_err("future schema should fail");

        match error {
            TraceReadError::UnsupportedSchemaVersion {
                schema_version,
                expected_schema_version,
                ..
            } => {
                assert_eq!(schema_version, EVENT_SCHEMA_VERSION + 1);
                assert_eq!(expected_schema_version, EVENT_SCHEMA_VERSION);
            }
            other => panic!("expected unsupported schema error, got {other:?}"),
        }
    }

    #[test]
    fn file_reader_errors_include_path_context() {
        let path = PathBuf::from("/tmp/eidolon-events.jsonl");
        let error = read_events_jsonl_with_path("not json\n".as_bytes(), Some(path.clone()))
            .expect_err("invalid json should fail");

        match error {
            TraceReadError::ParseLine {
                path: Some(error_path),
                line_number,
                ..
            } => {
                assert_eq!(error_path, path);
                assert_eq!(line_number, 1);
            }
            other => panic!("expected path-aware parse error, got {other:?}"),
        }
    }
}
