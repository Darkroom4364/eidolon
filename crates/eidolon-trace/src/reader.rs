use std::{
    error::Error,
    fmt,
    fs::File,
    io::{self, BufRead, BufReader},
    path::{Path, PathBuf},
};

use eidolon_core::{Event, EVENT_SCHEMA_VERSION};
use serde_json::Value;

use crate::TimelineEvent;

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
        }
    }
}

impl Error for TraceReadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Open { source, .. } | Self::ReadLine { source, .. } => Some(source),
            Self::ParseLine { source, .. } => Some(source),
            Self::MissingSchemaVersion { .. } | Self::UnsupportedSchemaVersion { .. } => None,
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

#[cfg(test)]
mod tests {
    use eidolon_core::{
        EventKind, EventSource, IngressIdentity, PolicyState, RoutingDecision, SessionId,
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
