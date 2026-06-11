use std::{env, fmt, fs, path::PathBuf, process::ExitCode};

use eidolon_core::SessionId;
use eidolon_trace::{
    build_session_timelines, edge_decision_export_for_timeline, read_events_jsonl_file,
    SessionTimeline,
};

fn main() -> ExitCode {
    match CliAction::from_args(env::args().skip(1)) {
        Ok(CliAction::Help) => {
            print!("{}", usage());
            ExitCode::SUCCESS
        }
        Ok(CliAction::Run(config)) => match run(config) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("error: {error}\n\n{}", usage());
            ExitCode::from(2)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliConfig {
    events_path: PathBuf,
    session_id: Option<SessionId>,
    pretty: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CliAction {
    Run(CliConfig),
    Help,
}

impl CliAction {
    fn from_args<I, S>(args: I) -> Result<Self, CliError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut builder = CliConfigBuilder::default();
        let mut args = args.into_iter().map(Into::into).peekable();

        while let Some(arg) = args.next() {
            if arg == "-h" || arg == "--help" {
                return Ok(Self::Help);
            }

            let (flag, inline_value) = split_option(&arg)?;
            match flag {
                "--events" => {
                    let value = option_value(flag, inline_value, &mut args)?;
                    set_once(&mut builder.events_path, flag, parse_events_path(&value)?)?;
                }
                "--session" => {
                    let value = option_value(flag, inline_value, &mut args)?;
                    set_once(&mut builder.session_id, flag, parse_session_id(&value)?)?;
                }
                "--pretty" => {
                    if builder.pretty {
                        return Err(CliError::new(format!("duplicate option `{flag}`")));
                    }
                    builder.pretty = true;
                }
                _ if flag.starts_with('-') => {
                    return Err(CliError::new(format!("unknown option `{flag}`")));
                }
                _ => {
                    return Err(CliError::new(format!(
                        "unexpected positional argument `{flag}`"
                    )));
                }
            }
        }

        builder.build().map(Self::Run)
    }
}

#[derive(Debug, Default)]
struct CliConfigBuilder {
    events_path: Option<PathBuf>,
    session_id: Option<SessionId>,
    pretty: bool,
}

impl CliConfigBuilder {
    fn build(self) -> Result<CliConfig, CliError> {
        Ok(CliConfig {
            events_path: self
                .events_path
                .ok_or_else(|| CliError::new("missing value for `--events`"))?,
            session_id: self.session_id,
            pretty: self.pretty,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliError {
    message: String,
}

impl CliError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

fn run(config: CliConfig) -> Result<(), CliError> {
    let events = read_events_jsonl_file(&config.events_path)
        .map_err(|error| CliError::new(error.to_string()))?;
    let timelines = build_session_timelines(events);
    let timeline = select_timeline(&timelines, config.session_id)?;
    let export = edge_decision_export_for_timeline(timeline)
        .ok_or_else(|| CliError::new("selected session has no request_seen event to export"))?;

    if config.pretty {
        println!(
            "{}",
            serde_json::to_string_pretty(&export)
                .expect("edge decision export should serialize pretty")
        );
    } else {
        println!(
            "{}",
            serde_json::to_string(&export).expect("edge decision export should serialize")
        );
    }

    Ok(())
}

fn select_timeline(
    timelines: &[SessionTimeline],
    session_id: Option<SessionId>,
) -> Result<&SessionTimeline, CliError> {
    if timelines.is_empty() {
        return Err(CliError::new(
            "event log does not contain any session timelines",
        ));
    }

    if let Some(session_id) = session_id {
        return timelines
            .iter()
            .find(|timeline| timeline.session_id == session_id)
            .ok_or_else(|| {
                CliError::new(format!("session `{}` not found in event log", session_id.0))
            });
    }

    if timelines.len() == 1 {
        return Ok(&timelines[0]);
    }

    Err(CliError::new(
        "event log contains multiple sessions; pass `--session <UUID>`",
    ))
}

fn usage() -> String {
    "\
Usage: eidolon-edge-export [OPTIONS]

Options:
  --events <PATH>   Event JSONL file path
  --session <UUID>  Optional session ID; required when the file contains multiple sessions
  --pretty          Pretty-print JSON output
  -h, --help        Show this help text

Example:
  cargo run -p eidolon-trace --bin eidolon-edge-export -- --events /tmp/eidolon-events.jsonl --pretty
"
    .to_string()
}

fn split_option(arg: &str) -> Result<(&str, Option<String>), CliError> {
    if let Some((flag, value)) = arg.split_once('=') {
        if flag.is_empty() {
            return Err(CliError::new("empty option name"));
        }
        Ok((flag, Some(value.to_string())))
    } else {
        Ok((arg, None))
    }
}

fn option_value<I>(
    flag: &str,
    inline_value: Option<String>,
    args: &mut std::iter::Peekable<I>,
) -> Result<String, CliError>
where
    I: Iterator<Item = String>,
{
    if let Some(value) = inline_value {
        return Ok(value);
    }

    match args.next() {
        Some(value) if !value.starts_with('-') => Ok(value),
        Some(next_flag) => Err(CliError::new(format!(
            "missing value for `{flag}` before `{next_flag}`"
        ))),
        None => Err(CliError::new(format!("missing value for `{flag}`"))),
    }
}

fn set_once<T>(slot: &mut Option<T>, flag: &str, value: T) -> Result<(), CliError> {
    if slot.replace(value).is_some() {
        return Err(CliError::new(format!("duplicate option `{flag}`")));
    }
    Ok(())
}

fn parse_events_path(raw: &str) -> Result<PathBuf, CliError> {
    if raw.trim().is_empty() {
        return Err(CliError::new("events path cannot be empty"));
    }

    if raw.split(['/', '\\']).any(|segment| segment == "..") {
        return Err(CliError::new(format!(
            "events path must not contain parent traversal components: `{raw}`",
        )));
    }

    let path = fs::canonicalize(raw).map_err(|error| {
        CliError::new(format!(
            "events path must exist and resolve cleanly: {error}"
        ))
    })?;
    if !path.is_file() {
        return Err(CliError::new(format!(
            "events path must be an existing file: `{}`",
            path.display()
        )));
    }

    Ok(path)
}

fn parse_session_id(raw: &str) -> Result<SessionId, CliError> {
    if raw.trim().is_empty() {
        return Err(CliError::new("session ID cannot be empty"));
    }

    raw.parse()
        .map(SessionId)
        .map_err(|error| CliError::new(format!("session ID must be a valid UUID: {error}")))
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use chrono::{TimeZone, Utc};
    use eidolon_core::{
        EdgeRecommendedAction, Event, EventKind, EventSource, IngressIdentity,
        IngressIdentitySource, IngressTrustTier, PolicyState, RoutingDecision,
    };
    use uuid::Uuid;

    use super::*;

    fn must_ok<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{context}: {error}"),
        }
    }

    fn must_some<T>(value: Option<T>, context: &str) -> T {
        match value {
            Some(value) => value,
            None => panic!("{context}"),
        }
    }

    fn path_str<'a>(path: &'a Path, context: &str) -> &'a str {
        match path.to_str() {
            Some(value) => value,
            None => panic!("{context}"),
        }
    }

    fn unique_temp_path(name: &str) -> PathBuf {
        let unique = format!(
            "eidolon-edge-export-{}-{}-{name}",
            std::process::id(),
            Uuid::new_v4()
        );
        env::temp_dir().join(unique)
    }

    fn write_events(events: &[Event]) -> PathBuf {
        let path = unique_temp_path("events.jsonl");
        let body = events
            .iter()
            .map(|event| must_ok(serde_json::to_string(event), "event should serialize"))
            .collect::<Vec<_>>()
            .join("\n");
        must_ok(
            fs::write(&path, format!("{body}\n")),
            "event log should write",
        );
        path
    }

    fn request_event(session_id: SessionId, path: &str) -> Event {
        let mut event = Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::Observe,
            EventKind::RequestSeen {
                method: "GET".to_string(),
                path: path.to_string(),
                safe_headers: Vec::new(),
                ingress_identity: IngressIdentity {
                    source: IngressIdentitySource::LocalAllowlist,
                    trust_tier: IngressTrustTier::Allowlisted,
                    label: Some("internal-crawler".to_string()),
                    expires_at: None,
                },
                ingress_signals: Default::default(),
                discovery_recon_score: Default::default(),
                routing_decision: RoutingDecision::ProtectedUpstream,
            },
        );
        event.observed_at = Utc
            .with_ymd_and_hms(2026, 6, 5, 12, 0, 0)
            .single()
            .unwrap_or_else(|| panic!("timestamp should be valid"));
        event
    }

    #[test]
    fn parses_explicit_flags() {
        let events_path = unique_temp_path("parse-events.jsonl");
        must_ok(fs::write(&events_path, ""), "placeholder should write");
        let session_id = SessionId::new();

        let action = CliAction::from_args([
            "--events",
            path_str(&events_path, "events path should be utf8"),
            "--session",
            &session_id.0.to_string(),
            "--pretty",
        ])
        .unwrap_or_else(|error| panic!("config should parse: {error}"));

        let CliAction::Run(config) = action else {
            panic!("expected runnable config");
        };

        assert_eq!(
            config.events_path,
            must_ok(
                fs::canonicalize(&events_path),
                "events path should canonicalize"
            )
        );
        assert_eq!(config.session_id, Some(session_id));
        assert!(config.pretty);
    }

    #[test]
    fn rejects_missing_or_invalid_inputs() {
        let events_path = unique_temp_path("invalid-session-events.jsonl");
        must_ok(fs::write(&events_path, ""), "placeholder should write");
        let missing_events =
            CliAction::from_args(["--events", ""]).expect_err("empty path should fail");
        let invalid_session = CliAction::from_args([
            "--events",
            path_str(&events_path, "events path should be utf8"),
            "--session",
            "not-a-uuid",
        ])
        .expect_err("invalid session should fail");

        assert!(missing_events
            .to_string()
            .contains("events path cannot be empty"));
        assert!(invalid_session
            .to_string()
            .contains("session ID must be a valid UUID"));
    }

    #[test]
    fn requires_explicit_session_when_event_log_has_multiple_sessions() {
        let first_session = SessionId::new();
        let second_session = SessionId::new();
        let path = write_events(&[
            request_event(first_session, "/docs/legacy-import"),
            request_event(second_session, "/openapi.json"),
        ]);
        let events = must_ok(read_events_jsonl_file(&path), "events should parse");
        let timelines = build_session_timelines(events);

        let error = select_timeline(&timelines, None).expect_err("selection should fail");

        assert!(error
            .to_string()
            .contains("event log contains multiple sessions"));
    }

    #[test]
    fn selects_single_timeline_and_emits_export() {
        let session_id = SessionId::new();
        let path = write_events(&[
            request_event(session_id, "/docs/legacy-import"),
            Event::new(
                session_id,
                EventSource::PolicyRouter,
                PolicyState::Observe,
                EventKind::PolicyDecision {
                    routing_decision: RoutingDecision::ProtectedUpstream,
                    reason: "trusted ingress identity suppressed bait surface intervention before runtime suspicion was established".to_string(),
                },
            ),
        ]);
        let events = must_ok(read_events_jsonl_file(&path), "events should parse");
        let timelines = build_session_timelines(events);
        let timeline = must_ok(
            select_timeline(&timelines, None),
            "single session should select",
        );
        let export = must_some(
            edge_decision_export_for_timeline(timeline),
            "edge decision export should exist",
        );

        assert_eq!(export.session_id, session_id);
        assert_eq!(export.request.path, "/docs/legacy-import");
        assert_eq!(
            export.edge_recommendation.action,
            EdgeRecommendedAction::Allow
        );
    }
}
