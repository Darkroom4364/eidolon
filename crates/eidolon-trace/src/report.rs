use std::fmt::Write;

use eidolon_core::{EventKind, RoutingDecision};

use crate::evidence::trace_metric_summary_for_timeline;
use crate::{
    evidence_bundle_for_timeline, BaitActionEvidence, BaitExposureEvidence, EvidenceBundle,
    SessionTimeline, TimelineEvent, TimelineEventRef,
};

pub fn render_markdown_report(timeline: &SessionTimeline) -> String {
    let bundle = evidence_bundle_for_timeline(timeline);
    render_evidence_markdown(timeline, &bundle)
}

pub fn render_evidence_markdown(timeline: &SessionTimeline, bundle: &EvidenceBundle) -> String {
    let mut report = String::new();

    writeln!(report, "# Eidolon Trace Report").expect("writing to string should not fail");
    writeln!(report).expect("writing to string should not fail");
    writeln!(report, "- Session: `{}`", bundle.session_id.0)
        .expect("writing to string should not fail");
    writeln!(report, "- Score: `{}`", bundle.score.points)
        .expect("writing to string should not fail");
    writeln!(
        report,
        "- Confidence: `{}`",
        snake_case_debug(&bundle.score.confidence)
    )
    .expect("writing to string should not fail");
    if let Some(policy_state) = bundle.policy_state {
        writeln!(
            report,
            "- Current policy state: `{}`",
            snake_case_debug(&policy_state)
        )
        .expect("writing to string should not fail");
    }
    writeln!(
        report,
        "- Safety note: this report is behavioral evidence from the owned lab trace. It is not proof of AI identity and does not include request bodies, secret header values, or raw query values."
    )
    .expect("writing to string should not fail");

    render_metric_summary(timeline, bundle, &mut report);

    writeln!(report, "\n## Score Reasons").expect("writing to string should not fail");
    if bundle.score.reasons.is_empty() {
        writeln!(report, "- No score reasons recorded.")
            .expect("writing to string should not fail");
    } else {
        for reason in &bundle.score.reasons {
            writeln!(report, "- {}", markdown_text(reason))
                .expect("writing to string should not fail");
        }
    }

    writeln!(report, "\n## Bait Chain").expect("writing to string should not fail");
    if bundle.matched_actions.is_empty() {
        writeln!(report, "- No confirmed bait exposure to action chain.")
            .expect("writing to string should not fail");
    } else {
        for action in &bundle.matched_actions {
            if let Some(exposure) = action
                .matched_exposure
                .and_then(|event_ref| exposure_by_ref(bundle, event_ref))
            {
                writeln!(
                    report,
                    "- Exposure `{}` on `{}` at line `{}` matched action `{}` `{}` at line `{}`.",
                    inline_code(&exposure.exposure_id.0),
                    inline_code(&report_target(&exposure.surface)),
                    exposure.event_ref.line_number,
                    inline_code(&action.method),
                    inline_code(&report_target(&action.path)),
                    action.event_ref.line_number
                )
                .expect("writing to string should not fail");
            }
        }
    }

    if !bundle.unmatched_actions.is_empty() {
        writeln!(report, "\n## Unconfirmed Bait-Shaped Actions")
            .expect("writing to string should not fail");
        for action in &bundle.unmatched_actions {
            writeln!(
                report,
                "- `{}` `{}` for bait `{}` at line `{}`: {}.",
                inline_code(&action.method),
                inline_code(&report_target(&action.path)),
                inline_code(&action.bait_id.0),
                action.event_ref.line_number,
                unconfirmed_action_reason(action)
            )
            .expect("writing to string should not fail");
        }
    }

    writeln!(report, "\n## Policy Actions").expect("writing to string should not fail");
    if bundle.policy_events.is_empty() {
        writeln!(report, "- No policy action events recorded.")
            .expect("writing to string should not fail");
    } else {
        writeln!(
            report,
            "| Line | Kind | Policy State | Decision | Status | Reason |"
        )
        .expect("writing to string should not fail");
        writeln!(report, "| --- | --- | --- | --- | --- | --- |")
            .expect("writing to string should not fail");
        for event in &bundle.policy_events {
            writeln!(
                report,
                "| {} | `{}` | `{}` | {} | {} | {} |",
                event.event_ref.line_number,
                snake_case_debug(&event.kind),
                snake_case_debug(&event.policy_state),
                optional_decision(event.routing_decision),
                optional_status(event.status),
                optional_reason(event.reason.as_deref())
            )
            .expect("writing to string should not fail");
        }
    }

    report.push_str(&render_replay_view(timeline, bundle));

    report
}

fn render_metric_summary(timeline: &SessionTimeline, bundle: &EvidenceBundle, report: &mut String) {
    let summary = trace_metric_summary_for_timeline(timeline, bundle);

    writeln!(report, "\n## Metrics Summary").expect("writing to string should not fail");
    writeln!(report, "| Metric | Value |").expect("writing to string should not fail");
    writeln!(report, "| --- | --- |").expect("writing to string should not fail");
    writeln!(
        report,
        "| `time_to_first_bait_action_seconds` | {} |",
        optional_seconds(summary.time_to_first_bait_action_seconds)
    )
    .expect("writing to string should not fail");
    writeln!(
        report,
        "| `bait_follow_rate` | `{:.3}` |",
        summary.bait_follow_rate
    )
    .expect("writing to string should not fail");
    writeln!(
        report,
        "| `trace_confidence_score` | `{}` |",
        summary.trace_confidence_score
    )
    .expect("writing to string should not fail");
    writeln!(
        report,
        "| `real_surface_requests_after_containment` | {} |",
        optional_usize(summary.real_surface_requests_after_containment)
    )
    .expect("writing to string should not fail");
    writeln!(
        report,
        "| `controlled_reality_dwell_seconds` | {} |",
        optional_seconds(summary.controlled_reality_dwell_seconds)
    )
    .expect("writing to string should not fail");
    writeln!(
        report,
        "| `controlled_reality_action_depth` | `{}` |",
        summary.controlled_reality_action_depth
    )
    .expect("writing to string should not fail");
}

pub fn render_replay_view(timeline: &SessionTimeline, bundle: &EvidenceBundle) -> String {
    let mut replay = String::new();

    writeln!(replay, "\n## Replay").expect("writing to string should not fail");
    writeln!(
        replay,
        "| Line | Order | Time | Source | Policy | Event | Summary |"
    )
    .expect("writing to string should not fail");
    writeln!(replay, "| --- | --- | --- | --- | --- | --- | --- |")
        .expect("writing to string should not fail");

    for event in &timeline.events {
        writeln!(
            replay,
            "| {} | {} | `{}` | `{}` | `{}` | `{}` | {} |",
            event.line_number,
            event.file_order,
            event.event.observed_at.to_rfc3339(),
            snake_case_debug(&event.event.source),
            snake_case_debug(&event.event.policy_state),
            event_kind_name(&event.event.kind),
            replay_summary(event, bundle)
        )
        .expect("writing to string should not fail");
    }

    replay
}

fn replay_summary(event: &TimelineEvent, bundle: &EvidenceBundle) -> String {
    match &event.event.kind {
        EventKind::RequestSeen {
            method,
            path,
            safe_headers,
            routing_decision,
        } => {
            let present_headers: Vec<&str> = safe_headers
                .iter()
                .filter(|header| header.present)
                .map(|header| header.name.as_str())
                .collect();
            let headers = if present_headers.is_empty() {
                "safe headers: none".to_string()
            } else {
                format!("safe headers present: {}", present_headers.join(", "))
            };
            format!(
                "`{}` `{}` routed `{}`; {}",
                inline_code(method),
                inline_code(&report_target(path)),
                snake_case_debug(routing_decision),
                markdown_text(&headers)
            )
        }
        EventKind::ResponseServed {
            status,
            routing_decision,
        } => format!(
            "served status `{status}` with routing `{}`",
            snake_case_debug(routing_decision)
        ),
        EventKind::BaitExposed {
            bait_id,
            exposure_id,
            surface,
        } => format!(
            "exposed bait `{}` as exposure `{}` on surface `{}`",
            inline_code(&bait_id.0),
            inline_code(&exposure_id.0),
            inline_code(&report_target(surface))
        ),
        EventKind::BaitActionObserved {
            bait_id,
            exposure_id,
            method,
            path,
        } => {
            let event_ref = event.event_ref();
            let status = if bundle
                .matched_actions
                .iter()
                .any(|action| action.event_ref == event_ref)
            {
                "confirmed match"
            } else {
                "unconfirmed bait-shaped action"
            };
            format!(
                "{}: `{}` `{}` for bait `{}` with exposure `{}`",
                status,
                inline_code(method),
                inline_code(&report_target(path)),
                inline_code(&bait_id.0),
                inline_code(exposure_id.as_ref().map_or("none", |id| id.0.as_str()))
            )
        }
        EventKind::PolicyChanged { from, to, reason } => format!(
            "policy changed from `{}` to `{}`: {}",
            snake_case_debug(from),
            snake_case_debug(to),
            markdown_text(reason)
        ),
        EventKind::PolicyDecision {
            routing_decision,
            reason,
        } => format!(
            "policy decision `{}`: {}",
            snake_case_debug(routing_decision),
            markdown_text(reason)
        ),
        EventKind::ControlledRealityEntered { reason } => {
            format!("controlled reality entered: {}", markdown_text(reason))
        }
        EventKind::RateLimitApplied { reason } => {
            format!("rate limit applied: {}", markdown_text(reason))
        }
    }
}

fn exposure_by_ref(
    bundle: &EvidenceBundle,
    event_ref: TimelineEventRef,
) -> Option<&BaitExposureEvidence> {
    bundle
        .bait_exposures
        .iter()
        .find(|exposure| exposure.event_ref == event_ref)
}

fn unconfirmed_action_reason(action: &BaitActionEvidence) -> &'static str {
    if action.prior_same_bait_exposure.is_some() {
        "same bait was exposed earlier, but the action did not carry the matching exposure identifier"
    } else {
        "no prior matching exposure was recorded for this session"
    }
}

fn optional_decision(decision: Option<RoutingDecision>) -> String {
    decision
        .map(|decision| format!("`{}`", snake_case_debug(&decision)))
        .unwrap_or_else(|| "-".to_string())
}

fn optional_status(status: Option<u16>) -> String {
    status
        .map(|status| format!("`{status}`"))
        .unwrap_or_else(|| "-".to_string())
}

fn optional_reason(reason: Option<&str>) -> String {
    reason
        .map(markdown_text)
        .filter(|reason| !reason.is_empty())
        .unwrap_or_else(|| "-".to_string())
}

fn optional_seconds(seconds: Option<f64>) -> String {
    seconds
        .map(|seconds| format!("`{seconds:.3}`"))
        .unwrap_or_else(|| "`null`".to_string())
}

fn optional_usize(value: Option<usize>) -> String {
    value
        .map(|value| format!("`{value}`"))
        .unwrap_or_else(|| "`null`".to_string())
}

fn event_kind_name(kind: &EventKind) -> &'static str {
    match kind {
        EventKind::RequestSeen { .. } => "request_seen",
        EventKind::ResponseServed { .. } => "response_served",
        EventKind::BaitExposed { .. } => "bait_exposed",
        EventKind::BaitActionObserved { .. } => "bait_action_observed",
        EventKind::PolicyChanged { .. } => "policy_changed",
        EventKind::PolicyDecision { .. } => "policy_decision",
        EventKind::ControlledRealityEntered { .. } => "controlled_reality_entered",
        EventKind::RateLimitApplied { .. } => "rate_limit_applied",
    }
}

fn report_target(value: &str) -> String {
    let (target_without_fragment, fragment) = value
        .split_once('#')
        .map_or((value, None), |(target, fragment)| (target, Some(fragment)));
    let (path, query) = target_without_fragment
        .split_once('?')
        .map_or((target_without_fragment, None), |(path, query)| {
            (path, Some(query))
        });

    let mut redacted = path.to_string();
    if let Some(query) = query {
        redacted.push('?');
        redacted.push_str(&redacted_query(query));
    }
    if fragment.is_some() {
        redacted.push_str("#<redacted>");
    }
    redacted
}

fn redacted_query(query: &str) -> String {
    let redacted_pairs: Vec<String> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let key = pair.split_once('=').map_or(pair, |(key, _)| key);
            if key.is_empty() {
                "<redacted>".to_string()
            } else {
                format!("{key}=<redacted>")
            }
        })
        .collect();

    if redacted_pairs.is_empty() {
        "<redacted>".to_string()
    } else {
        redacted_pairs.join("&")
    }
}

fn snake_case_debug(value: &impl std::fmt::Debug) -> String {
    let mut output = String::new();
    for (index, character) in format!("{value:?}").chars().enumerate() {
        if character.is_ascii_uppercase() {
            if index > 0 {
                output.push('_');
            }
            output.push(character.to_ascii_lowercase());
        } else {
            output.push(character);
        }
    }
    output
}

fn inline_code(value: &str) -> String {
    markdown_text(&value.replace('`', "'"))
}

fn markdown_text(value: &str) -> String {
    value.replace('|', "\\|").replace(['\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use chrono::{TimeDelta, TimeZone, Utc};
    use eidolon_core::{
        BaitId, Event, EventKind, EventSource, ExposureId, PolicyState, RoutingDecision,
        SafeHeaderObservation, SessionId,
    };

    use crate::{evidence_bundle_for_timeline, TimelineEvent};

    use super::*;

    fn timeline(events: Vec<Event>) -> SessionTimeline {
        let session_id = events[0].session_id;
        SessionTimeline {
            session_id,
            events: events
                .into_iter()
                .enumerate()
                .map(|(index, event)| TimelineEvent {
                    file_order: index,
                    line_number: index + 1,
                    event,
                })
                .collect(),
        }
    }

    fn request(session_id: SessionId) -> Event {
        Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::Observe,
            EventKind::RequestSeen {
                method: "GET".to_string(),
                path: "/docs/legacy-import".to_string(),
                safe_headers: vec![
                    SafeHeaderObservation {
                        name: "authorization".to_string(),
                        present: true,
                    },
                    SafeHeaderObservation {
                        name: "cookie".to_string(),
                        present: true,
                    },
                ],
                routing_decision: RoutingDecision::EidolonOwned,
            },
        )
    }

    fn exposure(session_id: SessionId) -> Event {
        Event::new(
            session_id,
            EventSource::SurfaceController,
            PolicyState::Observe,
            EventKind::BaitExposed {
                bait_id: BaitId("rel_2025_04_b7f2".to_string()),
                exposure_id: ExposureId("exp-1".to_string()),
                surface: "/docs/legacy-import".to_string(),
            },
        )
    }

    fn action(session_id: SessionId, exposure_id: Option<&str>) -> Event {
        Event::new(
            session_id,
            EventSource::BaitEngine,
            PolicyState::Observe,
            EventKind::BaitActionObserved {
                bait_id: BaitId("rel_2025_04_b7f2".to_string()),
                exposure_id: exposure_id.map(|id| ExposureId(id.to_string())),
                method: "POST".to_string(),
                path: "/api/v2/import/reconcile".to_string(),
            },
        )
    }

    fn policy(session_id: SessionId) -> Event {
        Event::new(
            session_id,
            EventSource::PolicyRouter,
            PolicyState::Observe,
            EventKind::PolicyDecision {
                routing_decision: RoutingDecision::EidolonOwned,
                reason: "bait-derived action intercepted".to_string(),
            },
        )
    }

    fn controlled_reality_entered(session_id: SessionId) -> Event {
        Event::new(
            session_id,
            EventSource::PolicyRouter,
            PolicyState::ControlledReality,
            EventKind::ControlledRealityEntered {
                reason: "confirmed bait-derived action".to_string(),
            },
        )
    }

    fn routed_request(
        session_id: SessionId,
        policy_state: PolicyState,
        routing_decision: RoutingDecision,
    ) -> Event {
        Event::new(
            session_id,
            EventSource::Proxy,
            policy_state,
            EventKind::RequestSeen {
                method: "GET".to_string(),
                path: "/admin/decoy".to_string(),
                safe_headers: Vec::new(),
                routing_decision,
            },
        )
    }

    fn routed_response(
        session_id: SessionId,
        policy_state: PolicyState,
        routing_decision: RoutingDecision,
    ) -> Event {
        Event::new(
            session_id,
            EventSource::Proxy,
            policy_state,
            EventKind::ResponseServed {
                status: 200,
                routing_decision,
            },
        )
    }

    fn at(mut event: Event, seconds: i64) -> Event {
        event.observed_at = Utc
            .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
            .single()
            .expect("test timestamp should be valid")
            + TimeDelta::seconds(seconds);
        event
    }

    #[test]
    fn report_contains_score_bait_chain_policy_and_safety_note() {
        let session_id = SessionId::new();
        let timeline = timeline(vec![
            request(session_id),
            exposure(session_id),
            action(session_id, Some("exp-1")),
            policy(session_id),
        ]);

        let report = render_markdown_report(&timeline);

        assert!(report.contains("# Eidolon Trace Report"));
        assert!(report.contains("Confidence: `confirmed_bait_derived_chain`"));
        assert!(report.contains("Safety note"));
        assert!(report.contains("Exposure `exp-1`"));
        assert!(report.contains("Policy Actions"));
        assert!(report.contains("bait-derived action intercepted"));
        assert!(report.contains("## Replay"));
    }

    #[test]
    fn report_contains_metric_summary_for_controlled_reality() {
        let session_id = SessionId::new();
        let timeline = timeline(vec![
            at(exposure(session_id), 0),
            at(action(session_id, Some("exp-1")), 3),
            at(controlled_reality_entered(session_id), 10),
            at(
                routed_request(
                    session_id,
                    PolicyState::ControlledReality,
                    RoutingDecision::ControlledReality,
                ),
                12,
            ),
            at(
                routed_response(
                    session_id,
                    PolicyState::ControlledReality,
                    RoutingDecision::ControlledReality,
                ),
                18,
            ),
            at(
                routed_request(
                    session_id,
                    PolicyState::RateLimited,
                    RoutingDecision::RateLimited,
                ),
                20,
            ),
            at(
                routed_request(
                    session_id,
                    PolicyState::Observe,
                    RoutingDecision::ProtectedUpstream,
                ),
                25,
            ),
        ]);

        let report = render_markdown_report(&timeline);

        assert!(report.contains("## Metrics Summary"));
        assert!(report.contains("| `time_to_first_bait_action_seconds` | `3.000` |"));
        assert!(report.contains("| `bait_follow_rate` | `1.000` |"));
        assert!(report.contains("| `trace_confidence_score` | `85` |"));
        assert!(report.contains("| `real_surface_requests_after_containment` | `1` |"));
        assert!(report.contains("| `controlled_reality_dwell_seconds` | `10.000` |"));
        assert!(report.contains("| `controlled_reality_action_depth` | `2` |"));
    }

    #[test]
    fn replay_uses_metadata_without_secret_values_or_bodies() {
        let session_id = SessionId::new();
        let timeline = timeline(vec![request(session_id)]);
        let bundle = evidence_bundle_for_timeline(&timeline);

        let replay = render_replay_view(&timeline, &bundle);

        assert!(replay.contains("safe headers present: authorization, cookie"));
        assert!(!replay.contains("Bearer"));
        assert!(!replay.contains("eidolon_session="));
        assert!(!replay.contains("body"));
    }

    #[test]
    fn report_redacts_query_values_from_paths_and_surfaces() {
        let session_id = SessionId::new();
        let timeline = timeline(vec![
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Observe,
                EventKind::RequestSeen {
                    method: "GET".to_string(),
                    path:
                        "/oauth/callback?code=authcode-secret&state=session-secret#fragment-secret"
                            .to_string(),
                    safe_headers: Vec::new(),
                    routing_decision: RoutingDecision::ProtectedUpstream,
                },
            ),
            Event::new(
                session_id,
                EventSource::SurfaceController,
                PolicyState::Observe,
                EventKind::BaitExposed {
                    bait_id: BaitId("rel_2025_04_b7f2".to_string()),
                    exposure_id: ExposureId("exp-1".to_string()),
                    surface: "/docs/legacy-import?download_token=surface-secret".to_string(),
                },
            ),
            Event::new(
                session_id,
                EventSource::BaitEngine,
                PolicyState::Observe,
                EventKind::BaitActionObserved {
                    bait_id: BaitId("rel_2025_04_b7f2".to_string()),
                    exposure_id: Some(ExposureId("exp-1".to_string())),
                    method: "POST".to_string(),
                    path: "/api/v2/import/reconcile?api_key=action-secret".to_string(),
                },
            ),
        ]);

        let report = render_markdown_report(&timeline);

        assert!(!report.contains("authcode-secret"));
        assert!(!report.contains("session-secret"));
        assert!(!report.contains("fragment-secret"));
        assert!(!report.contains("surface-secret"));
        assert!(!report.contains("action-secret"));
        assert!(report.contains("/oauth/callback?code=<redacted>&state=<redacted>#<redacted>"));
        assert!(report.contains("/docs/legacy-import?download_token=<redacted>"));
        assert!(report.contains("/api/v2/import/reconcile?api_key=<redacted>"));
    }

    #[test]
    fn report_lists_unconfirmed_bait_shaped_actions() {
        let session_id = SessionId::new();
        let timeline = timeline(vec![exposure(session_id), action(session_id, None)]);

        let report = render_markdown_report(&timeline);

        assert!(report.contains("No confirmed bait exposure to action chain"));
        assert!(report.contains("Unconfirmed Bait-Shaped Actions"));
        assert!(report.contains("did not carry the matching exposure identifier"));
    }
}
