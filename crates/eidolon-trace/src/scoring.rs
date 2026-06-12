use eidolon_core::{ConfidenceBand, Event, Score};

use crate::{
    build_session_timelines,
    evidence::{collect_evidence, EvidenceBundle},
    SessionTimeline, TimelineEvent,
};

pub fn score_events(events: &[Event]) -> Score {
    let timeline_events = events
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, event)| TimelineEvent {
            file_order: index,
            line_number: index + 1,
            event,
        });
    let timelines = build_session_timelines(timeline_events);

    score_timelines(&timelines)
}

pub fn score_timelines(timelines: &[SessionTimeline]) -> Score {
    timelines
        .iter()
        .map(score_timeline)
        .max_by_key(|score| (confidence_rank(score.confidence), score.points))
        .unwrap_or_else(low_score)
}

pub fn score_timeline(timeline: &SessionTimeline) -> Score {
    score_evidence(&collect_evidence(timeline))
}

pub fn score_evidence(bundle: &EvidenceBundle) -> Score {
    let mut points = 0;
    let mut reasons = Vec::new();
    let exposed = !bundle.bait_exposures.is_empty();
    let confirmed = !bundle.matched_actions.is_empty();
    let acted = confirmed || !bundle.unmatched_actions.is_empty();
    let same_bait_after_exposure = bundle
        .unmatched_actions
        .iter()
        .any(|action| action.prior_same_bait_exposure.is_some());

    if exposed {
        points += 15;
        reasons.push("controlled bait was exposed to the session".to_string());
    }

    if confirmed {
        points += 70;
        reasons.push("session performed an action matching bait-derived evidence".to_string());
    } else if same_bait_after_exposure {
        points += 50;
        reasons.push(
            "session performed a same-bait action after exposure, but correlation identifiers did not match"
                .to_string(),
        );
    } else if acted {
        points += 40;
        reasons.push(
            "session performed a bait-shaped action without a matching recorded exposure"
                .to_string(),
        );
    }

    let confidence = if confirmed {
        ConfidenceBand::ConfirmedBaitDerivedChain
    } else if same_bait_after_exposure {
        ConfidenceBand::High
    } else if acted || points >= 20 {
        ConfidenceBand::Medium
    } else {
        ConfidenceBand::Low
    };

    Score {
        points,
        confidence,
        reasons,
    }
}

fn low_score() -> Score {
    Score {
        points: 0,
        confidence: ConfidenceBand::Low,
        reasons: Vec::new(),
    }
}

fn confidence_rank(confidence: ConfidenceBand) -> i32 {
    match confidence {
        ConfidenceBand::Low => 0,
        ConfidenceBand::Medium => 1,
        ConfidenceBand::High => 2,
        ConfidenceBand::ConfirmedBaitDerivedChain => 3,
    }
}

#[cfg(test)]
mod tests {
    use eidolon_core::{
        BaitId, Event, EventKind, EventSource, ExposureId, IngressIdentity, PolicyState,
        RoutingDecision, SessionId,
    };

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

    fn bait_exposed(session_id: SessionId) -> Event {
        bait_exposed_with(session_id, "rel_2025_04_b7f2", "exp-1")
    }

    fn bait_exposed_with(session_id: SessionId, bait_id: &str, exposure_id: &str) -> Event {
        Event::new(
            session_id,
            EventSource::SurfaceController,
            PolicyState::Observe,
            EventKind::BaitExposed {
                bait_id: BaitId(bait_id.to_string()),
                exposure_id: ExposureId(exposure_id.to_string()),
                surface: "/docs/legacy-import".to_string(),
                header_value_mint: None,
            },
        )
    }

    fn bait_action(session_id: SessionId) -> Event {
        bait_action_with(session_id, "rel_2025_04_b7f2", Some("exp-1"))
    }

    fn bait_action_with(session_id: SessionId, bait_id: &str, exposure_id: Option<&str>) -> Event {
        Event::new(
            session_id,
            EventSource::BaitEngine,
            PolicyState::Observe,
            EventKind::BaitActionObserved {
                bait_id: BaitId(bait_id.to_string()),
                exposure_id: exposure_id.map(|exposure_id| ExposureId(exposure_id.to_string())),
                method: "POST".to_string(),
                path: "/api/v2/import/reconcile".to_string(),
                header_value_mint: None,
                header_value_mint_status: None,
            },
        )
    }

    fn request_seen(session_id: SessionId, path: &str) -> Event {
        Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::Observe,
            EventKind::RequestSeen {
                method: "POST".to_string(),
                path: path.to_string(),
                safe_headers: Vec::new(),
                ingress_identity: IngressIdentity::default(),
                ingress_signals: Default::default(),
                discovery_recon_score: Default::default(),
                routing_decision: RoutingDecision::ProtectedUpstream,
            },
        )
    }

    #[test]
    fn exact_bait_chain_is_confirmed() {
        let session_id = SessionId::new();
        let score = score_timeline(&timeline(vec![
            bait_exposed(session_id),
            bait_action(session_id),
        ]));

        assert_eq!(score.points, 85);
        assert_eq!(score.confidence, ConfidenceBand::ConfirmedBaitDerivedChain);
        assert_eq!(score.reasons.len(), 2);
        assert!(score.reasons[0].contains("controlled bait was exposed"));
    }

    #[test]
    fn exposure_without_action_scores_low() {
        let session_id = SessionId::new();
        let score = score_timeline(&timeline(vec![bait_exposed(session_id)]));

        assert_eq!(score.points, 15);
        assert_eq!(score.confidence, ConfidenceBand::Low);
    }

    #[test]
    fn action_without_exposure_is_medium_not_confirmed() {
        let session_id = SessionId::new();
        let score = score_timeline(&timeline(vec![bait_action(session_id)]));

        assert_eq!(score.points, 40);
        assert_eq!(score.confidence, ConfidenceBand::Medium);
        assert!(score.reasons[0].contains("without a matching"));
    }

    #[test]
    fn same_bait_action_after_exposure_with_missing_id_is_high_not_confirmed() {
        let session_id = SessionId::new();
        let score = score_timeline(&timeline(vec![
            bait_exposed(session_id),
            bait_action_with(session_id, "rel_2025_04_b7f2", None),
        ]));

        assert_eq!(score.points, 65);
        assert_eq!(score.confidence, ConfidenceBand::High);
        assert!(score.reasons[1].contains("correlation identifiers did not match"));
    }

    #[test]
    fn wrong_session_exposure_and_action_are_not_confirmed() {
        let score = score_events(&[
            bait_exposed(SessionId::new()),
            bait_action(SessionId::new()),
        ]);

        assert_eq!(score.points, 40);
        assert_eq!(score.confidence, ConfidenceBand::Medium);
        assert!(score.reasons[0].contains("without a matching"));
    }

    #[test]
    fn action_before_exposure_is_not_confirmed_or_high() {
        let session_id = SessionId::new();
        let score = score_timeline(&timeline(vec![
            bait_action(session_id),
            bait_exposed(session_id),
        ]));

        assert_eq!(score.points, 55);
        assert_eq!(score.confidence, ConfidenceBand::Medium);
        assert!(score.reasons[1].contains("without a matching"));
    }

    #[test]
    fn mismatched_exposure_id_is_high_but_not_confirmed() {
        let session_id = SessionId::new();
        let score = score_timeline(&timeline(vec![
            bait_exposed_with(session_id, "rel_2025_04_b7f2", "exp-1"),
            bait_action_with(session_id, "rel_2025_04_b7f2", Some("exp-2")),
        ]));

        assert_eq!(score.confidence, ConfidenceBand::High);
    }

    #[test]
    fn mismatched_bait_id_is_medium_not_high() {
        let session_id = SessionId::new();
        let score = score_timeline(&timeline(vec![
            bait_exposed_with(session_id, "rel_2025_04_b7f2", "exp-1"),
            bait_action_with(session_id, "different", Some("exp-1")),
        ]));

        assert_eq!(score.confidence, ConfidenceBand::Medium);
    }

    #[test]
    fn sham_surface_without_bait_exposure_scores_low() {
        let session_id = SessionId::new();
        let score = score_timeline(&timeline(vec![
            request_seen(session_id, "/docs/sham-import"),
            request_seen(session_id, "/api/v2/import/reconcile"),
        ]));

        assert_eq!(score.points, 0);
        assert_eq!(score.confidence, ConfidenceBand::Low);
        assert!(score.reasons.is_empty());
    }

    #[test]
    fn near_miss_request_does_not_score() {
        let session_id = SessionId::new();
        let score = score_timeline(&timeline(vec![request_seen(
            session_id,
            "/api/v2/import/reconcile",
        )]));

        assert_eq!(score.points, 0);
        assert_eq!(score.confidence, ConfidenceBand::Low);
        assert!(score.reasons.is_empty());
    }

    #[test]
    fn score_timelines_returns_strongest_session_score() {
        let exposed_session = SessionId::new();
        let confirmed_session = SessionId::new();
        let timelines = vec![
            timeline(vec![bait_exposed(exposed_session)]),
            timeline(vec![
                bait_exposed(confirmed_session),
                bait_action(confirmed_session),
            ]),
        ];

        let score = score_timelines(&timelines);

        assert_eq!(score.confidence, ConfidenceBand::ConfirmedBaitDerivedChain);
    }

    #[test]
    fn score_timelines_uses_points_as_tie_breaker_within_confidence_band() {
        let action_only_session = SessionId::new();
        let action_before_exposure_session = SessionId::new();
        let timelines = vec![
            timeline(vec![bait_action(action_only_session)]),
            timeline(vec![
                bait_action(action_before_exposure_session),
                bait_exposed(action_before_exposure_session),
            ]),
        ];

        let score = score_timelines(&timelines);

        assert_eq!(score.confidence, ConfidenceBand::Medium);
        assert_eq!(score.points, 55);
    }

    #[test]
    fn confidence_rank_order_is_stable_for_timeline_selection() {
        assert!(
            confidence_rank(ConfidenceBand::ConfirmedBaitDerivedChain)
                > confidence_rank(ConfidenceBand::High)
        );
        assert!(confidence_rank(ConfidenceBand::High) > confidence_rank(ConfidenceBand::Medium));
        assert!(confidence_rank(ConfidenceBand::Medium) > confidence_rank(ConfidenceBand::Low));
    }
}
