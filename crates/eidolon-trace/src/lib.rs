use std::collections::HashSet;

use eidolon_core::{BaitId, ConfidenceBand, Event, EventKind, ExposureId, Score, SessionId};

pub fn score_events(events: &[Event]) -> Score {
    let mut points = 0;
    let mut reasons = Vec::new();
    let mut exposures = HashSet::new();
    let mut acted = false;
    let mut confirmed = false;

    for event in events {
        match &event.kind {
            EventKind::BaitExposed {
                bait_id,
                exposure_id,
                ..
            } => {
                exposures.insert(ExposureKey {
                    session_id: event.session_id,
                    bait_id: bait_id.clone(),
                    exposure_id: exposure_id.clone(),
                });
            }
            EventKind::BaitActionObserved {
                bait_id,
                exposure_id,
                ..
            } => {
                acted = true;
                if exposure_id.as_ref().is_some_and(|exposure_id| {
                    exposures.contains(&ExposureKey {
                        session_id: event.session_id,
                        bait_id: bait_id.clone(),
                        exposure_id: exposure_id.clone(),
                    })
                }) {
                    confirmed = true;
                }
            }
            _ => {}
        }
    }

    let exposed = !exposures.is_empty();

    if exposed {
        points += 15;
        reasons.push("controlled bait was exposed to the session".to_string());
    }

    if confirmed {
        points += 70;
        reasons.push("session performed an action matching bait-derived evidence".to_string());
    } else if acted {
        points += 40;
        reasons.push(
            "session performed a bait-shaped action without a matching recorded exposure"
                .to_string(),
        );
    }

    let confidence = match (confirmed, acted, points) {
        (true, _, _) => ConfidenceBand::ConfirmedBaitDerivedChain,
        (false, true, _) => ConfidenceBand::Medium,
        (_, _, 50..) => ConfidenceBand::High,
        (_, _, 20..) => ConfidenceBand::Medium,
        _ => ConfidenceBand::Low,
    };

    Score {
        points,
        confidence,
        reasons,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ExposureKey {
    session_id: SessionId,
    bait_id: BaitId,
    exposure_id: ExposureId,
}

#[cfg(test)]
mod tests {
    use eidolon_core::{
        BaitId, Event, EventKind, EventSource, ExposureId, PolicyState, RoutingDecision, SessionId,
    };

    use super::*;

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
            },
        )
    }

    #[test]
    fn exposure_and_action_confirms_bait_chain() {
        let session_id = SessionId::new();
        let score = score_events(&[bait_exposed(session_id), bait_action(session_id)]);

        assert_eq!(score.points, 85);
        assert_eq!(score.confidence, ConfidenceBand::ConfirmedBaitDerivedChain);
        assert_eq!(score.reasons.len(), 2);
    }

    #[test]
    fn exposure_without_action_scores_low() {
        let session_id = SessionId::new();
        let score = score_events(&[bait_exposed(session_id)]);

        assert_eq!(score.points, 15);
        assert_eq!(score.confidence, ConfidenceBand::Low);
    }

    #[test]
    fn action_without_exposure_is_not_confirmed() {
        let session_id = SessionId::new();
        let score = score_events(&[bait_action(session_id)]);

        assert_eq!(score.points, 40);
        assert_eq!(score.confidence, ConfidenceBand::Medium);
        assert!(score.reasons[0].contains("without a matching"));
    }

    #[test]
    fn wrong_session_exposure_and_action_are_not_confirmed() {
        let score = score_events(&[
            bait_exposed(SessionId::new()),
            bait_action(SessionId::new()),
        ]);

        assert_eq!(score.points, 55);
        assert_eq!(score.confidence, ConfidenceBand::Medium);
        assert!(score.reasons[1].contains("without a matching"));
    }

    #[test]
    fn action_before_exposure_is_not_confirmed() {
        let session_id = SessionId::new();
        let score = score_events(&[bait_action(session_id), bait_exposed(session_id)]);

        assert_eq!(score.points, 55);
        assert_eq!(score.confidence, ConfidenceBand::Medium);
        assert!(score.reasons[1].contains("without a matching"));
    }

    #[test]
    fn mismatched_exposure_id_is_not_confirmed() {
        let session_id = SessionId::new();
        let score = score_events(&[
            bait_exposed_with(session_id, "rel_2025_04_b7f2", "exp-1"),
            bait_action_with(session_id, "rel_2025_04_b7f2", Some("exp-2")),
        ]);

        assert_eq!(score.confidence, ConfidenceBand::Medium);
    }

    #[test]
    fn mismatched_bait_id_is_not_confirmed() {
        let session_id = SessionId::new();
        let score = score_events(&[
            bait_exposed_with(session_id, "rel_2025_04_b7f2", "exp-1"),
            bait_action_with(session_id, "different", Some("exp-1")),
        ]);

        assert_eq!(score.confidence, ConfidenceBand::Medium);
    }

    #[test]
    fn action_with_null_exposure_id_is_not_confirmed() {
        let session_id = SessionId::new();
        let score = score_events(&[
            bait_exposed(session_id),
            bait_action_with(session_id, "rel_2025_04_b7f2", None),
        ]);

        assert_eq!(score.confidence, ConfidenceBand::Medium);
    }

    #[test]
    fn near_miss_request_does_not_score() {
        let session_id = SessionId::new();
        let event = Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::Observe,
            EventKind::RequestSeen {
                method: "POST".to_string(),
                path: "/api/v2/import/reconcile".to_string(),
                safe_headers: Vec::new(),
                routing_decision: RoutingDecision::ProtectedUpstream,
            },
        );

        let score = score_events(&[event]);

        assert_eq!(score.points, 0);
        assert_eq!(score.confidence, ConfidenceBand::Low);
        assert!(score.reasons.is_empty());
    }
}
