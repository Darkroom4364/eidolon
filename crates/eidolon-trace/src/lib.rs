use eidolon_core::{ConfidenceBand, Event, EventKind, Score};

pub fn score_events(events: &[Event]) -> Score {
    let mut points = 0;
    let mut reasons = Vec::new();

    let exposed = events
        .iter()
        .any(|event| matches!(event.kind, EventKind::BaitExposed { .. }));

    let acted = events
        .iter()
        .any(|event| matches!(event.kind, EventKind::BaitActionObserved { .. }));

    if exposed {
        points += 15;
        reasons.push("controlled bait was exposed to the session".to_string());
    }

    if exposed && acted {
        points += 70;
        reasons.push("session performed an action matching bait-derived evidence".to_string());
    } else if acted {
        points += 40;
        reasons
            .push("session performed a bait-shaped action without a recorded exposure".to_string());
    }

    let confidence = match (exposed, acted, points) {
        (true, true, _) => ConfidenceBand::ConfirmedBaitDerivedChain,
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

#[cfg(test)]
mod tests {
    use eidolon_core::{
        BaitId, Event, EventKind, EventSource, ExposureId, PolicyState, RoutingDecision, SessionId,
    };

    use super::*;

    fn bait_exposed(session_id: SessionId) -> Event {
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

    fn bait_action(session_id: SessionId) -> Event {
        Event::new(
            session_id,
            EventSource::BaitEngine,
            PolicyState::Observe,
            EventKind::BaitActionObserved {
                bait_id: BaitId("rel_2025_04_b7f2".to_string()),
                exposure_id: Some(ExposureId("exp-1".to_string())),
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
        assert!(score.reasons[0].contains("without a recorded exposure"));
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
