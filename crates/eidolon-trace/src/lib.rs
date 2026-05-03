use eidolon_core::{ConfidenceBand, Event, EventKind, Score};

pub fn score_events(events: &[Event]) -> Score {
    let mut points = 0;
    let mut reasons = Vec::new();

    let exposed = events.iter().any(|event| {
        matches!(
            event.kind,
            EventKind::BaitExposed {
                bait_id: _,
                surface: _
            }
        )
    });

    let acted = events.iter().any(|event| {
        matches!(
            event.kind,
            EventKind::BaitActionObserved {
                bait_id: _,
                method: _,
                path: _
            }
        )
    });

    if exposed {
        points += 15;
        reasons.push("controlled bait was exposed to the session".to_string());
    }

    if acted {
        points += 70;
        reasons.push("session performed an action matching bait-derived evidence".to_string());
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
