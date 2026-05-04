use eidolon_bait::{docs_for_bait, BasicBaitTemplate};
use eidolon_core::{Event, EventKind, EventSource, ExposureId, PolicyState, SessionId};
use eidolon_trace::score_events;

fn main() {
    let session_id = SessionId::new();
    let bait = BasicBaitTemplate::legacy_import_demo().to_bait();
    let exposure_id = ExposureId(format!("{}:{}", session_id.0, bait.id.0));

    let events = vec![
        Event::new(
            session_id,
            EventSource::SurfaceController,
            PolicyState::Observe,
            EventKind::BaitExposed {
                bait_id: bait.id.clone(),
                exposure_id: exposure_id.clone(),
                surface: bait.surface.clone(),
            },
        ),
        Event::new(
            session_id,
            EventSource::BaitEngine,
            PolicyState::Observe,
            EventKind::BaitActionObserved {
                bait_id: bait.id.clone(),
                exposure_id: Some(exposure_id),
                method: bait.expected_action.method.clone(),
                path: bait.expected_action.path.clone(),
            },
        ),
    ];

    let score = score_events(&events);

    println!("{}", docs_for_bait(&bait));
    println!("score: {} {:?}", score.points, score.confidence);
    for reason in score.reasons {
        println!("- {reason}");
    }
}
