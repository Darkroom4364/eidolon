use agentwall_bait::{docs_for_bait, BasicBaitTemplate};
use agentwall_core::{Event, EventKind, SessionId};
use agentwall_trace::score_events;

fn main() {
    let session_id = SessionId::new();
    let bait = BasicBaitTemplate::legacy_import_demo().to_bait();

    let events = vec![
        Event::new(
            session_id,
            EventKind::BaitExposed {
                bait_id: bait.id.clone(),
                surface: bait.surface.clone(),
            },
        ),
        Event::new(
            session_id,
            EventKind::BaitActionObserved {
                bait_id: bait.id.clone(),
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
