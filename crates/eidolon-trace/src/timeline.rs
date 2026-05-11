use std::collections::HashMap;

use eidolon_core::{Event, SessionId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub file_order: usize,
    pub line_number: usize,
    pub event: Event,
}

impl TimelineEvent {
    pub fn event_ref(&self) -> TimelineEventRef {
        TimelineEventRef {
            event_id: self.event.id,
            file_order: self.file_order,
            line_number: self.line_number,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TimelineEventRef {
    pub event_id: Uuid,
    pub file_order: usize,
    pub line_number: usize,
}

impl From<&TimelineEvent> for TimelineEventRef {
    fn from(event: &TimelineEvent) -> Self {
        event.event_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTimeline {
    pub session_id: SessionId,
    pub events: Vec<TimelineEvent>,
}

pub fn build_session_timelines<I>(events: I) -> Vec<SessionTimeline>
where
    I: IntoIterator<Item = TimelineEvent>,
{
    let mut grouped: HashMap<SessionId, Vec<TimelineEvent>> = HashMap::new();
    for event in events {
        grouped
            .entry(event.event.session_id)
            .or_default()
            .push(event);
    }

    let mut timelines: Vec<SessionTimeline> = grouped
        .into_iter()
        .map(|(session_id, mut events)| {
            events.sort_by(|left, right| {
                left.event
                    .observed_at
                    .cmp(&right.event.observed_at)
                    .then(left.file_order.cmp(&right.file_order))
            });

            SessionTimeline { session_id, events }
        })
        .collect();

    timelines.sort_by_key(|timeline| timeline.session_id.0);
    timelines
}

#[cfg(test)]
mod tests {
    use chrono::TimeDelta;
    use eidolon_core::{EventKind, EventSource, PolicyState};
    use uuid::Uuid;

    use super::*;

    fn event(session_id: SessionId) -> Event {
        Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::Observe,
            EventKind::ResponseServed {
                status: 200,
                routing_decision: eidolon_core::RoutingDecision::ProtectedUpstream,
            },
        )
    }

    #[test]
    fn event_ref_preserves_replay_coordinates() {
        let timeline_event = TimelineEvent {
            file_order: 7,
            line_number: 8,
            event: event(SessionId::new()),
        };

        assert_eq!(
            timeline_event.event_ref(),
            TimelineEventRef {
                event_id: timeline_event.event.id,
                file_order: 7,
                line_number: 8,
            }
        );
    }

    #[test]
    fn build_session_timelines_groups_and_sorts_events() {
        let first_session = SessionId::new();
        let second_session = SessionId::new();
        let mut later = event(first_session);
        let earlier = event(first_session);
        later.observed_at = earlier.observed_at + TimeDelta::seconds(1);

        let timelines = build_session_timelines([
            TimelineEvent {
                file_order: 1,
                line_number: 2,
                event: later,
            },
            TimelineEvent {
                file_order: 0,
                line_number: 1,
                event: earlier,
            },
            TimelineEvent {
                file_order: 2,
                line_number: 3,
                event: event(second_session),
            },
        ]);

        let first = timelines
            .iter()
            .find(|timeline| timeline.session_id == first_session)
            .expect("first session timeline should exist");
        assert_eq!(first.events[0].file_order, 0);
        assert_eq!(first.events[1].file_order, 1);

        let second = timelines
            .iter()
            .find(|timeline| timeline.session_id == second_session)
            .expect("second session timeline should exist");
        assert_eq!(second.events.len(), 1);
    }

    #[test]
    fn build_session_timelines_uses_file_order_as_stable_tie_breaker() {
        let session_id = SessionId::new();
        let first = event(session_id);
        let mut second = event(session_id);
        second.observed_at = first.observed_at;

        let timelines = build_session_timelines([
            TimelineEvent {
                file_order: 10,
                line_number: 11,
                event: second,
            },
            TimelineEvent {
                file_order: 2,
                line_number: 3,
                event: first,
            },
        ]);

        assert_eq!(timelines[0].events[0].file_order, 2);
        assert_eq!(timelines[0].events[1].file_order, 10);
    }

    #[test]
    fn build_session_timelines_returns_sessions_in_stable_id_order() {
        let later_session = SessionId(Uuid::from_u128(2));
        let earlier_session = SessionId(Uuid::from_u128(1));

        let timelines = build_session_timelines([
            TimelineEvent {
                file_order: 0,
                line_number: 1,
                event: event(later_session),
            },
            TimelineEvent {
                file_order: 1,
                line_number: 2,
                event: event(earlier_session),
            },
        ]);

        assert_eq!(timelines[0].session_id, earlier_session);
        assert_eq!(timelines[1].session_id, later_session);
    }
}
