use std::collections::HashMap;

use eidolon_core::{BaitId, EventKind, ExposureId, PolicyState, RoutingDecision, Score, SessionId};
use serde::{Deserialize, Serialize};

use crate::{SessionTimeline, TimelineEventRef};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub session_id: SessionId,
    pub policy_state: Option<PolicyState>,
    pub observed_surfaces: Vec<ObservedSurface>,
    pub bait_exposures: Vec<BaitExposureEvidence>,
    pub matched_actions: Vec<BaitActionEvidence>,
    pub unmatched_actions: Vec<BaitActionEvidence>,
    pub policy_events: Vec<PolicyEventEvidence>,
    pub baseline_comparison: BaselineComparison,
    pub score: Score,
    pub source_refs: Vec<TimelineEventRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedSurface {
    pub surface: String,
    pub bait_id: BaitId,
    pub exposure_id: ExposureId,
    pub event_ref: TimelineEventRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaitExposureEvidence {
    pub bait_id: BaitId,
    pub exposure_id: ExposureId,
    pub surface: String,
    pub event_ref: TimelineEventRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaitActionEvidence {
    pub bait_id: BaitId,
    pub exposure_id: Option<ExposureId>,
    pub method: String,
    pub path: String,
    pub event_ref: TimelineEventRef,
    pub matched_exposure: Option<TimelineEventRef>,
    pub prior_same_bait_exposure: Option<TimelineEventRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEventEvidence {
    pub event_ref: TimelineEventRef,
    pub policy_state: PolicyState,
    pub kind: PolicyEvidenceKind,
    pub routing_decision: Option<RoutingDecision>,
    pub from_policy_state: Option<PolicyState>,
    pub to_policy_state: Option<PolicyState>,
    pub status: Option<u16>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEvidenceKind {
    ResponseServed,
    PolicyDecision,
    PolicyChanged,
    ControlledRealityEntered,
    RateLimitApplied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineComparison {
    pub baseline_name: Option<String>,
    pub points_delta: Option<i32>,
    pub notes: Vec<String>,
}

impl Default for BaselineComparison {
    fn default() -> Self {
        Self {
            baseline_name: None,
            points_delta: None,
            notes: vec![
                "baseline comparison is not computed in the M2 evidence bundle yet".to_string(),
            ],
        }
    }
}

pub fn evidence_bundle_for_timeline(timeline: &SessionTimeline) -> EvidenceBundle {
    let mut bundle = collect_evidence(timeline);
    bundle.score = crate::score_evidence(&bundle);
    bundle
}

pub(crate) fn collect_evidence(timeline: &SessionTimeline) -> EvidenceBundle {
    let mut exact_exposures: HashMap<(BaitId, ExposureId), TimelineEventRef> = HashMap::new();
    let mut latest_bait_exposures: HashMap<BaitId, TimelineEventRef> = HashMap::new();
    let mut bundle = EvidenceBundle {
        session_id: timeline.session_id,
        policy_state: timeline.events.last().map(|event| event.event.policy_state),
        observed_surfaces: Vec::new(),
        bait_exposures: Vec::new(),
        matched_actions: Vec::new(),
        unmatched_actions: Vec::new(),
        policy_events: Vec::new(),
        baseline_comparison: BaselineComparison::default(),
        score: Score {
            points: 0,
            confidence: eidolon_core::ConfidenceBand::Low,
            reasons: Vec::new(),
        },
        source_refs: timeline.events.iter().map(TimelineEventRef::from).collect(),
    };

    for timeline_event in &timeline.events {
        let event_ref = timeline_event.event_ref();
        match &timeline_event.event.kind {
            EventKind::BaitExposed {
                bait_id,
                exposure_id,
                surface,
            } => {
                bundle.observed_surfaces.push(ObservedSurface {
                    surface: surface.clone(),
                    bait_id: bait_id.clone(),
                    exposure_id: exposure_id.clone(),
                    event_ref,
                });
                bundle.bait_exposures.push(BaitExposureEvidence {
                    bait_id: bait_id.clone(),
                    exposure_id: exposure_id.clone(),
                    surface: surface.clone(),
                    event_ref,
                });
                exact_exposures.insert((bait_id.clone(), exposure_id.clone()), event_ref);
                latest_bait_exposures.insert(bait_id.clone(), event_ref);
            }
            EventKind::BaitActionObserved {
                bait_id,
                exposure_id,
                method,
                path,
            } => {
                let matched_exposure = exposure_id.as_ref().and_then(|exposure_id| {
                    exact_exposures
                        .get(&(bait_id.clone(), exposure_id.clone()))
                        .copied()
                });
                let prior_same_bait_exposure = if matched_exposure.is_none() {
                    latest_bait_exposures.get(bait_id).copied()
                } else {
                    None
                };
                let action = BaitActionEvidence {
                    bait_id: bait_id.clone(),
                    exposure_id: exposure_id.clone(),
                    method: method.clone(),
                    path: path.clone(),
                    event_ref,
                    matched_exposure,
                    prior_same_bait_exposure,
                };

                if matched_exposure.is_some() {
                    bundle.matched_actions.push(action);
                } else {
                    bundle.unmatched_actions.push(action);
                }
            }
            EventKind::ResponseServed {
                status,
                routing_decision,
            } => bundle.policy_events.push(PolicyEventEvidence {
                event_ref,
                policy_state: timeline_event.event.policy_state,
                kind: PolicyEvidenceKind::ResponseServed,
                routing_decision: Some(*routing_decision),
                from_policy_state: None,
                to_policy_state: None,
                status: Some(*status),
                reason: None,
            }),
            EventKind::PolicyDecision {
                routing_decision,
                reason,
            } => bundle.policy_events.push(PolicyEventEvidence {
                event_ref,
                policy_state: timeline_event.event.policy_state,
                kind: PolicyEvidenceKind::PolicyDecision,
                routing_decision: Some(*routing_decision),
                from_policy_state: None,
                to_policy_state: None,
                status: None,
                reason: Some(reason.clone()),
            }),
            EventKind::PolicyChanged { from, to, reason } => {
                bundle.policy_events.push(PolicyEventEvidence {
                    event_ref,
                    policy_state: timeline_event.event.policy_state,
                    kind: PolicyEvidenceKind::PolicyChanged,
                    routing_decision: None,
                    from_policy_state: Some(*from),
                    to_policy_state: Some(*to),
                    status: None,
                    reason: Some(reason.clone()),
                });
            }
            EventKind::ControlledRealityEntered { reason } => {
                bundle.policy_events.push(PolicyEventEvidence {
                    event_ref,
                    policy_state: timeline_event.event.policy_state,
                    kind: PolicyEvidenceKind::ControlledRealityEntered,
                    routing_decision: Some(RoutingDecision::ControlledReality),
                    from_policy_state: None,
                    to_policy_state: None,
                    status: None,
                    reason: Some(reason.clone()),
                });
            }
            EventKind::RateLimitApplied { reason } => {
                bundle.policy_events.push(PolicyEventEvidence {
                    event_ref,
                    policy_state: timeline_event.event.policy_state,
                    kind: PolicyEvidenceKind::RateLimitApplied,
                    routing_decision: Some(RoutingDecision::RateLimited),
                    from_policy_state: None,
                    to_policy_state: None,
                    status: None,
                    reason: Some(reason.clone()),
                });
            }
            EventKind::RequestSeen { .. } => {}
        }
    }

    bundle
}

#[cfg(test)]
mod tests {
    use eidolon_core::{
        Event, EventKind, EventSource, ExposureId, PolicyState, RoutingDecision, SessionId,
    };

    use crate::TimelineEvent;

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

    fn exposure(session_id: SessionId) -> Event {
        Event::new(
            session_id,
            EventSource::SurfaceController,
            PolicyState::Observe,
            EventKind::BaitExposed {
                bait_id: BaitId("bait-1".to_string()),
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
                bait_id: BaitId("bait-1".to_string()),
                exposure_id: exposure_id.map(|id| ExposureId(id.to_string())),
                method: "POST".to_string(),
                path: "/api/v2/import/reconcile".to_string(),
            },
        )
    }

    #[test]
    fn bundle_records_surfaces_matched_actions_policy_and_source_refs() {
        let session_id = SessionId::new();
        let policy = Event::new(
            session_id,
            EventSource::PolicyRouter,
            PolicyState::Observe,
            EventKind::PolicyDecision {
                routing_decision: RoutingDecision::EidolonOwned,
                reason: "bait-derived action intercepted".to_string(),
            },
        );

        let bundle = evidence_bundle_for_timeline(&timeline(vec![
            exposure(session_id),
            action(session_id, Some("exp-1")),
            policy,
        ]));

        assert_eq!(bundle.session_id, session_id);
        assert_eq!(bundle.observed_surfaces.len(), 1);
        assert_eq!(bundle.bait_exposures.len(), 1);
        assert_eq!(bundle.matched_actions.len(), 1);
        assert!(bundle.unmatched_actions.is_empty());
        assert_eq!(bundle.policy_events.len(), 1);
        assert_eq!(bundle.source_refs.len(), 3);
        assert_eq!(
            bundle.matched_actions[0].matched_exposure,
            Some(bundle.bait_exposures[0].event_ref)
        );
        assert_eq!(
            bundle.baseline_comparison.notes,
            vec!["baseline comparison is not computed in the M2 evidence bundle yet"]
        );
        serde_json::to_string(&bundle).expect("evidence bundle should serialize");
    }

    #[test]
    fn bundle_keeps_same_bait_unmatched_action_for_negative_controls() {
        let session_id = SessionId::new();
        let bundle = evidence_bundle_for_timeline(&timeline(vec![
            exposure(session_id),
            action(session_id, None),
        ]));

        assert!(bundle.matched_actions.is_empty());
        assert_eq!(bundle.unmatched_actions.len(), 1);
        assert_eq!(
            bundle.unmatched_actions[0].prior_same_bait_exposure,
            Some(bundle.bait_exposures[0].event_ref)
        );
    }
}
