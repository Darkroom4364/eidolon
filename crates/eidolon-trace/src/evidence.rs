use std::collections::HashMap;

use eidolon_core::{
    BaitHeaderValueMintAudit, BaitHeaderValueMintStatus, BaitId, EventKind, ExposureId,
    PolicyState, RoutingDecision, Score, SessionId,
};
use serde::{Deserialize, Serialize};

use crate::{SessionTimeline, TimelineEvent, TimelineEventRef};

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
    pub header_value_mint: Option<BaitHeaderValueMintAudit>,
    pub event_ref: TimelineEventRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaitActionEvidence {
    pub bait_id: BaitId,
    pub exposure_id: Option<ExposureId>,
    pub method: String,
    pub path: String,
    pub header_value_mint: Option<BaitHeaderValueMintAudit>,
    pub header_value_mint_status: Option<BaitHeaderValueMintStatus>,
    pub event_ref: TimelineEventRef,
    pub matched_exposure: Option<TimelineEventRef>,
    pub prior_same_bait_exposure: Option<TimelineEventRef>,
}

/// Validity classification of the proof attached to a bait action.
///
/// Only `Accepted` actions may count as confirmed bait-derived evidence
/// (engineering operating policy invariant 3). `Rejected` and `Unknown`
/// actions remain visible as direct facts but never confirm a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofOutcome {
    /// A fresh session-minted proof matched, or the bait carries no mint
    /// concept (static bait) so no proof validity applies.
    Accepted,
    /// The proof was replayed, expired, or mismatched.
    Rejected,
    /// The bait is mint-enabled but no outcome status was recorded, for
    /// example historical events predating status auditing.
    Unknown,
}

/// Classify a bait action's proof from its mint audit metadata and recorded
/// outcome status. Static baits (no mint audit) are accepted by construction;
/// mint-enabled baits require an explicit accepted status, and historical
/// events without a status degrade to `Unknown` rather than confirmed.
pub fn proof_outcome(
    header_value_mint: &Option<BaitHeaderValueMintAudit>,
    header_value_mint_status: Option<BaitHeaderValueMintStatus>,
) -> ProofOutcome {
    match header_value_mint_status {
        Some(BaitHeaderValueMintStatus::MatchedSessionValue) => ProofOutcome::Accepted,
        Some(
            BaitHeaderValueMintStatus::ReplaySeen
            | BaitHeaderValueMintStatus::ExpiredSessionValue
            | BaitHeaderValueMintStatus::SessionValueMismatch
            | BaitHeaderValueMintStatus::ReplayStateCapacityExceeded
            | BaitHeaderValueMintStatus::ReplayStateUnavailable
            | BaitHeaderValueMintStatus::MissingSessionValue
            | BaitHeaderValueMintStatus::MalformedSessionValue,
        ) => ProofOutcome::Rejected,
        None => {
            if header_value_mint.is_some() {
                ProofOutcome::Unknown
            } else {
                ProofOutcome::Accepted
            }
        }
    }
}

impl BaitActionEvidence {
    pub fn proof_outcome(&self) -> ProofOutcome {
        proof_outcome(&self.header_value_mint, self.header_value_mint_status)
    }
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
    RealityEscapeAttempt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineComparison {
    pub baseline_name: Option<String>,
    pub points_delta: Option<i32>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct TraceMetricSummary {
    pub time_to_first_bait_action_seconds: Option<f64>,
    pub bait_follow_rate: f64,
    pub trace_confidence_score: i32,
    pub real_surface_requests_after_containment: Option<usize>,
    pub controlled_reality_dwell_seconds: Option<f64>,
    pub controlled_reality_action_depth: usize,
    pub controlled_reality_branch_count: usize,
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

pub(crate) fn trace_metric_summary_for_timeline(
    timeline: &SessionTimeline,
    bundle: &EvidenceBundle,
) -> TraceMetricSummary {
    let containment_bounds = containment_bounds(timeline);

    TraceMetricSummary {
        time_to_first_bait_action_seconds: time_to_first_bait_action_seconds(timeline, bundle),
        bait_follow_rate: if bundle.matched_actions.is_empty() {
            0.0
        } else {
            1.0
        },
        trace_confidence_score: bundle.score.points,
        real_surface_requests_after_containment: containment_bounds.map(|(first, _)| {
            timeline
                .events
                .iter()
                .skip(first + 1)
                .filter(|event| request_routes_to_real_surface(event))
                .count()
        }),
        controlled_reality_dwell_seconds: containment_bounds
            .map(|(first, last)| seconds_between(&timeline.events[first], &timeline.events[last])),
        controlled_reality_action_depth: controlled_reality_action_depth(timeline),
        controlled_reality_branch_count: controlled_reality_branch_count(timeline),
    }
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
                header_value_mint,
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
                    header_value_mint: header_value_mint.clone(),
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
                header_value_mint,
                header_value_mint_status,
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
                    header_value_mint: header_value_mint.clone(),
                    header_value_mint_status: *header_value_mint_status,
                    event_ref,
                    matched_exposure,
                    prior_same_bait_exposure,
                };

                if matched_exposure.is_some() && action.proof_outcome() == ProofOutcome::Accepted {
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
            EventKind::RealityEscapeAttempt {
                routing_decision,
                reason,
                ..
            } => {
                bundle.policy_events.push(PolicyEventEvidence {
                    event_ref,
                    policy_state: timeline_event.event.policy_state,
                    kind: PolicyEvidenceKind::RealityEscapeAttempt,
                    routing_decision: Some(*routing_decision),
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

fn time_to_first_bait_action_seconds(
    timeline: &SessionTimeline,
    bundle: &EvidenceBundle,
) -> Option<f64> {
    bundle
        .matched_actions
        .iter()
        .filter_map(|action| {
            let exposure = event_by_ref(timeline, action.matched_exposure?)?;
            let action = event_by_ref(timeline, action.event_ref)?;
            Some(seconds_between(exposure, action))
        })
        .min_by(|left, right| left.total_cmp(right))
}

fn event_by_ref(timeline: &SessionTimeline, event_ref: TimelineEventRef) -> Option<&TimelineEvent> {
    timeline.events.iter().find(|event| {
        event.event.id == event_ref.event_id
            && event.file_order == event_ref.file_order
            && event.line_number == event_ref.line_number
    })
}

fn containment_bounds(timeline: &SessionTimeline) -> Option<(usize, usize)> {
    let mut first = None;
    let mut last = None;

    for (index, event) in timeline.events.iter().enumerate() {
        if containment_marker(event) {
            first.get_or_insert(index);
            last = Some(index);
        }
    }

    first.zip(last)
}

fn containment_marker(event: &TimelineEvent) -> bool {
    containment_policy_state(event.event.policy_state)
        || policy_change_touches_containment(&event.event.kind)
        || request_or_response_routes_to_containment(&event.event.kind)
        || matches!(
            &event.event.kind,
            EventKind::ControlledRealityEntered { .. }
        )
}

fn controlled_reality_request(event: &TimelineEvent) -> bool {
    match &event.event.kind {
        EventKind::RequestSeen {
            routing_decision, ..
        } => {
            containment_policy_state(event.event.policy_state)
                || containment_routing_decision(*routing_decision)
        }
        _ => false,
    }
}

fn controlled_reality_action_depth(timeline: &SessionTimeline) -> usize {
    let mut depth = 0;
    let mut pending_request_was_containment = None;

    for event in &timeline.events {
        match &event.event.kind {
            EventKind::RequestSeen { .. } => {
                let contained = controlled_reality_request(event);
                if contained {
                    depth += 1;
                }
                pending_request_was_containment = Some(contained);
            }
            EventKind::ResponseServed {
                routing_decision, ..
            } if containment_routing_decision(*routing_decision) => {
                if pending_request_was_containment != Some(true) {
                    depth += 1;
                }
                pending_request_was_containment = None;
            }
            EventKind::ResponseServed { .. } => {
                pending_request_was_containment = None;
            }
            _ => {}
        }
    }

    depth
}

fn controlled_reality_branch_count(timeline: &SessionTimeline) -> usize {
    let mut branches = std::collections::HashSet::new();
    let mut pending_request = None;

    for event in &timeline.events {
        match &event.event.kind {
            EventKind::RequestSeen {
                path,
                routing_decision,
                ..
            } => {
                let contained = containment_policy_state(event.event.policy_state)
                    || containment_routing_decision(*routing_decision);
                if contained {
                    branches.insert(normalized_branch_path(path).to_string());
                }
                pending_request = Some((normalized_branch_path(path).to_string(), contained));
            }
            EventKind::ResponseServed {
                routing_decision, ..
            } if containment_routing_decision(*routing_decision) => {
                if let Some((path, false)) = pending_request.take() {
                    branches.insert(path);
                }
            }
            EventKind::ResponseServed { .. } => {
                pending_request = None;
            }
            _ => {}
        }
    }

    branches.len()
}

fn normalized_branch_path(target: &str) -> &str {
    let without_fragment = target.split_once('#').map_or(target, |(path, _)| path);
    without_fragment
        .split_once('?')
        .map_or(without_fragment, |(path, _)| path)
}

fn request_or_response_routes_to_containment(kind: &EventKind) -> bool {
    match kind {
        EventKind::RequestSeen {
            routing_decision, ..
        }
        | EventKind::ResponseServed {
            routing_decision, ..
        } => containment_routing_decision(*routing_decision),
        _ => false,
    }
}

fn request_routes_to_real_surface(event: &TimelineEvent) -> bool {
    match &event.event.kind {
        EventKind::RequestSeen {
            routing_decision, ..
        } => matches!(
            *routing_decision,
            RoutingDecision::ProtectedUpstream | RoutingDecision::RewrittenUpstream
        ),
        _ => false,
    }
}

fn policy_change_touches_containment(kind: &EventKind) -> bool {
    match kind {
        EventKind::PolicyChanged { from, to, .. } => {
            containment_policy_state(*from) || containment_policy_state(*to)
        }
        _ => false,
    }
}

fn containment_policy_state(policy_state: PolicyState) -> bool {
    matches!(
        policy_state,
        PolicyState::ControlledReality | PolicyState::RateLimited
    )
}

fn containment_routing_decision(routing_decision: RoutingDecision) -> bool {
    matches!(
        routing_decision,
        RoutingDecision::ControlledReality | RoutingDecision::RateLimited
    )
}

fn seconds_between(start: &TimelineEvent, end: &TimelineEvent) -> f64 {
    let milliseconds = end
        .event
        .observed_at
        .signed_duration_since(start.event.observed_at)
        .num_milliseconds()
        .max(0);
    milliseconds as f64 / 1000.0
}

#[cfg(test)]
mod tests {
    use chrono::{TimeDelta, TimeZone, Utc};
    use eidolon_core::{
        Event, EventKind, EventSource, ExposureId, IngressIdentity, PolicyState, RoutingDecision,
        SessionId,
    };
    use serde_json::json;

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
                header_value_mint: None,
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
                header_value_mint: None,
                header_value_mint_status: None,
            },
        )
    }

    fn request(
        session_id: SessionId,
        policy_state: PolicyState,
        routing_decision: RoutingDecision,
    ) -> Event {
        request_to_path(session_id, policy_state, routing_decision, "/admin/decoy")
    }

    fn request_to_path(
        session_id: SessionId,
        policy_state: PolicyState,
        routing_decision: RoutingDecision,
        path: &str,
    ) -> Event {
        Event::new(
            session_id,
            EventSource::Proxy,
            policy_state,
            EventKind::RequestSeen {
                method: "GET".to_string(),
                path: path.to_string(),
                safe_headers: Vec::new(),
                ingress_identity: IngressIdentity::default(),
                authenticated_ingress_rule_rejection: None,
                local_ingress_trust_scope_rejection: None,
                trusted_ingress_soften_match: None,
                ingress_signals: Default::default(),
                discovery_recon_score: Default::default(),
                routing_decision,
            },
        )
    }

    fn response(
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

    fn at(mut event: Event, seconds: i64) -> Event {
        event.observed_at = Utc
            .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
            .single()
            .expect("test timestamp should be valid")
            + TimeDelta::seconds(seconds);
        event
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
    fn collected_evidence_defaults_to_unscored_low_confidence() {
        let session_id = SessionId::new();
        let bundle = collect_evidence(&timeline(vec![exposure(session_id)]));

        assert_eq!(bundle.score.points, 0);
        assert_eq!(bundle.score.confidence, eidolon_core::ConfidenceBand::Low);
        assert!(bundle.score.reasons.is_empty());
    }

    fn mint_audit() -> BaitHeaderValueMintAudit {
        BaitHeaderValueMintAudit {
            header_name: "X-Trace".to_string(),
            kind: eidolon_core::HeaderValueMintKind::SessionHmacSha256V1,
            prefix: "test".to_string(),
        }
    }

    fn minted_action(
        session_id: SessionId,
        exposure_id: Option<&str>,
        status: Option<BaitHeaderValueMintStatus>,
    ) -> Event {
        Event::new(
            session_id,
            EventSource::BaitEngine,
            PolicyState::Observe,
            EventKind::BaitActionObserved {
                bait_id: BaitId("bait-1".to_string()),
                exposure_id: exposure_id.map(|id| ExposureId(id.to_string())),
                method: "POST".to_string(),
                path: "/api/v2/import/reconcile".to_string(),
                header_value_mint: Some(mint_audit()),
                header_value_mint_status: status,
            },
        )
    }

    fn minted_exposure(session_id: SessionId) -> Event {
        Event::new(
            session_id,
            EventSource::SurfaceController,
            PolicyState::Observe,
            EventKind::BaitExposed {
                bait_id: BaitId("bait-1".to_string()),
                exposure_id: ExposureId("exp-1".to_string()),
                surface: "/docs/legacy-import".to_string(),
                header_value_mint: Some(mint_audit()),
            },
        )
    }

    #[test]
    fn proof_outcome_classifies_accepted_rejected_and_unknown() {
        let mint = Some(mint_audit());

        assert_eq!(proof_outcome(&mint, None), ProofOutcome::Unknown);
        assert_eq!(
            proof_outcome(&mint, Some(BaitHeaderValueMintStatus::MatchedSessionValue)),
            ProofOutcome::Accepted
        );
        assert_eq!(
            proof_outcome(&mint, Some(BaitHeaderValueMintStatus::ReplaySeen)),
            ProofOutcome::Rejected
        );
        assert_eq!(
            proof_outcome(&mint, Some(BaitHeaderValueMintStatus::ExpiredSessionValue)),
            ProofOutcome::Rejected
        );
        assert_eq!(
            proof_outcome(&mint, Some(BaitHeaderValueMintStatus::SessionValueMismatch)),
            ProofOutcome::Rejected
        );

        // Static baits carry no mint concept and are accepted by construction.
        assert_eq!(proof_outcome(&None, None), ProofOutcome::Accepted);
    }

    #[test]
    fn replayed_proof_with_linked_exposure_is_not_confirmed() {
        let session_id = SessionId::new();
        let bundle = collect_evidence(&timeline(vec![
            minted_exposure(session_id),
            minted_action(
                session_id,
                Some("exp-1"),
                Some(BaitHeaderValueMintStatus::ReplaySeen),
            ),
        ]));

        assert!(bundle.matched_actions.is_empty());
        assert_eq!(bundle.unmatched_actions.len(), 1);
        assert_eq!(
            bundle.unmatched_actions[0].proof_outcome(),
            ProofOutcome::Rejected
        );
        assert!(bundle.unmatched_actions[0].matched_exposure.is_some());
    }

    #[test]
    fn expired_proof_with_linked_exposure_is_not_confirmed() {
        let session_id = SessionId::new();
        let bundle = collect_evidence(&timeline(vec![
            minted_exposure(session_id),
            minted_action(
                session_id,
                Some("exp-1"),
                Some(BaitHeaderValueMintStatus::ExpiredSessionValue),
            ),
        ]));

        assert!(bundle.matched_actions.is_empty());
        assert_eq!(bundle.unmatched_actions.len(), 1);
        assert_eq!(
            bundle.unmatched_actions[0].proof_outcome(),
            ProofOutcome::Rejected
        );
    }

    #[test]
    fn mismatched_proof_with_linked_exposure_is_not_confirmed() {
        let session_id = SessionId::new();
        let bundle = collect_evidence(&timeline(vec![
            minted_exposure(session_id),
            minted_action(
                session_id,
                Some("exp-1"),
                Some(BaitHeaderValueMintStatus::SessionValueMismatch),
            ),
        ]));

        assert!(bundle.matched_actions.is_empty());
        assert_eq!(bundle.unmatched_actions.len(), 1);
        assert_eq!(
            bundle.unmatched_actions[0].proof_outcome(),
            ProofOutcome::Rejected
        );
    }

    #[test]
    fn historical_mint_action_without_status_degrades_to_unknown() {
        let session_id = SessionId::new();
        let bundle = collect_evidence(&timeline(vec![
            minted_exposure(session_id),
            minted_action(session_id, Some("exp-1"), None),
        ]));

        assert!(bundle.matched_actions.is_empty());
        assert_eq!(bundle.unmatched_actions.len(), 1);
        assert_eq!(
            bundle.unmatched_actions[0].proof_outcome(),
            ProofOutcome::Unknown
        );
        assert!(bundle.unmatched_actions[0].matched_exposure.is_some());
    }

    #[test]
    fn accepted_mint_proof_with_linked_exposure_is_confirmed() {
        let session_id = SessionId::new();
        let bundle = collect_evidence(&timeline(vec![
            minted_exposure(session_id),
            minted_action(
                session_id,
                Some("exp-1"),
                Some(BaitHeaderValueMintStatus::MatchedSessionValue),
            ),
        ]));

        assert_eq!(bundle.matched_actions.len(), 1);
        assert_eq!(
            bundle.matched_actions[0].proof_outcome(),
            ProofOutcome::Accepted
        );
        assert!(bundle.unmatched_actions.is_empty());
    }

    #[test]
    fn mixed_session_confirms_only_from_accepted_proofs() {
        let session_id = SessionId::new();
        let bundle = collect_evidence(&timeline(vec![
            minted_exposure(session_id),
            minted_action(
                session_id,
                Some("exp-1"),
                Some(BaitHeaderValueMintStatus::ReplaySeen),
            ),
            exposure(session_id),
            action(session_id, Some("exp-1")),
        ]));

        assert_eq!(bundle.matched_actions.len(), 1);
        assert_eq!(
            bundle.matched_actions[0].proof_outcome(),
            ProofOutcome::Accepted
        );
        assert_eq!(bundle.unmatched_actions.len(), 1);
        assert_eq!(
            bundle.unmatched_actions[0].proof_outcome(),
            ProofOutcome::Rejected
        );
    }

    #[test]
    fn event_lookup_requires_all_replay_coordinates_to_match() {
        let session_id = SessionId::new();
        let timeline = timeline(vec![
            exposure(session_id),
            action(session_id, Some("exp-1")),
        ]);
        let exposure_ref = timeline.events[0].event_ref();

        assert!(event_by_ref(&timeline, exposure_ref).is_some());
        assert!(event_by_ref(
            &timeline,
            TimelineEventRef {
                event_id: exposure_ref.event_id,
                file_order: exposure_ref.file_order + 1,
                line_number: exposure_ref.line_number,
            },
        )
        .is_none());
        assert!(event_by_ref(
            &timeline,
            TimelineEventRef {
                event_id: exposure_ref.event_id,
                file_order: exposure_ref.file_order,
                line_number: exposure_ref.line_number + 1,
            },
        )
        .is_none());
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

    #[test]
    fn trace_summary_measures_bait_follow_and_controlled_reality_depth() {
        let session_id = SessionId::new();
        let timeline = timeline(vec![
            at(exposure(session_id), 0),
            at(action(session_id, Some("exp-1")), 5),
            at(controlled_reality_entered(session_id), 10),
            at(
                request(
                    session_id,
                    PolicyState::ControlledReality,
                    RoutingDecision::ControlledReality,
                ),
                12,
            ),
            at(
                response(
                    session_id,
                    PolicyState::ControlledReality,
                    RoutingDecision::ControlledReality,
                ),
                14,
            ),
            at(
                request(
                    session_id,
                    PolicyState::RateLimited,
                    RoutingDecision::RateLimited,
                ),
                20,
            ),
            at(
                request(
                    session_id,
                    PolicyState::Observe,
                    RoutingDecision::ProtectedUpstream,
                ),
                21,
            ),
        ]);
        let bundle = evidence_bundle_for_timeline(&timeline);

        let summary = trace_metric_summary_for_timeline(&timeline, &bundle);

        assert_eq!(summary.time_to_first_bait_action_seconds, Some(5.0));
        assert_eq!(summary.bait_follow_rate, 1.0);
        assert_eq!(summary.trace_confidence_score, 85);
        assert_eq!(summary.real_surface_requests_after_containment, Some(1));
        assert_eq!(summary.controlled_reality_dwell_seconds, Some(10.0));
        assert_eq!(summary.controlled_reality_action_depth, 2);
        assert_eq!(summary.controlled_reality_branch_count, 1);

        let serialized =
            serde_json::to_value(&summary).expect("trace metric summary should serialize");
        assert_eq!(serialized["controlled_reality_action_depth"], json!(2));
        assert_eq!(serialized["controlled_reality_branch_count"], json!(1));
        assert_eq!(
            serialized["real_surface_requests_after_containment"],
            json!(1)
        );
    }

    #[test]
    fn trace_summary_counts_only_real_surface_requests_after_containment_marker() {
        let session_id = SessionId::new();
        let timeline = timeline(vec![
            request(
                session_id,
                PolicyState::ControlledReality,
                RoutingDecision::ProtectedUpstream,
            ),
            request(
                session_id,
                PolicyState::Observe,
                RoutingDecision::ProtectedUpstream,
            ),
            request(
                session_id,
                PolicyState::Observe,
                RoutingDecision::RewrittenUpstream,
            ),
        ]);
        let bundle = evidence_bundle_for_timeline(&timeline);

        let summary = trace_metric_summary_for_timeline(&timeline, &bundle);

        assert_eq!(summary.real_surface_requests_after_containment, Some(2));
    }

    #[test]
    fn trace_summary_treats_policy_change_to_containment_as_containment_marker() {
        let session_id = SessionId::new();
        let policy_changed = Event::new(
            session_id,
            EventSource::PolicyRouter,
            PolicyState::Observe,
            EventKind::PolicyChanged {
                from: PolicyState::Observe,
                to: PolicyState::ControlledReality,
                reason: "confirmed bait-derived action".to_string(),
            },
        );
        let timeline = timeline(vec![
            at(policy_changed, 0),
            at(
                request(
                    session_id,
                    PolicyState::Observe,
                    RoutingDecision::ProtectedUpstream,
                ),
                1,
            ),
        ]);
        let bundle = evidence_bundle_for_timeline(&timeline);

        let summary = trace_metric_summary_for_timeline(&timeline, &bundle);

        assert_eq!(summary.controlled_reality_dwell_seconds, Some(0.0));
        assert_eq!(summary.real_surface_requests_after_containment, Some(1));
    }

    #[test]
    fn trace_summary_does_not_treat_bait_events_as_containment() {
        let session_id = SessionId::new();
        let timeline = timeline(vec![
            exposure(session_id),
            action(session_id, Some("exp-1")),
        ]);
        let bundle = evidence_bundle_for_timeline(&timeline);

        let summary = trace_metric_summary_for_timeline(&timeline, &bundle);

        assert_eq!(summary.real_surface_requests_after_containment, None);
        assert_eq!(summary.controlled_reality_dwell_seconds, None);
    }

    #[test]
    fn trace_summary_leaves_containment_metrics_null_before_entry() {
        let session_id = SessionId::new();
        let timeline = timeline(vec![request(
            session_id,
            PolicyState::Observe,
            RoutingDecision::ProtectedUpstream,
        )]);
        let bundle = evidence_bundle_for_timeline(&timeline);

        let summary = trace_metric_summary_for_timeline(&timeline, &bundle);

        assert_eq!(summary.time_to_first_bait_action_seconds, None);
        assert_eq!(summary.bait_follow_rate, 0.0);
        assert_eq!(summary.real_surface_requests_after_containment, None);
        assert_eq!(summary.controlled_reality_dwell_seconds, None);
        assert_eq!(summary.controlled_reality_action_depth, 0);
        assert_eq!(summary.controlled_reality_branch_count, 0);
    }

    #[test]
    fn trace_summary_counts_transition_response_as_first_controlled_action() {
        let session_id = SessionId::new();
        let timeline = timeline(vec![
            at(
                request(
                    session_id,
                    PolicyState::Observe,
                    RoutingDecision::EidolonOwned,
                ),
                0,
            ),
            at(controlled_reality_entered(session_id), 1),
            at(
                response(
                    session_id,
                    PolicyState::ControlledReality,
                    RoutingDecision::ControlledReality,
                ),
                2,
            ),
        ]);
        let bundle = evidence_bundle_for_timeline(&timeline);

        let summary = trace_metric_summary_for_timeline(&timeline, &bundle);

        assert_eq!(summary.controlled_reality_action_depth, 1);
        assert_eq!(summary.controlled_reality_branch_count, 1);
        assert_eq!(summary.controlled_reality_dwell_seconds, Some(1.0));
    }

    #[test]
    fn trace_summary_counts_distinct_controlled_reality_branches() {
        let session_id = SessionId::new();
        let timeline = timeline(vec![
            at(controlled_reality_entered(session_id), 0),
            at(
                request_to_path(
                    session_id,
                    PolicyState::ControlledReality,
                    RoutingDecision::ControlledReality,
                    "/api/v2/import/reconcile?a=1",
                ),
                1,
            ),
            at(
                request_to_path(
                    session_id,
                    PolicyState::ControlledReality,
                    RoutingDecision::ControlledReality,
                    "/api/v2/import/reconcile?a=2",
                ),
                2,
            ),
            at(
                request_to_path(
                    session_id,
                    PolicyState::ControlledReality,
                    RoutingDecision::ControlledReality,
                    "/admin/decoy",
                ),
                3,
            ),
            at(
                request_to_path(
                    session_id,
                    PolicyState::ControlledReality,
                    RoutingDecision::RateLimited,
                    "/admin/decoy",
                ),
                4,
            ),
        ]);
        let bundle = evidence_bundle_for_timeline(&timeline);

        let summary = trace_metric_summary_for_timeline(&timeline, &bundle);

        assert_eq!(summary.controlled_reality_action_depth, 4);
        assert_eq!(summary.controlled_reality_branch_count, 2);
    }

    #[test]
    fn reversed_event_timestamps_do_not_produce_negative_dwell_time() {
        let session_id = SessionId::new();
        let timeline = timeline(vec![
            at(controlled_reality_entered(session_id), 10),
            at(
                response(
                    session_id,
                    PolicyState::ControlledReality,
                    RoutingDecision::ControlledReality,
                ),
                9,
            ),
        ]);
        let bundle = evidence_bundle_for_timeline(&timeline);

        let summary = trace_metric_summary_for_timeline(&timeline, &bundle);

        assert_eq!(summary.controlled_reality_dwell_seconds, Some(0.0));
    }
}
