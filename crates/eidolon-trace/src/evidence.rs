use std::collections::{HashMap, HashSet};

use eidolon_core::{
    BaitClass, BaitHeaderValueMintAudit, BaitHeaderValueMintStatus, BaitId,
    ControlledRealityInteraction, ControlledRealityInteractionAction,
    ControlledRealityWorkflowState, EventKind, EventSource, ExposureId, PersistenceMetadata,
    PolicyState, RequestId, RoutingDecision, Score, SessionId,
};
use serde::{Deserialize, Serialize};

use crate::{SessionTimeline, TimelineEvent, TimelineEventRef};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub session_id: SessionId,
    pub policy_state: Option<PolicyState>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_observations: Vec<RequestObservation>,
    pub observed_surfaces: Vec<ObservedSurface>,
    pub bait_exposures: Vec<BaitExposureEvidence>,
    pub matched_actions: Vec<BaitActionEvidence>,
    pub unmatched_actions: Vec<BaitActionEvidence>,
    pub policy_events: Vec<PolicyEventEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub controlled_reality_interactions: Vec<ControlledRealityInteractionEvidence>,
    pub baseline_comparison: BaselineComparison,
    pub score: Score,
    pub source_refs: Vec<TimelineEventRef>,
}

/// Minimal request facts used to prove that bait events came from exact,
/// uniquely observed requests. The path is retained exactly as recorded by the
/// redacted event contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestObservation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<EventSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_state: Option<PolicyState>,
    pub method: String,
    pub path: String,
    pub routing_decision: RoutingDecision,
    pub event_ref: TimelineEventRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedSurface {
    pub surface: String,
    pub bait_id: BaitId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bait_class: Option<BaitClass>,
    pub exposure_id: ExposureId,
    pub event_ref: TimelineEventRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaitExposureEvidence {
    pub bait_id: BaitId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bait_class: Option<BaitClass>,
    pub exposure_id: ExposureId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
    pub surface: String,
    pub header_value_mint: Option<BaitHeaderValueMintAudit>,
    pub event_ref: TimelineEventRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaitActionEvidence {
    pub bait_id: BaitId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bait_class: Option<BaitClass>,
    pub exposure_id: Option<ExposureId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BaitActionConfirmationFailureReason {
    MissingCorrelationMetadata,
    MissingOrDuplicateRequestObservation,
    RequestShapeMismatch,
    UnsafeActionRouting,
    InvalidEventOrder,
    ProofAuditMismatch,
}

pub(crate) fn confirms_bait_action(bundle: &EvidenceBundle, action: &BaitActionEvidence) -> bool {
    bundle
        .bait_exposures
        .iter()
        .any(|exposure| confirms_bait_action_pair(bundle, exposure, action))
}

pub(crate) fn bait_action_confirmation_failure(
    bundle: &EvidenceBundle,
    action: &BaitActionEvidence,
) -> Option<BaitActionConfirmationFailureReason> {
    if confirms_bait_action(bundle, action) {
        return None;
    }

    let Some(matched_exposure) = action.matched_exposure else {
        return Some(BaitActionConfirmationFailureReason::MissingCorrelationMetadata);
    };
    let Some(exposure) = bundle
        .bait_exposures
        .iter()
        .find(|exposure| exposure.event_ref == matched_exposure)
    else {
        return Some(BaitActionConfirmationFailureReason::MissingCorrelationMetadata);
    };

    confirms_bait_action_pair_result(bundle, exposure, action).err()
}

fn confirms_bait_action_pair(
    bundle: &EvidenceBundle,
    exposure: &BaitExposureEvidence,
    action: &BaitActionEvidence,
) -> bool {
    confirms_bait_action_pair_result(bundle, exposure, action).is_ok()
}

fn confirms_bait_action_pair_result(
    bundle: &EvidenceBundle,
    exposure: &BaitExposureEvidence,
    action: &BaitActionEvidence,
) -> Result<(), BaitActionConfirmationFailureReason> {
    let (
        Some(exposure_class),
        Some(action_class),
        Some(action_exposure_id),
        Some(exposure_request_id),
        Some(action_request_id),
        Some(matched_exposure),
    ) = (
        exposure.bait_class,
        action.bait_class,
        action.exposure_id.as_ref(),
        exposure.request_id,
        action.request_id,
        action.matched_exposure,
    )
    else {
        return Err(BaitActionConfirmationFailureReason::MissingCorrelationMetadata);
    };

    if exposure.bait_id != action.bait_id
        || exposure_class != action_class
        || exposure.exposure_id != *action_exposure_id
        || exposure.event_ref != matched_exposure
    {
        return Err(BaitActionConfirmationFailureReason::MissingCorrelationMetadata);
    }

    let Some(exposure_request) = unique_request_observation(bundle, exposure_request_id) else {
        return Err(BaitActionConfirmationFailureReason::MissingOrDuplicateRequestObservation);
    };
    let Some(action_request) = unique_request_observation(bundle, action_request_id) else {
        return Err(BaitActionConfirmationFailureReason::MissingOrDuplicateRequestObservation);
    };

    if exposure_request_id == action_request_id
        || exposure_request.path != exposure.surface
        || action_request.method != action.method
        || action_request.path != action.path
    {
        return Err(BaitActionConfirmationFailureReason::RequestShapeMismatch);
    }
    if !matches!(
        action_request.routing_decision,
        RoutingDecision::EidolonOwned | RoutingDecision::ControlledReality
    ) {
        return Err(BaitActionConfirmationFailureReason::UnsafeActionRouting);
    }
    if !(exposure_request.event_ref.file_order < exposure.event_ref.file_order
        && exposure.event_ref.file_order < action_request.event_ref.file_order
        && action_request.event_ref.file_order < action.event_ref.file_order)
    {
        return Err(BaitActionConfirmationFailureReason::InvalidEventOrder);
    }
    if !proof_matches_exposure(exposure, action) {
        return Err(BaitActionConfirmationFailureReason::ProofAuditMismatch);
    }

    Ok(())
}

fn unique_request_observation(
    bundle: &EvidenceBundle,
    request_id: RequestId,
) -> Option<&RequestObservation> {
    let mut matches = bundle
        .request_observations
        .iter()
        .filter(|observation| observation.request_id == Some(request_id));
    let observation = matches.next()?;
    matches.next().is_none().then_some(observation)
}

fn proof_matches_exposure(exposure: &BaitExposureEvidence, action: &BaitActionEvidence) -> bool {
    match (
        &exposure.header_value_mint,
        &action.header_value_mint,
        action.header_value_mint_status,
    ) {
        (Some(exposure_audit), Some(action_audit), Some(status)) => {
            exposure_audit == action_audit
                && status == BaitHeaderValueMintStatus::MatchedSessionValue
        }
        (None, None, None) => true,
        _ => false,
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
    #[serde(default, skip_serializing_if = "PersistenceMetadata::is_empty")]
    pub persistence: PersistenceMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlledRealityInteractionEvidence {
    pub request_id: RequestId,
    #[serde(flatten)]
    pub interaction: ControlledRealityInteraction,
    pub event_ref: TimelineEventRef,
}

struct ControlledRealityCandidate {
    evidence: ControlledRealityInteractionEvidence,
    source: EventSource,
    policy_state: PolicyState,
    status: u16,
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
    let mut exact_exposures: HashMap<(BaitId, Option<BaitClass>, ExposureId), TimelineEventRef> =
        HashMap::new();
    let mut latest_bait_exposures: HashMap<(BaitId, Option<BaitClass>), TimelineEventRef> =
        HashMap::new();
    let mut actions = Vec::new();
    let mut controlled_reality_candidates = Vec::new();
    let mut response_counts = HashMap::new();
    let mut bundle = EvidenceBundle {
        session_id: timeline.session_id,
        policy_state: timeline.events.last().map(|event| event.event.policy_state),
        request_observations: Vec::new(),
        observed_surfaces: Vec::new(),
        bait_exposures: Vec::new(),
        matched_actions: Vec::new(),
        unmatched_actions: Vec::new(),
        policy_events: Vec::new(),
        controlled_reality_interactions: Vec::new(),
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
                bait_class,
                exposure_id,
                surface,
                header_value_mint,
            } => {
                bundle.observed_surfaces.push(ObservedSurface {
                    surface: surface.clone(),
                    bait_id: bait_id.clone(),
                    bait_class: *bait_class,
                    exposure_id: exposure_id.clone(),
                    event_ref,
                });
                bundle.bait_exposures.push(BaitExposureEvidence {
                    bait_id: bait_id.clone(),
                    bait_class: *bait_class,
                    exposure_id: exposure_id.clone(),
                    request_id: timeline_event.event.request_id,
                    surface: surface.clone(),
                    header_value_mint: header_value_mint.clone(),
                    event_ref,
                });
                exact_exposures.insert(
                    (bait_id.clone(), *bait_class, exposure_id.clone()),
                    event_ref,
                );
                latest_bait_exposures.insert((bait_id.clone(), *bait_class), event_ref);
            }
            EventKind::BaitActionObserved {
                bait_id,
                bait_class,
                exposure_id,
                method,
                path,
                header_value_mint,
                header_value_mint_status,
            } => {
                let matched_exposure = exposure_id.as_ref().and_then(|exposure_id| {
                    exact_exposures
                        .get(&(bait_id.clone(), *bait_class, exposure_id.clone()))
                        .copied()
                });
                let prior_same_bait_exposure = if matched_exposure.is_none() {
                    latest_bait_exposures
                        .get(&(bait_id.clone(), *bait_class))
                        .copied()
                } else {
                    None
                };
                let action = BaitActionEvidence {
                    bait_id: bait_id.clone(),
                    bait_class: *bait_class,
                    exposure_id: exposure_id.clone(),
                    request_id: timeline_event.event.request_id,
                    method: method.clone(),
                    path: path.clone(),
                    header_value_mint: header_value_mint.clone(),
                    header_value_mint_status: *header_value_mint_status,
                    event_ref,
                    matched_exposure,
                    prior_same_bait_exposure,
                };

                actions.push(action);
            }
            EventKind::ResponseServed {
                status,
                routing_decision,
                controlled_reality,
            } => {
                if let Some(request_id) = timeline_event.event.request_id {
                    *response_counts.entry(request_id).or_insert(0_usize) += 1;
                }
                bundle.policy_events.push(PolicyEventEvidence {
                    event_ref,
                    policy_state: timeline_event.event.policy_state,
                    kind: PolicyEvidenceKind::ResponseServed,
                    routing_decision: Some(*routing_decision),
                    from_policy_state: None,
                    to_policy_state: None,
                    status: Some(*status),
                    reason: None,
                    persistence: timeline_event.event.persistence,
                });
                if *routing_decision == RoutingDecision::ControlledReality {
                    if let (Some(request_id), Some(interaction)) =
                        (timeline_event.event.request_id, controlled_reality)
                    {
                        controlled_reality_candidates.push(ControlledRealityCandidate {
                            evidence: ControlledRealityInteractionEvidence {
                                request_id,
                                interaction: interaction.clone(),
                                event_ref,
                            },
                            source: timeline_event.event.source,
                            policy_state: timeline_event.event.policy_state,
                            status: *status,
                        });
                    }
                }
            }
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
                persistence: timeline_event.event.persistence,
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
                    persistence: timeline_event.event.persistence,
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
                    persistence: timeline_event.event.persistence,
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
                    persistence: timeline_event.event.persistence,
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
                    persistence: timeline_event.event.persistence,
                });
            }
            EventKind::RequestSeen {
                method,
                path,
                routing_decision,
                ..
            } => bundle.request_observations.push(RequestObservation {
                request_id: timeline_event.event.request_id,
                source: Some(timeline_event.event.source),
                policy_state: Some(timeline_event.event.policy_state),
                method: method.clone(),
                path: path.clone(),
                routing_decision: *routing_decision,
                event_ref,
            }),
        }
    }

    for action in actions {
        if confirms_bait_action(&bundle, &action) {
            bundle.matched_actions.push(action);
        } else {
            bundle.unmatched_actions.push(action);
        }
    }
    bundle.controlled_reality_interactions = validated_controlled_reality_interactions(
        &bundle,
        controlled_reality_candidates,
        &response_counts,
    );

    bundle
}

fn validated_controlled_reality_interactions(
    bundle: &EvidenceBundle,
    candidates: Vec<ControlledRealityCandidate>,
    response_counts: &HashMap<RequestId, usize>,
) -> Vec<ControlledRealityInteractionEvidence> {
    let mut validated = Vec::new();
    let mut seen_request_ids = HashSet::new();
    let mut workflow_state = ControlledRealityWorkflowState::Ready;
    let mut workflow_origin = None;
    let mut workflow_job = None;

    for candidate in candidates {
        let evidence = &candidate.evidence;
        let interaction = &evidence.interaction;
        let Some(request) = unique_request_observation(bundle, evidence.request_id) else {
            continue;
        };
        let Some(origin_request) =
            unique_request_observation(bundle, interaction.origin_request_id)
        else {
            continue;
        };
        if candidate.source != EventSource::Proxy
            || candidate.policy_state != PolicyState::ControlledReality
            || response_counts.get(&evidence.request_id) != Some(&1)
            || !controlled_workflow_request_provenance_matches(interaction, request)
            || !controlled_workflow_origin_provenance_matches(origin_request)
            || !controlled_workflow_request_routing_matches(interaction, request)
            || !controlled_workflow_origin_matches(origin_request)
            || !controlled_reality_status_matches(interaction, candidate.status)
            || !seen_request_ids.insert(evidence.request_id)
            || request.event_ref.file_order >= evidence.event_ref.file_order
            || origin_request.event_ref.file_order >= evidence.event_ref.file_order
            || interaction.from_state != workflow_state
        {
            continue;
        }

        let valid = match &interaction.action {
            ControlledRealityInteractionAction::JobSubmitted => {
                if !is_import_reconcile_submit(request) {
                    false
                } else if workflow_state == ControlledRealityWorkflowState::Ready {
                    if evidence.request_id != interaction.origin_request_id
                        || interaction.to_state != ControlledRealityWorkflowState::Queued
                    {
                        false
                    } else {
                        workflow_origin = Some(interaction.origin_request_id);
                        workflow_job = Some(interaction.job_id.clone());
                        workflow_state = interaction.to_state;
                        true
                    }
                } else {
                    workflow_identity_matches(interaction, workflow_origin, workflow_job.as_ref())
                        && interaction.to_state == workflow_state
                }
            }
            ControlledRealityInteractionAction::StatusRead => {
                if !workflow_identity_matches(interaction, workflow_origin, workflow_job.as_ref())
                    || !is_import_reconcile_status(request, interaction.job_id.as_str())
                {
                    false
                } else {
                    let next_state = match workflow_state {
                        ControlledRealityWorkflowState::Queued => {
                            ControlledRealityWorkflowState::Completed
                        }
                        ControlledRealityWorkflowState::Completed => {
                            ControlledRealityWorkflowState::Completed
                        }
                        ControlledRealityWorkflowState::Ready => continue,
                    };
                    if interaction.to_state != next_state {
                        false
                    } else {
                        workflow_state = next_state;
                        true
                    }
                }
            }
            ControlledRealityInteractionAction::ArtifactRead { .. } => {
                workflow_state == ControlledRealityWorkflowState::Completed
                    && interaction.to_state == ControlledRealityWorkflowState::Completed
                    && workflow_identity_matches(
                        interaction,
                        workflow_origin,
                        workflow_job.as_ref(),
                    )
                    && is_import_reconcile_artifact(request, interaction.job_id.as_str())
            }
        };

        if valid {
            validated.push(candidate.evidence);
        }
    }

    validated
}

fn controlled_workflow_request_routing_matches(
    interaction: &ControlledRealityInteraction,
    request: &RequestObservation,
) -> bool {
    match &interaction.action {
        ControlledRealityInteractionAction::JobSubmitted => matches!(
            request.routing_decision,
            RoutingDecision::EidolonOwned | RoutingDecision::ControlledReality
        ),
        ControlledRealityInteractionAction::StatusRead
        | ControlledRealityInteractionAction::ArtifactRead { .. } => {
            request.routing_decision == RoutingDecision::ControlledReality
        }
    }
}

fn controlled_workflow_request_provenance_matches(
    interaction: &ControlledRealityInteraction,
    request: &RequestObservation,
) -> bool {
    request.source == Some(EventSource::Proxy)
        && match &interaction.action {
            ControlledRealityInteractionAction::JobSubmitted => {
                controlled_workflow_origin_policy_state(request.policy_state)
            }
            ControlledRealityInteractionAction::StatusRead
            | ControlledRealityInteractionAction::ArtifactRead { .. } => {
                request.policy_state == Some(PolicyState::ControlledReality)
            }
        }
}

fn controlled_workflow_origin_provenance_matches(request: &RequestObservation) -> bool {
    request.source == Some(EventSource::Proxy)
        && controlled_workflow_origin_policy_state(request.policy_state)
}

fn controlled_workflow_origin_policy_state(policy_state: Option<PolicyState>) -> bool {
    matches!(
        policy_state,
        Some(
            PolicyState::Observe
                | PolicyState::Suspicious
                | PolicyState::RateLimited
                | PolicyState::ControlledReality
        )
    )
}

fn controlled_workflow_origin_matches(request: &RequestObservation) -> bool {
    matches!(
        request.routing_decision,
        RoutingDecision::EidolonOwned | RoutingDecision::ControlledReality
    ) && is_import_reconcile_submit(request)
}

fn controlled_reality_status_matches(
    interaction: &ControlledRealityInteraction,
    status: u16,
) -> bool {
    match &interaction.action {
        ControlledRealityInteractionAction::JobSubmitted => match interaction.to_state {
            ControlledRealityWorkflowState::Queued => status == 202,
            ControlledRealityWorkflowState::Completed => status == 200,
            ControlledRealityWorkflowState::Ready => false,
        },
        ControlledRealityInteractionAction::StatusRead
        | ControlledRealityInteractionAction::ArtifactRead { .. } => status == 200,
    }
}

fn workflow_identity_matches(
    interaction: &ControlledRealityInteraction,
    workflow_origin: Option<RequestId>,
    workflow_job: Option<&eidolon_core::ControlledRealityJobId>,
) -> bool {
    workflow_origin == Some(interaction.origin_request_id)
        && workflow_job == Some(&interaction.job_id)
}

fn is_import_reconcile_submit(request: &RequestObservation) -> bool {
    request.method.eq_ignore_ascii_case("POST")
        && normalized_branch_path(&request.path) == "/api/v2/import/reconcile"
}

fn is_import_reconcile_status(request: &RequestObservation, job_id: &str) -> bool {
    request.method.eq_ignore_ascii_case("GET")
        && normalized_branch_path(&request.path)
            == format!("/api/v2/import/reconcile/jobs/{job_id}")
}

fn is_import_reconcile_artifact(request: &RequestObservation, job_id: &str) -> bool {
    request.method.eq_ignore_ascii_case("GET")
        && normalized_branch_path(&request.path)
            == format!("/api/v2/import/reconcile/jobs/{job_id}/result")
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
                let branch = controlled_reality_branch_key(path);
                if contained {
                    branches.insert(branch.clone());
                }
                pending_request = Some((branch, contained));
            }
            EventKind::ResponseServed {
                routing_decision,
                controlled_reality,
                ..
            } if containment_routing_decision(*routing_decision) => {
                if let Some(interaction) = controlled_reality {
                    branches.insert(controlled_reality_interaction_branch_key(interaction));
                    pending_request = None;
                } else if let Some((path, _)) = pending_request.take() {
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

fn controlled_reality_branch_key(target: &str) -> String {
    const IMPORT_RECONCILE_PATH: &str = "/api/v2/import/reconcile";
    const IMPORT_RECONCILE_JOBS_PREFIX: &str = "/api/v2/import/reconcile/jobs/";

    let path = normalized_branch_path(target);
    if path == IMPORT_RECONCILE_PATH || path.starts_with(IMPORT_RECONCILE_JOBS_PREFIX) {
        controlled_reality_import_reconcile_branch_key().to_string()
    } else {
        path.to_string()
    }
}

fn controlled_reality_interaction_branch_key(interaction: &ControlledRealityInteraction) -> String {
    match interaction.branch {
        eidolon_core::ControlledRealityBranch::ImportReconcile => {
            controlled_reality_import_reconcile_branch_key().to_string()
        }
    }
}

fn controlled_reality_import_reconcile_branch_key() -> &'static str {
    "controlled_reality:import_reconcile"
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
        ControlledRealityBranch, ControlledRealityJobId, Event, EventKind, EventSource, ExposureId,
        IngressIdentity, PolicyState, RoutingDecision, SessionId,
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
                bait_class: Some(BaitClass::Docs),
                exposure_id: ExposureId("exp-1".to_string()),
                surface: "/docs/legacy-import".to_string(),
                header_value_mint: None,
            },
        )
        .with_request_id(RequestId::new())
    }

    fn action(session_id: SessionId, exposure_id: Option<&str>) -> Event {
        Event::new(
            session_id,
            EventSource::BaitEngine,
            PolicyState::Observe,
            EventKind::BaitActionObserved {
                bait_id: BaitId("bait-1".to_string()),
                bait_class: Some(BaitClass::Docs),
                exposure_id: exposure_id.map(|id| ExposureId(id.to_string())),
                method: "POST".to_string(),
                path: "/api/v2/import/reconcile".to_string(),
                header_value_mint: None,
                header_value_mint_status: None,
            },
        )
        .with_request_id(RequestId::new())
    }

    fn with_bait_class(mut event: Event, bait_class: Option<BaitClass>) -> Event {
        match &mut event.kind {
            EventKind::BaitExposed {
                bait_class: event_class,
                ..
            }
            | EventKind::BaitActionObserved {
                bait_class: event_class,
                ..
            } => *event_class = bait_class,
            other => panic!("expected bait event, got {other:?}"),
        }
        event
    }

    fn request_for_bait_event(event: &Event, routing_decision: RoutingDecision) -> Event {
        let request_id = event
            .request_id
            .expect("bait test events must carry request ids");
        let (method, path) = match &event.kind {
            EventKind::BaitExposed { surface, .. } => ("GET", surface.as_str()),
            EventKind::BaitActionObserved { method, path, .. } => (method.as_str(), path.as_str()),
            other => panic!("expected bait event, got {other:?}"),
        };

        request_seen_with(event.session_id, request_id, method, path, routing_decision)
    }

    fn bait_chain(exposure: Event, action: Event) -> Vec<Event> {
        bait_chain_with_action_routing(exposure, action, RoutingDecision::EidolonOwned)
    }

    fn bait_chain_with_action_routing(
        exposure: Event,
        action: Event,
        action_routing: RoutingDecision,
    ) -> Vec<Event> {
        vec![
            request_for_bait_event(&exposure, RoutingDecision::ProtectedUpstream),
            exposure,
            request_for_bait_event(&action, action_routing),
            action,
        ]
    }

    fn request_seen_with(
        session_id: SessionId,
        request_id: RequestId,
        method: &str,
        path: &str,
        routing_decision: RoutingDecision,
    ) -> Event {
        let policy_state = if routing_decision == RoutingDecision::ControlledReality {
            PolicyState::ControlledReality
        } else {
            PolicyState::Observe
        };
        Event::new(
            session_id,
            EventSource::Proxy,
            policy_state,
            EventKind::RequestSeen {
                method: method.to_string(),
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
        .with_request_id(request_id)
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
                controlled_reality: None,
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

    fn controlled_workflow_response(
        session_id: SessionId,
        request_id: RequestId,
        origin_request_id: RequestId,
        job_id: ControlledRealityJobId,
        from_state: ControlledRealityWorkflowState,
        to_state: ControlledRealityWorkflowState,
        action: ControlledRealityInteractionAction,
    ) -> Event {
        let status = match (&action, to_state) {
            (
                ControlledRealityInteractionAction::JobSubmitted,
                ControlledRealityWorkflowState::Queued,
            ) => 202,
            _ => 200,
        };
        Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::ControlledReality,
            EventKind::ResponseServed {
                status,
                routing_decision: RoutingDecision::ControlledReality,
                controlled_reality: Some(ControlledRealityInteraction {
                    branch: ControlledRealityBranch::ImportReconcile,
                    origin_request_id,
                    from_state,
                    to_state,
                    job_id,
                    action,
                }),
            },
        )
        .with_request_id(request_id)
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
    fn controlled_workflow_evidence_requires_unique_linked_legal_steps() {
        let session_id = SessionId::new();
        let origin_request_id = RequestId::new();
        let status_request_id = RequestId::new();
        let job_id =
            ControlledRealityJobId::new("job_0123456789abcdef".to_string()).expect("valid job id");
        let status_path = format!("/api/v2/import/reconcile/jobs/{}", job_id.as_str());
        let valid = timeline(vec![
            request_seen_with(
                session_id,
                origin_request_id,
                "POST",
                "/api/v2/import/reconcile",
                RoutingDecision::EidolonOwned,
            ),
            controlled_workflow_response(
                session_id,
                origin_request_id,
                origin_request_id,
                job_id.clone(),
                ControlledRealityWorkflowState::Ready,
                ControlledRealityWorkflowState::Queued,
                ControlledRealityInteractionAction::JobSubmitted,
            ),
            request_seen_with(
                session_id,
                status_request_id,
                "GET",
                &status_path,
                RoutingDecision::ControlledReality,
            ),
            controlled_workflow_response(
                session_id,
                status_request_id,
                origin_request_id,
                job_id,
                ControlledRealityWorkflowState::Queued,
                ControlledRealityWorkflowState::Completed,
                ControlledRealityInteractionAction::StatusRead,
            ),
        ]);

        let bundle = collect_evidence(&valid);

        assert_eq!(bundle.controlled_reality_interactions.len(), 2);
    }

    #[test]
    fn controlled_workflow_evidence_rejects_wrong_status_source_routing_and_duplicates() {
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let job_id =
            ControlledRealityJobId::new("job_0123456789abcdef".to_string()).expect("valid job id");
        let request = request_seen_with(
            session_id,
            request_id,
            "POST",
            "/api/v2/import/reconcile",
            RoutingDecision::EidolonOwned,
        );
        let wrong_routing_request = request_seen_with(
            session_id,
            request_id,
            "POST",
            "/api/v2/import/reconcile",
            RoutingDecision::ProtectedUpstream,
        );
        let response = controlled_workflow_response(
            session_id,
            request_id,
            request_id,
            job_id,
            ControlledRealityWorkflowState::Ready,
            ControlledRealityWorkflowState::Queued,
            ControlledRealityInteractionAction::JobSubmitted,
        );

        let mut wrong_status = response.clone();
        let EventKind::ResponseServed { status, .. } = &mut wrong_status.kind else {
            panic!("workflow helper should return a response event");
        };
        *status = 200;

        let mut wrong_source = response.clone();
        wrong_source.source = EventSource::TraceEngine;
        let mut wrong_request_source = request.clone();
        wrong_request_source.source = EventSource::TraceEngine;
        let mut wrong_request_policy = request.clone();
        wrong_request_policy.policy_state = PolicyState::Blocked;

        assert!(
            collect_evidence(&timeline(vec![request.clone(), wrong_status]))
                .controlled_reality_interactions
                .is_empty()
        );
        assert!(
            collect_evidence(&timeline(vec![request.clone(), wrong_source]))
                .controlled_reality_interactions
                .is_empty()
        );
        assert!(
            collect_evidence(&timeline(vec![wrong_request_source, response.clone()]))
                .controlled_reality_interactions
                .is_empty()
        );
        assert!(
            collect_evidence(&timeline(vec![wrong_request_policy, response.clone()]))
                .controlled_reality_interactions
                .is_empty()
        );
        assert!(
            collect_evidence(&timeline(vec![wrong_routing_request, response.clone()]))
                .controlled_reality_interactions
                .is_empty()
        );
        assert!(
            collect_evidence(&timeline(vec![request, response.clone(), response]))
                .controlled_reality_interactions
                .is_empty()
        );
    }

    #[test]
    fn controlled_workflow_evidence_rejects_orphans_duplicates_and_changed_ids() {
        let session_id = SessionId::new();
        let origin_request_id = RequestId::new();
        let status_request_id = RequestId::new();
        let job_id =
            ControlledRealityJobId::new("job_0123456789abcdef".to_string()).expect("valid job id");
        let changed_job =
            ControlledRealityJobId::new("job_fedcba9876543210".to_string()).expect("valid job id");
        let status_path = format!("/api/v2/import/reconcile/jobs/{}", job_id.as_str());
        let orphan = timeline(vec![controlled_workflow_response(
            session_id,
            origin_request_id,
            origin_request_id,
            job_id.clone(),
            ControlledRealityWorkflowState::Ready,
            ControlledRealityWorkflowState::Queued,
            ControlledRealityInteractionAction::JobSubmitted,
        )]);
        let duplicate_origin = timeline(vec![
            request_seen_with(
                session_id,
                origin_request_id,
                "POST",
                "/api/v2/import/reconcile",
                RoutingDecision::ControlledReality,
            ),
            request_seen_with(
                session_id,
                origin_request_id,
                "POST",
                "/api/v2/import/reconcile",
                RoutingDecision::ControlledReality,
            ),
            controlled_workflow_response(
                session_id,
                origin_request_id,
                origin_request_id,
                job_id.clone(),
                ControlledRealityWorkflowState::Ready,
                ControlledRealityWorkflowState::Queued,
                ControlledRealityInteractionAction::JobSubmitted,
            ),
        ]);
        let changed_id = timeline(vec![
            request_seen_with(
                session_id,
                origin_request_id,
                "POST",
                "/api/v2/import/reconcile",
                RoutingDecision::ControlledReality,
            ),
            controlled_workflow_response(
                session_id,
                origin_request_id,
                origin_request_id,
                job_id,
                ControlledRealityWorkflowState::Ready,
                ControlledRealityWorkflowState::Queued,
                ControlledRealityInteractionAction::JobSubmitted,
            ),
            request_seen_with(
                session_id,
                status_request_id,
                "GET",
                &status_path,
                RoutingDecision::ControlledReality,
            ),
            controlled_workflow_response(
                session_id,
                status_request_id,
                origin_request_id,
                changed_job,
                ControlledRealityWorkflowState::Queued,
                ControlledRealityWorkflowState::Completed,
                ControlledRealityInteractionAction::StatusRead,
            ),
        ]);
        let illegal_transition = timeline(vec![
            request_seen_with(
                session_id,
                origin_request_id,
                "POST",
                "/api/v2/import/reconcile",
                RoutingDecision::ControlledReality,
            ),
            controlled_workflow_response(
                session_id,
                origin_request_id,
                origin_request_id,
                ControlledRealityJobId::new("job_0123456789abcdef".to_string())
                    .expect("valid job id"),
                ControlledRealityWorkflowState::Ready,
                ControlledRealityWorkflowState::Queued,
                ControlledRealityInteractionAction::JobSubmitted,
            ),
            request_seen_with(
                session_id,
                status_request_id,
                "GET",
                &status_path,
                RoutingDecision::ControlledReality,
            ),
            controlled_workflow_response(
                session_id,
                status_request_id,
                origin_request_id,
                ControlledRealityJobId::new("job_0123456789abcdef".to_string())
                    .expect("valid job id"),
                ControlledRealityWorkflowState::Ready,
                ControlledRealityWorkflowState::Completed,
                ControlledRealityInteractionAction::StatusRead,
            ),
        ]);

        assert!(collect_evidence(&orphan)
            .controlled_reality_interactions
            .is_empty());
        assert!(collect_evidence(&duplicate_origin)
            .controlled_reality_interactions
            .is_empty());
        assert_eq!(
            collect_evidence(&changed_id)
                .controlled_reality_interactions
                .len(),
            1
        );
        assert_eq!(
            collect_evidence(&illegal_transition)
                .controlled_reality_interactions
                .len(),
            1
        );
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

        let mut events = bait_chain(exposure(session_id), action(session_id, Some("exp-1")));
        events.push(policy);
        let bundle = evidence_bundle_for_timeline(&timeline(events));

        assert_eq!(bundle.session_id, session_id);
        assert_eq!(bundle.request_observations.len(), 2);
        assert_eq!(bundle.observed_surfaces.len(), 1);
        assert_eq!(bundle.bait_exposures.len(), 1);
        assert_eq!(bundle.matched_actions.len(), 1);
        assert_eq!(
            bundle.observed_surfaces[0].bait_class,
            Some(BaitClass::Docs)
        );
        assert_eq!(bundle.bait_exposures[0].bait_class, Some(BaitClass::Docs));
        assert_eq!(bundle.matched_actions[0].bait_class, Some(BaitClass::Docs));
        assert!(bundle.unmatched_actions.is_empty());
        assert_eq!(bundle.policy_events.len(), 1);
        assert_eq!(bundle.source_refs.len(), 5);
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
    fn class_provenance_requires_equal_known_classes() {
        let cases = [
            (Some(BaitClass::Docs), Some(BaitClass::HiddenRoute)),
            (Some(BaitClass::Docs), None),
            (None, Some(BaitClass::Docs)),
        ];

        for (exposure_class, action_class) in cases {
            let session_id = SessionId::new();
            let bundle = collect_evidence(&timeline(bait_chain(
                with_bait_class(exposure(session_id), exposure_class),
                with_bait_class(action(session_id, Some("exp-1")), action_class),
            )));

            assert!(bundle.matched_actions.is_empty());
            assert_eq!(bundle.unmatched_actions.len(), 1);
            assert_eq!(bundle.unmatched_actions[0].matched_exposure, None);
            assert_eq!(bundle.unmatched_actions[0].prior_same_bait_exposure, None);
        }

        let session_id = SessionId::new();
        let mut legacy_exposure = with_bait_class(exposure(session_id), None);
        legacy_exposure.request_id = None;
        let mut legacy_action = with_bait_class(action(session_id, Some("exp-1")), None);
        legacy_action.request_id = None;
        let legacy_bundle = collect_evidence(&timeline(vec![legacy_exposure, legacy_action]));
        assert!(legacy_bundle.matched_actions.is_empty());
        assert_eq!(legacy_bundle.unmatched_actions.len(), 1);
        assert_eq!(
            legacy_bundle.unmatched_actions[0].matched_exposure,
            Some(legacy_bundle.bait_exposures[0].event_ref)
        );
    }

    #[test]
    fn confirmation_requires_present_request_ids() {
        for missing_exposure_id in [true, false] {
            let session_id = SessionId::new();
            let mut events = bait_chain(exposure(session_id), action(session_id, Some("exp-1")));
            if missing_exposure_id {
                events[1].request_id = None;
            } else {
                events[3].request_id = None;
            }

            let bundle = collect_evidence(&timeline(events));

            assert!(bundle.matched_actions.is_empty());
            assert_eq!(bundle.unmatched_actions.len(), 1);
            assert!(bundle.unmatched_actions[0].matched_exposure.is_some());
        }
    }

    #[test]
    fn confirmation_requires_request_seen_observations() {
        let session_id = SessionId::new();
        let bundle = collect_evidence(&timeline(vec![
            exposure(session_id),
            action(session_id, Some("exp-1")),
        ]));

        assert!(bundle.request_observations.is_empty());
        assert!(bundle.matched_actions.is_empty());
        assert_eq!(bundle.unmatched_actions.len(), 1);
    }

    #[test]
    fn confirmation_rejects_duplicate_request_seen_ids() {
        let session_id = SessionId::new();
        let exposure = exposure(session_id);
        let action = action(session_id, Some("exp-1"));
        let duplicate = request_for_bait_event(&action, RoutingDecision::EidolonOwned);
        let mut events = bait_chain(exposure, action);
        events.insert(3, duplicate);
        let bundle = collect_evidence(&timeline(events));

        assert_eq!(bundle.request_observations.len(), 3);
        assert!(bundle.matched_actions.is_empty());
        assert_eq!(bundle.unmatched_actions.len(), 1);
    }

    #[test]
    fn confirmation_requires_distinct_request_ids() {
        let session_id = SessionId::new();
        let request_id = RequestId::new();
        let exposure = exposure(session_id).with_request_id(request_id);
        let action = action(session_id, Some("exp-1")).with_request_id(request_id);
        let bundle = collect_evidence(&timeline(bait_chain(exposure, action)));

        assert!(bundle.matched_actions.is_empty());
        assert_eq!(bundle.unmatched_actions.len(), 1);
        assert!(bundle.unmatched_actions[0].matched_exposure.is_some());
    }

    #[test]
    fn confirmation_requires_matching_action_method_and_path() {
        for field in ["method", "path"] {
            let session_id = SessionId::new();
            let mut events = bait_chain(exposure(session_id), action(session_id, Some("exp-1")));
            let EventKind::RequestSeen { method, path, .. } = &mut events[2].kind else {
                panic!("expected action request");
            };
            if field == "method" {
                *method = "PUT".to_string();
            } else {
                *path = "/api/v2/import/other".to_string();
            }

            let bundle = collect_evidence(&timeline(events));

            assert!(bundle.matched_actions.is_empty(), "{field} mismatch");
            assert_eq!(bundle.unmatched_actions.len(), 1);
        }
    }

    #[test]
    fn confirmation_requires_matching_exposure_path() {
        let session_id = SessionId::new();
        let mut events = bait_chain(exposure(session_id), action(session_id, Some("exp-1")));
        let EventKind::RequestSeen { path, .. } = &mut events[0].kind else {
            panic!("expected exposure request");
        };
        *path = "/docs/other".to_string();

        let bundle = collect_evidence(&timeline(events));

        assert!(bundle.matched_actions.is_empty());
        assert_eq!(bundle.unmatched_actions.len(), 1);
    }

    #[test]
    fn confirmation_rejects_protected_upstream_action_routing() {
        let session_id = SessionId::new();
        let bundle = collect_evidence(&timeline(bait_chain_with_action_routing(
            exposure(session_id),
            action(session_id, Some("exp-1")),
            RoutingDecision::ProtectedUpstream,
        )));

        assert!(bundle.matched_actions.is_empty());
        assert_eq!(bundle.unmatched_actions.len(), 1);
    }

    #[test]
    fn confirmation_requires_exposure_before_action() {
        let session_id = SessionId::new();
        let exposure = exposure(session_id);
        let action = action(session_id, Some("exp-1"));
        let bundle = collect_evidence(&timeline(vec![
            request_for_bait_event(&action, RoutingDecision::EidolonOwned),
            action,
            request_for_bait_event(&exposure, RoutingDecision::ProtectedUpstream),
            exposure,
        ]));

        assert!(bundle.matched_actions.is_empty());
        assert_eq!(bundle.unmatched_actions.len(), 1);
        assert!(bundle.unmatched_actions[0].matched_exposure.is_none());
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
                bait_class: Some(BaitClass::Docs),
                exposure_id: exposure_id.map(|id| ExposureId(id.to_string())),
                method: "POST".to_string(),
                path: "/api/v2/import/reconcile".to_string(),
                header_value_mint: Some(mint_audit()),
                header_value_mint_status: status,
            },
        )
        .with_request_id(RequestId::new())
    }

    fn minted_exposure(session_id: SessionId) -> Event {
        Event::new(
            session_id,
            EventSource::SurfaceController,
            PolicyState::Observe,
            EventKind::BaitExposed {
                bait_id: BaitId("bait-1".to_string()),
                bait_class: Some(BaitClass::Docs),
                exposure_id: ExposureId("exp-1".to_string()),
                surface: "/docs/legacy-import".to_string(),
                header_value_mint: Some(mint_audit()),
            },
        )
        .with_request_id(RequestId::new())
    }

    fn assert_unmatched_action_is_request_linked(bundle: &EvidenceBundle) {
        let exposure = &bundle.bait_exposures[0];
        let action = &bundle.unmatched_actions[0];

        assert_eq!(exposure.bait_class, Some(BaitClass::Docs));
        assert_eq!(action.bait_class, Some(BaitClass::Docs));
        assert_eq!(action.matched_exposure, Some(exposure.event_ref));
        assert!(exposure.request_id.is_some());
        assert!(action.request_id.is_some());
        assert_ne!(exposure.request_id, action.request_id);
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
        let bundle = collect_evidence(&timeline(bait_chain(
            minted_exposure(session_id),
            minted_action(
                session_id,
                Some("exp-1"),
                Some(BaitHeaderValueMintStatus::ReplaySeen),
            ),
        )));

        assert!(bundle.matched_actions.is_empty());
        assert_eq!(bundle.unmatched_actions.len(), 1);
        assert_eq!(
            bundle.unmatched_actions[0].proof_outcome(),
            ProofOutcome::Rejected
        );
        assert_unmatched_action_is_request_linked(&bundle);
    }

    #[test]
    fn expired_proof_with_linked_exposure_is_not_confirmed() {
        let session_id = SessionId::new();
        let bundle = collect_evidence(&timeline(bait_chain(
            minted_exposure(session_id),
            minted_action(
                session_id,
                Some("exp-1"),
                Some(BaitHeaderValueMintStatus::ExpiredSessionValue),
            ),
        )));

        assert!(bundle.matched_actions.is_empty());
        assert_eq!(bundle.unmatched_actions.len(), 1);
        assert_eq!(
            bundle.unmatched_actions[0].proof_outcome(),
            ProofOutcome::Rejected
        );
        assert_unmatched_action_is_request_linked(&bundle);
    }

    #[test]
    fn mismatched_proof_with_linked_exposure_is_not_confirmed() {
        let session_id = SessionId::new();
        let bundle = collect_evidence(&timeline(bait_chain(
            minted_exposure(session_id),
            minted_action(
                session_id,
                Some("exp-1"),
                Some(BaitHeaderValueMintStatus::SessionValueMismatch),
            ),
        )));

        assert!(bundle.matched_actions.is_empty());
        assert_eq!(bundle.unmatched_actions.len(), 1);
        assert_eq!(
            bundle.unmatched_actions[0].proof_outcome(),
            ProofOutcome::Rejected
        );
        assert_unmatched_action_is_request_linked(&bundle);
    }

    #[test]
    fn historical_mint_action_without_status_degrades_to_unknown() {
        let session_id = SessionId::new();
        let bundle = collect_evidence(&timeline(bait_chain(
            minted_exposure(session_id),
            minted_action(session_id, Some("exp-1"), None),
        )));

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
        let bundle = collect_evidence(&timeline(bait_chain(
            minted_exposure(session_id),
            minted_action(
                session_id,
                Some("exp-1"),
                Some(BaitHeaderValueMintStatus::MatchedSessionValue),
            ),
        )));

        assert_eq!(bundle.matched_actions.len(), 1);
        assert_eq!(
            bundle.matched_actions[0].proof_outcome(),
            ProofOutcome::Accepted
        );
        assert!(bundle.unmatched_actions.is_empty());
    }

    #[test]
    fn minted_confirmation_requires_exact_matching_audit() {
        for omit_audit in [false, true] {
            let session_id = SessionId::new();
            let exposure = minted_exposure(session_id);
            let mut action = minted_action(
                session_id,
                Some("exp-1"),
                Some(BaitHeaderValueMintStatus::MatchedSessionValue),
            );
            let EventKind::BaitActionObserved {
                header_value_mint, ..
            } = &mut action.kind
            else {
                panic!("expected bait action");
            };
            if omit_audit {
                *header_value_mint = None;
            } else {
                header_value_mint.as_mut().expect("mint audit").prefix = "different".to_string();
            }

            let bundle = collect_evidence(&timeline(bait_chain(exposure, action)));

            assert!(bundle.matched_actions.is_empty());
            assert_eq!(bundle.unmatched_actions.len(), 1);
        }
    }

    #[test]
    fn static_bait_with_exact_request_chain_is_confirmed() {
        let session_id = SessionId::new();
        let bundle = collect_evidence(&timeline(bait_chain(
            exposure(session_id),
            action(session_id, Some("exp-1")),
        )));

        assert_eq!(bundle.matched_actions.len(), 1);
        assert!(bundle.unmatched_actions.is_empty());
    }

    #[test]
    fn legacy_bundle_without_request_observations_remains_readable() {
        let session_id = SessionId::new();
        let bundle = collect_evidence(&timeline(vec![exposure(session_id)]));
        let mut serialized = serde_json::to_value(bundle).expect("bundle should serialize");
        serialized
            .as_object_mut()
            .expect("bundle object")
            .remove("request_observations");

        let parsed: EvidenceBundle =
            serde_json::from_value(serialized).expect("legacy bundle should deserialize");

        assert!(parsed.request_observations.is_empty());
        assert_eq!(parsed.bait_exposures.len(), 1);
    }

    #[test]
    fn mixed_session_confirms_only_from_accepted_proofs() {
        let session_id = SessionId::new();
        let mut events = bait_chain(
            minted_exposure(session_id),
            minted_action(
                session_id,
                Some("exp-1"),
                Some(BaitHeaderValueMintStatus::ReplaySeen),
            ),
        );
        events.extend(bait_chain(
            exposure(session_id),
            action(session_id, Some("exp-1")),
        ));
        let bundle = collect_evidence(&timeline(events));

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
        let exposure = at(exposure(session_id), 0);
        let action = at(action(session_id, Some("exp-1")), 5);
        let timeline = timeline(vec![
            at(
                request_for_bait_event(&exposure, RoutingDecision::ProtectedUpstream),
                -1,
            ),
            exposure,
            at(
                request_for_bait_event(&action, RoutingDecision::EidolonOwned),
                4,
            ),
            action,
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
