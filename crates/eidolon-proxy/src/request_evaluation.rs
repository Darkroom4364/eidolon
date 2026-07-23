//! Pure request policy and routing evaluation.

use eidolon_bait::BaitRegistry;
use eidolon_core::{
    BaitClass, IngressAdvisorySignals, IngressIdentity, PersistenceMetadata, PolicyState,
    RoutingDecision, SessionId,
};

use crate::{
    controlled_reality::is_unsafe_method,
    ingress_identity,
    policy::{
        self, DecoyWriteProbePathKind, DiscoveryReconAggregationScore, DiscoveryReconState,
        DiscoverySurfaceKind, InterventionMode, LinkedBaitSurfaceKind, PolicyDecision,
        PolicyTransition,
    },
    surface::{SurfaceAction, SurfaceRequestMeta},
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RequestPolicyFacts {
    pub discovery_surface: Option<DiscoverySurfaceKind>,
    pub legacy_openapi_discovery_query: bool,
    pub suspicious_discovery_bait: Option<BaitClass>,
    pub linked_bait_surface: Option<LinkedBaitSurfaceKind>,
    pub blind_decoy_write_probe: Option<DecoyWriteProbePathKind>,
    pub owns_configured_unsafe_bait_action: bool,
}

impl RequestPolicyFacts {
    pub fn aggregated_discovery_recon_candidate(self) -> bool {
        self.discovery_surface.is_some()
            || self.linked_bait_surface.is_some()
            || self.blind_decoy_write_probe.is_some()
    }
}

pub struct RequestClassificationInput<'a> {
    pub bait_registry: &'a BaitRegistry,
    pub request: &'a SurfaceRequestMeta,
    pub session_id: SessionId,
    pub bait_signing_secret: Option<&'a str>,
    pub docs_discovery_target: &'a str,
    pub canonical_openapi_discovery_target: &'a str,
    pub legacy_openapi_query: &'a str,
}

pub fn classify_request(input: RequestClassificationInput<'_>) -> RequestPolicyFacts {
    let discovery_surface = classify_discovery_surface(
        input.bait_registry,
        input.request,
        input.docs_discovery_target,
        input.legacy_openapi_query,
    );
    let linked_bait_surface = classify_linked_bait_surface(input.bait_registry, input.request);
    let blind_decoy_write_probe = classify_blind_decoy_write_probe(
        input.bait_registry,
        input.request,
        input.session_id,
        input.bait_signing_secret,
    );
    let legacy_openapi_discovery_query = input.request.method == "GET"
        && discovery_surface == Some(DiscoverySurfaceKind::OpenApi)
        && input.request.path == input.canonical_openapi_discovery_target
        && input.request.query.as_deref() == Some(input.legacy_openapi_query);
    let suspicious_discovery_bait = classify_suspicious_discovery_bait(
        input.bait_registry,
        input.request,
        input.docs_discovery_target,
        input.canonical_openapi_discovery_target,
        input.legacy_openapi_query,
    );
    let owns_configured_unsafe_bait_action =
        classify_owned_unsafe_bait_action(input.bait_registry, input.request);

    RequestPolicyFacts {
        discovery_surface,
        legacy_openapi_discovery_query,
        suspicious_discovery_bait,
        linked_bait_surface,
        blind_decoy_write_probe,
        owns_configured_unsafe_bait_action,
    }
}

fn classify_discovery_surface(
    bait_registry: &BaitRegistry,
    request: &SurfaceRequestMeta,
    docs_discovery_target: &str,
    legacy_openapi_query: &str,
) -> Option<DiscoverySurfaceKind> {
    if request.method != "GET" {
        return None;
    }
    if request.path == docs_discovery_target {
        return Some(DiscoverySurfaceKind::Docs);
    }

    bait_registry
        .bait_for_class(BaitClass::OpenApi)
        .filter(|bait| {
            request.path == bait.surface
                && match request.query.as_deref() {
                    None => true,
                    Some(query) => query == legacy_openapi_query,
                }
        })
        .map(|_| DiscoverySurfaceKind::OpenApi)
}

fn classify_suspicious_discovery_bait(
    bait_registry: &BaitRegistry,
    request: &SurfaceRequestMeta,
    docs_discovery_target: &str,
    canonical_openapi_discovery_target: &str,
    legacy_openapi_query: &str,
) -> Option<BaitClass> {
    if request.method != "GET" {
        return None;
    }
    if request.path == docs_discovery_target {
        return bait_registry
            .bait_for_class(BaitClass::Docs)
            .map(|_| BaitClass::Docs);
    }
    if request.path != canonical_openapi_discovery_target
        || !match request.query.as_deref() {
            None => true,
            Some(query) => query == legacy_openapi_query,
        }
    {
        return None;
    }

    bait_registry
        .bait_for_class(BaitClass::OpenApi)
        .filter(|bait| bait.surface == request.path)
        .map(|_| BaitClass::OpenApi)
}

fn classify_linked_bait_surface(
    bait_registry: &BaitRegistry,
    request: &SurfaceRequestMeta,
) -> Option<LinkedBaitSurfaceKind> {
    if request.method != "GET" {
        return None;
    }

    bait_registry
        .baits()
        .iter()
        .find(|bait| bait.bait_class != BaitClass::OpenApi && bait.surface == request.path)
        .map(|_| {
            if request.path.starts_with("/docs/") {
                LinkedBaitSurfaceKind::Docs
            } else if request.path.starts_with("/assets/") {
                LinkedBaitSurfaceKind::Assets
            } else {
                LinkedBaitSurfaceKind::Other
            }
        })
}

fn classify_blind_decoy_write_probe(
    bait_registry: &BaitRegistry,
    request: &SurfaceRequestMeta,
    session_id: SessionId,
    bait_signing_secret: Option<&str>,
) -> Option<DecoyWriteProbePathKind> {
    if !matches!(request.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
        return None;
    }

    let headers: Vec<(&str, &str)> = request
        .headers
        .iter()
        .map(|header| (header.name.as_str(), header.value.as_str()))
        .collect();
    if bait_registry
        .match_action_for_session(
            &request.method,
            &request.path,
            headers.iter().copied(),
            session_id,
            bait_signing_secret,
        )
        .ok()
        .flatten()
        .is_some()
        || bait_registry
            .match_action_shape(&request.method, &request.path, headers.iter().copied())
            .is_some()
    {
        return None;
    }

    bait_registry.baits().iter().find(|bait| {
        bait.expected_action
            .method
            .eq_ignore_ascii_case(&request.method)
            && bait.expected_action.path == request.path
            && bait.expected_action.header_name.is_some()
    })?;

    Some(
        if request.path == crate::controlled_reality::DECOY_RECONCILE_PATH {
            DecoyWriteProbePathKind::Reconcile
        } else {
            DecoyWriteProbePathKind::Other
        },
    )
}

fn classify_owned_unsafe_bait_action(
    bait_registry: &BaitRegistry,
    request: &SurfaceRequestMeta,
) -> bool {
    if !is_unsafe_method(&request.method) {
        return false;
    }

    let incoming_path = canonical_action_route_path(&request.target);
    bait_registry.baits().iter().any(|bait| {
        if !bait
            .expected_action
            .method
            .eq_ignore_ascii_case(&request.method)
        {
            return false;
        }

        match (
            canonical_action_route_path(&bait.expected_action.path),
            incoming_path.as_ref(),
        ) {
            (Ok(expected), Ok(incoming)) => expected == incoming.as_str(),
            _ => {
                bait.expected_action.path == request.path
                    || bait.expected_action.path == request.target
            }
        }
    })
}

pub fn canonical_action_route_path(target: &str) -> Result<String, &'static str> {
    let raw_path_end = target
        .char_indices()
        .find_map(|(index, character)| matches!(character, '?' | '#').then_some(index))
        .unwrap_or(target.len());
    let raw_path = &target[..raw_path_end];
    let bytes = raw_path.as_bytes();
    let mut canonical = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] != b'%' {
            canonical.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err("percent escape is incomplete");
        }
        let high = action_hex_value(bytes[index + 1]).ok_or("percent escape is not hexadecimal")?;
        let low = action_hex_value(bytes[index + 2]).ok_or("percent escape is not hexadecimal")?;
        canonical.push((high << 4) | low);
        index += 3;
    }

    let decoded =
        String::from_utf8(canonical).map_err(|_| "percent escape decodes to invalid UTF-8")?;
    let decoded_path_end = decoded
        .char_indices()
        .find_map(|(index, character)| matches!(character, '?' | '#').then_some(index))
        .unwrap_or(decoded.len());
    Ok(decoded[..decoded_path_end].to_string())
}

fn action_hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RequestEvaluationInput<'a> {
    pub starting_policy_state: PolicyState,
    pub intervention_mode: InterventionMode,
    pub path: &'a str,
    pub trusted_bait_soften_path_prefixes: &'a [String],
    pub ingress_identity: &'a IngressIdentity,
    pub ingress_signals: &'a IngressAdvisorySignals,
    pub discovery_recon_state: DiscoveryReconState,
    pub request_facts: RequestPolicyFacts,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestEvaluation {
    pub decision: PolicyDecision,
    pub transitions: Vec<PolicyTransition>,
    pub discovery_recon_score: DiscoveryReconAggregationScore,
    pub discovery_recon_threshold: u8,
}

pub fn evaluate_request(input: RequestEvaluationInput<'_>) -> RequestEvaluation {
    let discovery_recon_score = policy::aggregated_discovery_recon_score(
        input.ingress_signals,
        input.discovery_recon_state,
    );
    let mut discovery_recon_threshold = policy::discovery_recon_aggregation_score_threshold();
    let mut policy_state = input.starting_policy_state;
    let mut transitions = Vec::new();
    let mut decision_transition = None;

    if input.intervention_mode.interventions_enabled() {
        let suspicious_transition = policy::transition_to_suspicious_from_ingress_signals(
            policy_state,
            input.path,
            input.trusted_bait_soften_path_prefixes,
            input.ingress_identity,
            input.ingress_signals,
        )
        .or_else(|| {
            policy::transition_to_suspicious_from_discovery_fanout(
                policy_state,
                input.path,
                input.ingress_identity,
                input.discovery_recon_state.fanout,
            )
        })
        .or_else(|| {
            policy::transition_to_suspicious_from_aggregated_discovery_recon(
                policy_state,
                input.path,
                input.request_facts.aggregated_discovery_recon_candidate(),
                input.ingress_identity,
                input.ingress_signals,
                input.discovery_recon_state,
            )
        });

        if let Some(transition) = suspicious_transition {
            policy_state = transition.to;
            transitions.push(transition);
        }

        let persistence_transition = if input.starting_policy_state == PolicyState::Suspicious {
            policy::transition_to_rate_limited_from_suspicious_discovery_recon(
                policy_state,
                input.path,
                input.request_facts.discovery_surface.is_some(),
                input.request_facts.blind_decoy_write_probe.is_some(),
                input.ingress_identity,
                input.ingress_signals,
                input.discovery_recon_state,
            )
        } else if input.starting_policy_state == PolicyState::RateLimited {
            policy::transition_to_blocked_from_repeated_discovery_recon(
                policy_state,
                input.path,
                input.request_facts.discovery_surface.is_some(),
                input.request_facts.blind_decoy_write_probe.is_some(),
                input.ingress_identity,
                input.ingress_signals,
                input.discovery_recon_state,
            )
        } else {
            None
        };

        if let Some(transition) = persistence_transition {
            discovery_recon_threshold = policy::discovery_recon_rate_limit_score_threshold();
            policy_state = transition.to;
            decision_transition = Some(transition.clone());
            transitions.push(transition);
        }
    }

    let mut decision = policy::decide_for_state(policy_state, input.intervention_mode);
    if let Some(transition) = decision_transition {
        decision = transition.decision(decision.routing_decision);
    }

    RequestEvaluation {
        decision,
        transitions,
        discovery_recon_score,
        discovery_recon_threshold,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitialRoutePlan {
    ProtectedUpstream,
    SurfaceController,
    ControlledReality,
    RateLimited,
    Blocked,
    InvalidRewrittenUpstream,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuspiciousDiscoveryPlan {
    Preserve,
    ServeDocsBait,
    ServeOpenApiBait,
}

pub fn suspicious_discovery_plan(
    policy_state: PolicyState,
    controller_action: &SurfaceAction,
    request_facts: RequestPolicyFacts,
) -> SuspiciousDiscoveryPlan {
    if policy_state != PolicyState::Suspicious
        || !matches!(controller_action, SurfaceAction::RewrittenUpstream { .. })
    {
        return SuspiciousDiscoveryPlan::Preserve;
    }

    match request_facts.suspicious_discovery_bait {
        Some(BaitClass::Docs) => SuspiciousDiscoveryPlan::ServeDocsBait,
        Some(BaitClass::OpenApi) => SuspiciousDiscoveryPlan::ServeOpenApiBait,
        _ => SuspiciousDiscoveryPlan::Preserve,
    }
}

pub fn initial_route_plan(
    decision: &PolicyDecision,
    intervention_mode: InterventionMode,
) -> InitialRoutePlan {
    if !intervention_mode.interventions_enabled() {
        return InitialRoutePlan::ProtectedUpstream;
    }

    match decision.routing_decision {
        RoutingDecision::ProtectedUpstream => InitialRoutePlan::SurfaceController,
        RoutingDecision::ControlledReality => InitialRoutePlan::ControlledReality,
        RoutingDecision::RateLimited => InitialRoutePlan::RateLimited,
        RoutingDecision::EidolonOwned => InitialRoutePlan::Blocked,
        RoutingDecision::RewrittenUpstream => InitialRoutePlan::InvalidRewrittenUpstream,
    }
}

pub struct SurfaceEvaluationInput<'a> {
    pub policy_decision: &'a PolicyDecision,
    pub candidate_action: SurfaceAction,
    pub trusted_bait_soften_path_prefixes: &'a [String],
    pub local_trusted_bait_soften_path_prefixes: Option<&'a [String]>,
    pub ingress_identity: &'a IngressIdentity,
    pub request_method: &'a str,
    pub request_path: &'a str,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SurfaceEvaluation {
    pub action: SurfaceAction,
    pub decision: PolicyDecision,
    pub requested_intervention: bool,
    pub trusted_ingress_softening_reason: Option<String>,
}

pub fn evaluate_surface(input: SurfaceEvaluationInput<'_>) -> SurfaceEvaluation {
    let requested_intervention =
        !matches!(&input.candidate_action, SurfaceAction::ProtectedUpstream);
    let trusted_ingress_softens = matches!(
        input.policy_decision.policy_state,
        PolicyState::Normal | PolicyState::Observe
    ) && input.request_method == "GET"
        && ingress_identity::softens_bait_surface_exposure(input.ingress_identity)
        && input
            .trusted_bait_soften_path_prefixes
            .iter()
            .any(|prefix| {
                ingress_identity::path_matches_segment_prefix(input.request_path, prefix)
            })
        && input
            .local_trusted_bait_soften_path_prefixes
            .map(|prefixes| {
                prefixes.iter().any(|prefix| {
                    ingress_identity::path_matches_segment_prefix(input.request_path, prefix)
                })
            })
            .unwrap_or(true)
        && matches!(
            &input.candidate_action,
            SurfaceAction::EidolonOwned { .. } | SurfaceAction::RewrittenUpstream { .. }
        );

    let trusted_ingress_softening_reason = trusted_ingress_softens.then(|| {
        "trusted ingress identity suppressed bait surface intervention before runtime suspicion was established"
            .to_string()
    });
    let action = if trusted_ingress_softens {
        SurfaceAction::ProtectedUpstream
    } else {
        input.candidate_action
    };
    let decision = PolicyDecision::new(
        input.policy_decision.policy_state,
        action.routing_decision(),
        trusted_ingress_softening_reason
            .clone()
            .unwrap_or_else(|| input.policy_decision.reason.clone()),
    )
    .with_persistence(input.policy_decision.persistence);

    SurfaceEvaluation {
        action,
        decision,
        requested_intervention,
        trusted_ingress_softening_reason,
    }
}

pub fn correlated_bait_action_transition(
    policy_state: PolicyState,
    proof_accepted: bool,
    matched_prior_exposure: bool,
) -> Option<PolicyTransition> {
    (proof_accepted && matched_prior_exposure)
        .then(|| policy::transition_after_correlated_bait_action(policy_state))
        .flatten()
}

pub fn same_bait_near_miss_transition(
    policy_state: PolicyState,
    path: &str,
    bait_id: &eidolon_core::BaitId,
    prior_same_bait_exposure: bool,
) -> Option<PolicyTransition> {
    policy::transition_to_rate_limited_from_same_bait_near_miss(
        policy_state,
        path,
        bait_id,
        prior_same_bait_exposure,
    )
    .or_else(|| {
        policy::transition_to_blocked_from_repeated_same_bait_near_miss(
            policy_state,
            path,
            bait_id,
            prior_same_bait_exposure,
        )
    })
}

pub fn controlled_reality_depth_transition(
    policy_state: PolicyState,
    path: &str,
    depth: u32,
    depth_limit: u32,
) -> Option<PolicyTransition> {
    policy::transition_to_blocked_from_repeated_controlled_reality_depth_limit(
        policy_state,
        path,
        depth,
        depth_limit,
    )
}

pub fn reality_escape_transition(
    policy_state: PolicyState,
    path: &str,
    attempt_count: u32,
) -> Option<PolicyTransition> {
    policy::transition_to_blocked_from_repeated_reality_escape_attempt(
        policy_state,
        path,
        attempt_count,
    )
}

pub fn fail_closed_unsafe_bait_action_decision(decision: &PolicyDecision) -> PolicyDecision {
    PolicyDecision::new(
        decision.policy_state,
        RoutingDecision::EidolonOwned,
        "configured unsafe bait action failed closed after proof rejection",
    )
    .with_persistence(decision.persistence)
}

pub fn interventions_disabled_bait_action_decision(policy_state: PolicyState) -> PolicyDecision {
    PolicyDecision::new(
        policy_state,
        RoutingDecision::EidolonOwned,
        "interventions disabled; configured unsafe bait action failed closed",
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewriteEvaluation {
    Rewritten,
    Refused(String),
    Unchanged,
    SkippedNonSuccess,
}

pub fn rewrite_response_decision(
    decision: &PolicyDecision,
    evaluation: RewriteEvaluation,
) -> PolicyDecision {
    let (routing_decision, reason) = match evaluation {
        RewriteEvaluation::Rewritten => (
            RoutingDecision::RewrittenUpstream,
            "surface controller rewrote upstream response".to_string(),
        ),
        RewriteEvaluation::Refused(refusal) => (
            RoutingDecision::ProtectedUpstream,
            format!(
                "surface controller rewrite refused; forwarded original upstream response: {refusal}"
            ),
        ),
        RewriteEvaluation::Unchanged => (
            RoutingDecision::ProtectedUpstream,
            "surface controller rewrite made no changes; forwarded original upstream response"
                .to_string(),
        ),
        RewriteEvaluation::SkippedNonSuccess => (
            RoutingDecision::ProtectedUpstream,
            "surface controller skipped rewrite for non-200 upstream response".to_string(),
        ),
    };

    PolicyDecision::new(decision.policy_state, routing_decision, reason)
        .with_persistence(decision.persistence)
}

pub fn surface_action_can_reach_upstream(action: &SurfaceAction) -> bool {
    action.is_upstream()
}

pub fn direct_surface_decision(
    policy_state: PolicyState,
    action: &SurfaceAction,
    default_reason: String,
    persistence: PersistenceMetadata,
) -> PolicyDecision {
    let decision = match action {
        SurfaceAction::ProtectedUpstream => {
            PolicyDecision::protected_upstream(policy_state, default_reason)
        }
        SurfaceAction::EidolonOwned { .. } => {
            let reason = if policy_state == PolicyState::Blocked {
                default_reason
            } else {
                "surface controller served eidolon-owned response".to_string()
            };
            PolicyDecision::new(policy_state, RoutingDecision::EidolonOwned, reason)
        }
        SurfaceAction::ControlledReality { reason, .. } => PolicyDecision::new(
            policy_state,
            RoutingDecision::ControlledReality,
            reason.clone(),
        ),
        SurfaceAction::RateLimited { reason, .. } => {
            PolicyDecision::new(policy_state, RoutingDecision::RateLimited, reason.clone())
        }
        SurfaceAction::RewrittenUpstream { .. } => PolicyDecision::new(
            policy_state,
            RoutingDecision::RewrittenUpstream,
            "surface controller requested upstream response rewrite",
        ),
    };

    decision.with_persistence(persistence)
}

pub fn upstream_request_decision(
    policy_state: PolicyState,
    surface_action: &SurfaceAction,
    default_reason: String,
    persistence: PersistenceMetadata,
) -> PolicyDecision {
    let decision = match surface_action {
        SurfaceAction::RewrittenUpstream { .. } => PolicyDecision::new(
            policy_state,
            RoutingDecision::ProtectedUpstream,
            "surface controller requested upstream response rewrite; request forwarded to protected upstream before rewrite outcome",
        ),
        _ => PolicyDecision::protected_upstream(policy_state, default_reason),
    };

    decision.with_persistence(persistence)
}

pub fn bait_action_interception_decision(
    decision: &PolicyDecision,
    proof_accepted: bool,
) -> PolicyDecision {
    PolicyDecision::new(
        decision.policy_state,
        RoutingDecision::EidolonOwned,
        if proof_accepted {
            "bait-derived decoy action intercepted before protected upstream"
        } else {
            "rejected bait proof failed closed before protected upstream"
        },
    )
    .with_persistence(decision.persistence)
}

#[cfg(test)]
mod tests {
    use eidolon_core::{
        BaitId, IngressActorKind, IngressIdentitySource, IngressTrustTier,
        PreContainmentPersistenceClass, RoutingDecision,
    };

    use super::*;
    use crate::{
        policy::DiscoverySurfaceFanout,
        surface::{RewritePlan, SurfaceResponse},
    };

    fn agentic_signals(vendor_score: u16) -> IngressAdvisorySignals {
        IngressAdvisorySignals {
            actor_kind: IngressActorKind::AgenticBrowser,
            vendor_score: Some(vendor_score),
            vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn request_classification_produces_typed_policy_facts() {
        let registry = BaitRegistry::m3_catalog();
        let session_id = SessionId::new();
        let docs_request = SurfaceRequestMeta::new("GET", "/docs", vec![], 0);
        let docs = classify_request(RequestClassificationInput {
            bait_registry: &registry,
            request: &docs_request,
            session_id,
            bait_signing_secret: None,
            docs_discovery_target: "/docs",
            canonical_openapi_discovery_target: "/openapi.json",
            legacy_openapi_query: "eidolon_surface=legacy-import",
        });
        assert_eq!(docs.discovery_surface, Some(DiscoverySurfaceKind::Docs));
        assert!(docs.aggregated_discovery_recon_candidate());

        let bait = registry
            .baits()
            .iter()
            .find(|bait| bait.expected_action.header_name.is_some())
            .expect("catalog should contain a constrained action");
        let blind_request = SurfaceRequestMeta::new(
            bait.expected_action.method.clone(),
            bait.expected_action.path.clone(),
            vec![],
            0,
        );
        let blind = classify_request(RequestClassificationInput {
            bait_registry: &registry,
            request: &blind_request,
            session_id,
            bait_signing_secret: None,
            docs_discovery_target: "/docs",
            canonical_openapi_discovery_target: "/openapi.json",
            legacy_openapi_query: "eidolon_surface=legacy-import",
        });
        assert!(blind.blind_decoy_write_probe.is_some());
        assert!(blind.owns_configured_unsafe_bait_action);
        assert!(blind.aggregated_discovery_recon_candidate());
    }

    #[test]
    fn legacy_openapi_query_fact_requires_the_canonical_surface() {
        let mut registry = BaitRegistry::new();
        let mut bait = eidolon_bait::BasicBaitTemplate::openapi_reconcile_demo();
        bait.surface = "/custom-openapi.json".to_string();
        registry.add(bait.to_bait());
        let session_id = SessionId::new();

        let custom_request = SurfaceRequestMeta::new(
            "GET",
            "/custom-openapi.json?eidolon_surface=legacy-import",
            vec![],
            0,
        );
        let custom = classify_request(RequestClassificationInput {
            bait_registry: &registry,
            request: &custom_request,
            session_id,
            bait_signing_secret: None,
            docs_discovery_target: "/docs",
            canonical_openapi_discovery_target: "/openapi.json",
            legacy_openapi_query: "eidolon_surface=legacy-import",
        });
        assert_eq!(
            custom.discovery_surface,
            Some(DiscoverySurfaceKind::OpenApi)
        );
        assert!(!custom.legacy_openapi_discovery_query);
        assert_eq!(custom.suspicious_discovery_bait, None);

        let canonical_request = SurfaceRequestMeta::new(
            "GET",
            "/openapi.json?eidolon_surface=legacy-import",
            vec![],
            0,
        );
        let canonical = classify_request(RequestClassificationInput {
            bait_registry: &BaitRegistry::m3_catalog(),
            request: &canonical_request,
            session_id,
            bait_signing_secret: None,
            docs_discovery_target: "/docs",
            canonical_openapi_discovery_target: "/openapi.json",
            legacy_openapi_query: "eidolon_surface=legacy-import",
        });
        assert!(canonical.legacy_openapi_discovery_query);
        assert_eq!(
            canonical.suspicious_discovery_bait,
            Some(BaitClass::OpenApi)
        );
    }

    #[test]
    fn suspicious_discovery_plan_is_typed_and_requires_rewrite_routing() {
        let rewritten = SurfaceAction::RewrittenUpstream {
            plan: RewritePlan::default(),
        };
        let facts = RequestPolicyFacts {
            suspicious_discovery_bait: Some(BaitClass::Docs),
            ..Default::default()
        };

        assert_eq!(
            suspicious_discovery_plan(PolicyState::Suspicious, &rewritten, facts),
            SuspiciousDiscoveryPlan::ServeDocsBait
        );
        assert_eq!(
            suspicious_discovery_plan(PolicyState::Observe, &rewritten, facts),
            SuspiciousDiscoveryPlan::Preserve
        );
        assert_eq!(
            suspicious_discovery_plan(
                PolicyState::Suspicious,
                &SurfaceAction::ProtectedUpstream,
                facts,
            ),
            SuspiciousDiscoveryPlan::Preserve
        );
    }

    #[test]
    fn disabled_mode_skips_transitions_and_forwards() {
        let prefixes = vec!["/docs".to_string()];
        let identity = IngressIdentity::default();
        let signals = agentic_signals(12);

        let evaluation = evaluate_request(RequestEvaluationInput {
            starting_policy_state: PolicyState::Observe,
            intervention_mode: InterventionMode::Disabled,
            path: "/docs",
            trusted_bait_soften_path_prefixes: &prefixes,
            ingress_identity: &identity,
            ingress_signals: &signals,
            discovery_recon_state: DiscoveryReconState::default(),
            request_facts: RequestPolicyFacts {
                discovery_surface: Some(DiscoverySurfaceKind::Docs),
                linked_bait_surface: None,
                blind_decoy_write_probe: None,
                ..Default::default()
            },
        });

        assert!(evaluation.transitions.is_empty());
        assert_eq!(evaluation.decision.policy_state, PolicyState::Observe);
        assert_eq!(
            evaluation.decision.routing_decision,
            RoutingDecision::ProtectedUpstream
        );
        assert!(evaluation
            .decision
            .reason
            .contains("interventions disabled"));
        assert_eq!(
            evaluation.discovery_recon_threshold,
            policy::discovery_recon_aggregation_score_threshold()
        );
    }

    #[test]
    fn suspicious_promotion_preserves_transition_precedence() {
        let prefixes = vec!["/docs".to_string()];
        let identity = IngressIdentity::default();
        let signals = agentic_signals(12);

        let evaluation = evaluate_request(RequestEvaluationInput {
            starting_policy_state: PolicyState::Observe,
            intervention_mode: InterventionMode::Enabled,
            path: "/docs",
            trusted_bait_soften_path_prefixes: &prefixes,
            ingress_identity: &identity,
            ingress_signals: &signals,
            discovery_recon_state: DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: true,
                },
                ..Default::default()
            },
            request_facts: RequestPolicyFacts {
                discovery_surface: Some(DiscoverySurfaceKind::Docs),
                linked_bait_surface: None,
                blind_decoy_write_probe: None,
                ..Default::default()
            },
        });

        assert_eq!(evaluation.transitions.len(), 1);
        assert_eq!(evaluation.transitions[0].from, PolicyState::Observe);
        assert_eq!(evaluation.transitions[0].to, PolicyState::Suspicious);
        assert!(evaluation.transitions[0]
            .reason
            .contains("authenticated ingress advisory signals"));
        assert_eq!(evaluation.decision.policy_state, PolicyState::Suspicious);
        assert_eq!(
            evaluation.decision.routing_decision,
            RoutingDecision::ProtectedUpstream
        );
        assert!(evaluation.decision.persistence.is_empty());
    }

    #[test]
    fn fanout_and_aggregate_promotions_are_directly_testable() {
        let prefixes = vec!["/docs".to_string(), "/openapi.json".to_string()];
        let identity = IngressIdentity::default();
        let default_signals = IngressAdvisorySignals::default();
        let fanout = evaluate_request(RequestEvaluationInput {
            starting_policy_state: PolicyState::Observe,
            intervention_mode: InterventionMode::Enabled,
            path: "/openapi.json",
            trusted_bait_soften_path_prefixes: &prefixes,
            ingress_identity: &identity,
            ingress_signals: &default_signals,
            discovery_recon_state: DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: true,
                },
                ..Default::default()
            },
            request_facts: RequestPolicyFacts {
                discovery_surface: Some(DiscoverySurfaceKind::OpenApi),
                linked_bait_surface: None,
                blind_decoy_write_probe: None,
                ..Default::default()
            },
        });
        assert!(fanout.transitions[0]
            .reason
            .contains("discovery-surface fanout"));

        let aggregate_signals = agentic_signals(35);
        let aggregate = evaluate_request(RequestEvaluationInput {
            starting_policy_state: PolicyState::Observe,
            intervention_mode: InterventionMode::Enabled,
            path: "/docs",
            trusted_bait_soften_path_prefixes: &prefixes,
            ingress_identity: &identity,
            ingress_signals: &aggregate_signals,
            discovery_recon_state: DiscoveryReconState {
                request_count: 2,
                query_seen: true,
                ..Default::default()
            },
            request_facts: RequestPolicyFacts {
                discovery_surface: Some(DiscoverySurfaceKind::Docs),
                linked_bait_surface: None,
                blind_decoy_write_probe: None,
                ..Default::default()
            },
        });
        assert!(aggregate.transitions[0]
            .reason
            .contains("multi-signal discovery recon aggregation"));
    }

    #[test]
    fn pre_containment_persistence_transition_reaches_decision() {
        let prefixes = vec!["/docs".to_string()];
        let identity = IngressIdentity::default();
        let mut signals = agentic_signals(35);
        signals.detection_ids.push("det-1".to_string());
        let persistence =
            PersistenceMetadata::pre_containment(PreContainmentPersistenceClass::DiscoveryRecon);

        let evaluation = evaluate_request(RequestEvaluationInput {
            starting_policy_state: PolicyState::Suspicious,
            intervention_mode: InterventionMode::Enabled,
            path: "/docs",
            trusted_bait_soften_path_prefixes: &prefixes,
            ingress_identity: &identity,
            ingress_signals: &signals,
            discovery_recon_state: DiscoveryReconState {
                request_count: 2,
                query_seen: true,
                ..Default::default()
            },
            request_facts: RequestPolicyFacts {
                discovery_surface: Some(DiscoverySurfaceKind::Docs),
                linked_bait_surface: None,
                blind_decoy_write_probe: None,
                ..Default::default()
            },
        });

        assert_eq!(evaluation.transitions.len(), 1);
        assert_eq!(evaluation.transitions[0].from, PolicyState::Suspicious);
        assert_eq!(evaluation.transitions[0].to, PolicyState::RateLimited);
        assert_eq!(evaluation.transitions[0].persistence, persistence);
        assert_eq!(evaluation.decision.policy_state, PolicyState::RateLimited);
        assert_eq!(
            evaluation.decision.routing_decision,
            RoutingDecision::RateLimited
        );
        assert_eq!(evaluation.decision.persistence, persistence);
        assert_eq!(
            evaluation.discovery_recon_threshold,
            policy::discovery_recon_rate_limit_score_threshold()
        );
    }

    #[test]
    fn rate_limited_recon_retry_becomes_blocked() {
        let prefixes = vec!["/docs".to_string()];
        let identity = IngressIdentity::default();
        let mut signals = agentic_signals(35);
        signals.detection_ids.push("det-1".to_string());

        let evaluation = evaluate_request(RequestEvaluationInput {
            starting_policy_state: PolicyState::RateLimited,
            intervention_mode: InterventionMode::Enabled,
            path: "/docs",
            trusted_bait_soften_path_prefixes: &prefixes,
            ingress_identity: &identity,
            ingress_signals: &signals,
            discovery_recon_state: DiscoveryReconState {
                request_count: 2,
                query_seen: true,
                ..Default::default()
            },
            request_facts: RequestPolicyFacts {
                discovery_surface: Some(DiscoverySurfaceKind::Docs),
                linked_bait_surface: None,
                blind_decoy_write_probe: None,
                ..Default::default()
            },
        });

        assert_eq!(evaluation.transitions.len(), 1);
        assert_eq!(evaluation.transitions[0].to, PolicyState::Blocked);
        assert_eq!(evaluation.decision.policy_state, PolicyState::Blocked);
        assert_eq!(
            evaluation.decision.routing_decision,
            RoutingDecision::EidolonOwned
        );
        assert!(!evaluation.decision.persistence.is_empty());
    }

    #[test]
    fn surface_evaluation_handles_trust_softening() {
        let policy_decision = PolicyDecision::protected_upstream(PolicyState::Observe, "observe");
        let identity = IngressIdentity {
            source: IngressIdentitySource::SignedAgent,
            trust_tier: IngressTrustTier::SignedAttested,
            label: Some("trusted-agent".to_string()),
            not_before: None,
            expires_at: None,
        };
        let prefixes = vec!["/docs".to_string()];
        let evaluation = evaluate_surface(SurfaceEvaluationInput {
            policy_decision: &policy_decision,
            candidate_action: SurfaceAction::EidolonOwned {
                response: SurfaceResponse::new(200, vec![], Vec::new()),
            },
            trusted_bait_soften_path_prefixes: &prefixes,
            local_trusted_bait_soften_path_prefixes: Some(&prefixes),
            ingress_identity: &identity,
            request_method: "GET",
            request_path: "/docs",
        });

        assert!(evaluation.requested_intervention);
        assert!(evaluation.trusted_ingress_softening_reason.is_some());
        assert!(matches!(
            evaluation.action,
            SurfaceAction::ProtectedUpstream
        ));
        assert_eq!(
            evaluation.decision.routing_decision,
            RoutingDecision::ProtectedUpstream
        );
    }

    #[test]
    fn followup_transitions_require_their_explicit_evidence() {
        let bait_id = BaitId("docs-action".to_string());

        assert!(correlated_bait_action_transition(PolicyState::Observe, true, true).is_some());
        assert!(correlated_bait_action_transition(PolicyState::Observe, false, true).is_none());
        assert!(correlated_bait_action_transition(PolicyState::Observe, true, false).is_none());
        assert_eq!(
            same_bait_near_miss_transition(PolicyState::Suspicious, "/api/import", &bait_id, true,)
                .expect("suspicious near miss should rate limit")
                .to,
            PolicyState::RateLimited
        );
        assert_eq!(
            same_bait_near_miss_transition(
                PolicyState::RateLimited,
                "/api/import",
                &bait_id,
                true,
            )
            .expect("repeated rate-limited near miss should block")
            .to,
            PolicyState::Blocked
        );
        assert!(controlled_reality_depth_transition(
            PolicyState::ControlledReality,
            "/api/import",
            3,
            1,
        )
        .is_some());
        assert!(
            reality_escape_transition(PolicyState::ControlledReality, "/outside", 2,).is_some()
        );
    }

    #[test]
    fn initial_route_and_rewrite_outcomes_are_explicit() {
        let decision = PolicyDecision::protected_upstream(PolicyState::Observe, "observe");
        assert_eq!(
            initial_route_plan(&decision, InterventionMode::Enabled),
            InitialRoutePlan::SurfaceController
        );
        assert_eq!(
            initial_route_plan(&decision, InterventionMode::Disabled),
            InitialRoutePlan::ProtectedUpstream
        );

        let rewritten = rewrite_response_decision(&decision, RewriteEvaluation::Rewritten);
        assert_eq!(
            rewritten.routing_decision,
            RoutingDecision::RewrittenUpstream
        );
        let refused = rewrite_response_decision(
            &decision,
            RewriteEvaluation::Refused("unsafe body".to_string()),
        );
        assert_eq!(refused.routing_decision, RoutingDecision::ProtectedUpstream);
        assert!(refused.reason.contains("unsafe body"));
    }

    #[test]
    fn routing_helpers_preserve_persistence() {
        let persistence =
            PersistenceMetadata::pre_containment(PreContainmentPersistenceClass::SameBaitNearMiss);
        let base = PolicyDecision::protected_upstream(PolicyState::Suspicious, "base")
            .with_persistence(persistence);
        let rate_limited = SurfaceAction::RateLimited {
            reason: "slow down".to_string(),
            response: SurfaceResponse::new(429, vec![], Vec::new()),
        };
        let rewritten = SurfaceAction::RewrittenUpstream {
            plan: RewritePlan::default(),
        };

        let direct = direct_surface_decision(
            PolicyState::Suspicious,
            &rate_limited,
            base.reason.clone(),
            base.persistence,
        );
        let upstream = upstream_request_decision(
            PolicyState::Suspicious,
            &rewritten,
            base.reason.clone(),
            base.persistence,
        );
        let intercepted = bait_action_interception_decision(&base, false);
        let failed_closed = fail_closed_unsafe_bait_action_decision(&base);
        let disabled = interventions_disabled_bait_action_decision(PolicyState::Suspicious);

        assert_eq!(direct.routing_decision, RoutingDecision::RateLimited);
        assert_eq!(direct.persistence, persistence);
        assert_eq!(
            upstream.routing_decision,
            RoutingDecision::ProtectedUpstream
        );
        assert_eq!(upstream.persistence, persistence);
        assert_eq!(intercepted.routing_decision, RoutingDecision::EidolonOwned);
        assert_eq!(intercepted.persistence, persistence);
        assert_eq!(
            failed_closed.routing_decision,
            RoutingDecision::EidolonOwned
        );
        assert_eq!(failed_closed.persistence, persistence);
        assert_eq!(disabled.routing_decision, RoutingDecision::EidolonOwned);
        assert!(surface_action_can_reach_upstream(
            &SurfaceAction::ProtectedUpstream
        ));
        assert!(surface_action_can_reach_upstream(&rewritten));
        assert!(!surface_action_can_reach_upstream(&rate_limited));
    }
}
