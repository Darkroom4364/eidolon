use eidolon_core::{
    Event, EventKind, EventSource, IngressActorKind, IngressAdvisorySignals, IngressIdentity,
    PolicyState, RoutingDecision, SessionId,
};

use crate::ingress_identity;

pub const INITIAL_POLICY_STATE: PolicyState = PolicyState::Observe;

const DEFAULT_OBSERVE_REASON: &str = "observe policy forwards traffic to the protected upstream";
const INTERVENTIONS_DISABLED_REASON: &str =
    "interventions disabled; forwarding to protected upstream";
const BAIT_ACTION_CONTROLLED_REALITY_REASON: &str =
    "confirmed bait-derived action moved session into controlled reality";
const DISCOVERY_INGRESS_SUSPICIOUS_REASON_PREFIX: &str =
    "authenticated ingress advisory signals promoted discovery request to suspicious";
const AUTOMATION_LIKELIHOOD_INVERSE_SCORE_KIND: &str = "automation_likelihood_inverse";
const DISCOVERY_SUSPICIOUS_VENDOR_SCORE_MAX: u16 = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    pub policy_state: PolicyState,
    pub routing_decision: RoutingDecision,
    pub reason: String,
}

impl PolicyDecision {
    pub fn new(
        policy_state: PolicyState,
        routing_decision: RoutingDecision,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            policy_state,
            routing_decision,
            reason: reason.into(),
        }
    }

    pub fn protected_upstream(policy_state: PolicyState, reason: impl Into<String>) -> Self {
        Self::new(policy_state, RoutingDecision::ProtectedUpstream, reason)
    }
}

impl Default for PolicyDecision {
    fn default() -> Self {
        Self::protected_upstream(INITIAL_POLICY_STATE, DEFAULT_OBSERVE_REASON)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyTransition {
    pub from: PolicyState,
    pub to: PolicyState,
    pub reason: String,
}

impl PolicyTransition {
    pub fn new(from: PolicyState, to: PolicyState, reason: impl Into<String>) -> Self {
        Self {
            from,
            to,
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum InterventionMode {
    Enabled,
    #[default]
    Disabled,
}

impl InterventionMode {
    pub fn interventions_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

pub fn initial_policy_state() -> PolicyState {
    INITIAL_POLICY_STATE
}

pub fn v0_protected_upstream_decision() -> PolicyDecision {
    PolicyDecision::default()
}

pub fn transition_after_correlated_bait_action(
    current_state: PolicyState,
) -> Option<PolicyTransition> {
    match current_state {
        PolicyState::Observe | PolicyState::Suspicious => Some(PolicyTransition::new(
            current_state,
            PolicyState::ControlledReality,
            BAIT_ACTION_CONTROLLED_REALITY_REASON,
        )),
        PolicyState::Normal
        | PolicyState::ControlledReality
        | PolicyState::RateLimited
        | PolicyState::Blocked => None,
    }
}

pub fn transition_to_suspicious_from_ingress_signals(
    current_state: PolicyState,
    path: &str,
    discovery_path_prefixes: &[String],
    ingress_identity: &IngressIdentity,
    ingress_signals: &IngressAdvisorySignals,
) -> Option<PolicyTransition> {
    if !matches!(current_state, PolicyState::Normal | PolicyState::Observe) {
        return None;
    }
    if ingress_identity::softens_bait_surface_exposure(ingress_identity) {
        return None;
    }
    if !discovery_path_prefixes
        .iter()
        .any(|prefix| path.starts_with(prefix))
    {
        return None;
    }
    if !matches!(
        ingress_signals.actor_kind,
        IngressActorKind::AutonomousAgent | IngressActorKind::AgenticBrowser
    ) {
        return None;
    }
    if ingress_signals.vendor_score_kind.as_deref()
        != Some(AUTOMATION_LIKELIHOOD_INVERSE_SCORE_KIND)
    {
        return None;
    }
    let vendor_score = ingress_signals.vendor_score?;
    if vendor_score > DISCOVERY_SUSPICIOUS_VENDOR_SCORE_MAX {
        return None;
    }

    Some(PolicyTransition::new(
        current_state,
        PolicyState::Suspicious,
        format!(
            "{DISCOVERY_INGRESS_SUSPICIOUS_REASON_PREFIX}: path={path} actor_kind={} vendor_score={vendor_score} kind={AUTOMATION_LIKELIHOOD_INVERSE_SCORE_KIND}",
            snake_case_actor_kind(ingress_signals.actor_kind),
        ),
    ))
}

pub fn decide_for_state(
    policy_state: PolicyState,
    intervention_mode: InterventionMode,
) -> PolicyDecision {
    if !intervention_mode.interventions_enabled() {
        return PolicyDecision::protected_upstream(policy_state, INTERVENTIONS_DISABLED_REASON);
    }

    match policy_state {
        PolicyState::Normal => PolicyDecision::protected_upstream(
            policy_state,
            "normal policy forwards traffic to the protected upstream",
        ),
        PolicyState::Observe => {
            PolicyDecision::protected_upstream(policy_state, DEFAULT_OBSERVE_REASON)
        }
        PolicyState::Suspicious => PolicyDecision::protected_upstream(
            policy_state,
            "suspicious policy observes only and forwards to the protected upstream",
        ),
        PolicyState::ControlledReality => PolicyDecision::new(
            policy_state,
            RoutingDecision::ControlledReality,
            "controlled reality policy routes to eidolon-controlled responses",
        ),
        PolicyState::RateLimited => PolicyDecision::new(
            policy_state,
            RoutingDecision::RateLimited,
            "rate limited policy throttles the request",
        ),
        PolicyState::Blocked => PolicyDecision::new(
            policy_state,
            RoutingDecision::EidolonOwned,
            "blocked policy routes to an eidolon-owned response",
        ),
    }
}

pub fn policy_intervention_event(session_id: SessionId, decision: &PolicyDecision) -> Event {
    let kind = match decision.routing_decision {
        RoutingDecision::ControlledReality => EventKind::ControlledRealityEntered {
            reason: decision.reason.clone(),
        },
        RoutingDecision::RateLimited => EventKind::RateLimitApplied {
            reason: decision.reason.clone(),
        },
        _ => EventKind::PolicyDecision {
            routing_decision: decision.routing_decision,
            reason: decision.reason.clone(),
        },
    };

    Event::new(
        session_id,
        EventSource::PolicyRouter,
        decision.policy_state,
        kind,
    )
}

pub fn policy_changed_event(session_id: SessionId, transition: &PolicyTransition) -> Event {
    Event::new(
        session_id,
        EventSource::PolicyRouter,
        transition.to,
        EventKind::PolicyChanged {
            from: transition.from,
            to: transition.to,
            reason: transition.reason.clone(),
        },
    )
}

pub fn response_audit_event(
    session_id: SessionId,
    decision: &PolicyDecision,
    status: u16,
) -> Event {
    Event::new(
        session_id,
        EventSource::Proxy,
        decision.policy_state,
        EventKind::ResponseServed {
            status,
            routing_decision: decision.routing_decision,
        },
    )
}

pub fn reality_escape_attempt_event(
    session_id: SessionId,
    policy_state: PolicyState,
    method: impl Into<String>,
    path: impl Into<String>,
    routing_decision: RoutingDecision,
    reason: impl Into<String>,
) -> Event {
    Event::new(
        session_id,
        EventSource::PolicyRouter,
        policy_state,
        EventKind::RealityEscapeAttempt {
            method: method.into(),
            path: path.into(),
            routing_decision,
            reason: reason.into(),
        },
    )
}

fn snake_case_actor_kind(actor_kind: IngressActorKind) -> &'static str {
    match actor_kind {
        IngressActorKind::Unknown => "unknown",
        IngressActorKind::Crawler => "crawler",
        IngressActorKind::Assistant => "assistant",
        IngressActorKind::AutonomousAgent => "autonomous_agent",
        IngressActorKind::AgenticBrowser => "agentic_browser",
        IngressActorKind::PartnerAutomation => "partner_automation",
        IngressActorKind::InternalScanner => "internal_scanner",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_observes_and_forwards_to_protected_upstream() {
        let decision = v0_protected_upstream_decision();

        assert_eq!(initial_policy_state(), PolicyState::Observe);
        assert_eq!(decision.policy_state, PolicyState::Observe);
        assert_eq!(
            decision.routing_decision,
            RoutingDecision::ProtectedUpstream
        );
        assert!(decision.reason.contains("observe"));
    }

    #[test]
    fn disabled_interventions_force_protected_upstream() {
        let decision = decide_for_state(PolicyState::ControlledReality, InterventionMode::Disabled);

        assert_eq!(decision.policy_state, PolicyState::ControlledReality);
        assert_eq!(
            decision.routing_decision,
            RoutingDecision::ProtectedUpstream
        );
        assert!(decision.reason.contains("interventions disabled"));
    }

    #[test]
    fn enabled_interventions_map_controlled_reality_and_rate_limit() {
        let controlled =
            decide_for_state(PolicyState::ControlledReality, InterventionMode::Enabled);
        let rate_limited = decide_for_state(PolicyState::RateLimited, InterventionMode::Enabled);

        assert_eq!(
            controlled.routing_decision,
            RoutingDecision::ControlledReality
        );
        assert_eq!(rate_limited.routing_decision, RoutingDecision::RateLimited);
    }

    #[test]
    fn correlated_bait_action_transitions_observe_or_suspicious_to_controlled_reality() {
        let Some(observe) = transition_after_correlated_bait_action(PolicyState::Observe) else {
            panic!("observe should transition");
        };
        let Some(suspicious) = transition_after_correlated_bait_action(PolicyState::Suspicious)
        else {
            panic!("suspicious should transition");
        };

        assert_eq!(observe.from, PolicyState::Observe);
        assert_eq!(observe.to, PolicyState::ControlledReality);
        assert_eq!(suspicious.from, PolicyState::Suspicious);
        assert_eq!(suspicious.to, PolicyState::ControlledReality);
    }

    #[test]
    fn low_score_agentic_discovery_signals_promote_to_suspicious() {
        let Some(transition) = transition_to_suspicious_from_ingress_signals(
            PolicyState::Observe,
            "/docs/legacy-import",
            &["/docs".to_string(), "/openapi.json".to_string()],
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(12),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
        ) else {
            panic!("observe should transition to suspicious");
        };

        assert_eq!(transition.from, PolicyState::Observe);
        assert_eq!(transition.to, PolicyState::Suspicious);
        assert!(transition
            .reason
            .contains(DISCOVERY_INGRESS_SUSPICIOUS_REASON_PREFIX));
        assert!(transition.reason.contains("actor_kind=agentic_browser"));
        assert!(transition.reason.contains("vendor_score=12"));
    }

    #[test]
    fn trusted_identity_does_not_promote_to_suspicious_from_ingress_signals() {
        let transition = transition_to_suspicious_from_ingress_signals(
            PolicyState::Observe,
            "/docs/legacy-import",
            &["/docs".to_string(), "/openapi.json".to_string()],
            &IngressIdentity {
                source: eidolon_core::IngressIdentitySource::SignedAgent,
                trust_tier: eidolon_core::IngressTrustTier::SignedAttested,
                label: Some("signed-agent".to_string()),
                expires_at: None,
            },
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(12),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
        );

        assert_eq!(transition, None);
    }

    #[test]
    fn non_discovery_or_high_score_signals_do_not_promote_to_suspicious() {
        let high_score = transition_to_suspicious_from_ingress_signals(
            PolicyState::Observe,
            "/docs/legacy-import",
            &["/docs".to_string(), "/openapi.json".to_string()],
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(91),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
        );
        let non_discovery = transition_to_suspicious_from_ingress_signals(
            PolicyState::Observe,
            "/health",
            &["/docs".to_string(), "/openapi.json".to_string()],
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AutonomousAgent,
                vendor_score: Some(12),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
        );

        assert_eq!(high_score, None);
        assert_eq!(non_discovery, None);
    }

    #[test]
    fn correlated_bait_action_does_not_transition_terminal_or_already_controlled_states() {
        for state in [
            PolicyState::Normal,
            PolicyState::ControlledReality,
            PolicyState::RateLimited,
            PolicyState::Blocked,
        ] {
            assert_eq!(transition_after_correlated_bait_action(state), None);
        }
    }

    #[test]
    fn policy_changed_event_records_real_state_transition() {
        let session_id = SessionId::new();
        let transition = transition_after_correlated_bait_action(PolicyState::Observe)
            .expect("observe should transition");

        let event = policy_changed_event(session_id, &transition);

        assert_eq!(event.session_id, session_id);
        assert_eq!(event.source, EventSource::PolicyRouter);
        assert_eq!(event.policy_state, PolicyState::ControlledReality);
        assert!(matches!(
            event.kind,
            EventKind::PolicyChanged {
                from: PolicyState::Observe,
                to: PolicyState::ControlledReality,
                ref reason,
            } if reason == &transition.reason
        ));
    }

    #[test]
    fn policy_intervention_event_uses_specific_core_event_kind() {
        let session_id = SessionId::new();
        let decision = decide_for_state(PolicyState::RateLimited, InterventionMode::Enabled);

        let event = policy_intervention_event(session_id, &decision);

        assert_eq!(event.session_id, session_id);
        assert_eq!(event.source, EventSource::PolicyRouter);
        assert_eq!(event.policy_state, PolicyState::RateLimited);
        assert!(matches!(
            event.kind,
            EventKind::RateLimitApplied { ref reason }
                if reason == &decision.reason
        ));
    }

    #[test]
    fn policy_intervention_event_audits_noop_without_fake_state_change() {
        let session_id = SessionId::new();
        let decision = decide_for_state(PolicyState::ControlledReality, InterventionMode::Disabled);

        let event = policy_intervention_event(session_id, &decision);

        assert_eq!(event.session_id, session_id);
        assert_eq!(event.source, EventSource::PolicyRouter);
        assert_eq!(event.policy_state, PolicyState::ControlledReality);
        assert!(matches!(
            event.kind,
            EventKind::PolicyDecision {
                routing_decision: RoutingDecision::ProtectedUpstream,
                ref reason,
            } if reason == &decision.reason
        ));
    }

    #[test]
    fn response_audit_event_records_status_and_routing_decision() {
        let session_id = SessionId::new();
        let decision = PolicyDecision::new(
            PolicyState::ControlledReality,
            RoutingDecision::RewrittenUpstream,
            "response body was rewritten",
        );

        let event = response_audit_event(session_id, &decision, 203);

        assert_eq!(event.session_id, session_id);
        assert_eq!(event.source, EventSource::Proxy);
        assert_eq!(event.policy_state, PolicyState::ControlledReality);
        assert!(matches!(
            event.kind,
            EventKind::ResponseServed {
                status: 203,
                routing_decision: RoutingDecision::RewrittenUpstream
            }
        ));
    }
}
