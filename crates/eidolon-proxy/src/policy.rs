use eidolon_core::{Event, EventKind, EventSource, PolicyState, RoutingDecision, SessionId};

pub const INITIAL_POLICY_STATE: PolicyState = PolicyState::Observe;

const DEFAULT_OBSERVE_REASON: &str = "observe policy forwards traffic to the protected upstream";
const INTERVENTIONS_DISABLED_REASON: &str =
    "interventions disabled; forwarding to protected upstream";
const BAIT_ACTION_CONTROLLED_REALITY_REASON: &str =
    "confirmed bait-derived action moved session into controlled reality";

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
        let observe = transition_after_correlated_bait_action(PolicyState::Observe)
            .expect("observe should transition");
        let suspicious = transition_after_correlated_bait_action(PolicyState::Suspicious)
            .expect("suspicious should transition");

        assert_eq!(observe.from, PolicyState::Observe);
        assert_eq!(observe.to, PolicyState::ControlledReality);
        assert_eq!(suspicious.from, PolicyState::Suspicious);
        assert_eq!(suspicious.to, PolicyState::ControlledReality);
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
