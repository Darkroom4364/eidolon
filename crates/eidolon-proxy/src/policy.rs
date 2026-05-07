use eidolon_core::{Event, EventKind, EventSource, PolicyState, RoutingDecision, SessionId};

pub const INITIAL_POLICY_STATE: PolicyState = PolicyState::Observe;

const DEFAULT_OBSERVE_REASON: &str = "observe policy forwards traffic to the protected upstream";
const INTERVENTIONS_DISABLED_REASON: &str =
    "interventions disabled; forwarding to protected upstream";

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
        _ => {
            // Core does not yet have a dedicated policy decision/audit event.
            // PolicyChanged is the closest vocabulary for recording the decision
            // reason until a dedicated audit kind is added.
            EventKind::PolicyChanged {
                from: decision.policy_state,
                to: decision.policy_state,
                reason: decision.reason.clone(),
            }
        }
    };

    Event::new(
        session_id,
        EventSource::PolicyRouter,
        decision.policy_state,
        kind,
    )
}

pub fn response_audit_event(
    session_id: SessionId,
    decision: &PolicyDecision,
    status: u16,
) -> Event {
    Event::new(
        session_id,
        EventSource::PolicyRouter,
        decision.policy_state,
        EventKind::ResponseServed {
            status,
            routing_decision: decision.routing_decision,
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
    fn response_audit_event_records_status_and_routing_decision() {
        let session_id = SessionId::new();
        let decision = PolicyDecision::new(
            PolicyState::ControlledReality,
            RoutingDecision::RewrittenUpstream,
            "response body was rewritten",
        );

        let event = response_audit_event(session_id, &decision, 203);

        assert_eq!(event.session_id, session_id);
        assert_eq!(event.source, EventSource::PolicyRouter);
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
