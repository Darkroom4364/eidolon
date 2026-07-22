#[cfg(test)]
use eidolon_core::PreContainmentPersistenceKind;
use eidolon_core::{
    BaitId, Event, EventKind, EventSource, IngressActorKind, IngressAdvisorySignals,
    IngressIdentity, PolicyPersistenceMetadata, PolicyState, PostContainmentPersistenceKind,
    PreContainmentPersistenceClass, RequestId, RoutingDecision, SessionId,
};
use serde::{Deserialize, Serialize};

use crate::ingress_identity;

pub const INITIAL_POLICY_STATE: PolicyState = PolicyState::Observe;

const DEFAULT_OBSERVE_REASON: &str = "observe policy forwards traffic to the protected upstream";
const INTERVENTIONS_DISABLED_REASON: &str =
    "interventions disabled; forwarding to protected upstream";
const BAIT_ACTION_CONTROLLED_REALITY_REASON: &str =
    "confirmed bait-derived action moved session into controlled reality";
const DISCOVERY_INGRESS_SUSPICIOUS_REASON_PREFIX: &str =
    "authenticated ingress advisory signals promoted discovery request to suspicious";
const DISCOVERY_FANOUT_SUSPICIOUS_REASON_PREFIX: &str =
    "session recon discovery-surface fanout promoted request to suspicious";
const DISCOVERY_RECON_AGGREGATION_SUSPICIOUS_REASON_PREFIX: &str =
    "multi-signal discovery recon aggregation promoted request to suspicious";
const DISCOVERY_RECON_PERSISTENCE_RATE_LIMIT_REASON_PREFIX: &str =
    "suspicious discovery recon persistence moved session to rate limited";
const DISCOVERY_RECON_PERSISTENCE_BLOCKED_REASON_PREFIX: &str =
    "rate-limited discovery recon retry moved session to blocked";
const SAME_BAIT_NEAR_MISS_RATE_LIMIT_REASON_PREFIX: &str =
    "suspicious same-bait near miss after exposure moved session to rate limited";
const REPEATED_SAME_BAIT_NEAR_MISS_BLOCKED_REASON_PREFIX: &str =
    "rate-limited same-bait near miss retry moved session to blocked";
const REPEATED_CONTROLLED_REALITY_DEPTH_LIMIT_BLOCKED_REASON_PREFIX: &str =
    "controlled-reality probe continued after depth-limit throttle and moved session to blocked";
const REPEATED_REALITY_ESCAPE_BLOCKED_REASON_PREFIX: &str =
    "controlled session repeatedly probed outside the controlled-reality branch and moved session to blocked";
const AUTOMATION_LIKELIHOOD_INVERSE_SCORE_KIND: &str = "automation_likelihood_inverse";
const DISCOVERY_SUSPICIOUS_VENDOR_SCORE_MAX: u16 = 20;
const DISCOVERY_RECON_AGGREGATION_VENDOR_SCORE_MAX: u16 = 40;
const DISCOVERY_RECON_AGGREGATION_SCORE_THRESHOLD: u8 = 3;
const DISCOVERY_RECON_RATE_LIMIT_SCORE_THRESHOLD: u8 = 5;
const DISCOVERY_RECON_REPEATED_DISCOVERY_SCORE: u8 = 2;
const DISCOVERY_RECON_QUERY_SEEN_SCORE: u8 = 1;
const DISCOVERY_RECON_LEGACY_OPENAPI_QUERY_SCORE: u8 = 2;
const DISCOVERY_RECON_LINKED_BAIT_SURFACE_SCORE: u8 = 2;
const DISCOVERY_RECON_LINKED_BAIT_CLASS_FANOUT_BONUS: u8 = 1;
const DISCOVERY_RECON_DECOY_WRITE_PROBE_SCORE: u8 = 2;
const DISCOVERY_RECON_DECOY_WRITE_PROBE_REPEAT_BONUS: u8 = 1;
const DISCOVERY_RECON_DECOY_WRITE_PROBE_PATH_FANOUT_BONUS: u8 = 1;
const DISCOVERY_RECON_DECOY_WRITE_PROBE_COUNT_CAP: u8 = 2;
const DISCOVERY_RECON_DETECTION_SIGNAL_SCORE: u8 = 2;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiscoveryReconState {
    pub fanout: DiscoverySurfaceFanout,
    pub request_count: u32,
    pub query_seen: bool,
    pub legacy_openapi_query_seen: bool,
    pub linked_bait_surface_seen: bool,
    pub linked_bait_surface_classes: u8,
    pub decoy_write_probe_seen: bool,
    pub decoy_write_probe_count: u8,
    pub decoy_write_probe_path_classes: u8,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiscoveryReconAggregationScore {
    pub repeated_discovery_score: u8,
    pub query_score: u8,
    pub legacy_openapi_query_score: u8,
    pub linked_bait_surface_score: u8,
    pub linked_bait_class_fanout_bonus: u8,
    pub decoy_write_probe_score: u8,
    pub decoy_write_probe_path_fanout_bonus: u8,
    pub detection_score: u8,
    pub total: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DiscoveryReconSignalProfile {
    vendor_score: u16,
    detection_count: usize,
    recon_score: DiscoveryReconAggregationScore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DiscoveryReconPersistenceProfile {
    signal: DiscoveryReconSignalProfile,
    persistence_class: PreContainmentPersistenceClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverySurfaceKind {
    Docs,
    OpenApi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkedBaitSurfaceKind {
    Docs,
    Assets,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoyWriteProbePathKind {
    Reconcile,
    Other,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoverySurfaceFanout {
    #[serde(default)]
    pub docs_seen: bool,
    #[serde(default)]
    pub openapi_seen: bool,
}

impl DiscoverySurfaceFanout {
    pub fn mark(self, kind: DiscoverySurfaceKind) -> Self {
        let mut next = self;
        match kind {
            DiscoverySurfaceKind::Docs => next.docs_seen = true,
            DiscoverySurfaceKind::OpenApi => next.openapi_seen = true,
        }
        next
    }

    pub fn distinct_surface_count(self) -> u8 {
        u8::from(self.docs_seen) + u8::from(self.openapi_seen)
    }

    pub fn summary(self) -> &'static str {
        match (self.docs_seen, self.openapi_seen) {
            (true, true) => "/docs,/openapi.json",
            (true, false) => "/docs",
            (false, true) => "/openapi.json",
            (false, false) => "none",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedBaitSurfaceFanout {
    #[serde(default)]
    pub docs_seen: bool,
    #[serde(default)]
    pub assets_seen: bool,
    #[serde(default)]
    pub other_seen: bool,
}

impl LinkedBaitSurfaceFanout {
    pub fn mark(self, kind: LinkedBaitSurfaceKind) -> Self {
        let mut next = self;
        match kind {
            LinkedBaitSurfaceKind::Docs => next.docs_seen = true,
            LinkedBaitSurfaceKind::Assets => next.assets_seen = true,
            LinkedBaitSurfaceKind::Other => next.other_seen = true,
        }
        next
    }

    pub fn any_seen(self) -> bool {
        self.distinct_surface_count() > 0
    }

    pub fn distinct_surface_count(self) -> u8 {
        u8::from(self.docs_seen) + u8::from(self.assets_seen) + u8::from(self.other_seen)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecoyWriteProbeFanout {
    #[serde(default)]
    pub reconcile_seen: bool,
    #[serde(default)]
    pub other_seen: bool,
}

impl DecoyWriteProbeFanout {
    pub fn mark(self, kind: DecoyWriteProbePathKind) -> Self {
        let mut next = self;
        match kind {
            DecoyWriteProbePathKind::Reconcile => next.reconcile_seen = true,
            DecoyWriteProbePathKind::Other => next.other_seen = true,
        }
        next
    }

    pub fn distinct_path_count(self) -> u8 {
        u8::from(self.reconcile_seen) + u8::from(self.other_seen)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    pub policy_state: PolicyState,
    pub routing_decision: RoutingDecision,
    pub reason: String,
    pub persistence: PolicyPersistenceMetadata,
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
            persistence: PolicyPersistenceMetadata::default(),
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
    pub persistence: PolicyPersistenceMetadata,
}

impl PolicyTransition {
    pub fn new(from: PolicyState, to: PolicyState, reason: impl Into<String>) -> Self {
        Self {
            from,
            to,
            reason: reason.into(),
            persistence: PolicyPersistenceMetadata::default(),
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
        PolicyState::Observe | PolicyState::Suspicious | PolicyState::RateLimited => {
            Some(PolicyTransition::new(
                current_state,
                PolicyState::ControlledReality,
                BAIT_ACTION_CONTROLLED_REALITY_REASON,
            ))
        }
        PolicyState::Normal | PolicyState::ControlledReality | PolicyState::Blocked => None,
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

pub fn transition_to_suspicious_from_discovery_fanout(
    current_state: PolicyState,
    path: &str,
    ingress_identity: &IngressIdentity,
    fanout: DiscoverySurfaceFanout,
) -> Option<PolicyTransition> {
    if !matches!(current_state, PolicyState::Normal | PolicyState::Observe) {
        return None;
    }
    if ingress_identity::softens_bait_surface_exposure(ingress_identity) {
        return None;
    }
    if fanout.distinct_surface_count() < 2 {
        return None;
    }

    Some(PolicyTransition::new(
        current_state,
        PolicyState::Suspicious,
        format!(
            "{DISCOVERY_FANOUT_SUSPICIOUS_REASON_PREFIX}: path={path} distinct_surfaces={} surfaces={}",
            fanout.distinct_surface_count(),
            fanout.summary(),
        ),
    ))
}

pub fn transition_to_suspicious_from_aggregated_discovery_recon(
    current_state: PolicyState,
    path: &str,
    path_is_recon_candidate: bool,
    ingress_identity: &IngressIdentity,
    ingress_signals: &IngressAdvisorySignals,
    recon_state: DiscoveryReconState,
) -> Option<PolicyTransition> {
    if !matches!(current_state, PolicyState::Normal | PolicyState::Observe) {
        return None;
    }
    if ingress_identity::softens_bait_surface_exposure(ingress_identity) {
        return None;
    }
    if !path_is_recon_candidate {
        return None;
    }
    let signal = discovery_recon_signal_profile(ingress_signals, recon_state)?;
    let recon_score = signal.recon_score;
    if recon_score.total < DISCOVERY_RECON_AGGREGATION_SCORE_THRESHOLD
        || recon_score.total == recon_score.decoy_write_probe_score
    {
        return None;
    }

    Some(PolicyTransition::new(
        current_state,
        PolicyState::Suspicious,
        format_discovery_recon_reason(
            DISCOVERY_RECON_AGGREGATION_SUSPICIOUS_REASON_PREFIX,
            "recon_threshold",
            DISCOVERY_RECON_AGGREGATION_SCORE_THRESHOLD,
            path,
            ingress_signals.actor_kind,
            signal,
            recon_state,
        ),
    ))
}

pub fn aggregated_discovery_recon_score(
    ingress_signals: &IngressAdvisorySignals,
    recon_state: DiscoveryReconState,
) -> DiscoveryReconAggregationScore {
    let repeated_discovery_score = if recon_state.request_count >= 2 {
        DISCOVERY_RECON_REPEATED_DISCOVERY_SCORE
    } else {
        0
    };
    let query_score = if recon_state.query_seen {
        DISCOVERY_RECON_QUERY_SEEN_SCORE
    } else {
        0
    };
    let legacy_openapi_query_score = if recon_state.legacy_openapi_query_seen {
        DISCOVERY_RECON_LEGACY_OPENAPI_QUERY_SCORE
    } else {
        0
    };
    let linked_bait_surface_score = if recon_state.linked_bait_surface_seen {
        DISCOVERY_RECON_LINKED_BAIT_SURFACE_SCORE
    } else {
        0
    };
    let linked_bait_class_fanout_bonus = if recon_state.linked_bait_surface_classes >= 2 {
        DISCOVERY_RECON_LINKED_BAIT_CLASS_FANOUT_BONUS
    } else {
        0
    };
    let decoy_write_probe_score = if recon_state.decoy_write_probe_count == 0 {
        0
    } else {
        DISCOVERY_RECON_DECOY_WRITE_PROBE_SCORE.saturating_add(
            if recon_state.decoy_write_probe_count >= DISCOVERY_RECON_DECOY_WRITE_PROBE_COUNT_CAP {
                DISCOVERY_RECON_DECOY_WRITE_PROBE_REPEAT_BONUS
            } else {
                0
            },
        )
    };
    let decoy_write_probe_path_fanout_bonus = if recon_state.decoy_write_probe_path_classes >= 2 {
        DISCOVERY_RECON_DECOY_WRITE_PROBE_PATH_FANOUT_BONUS
    } else {
        0
    };
    let detection_score = if ingress_signals.detection_ids.is_empty() {
        0
    } else {
        DISCOVERY_RECON_DETECTION_SIGNAL_SCORE
    };
    let total = repeated_discovery_score
        .saturating_add(query_score)
        .saturating_add(legacy_openapi_query_score)
        .saturating_add(linked_bait_surface_score)
        .saturating_add(linked_bait_class_fanout_bonus)
        .saturating_add(decoy_write_probe_score)
        .saturating_add(decoy_write_probe_path_fanout_bonus)
        .saturating_add(detection_score);

    DiscoveryReconAggregationScore {
        repeated_discovery_score,
        query_score,
        legacy_openapi_query_score,
        linked_bait_surface_score,
        linked_bait_class_fanout_bonus,
        decoy_write_probe_score,
        decoy_write_probe_path_fanout_bonus,
        detection_score,
        total,
    }
}

pub fn discovery_recon_aggregation_score_threshold() -> u8 {
    DISCOVERY_RECON_AGGREGATION_SCORE_THRESHOLD
}

pub fn discovery_recon_rate_limit_score_threshold() -> u8 {
    DISCOVERY_RECON_RATE_LIMIT_SCORE_THRESHOLD
}

pub fn discovery_recon_decoy_write_probe_count_cap() -> u8 {
    DISCOVERY_RECON_DECOY_WRITE_PROBE_COUNT_CAP
}

pub fn transition_to_rate_limited_from_suspicious_discovery_recon(
    current_state: PolicyState,
    path: &str,
    path_is_top_level_discovery: bool,
    path_is_blind_decoy_write_probe: bool,
    ingress_identity: &IngressIdentity,
    ingress_signals: &IngressAdvisorySignals,
    recon_state: DiscoveryReconState,
) -> Option<PolicyTransition> {
    if current_state != PolicyState::Suspicious {
        return None;
    }
    let profile = discovery_recon_persistence_profile(
        path_is_top_level_discovery,
        path_is_blind_decoy_write_probe,
        ingress_identity,
        ingress_signals,
        recon_state,
    )?;
    let recon_score = profile.signal.recon_score;
    if recon_score.total < DISCOVERY_RECON_RATE_LIMIT_SCORE_THRESHOLD {
        return None;
    }

    let mut transition = PolicyTransition::new(
        current_state,
        PolicyState::RateLimited,
        format_discovery_recon_reason(
            DISCOVERY_RECON_PERSISTENCE_RATE_LIMIT_REASON_PREFIX,
            "recon_rate_limit_threshold",
            DISCOVERY_RECON_RATE_LIMIT_SCORE_THRESHOLD,
            path,
            ingress_signals.actor_kind,
            profile.signal,
            recon_state,
        ),
    );
    transition.persistence = pre_containment_persistence_metadata(profile.persistence_class);
    Some(transition)
}

pub fn transition_to_blocked_from_repeated_discovery_recon(
    current_state: PolicyState,
    path: &str,
    path_is_top_level_discovery: bool,
    path_is_blind_decoy_write_probe: bool,
    ingress_identity: &IngressIdentity,
    ingress_signals: &IngressAdvisorySignals,
    recon_state: DiscoveryReconState,
) -> Option<PolicyTransition> {
    if current_state != PolicyState::RateLimited {
        return None;
    }
    let profile = discovery_recon_persistence_profile(
        path_is_top_level_discovery,
        path_is_blind_decoy_write_probe,
        ingress_identity,
        ingress_signals,
        recon_state,
    )?;
    let recon_score = profile.signal.recon_score;
    if recon_score.total < DISCOVERY_RECON_RATE_LIMIT_SCORE_THRESHOLD {
        return None;
    }

    let mut transition = PolicyTransition::new(
        current_state,
        PolicyState::Blocked,
        format_discovery_recon_reason(
            DISCOVERY_RECON_PERSISTENCE_BLOCKED_REASON_PREFIX,
            "recon_block_threshold",
            DISCOVERY_RECON_RATE_LIMIT_SCORE_THRESHOLD,
            path,
            ingress_signals.actor_kind,
            profile.signal,
            recon_state,
        ),
    );
    transition.persistence =
        pre_containment_blocked_persistence_metadata(profile.persistence_class);
    Some(transition)
}

pub fn transition_to_rate_limited_from_same_bait_near_miss(
    current_state: PolicyState,
    path: &str,
    bait_id: &BaitId,
    prior_same_bait_exposure: bool,
) -> Option<PolicyTransition> {
    if current_state != PolicyState::Suspicious || !prior_same_bait_exposure {
        return None;
    }

    let mut transition = PolicyTransition::new(
        current_state,
        PolicyState::RateLimited,
        format!(
            "{SAME_BAIT_NEAR_MISS_RATE_LIMIT_REASON_PREFIX}: path={path} bait_id={}",
            bait_id.0
        ),
    );
    transition.persistence =
        pre_containment_persistence_metadata(PreContainmentPersistenceClass::SameBaitNearMiss);
    Some(transition)
}

pub fn transition_to_blocked_from_repeated_same_bait_near_miss(
    current_state: PolicyState,
    path: &str,
    bait_id: &BaitId,
    prior_same_bait_exposure: bool,
) -> Option<PolicyTransition> {
    if current_state != PolicyState::RateLimited || !prior_same_bait_exposure {
        return None;
    }

    let mut transition = PolicyTransition::new(
        current_state,
        PolicyState::Blocked,
        format!(
            "{REPEATED_SAME_BAIT_NEAR_MISS_BLOCKED_REASON_PREFIX}: path={path} bait_id={}",
            bait_id.0
        ),
    );
    transition.persistence = pre_containment_blocked_persistence_metadata(
        PreContainmentPersistenceClass::SameBaitNearMiss,
    );
    Some(transition)
}

fn discovery_recon_signal_profile(
    ingress_signals: &IngressAdvisorySignals,
    recon_state: DiscoveryReconState,
) -> Option<DiscoveryReconSignalProfile> {
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
    if vendor_score <= DISCOVERY_SUSPICIOUS_VENDOR_SCORE_MAX
        || vendor_score > DISCOVERY_RECON_AGGREGATION_VENDOR_SCORE_MAX
    {
        return None;
    }

    Some(DiscoveryReconSignalProfile {
        vendor_score,
        detection_count: ingress_signals.detection_ids.len(),
        recon_score: aggregated_discovery_recon_score(ingress_signals, recon_state),
    })
}

fn discovery_recon_persistence_profile(
    path_is_top_level_discovery: bool,
    path_is_blind_decoy_write_probe: bool,
    ingress_identity: &IngressIdentity,
    ingress_signals: &IngressAdvisorySignals,
    recon_state: DiscoveryReconState,
) -> Option<DiscoveryReconPersistenceProfile> {
    if ingress_identity::softens_bait_surface_exposure(ingress_identity) {
        return None;
    }
    if !path_is_top_level_discovery && !path_is_blind_decoy_write_probe {
        return None;
    }

    Some(DiscoveryReconPersistenceProfile {
        signal: discovery_recon_signal_profile(ingress_signals, recon_state)?,
        persistence_class: pre_containment_persistence_class_for_recon(
            path_is_top_level_discovery,
            path_is_blind_decoy_write_probe,
        )?,
    })
}

fn format_discovery_recon_reason(
    prefix: &str,
    threshold_field: &str,
    threshold: u8,
    path: &str,
    actor_kind: IngressActorKind,
    signal: DiscoveryReconSignalProfile,
    recon_state: DiscoveryReconState,
) -> String {
    format!(
        "{prefix}: path={path} actor_kind={} vendor_score={} discovery_requests={} distinct_surfaces={} query_seen={} legacy_openapi_query_seen={} linked_bait_surface_seen={} linked_bait_surface_classes={} decoy_write_probe_seen={} decoy_write_probe_count={} decoy_write_probe_path_classes={} detection_count={} repeated_discovery_score={} query_score={} legacy_openapi_query_score={} linked_bait_surface_score={} linked_bait_class_fanout_bonus={} decoy_write_probe_score={} decoy_write_probe_path_fanout_bonus={} detection_score={} recon_score={} {threshold_field}={threshold}",
        snake_case_actor_kind(actor_kind),
        signal.vendor_score,
        recon_state.request_count,
        recon_state.fanout.distinct_surface_count(),
        recon_state.query_seen,
        recon_state.legacy_openapi_query_seen,
        recon_state.linked_bait_surface_seen,
        recon_state.linked_bait_surface_classes,
        recon_state.decoy_write_probe_seen,
        recon_state.decoy_write_probe_count,
        recon_state.decoy_write_probe_path_classes,
        signal.detection_count,
        signal.recon_score.repeated_discovery_score,
        signal.recon_score.query_score,
        signal.recon_score.legacy_openapi_query_score,
        signal.recon_score.linked_bait_surface_score,
        signal.recon_score.linked_bait_class_fanout_bonus,
        signal.recon_score.decoy_write_probe_score,
        signal.recon_score.decoy_write_probe_path_fanout_bonus,
        signal.recon_score.detection_score,
        signal.recon_score.total,
    )
}

fn pre_containment_persistence_class_for_recon(
    path_is_top_level_discovery: bool,
    path_is_blind_decoy_write_probe: bool,
) -> Option<PreContainmentPersistenceClass> {
    if path_is_blind_decoy_write_probe {
        return Some(PreContainmentPersistenceClass::WriteRecon);
    }
    if path_is_top_level_discovery {
        return Some(PreContainmentPersistenceClass::DiscoveryRecon);
    }
    None
}

fn pre_containment_persistence_metadata(
    persistence_class: PreContainmentPersistenceClass,
) -> PolicyPersistenceMetadata {
    PolicyPersistenceMetadata {
        pre_containment_persistence_class: Some(persistence_class),
        pre_containment_persistence_kind: None,
        post_containment_persistence_kind: None,
    }
}

fn pre_containment_blocked_persistence_metadata(
    persistence_class: PreContainmentPersistenceClass,
) -> PolicyPersistenceMetadata {
    PolicyPersistenceMetadata {
        pre_containment_persistence_class: Some(persistence_class),
        pre_containment_persistence_kind: Some(persistence_class.blocked_kind()),
        post_containment_persistence_kind: None,
    }
}

fn post_containment_persistence_metadata(
    persistence_kind: PostContainmentPersistenceKind,
) -> PolicyPersistenceMetadata {
    PolicyPersistenceMetadata {
        pre_containment_persistence_class: None,
        pre_containment_persistence_kind: None,
        post_containment_persistence_kind: Some(persistence_kind),
    }
}

pub fn transition_to_blocked_from_repeated_controlled_reality_depth_limit(
    current_state: PolicyState,
    path: &str,
    depth: u32,
    depth_limit: u32,
) -> Option<PolicyTransition> {
    if current_state != PolicyState::ControlledReality || depth <= depth_limit.saturating_add(1) {
        return None;
    }

    let mut transition = PolicyTransition::new(
        current_state,
        PolicyState::Blocked,
        format!(
            "{REPEATED_CONTROLLED_REALITY_DEPTH_LIMIT_BLOCKED_REASON_PREFIX}: path={path} depth={depth} depth_limit={depth_limit}",
        ),
    );
    transition.persistence = post_containment_persistence_metadata(
        PostContainmentPersistenceKind::ControlledRealityDepthLimit,
    );
    Some(transition)
}

pub fn transition_to_blocked_from_repeated_reality_escape_attempt(
    current_state: PolicyState,
    path: &str,
    attempt_count: u32,
) -> Option<PolicyTransition> {
    if current_state != PolicyState::ControlledReality || attempt_count < 2 {
        return None;
    }

    let mut transition = PolicyTransition::new(
        current_state,
        PolicyState::Blocked,
        format!(
            "{REPEATED_REALITY_ESCAPE_BLOCKED_REASON_PREFIX}: path={path} attempt_count={attempt_count}",
        ),
    );
    transition.persistence = post_containment_persistence_metadata(
        PostContainmentPersistenceKind::ControlledRealityBranchEscape,
    );
    Some(transition)
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

pub fn policy_intervention_event(
    session_id: SessionId,
    request_id: RequestId,
    decision: &PolicyDecision,
) -> Event {
    let kind = match decision.routing_decision {
        RoutingDecision::ControlledReality => EventKind::ControlledRealityEntered {
            reason: decision.reason.clone(),
            persistence: decision.persistence.clone(),
        },
        RoutingDecision::RateLimited => EventKind::RateLimitApplied {
            reason: decision.reason.clone(),
            persistence: decision.persistence.clone(),
        },
        _ => EventKind::PolicyDecision {
            routing_decision: decision.routing_decision,
            reason: decision.reason.clone(),
            persistence: decision.persistence.clone(),
        },
    };

    Event::new(
        session_id,
        EventSource::PolicyRouter,
        decision.policy_state,
        kind,
    )
    .with_request_id(request_id)
}

pub fn policy_changed_event(
    session_id: SessionId,
    request_id: RequestId,
    transition: &PolicyTransition,
) -> Event {
    Event::new(
        session_id,
        EventSource::PolicyRouter,
        transition.to,
        EventKind::PolicyChanged {
            from: transition.from,
            to: transition.to,
            reason: transition.reason.clone(),
            persistence: transition.persistence.clone(),
        },
    )
    .with_request_id(request_id)
}

pub fn response_audit_event(
    session_id: SessionId,
    request_id: RequestId,
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
    .with_request_id(request_id)
}

pub fn reality_escape_attempt_event(
    session_id: SessionId,
    request_id: RequestId,
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
            persistence: PolicyPersistenceMetadata::default(),
        },
    )
    .with_request_id(request_id)
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
    fn correlated_bait_action_transitions_observe_suspicious_or_rate_limited_to_controlled_reality()
    {
        let Some(observe) = transition_after_correlated_bait_action(PolicyState::Observe) else {
            panic!("observe should transition");
        };
        let Some(suspicious) = transition_after_correlated_bait_action(PolicyState::Suspicious)
        else {
            panic!("suspicious should transition");
        };
        let Some(rate_limited) = transition_after_correlated_bait_action(PolicyState::RateLimited)
        else {
            panic!("rate_limited should transition");
        };

        assert_eq!(observe.from, PolicyState::Observe);
        assert_eq!(observe.to, PolicyState::ControlledReality);
        assert_eq!(suspicious.from, PolicyState::Suspicious);
        assert_eq!(suspicious.to, PolicyState::ControlledReality);
        assert_eq!(rate_limited.from, PolicyState::RateLimited);
        assert_eq!(rate_limited.to, PolicyState::ControlledReality);
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
                not_before: None,
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
    fn discovery_surface_fanout_promotes_to_suspicious() {
        let Some(transition) = transition_to_suspicious_from_discovery_fanout(
            PolicyState::Observe,
            "/openapi.json",
            &IngressIdentity::default(),
            DiscoverySurfaceFanout {
                docs_seen: true,
                openapi_seen: true,
            },
        ) else {
            panic!("observe should transition to suspicious");
        };

        assert_eq!(transition.from, PolicyState::Observe);
        assert_eq!(transition.to, PolicyState::Suspicious);
        assert!(transition.reason.contains("discovery-surface fanout"));
        assert!(transition.reason.contains("distinct_surfaces=2"));
        assert!(transition.reason.contains("surfaces=/docs,/openapi.json"));
    }

    #[test]
    fn trusted_identity_does_not_promote_to_suspicious_from_discovery_fanout() {
        let transition = transition_to_suspicious_from_discovery_fanout(
            PolicyState::Observe,
            "/openapi.json",
            &IngressIdentity {
                source: eidolon_core::IngressIdentitySource::SignedAgent,
                trust_tier: eidolon_core::IngressTrustTier::SignedAttested,
                label: Some("signed-agent".to_string()),
                not_before: None,
                expires_at: None,
            },
            DiscoverySurfaceFanout {
                docs_seen: true,
                openapi_seen: true,
            },
        );

        assert_eq!(transition, None);
    }

    #[test]
    fn incomplete_discovery_surface_fanout_does_not_promote_to_suspicious() {
        let docs_only = transition_to_suspicious_from_discovery_fanout(
            PolicyState::Observe,
            "/docs",
            &IngressIdentity::default(),
            DiscoverySurfaceFanout {
                docs_seen: true,
                openapi_seen: false,
            },
        );
        let already_suspicious = transition_to_suspicious_from_discovery_fanout(
            PolicyState::Suspicious,
            "/openapi.json",
            &IngressIdentity::default(),
            DiscoverySurfaceFanout {
                docs_seen: true,
                openapi_seen: true,
            },
        );

        assert_eq!(docs_only, None);
        assert_eq!(already_suspicious, None);
    }

    #[test]
    fn suspicious_same_bait_near_miss_after_exposure_promotes_to_rate_limited() {
        let Some(transition) = transition_to_rate_limited_from_same_bait_near_miss(
            PolicyState::Suspicious,
            "/api/v2/import/reconcile",
            &BaitId("rel_2025_04_b7f2".to_string()),
            true,
        ) else {
            panic!("suspicious near miss should transition to rate limited");
        };

        assert_eq!(transition.from, PolicyState::Suspicious);
        assert_eq!(transition.to, PolicyState::RateLimited);
        assert!(transition
            .reason
            .contains(SAME_BAIT_NEAR_MISS_RATE_LIMIT_REASON_PREFIX));
        assert!(transition.reason.contains("path=/api/v2/import/reconcile"));
        assert!(transition.reason.contains("bait_id=rel_2025_04_b7f2"));
        assert_eq!(
            transition.persistence.pre_containment_persistence_class,
            Some(PreContainmentPersistenceClass::SameBaitNearMiss)
        );
        assert_eq!(
            transition.persistence.pre_containment_persistence_kind,
            None
        );
    }

    #[test]
    fn same_bait_near_miss_requires_suspicious_state_and_prior_exposure() {
        let no_prior = transition_to_rate_limited_from_same_bait_near_miss(
            PolicyState::Suspicious,
            "/api/v2/import/reconcile",
            &BaitId("rel_2025_04_b7f2".to_string()),
            false,
        );
        let observe = transition_to_rate_limited_from_same_bait_near_miss(
            PolicyState::Observe,
            "/api/v2/import/reconcile",
            &BaitId("rel_2025_04_b7f2".to_string()),
            true,
        );

        assert_eq!(no_prior, None);
        assert_eq!(observe, None);
    }

    #[test]
    fn suspicious_discovery_recon_persistence_promotes_to_rate_limited() {
        let Some(transition) = transition_to_rate_limited_from_suspicious_discovery_recon(
            PolicyState::Suspicious,
            "/docs",
            true,
            false,
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(35),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: true,
                },
                request_count: 2,
                query_seen: true,
                legacy_openapi_query_seen: true,
                linked_bait_surface_seen: false,
                linked_bait_surface_classes: 0,
                decoy_write_probe_seen: false,
                decoy_write_probe_count: 0,
                decoy_write_probe_path_classes: 0,
            },
        ) else {
            panic!("suspicious discovery recon persistence should transition to rate limited");
        };

        assert_eq!(transition.from, PolicyState::Suspicious);
        assert_eq!(transition.to, PolicyState::RateLimited);
        assert!(transition
            .reason
            .contains(DISCOVERY_RECON_PERSISTENCE_RATE_LIMIT_REASON_PREFIX));
        assert!(transition.reason.contains("path=/docs"));
        assert!(transition.reason.contains("vendor_score=35"));
        assert!(transition.reason.contains("discovery_requests=2"));
        assert!(transition.reason.contains("distinct_surfaces=2"));
        assert!(transition.reason.contains("query_seen=true"));
        assert!(transition.reason.contains("legacy_openapi_query_seen=true"));
        assert!(transition.reason.contains("detection_count=0"));
        assert!(transition.reason.contains("repeated_discovery_score=2"));
        assert!(transition.reason.contains("query_score=1"));
        assert!(transition.reason.contains("legacy_openapi_query_score=2"));
        assert!(transition.reason.contains("recon_score=5"));
        assert!(transition.reason.contains("recon_rate_limit_threshold=5"));
        assert_eq!(
            transition.persistence.pre_containment_persistence_class,
            Some(PreContainmentPersistenceClass::DiscoveryRecon)
        );
        assert_eq!(
            transition.persistence.pre_containment_persistence_kind,
            None
        );
    }

    #[test]
    fn suspicious_discovery_recon_rate_limit_requires_top_level_path_and_higher_score() {
        let no_top_level = transition_to_rate_limited_from_suspicious_discovery_recon(
            PolicyState::Suspicious,
            "/docs/legacy-import",
            false,
            false,
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(35),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: false,
                },
                request_count: 1,
                query_seen: true,
                legacy_openapi_query_seen: false,
                linked_bait_surface_seen: true,
                linked_bait_surface_classes: 1,
                decoy_write_probe_seen: false,
                decoy_write_probe_count: 0,
                decoy_write_probe_path_classes: 0,
            },
        );
        let below_threshold = transition_to_rate_limited_from_suspicious_discovery_recon(
            PolicyState::Suspicious,
            "/docs",
            true,
            false,
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(35),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: false,
                },
                request_count: 2,
                query_seen: true,
                legacy_openapi_query_seen: false,
                linked_bait_surface_seen: false,
                linked_bait_surface_classes: 0,
                decoy_write_probe_seen: false,
                decoy_write_probe_count: 0,
                decoy_write_probe_path_classes: 0,
            },
        );
        let observe = transition_to_rate_limited_from_suspicious_discovery_recon(
            PolicyState::Observe,
            "/docs",
            true,
            false,
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(35),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: true,
                },
                request_count: 2,
                query_seen: true,
                legacy_openapi_query_seen: true,
                linked_bait_surface_seen: false,
                linked_bait_surface_classes: 0,
                decoy_write_probe_seen: false,
                decoy_write_probe_count: 0,
                decoy_write_probe_path_classes: 0,
            },
        );

        assert_eq!(no_top_level, None);
        assert_eq!(below_threshold, None);
        assert_eq!(observe, None);
    }

    #[test]
    fn suspicious_discovery_recon_blind_write_fanout_promotes_to_rate_limited() {
        let Some(transition) = transition_to_rate_limited_from_suspicious_discovery_recon(
            PolicyState::Suspicious,
            "/api/v2/import/validate",
            false,
            true,
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(35),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: false,
                },
                request_count: 1,
                query_seen: true,
                legacy_openapi_query_seen: false,
                linked_bait_surface_seen: false,
                linked_bait_surface_classes: 0,
                decoy_write_probe_seen: true,
                decoy_write_probe_count: 2,
                decoy_write_probe_path_classes: 2,
            },
        ) else {
            panic!("blind-write fanout should transition suspicious recon to rate limited");
        };

        assert_eq!(transition.from, PolicyState::Suspicious);
        assert_eq!(transition.to, PolicyState::RateLimited);
        assert!(transition.reason.contains("path=/api/v2/import/validate"));
        assert!(transition.reason.contains("discovery_requests=1"));
        assert!(transition.reason.contains("query_seen=true"));
        assert!(transition.reason.contains("decoy_write_probe_count=2"));
        assert!(transition
            .reason
            .contains("decoy_write_probe_path_classes=2"));
        assert!(transition.reason.contains("repeated_discovery_score=0"));
        assert!(transition.reason.contains("query_score=1"));
        assert!(transition.reason.contains("decoy_write_probe_score=3"));
        assert!(transition
            .reason
            .contains("decoy_write_probe_path_fanout_bonus=1"));
        assert!(transition.reason.contains("recon_score=5"));
        assert!(transition.reason.contains("recon_rate_limit_threshold=5"));
        assert_eq!(
            transition.persistence.pre_containment_persistence_class,
            Some(PreContainmentPersistenceClass::WriteRecon)
        );
        assert_eq!(
            transition.persistence.pre_containment_persistence_kind,
            None
        );
    }

    #[test]
    fn repeated_discovery_recon_after_rate_limit_promotes_to_blocked() {
        let Some(transition) = transition_to_blocked_from_repeated_discovery_recon(
            PolicyState::RateLimited,
            "/docs",
            true,
            false,
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(35),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: true,
                },
                request_count: 3,
                query_seen: true,
                legacy_openapi_query_seen: true,
                linked_bait_surface_seen: false,
                linked_bait_surface_classes: 0,
                decoy_write_probe_seen: false,
                decoy_write_probe_count: 0,
                decoy_write_probe_path_classes: 0,
            },
        ) else {
            panic!("rate-limited discovery recon retry should transition to blocked");
        };

        assert_eq!(transition.from, PolicyState::RateLimited);
        assert_eq!(transition.to, PolicyState::Blocked);
        assert!(transition
            .reason
            .contains(DISCOVERY_RECON_PERSISTENCE_BLOCKED_REASON_PREFIX));
        assert!(transition.reason.contains("path=/docs"));
        assert!(transition.reason.contains("vendor_score=35"));
        assert!(transition.reason.contains("discovery_requests=3"));
        assert!(transition.reason.contains("distinct_surfaces=2"));
        assert!(transition.reason.contains("query_seen=true"));
        assert!(transition.reason.contains("legacy_openapi_query_seen=true"));
        assert!(transition.reason.contains("detection_count=0"));
        assert!(transition.reason.contains("repeated_discovery_score=2"));
        assert!(transition.reason.contains("query_score=1"));
        assert!(transition.reason.contains("legacy_openapi_query_score=2"));
        assert!(transition.reason.contains("recon_score=5"));
        assert!(transition.reason.contains("recon_block_threshold=5"));
        assert_eq!(
            transition.persistence.pre_containment_persistence_class,
            Some(PreContainmentPersistenceClass::DiscoveryRecon)
        );
        assert_eq!(
            transition.persistence.pre_containment_persistence_kind,
            Some(PreContainmentPersistenceKind::DiscoveryReconRetry)
        );
    }

    #[test]
    fn repeated_discovery_recon_block_allows_blind_decoy_write_probe_contributor() {
        let Some(transition) = transition_to_blocked_from_repeated_discovery_recon(
            PolicyState::RateLimited,
            "/docs",
            true,
            false,
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(35),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: false,
                },
                request_count: 3,
                query_seen: true,
                legacy_openapi_query_seen: false,
                linked_bait_surface_seen: false,
                linked_bait_surface_classes: 0,
                decoy_write_probe_seen: true,
                decoy_write_probe_count: 1,
                decoy_write_probe_path_classes: 0,
            },
        ) else {
            panic!("rate-limited discovery recon retry should transition to blocked");
        };

        assert_eq!(transition.from, PolicyState::RateLimited);
        assert_eq!(transition.to, PolicyState::Blocked);
        assert!(transition
            .reason
            .contains(DISCOVERY_RECON_PERSISTENCE_BLOCKED_REASON_PREFIX));
        assert!(transition.reason.contains("path=/docs"));
        assert!(transition.reason.contains("vendor_score=35"));
        assert!(transition.reason.contains("discovery_requests=3"));
        assert!(transition.reason.contains("distinct_surfaces=1"));
        assert!(transition.reason.contains("query_seen=true"));
        assert!(transition.reason.contains("decoy_write_probe_seen=true"));
        assert!(transition.reason.contains("detection_count=0"));
        assert!(transition.reason.contains("repeated_discovery_score=2"));
        assert!(transition.reason.contains("query_score=1"));
        assert!(transition.reason.contains("decoy_write_probe_score=2"));
        assert!(transition.reason.contains("recon_score=5"));
        assert!(transition.reason.contains("recon_block_threshold=5"));
        assert_eq!(
            transition.persistence.pre_containment_persistence_class,
            Some(PreContainmentPersistenceClass::DiscoveryRecon)
        );
        assert_eq!(
            transition.persistence.pre_containment_persistence_kind,
            Some(PreContainmentPersistenceKind::DiscoveryReconRetry)
        );
    }

    #[test]
    fn repeated_discovery_recon_block_requires_rate_limited_top_level_path_and_higher_score() {
        let no_top_level = transition_to_blocked_from_repeated_discovery_recon(
            PolicyState::RateLimited,
            "/docs/legacy-import",
            false,
            false,
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(35),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: true,
                },
                request_count: 3,
                query_seen: true,
                legacy_openapi_query_seen: true,
                linked_bait_surface_seen: false,
                linked_bait_surface_classes: 0,
                decoy_write_probe_seen: false,
                decoy_write_probe_count: 0,
                decoy_write_probe_path_classes: 0,
            },
        );
        let below_threshold = transition_to_blocked_from_repeated_discovery_recon(
            PolicyState::RateLimited,
            "/docs",
            true,
            false,
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(35),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: false,
                },
                request_count: 3,
                query_seen: false,
                legacy_openapi_query_seen: false,
                linked_bait_surface_seen: false,
                linked_bait_surface_classes: 0,
                decoy_write_probe_seen: false,
                decoy_write_probe_count: 0,
                decoy_write_probe_path_classes: 0,
            },
        );
        let suspicious = transition_to_blocked_from_repeated_discovery_recon(
            PolicyState::Suspicious,
            "/docs",
            true,
            false,
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(35),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: true,
                },
                request_count: 3,
                query_seen: true,
                legacy_openapi_query_seen: true,
                linked_bait_surface_seen: false,
                linked_bait_surface_classes: 0,
                decoy_write_probe_seen: false,
                decoy_write_probe_count: 0,
                decoy_write_probe_path_classes: 0,
            },
        );

        assert_eq!(no_top_level, None);
        assert_eq!(below_threshold, None);
        assert_eq!(suspicious, None);
    }

    #[test]
    fn repeated_discovery_recon_block_allows_blind_write_fanout_contributor() {
        let Some(transition) = transition_to_blocked_from_repeated_discovery_recon(
            PolicyState::RateLimited,
            "/api/v2/import/validate",
            false,
            true,
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(35),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: false,
                },
                request_count: 1,
                query_seen: true,
                legacy_openapi_query_seen: false,
                linked_bait_surface_seen: false,
                linked_bait_surface_classes: 0,
                decoy_write_probe_seen: true,
                decoy_write_probe_count: 2,
                decoy_write_probe_path_classes: 2,
            },
        ) else {
            panic!("blind-write fanout should transition rate-limited recon to blocked");
        };

        assert_eq!(transition.from, PolicyState::RateLimited);
        assert_eq!(transition.to, PolicyState::Blocked);
        assert!(transition.reason.contains("path=/api/v2/import/validate"));
        assert!(transition.reason.contains("discovery_requests=1"));
        assert!(transition.reason.contains("query_seen=true"));
        assert!(transition.reason.contains("decoy_write_probe_count=2"));
        assert!(transition
            .reason
            .contains("decoy_write_probe_path_classes=2"));
        assert!(transition.reason.contains("repeated_discovery_score=0"));
        assert!(transition.reason.contains("query_score=1"));
        assert!(transition.reason.contains("decoy_write_probe_score=3"));
        assert!(transition
            .reason
            .contains("decoy_write_probe_path_fanout_bonus=1"));
        assert!(transition.reason.contains("recon_score=5"));
        assert!(transition.reason.contains("recon_block_threshold=5"));
        assert_eq!(
            transition.persistence.pre_containment_persistence_class,
            Some(PreContainmentPersistenceClass::WriteRecon)
        );
        assert_eq!(
            transition.persistence.pre_containment_persistence_kind,
            Some(PreContainmentPersistenceKind::WriteReconRetry)
        );
    }

    #[test]
    fn repeated_same_bait_near_miss_after_rate_limit_promotes_to_blocked() {
        let Some(transition) = transition_to_blocked_from_repeated_same_bait_near_miss(
            PolicyState::RateLimited,
            "/api/v2/import/reconcile",
            &BaitId("rel_2025_04_b7f2".to_string()),
            true,
        ) else {
            panic!("rate-limited repeated near miss should transition to blocked");
        };

        assert_eq!(transition.from, PolicyState::RateLimited);
        assert_eq!(transition.to, PolicyState::Blocked);
        assert!(transition
            .reason
            .contains(REPEATED_SAME_BAIT_NEAR_MISS_BLOCKED_REASON_PREFIX));
        assert!(transition.reason.contains("path=/api/v2/import/reconcile"));
        assert!(transition.reason.contains("bait_id=rel_2025_04_b7f2"));
        assert_eq!(
            transition.persistence.pre_containment_persistence_class,
            Some(PreContainmentPersistenceClass::SameBaitNearMiss)
        );
        assert_eq!(
            transition.persistence.pre_containment_persistence_kind,
            Some(PreContainmentPersistenceKind::SameBaitNearMissRetry)
        );
    }

    #[test]
    fn blocked_retry_transition_requires_rate_limited_state_and_prior_exposure() {
        let no_prior = transition_to_blocked_from_repeated_same_bait_near_miss(
            PolicyState::RateLimited,
            "/api/v2/import/reconcile",
            &BaitId("rel_2025_04_b7f2".to_string()),
            false,
        );
        let suspicious = transition_to_blocked_from_repeated_same_bait_near_miss(
            PolicyState::Suspicious,
            "/api/v2/import/reconcile",
            &BaitId("rel_2025_04_b7f2".to_string()),
            true,
        );

        assert_eq!(no_prior, None);
        assert_eq!(suspicious, None);
    }

    #[test]
    fn aggregated_discovery_recon_promotes_to_suspicious() {
        let Some(transition) = transition_to_suspicious_from_aggregated_discovery_recon(
            PolicyState::Observe,
            "/docs",
            true,
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(35),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: false,
                },
                request_count: 2,
                query_seen: true,
                legacy_openapi_query_seen: false,
                linked_bait_surface_seen: false,
                linked_bait_surface_classes: 0,
                decoy_write_probe_seen: false,
                decoy_write_probe_count: 0,
                decoy_write_probe_path_classes: 0,
            },
        ) else {
            panic!("aggregated discovery recon should transition to suspicious");
        };

        assert_eq!(transition.from, PolicyState::Observe);
        assert_eq!(transition.to, PolicyState::Suspicious);
        assert!(transition
            .reason
            .contains(DISCOVERY_RECON_AGGREGATION_SUSPICIOUS_REASON_PREFIX));
        assert!(transition.reason.contains("vendor_score=35"));
        assert!(transition.reason.contains("discovery_requests=2"));
        assert!(transition.reason.contains("query_seen=true"));
        assert!(transition
            .reason
            .contains("legacy_openapi_query_seen=false"));
        assert!(transition.reason.contains("linked_bait_surface_seen=false"));
        assert!(transition.reason.contains("detection_count=0"));
        assert!(transition.reason.contains("repeated_discovery_score=2"));
        assert!(transition.reason.contains("query_score=1"));
        assert!(transition.reason.contains("recon_score=3"));
        assert!(transition.reason.contains("recon_threshold=3"));
    }

    #[test]
    fn aggregated_discovery_recon_requires_threshold_score_and_medium_score() {
        let no_repetition = transition_to_suspicious_from_aggregated_discovery_recon(
            PolicyState::Observe,
            "/docs",
            true,
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(35),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: false,
                },
                request_count: 1,
                query_seen: true,
                legacy_openapi_query_seen: false,
                linked_bait_surface_seen: false,
                linked_bait_surface_classes: 0,
                decoy_write_probe_seen: false,
                decoy_write_probe_count: 0,
                decoy_write_probe_path_classes: 0,
            },
        );
        let no_query_signal = transition_to_suspicious_from_aggregated_discovery_recon(
            PolicyState::Observe,
            "/docs",
            true,
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(35),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: false,
                },
                request_count: 2,
                query_seen: false,
                legacy_openapi_query_seen: false,
                linked_bait_surface_seen: false,
                linked_bait_surface_classes: 0,
                decoy_write_probe_seen: false,
                decoy_write_probe_count: 0,
                decoy_write_probe_path_classes: 0,
            },
        );
        let stronger_direct_score = transition_to_suspicious_from_aggregated_discovery_recon(
            PolicyState::Observe,
            "/docs",
            true,
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(12),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: false,
                },
                request_count: 2,
                query_seen: true,
                legacy_openapi_query_seen: false,
                linked_bait_surface_seen: false,
                linked_bait_surface_classes: 0,
                decoy_write_probe_seen: false,
                decoy_write_probe_count: 0,
                decoy_write_probe_path_classes: 0,
            },
        );
        let trusted = transition_to_suspicious_from_aggregated_discovery_recon(
            PolicyState::Observe,
            "/docs",
            true,
            &IngressIdentity {
                source: eidolon_core::IngressIdentitySource::SignedAgent,
                trust_tier: eidolon_core::IngressTrustTier::SignedAttested,
                ..Default::default()
            },
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(35),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: false,
                },
                request_count: 2,
                query_seen: true,
                legacy_openapi_query_seen: false,
                linked_bait_surface_seen: false,
                linked_bait_surface_classes: 0,
                decoy_write_probe_seen: false,
                decoy_write_probe_count: 0,
                decoy_write_probe_path_classes: 0,
            },
        );

        assert_eq!(no_repetition, None);
        assert_eq!(no_query_signal, None);
        assert_eq!(stronger_direct_score, None);
        assert_eq!(trusted, None);
    }

    #[test]
    fn aggregated_discovery_recon_detection_ids_allow_first_request_promotion() {
        let Some(transition) = transition_to_suspicious_from_aggregated_discovery_recon(
            PolicyState::Observe,
            "/docs",
            true,
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(35),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                detection_ids: vec!["3355446".to_string(), "445566".to_string()],
                ..Default::default()
            },
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: false,
                },
                request_count: 1,
                query_seen: true,
                legacy_openapi_query_seen: false,
                linked_bait_surface_seen: false,
                linked_bait_surface_classes: 0,
                decoy_write_probe_seen: false,
                decoy_write_probe_count: 0,
                decoy_write_probe_path_classes: 0,
            },
        ) else {
            panic!("detection-backed aggregated discovery recon should transition to suspicious");
        };

        assert_eq!(transition.from, PolicyState::Observe);
        assert_eq!(transition.to, PolicyState::Suspicious);
        assert!(transition.reason.contains("discovery_requests=1"));
        assert!(transition.reason.contains("query_seen=true"));
        assert!(transition
            .reason
            .contains("legacy_openapi_query_seen=false"));
        assert!(transition.reason.contains("linked_bait_surface_seen=false"));
        assert!(transition.reason.contains("detection_count=2"));
        assert!(transition.reason.contains("query_score=1"));
        assert!(transition.reason.contains("detection_score=2"));
        assert!(transition.reason.contains("recon_score=3"));
    }

    #[test]
    fn aggregated_discovery_recon_legacy_openapi_query_allows_first_request_promotion() {
        let Some(transition) = transition_to_suspicious_from_aggregated_discovery_recon(
            PolicyState::Observe,
            "/openapi.json",
            true,
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(35),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: false,
                    openapi_seen: true,
                },
                request_count: 1,
                query_seen: true,
                legacy_openapi_query_seen: true,
                linked_bait_surface_seen: false,
                linked_bait_surface_classes: 0,
                decoy_write_probe_seen: false,
                decoy_write_probe_count: 0,
                decoy_write_probe_path_classes: 0,
            },
        ) else {
            panic!(
                "legacy-openapi-query aggregated discovery recon should transition to suspicious"
            );
        };

        assert_eq!(transition.from, PolicyState::Observe);
        assert_eq!(transition.to, PolicyState::Suspicious);
        assert!(transition.reason.contains("discovery_requests=1"));
        assert!(transition.reason.contains("query_seen=true"));
        assert!(transition.reason.contains("legacy_openapi_query_seen=true"));
        assert!(transition.reason.contains("linked_bait_surface_seen=false"));
        assert!(transition.reason.contains("detection_count=0"));
        assert!(transition.reason.contains("query_score=1"));
        assert!(transition.reason.contains("legacy_openapi_query_score=2"));
        assert!(transition.reason.contains("recon_score=3"));
    }

    #[test]
    fn aggregated_discovery_recon_linked_bait_surface_allows_followup_promotion() {
        let Some(transition) = transition_to_suspicious_from_aggregated_discovery_recon(
            PolicyState::Observe,
            "/docs/legacy-import",
            true,
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(35),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: false,
                },
                request_count: 1,
                query_seen: true,
                legacy_openapi_query_seen: false,
                linked_bait_surface_seen: true,
                linked_bait_surface_classes: 1,
                decoy_write_probe_seen: false,
                decoy_write_probe_count: 0,
                decoy_write_probe_path_classes: 0,
            },
        ) else {
            panic!(
                "linked-bait-surface aggregated discovery recon should transition to suspicious"
            );
        };

        assert_eq!(transition.from, PolicyState::Observe);
        assert_eq!(transition.to, PolicyState::Suspicious);
        assert!(transition.reason.contains("path=/docs/legacy-import"));
        assert!(transition.reason.contains("discovery_requests=1"));
        assert!(transition.reason.contains("query_seen=true"));
        assert!(transition
            .reason
            .contains("legacy_openapi_query_seen=false"));
        assert!(transition.reason.contains("linked_bait_surface_seen=true"));
        assert!(transition.reason.contains("detection_count=0"));
        assert!(transition.reason.contains("query_score=1"));
        assert!(transition.reason.contains("linked_bait_surface_score=2"));
        assert!(transition.reason.contains("recon_score=3"));
    }

    #[test]
    fn aggregated_discovery_recon_blind_decoy_write_probe_allows_followup_promotion() {
        let Some(transition) = transition_to_suspicious_from_aggregated_discovery_recon(
            PolicyState::Observe,
            "/api/v2/import/reconcile",
            true,
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(35),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: false,
                },
                request_count: 1,
                query_seen: true,
                legacy_openapi_query_seen: false,
                linked_bait_surface_seen: false,
                linked_bait_surface_classes: 0,
                decoy_write_probe_seen: true,
                decoy_write_probe_count: 1,
                decoy_write_probe_path_classes: 0,
            },
        ) else {
            panic!("blind decoy write probe should transition medium-score recon to suspicious");
        };

        assert_eq!(transition.from, PolicyState::Observe);
        assert_eq!(transition.to, PolicyState::Suspicious);
        assert!(transition.reason.contains("path=/api/v2/import/reconcile"));
        assert!(transition.reason.contains("query_seen=true"));
        assert!(transition.reason.contains("decoy_write_probe_seen=true"));
        assert!(transition.reason.contains("decoy_write_probe_count=1"));
        assert!(transition.reason.contains("decoy_write_probe_score=2"));
        assert!(transition.reason.contains("recon_score=3"));
    }

    #[test]
    fn repeated_blind_decoy_write_probes_add_a_capped_bonus_to_weighted_recon() {
        let score = aggregated_discovery_recon_score(
            &IngressAdvisorySignals::default(),
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: false,
                },
                request_count: 1,
                query_seen: true,
                legacy_openapi_query_seen: false,
                linked_bait_surface_seen: false,
                linked_bait_surface_classes: 0,
                decoy_write_probe_seen: true,
                decoy_write_probe_count: 2,
                decoy_write_probe_path_classes: 0,
            },
        );

        assert_eq!(score.query_score, 1);
        assert_eq!(score.decoy_write_probe_score, 3);
        assert_eq!(score.total, 4);
    }

    #[test]
    fn distinct_blind_decoy_write_probe_paths_add_a_fanout_bonus_to_weighted_recon() {
        let score = aggregated_discovery_recon_score(
            &IngressAdvisorySignals::default(),
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: false,
                },
                request_count: 1,
                query_seen: true,
                legacy_openapi_query_seen: false,
                linked_bait_surface_seen: false,
                linked_bait_surface_classes: 0,
                decoy_write_probe_seen: true,
                decoy_write_probe_count: 2,
                decoy_write_probe_path_classes: 2,
            },
        );

        assert_eq!(score.query_score, 1);
        assert_eq!(score.decoy_write_probe_score, 3);
        assert_eq!(score.decoy_write_probe_path_fanout_bonus, 1);
        assert_eq!(score.total, 5);
    }

    #[test]
    fn repeated_blind_decoy_write_probes_still_require_another_recon_signal() {
        let no_query_or_discovery = transition_to_suspicious_from_aggregated_discovery_recon(
            PolicyState::Observe,
            "/api/v2/import/reconcile",
            true,
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(35),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout::default(),
                request_count: 0,
                query_seen: false,
                legacy_openapi_query_seen: false,
                linked_bait_surface_seen: false,
                linked_bait_surface_classes: 0,
                decoy_write_probe_seen: true,
                decoy_write_probe_count: 2,
                decoy_write_probe_path_classes: 0,
            },
        );

        assert_eq!(no_query_or_discovery, None);
    }

    #[test]
    fn discovery_recon_persistence_profile_classifies_recon_path_kind() {
        let discovery_profile = discovery_recon_persistence_profile(
            true,
            false,
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(35),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                detection_ids: vec!["3355446".to_string(), "445566".to_string()],
                ..Default::default()
            },
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: false,
                },
                request_count: 2,
                query_seen: true,
                legacy_openapi_query_seen: false,
                linked_bait_surface_seen: false,
                linked_bait_surface_classes: 0,
                decoy_write_probe_seen: false,
                decoy_write_probe_count: 0,
                decoy_write_probe_path_classes: 0,
            },
        )
        .expect("top-level discovery path should classify as a persistence profile");
        let write_profile = discovery_recon_persistence_profile(
            false,
            true,
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(35),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: false,
                },
                request_count: 1,
                query_seen: true,
                legacy_openapi_query_seen: false,
                linked_bait_surface_seen: false,
                linked_bait_surface_classes: 0,
                decoy_write_probe_seen: true,
                decoy_write_probe_count: 2,
                decoy_write_probe_path_classes: 2,
            },
        )
        .expect("blind write path should classify as a persistence profile");

        assert_eq!(
            discovery_profile.persistence_class,
            PreContainmentPersistenceClass::DiscoveryRecon
        );
        assert_eq!(discovery_profile.signal.vendor_score, 35);
        assert_eq!(discovery_profile.signal.detection_count, 2);
        assert_eq!(discovery_profile.signal.recon_score.total, 5);

        assert_eq!(
            write_profile.persistence_class,
            PreContainmentPersistenceClass::WriteRecon
        );
        assert_eq!(write_profile.signal.detection_count, 0);
        assert_eq!(write_profile.signal.recon_score.total, 5);
    }

    #[test]
    fn aggregated_discovery_recon_requires_top_level_or_linked_recon_path() {
        let no_candidate = transition_to_suspicious_from_aggregated_discovery_recon(
            PolicyState::Observe,
            "/api/v2/import/reconcile",
            false,
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(35),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: false,
                },
                request_count: 1,
                query_seen: true,
                legacy_openapi_query_seen: false,
                linked_bait_surface_seen: true,
                linked_bait_surface_classes: 1,
                decoy_write_probe_seen: false,
                decoy_write_probe_count: 0,
                decoy_write_probe_path_classes: 0,
            },
        );

        assert_eq!(no_candidate, None);
    }

    #[test]
    fn aggregated_discovery_recon_hidden_route_followup_allows_promotion() {
        let Some(transition) = transition_to_suspicious_from_aggregated_discovery_recon(
            PolicyState::Observe,
            "/customer/import-recovery-checklist",
            true,
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(35),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: false,
                },
                request_count: 1,
                query_seen: true,
                legacy_openapi_query_seen: false,
                linked_bait_surface_seen: true,
                linked_bait_surface_classes: 1,
                decoy_write_probe_seen: false,
                decoy_write_probe_count: 0,
                decoy_write_probe_path_classes: 0,
            },
        ) else {
            panic!("hidden-route linked discovery recon should transition to suspicious");
        };

        assert_eq!(transition.from, PolicyState::Observe);
        assert_eq!(transition.to, PolicyState::Suspicious);
        assert!(transition
            .reason
            .contains("path=/customer/import-recovery-checklist"));
        assert!(transition.reason.contains("discovery_requests=1"));
        assert!(transition.reason.contains("query_seen=true"));
        assert!(transition.reason.contains("linked_bait_surface_seen=true"));
        assert!(transition.reason.contains("query_score=1"));
        assert!(transition.reason.contains("linked_bait_surface_score=2"));
        assert!(transition.reason.contains("recon_score=3"));
    }

    #[test]
    fn aggregated_discovery_recon_multiple_linked_bait_classes_allow_followup_promotion() {
        let Some(transition) = transition_to_suspicious_from_aggregated_discovery_recon(
            PolicyState::Observe,
            "/assets/import-helper.js",
            true,
            &IngressIdentity::default(),
            &IngressAdvisorySignals {
                actor_kind: IngressActorKind::AgenticBrowser,
                vendor_score: Some(35),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                ..Default::default()
            },
            DiscoveryReconState {
                fanout: DiscoverySurfaceFanout {
                    docs_seen: true,
                    openapi_seen: false,
                },
                request_count: 1,
                query_seen: false,
                legacy_openapi_query_seen: false,
                linked_bait_surface_seen: true,
                linked_bait_surface_classes: 2,
                decoy_write_probe_seen: false,
                decoy_write_probe_count: 0,
                decoy_write_probe_path_classes: 0,
            },
        ) else {
            panic!("multi-class linked discovery recon should transition to suspicious");
        };

        assert_eq!(transition.from, PolicyState::Observe);
        assert_eq!(transition.to, PolicyState::Suspicious);
        assert!(transition.reason.contains("path=/assets/import-helper.js"));
        assert!(transition.reason.contains("query_seen=false"));
        assert!(transition.reason.contains("linked_bait_surface_seen=true"));
        assert!(transition.reason.contains("linked_bait_surface_classes=2"));
        assert!(transition.reason.contains("linked_bait_surface_score=2"));
        assert!(transition
            .reason
            .contains("linked_bait_class_fanout_bonus=1"));
        assert!(transition.reason.contains("recon_score=3"));
    }

    #[test]
    fn repeated_controlled_reality_depth_limit_promotes_to_blocked() {
        let Some(transition) = transition_to_blocked_from_repeated_controlled_reality_depth_limit(
            PolicyState::ControlledReality,
            "/api/v2/import/reconcile",
            6,
            4,
        ) else {
            panic!("controlled-reality repeated depth-limit probe should transition to blocked");
        };

        assert_eq!(transition.from, PolicyState::ControlledReality);
        assert_eq!(transition.to, PolicyState::Blocked);
        assert!(transition
            .reason
            .contains(REPEATED_CONTROLLED_REALITY_DEPTH_LIMIT_BLOCKED_REASON_PREFIX));
        assert!(transition.reason.contains("path=/api/v2/import/reconcile"));
        assert!(transition.reason.contains("depth=6"));
        assert!(transition.reason.contains("depth_limit=4"));
        assert_eq!(
            transition.persistence.post_containment_persistence_kind,
            Some(PostContainmentPersistenceKind::ControlledRealityDepthLimit)
        );
    }

    #[test]
    fn controlled_reality_depth_limit_block_requires_repeated_over_limit_probe() {
        let first_over_limit = transition_to_blocked_from_repeated_controlled_reality_depth_limit(
            PolicyState::ControlledReality,
            "/api/v2/import/reconcile",
            5,
            4,
        );
        let wrong_state = transition_to_blocked_from_repeated_controlled_reality_depth_limit(
            PolicyState::RateLimited,
            "/api/v2/import/reconcile",
            6,
            4,
        );

        assert_eq!(first_over_limit, None);
        assert_eq!(wrong_state, None);
    }

    #[test]
    fn repeated_reality_escape_attempt_promotes_to_blocked() {
        let Some(transition) = transition_to_blocked_from_repeated_reality_escape_attempt(
            PolicyState::ControlledReality,
            "/api/v1/projects",
            2,
        ) else {
            panic!("second reality escape attempt should transition to blocked");
        };

        assert_eq!(transition.from, PolicyState::ControlledReality);
        assert_eq!(transition.to, PolicyState::Blocked);
        assert!(transition
            .reason
            .contains(REPEATED_REALITY_ESCAPE_BLOCKED_REASON_PREFIX));
        assert!(transition.reason.contains("path=/api/v1/projects"));
        assert!(transition.reason.contains("attempt_count=2"));
        assert_eq!(
            transition.persistence.post_containment_persistence_kind,
            Some(PostContainmentPersistenceKind::ControlledRealityBranchEscape)
        );
    }

    #[test]
    fn repeated_reality_escape_attempt_requires_controlled_state_and_repetition() {
        let first_attempt = transition_to_blocked_from_repeated_reality_escape_attempt(
            PolicyState::ControlledReality,
            "/api/v1/projects",
            1,
        );
        let wrong_state = transition_to_blocked_from_repeated_reality_escape_attempt(
            PolicyState::Suspicious,
            "/api/v1/projects",
            2,
        );

        assert_eq!(first_attempt, None);
        assert_eq!(wrong_state, None);
    }

    #[test]
    fn correlated_bait_action_does_not_transition_terminal_or_already_controlled_states() {
        for state in [
            PolicyState::Normal,
            PolicyState::ControlledReality,
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

        let event = policy_changed_event(session_id, RequestId::new(), &transition);

        assert_eq!(event.session_id, session_id);
        assert_eq!(event.source, EventSource::PolicyRouter);
        assert_eq!(event.policy_state, PolicyState::ControlledReality);
        assert!(matches!(
            event.kind,
            EventKind::PolicyChanged {
                from: PolicyState::Observe,
                to: PolicyState::ControlledReality,
                ref reason,
                ..
            } if reason == &transition.reason
        ));
    }

    #[test]
    fn policy_intervention_event_uses_specific_core_event_kind() {
        let session_id = SessionId::new();
        let decision = decide_for_state(PolicyState::RateLimited, InterventionMode::Enabled);

        let event = policy_intervention_event(session_id, RequestId::new(), &decision);

        assert_eq!(event.session_id, session_id);
        assert_eq!(event.source, EventSource::PolicyRouter);
        assert_eq!(event.policy_state, PolicyState::RateLimited);
        assert!(matches!(
            event.kind,
            EventKind::RateLimitApplied { ref reason, .. }
                if reason == &decision.reason
        ));
    }

    #[test]
    fn policy_intervention_event_audits_noop_without_fake_state_change() {
        let session_id = SessionId::new();
        let decision = decide_for_state(PolicyState::ControlledReality, InterventionMode::Disabled);

        let event = policy_intervention_event(session_id, RequestId::new(), &decision);

        assert_eq!(event.session_id, session_id);
        assert_eq!(event.source, EventSource::PolicyRouter);
        assert_eq!(event.policy_state, PolicyState::ControlledReality);
        assert!(matches!(
            event.kind,
            EventKind::PolicyDecision {
                routing_decision: RoutingDecision::ProtectedUpstream,
                ref reason,
                ..
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

        let event = response_audit_event(session_id, RequestId::new(), &decision, 203);

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
