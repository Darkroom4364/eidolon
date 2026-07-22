use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const EVENT_SCHEMA_VERSION: u16 = 2;
pub const TRUSTED_INGRESS_CONTRACT_VERSION: &str = "2026-06-05.v1";
pub const PRE_CONTAINMENT_PERSISTENCE_REASON_FAMILY: &str = "pre_containment_persistence";
pub const POST_CONTAINMENT_PERSISTENCE_REASON_FAMILY: &str = "post_containment_persistence";
pub const PRE_CONTAINMENT_PERSISTENCE_CLASS_FIELD: &str = "persistence_class";
pub const PRE_CONTAINMENT_PERSISTENCE_KIND_FIELD: &str = "persistence_kind";
pub const POST_CONTAINMENT_PERSISTENCE_KIND_FIELD: &str = "post_containment_persistence_kind";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub Uuid);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

/// Opaque identifier of one request handled by the proxy.
///
/// Random v4 UUID: it encodes no secrets, client identity, or request data.
/// Every event derived from a request carries this id so reducers can join
/// policy, bait-action, routing, rejection, and response decisions to the
/// exact request that caused them (engineering operating policy invariant 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestId(pub Uuid);

impl RequestId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BaitId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExposureId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceKind {
    Docs,
    OpenApi,
    Route,
    Header,
    Token,
    Hostname,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaitClass {
    #[default]
    Docs,
    OpenApi,
    HiddenRoute,
    FakeCredentialToken,
    JsDiscoveredRoute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderValueMintKind {
    SessionHmacSha256V1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderValueMint {
    pub kind: HeaderValueMintKind,
    pub prefix: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_window_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaitHeaderValueMintAudit {
    pub header_name: String,
    pub kind: HeaderValueMintKind,
    pub prefix: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaitHeaderValueMintStatus {
    MatchedSessionValue,
    ExpiredSessionValue,
    ReplaySeen,
    SessionValueMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedAction {
    pub method: String,
    pub path: String,
    pub header_name: Option<String>,
    pub header_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_value_mint: Option<HeaderValueMint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bait {
    pub id: BaitId,
    #[serde(default)]
    pub bait_class: BaitClass,
    pub surface: String,
    pub surface_kind: SurfaceKind,
    pub expected_action: ExpectedAction,
}

impl Bait {
    pub fn header_value_mint_audit(&self) -> Option<BaitHeaderValueMintAudit> {
        let mint = self.expected_action.header_value_mint.as_ref()?;
        let header_name = self.expected_action.header_name.clone()?;
        Some(BaitHeaderValueMintAudit {
            header_name,
            kind: mint.kind,
            prefix: mint.prefix.clone(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    Proxy,
    SurfaceController,
    BaitEngine,
    TraceEngine,
    PolicyRouter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingDecision {
    ProtectedUpstream,
    EidolonOwned,
    RewrittenUpstream,
    ControlledReality,
    RateLimited,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeHeaderObservation {
    pub name: String,
    pub present: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngressIdentitySource {
    #[default]
    None,
    InternalScanner,
    LocalAllowlist,
    VerifiedBot,
    SignedAgent,
    PartnerAutomation,
    OperatorOverride,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngressTrustTier {
    #[default]
    None,
    WeaklyAsserted,
    Allowlisted,
    EdgeVerified,
    SignedAttested,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalIngressTrustScopeRejectionReason {
    Expired,
    NotYetActive,
    MethodMismatch,
    PathMismatch,
    RequiredHeaderMissing,
    RequiredHeaderValueMismatch,
    RequestUserAgentMissing,
    UserAgentMismatch,
    RequestHostMissing,
    HostMismatch,
    ClientPeerMissing,
    SourceCidrMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticatedIngressRuleRejectionReason {
    NoMatchingRule,
    Expired,
    NotYetActive,
    LabelMissing,
    LabelMismatch,
    VerifiedCategoryMissing,
    VerifiedCategoryMismatch,
    MethodMismatch,
    PathMismatch,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressIdentity {
    pub source: IngressIdentitySource,
    pub trust_tier: IngressTrustTier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalIngressTrustScopeRejection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub source: IngressIdentitySource,
    pub trust_tier: IngressTrustTier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_prefixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bait_soften_path_prefixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user_agent_substrings: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_cidrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_header_names: Vec<String>,
    pub reason: LocalIngressTrustScopeRejectionReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedIngressRuleRejection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub source: IngressIdentitySource,
    pub trust_tier: IngressTrustTier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_prefixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bait_soften_path_prefixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified_categories: Vec<String>,
    pub reason: AuthenticatedIngressRuleRejectionReason,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngressVerificationStrength {
    #[default]
    None,
    Low,
    Medium,
    High,
    Cryptographic,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngressActorKind {
    #[default]
    Unknown,
    Crawler,
    Assistant,
    AutonomousAgent,
    AgenticBrowser,
    PartnerAutomation,
    InternalScanner,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressAdvisorySignals {
    #[serde(default, skip_serializing_if = "is_default")]
    pub verification_strength: IngressVerificationStrength,
    #[serde(default, skip_serializing_if = "is_default")]
    pub actor_kind: IngressActorKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_score: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_score_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_score_scale: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detection_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edge_action: Option<EdgeRecommendedAction>,
}

impl IngressAdvisorySignals {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryReconScore {
    #[serde(default, skip_serializing_if = "is_default")]
    pub repeated_discovery_score: u8,
    #[serde(default, skip_serializing_if = "is_default")]
    pub query_score: u8,
    #[serde(default, skip_serializing_if = "is_default")]
    pub legacy_openapi_query_score: u8,
    #[serde(default, skip_serializing_if = "is_default")]
    pub linked_bait_surface_score: u8,
    #[serde(default, skip_serializing_if = "is_default")]
    pub linked_bait_class_fanout_bonus: u8,
    #[serde(default, skip_serializing_if = "is_default")]
    pub decoy_write_probe_score: u8,
    #[serde(default, skip_serializing_if = "is_default")]
    pub decoy_write_probe_path_fanout_bonus: u8,
    #[serde(default, skip_serializing_if = "is_default")]
    pub detection_score: u8,
    #[serde(default, skip_serializing_if = "is_default")]
    pub total: u8,
    #[serde(default, skip_serializing_if = "is_default")]
    pub threshold: u8,
}

impl DiscoveryReconScore {
    pub fn is_empty(&self) -> bool {
        self.repeated_discovery_score == 0
            && self.query_score == 0
            && self.legacy_openapi_query_score == 0
            && self.linked_bait_surface_score == 0
            && self.linked_bait_class_fanout_bonus == 0
            && self.decoy_write_probe_score == 0
            && self.decoy_write_probe_path_fanout_bonus == 0
            && self.detection_score == 0
            && self.total == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreContainmentPersistenceClass {
    DiscoveryRecon,
    WriteRecon,
    SameBaitNearMiss,
}

impl PreContainmentPersistenceClass {
    pub const fn code(self) -> &'static str {
        match self {
            Self::DiscoveryRecon => "discovery_recon",
            Self::WriteRecon => "write_recon",
            Self::SameBaitNearMiss => "same_bait_near_miss",
        }
    }

    pub const fn marker(self) -> &'static str {
        match self {
            Self::DiscoveryRecon => "persistence_class=discovery_recon",
            Self::WriteRecon => "persistence_class=write_recon",
            Self::SameBaitNearMiss => "persistence_class=same_bait_near_miss",
        }
    }

    pub const fn blocked_kind(self) -> PreContainmentPersistenceKind {
        match self {
            Self::DiscoveryRecon => PreContainmentPersistenceKind::DiscoveryReconRetry,
            Self::WriteRecon => PreContainmentPersistenceKind::WriteReconRetry,
            Self::SameBaitNearMiss => PreContainmentPersistenceKind::SameBaitNearMissRetry,
        }
    }

    pub fn from_explicit_reason_marker(reason: &str) -> Option<Self> {
        reason
            .split_ascii_whitespace()
            .find_map(|field| field.strip_prefix("persistence_class="))
            .and_then(Self::from_code)
    }

    pub fn from_reason(reason: &str) -> Option<Self> {
        if let Some(class) = Self::from_explicit_reason_marker(reason) {
            return Some(class);
        }

        if reason
            .contains("suspicious same-bait near miss after exposure moved session to rate limited")
            || reason.contains("rate-limited same-bait near miss retry moved session to blocked")
        {
            return Some(Self::SameBaitNearMiss);
        }

        if let Some(kind) = PreContainmentPersistenceKind::from_reason(reason) {
            return Some(match kind {
                PreContainmentPersistenceKind::DiscoveryReconRetry => Self::DiscoveryRecon,
                PreContainmentPersistenceKind::WriteReconRetry => Self::WriteRecon,
                PreContainmentPersistenceKind::SameBaitNearMissRetry => Self::SameBaitNearMiss,
            });
        }

        None
    }

    fn from_code(code: &str) -> Option<Self> {
        match code {
            "discovery_recon" => Some(Self::DiscoveryRecon),
            "write_recon" => Some(Self::WriteRecon),
            "same_bait_near_miss" => Some(Self::SameBaitNearMiss),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreContainmentPersistenceKind {
    DiscoveryReconRetry,
    WriteReconRetry,
    SameBaitNearMissRetry,
}

impl PreContainmentPersistenceKind {
    pub const fn detail_code(self) -> &'static str {
        match self {
            Self::DiscoveryReconRetry => "discovery_recon_retry",
            Self::WriteReconRetry => "write_recon_retry",
            Self::SameBaitNearMissRetry => "same_bait_near_miss_retry",
        }
    }

    pub const fn marker(self) -> &'static str {
        match self {
            Self::DiscoveryReconRetry => "persistence_kind=discovery_recon_retry",
            Self::WriteReconRetry => "persistence_kind=write_recon_retry",
            Self::SameBaitNearMissRetry => "persistence_kind=same_bait_near_miss_retry",
        }
    }

    pub fn from_explicit_reason_marker(reason: &str) -> Option<Self> {
        if let Some(detail_code) = reason
            .split_ascii_whitespace()
            .find_map(|field| field.strip_prefix("persistence_kind="))
        {
            return Self::from_detail_code(detail_code);
        }
        PreContainmentPersistenceClass::from_explicit_reason_marker(reason)
            .map(PreContainmentPersistenceClass::blocked_kind)
    }

    pub fn from_reason(reason: &str) -> Option<Self> {
        if let Some(kind) = Self::from_explicit_reason_marker(reason) {
            return Some(kind);
        }

        if reason.contains("rate-limited same-bait near miss retry moved session to blocked") {
            return Some(Self::SameBaitNearMissRetry);
        }

        if reason.contains("rate-limited discovery recon retry moved session to blocked") {
            if reason.contains("repeated_discovery_score=0")
                && reason.contains("decoy_write_probe_path_fanout_bonus=1")
            {
                return Some(Self::WriteReconRetry);
            }
            return Some(Self::DiscoveryReconRetry);
        }

        None
    }

    fn from_detail_code(detail_code: &str) -> Option<Self> {
        match detail_code {
            "discovery_recon_retry" => Some(Self::DiscoveryReconRetry),
            "write_recon_retry" => Some(Self::WriteReconRetry),
            "same_bait_near_miss_retry" => Some(Self::SameBaitNearMissRetry),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostContainmentPersistenceKind {
    ControlledRealityBranchEscape,
    ControlledRealityDepthLimit,
}

impl PostContainmentPersistenceKind {
    pub const fn detail_code(self) -> &'static str {
        match self {
            Self::ControlledRealityBranchEscape => "controlled_reality_branch_escape",
            Self::ControlledRealityDepthLimit => "controlled_reality_depth_limit",
        }
    }

    pub const fn marker(self) -> &'static str {
        match self {
            Self::ControlledRealityBranchEscape => {
                "post_containment_persistence_kind=controlled_reality_branch_escape"
            }
            Self::ControlledRealityDepthLimit => {
                "post_containment_persistence_kind=controlled_reality_depth_limit"
            }
        }
    }

    pub fn from_explicit_reason_marker(reason: &str) -> Option<Self> {
        reason
            .split_ascii_whitespace()
            .find_map(|field| field.strip_prefix("post_containment_persistence_kind="))
            .and_then(Self::from_detail_code)
    }

    pub fn from_reason(reason: &str) -> Option<Self> {
        if let Some(kind) = Self::from_explicit_reason_marker(reason) {
            return Some(kind);
        }

        if reason.contains(
            "controlled session repeatedly probed outside the controlled-reality branch and moved session to blocked",
        ) {
            return Some(Self::ControlledRealityBranchEscape);
        }

        if reason.contains(
            "controlled-reality probe continued after depth-limit throttle and moved session to blocked",
        ) {
            return Some(Self::ControlledRealityDepthLimit);
        }

        None
    }

    fn from_detail_code(detail_code: &str) -> Option<Self> {
        match detail_code {
            "controlled_reality_branch_escape" => Some(Self::ControlledRealityBranchEscape),
            "controlled_reality_depth_limit" => Some(Self::ControlledRealityDepthLimit),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyPersistenceMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_containment_persistence_class: Option<PreContainmentPersistenceClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_containment_persistence_kind: Option<PreContainmentPersistenceKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_containment_persistence_kind: Option<PostContainmentPersistenceKind>,
}

impl PolicyPersistenceMetadata {
    pub fn is_empty(&self) -> bool {
        self.pre_containment_persistence_class.is_none()
            && self.pre_containment_persistence_kind.is_none()
            && self.post_containment_persistence_kind.is_none()
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    RequestSeen {
        method: String,
        path: String,
        safe_headers: Vec<SafeHeaderObservation>,
        #[serde(default)]
        ingress_identity: IngressIdentity,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        authenticated_ingress_rule_rejection: Option<AuthenticatedIngressRuleRejection>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        local_ingress_trust_scope_rejection: Option<LocalIngressTrustScopeRejection>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trusted_ingress_soften_match: Option<TrustedIngressSoftenMatch>,
        #[serde(default, skip_serializing_if = "IngressAdvisorySignals::is_empty")]
        ingress_signals: IngressAdvisorySignals,
        #[serde(default, skip_serializing_if = "DiscoveryReconScore::is_empty")]
        discovery_recon_score: DiscoveryReconScore,
        routing_decision: RoutingDecision,
    },
    ResponseServed {
        status: u16,
        routing_decision: RoutingDecision,
    },
    BaitExposed {
        bait_id: BaitId,
        exposure_id: ExposureId,
        surface: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        header_value_mint: Option<BaitHeaderValueMintAudit>,
    },
    BaitActionObserved {
        bait_id: BaitId,
        exposure_id: Option<ExposureId>,
        method: String,
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        header_value_mint: Option<BaitHeaderValueMintAudit>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        header_value_mint_status: Option<BaitHeaderValueMintStatus>,
    },
    PolicyChanged {
        from: PolicyState,
        to: PolicyState,
        reason: String,
        #[serde(default, skip_serializing_if = "PolicyPersistenceMetadata::is_empty")]
        persistence: PolicyPersistenceMetadata,
    },
    PolicyDecision {
        routing_decision: RoutingDecision,
        reason: String,
        #[serde(default, skip_serializing_if = "PolicyPersistenceMetadata::is_empty")]
        persistence: PolicyPersistenceMetadata,
    },
    ControlledRealityEntered {
        reason: String,
        #[serde(default, skip_serializing_if = "PolicyPersistenceMetadata::is_empty")]
        persistence: PolicyPersistenceMetadata,
    },
    RateLimitApplied {
        reason: String,
        #[serde(default, skip_serializing_if = "PolicyPersistenceMetadata::is_empty")]
        persistence: PolicyPersistenceMetadata,
    },
    RealityEscapeAttempt {
        method: String,
        path: String,
        routing_decision: RoutingDecision,
        reason: String,
        #[serde(default, skip_serializing_if = "PolicyPersistenceMetadata::is_empty")]
        persistence: PolicyPersistenceMetadata,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub schema_version: u16,
    pub id: Uuid,
    pub session_id: SessionId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
    pub observed_at: DateTime<Utc>,
    pub source: EventSource,
    pub policy_state: PolicyState,
    pub kind: EventKind,
}

impl Event {
    pub fn new(
        session_id: SessionId,
        source: EventSource,
        policy_state: PolicyState,
        kind: EventKind,
    ) -> Self {
        Self {
            schema_version: EVENT_SCHEMA_VERSION,
            id: Uuid::new_v4(),
            session_id,
            request_id: None,
            observed_at: Utc::now(),
            source,
            policy_state,
            kind,
        }
    }

    /// Attach the opaque id of the request this event was derived from.
    pub fn with_request_id(mut self, request_id: RequestId) -> Self {
        self.request_id = Some(request_id);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyState {
    Normal,
    Observe,
    Suspicious,
    ControlledReality,
    RateLimited,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceBand {
    Low,
    Medium,
    High,
    ConfirmedBaitDerivedChain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Score {
    pub points: i32,
    pub confidence: ConfidenceBand,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeRecommendedAction {
    Allow,
    Observe,
    RateLimit,
    Challenge,
    Block,
    PreserveEidolonRouting,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeRequestRef {
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
}

/// Whether an edge export was assembled from events linked by explicit
/// request identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EdgeRequestLinkage {
    /// All contributing events share the exported request's explicit id.
    Linked,
    /// The underlying events predate request identifiers, so no causal join
    /// was possible; no heuristic cross-event join was attempted.
    #[default]
    UnknownLegacy,
}

impl EdgeRequestLinkage {
    pub fn unknown_legacy() -> Self {
        Self::UnknownLegacy
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgePolicySnapshot {
    pub state: PolicyState,
    pub routing_decision: RoutingDecision,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_containment_persistence_class: Option<PreContainmentPersistenceClass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_containment_persistence_kind: Option<PreContainmentPersistenceKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_containment_persistence_kind: Option<PostContainmentPersistenceKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeEvidenceRef {
    pub event_schema_version: u16,
    pub event_ids: Vec<Uuid>,
    pub bundle_ref: String,
    #[serde(default = "EdgeRequestLinkage::unknown_legacy")]
    pub request_linkage: EdgeRequestLinkage,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authenticated_ingress_rule_rejection_histories:
        Vec<EdgeAuthenticatedIngressRuleRejectionHistory>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_ingress_trust_scope_rejection_histories:
        Vec<EdgeLocalIngressTrustScopeRejectionHistory>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_ingress_soften_histories: Vec<EdgeTrustedIngressSoftenHistory>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bait_header_value_mints: Vec<EdgeBaitHeaderValueMintAudit>,
    #[serde(
        default,
        skip_serializing_if = "EdgeBaitHeaderValueMintOutcomeSummary::is_empty"
    )]
    pub bait_header_value_mint_outcome_summary: EdgeBaitHeaderValueMintOutcomeSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_bait_header_value_mint: Option<EdgeObservedBaitHeaderValueMint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeBaitHeaderValueMintAudit {
    pub bait_id: BaitId,
    pub header_name: String,
    pub kind: HeaderValueMintKind,
    pub prefix: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeObservedBaitHeaderValueMint {
    pub bait_id: BaitId,
    pub header_name: String,
    pub kind: HeaderValueMintKind,
    pub prefix: String,
    pub status: BaitHeaderValueMintStatus,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeBaitHeaderValueMintOutcomeSummary {
    #[serde(default, skip_serializing_if = "is_zero")]
    pub matched_session_value: u16,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub expired_session_value: u16,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub replay_seen: u16,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub session_value_mismatch: u16,
}

impl EdgeBaitHeaderValueMintOutcomeSummary {
    pub fn is_empty(&self) -> bool {
        self.matched_session_value == 0
            && self.expired_session_value == 0
            && self.replay_seen == 0
            && self.session_value_mismatch == 0
    }
}

fn is_zero(value: &u16) -> bool {
    *value == 0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeActivePolymorphicBait {
    pub bait_id: BaitId,
    pub surface: String,
    pub surface_kind: SurfaceKind,
    pub header_name: String,
    pub kind: HeaderValueMintKind,
    pub prefix: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgePolymorphicBaitCoverage {
    pub active_bait_count: u16,
    pub observed_bait_count: u16,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_bait_ids: Vec<BaitId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unobserved_bait_ids: Vec<BaitId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeTrustedIngressSoftenScope {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub source: IngressIdentitySource,
    pub trust_tier: IngressTrustTier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_prefixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bait_soften_path_prefixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user_agent_substrings: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_cidrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_header_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified_categories: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedIngressSoftenMatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub source: IngressIdentitySource,
    pub trust_tier: IngressTrustTier,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_prefixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bait_soften_path_prefixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user_agent_substrings: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_cidrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_header_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified_categories: Vec<String>,
    pub request_path_softened: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeTrustedIngressSoftenHistory {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub source: IngressIdentitySource,
    pub trust_tier: IngressTrustTier,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_prefixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bait_soften_path_prefixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user_agent_substrings: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_cidrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_header_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified_categories: Vec<String>,
    pub saw_request_path_softened: bool,
    pub saw_request_path_unsoftened: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeAuthenticatedIngressRuleRejectionHistory {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub source: IngressIdentitySource,
    pub trust_tier: IngressTrustTier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_prefixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bait_soften_path_prefixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified_categories: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<AuthenticatedIngressRuleRejectionReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeAuthenticatedTrustedIngressRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub source: IngressIdentitySource,
    pub trust_tier: IngressTrustTier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_prefixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bait_soften_path_prefixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified_categories: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeLocalIngressTrustScopeRejectionHistory {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub source: IngressIdentitySource,
    pub trust_tier: IngressTrustTier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_prefixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bait_soften_path_prefixes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user_agent_substrings: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_cidrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_header_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<LocalIngressTrustScopeRejectionReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeDeploymentContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bait_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub polymorphic_baits: Vec<EdgeActivePolymorphicBait>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub polymorphic_bait_coverage: Option<EdgePolymorphicBaitCoverage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authenticated_trusted_ingress_rules: Vec<EdgeAuthenticatedTrustedIngressRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_ingress_soften_scopes: Vec<EdgeTrustedIngressSoftenScope>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeRecommendation {
    pub action: EdgeRecommendedAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EidolonEdgeDecisionExport {
    pub contract_version: String,
    pub observed_at: DateTime<Utc>,
    pub session_id: SessionId,
    pub request: EdgeRequestRef,
    pub ingress_identity: IngressIdentity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticated_ingress_rule_rejection: Option<AuthenticatedIngressRuleRejection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_ingress_trust_scope_rejection: Option<LocalIngressTrustScopeRejection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_ingress_soften_match: Option<TrustedIngressSoftenMatch>,
    #[serde(default, skip_serializing_if = "IngressAdvisorySignals::is_empty")]
    pub ingress_signals: IngressAdvisorySignals,
    #[serde(default, skip_serializing_if = "DiscoveryReconScore::is_empty")]
    pub discovery_recon_score: DiscoveryReconScore,
    pub policy: EdgePolicySnapshot,
    pub evidence: EdgeEvidenceRef,
    pub edge_recommendation: EdgeRecommendation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_context: Option<EdgeDeploymentContext>,
}

fn is_default<T>(value: &T) -> bool
where
    T: Default + PartialEq,
{
    value == &T::default()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn must_ok<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{context}: {error}"),
        }
    }

    #[test]
    fn event_schema_version_is_the_m2_5_contract_version() {
        assert_eq!(EVENT_SCHEMA_VERSION, 2);
    }

    #[test]
    fn event_without_request_id_parses_as_legacy_and_roundtrips_with_id() {
        let legacy = json!({
            "schema_version": 2,
            "id": Uuid::new_v4(),
            "session_id": SessionId::new(),
            "observed_at": Utc::now(),
            "source": "proxy",
            "policy_state": "observe",
            "kind": {
                "type": "bait_action_observed",
                "bait_id": "bait-1",
                "exposure_id": null,
                "method": "POST",
                "path": "/api/v2/import/reconcile",
                "header_value_mint": null,
                "header_value_mint_status": null
            }
        });

        let event: Event = must_ok(
            serde_json::from_value(legacy),
            "legacy event without request_id should parse",
        );
        assert_eq!(event.request_id, None);

        let linked = event.with_request_id(RequestId::new());
        assert!(linked.request_id.is_some());
        let serialized = must_ok(
            serde_json::to_value(linked),
            "linked event should serialize",
        );
        let reparsed: Event = must_ok(
            serde_json::from_value(serialized.clone()),
            "linked event should reparse",
        );
        assert_eq!(reparsed.request_id, linked_request_id(&serialized));
    }

    fn linked_request_id(value: &serde_json::Value) -> Option<RequestId> {
        value
            .get("request_id")
            .and_then(|raw| serde_json::from_value(raw.clone()).ok())
    }

    #[test]
    fn edge_request_linkage_defaults_to_unknown_legacy() {
        assert_eq!(
            EdgeRequestLinkage::default(),
            EdgeRequestLinkage::UnknownLegacy
        );
        assert_eq!(
            EdgeRequestLinkage::unknown_legacy(),
            EdgeRequestLinkage::UnknownLegacy
        );
    }

    #[test]
    fn new_event_carries_contract_metadata() {
        let session_id = SessionId::new();
        let event = Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::Observe,
            EventKind::RequestSeen {
                method: "GET".to_string(),
                path: "/openapi.json".to_string(),
                safe_headers: vec![SafeHeaderObservation {
                    name: "user-agent".to_string(),
                    present: true,
                }],
                ingress_identity: IngressIdentity::default(),
                authenticated_ingress_rule_rejection: None,
                local_ingress_trust_scope_rejection: None,
                trusted_ingress_soften_match: None,
                ingress_signals: IngressAdvisorySignals::default(),
                discovery_recon_score: DiscoveryReconScore::default(),
                routing_decision: RoutingDecision::ProtectedUpstream,
            },
        );

        assert_eq!(event.schema_version, EVENT_SCHEMA_VERSION);
        assert_eq!(event.session_id, session_id);
        assert_eq!(event.source, EventSource::Proxy);
        assert_eq!(event.policy_state, PolicyState::Observe);
    }

    #[test]
    fn event_serializes_stable_snake_case_contract() {
        let session_id = SessionId::new();
        let event = Event::new(
            session_id,
            EventSource::PolicyRouter,
            PolicyState::Suspicious,
            EventKind::PolicyChanged {
                from: PolicyState::Observe,
                to: PolicyState::Suspicious,
                reason: "bait action matched expected header and path".to_string(),
                persistence: PolicyPersistenceMetadata::default(),
            },
        );

        let serialized = must_ok(serde_json::to_value(event), "event should serialize");

        assert_eq!(serialized["schema_version"], json!(EVENT_SCHEMA_VERSION));
        assert_eq!(serialized["source"], json!("policy_router"));
        assert_eq!(serialized["policy_state"], json!("suspicious"));
        assert_eq!(serialized["kind"]["type"], json!("policy_changed"));
        assert_eq!(serialized["kind"]["from"], json!("observe"));
        assert_eq!(serialized["kind"]["to"], json!("suspicious"));
    }

    #[test]
    fn request_seen_event_serializes_ingress_identity_fields() {
        let session_id = SessionId::new();
        let event = Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::Observe,
            EventKind::RequestSeen {
                method: "GET".to_string(),
                path: "/openapi.json".to_string(),
                safe_headers: vec![SafeHeaderObservation {
                    name: "user-agent".to_string(),
                    present: true,
                }],
                ingress_identity: IngressIdentity {
                    source: IngressIdentitySource::VerifiedBot,
                    trust_tier: IngressTrustTier::EdgeVerified,
                    label: Some("googlebot".to_string()),
                    not_before: None,
                    expires_at: None,
                },
                authenticated_ingress_rule_rejection: None,
                local_ingress_trust_scope_rejection: Some(LocalIngressTrustScopeRejection {
                    label: Some("docs-crawler".to_string()),
                    source: IngressIdentitySource::LocalAllowlist,
                    trust_tier: IngressTrustTier::Allowlisted,
                    not_before: None,
                    expires_at: None,
                    methods: vec!["GET".to_string()],
                    path_prefixes: vec!["/docs".to_string(), "/openapi.json".to_string()],
                    bait_soften_path_prefixes: vec!["/docs".to_string()],
                    user_agent_substrings: vec!["eidolon-docs-crawler".to_string()],
                    hosts: vec!["localhost".to_string()],
                    source_cidrs: vec!["127.0.0.1/32".to_string()],
                    required_header_names: vec!["X-Eidolon-Trusted-Actor".to_string()],
                    reason: LocalIngressTrustScopeRejectionReason::HostMismatch,
                }),
                trusted_ingress_soften_match: Some(TrustedIngressSoftenMatch {
                    label: Some("docs-crawler".to_string()),
                    source: IngressIdentitySource::LocalAllowlist,
                    trust_tier: IngressTrustTier::Allowlisted,
                    methods: vec!["GET".to_string()],
                    path_prefixes: vec!["/docs".to_string(), "/openapi.json".to_string()],
                    bait_soften_path_prefixes: vec!["/docs".to_string()],
                    user_agent_substrings: vec!["eidolon-docs-crawler".to_string()],
                    hosts: vec!["127.0.0.1".to_string()],
                    source_cidrs: vec!["127.0.0.1/32".to_string()],
                    required_header_names: vec!["X-Eidolon-Trusted-Actor".to_string()],
                    verified_categories: Vec::new(),
                    request_path_softened: false,
                }),
                ingress_signals: IngressAdvisorySignals {
                    verification_strength: IngressVerificationStrength::High,
                    actor_kind: IngressActorKind::Crawler,
                    verified_category: Some("AI Assistant".to_string()),
                    attestation_ref: None,
                    vendor_score: Some(12),
                    vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                    vendor_score_scale: Some("1-99".to_string()),
                    detection_ids: vec!["3355446".to_string()],
                    edge_action: Some(EdgeRecommendedAction::Allow),
                },
                discovery_recon_score: DiscoveryReconScore {
                    repeated_discovery_score: 2,
                    query_score: 1,
                    total: 3,
                    threshold: 3,
                    ..DiscoveryReconScore::default()
                },
                routing_decision: RoutingDecision::ProtectedUpstream,
            },
        );

        let serialized = must_ok(serde_json::to_value(event), "event should serialize");

        assert_eq!(
            serialized["kind"]["ingress_identity"]["source"],
            "verified_bot"
        );
        assert_eq!(
            serialized["kind"]["ingress_identity"]["trust_tier"],
            "edge_verified"
        );
        assert_eq!(serialized["kind"]["ingress_identity"]["label"], "googlebot");
        assert_eq!(
            serialized["kind"]["local_ingress_trust_scope_rejection"]["reason"],
            "host_mismatch"
        );
        assert_eq!(
            serialized["kind"]["local_ingress_trust_scope_rejection"]["hosts"][0],
            "localhost"
        );
        assert_eq!(
            serialized["kind"]["local_ingress_trust_scope_rejection"]["methods"][0],
            "GET"
        );
        assert_eq!(
            serialized["kind"]["trusted_ingress_soften_match"]["label"],
            "docs-crawler"
        );
        assert_eq!(
            serialized["kind"]["trusted_ingress_soften_match"]["request_path_softened"],
            false
        );
        assert_eq!(
            serialized["kind"]["ingress_signals"]["verification_strength"],
            "high"
        );
        assert_eq!(
            serialized["kind"]["ingress_signals"]["actor_kind"],
            "crawler"
        );
        assert_eq!(serialized["kind"]["ingress_signals"]["vendor_score"], 12);
        assert_eq!(
            serialized["kind"]["ingress_signals"]["edge_action"],
            "allow"
        );
        assert_eq!(
            serialized["kind"]["discovery_recon_score"]["repeated_discovery_score"],
            2
        );
        assert_eq!(
            serialized["kind"]["discovery_recon_score"]["query_score"],
            1
        );
        assert_eq!(serialized["kind"]["discovery_recon_score"]["total"], 3);
        assert_eq!(serialized["kind"]["discovery_recon_score"]["threshold"], 3);
    }

    #[test]
    fn request_seen_event_deserializes_without_ingress_identity() {
        let session_id = SessionId::new();
        let event = json!({
            "schema_version": EVENT_SCHEMA_VERSION,
            "id": Uuid::new_v4(),
            "session_id": session_id,
            "observed_at": Utc::now(),
            "source": "proxy",
            "policy_state": "observe",
            "kind": {
                "type": "request_seen",
                "method": "GET",
                "path": "/openapi.json",
                "safe_headers": [],
                "routing_decision": "protected_upstream"
            }
        });

        let parsed: Event = must_ok(serde_json::from_value(event), "legacy event should parse");

        match parsed.kind {
            EventKind::RequestSeen {
                ingress_identity, ..
            } => assert_eq!(ingress_identity, IngressIdentity::default()),
            other => panic!("expected request_seen, got {other:?}"),
        }
    }

    #[test]
    fn request_seen_event_deserializes_without_ingress_signals() {
        let session_id = SessionId::new();
        let event = json!({
            "schema_version": EVENT_SCHEMA_VERSION,
            "id": Uuid::new_v4(),
            "session_id": session_id,
            "observed_at": Utc::now(),
            "source": "proxy",
            "policy_state": "observe",
            "kind": {
                "type": "request_seen",
                "method": "GET",
                "path": "/openapi.json",
                "safe_headers": [],
                "ingress_identity": {
                    "source": "verified_bot",
                    "trust_tier": "edge_verified"
                },
                "routing_decision": "protected_upstream"
            }
        });

        let parsed: Event = must_ok(serde_json::from_value(event), "legacy event should parse");

        match parsed.kind {
            EventKind::RequestSeen {
                ingress_signals, ..
            } => assert_eq!(ingress_signals, IngressAdvisorySignals::default()),
            other => panic!("expected request_seen, got {other:?}"),
        }
    }

    #[test]
    fn request_seen_event_deserializes_without_discovery_recon_score() {
        let session_id = SessionId::new();
        let event = json!({
            "schema_version": EVENT_SCHEMA_VERSION,
            "id": Uuid::new_v4(),
            "session_id": session_id,
            "observed_at": Utc::now(),
            "source": "proxy",
            "policy_state": "observe",
            "kind": {
                "type": "request_seen",
                "method": "GET",
                "path": "/openapi.json",
                "safe_headers": [],
                "ingress_identity": {
                    "source": "verified_bot",
                    "trust_tier": "edge_verified"
                },
                "routing_decision": "protected_upstream"
            }
        });

        let parsed: Event = must_ok(serde_json::from_value(event), "legacy event should parse");

        match parsed.kind {
            EventKind::RequestSeen {
                discovery_recon_score,
                ..
            } => assert_eq!(discovery_recon_score, DiscoveryReconScore::default()),
            other => panic!("expected request_seen, got {other:?}"),
        }
    }

    #[test]
    fn pre_containment_persistence_kind_parses_explicit_marker() {
        let reason = "rate-limited discovery recon retry moved session to blocked: path=/docs persistence_kind=discovery_recon_retry";

        assert_eq!(
            PreContainmentPersistenceKind::from_explicit_reason_marker(reason),
            Some(PreContainmentPersistenceKind::DiscoveryReconRetry)
        );
        assert_eq!(
            PreContainmentPersistenceKind::from_reason(reason),
            Some(PreContainmentPersistenceKind::DiscoveryReconRetry)
        );
    }

    #[test]
    fn pre_containment_persistence_kind_preserves_legacy_write_recon_fallback() {
        let reason = "rate-limited discovery recon retry moved session to blocked: path=/api/v2/import/validate repeated_discovery_score=0 decoy_write_probe_path_fanout_bonus=1";

        assert_eq!(
            PreContainmentPersistenceKind::from_reason(reason),
            Some(PreContainmentPersistenceKind::WriteReconRetry)
        );
    }

    #[test]
    fn pre_containment_persistence_kind_can_fall_back_to_class_marker() {
        let reason =
            "suspicious discovery recon persistence moved session to rate limited: path=/docs persistence_class=discovery_recon";

        assert_eq!(
            PreContainmentPersistenceKind::from_explicit_reason_marker(reason),
            Some(PreContainmentPersistenceKind::DiscoveryReconRetry)
        );
        assert_eq!(
            PreContainmentPersistenceKind::from_reason(reason),
            Some(PreContainmentPersistenceKind::DiscoveryReconRetry)
        );
    }

    #[test]
    fn pre_containment_persistence_class_parses_explicit_marker() {
        let reason =
            "suspicious same-bait near miss after exposure moved session to rate limited: path=/api/v2/import/reconcile persistence_class=same_bait_near_miss";

        assert_eq!(
            PreContainmentPersistenceClass::from_explicit_reason_marker(reason),
            Some(PreContainmentPersistenceClass::SameBaitNearMiss)
        );
        assert_eq!(
            PreContainmentPersistenceClass::from_reason(reason),
            Some(PreContainmentPersistenceClass::SameBaitNearMiss)
        );
    }

    #[test]
    fn pre_containment_persistence_class_explicit_marker_does_not_use_legacy_phrase_fallback() {
        let reason = "suspicious same-bait near miss after exposure moved session to rate limited";

        assert_eq!(
            PreContainmentPersistenceClass::from_explicit_reason_marker(reason),
            None
        );
        assert_eq!(
            PreContainmentPersistenceClass::from_reason(reason),
            Some(PreContainmentPersistenceClass::SameBaitNearMiss)
        );
    }

    #[test]
    fn post_containment_persistence_kind_parses_explicit_marker() {
        let reason = "controlled session repeatedly probed outside the controlled-reality branch and moved session to blocked: path=/api/v1/projects post_containment_persistence_kind=controlled_reality_branch_escape";

        assert_eq!(
            PostContainmentPersistenceKind::from_explicit_reason_marker(reason),
            Some(PostContainmentPersistenceKind::ControlledRealityBranchEscape)
        );
        assert_eq!(
            PostContainmentPersistenceKind::from_reason(reason),
            Some(PostContainmentPersistenceKind::ControlledRealityBranchEscape)
        );
    }

    #[test]
    fn post_containment_persistence_kind_explicit_marker_does_not_use_legacy_phrase_fallback() {
        let reason =
            "controlled session repeatedly probed outside the controlled-reality branch and moved session to blocked";

        assert_eq!(
            PostContainmentPersistenceKind::from_explicit_reason_marker(reason),
            None
        );
        assert_eq!(
            PostContainmentPersistenceKind::from_reason(reason),
            Some(PostContainmentPersistenceKind::ControlledRealityBranchEscape)
        );
    }

    #[test]
    fn policy_decision_event_serializes_actual_routing_decision() {
        let session_id = SessionId::new();
        let event = Event::new(
            session_id,
            EventSource::PolicyRouter,
            PolicyState::ControlledReality,
            EventKind::PolicyDecision {
                routing_decision: RoutingDecision::ProtectedUpstream,
                reason: "interventions disabled; forwarding to protected upstream".to_string(),
                persistence: PolicyPersistenceMetadata::default(),
            },
        );

        let serialized = serde_json::to_value(event).expect("event should serialize");

        assert_eq!(serialized["source"], json!("policy_router"));
        assert_eq!(serialized["policy_state"], json!("controlled_reality"));
        assert_eq!(serialized["kind"]["type"], json!("policy_decision"));
        assert_eq!(
            serialized["kind"]["routing_decision"],
            json!("protected_upstream")
        );
        assert_eq!(
            serialized["kind"]["reason"],
            json!("interventions disabled; forwarding to protected upstream")
        );
    }

    #[test]
    fn bait_expected_action_round_trips() {
        let bait = Bait {
            id: BaitId("rel_2025_04_b7f2".to_string()),
            bait_class: BaitClass::Docs,
            surface: "/docs/legacy-import".to_string(),
            surface_kind: SurfaceKind::Docs,
            expected_action: ExpectedAction {
                method: "POST".to_string(),
                path: "/api/v2/import/reconcile".to_string(),
                header_name: Some("X-Migration-Trace".to_string()),
                header_value: Some("rel_2025_04_b7f2".to_string()),
                header_value_mint: None,
            },
        };

        let serialized = serde_json::to_string(&bait).expect("bait should serialize");
        let deserialized: Bait = serde_json::from_str(&serialized).expect("bait should parse");

        assert_eq!(deserialized, bait);
    }

    #[test]
    fn bait_class_defaults_to_docs_for_older_bait_records() {
        let bait: Bait = serde_json::from_value(json!({
            "id": "older-bait",
            "surface": "/docs/older",
            "surface_kind": "docs",
            "expected_action": {
                "method": "POST",
                "path": "/api/v2/import/reconcile",
                "header_name": "X-Migration-Trace",
                "header_value": "older"
            }
        }))
        .expect("older bait record should parse");

        assert_eq!(bait.bait_class, BaitClass::Docs);
    }

    #[test]
    fn bait_exposed_event_deserializes_without_header_value_mint() {
        let session_id = SessionId::new();
        let event = json!({
            "schema_version": EVENT_SCHEMA_VERSION,
            "id": Uuid::new_v4(),
            "session_id": session_id,
            "observed_at": Utc::now(),
            "source": "surface_controller",
            "policy_state": "observe",
            "kind": {
                "type": "bait_exposed",
                "bait_id": "older-bait",
                "exposure_id": "exp-older",
                "surface": "/docs/older"
            }
        });

        let parsed: Event = must_ok(
            serde_json::from_value(event),
            "legacy bait event should parse",
        );

        match parsed.kind {
            EventKind::BaitExposed {
                header_value_mint, ..
            } => assert_eq!(header_value_mint, None),
            other => panic!("expected bait_exposed, got {other:?}"),
        }
    }

    #[test]
    fn bait_action_event_serializes_header_value_mint_without_header_value() {
        let session_id = SessionId::new();
        let event = Event::new(
            session_id,
            EventSource::BaitEngine,
            PolicyState::Observe,
            EventKind::BaitActionObserved {
                bait_id: BaitId("minted-trace".to_string()),
                exposure_id: Some(ExposureId("exp-minted".to_string())),
                method: "POST".to_string(),
                path: "/api/v2/import/reconcile".to_string(),
                header_value_mint: Some(BaitHeaderValueMintAudit {
                    header_name: "X-Minted-Trace".to_string(),
                    kind: HeaderValueMintKind::SessionHmacSha256V1,
                    prefix: "minted".to_string(),
                }),
                header_value_mint_status: Some(BaitHeaderValueMintStatus::MatchedSessionValue),
            },
        );

        let serialized = must_ok(serde_json::to_value(event), "minted event should serialize");

        assert_eq!(
            serialized["kind"]["header_value_mint"]["header_name"],
            json!("X-Minted-Trace")
        );
        assert_eq!(
            serialized["kind"]["header_value_mint"]["kind"],
            json!("session_hmac_sha256_v1")
        );
        assert_eq!(
            serialized["kind"]["header_value_mint"]["prefix"],
            json!("minted")
        );
        assert_eq!(
            serialized["kind"]["header_value_mint_status"],
            json!("matched_session_value")
        );
    }

    #[test]
    fn edge_decision_export_serializes_stable_snake_case_contract() {
        let session_id = SessionId::new();
        let export = EidolonEdgeDecisionExport {
            contract_version: TRUSTED_INGRESS_CONTRACT_VERSION.to_string(),
            observed_at: Utc::now(),
            session_id,
            request: EdgeRequestRef {
                method: "GET".to_string(),
                path: "/openapi.json".to_string(),
                request_id: None,
            },
            ingress_identity: IngressIdentity {
                source: IngressIdentitySource::VerifiedBot,
                trust_tier: IngressTrustTier::EdgeVerified,
                label: Some("googlebot".to_string()),
                not_before: None,
                expires_at: None,
            },
            authenticated_ingress_rule_rejection: None,
            local_ingress_trust_scope_rejection: Some(LocalIngressTrustScopeRejection {
                label: Some("docs-crawler".to_string()),
                source: IngressIdentitySource::LocalAllowlist,
                trust_tier: IngressTrustTier::Allowlisted,
                not_before: None,
                expires_at: None,
                methods: vec!["GET".to_string()],
                path_prefixes: vec!["/docs".to_string(), "/openapi.json".to_string()],
                bait_soften_path_prefixes: vec!["/docs".to_string()],
                user_agent_substrings: vec!["eidolon-docs-crawler".to_string()],
                hosts: vec!["localhost".to_string()],
                source_cidrs: vec!["127.0.0.1/32".to_string()],
                required_header_names: vec!["X-Eidolon-Trusted-Actor".to_string()],
                reason: LocalIngressTrustScopeRejectionReason::HostMismatch,
            }),
            trusted_ingress_soften_match: Some(TrustedIngressSoftenMatch {
                label: Some("docs-crawler".to_string()),
                source: IngressIdentitySource::LocalAllowlist,
                trust_tier: IngressTrustTier::Allowlisted,
                methods: vec!["GET".to_string()],
                path_prefixes: vec!["/docs".to_string(), "/openapi.json".to_string()],
                bait_soften_path_prefixes: vec!["/docs".to_string()],
                user_agent_substrings: vec!["eidolon-docs-crawler".to_string()],
                hosts: vec!["127.0.0.1".to_string()],
                source_cidrs: vec!["127.0.0.1/32".to_string()],
                required_header_names: vec!["X-Eidolon-Trusted-Actor".to_string()],
                verified_categories: Vec::new(),
                request_path_softened: false,
            }),
            ingress_signals: IngressAdvisorySignals {
                verification_strength: IngressVerificationStrength::High,
                actor_kind: IngressActorKind::Crawler,
                verified_category: Some("Search Engine".to_string()),
                attestation_ref: None,
                vendor_score: Some(12),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                vendor_score_scale: Some("1-99".to_string()),
                detection_ids: vec!["3355446".to_string()],
                edge_action: Some(EdgeRecommendedAction::Allow),
            },
            discovery_recon_score: DiscoveryReconScore {
                detection_score: 2,
                query_score: 1,
                total: 3,
                threshold: 3,
                ..DiscoveryReconScore::default()
            },
            policy: EdgePolicySnapshot {
                state: PolicyState::Observe,
                routing_decision: RoutingDecision::ProtectedUpstream,
                reason: "trusted ingress identity suppressed bait surface intervention before runtime suspicion was established".to_string(),
                pre_containment_persistence_class: Some(
                    PreContainmentPersistenceClass::DiscoveryRecon,
                ),
                pre_containment_persistence_kind: Some(
                    PreContainmentPersistenceKind::DiscoveryReconRetry,
                ),
                post_containment_persistence_kind: Some(
                    PostContainmentPersistenceKind::ControlledRealityDepthLimit,
                ),
            },
            evidence: EdgeEvidenceRef {
                event_schema_version: EVENT_SCHEMA_VERSION,
                event_ids: vec![Uuid::new_v4()],
                bundle_ref: "session:ref".to_string(),
                request_linkage: EdgeRequestLinkage::UnknownLegacy,
                authenticated_ingress_rule_rejection_histories: Vec::new(),
                local_ingress_trust_scope_rejection_histories: vec![
                    EdgeLocalIngressTrustScopeRejectionHistory {
                        label: Some("docs-crawler".to_string()),
                        source: IngressIdentitySource::LocalAllowlist,
                        trust_tier: IngressTrustTier::Allowlisted,
                        not_before: None,
                        expires_at: None,
                        methods: vec!["GET".to_string()],
                        path_prefixes: vec!["/docs".to_string(), "/openapi.json".to_string()],
                        bait_soften_path_prefixes: vec!["/docs".to_string()],
                        user_agent_substrings: vec!["eidolon-docs-crawler".to_string()],
                        hosts: vec!["localhost".to_string()],
                        source_cidrs: vec!["127.0.0.1/32".to_string()],
                        required_header_names: vec!["X-Eidolon-Trusted-Actor".to_string()],
                        reasons: vec![
                            LocalIngressTrustScopeRejectionReason::HostMismatch,
                            LocalIngressTrustScopeRejectionReason::SourceCidrMismatch,
                        ],
                    },
                ],
                trusted_ingress_soften_histories: vec![EdgeTrustedIngressSoftenHistory {
                    label: Some("docs-crawler".to_string()),
                    source: IngressIdentitySource::LocalAllowlist,
                    trust_tier: IngressTrustTier::Allowlisted,
                    methods: vec!["GET".to_string()],
                    path_prefixes: vec!["/docs".to_string(), "/openapi.json".to_string()],
                    bait_soften_path_prefixes: vec!["/docs".to_string()],
                    user_agent_substrings: vec!["eidolon-docs-crawler".to_string()],
                    hosts: vec!["127.0.0.1".to_string()],
                    source_cidrs: vec!["127.0.0.1/32".to_string()],
                    required_header_names: vec!["X-Eidolon-Trusted-Actor".to_string()],
                    verified_categories: Vec::new(),
                    saw_request_path_softened: true,
                    saw_request_path_unsoftened: true,
                }],
                bait_header_value_mints: vec![EdgeBaitHeaderValueMintAudit {
                    bait_id: BaitId("minted_trace".to_string()),
                    header_name: "X-Minted-Trace".to_string(),
                    kind: HeaderValueMintKind::SessionHmacSha256V1,
                    prefix: "minted".to_string(),
                }],
                bait_header_value_mint_outcome_summary: EdgeBaitHeaderValueMintOutcomeSummary {
                    session_value_mismatch: 1,
                    ..Default::default()
                },
                latest_bait_header_value_mint: Some(EdgeObservedBaitHeaderValueMint {
                    bait_id: BaitId("minted_trace".to_string()),
                    header_name: "X-Minted-Trace".to_string(),
                    kind: HeaderValueMintKind::SessionHmacSha256V1,
                    prefix: "minted".to_string(),
                    status: BaitHeaderValueMintStatus::SessionValueMismatch,
                }),
            },
            edge_recommendation: EdgeRecommendation {
                action: EdgeRecommendedAction::Allow,
                ttl_seconds: Some(300),
                reason_codes: vec!["trusted_identity".to_string(), "bait_softened".to_string()],
            },
            deployment_context: Some(EdgeDeploymentContext {
                bait_profile_id: Some("orbstack_default_m3_catalog".to_string()),
                polymorphic_baits: vec![EdgeActivePolymorphicBait {
                    bait_id: BaitId("openapi_reconcile_trace".to_string()),
                    surface: "/openapi.json".to_string(),
                    surface_kind: SurfaceKind::OpenApi,
                    header_name: "X-OpenAPI-Trace".to_string(),
                    kind: HeaderValueMintKind::SessionHmacSha256V1,
                    prefix: "oapi".to_string(),
                }],
                polymorphic_bait_coverage: Some(EdgePolymorphicBaitCoverage {
                    active_bait_count: 3,
                    observed_bait_count: 1,
                    observed_bait_ids: vec![BaitId("minted_trace".to_string())],
                    unobserved_bait_ids: vec![
                        BaitId("openapi_reconcile_trace".to_string()),
                        BaitId("rel_2025_04_b7f2".to_string()),
                    ],
                }),
                authenticated_trusted_ingress_rules: Vec::new(),
                trusted_ingress_soften_scopes: vec![EdgeTrustedIngressSoftenScope {
                    label: Some("docs-crawler".to_string()),
                    source: IngressIdentitySource::LocalAllowlist,
                    trust_tier: IngressTrustTier::Allowlisted,
                    not_before: None,
                    expires_at: None,
                    methods: vec!["GET".to_string()],
                    path_prefixes: vec!["/docs".to_string(), "/openapi.json".to_string()],
                    bait_soften_path_prefixes: vec!["/docs".to_string()],
                    user_agent_substrings: vec!["eidolon-docs-crawler".to_string()],
                    hosts: vec!["127.0.0.1".to_string()],
                    source_cidrs: vec!["127.0.0.1/32".to_string()],
                    required_header_names: vec!["X-Eidolon-Trusted-Actor".to_string()],
                    verified_categories: Vec::new(),
                }],
            }),
        };

        let serialized = must_ok(serde_json::to_value(export), "edge export should serialize");

        assert_eq!(
            serialized["contract_version"],
            json!(TRUSTED_INGRESS_CONTRACT_VERSION)
        );
        assert_eq!(serialized["edge_recommendation"]["action"], json!("allow"));
        assert_eq!(
            serialized["ingress_identity"]["trust_tier"],
            json!("edge_verified")
        );
        assert_eq!(
            serialized["local_ingress_trust_scope_rejection"]["reason"],
            json!("host_mismatch")
        );
        assert_eq!(
            serialized["local_ingress_trust_scope_rejection"]["hosts"][0],
            json!("localhost")
        );
        assert_eq!(
            serialized["trusted_ingress_soften_match"]["label"],
            json!("docs-crawler")
        );
        assert_eq!(
            serialized["trusted_ingress_soften_match"]["request_path_softened"],
            json!(false)
        );
        assert_eq!(
            serialized["trusted_ingress_soften_match"]["hosts"][0],
            json!("127.0.0.1")
        );
        assert_eq!(serialized["ingress_signals"]["vendor_score"], json!(12));
        assert_eq!(serialized["ingress_signals"]["edge_action"], json!("allow"));
        assert_eq!(
            serialized["discovery_recon_score"]["detection_score"],
            json!(2)
        );
        assert_eq!(serialized["discovery_recon_score"]["query_score"], json!(1));
        assert_eq!(serialized["discovery_recon_score"]["total"], json!(3));
        assert_eq!(serialized["discovery_recon_score"]["threshold"], json!(3));
        assert_eq!(
            serialized["evidence"]["local_ingress_trust_scope_rejection_histories"][0]["label"],
            json!("docs-crawler")
        );
        assert_eq!(
            serialized["evidence"]["local_ingress_trust_scope_rejection_histories"][0]["reasons"]
                [0],
            json!("host_mismatch")
        );
        assert_eq!(
            serialized["evidence"]["local_ingress_trust_scope_rejection_histories"][0]["reasons"]
                [1],
            json!("source_cidr_mismatch")
        );
        assert_eq!(
            serialized["evidence"]["trusted_ingress_soften_histories"][0]["label"],
            json!("docs-crawler")
        );
        assert_eq!(
            serialized["evidence"]["trusted_ingress_soften_histories"][0]
                ["saw_request_path_softened"],
            json!(true)
        );
        assert_eq!(
            serialized["evidence"]["trusted_ingress_soften_histories"][0]
                ["saw_request_path_unsoftened"],
            json!(true)
        );
        assert_eq!(
            serialized["evidence"]["bait_header_value_mints"][0]["header_name"],
            json!("X-Minted-Trace")
        );
        assert_eq!(
            serialized["evidence"]["bait_header_value_mints"][0]["kind"],
            json!("session_hmac_sha256_v1")
        );
        assert_eq!(
            serialized["evidence"]["bait_header_value_mint_outcome_summary"]
                ["session_value_mismatch"],
            json!(1)
        );
        assert_eq!(
            serialized["evidence"]["latest_bait_header_value_mint"]["status"],
            json!("session_value_mismatch")
        );
        assert_eq!(
            serialized["deployment_context"]["bait_profile_id"],
            json!("orbstack_default_m3_catalog")
        );
        assert_eq!(
            serialized["deployment_context"]["polymorphic_baits"][0]["surface_kind"],
            json!("open_api")
        );
        assert_eq!(
            serialized["deployment_context"]["polymorphic_bait_coverage"]["active_bait_count"],
            json!(3)
        );
        assert_eq!(
            serialized["deployment_context"]["polymorphic_bait_coverage"]["observed_bait_count"],
            json!(1)
        );
        assert_eq!(
            serialized["deployment_context"]["polymorphic_bait_coverage"]["observed_bait_ids"][0],
            json!("minted_trace")
        );
        assert_eq!(
            serialized["deployment_context"]["trusted_ingress_soften_scopes"][0]["label"],
            json!("docs-crawler")
        );
        assert_eq!(
            serialized["deployment_context"]["trusted_ingress_soften_scopes"][0]["source"],
            json!("local_allowlist")
        );
        assert_eq!(
            serialized["deployment_context"]["trusted_ingress_soften_scopes"][0]
                ["bait_soften_path_prefixes"][0],
            json!("/docs")
        );
        assert_eq!(
            serialized["deployment_context"]["trusted_ingress_soften_scopes"][0]["hosts"][0],
            json!("127.0.0.1")
        );
        assert_eq!(
            serialized["policy"]["pre_containment_persistence_class"],
            json!("discovery_recon")
        );
        assert_eq!(
            serialized["policy"]["pre_containment_persistence_kind"],
            json!("discovery_recon_retry")
        );
        assert_eq!(
            serialized["policy"]["post_containment_persistence_kind"],
            json!("controlled_reality_depth_limit")
        );
    }
}
