use std::{fmt, fs, net::IpAddr, path::Path};

use chrono::{DateTime, Utc};
use eidolon_core::{
    AuthenticatedIngressRuleRejection, AuthenticatedIngressRuleRejectionReason,
    IngressAdvisorySignals, IngressIdentity, IngressIdentitySource, IngressTrustTier,
    LocalIngressTrustScopeRejection, LocalIngressTrustScopeRejectionReason,
};
use ipnet::IpNet;
use serde::Deserialize;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IngressIdentityResolver {
    entries: Vec<TrustedIngressEntry>,
    authenticated_entries: Vec<AuthenticatedTrustedIngressEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedIngressTrust {
    pub identity: IngressIdentity,
    pub methods: Vec<String>,
    pub path_prefixes: Vec<String>,
    pub bait_soften_path_prefixes: Option<Vec<String>>,
    pub user_agent_substrings: Option<Vec<String>>,
    pub hosts: Option<Vec<String>>,
    pub source_cidrs: Option<Vec<String>>,
    pub required_header_names: Vec<String>,
    pub verified_categories: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IngressTrustEvaluation {
    pub resolved: Option<ResolvedIngressTrust>,
    pub scope_rejection: Option<LocalIngressTrustScopeRejection>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthenticatedIngressTrustEvaluation {
    pub resolved: Option<ResolvedIngressTrust>,
    pub rule_rejection: Option<AuthenticatedIngressRuleRejection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct AuthenticatedRuleSpecificity {
    matched_path_prefix_len: usize,
    configured_path_prefix_len: usize,
    verified_category_required: bool,
    method_constrained: bool,
    has_time_window: bool,
    verified_category_count_inverse: usize,
    method_count_inverse: usize,
    path_prefix_count_inverse: usize,
}

impl IngressIdentityResolver {
    pub fn len(&self) -> usize {
        self.entries.len() + self.authenticated_entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.authenticated_entries.is_empty()
    }

    pub fn has_authenticated_entries(&self) -> bool {
        !self.authenticated_entries.is_empty()
    }

    pub fn resolve<I, N, V>(
        &self,
        method: &str,
        path: &str,
        request_host: Option<&str>,
        client_ip: Option<IpAddr>,
        headers: I,
    ) -> Option<ResolvedIngressTrust>
    where
        I: IntoIterator<Item = (N, V)>,
        N: AsRef<str>,
        V: AsRef<str>,
    {
        self.evaluate(method, path, request_host, client_ip, headers)
            .resolved
    }

    pub fn evaluate<I, N, V>(
        &self,
        method: &str,
        path: &str,
        request_host: Option<&str>,
        client_ip: Option<IpAddr>,
        headers: I,
    ) -> IngressTrustEvaluation
    where
        I: IntoIterator<Item = (N, V)>,
        N: AsRef<str>,
        V: AsRef<str>,
    {
        let headers: Vec<(String, String)> = headers
            .into_iter()
            .map(|(name, value)| (name.as_ref().to_string(), value.as_ref().to_string()))
            .collect();
        let method = method.trim().to_ascii_uppercase();

        let mut evaluation = IngressTrustEvaluation::default();
        for entry in &self.entries {
            match entry.evaluate(&method, path, request_host, client_ip, &headers) {
                TrustedIngressEntryEvaluation::Matched => {
                    evaluation.resolved = Some(entry.resolved_trust());
                    evaluation.scope_rejection = None;
                    return evaluation;
                }
                TrustedIngressEntryEvaluation::ScopeRejected(rejection) => {
                    if evaluation.scope_rejection.is_none() {
                        evaluation.scope_rejection = Some(*rejection);
                    }
                }
                TrustedIngressEntryEvaluation::NoMatch => {}
            }
        }

        evaluation
    }

    pub fn evaluate_authenticated(
        &self,
        identity: &IngressIdentity,
        signals: &IngressAdvisorySignals,
        method: &str,
        path: &str,
    ) -> AuthenticatedIngressTrustEvaluation {
        let method = method.trim().to_ascii_uppercase();
        let mut evaluation = AuthenticatedIngressTrustEvaluation::default();
        let mut saw_source_trust_candidate = false;
        let mut resolved_match: Option<(AuthenticatedRuleSpecificity, ResolvedIngressTrust)> = None;
        let mut rejected_match: Option<(
            u8,
            AuthenticatedRuleSpecificity,
            AuthenticatedIngressRuleRejection,
        )> = None;

        for entry in &self.authenticated_entries {
            let specificity = authenticated_rule_specificity(entry, path);
            match entry.evaluate(identity, signals, &method, path) {
                AuthenticatedTrustedIngressEntryEvaluation::Matched => {
                    let should_replace = match resolved_match.as_ref() {
                        None => true,
                        Some((current_specificity, _)) => specificity > *current_specificity,
                    };
                    if should_replace {
                        resolved_match = Some((specificity, entry.resolved_trust()));
                    }
                }
                AuthenticatedTrustedIngressEntryEvaluation::RuleRejected(rejection) => {
                    saw_source_trust_candidate = true;
                    let rejection_priority =
                        authenticated_rule_rejection_priority(rejection.reason);
                    let should_replace = match rejected_match.as_ref() {
                        None => true,
                        Some((current_priority, current_specificity, _)) => {
                            rejection_priority > *current_priority
                                || (rejection_priority == *current_priority
                                    && specificity > *current_specificity)
                        }
                    };
                    if should_replace {
                        rejected_match = Some((rejection_priority, specificity, rejection));
                    }
                }
                AuthenticatedTrustedIngressEntryEvaluation::NoMatch => {}
            }
        }

        if let Some((_, resolved)) = resolved_match {
            evaluation.resolved = Some(resolved);
            evaluation.rule_rejection = None;
            return evaluation;
        }

        if let Some((_, _, rejection)) = rejected_match {
            evaluation.rule_rejection = Some(rejection);
            return evaluation;
        }

        if !saw_source_trust_candidate && requires_authenticated_rule(identity) {
            evaluation.rule_rejection = Some(AuthenticatedIngressRuleRejection {
                label: identity.label.clone(),
                source: identity.source,
                trust_tier: identity.trust_tier,
                not_before: None,
                expires_at: None,
                methods: Vec::new(),
                path_prefixes: Vec::new(),
                bait_soften_path_prefixes: Vec::new(),
                verified_categories: Vec::new(),
                reason: AuthenticatedIngressRuleRejectionReason::NoMatchingRule,
            });
        }

        evaluation
    }

    pub fn resolve_authenticated(
        &self,
        identity: &IngressIdentity,
        signals: &IngressAdvisorySignals,
        method: &str,
        path: &str,
    ) -> Option<ResolvedIngressTrust> {
        self.evaluate_authenticated(identity, signals, method, path)
            .resolved
    }
}

/// Merge an explicit normalized ingress claim with a locally matched claim.
///
/// The stronger claim wins. When strength is equal, the local claim wins so an
/// operator-controlled allowlist can override an equally strong inbound claim.
pub fn merge_ingress_identity(
    explicit: IngressIdentity,
    local: Option<IngressIdentity>,
) -> IngressIdentity {
    let Some(local) = local else {
        return explicit;
    };

    if explicit == IngressIdentity::default() {
        return local;
    }
    if local == IngressIdentity::default() {
        return explicit;
    }

    if ingress_identity_strength(&local) >= ingress_identity_strength(&explicit) {
        local
    } else {
        explicit
    }
}

/// Return whether this identity is strong enough to suppress bait exposure
/// while the session is still in an observe-only posture.
pub fn softens_bait_surface_exposure(identity: &IngressIdentity) -> bool {
    identity.source != IngressIdentitySource::None
        && matches!(
            identity.trust_tier,
            IngressTrustTier::Allowlisted
                | IngressTrustTier::EdgeVerified
                | IngressTrustTier::SignedAttested
        )
}

pub fn requires_authenticated_rule(identity: &IngressIdentity) -> bool {
    identity.source != IngressIdentitySource::None
        && !matches!(
            identity.source,
            IngressIdentitySource::LocalAllowlist | IngressIdentitySource::OperatorOverride
        )
        && matches!(
            identity.trust_tier,
            IngressTrustTier::Allowlisted
                | IngressTrustTier::EdgeVerified
                | IngressTrustTier::SignedAttested
        )
}

pub fn downgrade_to_weakly_asserted(identity: IngressIdentity) -> IngressIdentity {
    if identity.source == IngressIdentitySource::None {
        return identity;
    }

    IngressIdentity {
        trust_tier: IngressTrustTier::WeaklyAsserted,
        ..identity
    }
}

fn ingress_identity_strength(identity: &IngressIdentity) -> (u8, u8) {
    (
        identity_policy_rank(identity),
        ingress_identity_source_rank(identity),
    )
}

fn identity_policy_rank(identity: &IngressIdentity) -> u8 {
    if identity.source == IngressIdentitySource::OperatorOverride {
        return 5;
    }

    match identity.trust_tier {
        IngressTrustTier::None => 0,
        IngressTrustTier::WeaklyAsserted => 1,
        IngressTrustTier::Allowlisted => 2,
        IngressTrustTier::EdgeVerified => 3,
        IngressTrustTier::SignedAttested => 4,
    }
}

fn ingress_identity_source_rank(identity: &IngressIdentity) -> u8 {
    match identity.source {
        IngressIdentitySource::None => 0,
        IngressIdentitySource::VerifiedBot => 1,
        IngressIdentitySource::PartnerAutomation => 2,
        IngressIdentitySource::InternalScanner => 3,
        IngressIdentitySource::LocalAllowlist => 4,
        IngressIdentitySource::SignedAgent => 5,
        IngressIdentitySource::OperatorOverride => 6,
    }
}

fn authenticated_rule_rejection_priority(reason: AuthenticatedIngressRuleRejectionReason) -> u8 {
    match reason {
        AuthenticatedIngressRuleRejectionReason::Expired
        | AuthenticatedIngressRuleRejectionReason::NotYetActive => 5,
        AuthenticatedIngressRuleRejectionReason::VerifiedCategoryMissing
        | AuthenticatedIngressRuleRejectionReason::VerifiedCategoryMismatch => 4,
        AuthenticatedIngressRuleRejectionReason::MethodMismatch
        | AuthenticatedIngressRuleRejectionReason::PathMismatch => 3,
        AuthenticatedIngressRuleRejectionReason::LabelMissing
        | AuthenticatedIngressRuleRejectionReason::LabelMismatch => 2,
        AuthenticatedIngressRuleRejectionReason::NoMatchingRule => 1,
    }
}

fn authenticated_rule_specificity(
    entry: &AuthenticatedTrustedIngressEntry,
    path: &str,
) -> AuthenticatedRuleSpecificity {
    let matched_path_prefix_len = entry
        .path_prefixes
        .iter()
        .filter(|prefix| path.starts_with(prefix.as_str()))
        .map(|prefix| prefix.len())
        .max()
        .unwrap_or_default();
    let configured_path_prefix_len = entry
        .path_prefixes
        .iter()
        .map(|prefix| prefix.len())
        .max()
        .unwrap_or_default();
    let configured_path_prefix_len = if matched_path_prefix_len == 0 {
        configured_path_prefix_len
    } else {
        matched_path_prefix_len
    };

    AuthenticatedRuleSpecificity {
        matched_path_prefix_len,
        configured_path_prefix_len,
        verified_category_required: !entry.verified_categories.is_empty(),
        method_constrained: !entry.methods.is_empty(),
        has_time_window: entry.identity.not_before.is_some() || entry.identity.expires_at.is_some(),
        verified_category_count_inverse: usize::MAX - entry.verified_categories.len(),
        method_count_inverse: usize::MAX - entry.methods.len(),
        path_prefix_count_inverse: usize::MAX - entry.path_prefixes.len(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrustedIngressEntry {
    identity: IngressIdentity,
    methods: Vec<String>,
    path_prefixes: Vec<String>,
    bait_soften_path_prefixes: Option<Vec<String>>,
    user_agent_substrings: Option<Vec<String>>,
    hosts: Option<Vec<String>>,
    source_cidrs: Option<Vec<IpNet>>,
    required_headers: Vec<RequiredHeaderMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthenticatedTrustedIngressEntry {
    identity: IngressIdentity,
    methods: Vec<String>,
    path_prefixes: Vec<String>,
    bait_soften_path_prefixes: Option<Vec<String>>,
    verified_categories: Vec<String>,
}

enum TrustedIngressEntryEvaluation {
    Matched,
    ScopeRejected(Box<LocalIngressTrustScopeRejection>),
    NoMatch,
}

enum AuthenticatedTrustedIngressEntryEvaluation {
    Matched,
    RuleRejected(AuthenticatedIngressRuleRejection),
    NoMatch,
}

impl TrustedIngressEntry {
    fn evaluate(
        &self,
        method: &str,
        path: &str,
        request_host: Option<&str>,
        client_ip: Option<IpAddr>,
        headers: &[(String, String)],
    ) -> TrustedIngressEntryEvaluation {
        if !self.required_headers.iter().all(|required| {
            headers.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case(&required.name) && value == &required.value
            })
        }) {
            if let Some(reason) = self.required_header_rejection_reason(headers) {
                return TrustedIngressEntryEvaluation::ScopeRejected(Box::new(
                    self.scope_rejection(reason),
                ));
            }
            return TrustedIngressEntryEvaluation::NoMatch;
        }

        if self
            .identity
            .not_before
            .is_some_and(|not_before| not_before > Utc::now())
        {
            return TrustedIngressEntryEvaluation::ScopeRejected(Box::new(
                self.scope_rejection(LocalIngressTrustScopeRejectionReason::NotYetActive),
            ));
        }

        if self
            .identity
            .expires_at
            .is_some_and(|expires_at| expires_at <= Utc::now())
        {
            return TrustedIngressEntryEvaluation::ScopeRejected(Box::new(
                self.scope_rejection(LocalIngressTrustScopeRejectionReason::Expired),
            ));
        }

        if let Some(user_agent_substrings) = &self.user_agent_substrings {
            let request_user_agent = headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
                .map(|(_, value)| value);
            let Some(request_user_agent) = request_user_agent else {
                return TrustedIngressEntryEvaluation::ScopeRejected(Box::new(
                    self.scope_rejection(
                        LocalIngressTrustScopeRejectionReason::RequestUserAgentMissing,
                    ),
                ));
            };
            let request_user_agent = request_user_agent.to_ascii_lowercase();
            if !user_agent_substrings
                .iter()
                .any(|candidate| request_user_agent.contains(candidate))
            {
                return TrustedIngressEntryEvaluation::ScopeRejected(Box::new(
                    self.scope_rejection(LocalIngressTrustScopeRejectionReason::UserAgentMismatch),
                ));
            }
        }

        if let Some(hosts) = &self.hosts {
            let Some(request_host) = request_host else {
                return TrustedIngressEntryEvaluation::ScopeRejected(Box::new(
                    self.scope_rejection(LocalIngressTrustScopeRejectionReason::RequestHostMissing),
                ));
            };
            if !hosts.iter().any(|host| host == request_host) {
                return TrustedIngressEntryEvaluation::ScopeRejected(Box::new(
                    self.scope_rejection(LocalIngressTrustScopeRejectionReason::HostMismatch),
                ));
            }
        }

        if let Some(source_cidrs) = &self.source_cidrs {
            let Some(client_ip) = client_ip else {
                return TrustedIngressEntryEvaluation::ScopeRejected(Box::new(
                    self.scope_rejection(LocalIngressTrustScopeRejectionReason::ClientPeerMissing),
                ));
            };
            if !source_cidrs.iter().any(|cidr| cidr.contains(&client_ip)) {
                return TrustedIngressEntryEvaluation::ScopeRejected(Box::new(
                    self.scope_rejection(LocalIngressTrustScopeRejectionReason::SourceCidrMismatch),
                ));
            }
        }

        if !self.methods.is_empty() && !self.methods.iter().any(|candidate| candidate == method) {
            return TrustedIngressEntryEvaluation::ScopeRejected(Box::new(
                self.scope_rejection(LocalIngressTrustScopeRejectionReason::MethodMismatch),
            ));
        }

        if !self.path_prefixes.is_empty()
            && !self
                .path_prefixes
                .iter()
                .any(|prefix| path.starts_with(prefix))
        {
            return TrustedIngressEntryEvaluation::ScopeRejected(Box::new(
                self.scope_rejection(LocalIngressTrustScopeRejectionReason::PathMismatch),
            ));
        }

        TrustedIngressEntryEvaluation::Matched
    }

    fn resolved_trust(&self) -> ResolvedIngressTrust {
        ResolvedIngressTrust {
            identity: self.identity.clone(),
            methods: self.methods.clone(),
            path_prefixes: self.path_prefixes.clone(),
            bait_soften_path_prefixes: self.bait_soften_path_prefixes.clone(),
            user_agent_substrings: self.user_agent_substrings.clone(),
            hosts: self.hosts.clone(),
            source_cidrs: self
                .source_cidrs
                .as_ref()
                .map(|cidrs| cidrs.iter().map(ToString::to_string).collect()),
            required_header_names: self
                .required_headers
                .iter()
                .map(|header| header.name.clone())
                .collect(),
            verified_categories: Vec::new(),
        }
    }

    fn scope_rejection(
        &self,
        reason: LocalIngressTrustScopeRejectionReason,
    ) -> LocalIngressTrustScopeRejection {
        LocalIngressTrustScopeRejection {
            label: self.identity.label.clone(),
            source: self.identity.source,
            trust_tier: self.identity.trust_tier,
            not_before: self.identity.not_before,
            expires_at: self.identity.expires_at,
            methods: self.methods.clone(),
            path_prefixes: self.path_prefixes.clone(),
            bait_soften_path_prefixes: self.bait_soften_path_prefixes.clone().unwrap_or_default(),
            user_agent_substrings: self.user_agent_substrings.clone().unwrap_or_default(),
            hosts: self.hosts.clone().unwrap_or_default(),
            source_cidrs: self
                .source_cidrs
                .as_ref()
                .map(|cidrs| cidrs.iter().map(ToString::to_string).collect())
                .unwrap_or_default(),
            required_header_names: self
                .required_headers
                .iter()
                .map(|header| header.name.clone())
                .collect(),
            reason,
        }
    }

    fn required_header_rejection_reason(
        &self,
        headers: &[(String, String)],
    ) -> Option<LocalIngressTrustScopeRejectionReason> {
        for required in &self.required_headers {
            let matches: Vec<&str> = headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case(&required.name))
                .map(|(_, value)| value.as_str())
                .collect();
            if matches.is_empty() {
                return Some(LocalIngressTrustScopeRejectionReason::RequiredHeaderMissing);
            }
            if !matches.iter().any(|value| *value == required.value) {
                return Some(LocalIngressTrustScopeRejectionReason::RequiredHeaderValueMismatch);
            }
        }

        None
    }
}

impl AuthenticatedTrustedIngressEntry {
    fn evaluate(
        &self,
        identity: &IngressIdentity,
        signals: &IngressAdvisorySignals,
        method: &str,
        path: &str,
    ) -> AuthenticatedTrustedIngressEntryEvaluation {
        if identity.source != self.identity.source
            || identity.trust_tier != self.identity.trust_tier
        {
            return AuthenticatedTrustedIngressEntryEvaluation::NoMatch;
        }

        match (&self.identity.label, &identity.label) {
            (Some(_), None) => {
                return AuthenticatedTrustedIngressEntryEvaluation::RuleRejected(
                    self.rule_rejection(AuthenticatedIngressRuleRejectionReason::LabelMissing),
                );
            }
            (Some(expected), Some(actual)) if actual != expected => {
                return AuthenticatedTrustedIngressEntryEvaluation::RuleRejected(
                    self.rule_rejection(AuthenticatedIngressRuleRejectionReason::LabelMismatch),
                );
            }
            _ => {}
        }

        if self
            .identity
            .not_before
            .is_some_and(|not_before| not_before > Utc::now())
        {
            return AuthenticatedTrustedIngressEntryEvaluation::RuleRejected(
                self.rule_rejection(AuthenticatedIngressRuleRejectionReason::NotYetActive),
            );
        }

        if self
            .identity
            .expires_at
            .is_some_and(|expires_at| expires_at <= Utc::now())
        {
            return AuthenticatedTrustedIngressEntryEvaluation::RuleRejected(
                self.rule_rejection(AuthenticatedIngressRuleRejectionReason::Expired),
            );
        }

        if !self.methods.is_empty() && !self.methods.iter().any(|candidate| candidate == method) {
            return AuthenticatedTrustedIngressEntryEvaluation::RuleRejected(
                self.rule_rejection(AuthenticatedIngressRuleRejectionReason::MethodMismatch),
            );
        }

        if !self.path_prefixes.is_empty()
            && !self
                .path_prefixes
                .iter()
                .any(|prefix| path.starts_with(prefix))
        {
            return AuthenticatedTrustedIngressEntryEvaluation::RuleRejected(
                self.rule_rejection(AuthenticatedIngressRuleRejectionReason::PathMismatch),
            );
        }

        if self.verified_categories.is_empty() {
            return AuthenticatedTrustedIngressEntryEvaluation::Matched;
        }

        let Some(verified_category) = signals.verified_category.as_deref() else {
            return AuthenticatedTrustedIngressEntryEvaluation::RuleRejected(
                self.rule_rejection(
                    AuthenticatedIngressRuleRejectionReason::VerifiedCategoryMissing,
                ),
            );
        };
        if !self
            .verified_categories
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(verified_category))
        {
            return AuthenticatedTrustedIngressEntryEvaluation::RuleRejected(self.rule_rejection(
                AuthenticatedIngressRuleRejectionReason::VerifiedCategoryMismatch,
            ));
        };

        AuthenticatedTrustedIngressEntryEvaluation::Matched
    }

    fn resolved_trust(&self) -> ResolvedIngressTrust {
        ResolvedIngressTrust {
            identity: self.identity.clone(),
            methods: self.methods.clone(),
            path_prefixes: self.path_prefixes.clone(),
            bait_soften_path_prefixes: self.bait_soften_path_prefixes.clone(),
            user_agent_substrings: None,
            hosts: None,
            source_cidrs: None,
            required_header_names: Vec::new(),
            verified_categories: self.verified_categories.clone(),
        }
    }

    fn rule_rejection(
        &self,
        reason: AuthenticatedIngressRuleRejectionReason,
    ) -> AuthenticatedIngressRuleRejection {
        AuthenticatedIngressRuleRejection {
            label: self.identity.label.clone(),
            source: self.identity.source,
            trust_tier: self.identity.trust_tier,
            not_before: self.identity.not_before,
            expires_at: self.identity.expires_at,
            methods: self.methods.clone(),
            path_prefixes: self.path_prefixes.clone(),
            bait_soften_path_prefixes: self.bait_soften_path_prefixes.clone().unwrap_or_default(),
            verified_categories: self.verified_categories.clone(),
            reason,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequiredHeaderMatch {
    name: String,
    value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressTrustConfigError {
    message: String,
}

impl IngressTrustConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for IngressTrustConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for IngressTrustConfigError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIngressTrustConfig {
    schema_version: u16,
    #[serde(default)]
    entries: Vec<RawTrustedIngressEntry>,
    #[serde(default)]
    authenticated_entries: Vec<RawAuthenticatedTrustedIngressEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTrustedIngressEntry {
    label: String,
    source: IngressIdentitySource,
    trust_tier: IngressTrustTier,
    #[serde(default)]
    not_before: Option<DateTime<Utc>>,
    #[serde(default)]
    expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    methods: Vec<String>,
    #[serde(default)]
    path_prefixes: Vec<String>,
    #[serde(default)]
    bait_soften_path_prefixes: Option<Vec<String>>,
    #[serde(default)]
    user_agent_substrings: Vec<String>,
    #[serde(default)]
    hosts: Vec<String>,
    #[serde(default)]
    source_cidrs: Vec<String>,
    required_headers: Vec<RawRequiredHeaderMatch>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAuthenticatedTrustedIngressEntry {
    label: String,
    source: IngressIdentitySource,
    trust_tier: IngressTrustTier,
    #[serde(default)]
    not_before: Option<DateTime<Utc>>,
    #[serde(default)]
    expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    methods: Vec<String>,
    #[serde(default)]
    path_prefixes: Vec<String>,
    #[serde(default)]
    bait_soften_path_prefixes: Option<Vec<String>>,
    #[serde(default)]
    verified_categories: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRequiredHeaderMatch {
    name: String,
    value: String,
}

pub fn load_ingress_identity_resolver(
    path: &Path,
) -> Result<IngressIdentityResolver, IngressTrustConfigError> {
    let raw = fs::read_to_string(path).map_err(|error| {
        IngressTrustConfigError::new(format!(
            "failed to read ingress trust config `{}`: {error}",
            path.display()
        ))
    })?;

    parse_ingress_identity_resolver(&raw)
}

fn parse_ingress_identity_resolver(
    raw: &str,
) -> Result<IngressIdentityResolver, IngressTrustConfigError> {
    let config: RawIngressTrustConfig = serde_json::from_str(raw).map_err(|error| {
        IngressTrustConfigError::new(format!("failed to parse ingress trust config: {error}"))
    })?;

    config.into_resolver()
}

impl RawIngressTrustConfig {
    fn into_resolver(self) -> Result<IngressIdentityResolver, IngressTrustConfigError> {
        if self.schema_version != 1 {
            return Err(IngressTrustConfigError::new(format!(
                "ingress trust config schema_version must be 1, got {}",
                self.schema_version
            )));
        }
        if self.entries.is_empty() && self.authenticated_entries.is_empty() {
            return Err(IngressTrustConfigError::new(
                "ingress trust config entries and authenticated_entries must not both be empty",
            ));
        }

        let entries = self
            .entries
            .into_iter()
            .enumerate()
            .map(|(index, entry)| entry.into_entry(index))
            .collect::<Result<Vec<_>, _>>()?;
        let authenticated_entries = self
            .authenticated_entries
            .into_iter()
            .enumerate()
            .map(|(index, entry)| entry.into_entry(index))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(IngressIdentityResolver {
            entries,
            authenticated_entries,
        })
    }
}

impl RawTrustedIngressEntry {
    fn into_entry(self, index: usize) -> Result<TrustedIngressEntry, IngressTrustConfigError> {
        let label = self.label.trim();
        if label.is_empty() {
            return Err(IngressTrustConfigError::new(format!(
                "ingress trust config entry {index} label must not be empty"
            )));
        }
        if self.source == IngressIdentitySource::None {
            return Err(IngressTrustConfigError::new(format!(
                "ingress trust config entry {index} source must not be `none`"
            )));
        }
        if self.trust_tier == IngressTrustTier::None {
            return Err(IngressTrustConfigError::new(format!(
                "ingress trust config entry {index} trust_tier must not be `none`"
            )));
        }
        if self.required_headers.is_empty() {
            return Err(IngressTrustConfigError::new(format!(
                "ingress trust config entry {index} required_headers must not be empty"
            )));
        }

        let methods = self
            .methods
            .into_iter()
            .map(|method| {
                let method = method.trim().to_ascii_uppercase();
                if method.is_empty() {
                    Err(IngressTrustConfigError::new(format!(
                        "ingress trust config entry {index} methods must not contain empty values"
                    )))
                } else {
                    Ok(method)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        let path_prefixes =
            normalize_path_prefixes(self.path_prefixes, index, "path_prefixes", true)?;
        let bait_soften_path_prefixes = match self.bait_soften_path_prefixes {
            Some(prefixes) => Some(normalize_path_prefixes(
                prefixes,
                index,
                "bait_soften_path_prefixes",
                true,
            )?),
            None => None,
        };
        let user_agent_substrings =
            normalize_user_agent_substrings(self.user_agent_substrings, index)?;
        let hosts = normalize_hosts(self.hosts, index)?;
        let source_cidrs = normalize_source_cidrs(self.source_cidrs, index)?;

        let required_headers = self
            .required_headers
            .into_iter()
            .map(|header| header.into_match(index))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(TrustedIngressEntry {
            identity: IngressIdentity {
                source: self.source,
                trust_tier: self.trust_tier,
                label: Some(label.to_string()),
                not_before: self.not_before,
                expires_at: self.expires_at,
            },
            methods,
            path_prefixes,
            bait_soften_path_prefixes,
            user_agent_substrings,
            hosts,
            source_cidrs,
            required_headers,
        })
    }
}

impl RawAuthenticatedTrustedIngressEntry {
    fn into_entry(
        self,
        index: usize,
    ) -> Result<AuthenticatedTrustedIngressEntry, IngressTrustConfigError> {
        let label = self.label.trim();
        if label.is_empty() {
            return Err(IngressTrustConfigError::new(format!(
                "ingress trust config authenticated_entries[{index}] label must not be empty"
            )));
        }
        if !matches!(
            self.source,
            IngressIdentitySource::InternalScanner
                | IngressIdentitySource::VerifiedBot
                | IngressIdentitySource::SignedAgent
                | IngressIdentitySource::PartnerAutomation
        ) {
            return Err(IngressTrustConfigError::new(format!(
                "ingress trust config authenticated_entries[{index}] source must be one of: internal_scanner, verified_bot, signed_agent, partner_automation"
            )));
        }
        if self.trust_tier == IngressTrustTier::None {
            return Err(IngressTrustConfigError::new(format!(
                "ingress trust config authenticated_entries[{index}] trust_tier must not be `none`"
            )));
        }

        let methods = self
            .methods
            .into_iter()
            .map(|method| {
                let method = method.trim().to_ascii_uppercase();
                if method.is_empty() {
                    Err(IngressTrustConfigError::new(format!(
                        "ingress trust config authenticated_entries[{index}] methods must not contain empty values"
                    )))
                } else {
                    Ok(method)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        let path_prefixes = normalize_path_prefixes(
            self.path_prefixes,
            index,
            "authenticated_entries.path_prefixes",
            false,
        )?;
        let bait_soften_path_prefixes = match self.bait_soften_path_prefixes {
            Some(prefixes) => Some(normalize_path_prefixes(
                prefixes,
                index,
                "authenticated_entries.bait_soften_path_prefixes",
                true,
            )?),
            None => None,
        };
        let verified_categories = self
            .verified_categories
            .into_iter()
            .map(|category| {
                let category = category.trim().to_string();
                if category.is_empty() {
                    Err(IngressTrustConfigError::new(format!(
                        "ingress trust config authenticated_entries[{index}] verified_categories must not contain empty values"
                    )))
                } else {
                    Ok(category)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(AuthenticatedTrustedIngressEntry {
            identity: IngressIdentity {
                source: self.source,
                trust_tier: self.trust_tier,
                label: Some(label.to_string()),
                not_before: self.not_before,
                expires_at: self.expires_at,
            },
            methods,
            path_prefixes,
            bait_soften_path_prefixes,
            verified_categories,
        })
    }
}

fn normalize_path_prefixes(
    prefixes: Vec<String>,
    index: usize,
    field_name: &str,
    allow_empty: bool,
) -> Result<Vec<String>, IngressTrustConfigError> {
    let prefixes = prefixes
        .into_iter()
        .map(|prefix| {
            let prefix = prefix.trim().to_string();
            if prefix.is_empty() || !prefix.starts_with('/') {
                Err(IngressTrustConfigError::new(format!(
                    "ingress trust config entry {index} {field_name} must start with `/`"
                )))
            } else {
                Ok(prefix)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;

    if !allow_empty && prefixes.is_empty() {
        return Err(IngressTrustConfigError::new(format!(
            "ingress trust config entry {index} {field_name} must not be empty"
        )));
    }

    Ok(prefixes)
}

fn normalize_source_cidrs(
    source_cidrs: Vec<String>,
    index: usize,
) -> Result<Option<Vec<IpNet>>, IngressTrustConfigError> {
    if source_cidrs.is_empty() {
        return Ok(None);
    }

    let source_cidrs = source_cidrs
        .into_iter()
        .map(|cidr| {
            let cidr = cidr.trim();
            if cidr.is_empty() {
                return Err(IngressTrustConfigError::new(format!(
                    "ingress trust config entry {index} source_cidrs must not contain empty values"
                )));
            }

            cidr.parse::<IpNet>()
                .or_else(|_| cidr.parse::<IpAddr>().map(IpNet::from))
                .map_err(|error| {
                    IngressTrustConfigError::new(format!(
                        "ingress trust config entry {index} source_cidrs value `{cidr}` is invalid: {error}"
                    ))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Some(source_cidrs))
}

fn normalize_user_agent_substrings(
    user_agent_substrings: Vec<String>,
    index: usize,
) -> Result<Option<Vec<String>>, IngressTrustConfigError> {
    if user_agent_substrings.is_empty() {
        return Ok(None);
    }

    let user_agent_substrings = user_agent_substrings
        .into_iter()
        .map(|substring| {
            let substring = substring.trim();
            if substring.is_empty() {
                return Err(IngressTrustConfigError::new(format!(
                    "ingress trust config entry {index} user_agent_substrings must not contain empty values"
                )));
            }

            Ok(substring.to_ascii_lowercase())
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Some(user_agent_substrings))
}

fn normalize_hosts(
    hosts: Vec<String>,
    index: usize,
) -> Result<Option<Vec<String>>, IngressTrustConfigError> {
    if hosts.is_empty() {
        return Ok(None);
    }

    let hosts = hosts
        .into_iter()
        .map(|host| normalize_host_scope_value(&host, index))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Some(hosts))
}

fn normalize_host_scope_value(host: &str, index: usize) -> Result<String, IngressTrustConfigError> {
    let host = host.trim();
    if host.is_empty() {
        return Err(IngressTrustConfigError::new(format!(
            "ingress trust config entry {index} hosts must not contain empty values"
        )));
    }
    if host.contains('/') || host.chars().any(char::is_whitespace) {
        return Err(IngressTrustConfigError::new(format!(
            "ingress trust config entry {index} hosts value `{host}` is invalid: host scopes must be plain hosts without paths"
        )));
    }

    let bracketless = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    if bracketless.parse::<IpAddr>().is_ok() {
        return Ok(bracketless.to_ascii_lowercase());
    }

    if host.contains(':') {
        return Err(IngressTrustConfigError::new(format!(
            "ingress trust config entry {index} hosts value `{host}` is invalid: host scopes must not include ports"
        )));
    }

    Ok(host.to_ascii_lowercase())
}

impl RawRequiredHeaderMatch {
    fn into_match(self, index: usize) -> Result<RequiredHeaderMatch, IngressTrustConfigError> {
        let name = self.name.trim();
        let value = self.value.trim();

        if name.is_empty() {
            return Err(IngressTrustConfigError::new(format!(
                "ingress trust config entry {index} required_headers.name must not be empty"
            )));
        }
        if value.is_empty() {
            return Err(IngressTrustConfigError::new(format!(
                "ingress trust config entry {index} required_headers.value must not be empty"
            )));
        }
        if name.eq_ignore_ascii_case("user-agent") {
            return Err(IngressTrustConfigError::new(format!(
                "ingress trust config entry {index} must not trust `user-agent` as a matcher"
            )));
        }

        Ok(RequiredHeaderMatch {
            name: name.to_string(),
            value: value.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use eidolon_core::{IngressIdentity, IngressIdentitySource, IngressTrustTier};

    use super::*;

    fn must_ok<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{context}: {error}"),
        }
    }

    fn must_some<T>(value: Option<T>, context: &str) -> T {
        match value {
            Some(value) => value,
            None => panic!("{context}"),
        }
    }

    #[test]
    fn parses_and_resolves_matching_entry() {
        let resolver = parse_ingress_identity_resolver(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "internal-crawler",
                  "source": "operator_override",
                  "trust_tier": "allowlisted",
                  "methods": ["GET"],
                  "path_prefixes": ["/docs", "/openapi.json"],
                  "required_headers": [
                    { "name": "X-Eidolon-Trusted-Actor", "value": "internal-crawler" }
                  ]
                }
              ]
            }"#,
        );
        let resolver = must_ok(resolver, "config should parse");

        let trust = must_some(
            resolver.resolve(
                "GET",
                "/docs/legacy-import",
                None,
                None,
                [("X-Eidolon-Trusted-Actor", "internal-crawler")],
            ),
            "entry should match",
        );

        assert_eq!(resolver.len(), 1);
        assert_eq!(
            trust.identity.source,
            IngressIdentitySource::OperatorOverride
        );
        assert_eq!(trust.identity.trust_tier, IngressTrustTier::Allowlisted);
        assert_eq!(trust.identity.label.as_deref(), Some("internal-crawler"));
        assert_eq!(
            trust.required_header_names,
            vec!["X-Eidolon-Trusted-Actor".to_string()]
        );
        assert_eq!(trust.methods, vec!["GET".to_string()]);
        assert!(trust.bait_soften_path_prefixes.is_none());
    }

    #[test]
    fn method_and_path_scopes_must_match() {
        let resolver = parse_ingress_identity_resolver(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "internal-crawler",
                  "source": "local_allowlist",
                  "trust_tier": "allowlisted",
                  "methods": ["GET"],
                  "path_prefixes": ["/docs"],
                  "required_headers": [
                    { "name": "X-Eidolon-Trusted-Actor", "value": "internal-crawler" }
                  ]
                }
              ]
            }"#,
        );
        let resolver = must_ok(resolver, "config should parse");

        let method_mismatch = resolver.evaluate(
            "POST",
            "/docs/legacy-import",
            None,
            None,
            [("X-Eidolon-Trusted-Actor", "internal-crawler")],
        );
        assert!(method_mismatch.resolved.is_none());
        assert_eq!(
            must_some(
                method_mismatch.scope_rejection,
                "method mismatch should be exposed"
            )
            .reason,
            LocalIngressTrustScopeRejectionReason::MethodMismatch
        );

        let path_mismatch = resolver.evaluate(
            "GET",
            "/health",
            None,
            None,
            [("X-Eidolon-Trusted-Actor", "internal-crawler")],
        );
        assert!(path_mismatch.resolved.is_none());
        let path_rejection = must_some(
            path_mismatch.scope_rejection,
            "path mismatch should be exposed",
        );
        assert_eq!(
            path_rejection.reason,
            LocalIngressTrustScopeRejectionReason::PathMismatch
        );
        assert_eq!(path_rejection.methods, vec!["GET".to_string()]);
        assert_eq!(path_rejection.path_prefixes, vec!["/docs".to_string()]);
    }

    #[test]
    fn first_matching_entry_wins() {
        let resolver = parse_ingress_identity_resolver(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "operator-seed",
                  "source": "operator_override",
                  "trust_tier": "allowlisted",
                  "required_headers": [
                    { "name": "X-Actor", "value": "seed" }
                  ]
                },
                {
                  "label": "scanner-seed",
                  "source": "internal_scanner",
                  "trust_tier": "weakly_asserted",
                  "required_headers": [
                    { "name": "X-Actor", "value": "seed" }
                  ]
                }
              ]
            }"#,
        );
        let resolver = must_ok(resolver, "config should parse");

        let trust = must_some(
            resolver.resolve("GET", "/docs", None, None, [("X-Actor", "seed")]),
            "entry should match",
        );

        assert_eq!(
            trust.identity.source,
            IngressIdentitySource::OperatorOverride
        );
        assert_eq!(trust.identity.trust_tier, IngressTrustTier::Allowlisted);
    }

    #[test]
    fn preserves_optional_expiry() {
        let resolver = parse_ingress_identity_resolver(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "operator-window",
                  "source": "operator_override",
                  "trust_tier": "allowlisted",
                  "expires_at": "2999-06-05T12:00:00Z",
                  "required_headers": [
                    { "name": "X-Actor", "value": "window" }
                  ]
                }
              ]
            }"#,
        );
        let resolver = must_ok(resolver, "config should parse");

        let trust = must_some(
            resolver.resolve("GET", "/docs", None, None, [("X-Actor", "window")]),
            "entry should match",
        );

        assert_eq!(
            trust.identity.expires_at,
            Some(
                Utc.with_ymd_and_hms(2999, 6, 5, 12, 0, 0)
                    .single()
                    .unwrap_or_else(|| panic!("timestamp should be valid"))
            )
        );
    }

    #[test]
    fn expired_entries_do_not_match() {
        let resolver = parse_ingress_identity_resolver(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "operator-window",
                  "source": "operator_override",
                  "trust_tier": "allowlisted",
                  "expires_at": "2000-01-01T00:00:00Z",
                  "required_headers": [
                    { "name": "X-Actor", "value": "window" }
                  ]
                }
              ]
            }"#,
        );
        let resolver = must_ok(resolver, "config should parse");

        assert!(
            resolver
                .resolve("GET", "/docs", None, None, [("X-Actor", "window")])
                .is_none(),
            "expired trust entries should not match",
        );
    }

    #[test]
    fn not_yet_active_entries_do_not_match() {
        let resolver = parse_ingress_identity_resolver(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "operator-window",
                  "source": "operator_override",
                  "trust_tier": "allowlisted",
                  "not_before": "2999-01-01T00:00:00Z",
                  "required_headers": [
                    { "name": "X-Actor", "value": "window" }
                  ]
                }
              ]
            }"#,
        );
        let resolver = must_ok(resolver, "config should parse");

        assert!(
            resolver
                .resolve("GET", "/docs", None, None, [("X-Actor", "window")])
                .is_none(),
            "not-yet-active trust entries should not match",
        );
    }

    #[test]
    fn not_yet_active_scope_rejections_are_exposed() {
        let resolver = must_ok(
            parse_ingress_identity_resolver(
                r#"{
                  "schema_version": 1,
                  "entries": [
                    {
                      "label": "docs-crawler",
                      "source": "local_allowlist",
                      "trust_tier": "allowlisted",
                      "not_before": "2999-01-01T00:00:00Z",
                      "path_prefixes": ["/docs"],
                      "required_headers": [
                        { "name": "X-Eidolon-Trusted-Actor", "value": "docs-crawler" }
                      ]
                    }
                  ]
                }"#,
            ),
            "config should parse",
        );

        let evaluation = resolver.evaluate(
            "GET",
            "/docs",
            None,
            None,
            [("X-Eidolon-Trusted-Actor", "docs-crawler")],
        );

        assert!(evaluation.resolved.is_none());
        let rejection = evaluation
            .scope_rejection
            .expect("scope rejection should be recorded");
        assert_eq!(rejection.label.as_deref(), Some("docs-crawler"));
        assert_eq!(
            rejection.reason,
            LocalIngressTrustScopeRejectionReason::NotYetActive
        );
        assert_eq!(
            rejection.not_before,
            Some(
                Utc.with_ymd_and_hms(2999, 1, 1, 0, 0, 0)
                    .single()
                    .unwrap_or_else(|| panic!("timestamp should be valid"))
            )
        );
        assert_eq!(
            rejection.required_header_names,
            vec!["X-Eidolon-Trusted-Actor".to_string()]
        );
    }

    #[test]
    fn missing_required_headers_are_exposed_as_scope_rejections() {
        let resolver = must_ok(
            parse_ingress_identity_resolver(
                r#"{
                  "schema_version": 1,
                  "entries": [
                    {
                      "label": "docs-crawler",
                      "source": "local_allowlist",
                      "trust_tier": "allowlisted",
                      "path_prefixes": ["/docs"],
                      "required_headers": [
                        { "name": "X-Eidolon-Trusted-Actor", "value": "docs-crawler" }
                      ]
                    }
                  ]
                }"#,
            ),
            "config should parse",
        );

        let evaluation = resolver.evaluate(
            "GET",
            "/docs",
            None,
            None,
            std::iter::empty::<(&str, &str)>(),
        );

        assert!(evaluation.resolved.is_none());
        let rejection = evaluation
            .scope_rejection
            .expect("scope rejection should be recorded");
        assert_eq!(
            rejection.reason,
            LocalIngressTrustScopeRejectionReason::RequiredHeaderMissing
        );
        assert_eq!(
            rejection.required_header_names,
            vec!["X-Eidolon-Trusted-Actor".to_string()]
        );
    }

    #[test]
    fn wrong_required_header_values_are_exposed_as_scope_rejections() {
        let resolver = must_ok(
            parse_ingress_identity_resolver(
                r#"{
                  "schema_version": 1,
                  "entries": [
                    {
                      "label": "docs-crawler",
                      "source": "local_allowlist",
                      "trust_tier": "allowlisted",
                      "path_prefixes": ["/docs"],
                      "required_headers": [
                        { "name": "X-Eidolon-Trusted-Actor", "value": "docs-crawler" }
                      ]
                    }
                  ]
                }"#,
            ),
            "config should parse",
        );

        let evaluation = resolver.evaluate(
            "GET",
            "/docs",
            None,
            None,
            [("X-Eidolon-Trusted-Actor", "wrong-crawler")],
        );

        assert!(evaluation.resolved.is_none());
        let rejection = evaluation
            .scope_rejection
            .expect("scope rejection should be recorded");
        assert_eq!(
            rejection.reason,
            LocalIngressTrustScopeRejectionReason::RequiredHeaderValueMismatch
        );
        assert_eq!(
            rejection.required_header_names,
            vec!["X-Eidolon-Trusted-Actor".to_string()]
        );
    }

    #[test]
    fn preserves_optional_bait_soften_scope() {
        let resolver = parse_ingress_identity_resolver(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "docs-crawler",
                  "source": "local_allowlist",
                  "trust_tier": "allowlisted",
                  "methods": ["GET"],
                  "path_prefixes": ["/docs", "/openapi.json"],
                  "bait_soften_path_prefixes": ["/docs"],
                  "required_headers": [
                    { "name": "X-Actor", "value": "docs-crawler" }
                  ]
                }
              ]
            }"#,
        );
        let resolver = must_ok(resolver, "config should parse");

        let trust = must_some(
            resolver.resolve(
                "GET",
                "/openapi.json",
                None,
                None,
                [("X-Actor", "docs-crawler")],
            ),
            "entry should match",
        );

        assert_eq!(
            trust.bait_soften_path_prefixes,
            Some(vec!["/docs".to_string()])
        );
    }

    #[test]
    fn user_agent_substrings_can_gate_local_trust_matches() {
        let resolver = must_ok(
            parse_ingress_identity_resolver(
                r#"{
                  "schema_version": 1,
                  "entries": [
                    {
                      "label": "docs-crawler",
                      "source": "local_allowlist",
                      "trust_tier": "allowlisted",
                      "path_prefixes": ["/docs"],
                      "user_agent_substrings": ["eidolon-docs-crawler"],
                      "required_headers": [
                        { "name": "X-Eidolon-Trusted-Actor", "value": "docs-crawler" }
                      ]
                    }
                  ]
                }"#,
            ),
            "config should parse",
        );

        let trust = must_some(
            resolver.resolve(
                "GET",
                "/docs",
                None,
                None,
                [
                    ("X-Eidolon-Trusted-Actor", "docs-crawler"),
                    ("User-Agent", "Eidolon-Docs-Crawler/1.0"),
                ],
            ),
            "entry should match",
        );

        assert_eq!(
            trust.user_agent_substrings,
            Some(vec!["eidolon-docs-crawler".to_string()])
        );
        assert!(resolver
            .resolve(
                "GET",
                "/docs",
                None,
                None,
                [
                    ("X-Eidolon-Trusted-Actor", "docs-crawler"),
                    ("User-Agent", "Mozilla/5.0"),
                ],
            )
            .is_none());
    }

    #[test]
    fn user_agent_scope_rejections_are_exposed() {
        let resolver = must_ok(
            parse_ingress_identity_resolver(
                r#"{
                  "schema_version": 1,
                  "entries": [
                    {
                      "label": "docs-crawler",
                      "source": "local_allowlist",
                      "trust_tier": "allowlisted",
                      "path_prefixes": ["/docs"],
                      "user_agent_substrings": ["eidolon-docs-crawler"],
                      "required_headers": [
                        { "name": "X-Eidolon-Trusted-Actor", "value": "docs-crawler" }
                      ]
                    }
                  ]
                }"#,
            ),
            "config should parse",
        );

        let mismatch = resolver.evaluate(
            "GET",
            "/docs",
            None,
            None,
            [
                ("X-Eidolon-Trusted-Actor", "docs-crawler"),
                ("User-Agent", "Mozilla/5.0"),
            ],
        );
        let mismatch_rejection = must_some(mismatch.scope_rejection, "mismatch should be recorded");
        assert_eq!(
            mismatch_rejection.reason,
            LocalIngressTrustScopeRejectionReason::UserAgentMismatch
        );
        assert_eq!(
            mismatch_rejection.user_agent_substrings,
            vec!["eidolon-docs-crawler".to_string()]
        );

        let missing = resolver.evaluate(
            "GET",
            "/docs",
            None,
            None,
            [("X-Eidolon-Trusted-Actor", "docs-crawler")],
        );
        let missing_rejection = must_some(missing.scope_rejection, "missing ua should be recorded");
        assert_eq!(
            missing_rejection.reason,
            LocalIngressTrustScopeRejectionReason::RequestUserAgentMissing
        );
    }

    #[test]
    fn authenticated_entries_can_resolve_strong_explicit_claims() {
        let resolver = must_ok(
            parse_ingress_identity_resolver(
                r#"{
                  "schema_version": 1,
                  "authenticated_entries": [
                    {
                      "label": "docs-signed-agent",
                      "source": "signed_agent",
                      "trust_tier": "signed_attested",
                      "verified_categories": ["Search Engine"],
                      "methods": ["GET"],
                      "path_prefixes": ["/docs", "/openapi.json"],
                      "bait_soften_path_prefixes": ["/docs"]
                    }
                  ]
                }"#,
            ),
            "config should parse",
        );

        let trust = must_some(
            resolver.resolve_authenticated(
                &IngressIdentity {
                    source: IngressIdentitySource::SignedAgent,
                    trust_tier: IngressTrustTier::SignedAttested,
                    label: Some("docs-signed-agent".to_string()),
                    not_before: None,
                    expires_at: None,
                },
                &IngressAdvisorySignals {
                    verified_category: Some("search engine".to_string()),
                    ..IngressAdvisorySignals::default()
                },
                "GET",
                "/docs?topic=imports",
            ),
            "authenticated entry should match",
        );

        assert_eq!(resolver.len(), 1);
        assert_eq!(trust.identity.source, IngressIdentitySource::SignedAgent);
        assert_eq!(trust.identity.trust_tier, IngressTrustTier::SignedAttested);
        assert_eq!(trust.identity.label.as_deref(), Some("docs-signed-agent"));
        assert_eq!(trust.methods, vec!["GET".to_string()]);
        assert_eq!(
            trust.path_prefixes,
            vec!["/docs".to_string(), "/openapi.json".to_string()]
        );
        assert_eq!(
            trust.bait_soften_path_prefixes,
            Some(vec!["/docs".to_string()])
        );
        assert_eq!(trust.verified_categories, vec!["Search Engine".to_string()]);
        assert!(trust.required_header_names.is_empty());
    }

    #[test]
    fn authenticated_entries_require_matching_category_and_path() {
        let resolver = must_ok(
            parse_ingress_identity_resolver(
                r#"{
                  "schema_version": 1,
                  "authenticated_entries": [
                    {
                      "label": "docs-signed-agent",
                      "source": "signed_agent",
                      "trust_tier": "signed_attested",
                      "verified_categories": ["Search Engine"],
                      "methods": ["GET"],
                      "path_prefixes": ["/docs"],
                      "bait_soften_path_prefixes": ["/docs"]
                    }
                  ]
                }"#,
            ),
            "config should parse",
        );

        let identity = IngressIdentity {
            source: IngressIdentitySource::SignedAgent,
            trust_tier: IngressTrustTier::SignedAttested,
            label: Some("docs-signed-agent".to_string()),
            not_before: None,
            expires_at: None,
        };

        let missing_category = resolver.evaluate_authenticated(
            &identity,
            &IngressAdvisorySignals::default(),
            "GET",
            "/docs",
        );
        assert!(missing_category.resolved.is_none());
        assert_eq!(
            must_some(
                missing_category.rule_rejection,
                "missing category rejection should be recorded",
            )
            .reason,
            AuthenticatedIngressRuleRejectionReason::VerifiedCategoryMissing
        );

        let path_mismatch = resolver.evaluate_authenticated(
            &identity,
            &IngressAdvisorySignals {
                verified_category: Some("Search Engine".to_string()),
                ..IngressAdvisorySignals::default()
            },
            "GET",
            "/customer/import-recovery-checklist",
        );
        assert!(path_mismatch.resolved.is_none());
        assert_eq!(
            must_some(
                path_mismatch.rule_rejection,
                "path mismatch should be recorded",
            )
            .reason,
            AuthenticatedIngressRuleRejectionReason::PathMismatch
        );

        let method_mismatch = resolver.evaluate_authenticated(
            &identity,
            &IngressAdvisorySignals {
                verified_category: Some("Search Engine".to_string()),
                ..IngressAdvisorySignals::default()
            },
            "POST",
            "/docs",
        );
        assert!(method_mismatch.resolved.is_none());
        assert_eq!(
            must_some(
                method_mismatch.rule_rejection,
                "method mismatch should be recorded",
            )
            .reason,
            AuthenticatedIngressRuleRejectionReason::MethodMismatch
        );
    }

    #[test]
    fn authenticated_entries_choose_most_specific_match() {
        let resolver = must_ok(
            parse_ingress_identity_resolver(
                r#"{
                  "schema_version": 1,
                  "authenticated_entries": [
                    {
                      "label": "docs-signed-agent",
                      "source": "signed_agent",
                      "trust_tier": "signed_attested",
                      "methods": ["GET"],
                      "path_prefixes": ["/docs", "/openapi.json"]
                    },
                    {
                      "label": "docs-signed-agent",
                      "source": "signed_agent",
                      "trust_tier": "signed_attested",
                      "verified_categories": ["AI Assistant"],
                      "methods": ["GET"],
                      "path_prefixes": ["/docs"],
                      "bait_soften_path_prefixes": ["/docs"]
                    }
                  ]
                }"#,
            ),
            "config should parse",
        );

        let trust = must_some(
            resolver.resolve_authenticated(
                &IngressIdentity {
                    source: IngressIdentitySource::SignedAgent,
                    trust_tier: IngressTrustTier::SignedAttested,
                    label: Some("docs-signed-agent".to_string()),
                    not_before: None,
                    expires_at: None,
                },
                &IngressAdvisorySignals {
                    verified_category: Some("AI Assistant".to_string()),
                    ..IngressAdvisorySignals::default()
                },
                "GET",
                "/docs?topic=imports",
            ),
            "most specific authenticated entry should match",
        );

        assert_eq!(trust.path_prefixes, vec!["/docs".to_string()]);
        assert_eq!(
            trust.bait_soften_path_prefixes,
            Some(vec!["/docs".to_string()])
        );
        assert_eq!(trust.verified_categories, vec!["AI Assistant".to_string()]);
    }

    #[test]
    fn authenticated_entries_choose_most_specific_rejection_when_rules_overlap() {
        let resolver = must_ok(
            parse_ingress_identity_resolver(
                r#"{
                  "schema_version": 1,
                  "authenticated_entries": [
                    {
                      "label": "docs-signed-agent",
                      "source": "signed_agent",
                      "trust_tier": "signed_attested",
                      "methods": ["GET"],
                      "path_prefixes": ["/docs"]
                    },
                    {
                      "label": "docs-signed-agent",
                      "source": "signed_agent",
                      "trust_tier": "signed_attested",
                      "methods": ["GET"],
                      "path_prefixes": ["/docs/legacy-import"]
                    }
                  ]
                }"#,
            ),
            "config should parse",
        );

        let rejection = must_some(
            resolver
                .evaluate_authenticated(
                    &IngressIdentity {
                        source: IngressIdentitySource::SignedAgent,
                        trust_tier: IngressTrustTier::SignedAttested,
                        label: Some("docs-signed-agent".to_string()),
                        not_before: None,
                        expires_at: None,
                    },
                    &IngressAdvisorySignals::default(),
                    "GET",
                    "/health",
                )
                .rule_rejection,
            "most specific rejection should be recorded",
        );

        assert_eq!(
            rejection.reason,
            AuthenticatedIngressRuleRejectionReason::PathMismatch
        );
        assert_eq!(
            rejection.path_prefixes,
            vec!["/docs/legacy-import".to_string()]
        );
    }

    #[test]
    fn authenticated_entries_expose_label_and_freshness_rejections() {
        let resolver = must_ok(
            parse_ingress_identity_resolver(
                r#"{
                  "schema_version": 1,
                  "authenticated_entries": [
                    {
                      "label": "future-signed-agent",
                      "source": "signed_agent",
                      "trust_tier": "signed_attested",
                      "not_before": "2999-01-01T00:00:00Z",
                      "methods": ["GET"],
                      "path_prefixes": ["/docs"]
                    },
                    {
                      "label": "expired-signed-agent",
                      "source": "signed_agent",
                      "trust_tier": "signed_attested",
                      "expires_at": "2000-01-01T00:00:00Z",
                      "methods": ["GET"],
                      "path_prefixes": ["/docs"]
                    },
                    {
                      "label": "current-signed-agent",
                      "source": "signed_agent",
                      "trust_tier": "signed_attested",
                      "methods": ["GET"],
                      "path_prefixes": ["/docs"]
                    }
                  ]
                }"#,
            ),
            "config should parse",
        );

        let label_mismatch = resolver.evaluate_authenticated(
            &IngressIdentity {
                source: IngressIdentitySource::SignedAgent,
                trust_tier: IngressTrustTier::SignedAttested,
                label: Some("wrong-signed-agent".to_string()),
                not_before: None,
                expires_at: None,
            },
            &IngressAdvisorySignals::default(),
            "GET",
            "/docs",
        );
        assert!(label_mismatch.resolved.is_none());
        assert_eq!(
            must_some(
                label_mismatch.rule_rejection,
                "label mismatch should be recorded",
            )
            .reason,
            AuthenticatedIngressRuleRejectionReason::LabelMismatch
        );

        let not_yet_active = resolver.evaluate_authenticated(
            &IngressIdentity {
                source: IngressIdentitySource::SignedAgent,
                trust_tier: IngressTrustTier::SignedAttested,
                label: Some("future-signed-agent".to_string()),
                not_before: None,
                expires_at: None,
            },
            &IngressAdvisorySignals::default(),
            "GET",
            "/docs",
        );
        assert!(not_yet_active.resolved.is_none());
        assert_eq!(
            must_some(
                not_yet_active.rule_rejection,
                "not-yet-active rejection should be recorded",
            )
            .reason,
            AuthenticatedIngressRuleRejectionReason::NotYetActive
        );

        let expired = resolver.evaluate_authenticated(
            &IngressIdentity {
                source: IngressIdentitySource::SignedAgent,
                trust_tier: IngressTrustTier::SignedAttested,
                label: Some("expired-signed-agent".to_string()),
                not_before: None,
                expires_at: None,
            },
            &IngressAdvisorySignals::default(),
            "GET",
            "/docs",
        );
        assert!(expired.resolved.is_none());
        assert_eq!(
            must_some(
                expired.rule_rejection,
                "expired rejection should be recorded"
            )
            .reason,
            AuthenticatedIngressRuleRejectionReason::Expired
        );
    }

    #[test]
    fn authenticated_entries_record_no_matching_rule_for_strong_identity_without_candidate() {
        let resolver = must_ok(
            parse_ingress_identity_resolver(
                r#"{
                  "schema_version": 1,
                  "authenticated_entries": [
                    {
                      "label": "docs-signed-agent",
                      "source": "verified_bot",
                      "trust_tier": "edge_verified",
                      "methods": ["GET"],
                      "path_prefixes": ["/docs"]
                    }
                  ]
                }"#,
            ),
            "config should parse",
        );

        let no_matching_rule = resolver.evaluate_authenticated(
            &IngressIdentity {
                source: IngressIdentitySource::SignedAgent,
                trust_tier: IngressTrustTier::SignedAttested,
                label: Some("different-signed-agent".to_string()),
                not_before: None,
                expires_at: None,
            },
            &IngressAdvisorySignals::default(),
            "GET",
            "/health",
        );
        assert!(no_matching_rule.resolved.is_none());
        let rejection = must_some(
            no_matching_rule.rule_rejection,
            "no-matching-rule rejection should be recorded",
        );
        assert_eq!(
            rejection.reason,
            AuthenticatedIngressRuleRejectionReason::NoMatchingRule
        );
        assert_eq!(rejection.label.as_deref(), Some("different-signed-agent"));
        assert!(rejection.path_prefixes.is_empty());
        assert!(rejection.methods.is_empty());
    }

    #[test]
    fn strong_explicit_identities_can_require_authenticated_rules() {
        let strong = IngressIdentity {
            source: IngressIdentitySource::SignedAgent,
            trust_tier: IngressTrustTier::SignedAttested,
            label: Some("docs-signed-agent".to_string()),
            not_before: None,
            expires_at: Some(
                Utc.with_ymd_and_hms(2999, 1, 1, 0, 0, 0)
                    .single()
                    .unwrap_or_else(|| panic!("timestamp should be valid")),
            ),
        };
        let downgraded = downgrade_to_weakly_asserted(strong.clone());

        assert!(requires_authenticated_rule(&strong));
        assert_eq!(downgraded.source, IngressIdentitySource::SignedAgent);
        assert_eq!(downgraded.trust_tier, IngressTrustTier::WeaklyAsserted);
        assert_eq!(downgraded.label.as_deref(), Some("docs-signed-agent"));
        assert_eq!(downgraded.expires_at, strong.expires_at);
        assert!(!requires_authenticated_rule(&IngressIdentity {
            source: IngressIdentitySource::LocalAllowlist,
            trust_tier: IngressTrustTier::Allowlisted,
            label: Some("docs-crawler".to_string()),
            not_before: None,
            expires_at: None,
        }));
    }

    #[test]
    fn rejects_empty_entries_and_user_agent_matchers() {
        let empty = parse_ingress_identity_resolver(r#"{"schema_version":1,"entries":[]}"#)
            .expect_err("empty config should fail");
        let user_agent = parse_ingress_identity_resolver(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "bad",
                  "source": "local_allowlist",
                  "trust_tier": "allowlisted",
                  "required_headers": [
                    { "name": "User-Agent", "value": "Googlebot/2.1" }
                  ]
                }
              ]
            }"#,
        )
        .expect_err("user-agent matcher should fail");
        let empty_substring = parse_ingress_identity_resolver(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "bad",
                  "source": "local_allowlist",
                  "trust_tier": "allowlisted",
                  "user_agent_substrings": [" "],
                  "required_headers": [
                    { "name": "X-Actor", "value": "bad" }
                  ]
                }
              ]
            }"#,
        )
        .expect_err("empty user-agent substring should fail");

        assert!(empty
            .to_string()
            .contains("entries and authenticated_entries must not both be empty"));
        assert!(user_agent
            .to_string()
            .contains("must not trust `user-agent`"));
        assert!(empty_substring
            .to_string()
            .contains("user_agent_substrings must not contain empty values"));
    }

    #[test]
    fn rejects_none_source_or_trust_tier() {
        let bad_source = parse_ingress_identity_resolver(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "bad-source",
                  "source": "none",
                  "trust_tier": "allowlisted",
                  "required_headers": [
                    { "name": "X-Actor", "value": "bad" }
                  ]
                }
              ]
            }"#,
        )
        .expect_err("none source should fail");
        let bad_tier = parse_ingress_identity_resolver(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "bad-tier",
                  "source": "local_allowlist",
                  "trust_tier": "none",
                  "required_headers": [
                    { "name": "X-Actor", "value": "bad" }
                  ]
                }
              ]
            }"#,
        )
        .expect_err("none trust tier should fail");

        assert!(bad_source.to_string().contains("source must not be `none`"));
        assert!(bad_tier
            .to_string()
            .contains("trust_tier must not be `none`"));
    }

    #[test]
    fn rejects_invalid_bait_soften_prefixes() {
        let bad_scope = parse_ingress_identity_resolver(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "bad-scope",
                  "source": "local_allowlist",
                  "trust_tier": "allowlisted",
                  "bait_soften_path_prefixes": ["docs"],
                  "required_headers": [
                    { "name": "X-Actor", "value": "bad" }
                  ]
                }
              ]
            }"#,
        )
        .expect_err("invalid soften scope should fail");

        assert!(bad_scope
            .to_string()
            .contains("bait_soften_path_prefixes must start with `/`"));
    }

    #[test]
    fn source_cidrs_can_gate_local_trust_matches() {
        let resolver = must_ok(
            parse_ingress_identity_resolver(
                r#"{
                  "schema_version": 1,
                  "entries": [
                    {
                      "label": "docs-crawler",
                      "source": "local_allowlist",
                      "trust_tier": "allowlisted",
                      "path_prefixes": ["/docs"],
                      "source_cidrs": ["127.0.0.1", "10.0.0.0/8"],
                      "required_headers": [
                        { "name": "X-Eidolon-Trusted-Actor", "value": "docs-crawler" }
                      ]
                    }
                  ]
                }"#,
            ),
            "config should parse",
        );

        assert!(resolver
            .resolve(
                "GET",
                "/docs",
                None,
                Some("127.0.0.1".parse().expect("loopback ip should parse")),
                [("X-Eidolon-Trusted-Actor", "docs-crawler")],
            )
            .is_some());
        assert!(resolver
            .resolve(
                "GET",
                "/docs",
                None,
                Some("192.168.1.20".parse().expect("private ip should parse")),
                [("X-Eidolon-Trusted-Actor", "docs-crawler")],
            )
            .is_none());
        assert!(resolver
            .resolve(
                "GET",
                "/docs",
                None,
                None,
                [("X-Eidolon-Trusted-Actor", "docs-crawler")],
            )
            .is_none());
    }

    #[test]
    fn source_cidr_scope_rejections_are_exposed() {
        let resolver = must_ok(
            parse_ingress_identity_resolver(
                r#"{
                  "schema_version": 1,
                  "entries": [
                    {
                      "label": "docs-crawler",
                      "source": "local_allowlist",
                      "trust_tier": "allowlisted",
                      "path_prefixes": ["/docs"],
                      "source_cidrs": ["10.0.0.0/8"],
                      "required_headers": [
                        { "name": "X-Eidolon-Trusted-Actor", "value": "docs-crawler" }
                      ]
                    }
                  ]
                }"#,
            ),
            "config should parse",
        );

        let evaluation = resolver.evaluate(
            "GET",
            "/docs",
            None,
            Some("192.168.1.20".parse().expect("private ip should parse")),
            [("X-Eidolon-Trusted-Actor", "docs-crawler")],
        );

        assert!(evaluation.resolved.is_none());
        let rejection = evaluation
            .scope_rejection
            .expect("scope rejection should be recorded");
        assert_eq!(rejection.label.as_deref(), Some("docs-crawler"));
        assert_eq!(
            rejection.reason,
            LocalIngressTrustScopeRejectionReason::SourceCidrMismatch
        );
    }

    #[test]
    fn hosts_can_gate_local_trust_matches() {
        let resolver = must_ok(
            parse_ingress_identity_resolver(
                r#"{
                  "schema_version": 1,
                  "entries": [
                    {
                      "label": "docs-crawler",
                      "source": "local_allowlist",
                      "trust_tier": "allowlisted",
                      "path_prefixes": ["/docs"],
                      "hosts": ["docs.example.test", "127.0.0.1"],
                      "required_headers": [
                        { "name": "X-Eidolon-Trusted-Actor", "value": "docs-crawler" }
                      ]
                    }
                  ]
                }"#,
            ),
            "config should parse",
        );

        assert!(resolver
            .resolve(
                "GET",
                "/docs",
                Some("docs.example.test"),
                None,
                [("X-Eidolon-Trusted-Actor", "docs-crawler")],
            )
            .is_some());
        assert!(resolver
            .resolve(
                "GET",
                "/docs",
                Some("api.example.test"),
                None,
                [("X-Eidolon-Trusted-Actor", "docs-crawler")],
            )
            .is_none());
        assert!(resolver
            .resolve(
                "GET",
                "/docs",
                None,
                None,
                [("X-Eidolon-Trusted-Actor", "docs-crawler")],
            )
            .is_none());
    }

    #[test]
    fn host_scope_rejections_are_exposed() {
        let resolver = must_ok(
            parse_ingress_identity_resolver(
                r#"{
                  "schema_version": 1,
                  "entries": [
                    {
                      "label": "docs-crawler",
                      "source": "local_allowlist",
                      "trust_tier": "allowlisted",
                      "path_prefixes": ["/docs"],
                      "hosts": ["docs.example.test"],
                      "required_headers": [
                        { "name": "X-Eidolon-Trusted-Actor", "value": "docs-crawler" }
                      ]
                    }
                  ]
                }"#,
            ),
            "config should parse",
        );

        let evaluation = resolver.evaluate(
            "GET",
            "/docs",
            Some("api.example.test"),
            None,
            [("X-Eidolon-Trusted-Actor", "docs-crawler")],
        );

        assert!(evaluation.resolved.is_none());
        let rejection = evaluation
            .scope_rejection
            .expect("scope rejection should be recorded");
        assert_eq!(rejection.label.as_deref(), Some("docs-crawler"));
        assert_eq!(
            rejection.reason,
            LocalIngressTrustScopeRejectionReason::HostMismatch
        );
        assert_eq!(rejection.hosts, vec!["docs.example.test".to_string()]);
    }

    #[test]
    fn rejects_invalid_hosts() {
        let error = parse_ingress_identity_resolver(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "bad-host",
                  "source": "local_allowlist",
                  "trust_tier": "allowlisted",
                  "hosts": ["docs.example.test:8443"],
                  "required_headers": [
                    { "name": "X-Eidolon-Trusted-Actor", "value": "docs-crawler" }
                  ]
                }
              ]
            }"#,
        )
        .expect_err("host scopes with ports should fail");

        assert!(error
            .to_string()
            .contains("host scopes must not include ports"));
    }

    #[test]
    fn rejects_invalid_source_cidrs() {
        let error = parse_ingress_identity_resolver(
            r#"{
              "schema_version": 1,
              "entries": [
                {
                  "label": "bad-source-cidr",
                  "source": "local_allowlist",
                  "trust_tier": "allowlisted",
                  "source_cidrs": ["bad-cidr"],
                  "required_headers": [
                    { "name": "X-Eidolon-Trusted-Actor", "value": "docs-crawler" }
                  ]
                }
              ]
            }"#,
        )
        .expect_err("invalid source_cidrs should fail");

        assert!(error
            .to_string()
            .contains("source_cidrs value `bad-cidr` is invalid"));
    }

    #[test]
    fn merge_prefers_stronger_local_identity() {
        let explicit = IngressIdentity {
            source: IngressIdentitySource::VerifiedBot,
            trust_tier: IngressTrustTier::WeaklyAsserted,
            label: Some("edge-bot".to_string()),
            not_before: None,
            expires_at: None,
        };
        let local = IngressIdentity {
            source: IngressIdentitySource::LocalAllowlist,
            trust_tier: IngressTrustTier::Allowlisted,
            label: Some("internal-crawler".to_string()),
            not_before: None,
            expires_at: None,
        };

        let merged = merge_ingress_identity(explicit, Some(local.clone()));

        assert_eq!(merged, local);
    }

    #[test]
    fn merge_prefers_explicit_signed_attested_identity_over_weaker_local_claim() {
        let explicit = IngressIdentity {
            source: IngressIdentitySource::SignedAgent,
            trust_tier: IngressTrustTier::SignedAttested,
            label: Some("signed-agent".to_string()),
            not_before: None,
            expires_at: None,
        };
        let local = IngressIdentity {
            source: IngressIdentitySource::LocalAllowlist,
            trust_tier: IngressTrustTier::Allowlisted,
            label: Some("internal-crawler".to_string()),
            not_before: None,
            expires_at: None,
        };

        let merged = merge_ingress_identity(explicit.clone(), Some(local));

        assert_eq!(merged, explicit);
    }

    #[test]
    fn merge_prefers_local_identity_when_strength_is_equal() {
        let explicit = IngressIdentity {
            source: IngressIdentitySource::LocalAllowlist,
            trust_tier: IngressTrustTier::Allowlisted,
            label: Some("edge".to_string()),
            not_before: None,
            expires_at: None,
        };
        let local = IngressIdentity {
            source: IngressIdentitySource::LocalAllowlist,
            trust_tier: IngressTrustTier::Allowlisted,
            label: Some("local".to_string()),
            not_before: None,
            expires_at: None,
        };

        let merged = merge_ingress_identity(explicit, Some(local.clone()));

        assert_eq!(merged, local);
    }

    #[test]
    fn only_stronger_trust_tiers_soften_bait_surface_exposure() {
        let weak = IngressIdentity {
            source: IngressIdentitySource::VerifiedBot,
            trust_tier: IngressTrustTier::WeaklyAsserted,
            label: None,
            not_before: None,
            expires_at: None,
        };
        let allowlisted = IngressIdentity {
            source: IngressIdentitySource::LocalAllowlist,
            trust_tier: IngressTrustTier::Allowlisted,
            label: None,
            not_before: None,
            expires_at: None,
        };

        assert!(!softens_bait_surface_exposure(&IngressIdentity::default()));
        assert!(!softens_bait_surface_exposure(&weak));
        assert!(softens_bait_surface_exposure(&allowlisted));
    }
}
