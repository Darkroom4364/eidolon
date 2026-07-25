use std::net::IpAddr;

use chrono::{DateTime, Utc};
use eidolon_core::{
    AuthenticatedIngressRuleRejection, EdgeRecommendedAction, IngressActorKind,
    IngressAdvisorySignals, IngressIdentity, IngressIdentitySource, IngressTrustTier,
    IngressVerificationStrength, LocalIngressTrustScopeRejection, SessionId,
    TrustedIngressSoftenMatch,
};

use crate::session_auth::{
    ContinuityKey, ContinuityOutcome, ContinuitySource, CookieOutcome, KeyStatus, SessionAuthority,
    SessionResolution,
};

/// Request header carrying first-party cookies.
pub const COOKIE_HEADER_NAME: &str = "Cookie";

/// Response header used when the proxy needs to establish a session cookie.
pub const SET_COOKIE_HEADER_NAME: &str = "Set-Cookie";

/// First-party session cookie used by the local proxy lab.
///
/// The cookie intentionally avoids a `Domain` attribute, so user agents keep it
/// host-only instead of sharing it across sibling domains.
pub const SESSION_COOKIE_NAME: &str = "eidolon_session";

/// Scope the lab session to all paths on the current first-party host.
pub const SESSION_COOKIE_PATH: &str = "/";

/// `Lax` keeps ordinary top-level navigation working while reducing ambient
/// cross-site cookie attachment.
pub const SESSION_COOKIE_SAME_SITE: &str = "Lax";

/// Stable attributes for local HTTP lab use.
///
/// `Secure` is intentionally omitted because this proxy is expected to run on
/// local HTTP during M1. Production HTTPS deployments should add `Secure`.
/// `Max-Age` and `Expires` are also omitted, making this a browser-session
/// cookie with minimal retention.
pub const SESSION_COOKIE_ATTRIBUTES: &str = "Path=/; HttpOnly; SameSite=Lax";

/// Normalized ingress trust signal headers reserved for Eidolon edge adapters.
pub const INGRESS_IDENTITY_SOURCE_HEADER_NAME: &str = "X-Eidolon-Ingress-Identity-Source";
pub const INGRESS_TRUST_TIER_HEADER_NAME: &str = "X-Eidolon-Ingress-Trust-Tier";
pub const INGRESS_IDENTITY_LABEL_HEADER_NAME: &str = "X-Eidolon-Ingress-Identity-Label";
pub const INGRESS_IDENTITY_EXPIRES_AT_HEADER_NAME: &str = "X-Eidolon-Ingress-Identity-Expires-At";
pub const INGRESS_TRANSPORT_AUTH_HEADER_NAME: &str = "X-Eidolon-Ingress-Transport-Auth";
pub const INGRESS_CONTINUITY_HEADER_NAME: &str = "X-Eidolon-Ingress-Continuity";
pub const INGRESS_VERIFICATION_STRENGTH_HEADER_NAME: &str =
    "X-Eidolon-Ingress-Verification-Strength";
pub const INGRESS_ACTOR_KIND_HEADER_NAME: &str = "X-Eidolon-Ingress-Actor-Kind";
pub const INGRESS_VERIFIED_CATEGORY_HEADER_NAME: &str = "X-Eidolon-Ingress-Verified-Category";
pub const INGRESS_ATTESTATION_REF_HEADER_NAME: &str = "X-Eidolon-Ingress-Attestation-Ref";
pub const INGRESS_VENDOR_SCORE_HEADER_NAME: &str = "X-Eidolon-Ingress-Vendor-Score";
pub const INGRESS_VENDOR_SCORE_KIND_HEADER_NAME: &str = "X-Eidolon-Ingress-Vendor-Score-Kind";
pub const INGRESS_VENDOR_SCORE_SCALE_HEADER_NAME: &str = "X-Eidolon-Ingress-Vendor-Score-Scale";
pub const INGRESS_DETECTION_IDS_HEADER_NAME: &str = "X-Eidolon-Ingress-Detection-Ids";
pub const INGRESS_EDGE_ACTION_HEADER_NAME: &str = "X-Eidolon-Ingress-Edge-Action";

const MIN_INGRESS_CONTINUITY_BYTES: usize = 16;
const MAX_INGRESS_CONTINUITY_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSource {
    /// A valid `SessionId` was recovered from the first-party session cookie.
    Cookie,
    /// No valid first-party cookie was present, so a request context was generated.
    Generated,
}

/// Reason a configured trusted-ingress continuity contract was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinuityInputRejection {
    MissingTransportAuth,
    DuplicateTransportAuth,
    InvalidTransportAuth,
    MissingContinuity,
    DuplicateContinuity,
    InvalidContinuity,
}

impl ContinuityInputRejection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingTransportAuth => "missing_transport_auth",
            Self::DuplicateTransportAuth => "duplicate_transport_auth",
            Self::InvalidTransportAuth => "invalid_transport_auth",
            Self::MissingContinuity => "missing_continuity",
            Self::DuplicateContinuity => "duplicate_continuity",
            Self::InvalidContinuity => "invalid_continuity",
        }
    }
}

/// Result of identifying the session for one proxied request.
///
/// Callers should reuse `session_id` for observation/intervention events and
/// emit `set_cookie_value` on the response when it returns `Some`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionContext {
    pub session_id: SessionId,
    pub source: SessionSource,
    pub cookie_outcome: CookieOutcome,
    pub key_status: Option<KeyStatus>,
    pub presented_key_version: Option<u32>,
    pub active_key_version: u32,
    pub continuity_outcome: ContinuityOutcome,
    pub continuity_source: Option<ContinuitySource>,
    pub enforcement_floor: Option<eidolon_core::PolicyState>,
    pub ingress_identity: IngressIdentity,
    pub authenticated_ingress_rule_rejection: Option<AuthenticatedIngressRuleRejection>,
    pub local_ingress_trust_scope_rejection: Option<LocalIngressTrustScopeRejection>,
    pub ingress_signals: IngressAdvisorySignals,
    pub trusted_ingress_soften_match: Option<TrustedIngressSoftenMatch>,
    pub trusted_bait_soften_path_prefixes: Option<Vec<String>>,
    continuity_key: Option<ContinuityKey>,
    set_cookie_value: Option<String>,
}

impl SessionContext {
    /// Whether the response should include a `Set-Cookie` header.
    pub fn should_set_cookie(&self) -> bool {
        self.set_cookie_value.is_some()
    }

    /// Formats a `Set-Cookie` value when this request created a new session.
    pub fn set_cookie_value(&self) -> Option<String> {
        self.set_cookie_value.clone()
    }

    pub fn continuity_key(&self) -> Option<ContinuityKey> {
        self.continuity_key
    }
}

/// Authenticate a session cookie or recover a bounded direct-peer continuity session.
pub fn derive_session_from_headers<I, N, V>(
    authority: &mut SessionAuthority,
    headers: I,
    peer_ip: Option<IpAddr>,
    now: u64,
) -> SessionContext
where
    I: IntoIterator<Item = (N, V)>,
    N: AsRef<str>,
    V: AsRef<str>,
{
    derive_session_from_headers_with_trusted_ingress_continuity(
        authority, headers, peer_ip, now, None, false, true,
    )
    .expect("Lab peer continuity has no authenticated ingress contract to reject")
}

/// Authenticate a session cookie and recover continuity from a trusted ingress.
///
/// Strict mode requires authenticated continuity on every request. Outside
/// strict mode, a presented continuity header must still authenticate, while
/// requests without one may use the explicitly enabled Lab peer fallback.
pub fn derive_session_from_headers_with_trusted_ingress_continuity<I, N, V>(
    authority: &mut SessionAuthority,
    headers: I,
    peer_ip: Option<IpAddr>,
    now: u64,
    ingress_transport_auth_secret: Option<&str>,
    require_authenticated_ingress_continuity: bool,
    allow_lab_peer_fallback: bool,
) -> Result<SessionContext, ContinuityInputRejection>
where
    I: IntoIterator<Item = (N, V)>,
    N: AsRef<str>,
    V: AsRef<str>,
{
    let headers: Vec<(String, String)> = headers
        .into_iter()
        .map(|(name, value)| (name.as_ref().to_string(), value.as_ref().to_string()))
        .collect();
    let ingress_identity = ingress_identity_from_headers(
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    );
    let ingress_signals = ingress_advisory_signals_from_headers(
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    );
    let continuity_header_present = headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(INGRESS_CONTINUITY_HEADER_NAME));
    let continuity_key = match (
        ingress_transport_auth_secret,
        require_authenticated_ingress_continuity || continuity_header_present,
    ) {
        (Some(shared_secret), true) => Some(authenticated_ingress_continuity_key_from_headers(
            headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
            shared_secret,
        )?),
        (None, true) => return Err(ContinuityInputRejection::MissingTransportAuth),
        (_, false) if allow_lab_peer_fallback => peer_ip.map(ContinuityKey::lab_peer),
        (_, false) => None,
    };

    let resolution = authority.resolve_with_continuity(
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
        continuity_key,
        now,
    );
    Ok(context_from_resolution(
        resolution,
        ingress_identity,
        ingress_signals,
        continuity_key,
    ))
}

fn context_from_resolution(
    resolution: SessionResolution,
    ingress_identity: IngressIdentity,
    ingress_signals: IngressAdvisorySignals,
    continuity_key: Option<ContinuityKey>,
) -> SessionContext {
    SessionContext {
        session_id: resolution.session_id,
        source: if resolution.from_cookie() {
            SessionSource::Cookie
        } else {
            SessionSource::Generated
        },
        cookie_outcome: resolution.cookie_outcome,
        key_status: resolution.key_status,
        presented_key_version: resolution.presented_key_version,
        active_key_version: resolution.active_key_version,
        continuity_outcome: resolution.continuity_outcome,
        continuity_source: resolution.continuity_source,
        enforcement_floor: resolution.enforcement_floor,
        ingress_identity,
        authenticated_ingress_rule_rejection: None,
        local_ingress_trust_scope_rejection: None,
        ingress_signals,
        trusted_ingress_soften_match: None,
        trusted_bait_soften_path_prefixes: None,
        continuity_key,
        set_cookie_value: resolution.set_cookie_value,
    }
}

/// Derive a minimized continuity key only from one authenticated ingress value.
pub(crate) fn authenticated_ingress_continuity_key_from_headers<I, N, V>(
    headers: I,
    shared_secret: &str,
) -> Result<ContinuityKey, ContinuityInputRejection>
where
    I: IntoIterator<Item = (N, V)>,
    N: AsRef<str>,
    V: AsRef<str>,
{
    let shared_secret = shared_secret.trim();
    let headers: Vec<(String, String)> = headers
        .into_iter()
        .map(|(name, value)| (name.as_ref().to_string(), value.as_ref().to_string()))
        .collect();

    let transport_auth: Vec<&str> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(INGRESS_TRANSPORT_AUTH_HEADER_NAME))
        .map(|(_, value)| value.as_str())
        .collect();
    let presented_auth = match transport_auth.as_slice() {
        [] => return Err(ContinuityInputRejection::MissingTransportAuth),
        [value] => *value,
        _ => return Err(ContinuityInputRejection::DuplicateTransportAuth),
    };
    if shared_secret.is_empty() || presented_auth != shared_secret {
        return Err(ContinuityInputRejection::InvalidTransportAuth);
    }

    let continuity: Vec<&str> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(INGRESS_CONTINUITY_HEADER_NAME))
        .map(|(_, value)| value.as_str())
        .collect();
    let raw = match continuity.as_slice() {
        [] => return Err(ContinuityInputRejection::MissingContinuity),
        [value] => value.trim(),
        _ => return Err(ContinuityInputRejection::DuplicateContinuity),
    };
    if !valid_ingress_continuity_value(raw) {
        return Err(ContinuityInputRejection::InvalidContinuity);
    }

    Ok(ContinuityKey::authenticated_ingress(raw, shared_secret))
}

fn valid_ingress_continuity_value(raw: &str) -> bool {
    (MIN_INGRESS_CONTINUITY_BYTES..=MAX_INGRESS_CONTINUITY_BYTES).contains(&raw.len())
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// Return a normalized ingress identity claim from explicit Eidolon trust headers.
///
/// This is intentionally passive in the first trust-plane slice: the derived
/// identity is auditable metadata only and does not imply policy exemption.
pub fn ingress_identity_from_headers<I, N, V>(headers: I) -> IngressIdentity
where
    I: IntoIterator<Item = (N, V)>,
    N: AsRef<str>,
    V: AsRef<str>,
{
    let mut source = None;
    let mut trust_tier = None;
    let mut label = None;
    let mut expires_at = None;

    for (name, value) in headers {
        let name = name.as_ref();
        let value = value.as_ref().trim();

        if name.eq_ignore_ascii_case(INGRESS_IDENTITY_SOURCE_HEADER_NAME) {
            source = parse_ingress_identity_source(value);
        } else if name.eq_ignore_ascii_case(INGRESS_TRUST_TIER_HEADER_NAME) {
            trust_tier = parse_ingress_trust_tier(value);
        } else if name.eq_ignore_ascii_case(INGRESS_IDENTITY_LABEL_HEADER_NAME) {
            label = (!value.is_empty()).then(|| value.to_string());
        } else if name.eq_ignore_ascii_case(INGRESS_IDENTITY_EXPIRES_AT_HEADER_NAME) {
            expires_at = parse_rfc3339_utc(value);
        }
    }

    match (source, trust_tier) {
        (Some(source), Some(trust_tier)) => stale_ingress_identity_to_weakly_asserted(
            IngressIdentity {
                source,
                trust_tier,
                label,
                not_before: None,
                expires_at,
            },
            Utc::now(),
        ),
        _ => IngressIdentity::default(),
    }
}

/// Return normalized advisory ingress signals from explicit Eidolon headers.
///
/// These signals are kept separate from normalized ingress identity so runtime
/// policy can treat verification, score, and edge hints as advisory inputs
/// instead of identity or proof.
pub fn ingress_advisory_signals_from_headers<I, N, V>(headers: I) -> IngressAdvisorySignals
where
    I: IntoIterator<Item = (N, V)>,
    N: AsRef<str>,
    V: AsRef<str>,
{
    let mut signals = IngressAdvisorySignals::default();

    for (name, value) in headers {
        let name = name.as_ref();
        let value = value.as_ref().trim();

        if name.eq_ignore_ascii_case(INGRESS_VERIFICATION_STRENGTH_HEADER_NAME) {
            if let Some(parsed) = parse_ingress_verification_strength(value) {
                signals.verification_strength = parsed;
            }
        } else if name.eq_ignore_ascii_case(INGRESS_ACTOR_KIND_HEADER_NAME) {
            if let Some(parsed) = parse_ingress_actor_kind(value) {
                signals.actor_kind = parsed;
            }
        } else if name.eq_ignore_ascii_case(INGRESS_VERIFIED_CATEGORY_HEADER_NAME) {
            signals.verified_category = parse_non_empty_header(value);
        } else if name.eq_ignore_ascii_case(INGRESS_ATTESTATION_REF_HEADER_NAME) {
            signals.attestation_ref = parse_non_empty_header(value);
        } else if name.eq_ignore_ascii_case(INGRESS_VENDOR_SCORE_HEADER_NAME) {
            signals.vendor_score = value.parse().ok();
        } else if name.eq_ignore_ascii_case(INGRESS_VENDOR_SCORE_KIND_HEADER_NAME) {
            signals.vendor_score_kind = parse_non_empty_header(value);
        } else if name.eq_ignore_ascii_case(INGRESS_VENDOR_SCORE_SCALE_HEADER_NAME) {
            signals.vendor_score_scale = parse_non_empty_header(value);
        } else if name.eq_ignore_ascii_case(INGRESS_DETECTION_IDS_HEADER_NAME) {
            signals.detection_ids = parse_detection_ids(value);
        } else if name.eq_ignore_ascii_case(INGRESS_EDGE_ACTION_HEADER_NAME) {
            signals.edge_action = parse_edge_recommended_action(value);
        }
    }

    signals
}

/// Return a normalized ingress identity only when the transport-auth header
/// matches the configured shared secret.
///
/// This keeps direct callers from minting trusted ingress identities on paths
/// that are not fronted by an attesting edge adapter.
pub fn authenticated_ingress_identity_from_headers<I, N, V>(
    headers: I,
    shared_secret: Option<&str>,
) -> IngressIdentity
where
    I: IntoIterator<Item = (N, V)>,
    N: AsRef<str>,
    V: AsRef<str>,
{
    let Some(shared_secret) = shared_secret
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return IngressIdentity::default();
    };

    let headers: Vec<(String, String)> = headers
        .into_iter()
        .map(|(name, value)| (name.as_ref().to_string(), value.as_ref().to_string()))
        .collect();
    let authenticated = headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case(INGRESS_TRANSPORT_AUTH_HEADER_NAME) && value == shared_secret
    });
    if !authenticated {
        return IngressIdentity::default();
    }

    ingress_identity_from_headers(
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    )
}

/// Return normalized advisory ingress signals only when the transport-auth
/// header matches the configured shared secret.
pub fn authenticated_ingress_advisory_signals_from_headers<I, N, V>(
    headers: I,
    shared_secret: Option<&str>,
) -> IngressAdvisorySignals
where
    I: IntoIterator<Item = (N, V)>,
    N: AsRef<str>,
    V: AsRef<str>,
{
    let Some(shared_secret) = shared_secret
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return IngressAdvisorySignals::default();
    };

    let headers: Vec<(String, String)> = headers
        .into_iter()
        .map(|(name, value)| (name.as_ref().to_string(), value.as_ref().to_string()))
        .collect();
    let authenticated = headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case(INGRESS_TRANSPORT_AUTH_HEADER_NAME) && value == shared_secret
    });
    if !authenticated {
        return IngressAdvisorySignals::default();
    }

    ingress_advisory_signals_from_headers(
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    )
}

fn parse_ingress_identity_source(value: &str) -> Option<IngressIdentitySource> {
    Some(match value {
        "none" => IngressIdentitySource::None,
        "internal_scanner" => IngressIdentitySource::InternalScanner,
        "local_allowlist" => IngressIdentitySource::LocalAllowlist,
        "verified_bot" => IngressIdentitySource::VerifiedBot,
        "signed_agent" => IngressIdentitySource::SignedAgent,
        "partner_automation" => IngressIdentitySource::PartnerAutomation,
        "operator_override" => IngressIdentitySource::OperatorOverride,
        _ => return None,
    })
}

fn parse_ingress_trust_tier(value: &str) -> Option<IngressTrustTier> {
    Some(match value {
        "none" => IngressTrustTier::None,
        "weakly_asserted" => IngressTrustTier::WeaklyAsserted,
        "allowlisted" => IngressTrustTier::Allowlisted,
        "edge_verified" => IngressTrustTier::EdgeVerified,
        "signed_attested" => IngressTrustTier::SignedAttested,
        _ => return None,
    })
}

fn parse_ingress_verification_strength(value: &str) -> Option<IngressVerificationStrength> {
    Some(match value {
        "none" => IngressVerificationStrength::None,
        "low" => IngressVerificationStrength::Low,
        "medium" => IngressVerificationStrength::Medium,
        "high" => IngressVerificationStrength::High,
        "cryptographic" => IngressVerificationStrength::Cryptographic,
        _ => return None,
    })
}

fn parse_ingress_actor_kind(value: &str) -> Option<IngressActorKind> {
    Some(match value {
        "unknown" => IngressActorKind::Unknown,
        "crawler" => IngressActorKind::Crawler,
        "assistant" => IngressActorKind::Assistant,
        "autonomous_agent" => IngressActorKind::AutonomousAgent,
        "agentic_browser" => IngressActorKind::AgenticBrowser,
        "partner_automation" => IngressActorKind::PartnerAutomation,
        "internal_scanner" => IngressActorKind::InternalScanner,
        _ => return None,
    })
}

fn parse_edge_recommended_action(value: &str) -> Option<EdgeRecommendedAction> {
    Some(match value {
        "allow" => EdgeRecommendedAction::Allow,
        "observe" => EdgeRecommendedAction::Observe,
        "rate_limit" => EdgeRecommendedAction::RateLimit,
        "challenge" => EdgeRecommendedAction::Challenge,
        "block" => EdgeRecommendedAction::Block,
        "preserve_eidolon_routing" => EdgeRecommendedAction::PreserveEidolonRouting,
        _ => return None,
    })
}

fn parse_non_empty_header(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}

fn parse_detection_ids(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_rfc3339_utc(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn stale_ingress_identity_to_weakly_asserted(
    mut identity: IngressIdentity,
    now: DateTime<Utc>,
) -> IngressIdentity {
    let Some(expires_at) = identity.expires_at else {
        return identity;
    };
    if expires_at > now {
        return identity;
    }

    if matches!(
        identity.trust_tier,
        IngressTrustTier::Allowlisted
            | IngressTrustTier::EdgeVerified
            | IngressTrustTier::SignedAttested
    ) {
        identity.trust_tier = IngressTrustTier::WeaklyAsserted;
    }

    identity
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_auth::SessionKeyVersion;

    const NOW: u64 = 1_750_000_000;

    fn test_session_authority() -> SessionAuthority {
        SessionAuthority::new(
            vec![SessionKeyVersion {
                version: 1,
                key: [0x42; 32],
            }],
            1,
        )
        .expect("test session authority should build")
    }

    #[test]
    fn uses_existing_valid_cookie() {
        let mut authority = test_session_authority();
        let expected = SessionId::new();
        let cookie = format!(
            "{}={}",
            SESSION_COOKIE_NAME,
            authority.mint_cookie_value(expected, NOW)
        );

        let context = derive_session_from_headers(&mut authority, [("Cookie", cookie)], None, NOW);

        assert_eq!(context.session_id, expected);
        assert_eq!(context.source, SessionSource::Cookie);
        assert_eq!(context.cookie_outcome, CookieOutcome::Valid);
        assert_eq!(context.ingress_identity, IngressIdentity::default());
        assert_eq!(context.ingress_signals, IngressAdvisorySignals::default());
        assert!(!context.should_set_cookie());
        assert_eq!(context.set_cookie_value(), None);
    }

    #[test]
    fn generates_session_when_cookie_absent() {
        let mut authority = test_session_authority();

        let context =
            derive_session_from_headers(&mut authority, [("Host", "127.0.0.1:8080")], None, NOW);

        assert_eq!(context.source, SessionSource::Generated);
        assert_eq!(context.cookie_outcome, CookieOutcome::Absent);
        assert_eq!(context.ingress_identity, IngressIdentity::default());
        assert_eq!(context.ingress_signals, IngressAdvisorySignals::default());
        assert!(context.should_set_cookie());
        let set_cookie = context.set_cookie_value().expect("cookie should be minted");
        assert!(set_cookie.starts_with(&format!("{}=v1.1.", SESSION_COOKIE_NAME)));
        assert!(set_cookie.contains(&context.session_id.0.to_string()));
    }

    #[test]
    fn generates_session_when_cookie_is_invalid() {
        let mut authority = test_session_authority();

        let context = derive_session_from_headers(
            &mut authority,
            [("Cookie", "eidolon_session=not-a-uuid; other=value")],
            None,
            NOW,
        );

        assert_eq!(context.source, SessionSource::Generated);
        assert_eq!(context.cookie_outcome, CookieOutcome::Malformed);
        assert_eq!(context.ingress_identity, IngressIdentity::default());
        assert_eq!(context.ingress_signals, IngressAdvisorySignals::default());
        assert!(context.should_set_cookie());
    }

    #[test]
    fn finds_valid_session_among_multiple_cookies() {
        let mut authority = test_session_authority();
        let expected = SessionId::new();
        let minted = authority.mint_cookie_value(expected, NOW);
        let cookie = format!(
            "theme=light; malformed; other=value; {}={}",
            SESSION_COOKIE_NAME, minted
        );

        let context = derive_session_from_headers(
            &mut authority,
            [("Host", "127.0.0.1:8080".to_string()), ("cookie", cookie)],
            None,
            NOW,
        );

        assert_eq!(context.session_id, expected);
        assert_eq!(context.source, SessionSource::Cookie);
        assert_eq!(context.ingress_identity, IngressIdentity::default());
        assert_eq!(context.ingress_signals, IngressAdvisorySignals::default());
        assert!(!context.should_set_cookie());
    }

    #[test]
    fn formats_set_cookie_for_local_http_lab() {
        let authority = test_session_authority();
        let session_id = SessionId::new();

        let value = authority.mint_set_cookie_value(session_id, NOW);

        assert!(value.starts_with(&format!("{}=v1.1.", SESSION_COOKIE_NAME)));
        assert!(value.contains(&session_id.0.to_string()));
        assert!(value.ends_with(&format!(
            "; Path={}; HttpOnly; SameSite={}",
            SESSION_COOKIE_PATH, SESSION_COOKIE_SAME_SITE
        )));
        assert!(!value.contains("Domain="));
        assert!(!value.contains("Max-Age="));
        assert!(!value.contains("Expires="));
        assert!(!value.contains("Secure"));
    }

    #[test]
    fn derives_normalized_ingress_identity_from_headers() {
        let mut authority = test_session_authority();

        let context = derive_session_from_headers(
            &mut authority,
            [
                ("Host", "proxy.local"),
                (INGRESS_IDENTITY_SOURCE_HEADER_NAME, "operator_override"),
                (INGRESS_TRUST_TIER_HEADER_NAME, "allowlisted"),
                (INGRESS_IDENTITY_LABEL_HEADER_NAME, "internal-crawler"),
                (
                    INGRESS_IDENTITY_EXPIRES_AT_HEADER_NAME,
                    "2999-06-04T12:00:00Z",
                ),
            ],
            None,
            NOW,
        );

        assert_eq!(context.source, SessionSource::Generated);
        assert_eq!(
            context.ingress_identity,
            IngressIdentity {
                source: IngressIdentitySource::OperatorOverride,
                trust_tier: IngressTrustTier::Allowlisted,
                label: Some("internal-crawler".to_string()),
                not_before: None,
                expires_at: Some(
                    DateTime::parse_from_rfc3339("2999-06-04T12:00:00Z")
                        .expect("timestamp should parse")
                        .with_timezone(&Utc),
                ),
            }
        );
        assert_eq!(context.ingress_signals, IngressAdvisorySignals::default());
    }

    #[test]
    fn ignores_incomplete_or_invalid_ingress_identity_claims() {
        let missing_tier = ingress_identity_from_headers([
            (INGRESS_IDENTITY_SOURCE_HEADER_NAME, "verified_bot"),
            (INGRESS_IDENTITY_LABEL_HEADER_NAME, "googlebot"),
        ]);
        let invalid_tier = ingress_identity_from_headers([
            (INGRESS_IDENTITY_SOURCE_HEADER_NAME, "verified_bot"),
            (INGRESS_TRUST_TIER_HEADER_NAME, "definitely-real"),
        ]);

        assert_eq!(missing_tier, IngressIdentity::default());
        assert_eq!(invalid_tier, IngressIdentity::default());
    }

    #[test]
    fn derives_advisory_ingress_signals_from_headers() {
        let mut authority = test_session_authority();

        let context = derive_session_from_headers(
            &mut authority,
            [
                ("Host", "proxy.local"),
                (INGRESS_VERIFICATION_STRENGTH_HEADER_NAME, "cryptographic"),
                (INGRESS_ACTOR_KIND_HEADER_NAME, "agentic_browser"),
                (INGRESS_VERIFIED_CATEGORY_HEADER_NAME, "AI Assistant"),
                (INGRESS_ATTESTATION_REF_HEADER_NAME, "jkt:sha256:ba3e64"),
                (INGRESS_VENDOR_SCORE_HEADER_NAME, "12"),
                (
                    INGRESS_VENDOR_SCORE_KIND_HEADER_NAME,
                    "automation_likelihood_inverse",
                ),
                (INGRESS_VENDOR_SCORE_SCALE_HEADER_NAME, "1-99"),
                (INGRESS_DETECTION_IDS_HEADER_NAME, "3355446, 445566"),
                (INGRESS_EDGE_ACTION_HEADER_NAME, "allow"),
            ],
            None,
            NOW,
        );

        assert_eq!(
            context.ingress_signals,
            IngressAdvisorySignals {
                verification_strength: IngressVerificationStrength::Cryptographic,
                actor_kind: IngressActorKind::AgenticBrowser,
                verified_category: Some("AI Assistant".to_string()),
                attestation_ref: Some("jkt:sha256:ba3e64".to_string()),
                vendor_score: Some(12),
                vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                vendor_score_scale: Some("1-99".to_string()),
                detection_ids: vec!["3355446".to_string(), "445566".to_string()],
                edge_action: Some(EdgeRecommendedAction::Allow),
            }
        );
    }

    #[test]
    fn ignores_invalid_advisory_ingress_signals() {
        let signals = ingress_advisory_signals_from_headers([
            (INGRESS_VERIFICATION_STRENGTH_HEADER_NAME, "very-real"),
            (INGRESS_ACTOR_KIND_HEADER_NAME, "definitely-normal"),
            (INGRESS_VENDOR_SCORE_HEADER_NAME, "not-a-number"),
            (INGRESS_EDGE_ACTION_HEADER_NAME, "permit"),
            (INGRESS_DETECTION_IDS_HEADER_NAME, " , "),
        ]);

        assert_eq!(signals, IngressAdvisorySignals::default());
    }

    #[test]
    fn authenticated_ingress_identity_requires_matching_transport_secret() {
        let headers = [
            (INGRESS_IDENTITY_SOURCE_HEADER_NAME, "signed_agent"),
            (INGRESS_TRUST_TIER_HEADER_NAME, "signed_attested"),
            (INGRESS_IDENTITY_LABEL_HEADER_NAME, "edge-signed-agent"),
            (INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
        ];

        assert_eq!(
            authenticated_ingress_identity_from_headers(headers, None),
            IngressIdentity::default()
        );
        assert_eq!(
            authenticated_ingress_identity_from_headers(headers, Some("wrong-secret")),
            IngressIdentity::default()
        );

        let identity = authenticated_ingress_identity_from_headers(headers, Some("edge-secret"));
        assert_eq!(identity.source, IngressIdentitySource::SignedAgent);
        assert_eq!(identity.trust_tier, IngressTrustTier::SignedAttested);
        assert_eq!(identity.label.as_deref(), Some("edge-signed-agent"));
    }

    #[test]
    fn authenticated_continuity_separates_clients_behind_one_ingress_peer() {
        let mut authority = test_session_authority();
        let peer: IpAddr = "10.0.0.10".parse().expect("peer IP should parse");
        let first = derive_session_from_headers_with_trusted_ingress_continuity(
            &mut authority,
            [
                (INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
                (INGRESS_CONTINUITY_HEADER_NAME, "client_A_0123456789abcdef"),
            ],
            Some(peer),
            NOW,
            Some("edge-secret"),
            true,
            false,
        )
        .expect("first authenticated continuity should resolve");
        let second = derive_session_from_headers_with_trusted_ingress_continuity(
            &mut authority,
            [
                (INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
                (INGRESS_CONTINUITY_HEADER_NAME, "client_B_0123456789abcdef"),
            ],
            Some(peer),
            NOW + 1,
            Some("edge-secret"),
            true,
            false,
        )
        .expect("second authenticated continuity should resolve");
        let recovered_first = derive_session_from_headers_with_trusted_ingress_continuity(
            &mut authority,
            [
                (INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
                (INGRESS_CONTINUITY_HEADER_NAME, "client_A_0123456789abcdef"),
            ],
            Some(peer),
            NOW + 5,
            Some("edge-secret"),
            true,
            false,
        )
        .expect("same authenticated continuity should recover");

        assert_ne!(first.session_id, second.session_id);
        assert_eq!(recovered_first.session_id, first.session_id);
        assert_eq!(
            recovered_first.continuity_source,
            Some(ContinuitySource::AuthenticatedIngress)
        );
        assert_eq!(
            recovered_first.continuity_outcome,
            ContinuityOutcome::Recovered
        );
    }

    #[test]
    fn configured_secret_without_continuity_preserves_lab_peer_fallback() {
        let mut authority = test_session_authority();
        let peer: IpAddr = "10.0.0.10".parse().expect("peer IP should parse");
        let first = derive_session_from_headers_with_trusted_ingress_continuity(
            &mut authority,
            [(INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret")],
            Some(peer),
            NOW,
            Some("edge-secret"),
            false,
            true,
        )
        .expect("non-strict Lab request should resolve");
        let recovered = derive_session_from_headers_with_trusted_ingress_continuity(
            &mut authority,
            [("Host", "proxy.local")],
            Some(peer),
            NOW + 1,
            Some("edge-secret"),
            false,
            true,
        )
        .expect("ordinary Lab request should preserve peer continuity");

        assert_eq!(recovered.session_id, first.session_id);
        assert_eq!(recovered.continuity_outcome, ContinuityOutcome::Recovered);
        assert_eq!(recovered.continuity_source, Some(ContinuitySource::LabPeer));
    }

    #[test]
    fn forged_or_unsigned_continuity_is_not_trusted() {
        let mut authority = test_session_authority();
        let raw = "client_A_0123456789abcdef";
        let legitimate = derive_session_from_headers_with_trusted_ingress_continuity(
            &mut authority,
            [
                (INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
                (INGRESS_CONTINUITY_HEADER_NAME, raw),
            ],
            None,
            NOW,
            Some("edge-secret"),
            true,
            false,
        )
        .expect("legitimate continuity should resolve");
        let forged = derive_session_from_headers_with_trusted_ingress_continuity(
            &mut authority,
            [
                (INGRESS_TRANSPORT_AUTH_HEADER_NAME, "wrong-secret"),
                (INGRESS_CONTINUITY_HEADER_NAME, raw),
            ],
            None,
            NOW + 1,
            Some("edge-secret"),
            true,
            false,
        )
        .expect_err("forged transport auth must fail closed");
        let unsigned = derive_session_from_headers_with_trusted_ingress_continuity(
            &mut authority,
            [(INGRESS_CONTINUITY_HEADER_NAME, raw)],
            None,
            NOW + 2,
            Some("edge-secret"),
            true,
            false,
        )
        .expect_err("unsigned continuity must fail closed");

        assert_eq!(
            legitimate.continuity_source,
            Some(ContinuitySource::AuthenticatedIngress)
        );
        assert_eq!(forged, ContinuityInputRejection::InvalidTransportAuth);
        assert_eq!(unsigned, ContinuityInputRejection::MissingTransportAuth);
    }

    #[test]
    fn authenticated_continuity_survives_cookie_discard_with_enforcement_floor() {
        let mut authority = test_session_authority();
        let headers = [
            (INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
            (INGRESS_CONTINUITY_HEADER_NAME, "client_A_0123456789abcdef"),
        ];
        let original = derive_session_from_headers_with_trusted_ingress_continuity(
            &mut authority,
            headers,
            None,
            NOW,
            Some("edge-secret"),
            true,
            false,
        )
        .expect("authenticated continuity should resolve");
        authority.note_enforcement_with_continuity(
            original.continuity_key(),
            original.session_id,
            eidolon_core::PolicyState::Blocked,
            NOW + 1,
        );

        let recovered = derive_session_from_headers_with_trusted_ingress_continuity(
            &mut authority,
            headers,
            None,
            NOW + 5,
            Some("edge-secret"),
            true,
            false,
        )
        .expect("authenticated continuity should recover");

        assert_eq!(recovered.session_id, original.session_id);
        assert_eq!(
            recovered.enforcement_floor,
            Some(eidolon_core::PolicyState::Blocked)
        );
        assert_eq!(recovered.continuity_outcome, ContinuityOutcome::Recovered);
    }

    #[test]
    fn continuity_raw_value_is_not_exposed_and_restart_requires_cookie() {
        let raw = "client_A_0123456789abcdef";
        let headers = [
            (INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
            (INGRESS_CONTINUITY_HEADER_NAME, raw),
        ];
        let mut first_authority = test_session_authority();
        let original = derive_session_from_headers_with_trusted_ingress_continuity(
            &mut first_authority,
            headers,
            None,
            NOW,
            Some("edge-secret"),
            true,
            false,
        )
        .expect("authenticated continuity should resolve");
        let key = original
            .continuity_key()
            .expect("authenticated continuity should produce a key");
        assert!(!format!("{key:?}").contains(raw));

        let mut restarted_without_cookie = test_session_authority();
        let lost = derive_session_from_headers_with_trusted_ingress_continuity(
            &mut restarted_without_cookie,
            headers,
            None,
            NOW + 1,
            Some("edge-secret"),
            true,
            false,
        )
        .expect("authenticated continuity remains valid after restart");
        assert_ne!(lost.session_id, original.session_id);
        assert_eq!(lost.continuity_outcome, ContinuityOutcome::NoRecord);

        let cookie = format!(
            "{}={}",
            SESSION_COOKIE_NAME,
            first_authority.mint_cookie_value(original.session_id, NOW)
        );
        let mut restarted_with_cookie = test_session_authority();
        let restored = derive_session_from_headers_with_trusted_ingress_continuity(
            &mut restarted_with_cookie,
            [
                ("Cookie", cookie.as_str()),
                (INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
                (INGRESS_CONTINUITY_HEADER_NAME, raw),
            ],
            None,
            NOW + 1,
            Some("edge-secret"),
            true,
            false,
        )
        .expect("valid signed cookie should survive restart");
        assert_eq!(restored.session_id, original.session_id);
        assert_eq!(restored.cookie_outcome, CookieOutcome::Valid);
    }

    #[test]
    fn malformed_or_ambiguous_continuity_values_are_rejected() {
        let valid = "client_A_0123456789abcdef";
        assert!(authenticated_ingress_continuity_key_from_headers(
            [
                (INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
                (INGRESS_CONTINUITY_HEADER_NAME, valid),
            ],
            "edge-secret",
        )
        .is_ok());
        for invalid in ["short", "contains spaces 1234", "contains/slash/1234"] {
            assert!(
                authenticated_ingress_continuity_key_from_headers(
                    [
                        (INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
                        (INGRESS_CONTINUITY_HEADER_NAME, invalid),
                    ],
                    "edge-secret",
                ) == Err(ContinuityInputRejection::InvalidContinuity)
            );
        }
        let oversized = "a".repeat(MAX_INGRESS_CONTINUITY_BYTES + 1);
        assert_eq!(
            authenticated_ingress_continuity_key_from_headers(
                [
                    (INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
                    (INGRESS_CONTINUITY_HEADER_NAME, oversized.as_str()),
                ],
                "edge-secret",
            ),
            Err(ContinuityInputRejection::InvalidContinuity)
        );
        assert_eq!(
            authenticated_ingress_continuity_key_from_headers(
                [(INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret")],
                "edge-secret",
            ),
            Err(ContinuityInputRejection::MissingContinuity)
        );
        assert_eq!(
            authenticated_ingress_continuity_key_from_headers(
                [
                    (INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
                    (INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
                    (INGRESS_CONTINUITY_HEADER_NAME, valid),
                ],
                "edge-secret",
            ),
            Err(ContinuityInputRejection::DuplicateTransportAuth)
        );
        assert!(
            authenticated_ingress_continuity_key_from_headers(
                [
                    (INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
                    (INGRESS_CONTINUITY_HEADER_NAME, valid),
                    (INGRESS_CONTINUITY_HEADER_NAME, "client_B_0123456789abcdef",),
                ],
                "edge-secret",
            ) == Err(ContinuityInputRejection::DuplicateContinuity)
        );
    }

    #[test]
    fn stale_authenticated_ingress_identity_degrades_to_weakly_asserted() {
        let identity = authenticated_ingress_identity_from_headers(
            [
                (INGRESS_IDENTITY_SOURCE_HEADER_NAME, "signed_agent"),
                (INGRESS_TRUST_TIER_HEADER_NAME, "signed_attested"),
                (INGRESS_IDENTITY_LABEL_HEADER_NAME, "edge-signed-agent"),
                (
                    INGRESS_IDENTITY_EXPIRES_AT_HEADER_NAME,
                    "2000-01-01T00:00:00Z",
                ),
                (INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
            ],
            Some("edge-secret"),
        );

        assert_eq!(identity.source, IngressIdentitySource::SignedAgent);
        assert_eq!(identity.trust_tier, IngressTrustTier::WeaklyAsserted);
        assert_eq!(identity.label.as_deref(), Some("edge-signed-agent"));
        assert_eq!(
            identity.expires_at,
            Some(
                DateTime::parse_from_rfc3339("2000-01-01T00:00:00Z")
                    .expect("timestamp should parse")
                    .with_timezone(&Utc),
            )
        );
    }

    #[test]
    fn authenticated_ingress_signals_require_matching_transport_secret() {
        let headers = [
            (INGRESS_VERIFICATION_STRENGTH_HEADER_NAME, "high"),
            (INGRESS_ACTOR_KIND_HEADER_NAME, "crawler"),
            (INGRESS_VENDOR_SCORE_HEADER_NAME, "91"),
            (INGRESS_EDGE_ACTION_HEADER_NAME, "observe"),
            (INGRESS_TRANSPORT_AUTH_HEADER_NAME, "edge-secret"),
        ];

        assert_eq!(
            authenticated_ingress_advisory_signals_from_headers(headers, None),
            IngressAdvisorySignals::default()
        );
        assert_eq!(
            authenticated_ingress_advisory_signals_from_headers(headers, Some("wrong-secret")),
            IngressAdvisorySignals::default()
        );

        let signals =
            authenticated_ingress_advisory_signals_from_headers(headers, Some("edge-secret"));
        assert_eq!(
            signals.verification_strength,
            IngressVerificationStrength::High
        );
        assert_eq!(signals.actor_kind, IngressActorKind::Crawler);
        assert_eq!(signals.vendor_score, Some(91));
        assert_eq!(signals.edge_action, Some(EdgeRecommendedAction::Observe));
    }
}
