use chrono::{DateTime, Utc};
use eidolon_core::{
    EdgeRecommendedAction, IngressActorKind, IngressAdvisorySignals, IngressIdentity,
    IngressIdentitySource, IngressTrustTier, IngressVerificationStrength,
    LocalIngressTrustScopeRejection, SessionId, TrustedIngressSoftenMatch,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSource {
    /// A valid `SessionId` was recovered from the first-party session cookie.
    Cookie,
    /// No valid first-party cookie was present, so a request context was generated.
    Generated,
}

/// Result of identifying the session for one proxied request.
///
/// Callers should reuse `session_id` for observation/intervention events and
/// emit `set_cookie_value` on the response when it returns `Some`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionContext {
    pub session_id: SessionId,
    pub source: SessionSource,
    pub ingress_identity: IngressIdentity,
    pub local_ingress_trust_scope_rejection: Option<LocalIngressTrustScopeRejection>,
    pub ingress_signals: IngressAdvisorySignals,
    pub trusted_ingress_soften_match: Option<TrustedIngressSoftenMatch>,
    pub trusted_bait_soften_path_prefixes: Option<Vec<String>>,
}

impl SessionContext {
    /// Whether the response should include a `Set-Cookie` header.
    pub fn should_set_cookie(&self) -> bool {
        matches!(self.source, SessionSource::Generated)
    }

    /// Formats a `Set-Cookie` value when this request created a new session.
    pub fn set_cookie_value(&self) -> Option<String> {
        self.should_set_cookie()
            .then(|| format_set_cookie(self.session_id))
    }
}

/// Derive a session from request headers or create a new generated context.
///
/// Header names are matched case-insensitively. Malformed cookie pairs and
/// non-UUID values for the Eidolon session cookie are ignored.
pub fn derive_session_from_headers<I, N, V>(headers: I) -> SessionContext
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

    if let Some(session_id) = session_id_from_headers(
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    ) {
        SessionContext {
            session_id,
            source: SessionSource::Cookie,
            ingress_identity,
            local_ingress_trust_scope_rejection: None,
            ingress_signals,
            trusted_ingress_soften_match: None,
            trusted_bait_soften_path_prefixes: None,
        }
    } else {
        SessionContext {
            session_id: SessionId::new(),
            source: SessionSource::Generated,
            ingress_identity,
            local_ingress_trust_scope_rejection: None,
            ingress_signals,
            trusted_ingress_soften_match: None,
            trusted_bait_soften_path_prefixes: None,
        }
    }
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

/// Return the first valid Eidolon session found in any inbound `Cookie` header.
pub fn session_id_from_headers<I, N, V>(headers: I) -> Option<SessionId>
where
    I: IntoIterator<Item = (N, V)>,
    N: AsRef<str>,
    V: AsRef<str>,
{
    headers
        .into_iter()
        .filter(|(name, _)| name.as_ref().eq_ignore_ascii_case(COOKIE_HEADER_NAME))
        .find_map(|(_, value)| session_id_from_cookie_header(value.as_ref()))
}

/// Parse one raw `Cookie` header value for the Eidolon session cookie.
pub fn session_id_from_cookie_header(header_value: &str) -> Option<SessionId> {
    header_value
        .split(';')
        .filter_map(cookie_pair)
        .filter(|(name, _)| *name == SESSION_COOKIE_NAME)
        .find_map(|(_, value)| parse_session_id(value))
}

/// Format a local-lab `Set-Cookie` header value for a generated session.
pub fn format_set_cookie(session_id: SessionId) -> String {
    format!(
        "{}={}; {}",
        SESSION_COOKIE_NAME, session_id.0, SESSION_COOKIE_ATTRIBUTES
    )
}

fn cookie_pair(raw: &str) -> Option<(&str, &str)> {
    let (name, value) = raw.trim().split_once('=')?;
    let name = name.trim();
    let value = value.trim();

    (!name.is_empty() && !value.is_empty()).then_some((name, value))
}

fn parse_session_id(value: &str) -> Option<SessionId> {
    Some(SessionId(value.parse().ok()?))
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

    #[test]
    fn uses_existing_valid_cookie() {
        let expected = SessionId::new();
        let cookie = format!("{}={}", SESSION_COOKIE_NAME, expected.0);

        let context = derive_session_from_headers([("Cookie", cookie)]);

        assert_eq!(context.session_id, expected);
        assert_eq!(context.source, SessionSource::Cookie);
        assert_eq!(context.ingress_identity, IngressIdentity::default());
        assert_eq!(context.ingress_signals, IngressAdvisorySignals::default());
        assert!(!context.should_set_cookie());
        assert_eq!(context.set_cookie_value(), None);
    }

    #[test]
    fn generates_session_when_cookie_absent() {
        let context = derive_session_from_headers([("Host", "127.0.0.1:8080")]);

        assert_eq!(context.source, SessionSource::Generated);
        assert_eq!(context.ingress_identity, IngressIdentity::default());
        assert_eq!(context.ingress_signals, IngressAdvisorySignals::default());
        assert!(context.should_set_cookie());
        assert_eq!(
            context.set_cookie_value(),
            Some(format_set_cookie(context.session_id))
        );
    }

    #[test]
    fn generates_session_when_cookie_is_invalid() {
        let context =
            derive_session_from_headers([("Cookie", "eidolon_session=not-a-uuid; other=value")]);

        assert_eq!(context.source, SessionSource::Generated);
        assert_eq!(context.ingress_identity, IngressIdentity::default());
        assert_eq!(context.ingress_signals, IngressAdvisorySignals::default());
        assert!(context.should_set_cookie());
    }

    #[test]
    fn finds_valid_session_among_multiple_cookies() {
        let expected = SessionId::new();
        let cookie = format!(
            "theme=light; malformed; {}=not-a-uuid; other=value; {}={}",
            SESSION_COOKIE_NAME, SESSION_COOKIE_NAME, expected.0
        );

        let context = derive_session_from_headers([
            ("Host", "127.0.0.1:8080".to_string()),
            ("cookie", cookie),
        ]);

        assert_eq!(context.session_id, expected);
        assert_eq!(context.source, SessionSource::Cookie);
        assert_eq!(context.ingress_identity, IngressIdentity::default());
        assert_eq!(context.ingress_signals, IngressAdvisorySignals::default());
        assert!(!context.should_set_cookie());
    }

    #[test]
    fn cookie_pair_rejects_empty_names_and_values() {
        assert_eq!(cookie_pair("=value"), None);
        assert_eq!(cookie_pair("eidolon_session="), None);
        assert_eq!(
            cookie_pair(" eidolon_session = value "),
            Some(("eidolon_session", "value"))
        );
    }

    #[test]
    fn formats_set_cookie_for_local_http_lab() {
        let session_id = SessionId::new();

        let value = format_set_cookie(session_id);

        assert_eq!(
            value,
            format!(
                "{}={}; Path={}; HttpOnly; SameSite={}",
                SESSION_COOKIE_NAME, session_id.0, SESSION_COOKIE_PATH, SESSION_COOKIE_SAME_SITE
            )
        );
        assert!(!value.contains("Domain="));
        assert!(!value.contains("Max-Age="));
        assert!(!value.contains("Expires="));
        assert!(!value.contains("Secure"));
    }

    #[test]
    fn derives_normalized_ingress_identity_from_headers() {
        let context = derive_session_from_headers([
            ("Host", "proxy.local"),
            (INGRESS_IDENTITY_SOURCE_HEADER_NAME, "operator_override"),
            (INGRESS_TRUST_TIER_HEADER_NAME, "allowlisted"),
            (INGRESS_IDENTITY_LABEL_HEADER_NAME, "internal-crawler"),
            (
                INGRESS_IDENTITY_EXPIRES_AT_HEADER_NAME,
                "2999-06-04T12:00:00Z",
            ),
        ]);

        assert_eq!(context.source, SessionSource::Generated);
        assert_eq!(
            context.ingress_identity,
            IngressIdentity {
                source: IngressIdentitySource::OperatorOverride,
                trust_tier: IngressTrustTier::Allowlisted,
                label: Some("internal-crawler".to_string()),
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
        let context = derive_session_from_headers([
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
        ]);

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
