use eidolon_core::SessionId;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionContext {
    pub session_id: SessionId,
    pub source: SessionSource,
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
    if let Some(session_id) = session_id_from_headers(headers) {
        SessionContext {
            session_id,
            source: SessionSource::Cookie,
        }
    } else {
        SessionContext {
            session_id: SessionId::new(),
            source: SessionSource::Generated,
        }
    }
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
        assert!(!context.should_set_cookie());
        assert_eq!(context.set_cookie_value(), None);
    }

    #[test]
    fn generates_session_when_cookie_absent() {
        let context = derive_session_from_headers([("Host", "127.0.0.1:8080")]);

        assert_eq!(context.source, SessionSource::Generated);
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
        assert!(!context.should_set_cookie());
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
}
