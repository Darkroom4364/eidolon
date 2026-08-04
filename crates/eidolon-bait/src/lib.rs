use std::{
    borrow::Cow,
    error::Error,
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use eidolon_core::{
    Bait, BaitClass, BaitHeaderValueMintStatus, BaitId, ExpectedAction, HeaderValueMintKind,
    SessionId, SurfaceKind,
};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

pub const DECOY_RECONCILE_PATH: &str = "/api/v2/import/reconcile";

#[derive(Debug, Clone)]
pub struct BasicBaitTemplate {
    pub id: String,
    pub bait_class: BaitClass,
    pub surface: String,
    pub surface_kind: SurfaceKind,
    pub route_suffix: String,
    pub header_name: String,
    pub header_value: String,
}

impl BasicBaitTemplate {
    pub fn legacy_import_demo() -> Self {
        Self {
            id: "rel_2025_04_b7f2".to_string(),
            bait_class: BaitClass::Docs,
            surface: "/docs/legacy-import".to_string(),
            surface_kind: SurfaceKind::Docs,
            route_suffix: "reconcile".to_string(),
            header_name: "X-Migration-Trace".to_string(),
            header_value: "rel_2025_04_b7f2".to_string(),
        }
    }

    pub fn openapi_reconcile_demo() -> Self {
        Self {
            id: "openapi_reconcile_trace".to_string(),
            bait_class: BaitClass::OpenApi,
            surface: "/openapi.json".to_string(),
            surface_kind: SurfaceKind::OpenApi,
            route_suffix: "reconcile".to_string(),
            header_name: "X-OpenAPI-Trace".to_string(),
            header_value: "openapi_2026_05_f3a1".to_string(),
        }
    }

    pub fn hidden_route_demo() -> Self {
        Self {
            id: "hidden_route_trace".to_string(),
            bait_class: BaitClass::HiddenRoute,
            surface: "/customer/import-recovery-checklist".to_string(),
            surface_kind: SurfaceKind::Route,
            route_suffix: "reconcile".to_string(),
            header_name: "X-Hidden-Route-Trace".to_string(),
            header_value: "hidden_route_2026_05_d91c".to_string(),
        }
    }

    pub fn fake_token_demo() -> Self {
        Self {
            id: "fake_service_token".to_string(),
            bait_class: BaitClass::FakeCredentialToken,
            surface: "/docs/service-token".to_string(),
            surface_kind: SurfaceKind::Token,
            route_suffix: "reconcile".to_string(),
            header_name: "X-Api-Key".to_string(),
            header_value: "eidolon_lab_token_2026_05_7e2a".to_string(),
        }
    }

    pub fn js_discovered_route_demo() -> Self {
        Self {
            id: "js_worker_resume_trace".to_string(),
            bait_class: BaitClass::JsDiscoveredRoute,
            surface: "/assets/import-helper.js".to_string(),
            surface_kind: SurfaceKind::Route,
            route_suffix: "reconcile".to_string(),
            header_name: "X-Import-Worker".to_string(),
            header_value: "worker_2026_05_c19b".to_string(),
        }
    }

    pub fn to_bait(&self) -> Bait {
        let path = format!("/api/v2/import/{}", self.route_suffix);

        Bait {
            id: BaitId(self.id.clone()),
            bait_class: self.bait_class,
            surface: self.surface.clone(),
            surface_kind: self.surface_kind.clone(),
            expected_action: ExpectedAction {
                method: "POST".to_string(),
                path,
                header_name: Some(self.header_name.clone()),
                header_value: Some(self.header_value.clone()),
                header_value_mint: None,
            },
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BaitRegistry {
    baits: Vec<Bait>,
}

impl BaitRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn m1_demo() -> Self {
        let mut registry = Self::new();
        registry.add(BasicBaitTemplate::legacy_import_demo().to_bait());
        registry
    }

    pub fn m3_catalog() -> Self {
        let mut registry = Self::new();
        for bait in m3_baits() {
            registry.add(bait);
        }
        registry
    }

    pub fn add(&mut self, bait: Bait) {
        debug_assert!(
            bait.expected_action.header_value.is_none()
                || bait.expected_action.header_name.is_some(),
            "bait expected action cannot require a header value without naming the header"
        );
        self.baits.push(bait);
    }

    pub fn baits(&self) -> &[Bait] {
        &self.baits
    }

    pub fn bait_for_surface(&self, surface: &str) -> Option<&Bait> {
        self.baits.iter().find(|bait| bait.surface == surface)
    }

    pub fn bait_for_class(&self, bait_class: BaitClass) -> Option<&Bait> {
        self.baits.iter().find(|bait| bait.bait_class == bait_class)
    }

    /// Returns whether the configured catalog contains this method and path.
    ///
    /// Ownership deliberately ignores proof headers and values. Callers use
    /// this before proof validation so a rejected decoy action cannot fall
    /// through to a protected upstream.
    pub fn matches_action_route(&self, method: &str, path: &str) -> bool {
        self.baits.iter().any(|bait| {
            bait.expected_action.method.eq_ignore_ascii_case(method)
                && bait.expected_action.path == path
        })
    }

    /// Returns the first registered bait whose expected action matches the request.
    ///
    /// `path` must be the normalized request path without a query string. Query
    /// parameters are not part of bait matching, so callers should split them
    /// before calling this method.
    pub fn match_action<'a, I>(
        &self,
        method: &str,
        path: &str,
        headers: I,
    ) -> Option<BaitActionMatch>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let headers: Vec<(&str, &str)> = headers.into_iter().collect();

        self.baits
            .iter()
            .find(|bait| exact_action_matches(&bait.expected_action, method, path, &headers))
            .cloned()
            .map(|bait| BaitActionMatch {
                bait,
                header_value_mint_status: None,
            })
    }

    pub fn match_action_for_session<'a, I>(
        &self,
        method: &str,
        path: &str,
        headers: I,
        session_id: SessionId,
        signing_secret: Option<&str>,
    ) -> Result<Option<BaitActionMatch>, BaitValueError>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        self.match_action_for_session_at(
            method,
            path,
            headers,
            session_id,
            signing_secret,
            current_epoch_seconds(),
        )
    }

    pub fn match_action_for_session_at<'a, I>(
        &self,
        method: &str,
        path: &str,
        headers: I,
        session_id: SessionId,
        signing_secret: Option<&str>,
        now_epoch_seconds: u64,
    ) -> Result<Option<BaitActionMatch>, BaitValueError>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let headers: Vec<(&str, &str)> = headers.into_iter().collect();
        let mut rejected_match = None;

        for bait in &self.baits {
            if let Some(status) = verify_action_for_session(
                bait,
                method,
                path,
                &headers,
                session_id,
                signing_secret,
                now_epoch_seconds,
            )? {
                if matches!(
                    status,
                    None | Some(BaitHeaderValueMintStatus::MatchedSessionValue)
                ) {
                    return Ok(Some(BaitActionMatch {
                        bait: bait.clone(),
                        header_value_mint_status: status,
                    }));
                }
                let candidate = BaitActionMatch {
                    bait: bait.clone(),
                    header_value_mint_status: status,
                };
                if status != Some(BaitHeaderValueMintStatus::MissingSessionValue)
                    || rejected_match.is_none()
                {
                    rejected_match = Some(candidate);
                }
            }
        }

        Ok(rejected_match)
    }

    /// Returns the first registered bait whose method and path match the request
    /// and whose expected header name is present, even if the value is wrong.
    ///
    /// For headerless bait actions, a method/path match is sufficient.
    pub fn match_action_shape<'a, I>(
        &self,
        method: &str,
        path: &str,
        headers: I,
    ) -> Option<BaitActionMatch>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let headers: Vec<(&str, &str)> = headers.into_iter().collect();

        self.baits
            .iter()
            .find(|bait| action_shape_matches(&bait.expected_action, method, path, &headers))
            .cloned()
            .map(|bait| BaitActionMatch {
                bait,
                header_value_mint_status: None,
            })
    }
}

pub fn m3_baits() -> Vec<Bait> {
    [
        BasicBaitTemplate::legacy_import_demo(),
        BasicBaitTemplate::openapi_reconcile_demo(),
        BasicBaitTemplate::hidden_route_demo(),
        BasicBaitTemplate::fake_token_demo(),
        BasicBaitTemplate::js_discovered_route_demo(),
    ]
    .into_iter()
    .map(|template| template.to_bait())
    .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaitActionMatch {
    pub bait: Bait,
    pub header_value_mint_status: Option<BaitHeaderValueMintStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaitValueError {
    MissingSigningSecret { bait_id: BaitId },
}

impl fmt::Display for BaitValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSigningSecret { bait_id } => write!(
                formatter,
                "bait `{}` requires a bait signing secret but none was configured",
                bait_id.0
            ),
        }
    }
}

impl Error for BaitValueError {}

fn action_shape_matches(
    expected: &ExpectedAction,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> bool {
    if !expected.method.eq_ignore_ascii_case(method) || expected.path != path {
        return false;
    }

    match (&expected.header_name, &expected.header_value) {
        (Some(expected_name), _) => headers
            .iter()
            .any(|(name, _)| expected_name.eq_ignore_ascii_case(name)),
        (None, Some(_)) => false,
        (None, None) => true,
    }
}

fn exact_action_matches(
    expected: &ExpectedAction,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> bool {
    if !expected.method.eq_ignore_ascii_case(method) || expected.path != path {
        return false;
    }

    match (&expected.header_name, &expected.header_value) {
        (Some(expected_name), Some(expected_value)) => headers.iter().any(|(name, value)| {
            expected_name.eq_ignore_ascii_case(name) && value.trim() == expected_value.trim()
        }),
        (Some(expected_name), None) => headers
            .iter()
            .any(|(name, _)| expected_name.eq_ignore_ascii_case(name)),
        (None, Some(_)) => false,
        (None, None) => true,
    }
}

pub fn docs_for_bait(bait: &Bait) -> String {
    let action = &bait.expected_action;
    let header_name = action.header_name.as_deref().unwrap_or("X-Migration-Trace");
    let header_value = action.header_value.as_deref().unwrap_or(&bait.id.0);

    format!(
        "# Customer Import Reconciliation\n\nThe import portal accepts customer-controlled manifests and optional source URLs for tenant data repair. Legacy clients can queue reconciliation by sending `{header_name}: {header_value}`.\n\nThe header is a compatibility gate only; possession of the value from an external client request is sufficient to enqueue a tenant import repair request.\n\nEndpoint:\n\n```http\n{} {}\n```\n",
        action.method, action.path
    )
}

pub fn render_bait_for_session<'a>(
    bait: &'a Bait,
    session_id: SessionId,
    signing_secret: Option<&str>,
) -> Result<Cow<'a, Bait>, BaitValueError> {
    render_bait_for_session_at(bait, session_id, signing_secret, current_epoch_seconds())
}

pub fn render_bait_for_session_at<'a>(
    bait: &'a Bait,
    session_id: SessionId,
    signing_secret: Option<&str>,
    now_epoch_seconds: u64,
) -> Result<Cow<'a, Bait>, BaitValueError> {
    let Some(mint) = bait.expected_action.header_value_mint.as_ref() else {
        return Ok(Cow::Borrowed(bait));
    };
    let Some(header_name) = bait.expected_action.header_name.as_deref() else {
        return Ok(Cow::Borrowed(bait));
    };
    let Some(signing_secret) = signing_secret
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(BaitValueError::MissingSigningSecret {
            bait_id: bait.id.clone(),
        });
    };

    let mut rendered = bait.clone();
    rendered.expected_action.header_value = Some(mint_header_value(
        bait,
        mint,
        session_id,
        signing_secret,
        header_name,
        now_epoch_seconds,
    ));
    Ok(Cow::Owned(rendered))
}

type HmacSha256 = Hmac<Sha256>;

fn mint_header_value(
    bait: &Bait,
    mint: &eidolon_core::HeaderValueMint,
    session_id: SessionId,
    signing_secret: &str,
    header_name: &str,
    now_epoch_seconds: u64,
) -> String {
    match mint.kind {
        HeaderValueMintKind::SessionHmacSha256V1 => {
            let window_bucket = mint
                .proof_window_seconds
                .filter(|window| *window > 0)
                .map(|window| now_epoch_seconds / window);
            let mut mac = match HmacSha256::new_from_slice(signing_secret.as_bytes()) {
                Ok(mac) => mac,
                Err(_error) => unreachable!("hmac accepts any key length"),
            };
            mac.update(b"eidolon-bait-header-v1");
            mac.update(b"\0");
            mac.update(session_id.0.as_bytes().as_ref());
            mac.update(b"\0");
            mac.update(bait.id.0.as_bytes());
            mac.update(b"\0");
            mac.update(bait.expected_action.method.to_ascii_uppercase().as_bytes());
            mac.update(b"\0");
            mac.update(bait.expected_action.path.as_bytes());
            mac.update(b"\0");
            mac.update(header_name.to_ascii_lowercase().as_bytes());
            if let Some(bucket) = window_bucket {
                mac.update(b"\0");
                mac.update(bucket.to_string().as_bytes());
            }
            let tag = mac.finalize().into_bytes();

            match window_bucket {
                Some(bucket) => format!("{}_w{bucket:x}_{}", mint.prefix, hex_prefix(&tag, 12)),
                None => format!("{}_{}", mint.prefix, hex_prefix(&tag, 12)),
            }
        }
    }
}

fn current_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn verify_action_for_session(
    bait: &Bait,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    session_id: SessionId,
    signing_secret: Option<&str>,
    now_epoch_seconds: u64,
) -> Result<Option<Option<BaitHeaderValueMintStatus>>, BaitValueError> {
    if !bait.expected_action.method.eq_ignore_ascii_case(method)
        || bait.expected_action.path != path
    {
        return Ok(None);
    }

    let Some(mint) = bait.expected_action.header_value_mint.as_ref() else {
        return Ok(
            exact_action_matches(&bait.expected_action, method, path, headers).then_some(None),
        );
    };
    let Some(header_name) = bait.expected_action.header_name.as_deref() else {
        return Ok(None);
    };
    let Some((_, presented_value)) = headers
        .iter()
        .find(|(name, _)| header_name.eq_ignore_ascii_case(name))
    else {
        return Ok(Some(Some(BaitHeaderValueMintStatus::MissingSessionValue)));
    };
    let Some(signing_secret) = signing_secret
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(BaitValueError::MissingSigningSecret {
            bait_id: bait.id.clone(),
        });
    };

    let Some(window) = mint.proof_window_seconds.filter(|window| *window > 0) else {
        let rendered =
            render_bait_for_session_at(bait, session_id, Some(signing_secret), now_epoch_seconds)?;
        return Ok(Some(Some(
            if exact_action_matches(&rendered.expected_action, method, path, headers) {
                BaitHeaderValueMintStatus::MatchedSessionValue
            } else {
                BaitHeaderValueMintStatus::SessionValueMismatch
            },
        )));
    };

    let Some((presented_bucket, presented_tag)) = parse_windowed_mint_value(mint, presented_value)
    else {
        return Ok(Some(Some(BaitHeaderValueMintStatus::MalformedSessionValue)));
    };
    let expected = mint_header_value(
        bait,
        mint,
        session_id,
        signing_secret,
        header_name,
        presented_bucket.saturating_mul(window),
    );
    let Some((_, expected_tag)) = parse_windowed_mint_value(mint, &expected) else {
        unreachable!("windowed mint output must parse");
    };
    if expected_tag != presented_tag {
        return Ok(Some(Some(BaitHeaderValueMintStatus::SessionValueMismatch)));
    }

    let current_bucket = now_epoch_seconds / window;
    let status = if presented_bucket == current_bucket {
        BaitHeaderValueMintStatus::MatchedSessionValue
    } else if presented_bucket < current_bucket {
        BaitHeaderValueMintStatus::ExpiredSessionValue
    } else {
        BaitHeaderValueMintStatus::SessionValueMismatch
    };
    Ok(Some(Some(status)))
}

fn parse_windowed_mint_value<'a>(
    mint: &eidolon_core::HeaderValueMint,
    value: &'a str,
) -> Option<(u64, &'a str)> {
    let remainder = value.strip_prefix(&format!("{}_w", mint.prefix))?;
    let (bucket_hex, tag) = remainder.split_once('_')?;
    if tag.len() != 24 || !tag.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some((u64::from_str_radix(bucket_hex, 16).ok()?, tag))
}

fn hex_prefix(bytes: &[u8], limit: usize) -> String {
    let mut output = String::with_capacity(limit * 2);
    for byte in bytes.iter().take(limit) {
        let high = byte >> 4;
        let low = byte & 0x0f;
        output.push(nibble_to_hex(high));
        output.push(nibble_to_hex(low));
    }
    output
}

fn nibble_to_hex(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => unreachable!("nibble must be <= 15"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_minted_bait() -> Bait {
        Bait {
            id: BaitId("minted_trace".to_string()),
            bait_class: BaitClass::Docs,
            surface: "/docs/minted-trace".to_string(),
            surface_kind: SurfaceKind::Docs,
            expected_action: ExpectedAction {
                method: "POST".to_string(),
                path: DECOY_RECONCILE_PATH.to_string(),
                header_name: Some("X-Migration-Trace".to_string()),
                header_value: None,
                header_value_mint: Some(eidolon_core::HeaderValueMint {
                    kind: HeaderValueMintKind::SessionHmacSha256V1,
                    prefix: "minted".to_string(),
                    proof_window_seconds: None,
                }),
            },
        }
    }

    fn demo_registry() -> BaitRegistry {
        BaitRegistry::m1_demo()
    }

    #[test]
    fn match_action_exact_match() {
        let registry = demo_registry();

        let matched = registry.match_action(
            "POST",
            "/api/v2/import/reconcile",
            [("X-Migration-Trace", "rel_2025_04_b7f2")],
        );

        assert_eq!(
            matched.map(|matched| matched.bait.id),
            Some(BaitId("rel_2025_04_b7f2".to_string()))
        );
    }

    #[test]
    fn match_action_rejects_wrong_header_value() {
        let registry = demo_registry();

        let matched = registry.match_action(
            "POST",
            "/api/v2/import/reconcile",
            [("X-Migration-Trace", "wrong")],
        );

        assert_eq!(matched, None);
    }

    #[test]
    fn action_route_matching_ignores_proof_headers_and_values() {
        let registry = demo_registry();

        assert!(registry.matches_action_route("POST", DECOY_RECONCILE_PATH));
        assert!(registry.matches_action_route("post", DECOY_RECONCILE_PATH));
        assert!(!registry.matches_action_route("GET", DECOY_RECONCILE_PATH));
        assert!(!registry.matches_action_route("POST", "/api/v2/import/reconcile/"));
    }

    #[test]
    fn shared_action_route_is_owned_without_selecting_a_bait() {
        let registry = BaitRegistry::m3_catalog();

        assert!(registry.matches_action_route("POST", DECOY_RECONCILE_PATH));
    }

    #[test]
    fn match_action_shape_accepts_wrong_header_value_near_miss() {
        let registry = demo_registry();

        let matched = registry.match_action_shape(
            "POST",
            "/api/v2/import/reconcile",
            [("X-Migration-Trace", "wrong")],
        );

        assert_eq!(
            matched.map(|matched| matched.bait.id),
            Some(BaitId("rel_2025_04_b7f2".to_string()))
        );
    }

    #[test]
    fn match_action_shape_chooses_openapi_bait_by_header_name() {
        let registry = BaitRegistry::m3_catalog();

        let matched = registry.match_action_shape(
            "POST",
            DECOY_RECONCILE_PATH,
            [("X-OpenAPI-Trace", "wrong")],
        );

        assert_eq!(
            matched.map(|matched| matched.bait.id),
            Some(BaitId("openapi_reconcile_trace".to_string()))
        );
    }

    #[test]
    fn match_action_shape_rejects_missing_header_on_shared_path() {
        let registry = BaitRegistry::m3_catalog();

        let matched = registry.match_action_shape("POST", DECOY_RECONCILE_PATH, []);

        assert_eq!(matched, None);
    }

    #[test]
    fn match_action_rejects_missing_header() {
        let registry = demo_registry();

        let matched = registry.match_action("POST", "/api/v2/import/reconcile", []);

        assert_eq!(matched, None);
    }

    #[test]
    fn match_action_accepts_case_insensitive_method_and_header_name() {
        let registry = demo_registry();

        let matched = registry.match_action(
            "post",
            "/api/v2/import/reconcile",
            [("x-migration-trace", "rel_2025_04_b7f2")],
        );

        assert!(matched.is_some());
    }

    #[test]
    fn match_action_rejects_path_near_miss() {
        let registry = demo_registry();

        let matched = registry.match_action(
            "POST",
            "/api/v2/import/reconcile/",
            [("X-Migration-Trace", "rel_2025_04_b7f2")],
        );

        assert_eq!(matched, None);
    }

    #[test]
    fn match_action_rejects_query_bearing_path() {
        let registry = demo_registry();

        let matched = registry.match_action(
            "POST",
            "/api/v2/import/reconcile?dry_run=1",
            [("X-Migration-Trace", "rel_2025_04_b7f2")],
        );

        assert_eq!(matched, None);
    }

    #[test]
    fn bait_for_surface_returns_matching_bait() {
        let registry = demo_registry();

        let bait = registry.bait_for_surface("/docs/legacy-import");

        assert_eq!(
            bait.map(|bait| &bait.id),
            Some(&BaitId("rel_2025_04_b7f2".to_string()))
        );
        assert!(registry.bait_for_surface("/docs/missing").is_none());
    }

    #[test]
    fn match_action_allows_method_path_match_without_expected_header() {
        let mut registry = BaitRegistry::new();
        registry.add(Bait {
            id: BaitId("no_header".to_string()),
            bait_class: BaitClass::Docs,
            surface: "/docs/no-header".to_string(),
            surface_kind: SurfaceKind::Docs,
            expected_action: ExpectedAction {
                method: "GET".to_string(),
                path: "/api/no-header".to_string(),
                header_name: None,
                header_value: None,
                header_value_mint: None,
            },
        });

        let matched = registry.match_action("get", "/api/no-header", []);

        assert_eq!(
            matched.map(|matched| matched.bait.id),
            Some(BaitId("no_header".to_string()))
        );
    }

    #[test]
    fn match_action_rejects_header_value_without_header_name() {
        let mut registry = BaitRegistry::new();
        registry.baits.push(Bait {
            id: BaitId("value_only".to_string()),
            bait_class: BaitClass::Docs,
            surface: "/docs/value-only".to_string(),
            surface_kind: SurfaceKind::Docs,
            expected_action: ExpectedAction {
                method: "POST".to_string(),
                path: "/api/value-only".to_string(),
                header_name: None,
                header_value: Some("shared-secret".to_string()),
                header_value_mint: None,
            },
        });

        assert_eq!(
            registry.match_action("POST", "/api/value-only", [("Unrelated", "shared-secret")]),
            None
        );
    }

    #[test]
    fn duplicate_matches_are_first_registered_wins() {
        let mut registry = BaitRegistry::new();
        for id in ["first", "second"] {
            registry.add(Bait {
                id: BaitId(id.to_string()),
                bait_class: BaitClass::Docs,
                surface: "/docs/duplicate".to_string(),
                surface_kind: SurfaceKind::Docs,
                expected_action: ExpectedAction {
                    method: "POST".to_string(),
                    path: "/api/duplicate".to_string(),
                    header_name: None,
                    header_value: None,
                    header_value_mint: None,
                },
            });
        }

        assert_eq!(
            registry
                .bait_for_surface("/docs/duplicate")
                .map(|bait| bait.id.clone()),
            Some(BaitId("first".to_string()))
        );
        assert_eq!(
            registry
                .match_action("POST", "/api/duplicate", [])
                .map(|matched| matched.bait.id),
            Some(BaitId("first".to_string()))
        );
    }

    #[test]
    fn docs_for_bait_uses_safe_header_defaults_when_action_omits_them() {
        let bait = Bait {
            id: BaitId("fallback-marker".to_string()),
            bait_class: BaitClass::Docs,
            surface: "/docs/fallback".to_string(),
            surface_kind: SurfaceKind::Docs,
            expected_action: ExpectedAction {
                method: "POST".to_string(),
                path: "/api/v2/fallback".to_string(),
                header_name: None,
                header_value: None,
                header_value_mint: None,
            },
        };

        let docs = docs_for_bait(&bait);

        assert!(docs.contains("X-Migration-Trace: fallback-marker"));
        assert!(docs.contains("POST /api/v2/fallback"));
    }

    #[test]
    fn m3_catalog_contains_the_five_required_bait_classes() {
        let registry = BaitRegistry::m3_catalog();
        let classes: Vec<BaitClass> = registry
            .baits()
            .iter()
            .map(|bait| bait.bait_class)
            .collect();

        assert_eq!(registry.baits().len(), 5);
        assert!(classes.contains(&BaitClass::Docs));
        assert!(classes.contains(&BaitClass::OpenApi));
        assert!(classes.contains(&BaitClass::HiddenRoute));
        assert!(classes.contains(&BaitClass::FakeCredentialToken));
        assert!(classes.contains(&BaitClass::JsDiscoveredRoute));
    }

    #[test]
    fn m3_catalog_uses_unique_ids_surfaces_and_action_headers() {
        let registry = BaitRegistry::m3_catalog();
        let mut ids = Vec::new();
        let mut surfaces = Vec::new();
        let mut headers = Vec::new();

        for bait in registry.baits() {
            ids.push(bait.id.0.as_str());
            surfaces.push(bait.surface.as_str());
            headers.push(
                bait.expected_action
                    .header_name
                    .as_deref()
                    .expect("M3 baits should require explicit headers"),
            );
            assert_eq!(bait.expected_action.method, "POST");
            assert_eq!(bait.expected_action.path, DECOY_RECONCILE_PATH);
            assert!(bait.expected_action.header_value.is_some());
        }

        ids.sort_unstable();
        ids.dedup();
        surfaces.sort_unstable();
        surfaces.dedup();
        headers.sort_unstable();
        headers.dedup();

        assert_eq!(ids.len(), 5);
        assert_eq!(surfaces.len(), 5);
        assert_eq!(headers.len(), 5);
    }

    #[test]
    fn m3_catalog_matches_each_bait_by_its_own_header() {
        let registry = BaitRegistry::m3_catalog();

        for bait in registry.baits() {
            let header_name = bait.expected_action.header_name.as_deref().unwrap();
            let header_value = bait.expected_action.header_value.as_deref().unwrap();
            let matched =
                registry.match_action("POST", DECOY_RECONCILE_PATH, [(header_name, header_value)]);

            assert_eq!(
                matched.map(|matched| matched.bait.id),
                Some(bait.id.clone())
            );
        }
    }

    #[test]
    fn bait_for_class_returns_matching_m3_bait() {
        let registry = BaitRegistry::m3_catalog();

        assert_eq!(
            registry
                .bait_for_class(BaitClass::FakeCredentialToken)
                .map(|bait| bait.surface.as_str()),
            Some("/docs/service-token")
        );
    }

    #[test]
    fn docs_for_bait_names_external_trust_boundary() {
        let bait = BasicBaitTemplate::legacy_import_demo().to_bait();
        let docs = docs_for_bait(&bait);

        assert!(docs.contains("customer-controlled manifests"));
        assert!(docs.contains("external client request"));
        assert!(docs.contains("compatibility gate only"));
        assert!(docs.contains("X-Migration-Trace: rel_2025_04_b7f2"));
        assert!(docs.contains("POST /api/v2/import/reconcile"));
    }

    #[test]
    fn render_bait_for_session_mints_stable_value_per_session() {
        let bait = session_minted_bait();
        let session_id = SessionId::new();

        let first = render_bait_for_session(&bait, session_id, Some("mint-secret"))
            .expect("minted bait should render")
            .into_owned();
        let second = render_bait_for_session(&bait, session_id, Some("mint-secret"))
            .expect("minted bait should render")
            .into_owned();

        assert_eq!(
            first.expected_action.header_value,
            second.expected_action.header_value
        );
        assert!(first
            .expected_action
            .header_value
            .as_deref()
            .is_some_and(|value| value.starts_with("minted_")));
    }

    #[test]
    fn render_bait_for_session_changes_value_across_sessions() {
        let bait = session_minted_bait();

        let first = render_bait_for_session(&bait, SessionId::new(), Some("mint-secret"))
            .expect("minted bait should render")
            .into_owned();
        let second = render_bait_for_session(&bait, SessionId::new(), Some("mint-secret"))
            .expect("minted bait should render")
            .into_owned();

        assert_ne!(
            first.expected_action.header_value,
            second.expected_action.header_value
        );
    }

    #[test]
    fn render_bait_for_session_requires_signing_secret_for_minted_baits() {
        let bait = session_minted_bait();

        let error = render_bait_for_session(&bait, SessionId::new(), None)
            .expect_err("minted bait should require a signing secret");

        assert!(error.to_string().contains("requires a bait signing secret"));
    }

    #[test]
    fn render_bait_for_session_keeps_static_negative_control_stable() {
        let bait = BasicBaitTemplate::hidden_route_demo().to_bait();

        let first = render_bait_for_session(&bait, SessionId::new(), Some("mint-secret"))
            .expect("static bait should render")
            .into_owned();
        let second = render_bait_for_session(&bait, SessionId::new(), Some("mint-secret"))
            .expect("static bait should render")
            .into_owned();

        assert_eq!(
            first.expected_action.header_name,
            second.expected_action.header_name
        );
        assert_eq!(
            first.expected_action.header_value,
            second.expected_action.header_value
        );
        assert_eq!(
            first.expected_action.header_value.as_deref(),
            Some("hidden_route_2026_05_d91c")
        );
        assert!(first.expected_action.header_value_mint.is_none());
        assert!(second.expected_action.header_value_mint.is_none());
    }

    #[test]
    fn match_action_for_session_preserves_static_negative_control_behavior() {
        let bait = BasicBaitTemplate::hidden_route_demo().to_bait();
        let mut registry = BaitRegistry::new();
        registry.add(bait);

        let matched = registry
            .match_action_for_session(
                "POST",
                DECOY_RECONCILE_PATH,
                [("X-Hidden-Route-Trace", "hidden_route_2026_05_d91c")],
                SessionId::new(),
                Some("mint-secret"),
            )
            .expect("static control should verify without session-specific minting");

        assert_eq!(
            matched.map(|matched| matched.bait.id),
            Some(BaitId("hidden_route_trace".to_string()))
        );
    }

    #[test]
    fn match_action_for_session_verifies_minted_header_value() {
        let bait = session_minted_bait();
        let mut registry = BaitRegistry::new();
        registry.add(bait.clone());
        let session_id = SessionId::new();
        let rendered = render_bait_for_session(&bait, session_id, Some("mint-secret"))
            .expect("minted bait should render")
            .into_owned();
        let header_name = rendered
            .expected_action
            .header_name
            .as_deref()
            .expect("minted bait should keep header name");
        let header_value = rendered
            .expected_action
            .header_value
            .as_deref()
            .expect("minted bait should produce header value");

        let matched = registry
            .match_action_for_session(
                "POST",
                DECOY_RECONCILE_PATH,
                [(header_name, header_value)],
                session_id,
                Some("mint-secret"),
            )
            .expect("minted action should verify");

        assert_eq!(
            matched.map(|matched| matched.bait.id),
            Some(BaitId("minted_trace".to_string()))
        );
    }

    #[test]
    fn match_action_for_session_rejects_minted_header_value_from_other_session() {
        let bait = session_minted_bait();
        let mut registry = BaitRegistry::new();
        registry.add(bait.clone());
        let session_a = SessionId::new();
        let session_b = SessionId::new();
        let rendered = render_bait_for_session(&bait, session_a, Some("mint-secret"))
            .expect("minted bait should render")
            .into_owned();
        let header_name = rendered
            .expected_action
            .header_name
            .as_deref()
            .expect("minted bait should keep header name");
        let header_value = rendered
            .expected_action
            .header_value
            .as_deref()
            .expect("minted bait should produce header value");

        let matched = registry
            .match_action_for_session(
                "POST",
                DECOY_RECONCILE_PATH,
                [(header_name, header_value)],
                session_b,
                Some("mint-secret"),
            )
            .expect("cross-session replay should not error");

        assert_eq!(
            matched.map(|matched| matched.header_value_mint_status),
            Some(Some(BaitHeaderValueMintStatus::SessionValueMismatch))
        );
        assert_eq!(
            registry
                .match_action_shape("POST", DECOY_RECONCILE_PATH, [(header_name, header_value)])
                .map(|matched| matched.bait.id),
            Some(BaitId("minted_trace".to_string()))
        );
    }

    #[test]
    fn windowed_mint_reports_expired_proof() {
        let mut bait = session_minted_bait();
        bait.expected_action
            .header_value_mint
            .as_mut()
            .expect("mint config")
            .proof_window_seconds = Some(60);
        let mut registry = BaitRegistry::new();
        registry.add(bait.clone());
        let session = SessionId::new();
        let rendered = render_bait_for_session_at(&bait, session, Some("secret"), 1_200)
            .expect("render")
            .into_owned();
        let name = rendered
            .expected_action
            .header_name
            .as_deref()
            .expect("name");
        let value = rendered
            .expected_action
            .header_value
            .as_deref()
            .expect("value");

        let accepted = registry
            .match_action_for_session_at(
                "POST",
                DECOY_RECONCILE_PATH,
                [(name, value)],
                session,
                Some("secret"),
                1_259,
            )
            .expect("verify")
            .expect("owned action");
        let expired = registry
            .match_action_for_session_at(
                "POST",
                DECOY_RECONCILE_PATH,
                [(name, value)],
                session,
                Some("secret"),
                1_260,
            )
            .expect("verify")
            .expect("owned action");

        assert_eq!(
            accepted.header_value_mint_status,
            Some(BaitHeaderValueMintStatus::MatchedSessionValue)
        );
        assert_eq!(
            expired.header_value_mint_status,
            Some(BaitHeaderValueMintStatus::ExpiredSessionValue)
        );
    }

    #[test]
    fn shared_route_checks_later_valid_minted_bait_before_rejecting() {
        let first = session_minted_bait();
        let mut second = first.clone();
        second.id = BaitId("second".to_string());
        second.expected_action.header_name = Some("X-Second-Proof".to_string());
        second
            .expected_action
            .header_value_mint
            .as_mut()
            .expect("mint")
            .prefix = "second".to_string();
        let session = SessionId::new();
        let rendered = render_bait_for_session_at(&second, session, Some("secret"), 1_200)
            .expect("render")
            .into_owned();
        let name = rendered
            .expected_action
            .header_name
            .as_deref()
            .expect("name");
        let value = rendered
            .expected_action
            .header_value
            .as_deref()
            .expect("value");
        let mut registry = BaitRegistry::new();
        registry.add(first);
        registry.add(second);

        let matched = registry
            .match_action_for_session_at(
                "POST",
                DECOY_RECONCILE_PATH,
                [(name, value)],
                session,
                Some("secret"),
                1_200,
            )
            .expect("verify")
            .expect("valid second bait");

        assert_eq!(matched.bait.id, BaitId("second".to_string()));
        assert_eq!(
            matched.header_value_mint_status,
            Some(BaitHeaderValueMintStatus::MatchedSessionValue)
        );
    }
}
