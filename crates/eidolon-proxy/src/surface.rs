use std::{fmt, io};

use eidolon_core::{RoutingDecision, SessionId};
use serde_json::{Map, Value};

pub const MAX_REWRITE_BODY_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceHeader {
    pub name: String,
    pub value: String,
}

impl SurfaceHeader {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceRequestMeta {
    pub method: String,
    pub target: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: Vec<SurfaceHeader>,
    pub body_len: usize,
}

impl SurfaceRequestMeta {
    pub fn new(
        method: impl Into<String>,
        target: impl Into<String>,
        headers: Vec<SurfaceHeader>,
        body_len: usize,
    ) -> Self {
        let target = target.into();
        let (path, query) = split_target(&target);

        Self {
            method: method.into(),
            target,
            path,
            query,
            headers,
            body_len,
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        find_header(&self.headers, name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceResponseMeta {
    pub status: u16,
    pub surface_path: Option<String>,
    pub headers: Vec<SurfaceHeader>,
    pub body_len: usize,
}

impl SurfaceResponseMeta {
    pub fn new(status: u16, headers: Vec<SurfaceHeader>, body_len: usize) -> Self {
        Self {
            status,
            surface_path: None,
            headers,
            body_len,
        }
    }

    pub fn for_surface(
        status: u16,
        surface_path: impl Into<String>,
        headers: Vec<SurfaceHeader>,
        body_len: usize,
    ) -> Self {
        Self {
            status,
            surface_path: Some(surface_path.into()),
            headers,
            body_len,
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        find_header(&self.headers, name)
    }

    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceResponse {
    pub status: u16,
    pub headers: Vec<SurfaceHeader>,
    pub body: Vec<u8>,
}

impl SurfaceResponse {
    pub fn new(status: u16, headers: Vec<SurfaceHeader>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers,
            body: body.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SurfaceAction {
    ProtectedUpstream,
    RewrittenUpstream {
        plan: RewritePlan,
    },
    EidolonOwned {
        response: SurfaceResponse,
    },
    ControlledReality {
        reason: String,
        response: SurfaceResponse,
    },
    RateLimited {
        reason: String,
        response: SurfaceResponse,
    },
}

impl SurfaceAction {
    pub fn routing_decision(&self) -> RoutingDecision {
        match self {
            Self::ProtectedUpstream => RoutingDecision::ProtectedUpstream,
            Self::RewrittenUpstream { .. } => RoutingDecision::RewrittenUpstream,
            Self::EidolonOwned { .. } => RoutingDecision::EidolonOwned,
            Self::ControlledReality { .. } => RoutingDecision::ControlledReality,
            Self::RateLimited { .. } => RoutingDecision::RateLimited,
        }
    }

    pub fn is_upstream(&self) -> bool {
        matches!(
            self,
            Self::ProtectedUpstream | Self::RewrittenUpstream { .. }
        )
    }
}

pub trait SurfaceController {
    fn decide(
        &self,
        request: &SurfaceRequestMeta,
        session_id: SessionId,
    ) -> io::Result<SurfaceAction>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ProtectedUpstreamController;

impl SurfaceController for ProtectedUpstreamController {
    fn decide(
        &self,
        _request: &SurfaceRequestMeta,
        _session_id: SessionId,
    ) -> io::Result<SurfaceAction> {
        Ok(SurfaceAction::ProtectedUpstream)
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct RewritePlan {
    pub operation: Option<RewriteOperation>,
}

impl RewritePlan {
    pub fn html(insertion: HtmlInsertion) -> Self {
        Self {
            operation: Some(RewriteOperation::Html(insertion)),
        }
    }

    pub fn robots_txt(appendix: RobotsTxtAppend) -> Self {
        Self {
            operation: Some(RewriteOperation::RobotsTxt(appendix)),
        }
    }

    pub fn openapi_paths(insertions: Vec<OpenApiPathInsertion>) -> Self {
        Self {
            operation: Some(RewriteOperation::OpenApiPaths(insertions)),
        }
    }

    pub fn json_fields(fields: Vec<JsonFieldInsertion>) -> Self {
        Self {
            operation: Some(RewriteOperation::JsonFields(fields)),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.operation
            .as_ref()
            .map(RewriteOperation::is_empty)
            .unwrap_or(true)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RewriteOperation {
    Html(HtmlInsertion),
    RobotsTxt(RobotsTxtAppend),
    OpenApiPaths(Vec<OpenApiPathInsertion>),
    JsonFields(Vec<JsonFieldInsertion>),
}

impl RewriteOperation {
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Html(insertion) => insertion.snippet.is_empty(),
            Self::RobotsTxt(appendix) => appendix.text.trim_matches('\n').is_empty(),
            Self::OpenApiPaths(insertions) => insertions.is_empty(),
            Self::JsonFields(fields) => fields.is_empty(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HtmlInsertion {
    pub snippet: String,
}

impl HtmlInsertion {
    pub fn new(snippet: impl Into<String>) -> Self {
        Self {
            snippet: snippet.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RobotsTxtAppend {
    pub text: String,
}

impl RobotsTxtAppend {
    pub fn new(text: impl Into<String>) -> Self {
        Self { text: text.into() }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpenApiPathInsertion {
    pub path: String,
    pub path_item: Value,
}

impl OpenApiPathInsertion {
    pub fn new(path: impl Into<String>, path_item: Value) -> Self {
        Self {
            path: path.into(),
            path_item,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct JsonFieldInsertion {
    pub name: String,
    pub value: Value,
}

impl JsonFieldInsertion {
    pub fn new(name: impl Into<String>, value: Value) -> Self {
        Self {
            name: name.into(),
            value,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewriteKind {
    Html,
    RobotsTxt,
    OpenApiJson,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewriteLogRecord {
    pub kind: RewriteKind,
    pub original_body: Vec<u8>,
    pub rewritten_body: Vec<u8>,
}

impl RewriteLogRecord {
    pub fn restore_body(&self) -> &[u8] {
        &self.original_body
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewriteOutcome {
    Unchanged {
        body: Vec<u8>,
    },
    Rewritten {
        log: RewriteLogRecord,
    },
    Refused {
        body: Vec<u8>,
        reason: RewriteRefusal,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewriteDisposition {
    Unchanged,
    Rewritten,
    Refused,
}

impl RewriteOutcome {
    pub fn body(&self) -> &[u8] {
        match self {
            Self::Unchanged { body } | Self::Refused { body, .. } => body,
            Self::Rewritten { log } => &log.rewritten_body,
        }
    }

    pub fn into_body(self) -> Vec<u8> {
        match self {
            Self::Unchanged { body } | Self::Refused { body, .. } => body,
            Self::Rewritten { log } => log.rewritten_body,
        }
    }

    pub fn is_rewritten(&self) -> bool {
        matches!(self, Self::Rewritten { .. })
    }

    pub fn disposition(&self) -> RewriteDisposition {
        match self {
            Self::Unchanged { .. } => RewriteDisposition::Unchanged,
            Self::Rewritten { .. } => RewriteDisposition::Rewritten,
            Self::Refused { .. } => RewriteDisposition::Refused,
        }
    }

    pub fn refusal(&self) -> Option<&RewriteRefusal> {
        match self {
            Self::Refused { reason, .. } => Some(reason),
            Self::Unchanged { .. } | Self::Rewritten { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewriteRefusal {
    BodyTooLarge { actual: usize, limit: usize },
    RewrittenBodyTooLarge { actual: usize, limit: usize },
    InvalidUtf8,
    HtmlSnippetDeniedByDenylist,
    InvalidJson(String),
    JsonRootNotObject,
    NotOpenApiDocument,
    OpenApiPathsNotObject,
    OpenApiPathAlreadyExists(String),
    InvalidOpenApiPath(String),
    InvalidOpenApiPathItem(String),
    JsonFieldAlreadyExists(String),
    InvalidJsonFieldName,
}

impl fmt::Display for RewriteRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BodyTooLarge { actual, limit } => {
                write!(formatter, "body is {actual} bytes, exceeding limit {limit}")
            }
            Self::RewrittenBodyTooLarge { actual, limit } => {
                write!(
                    formatter,
                    "rewritten body is {actual} bytes, exceeding limit {limit}"
                )
            }
            Self::InvalidUtf8 => formatter.write_str("body is not valid UTF-8"),
            Self::HtmlSnippetDeniedByDenylist => {
                formatter.write_str("HTML snippet matched the rewrite denylist")
            }
            Self::InvalidJson(error) => write!(formatter, "invalid JSON: {error}"),
            Self::JsonRootNotObject => formatter.write_str("JSON root is not an object"),
            Self::NotOpenApiDocument => {
                formatter.write_str("JSON document does not look like OpenAPI")
            }
            Self::OpenApiPathsNotObject => {
                formatter.write_str("OpenAPI `paths` member is not an object")
            }
            Self::OpenApiPathAlreadyExists(path) => {
                write!(formatter, "OpenAPI path already exists: {path}")
            }
            Self::InvalidOpenApiPath(path) => write!(formatter, "invalid OpenAPI path: {path}"),
            Self::InvalidOpenApiPathItem(path) => {
                write!(formatter, "OpenAPI path item for {path} is not an object")
            }
            Self::JsonFieldAlreadyExists(name) => {
                write!(formatter, "JSON field already exists: {name}")
            }
            Self::InvalidJsonFieldName => formatter.write_str("JSON field name cannot be empty"),
        }
    }
}

impl std::error::Error for RewriteRefusal {}

pub fn rewrite_response_body(
    meta: &SurfaceResponseMeta,
    body: &[u8],
    plan: &RewritePlan,
) -> RewriteOutcome {
    let Some(operation) = &plan.operation else {
        return unchanged(body);
    };

    if operation.is_empty() {
        return unchanged(body);
    }

    match operation {
        RewriteOperation::Html(html) if is_html_response(meta) => rewrite_html(body, html),
        RewriteOperation::RobotsTxt(robots_txt) if is_robots_response(meta) => {
            rewrite_robots_txt(body, robots_txt)
        }
        RewriteOperation::OpenApiPaths(paths) if is_json_response(meta) => {
            rewrite_openapi_json(body, paths)
        }
        RewriteOperation::JsonFields(fields) if is_json_response(meta) => {
            rewrite_json_object(body, fields)
        }
        RewriteOperation::Html(_)
        | RewriteOperation::RobotsTxt(_)
        | RewriteOperation::OpenApiPaths(_)
        | RewriteOperation::JsonFields(_) => unchanged(body),
    }
}

pub fn rewrite_html(body: &[u8], insertion: &HtmlInsertion) -> RewriteOutcome {
    if let Err(reason) = ensure_bounded_body(body) {
        return refused(body, reason);
    }

    if insertion.snippet.is_empty() {
        return unchanged(body);
    }

    if !html_snippet_passes_rewrite_denylist(&insertion.snippet) {
        return refused(body, RewriteRefusal::HtmlSnippetDeniedByDenylist);
    }

    let Ok(original) = std::str::from_utf8(body) else {
        return refused(body, RewriteRefusal::InvalidUtf8);
    };

    let mut rewritten = String::with_capacity(original.len() + insertion.snippet.len());
    if let Some(index) = find_ascii_case_insensitive(original, "</body>") {
        rewritten.push_str(&original[..index]);
        rewritten.push_str(&insertion.snippet);
        rewritten.push_str(&original[index..]);
    } else {
        rewritten.push_str(original);
        rewritten.push_str(&insertion.snippet);
    }

    finish_rewrite(RewriteKind::Html, body, rewritten.into_bytes())
}

pub fn rewrite_robots_txt(body: &[u8], appendix: &RobotsTxtAppend) -> RewriteOutcome {
    if let Err(reason) = ensure_bounded_body(body) {
        return refused(body, reason);
    }

    let appendix = appendix.text.trim_matches('\n');
    if appendix.is_empty() {
        return unchanged(body);
    }

    let Ok(original) = std::str::from_utf8(body) else {
        return refused(body, RewriteRefusal::InvalidUtf8);
    };

    let mut rewritten = String::with_capacity(original.len() + appendix.len() + 2);
    rewritten.push_str(original);
    if !rewritten.is_empty() && !rewritten.ends_with('\n') {
        rewritten.push('\n');
    }
    rewritten.push_str(appendix);
    if !rewritten.ends_with('\n') {
        rewritten.push('\n');
    }

    finish_rewrite(RewriteKind::RobotsTxt, body, rewritten.into_bytes())
}

pub fn rewrite_openapi_json(body: &[u8], insertions: &[OpenApiPathInsertion]) -> RewriteOutcome {
    if let Err(reason) = ensure_bounded_body(body) {
        return refused(body, reason);
    }

    if insertions.is_empty() {
        return unchanged(body);
    }

    let mut document = match parse_json(body) {
        Ok(value) => value,
        Err(reason) => return refused(body, reason),
    };

    let Some(root) = document.as_object_mut() else {
        return refused(body, RewriteRefusal::JsonRootNotObject);
    };

    if !looks_like_openapi(root) {
        return refused(body, RewriteRefusal::NotOpenApiDocument);
    }

    for insertion in insertions {
        if !insertion.path.starts_with('/') {
            return refused(
                body,
                RewriteRefusal::InvalidOpenApiPath(insertion.path.clone()),
            );
        }

        if !insertion.path_item.is_object() {
            return refused(
                body,
                RewriteRefusal::InvalidOpenApiPathItem(insertion.path.clone()),
            );
        }
    }

    if !root.contains_key("paths") {
        root.insert("paths".to_string(), Value::Object(Map::new()));
    }

    let Some(paths) = root.get_mut("paths").and_then(Value::as_object_mut) else {
        return refused(body, RewriteRefusal::OpenApiPathsNotObject);
    };

    for insertion in insertions {
        if paths.contains_key(&insertion.path) {
            return refused(
                body,
                RewriteRefusal::OpenApiPathAlreadyExists(insertion.path.clone()),
            );
        }

        paths.insert(insertion.path.clone(), insertion.path_item.clone());
    }

    finish_json_rewrite(RewriteKind::OpenApiJson, body, document)
}

pub fn rewrite_json_object(body: &[u8], fields: &[JsonFieldInsertion]) -> RewriteOutcome {
    if let Err(reason) = ensure_bounded_body(body) {
        return refused(body, reason);
    }

    if fields.is_empty() {
        return unchanged(body);
    }

    let mut document = match parse_json(body) {
        Ok(value) => value,
        Err(reason) => return refused(body, reason),
    };

    let Some(root) = document.as_object_mut() else {
        return refused(body, RewriteRefusal::JsonRootNotObject);
    };

    for field in fields {
        if field.name.is_empty() {
            return refused(body, RewriteRefusal::InvalidJsonFieldName);
        }

        if root.contains_key(&field.name) {
            return refused(
                body,
                RewriteRefusal::JsonFieldAlreadyExists(field.name.clone()),
            );
        }
    }

    for field in fields {
        root.insert(field.name.clone(), field.value.clone());
    }

    finish_json_rewrite(RewriteKind::Json, body, document)
}

fn split_target(target: &str) -> (String, Option<String>) {
    let path_and_query = match target.find("://") {
        Some(scheme_end) => {
            let after_authority = target[scheme_end + 3..]
                .find('/')
                .map(|index| scheme_end + 3 + index);
            after_authority.map_or("/", |index| &target[index..])
        }
        None => target,
    };

    let (path, query) = match path_and_query.split_once('?') {
        Some((path, query)) => (path, Some(query.to_string())),
        None => (path_and_query, None),
    };

    let path = if path.is_empty() { "/" } else { path };
    (path.to_string(), query)
}

fn find_header<'a>(headers: &'a [SurfaceHeader], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

fn is_html_response(meta: &SurfaceResponseMeta) -> bool {
    meta.content_type()
        .map(|content_type| media_type(content_type).eq_ignore_ascii_case("text/html"))
        .unwrap_or(false)
}

fn is_robots_response(meta: &SurfaceResponseMeta) -> bool {
    meta.surface_path
        .as_deref()
        .map(|path| path.ends_with("/robots.txt") || path == "robots.txt")
        .unwrap_or(false)
}

fn is_json_response(meta: &SurfaceResponseMeta) -> bool {
    meta.content_type()
        .map(|content_type| {
            let media_type = media_type(content_type).to_ascii_lowercase();
            media_type == "application/json" || media_type.ends_with("+json")
        })
        .unwrap_or(false)
}

fn media_type(content_type: &str) -> &str {
    content_type.split(';').next().unwrap_or("").trim()
}

fn ensure_bounded_body(body: &[u8]) -> Result<(), RewriteRefusal> {
    if body.len() > MAX_REWRITE_BODY_BYTES {
        Err(RewriteRefusal::BodyTooLarge {
            actual: body.len(),
            limit: MAX_REWRITE_BODY_BYTES,
        })
    } else {
        Ok(())
    }
}

fn finish_json_rewrite(kind: RewriteKind, original: &[u8], rewritten: Value) -> RewriteOutcome {
    match serde_json::to_vec(&rewritten) {
        Ok(body) => finish_rewrite(kind, original, body),
        Err(error) => refused(original, RewriteRefusal::InvalidJson(error.to_string())),
    }
}

fn finish_rewrite(kind: RewriteKind, original: &[u8], rewritten: Vec<u8>) -> RewriteOutcome {
    if rewritten.len() > MAX_REWRITE_BODY_BYTES {
        return refused(
            original,
            RewriteRefusal::RewrittenBodyTooLarge {
                actual: rewritten.len(),
                limit: MAX_REWRITE_BODY_BYTES,
            },
        );
    }

    if original == rewritten {
        return unchanged(original);
    }

    RewriteOutcome::Rewritten {
        log: RewriteLogRecord {
            kind,
            original_body: original.to_vec(),
            rewritten_body: rewritten,
        },
    }
}

fn parse_json(body: &[u8]) -> Result<Value, RewriteRefusal> {
    serde_json::from_slice(body).map_err(|error| RewriteRefusal::InvalidJson(error.to_string()))
}

fn unchanged(body: &[u8]) -> RewriteOutcome {
    RewriteOutcome::Unchanged {
        body: body.to_vec(),
    }
}

fn refused(body: &[u8], reason: RewriteRefusal) -> RewriteOutcome {
    RewriteOutcome::Refused {
        body: body.to_vec(),
        reason,
    }
}

fn looks_like_openapi(root: &Map<String, Value>) -> bool {
    root.get("openapi").is_some() || root.get("swagger").is_some()
}

fn find_ascii_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    haystack.to_ascii_lowercase().find(needle)
}

fn html_snippet_passes_rewrite_denylist(snippet: &str) -> bool {
    // This denylist catches obvious active-content snippets; it is not a CSP proof.
    let normalized = snippet.to_ascii_lowercase();
    !normalized.contains("<script")
        && !normalized.contains("javascript:")
        && !normalized.contains("data:text/html")
        && !has_inline_event_handler(&normalized)
}

fn has_inline_event_handler(normalized: &str) -> bool {
    let bytes = normalized.as_bytes();

    for index in 0..bytes.len().saturating_sub(3) {
        if !bytes[index].is_ascii_whitespace()
            || bytes[index + 1] != b'o'
            || bytes[index + 2] != b'n'
        {
            continue;
        }

        let mut cursor = index + 3;
        while cursor < bytes.len() && bytes[cursor].is_ascii_alphabetic() {
            cursor += 1;
        }

        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }

        if cursor < bytes.len() && bytes[cursor] == b'=' {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;

    #[test]
    fn surface_action_reports_core_routing_decision() {
        let action = SurfaceAction::RewrittenUpstream {
            plan: RewritePlan::html(HtmlInsertion::new(r#"<div id="eidolon"></div>"#)),
        };

        assert_eq!(
            action.routing_decision(),
            RoutingDecision::RewrittenUpstream
        );
        assert!(action.is_upstream());
    }

    #[test]
    fn request_metadata_splits_origin_and_absolute_targets() {
        let origin = SurfaceRequestMeta::new("GET", "/docs?view=full", Vec::new(), 0);
        assert_eq!(origin.path, "/docs");
        assert_eq!(origin.query.as_deref(), Some("view=full"));

        let absolute =
            SurfaceRequestMeta::new("GET", "http://127.0.0.1:8080/openapi.json", Vec::new(), 0);
        assert_eq!(absolute.path, "/openapi.json");
        assert_eq!(absolute.query, None);
    }

    #[test]
    fn empty_rewrite_plans_report_empty() {
        assert!(RewritePlan::default().is_empty());
        assert!(RewritePlan::html(HtmlInsertion::new("")).is_empty());
        assert!(RewritePlan::robots_txt(RobotsTxtAppend::new("\n\n")).is_empty());
        assert!(RewritePlan::openapi_paths(Vec::new()).is_empty());
        assert!(RewritePlan::json_fields(Vec::new()).is_empty());
    }

    #[test]
    fn rewrites_html_by_inserting_before_body_close() {
        let original = b"<html><body><main>docs</main></body></html>";
        let snippet = HtmlInsertion::new(r#"<div data-eidolon-surface="legacy"></div>"#);

        let outcome = rewrite_html(original, &snippet);

        assert!(outcome.is_rewritten());
        assert_eq!(outcome.disposition(), RewriteDisposition::Rewritten);
        assert_eq!(
            std::str::from_utf8(outcome.body()).unwrap(),
            r#"<html><body><main>docs</main><div data-eidolon-surface="legacy"></div></body></html>"#
        );

        let RewriteOutcome::Rewritten { log } = outcome else {
            panic!("expected rewritten HTML");
        };
        assert_eq!(log.kind, RewriteKind::Html);
        assert_eq!(log.restore_body(), original);
    }

    #[test]
    fn rewrites_html_by_appending_when_body_close_is_absent() {
        let original = b"<html><main>docs</main></html>";
        let snippet = HtmlInsertion::new(r#"<div data-eidolon-surface="legacy"></div>"#);

        let outcome = rewrite_html(original, &snippet);

        assert_eq!(
            std::str::from_utf8(outcome.body()).unwrap(),
            r#"<html><main>docs</main></html><div data-eidolon-surface="legacy"></div>"#
        );
    }

    #[test]
    fn appends_robots_txt_with_line_boundaries() {
        let original = b"User-agent: *\nDisallow: /admin";
        let appendix = RobotsTxtAppend::new("Allow: /docs/legacy-import");

        let outcome = rewrite_robots_txt(original, &appendix);

        assert!(outcome.is_rewritten());
        assert_eq!(
            std::str::from_utf8(outcome.body()).unwrap(),
            "User-agent: *\nDisallow: /admin\nAllow: /docs/legacy-import\n"
        );
    }

    #[test]
    fn appends_robots_txt_without_leading_blank_line_for_empty_original() {
        let outcome = rewrite_robots_txt(b"", &RobotsTxtAppend::new("Disallow: /decoy"));

        assert_eq!(
            std::str::from_utf8(outcome.body()).unwrap(),
            "Disallow: /decoy\n"
        );
    }

    #[test]
    fn rewrite_response_body_only_applies_media_specific_operations() {
        let html_plan = RewritePlan::html(HtmlInsertion::new("<div></div>"));
        let html_without_content_type = SurfaceResponseMeta::new(200, Vec::new(), 0);
        assert_eq!(
            rewrite_response_body(&html_without_content_type, b"<html></html>", &html_plan)
                .disposition(),
            RewriteDisposition::Unchanged
        );

        let robots_plan = RewritePlan::robots_txt(RobotsTxtAppend::new("Disallow: /decoy"));
        let nested_robots =
            SurfaceResponseMeta::for_surface(200, "/assets/robots.txt", Vec::new(), 0);
        assert_eq!(
            rewrite_response_body(&nested_robots, b"User-agent: *\n", &robots_plan).disposition(),
            RewriteDisposition::Rewritten
        );

        let unrelated_path = SurfaceResponseMeta::for_surface(200, "/docs", Vec::new(), 0);
        assert_eq!(
            rewrite_response_body(&unrelated_path, b"User-agent: *\n", &robots_plan).disposition(),
            RewriteDisposition::Unchanged
        );
    }

    #[test]
    fn inserts_openapi_path_with_json_value() {
        let original = br#"{"openapi":"3.0.0","info":{"title":"demo","version":"0"},"paths":{}}"#;
        let path_item = json!({
            "post": {
                "responses": {
                    "202": {
                        "description": "queued"
                    }
                }
            }
        });

        let outcome = rewrite_openapi_json(
            original,
            &[OpenApiPathInsertion::new(
                "/api/v2/import/reconcile",
                path_item.clone(),
            )],
        );

        assert!(outcome.is_rewritten());
        let rewritten: Value = serde_json::from_slice(outcome.body()).unwrap();
        assert_eq!(rewritten["paths"]["/api/v2/import/reconcile"], path_item);
        assert_eq!(rewritten["openapi"], json!("3.0.0"));
    }

    #[test]
    fn inserts_generic_json_object_field() {
        let original = br#"{"service":"docs"}"#;

        let outcome = rewrite_json_object(
            original,
            &[JsonFieldInsertion::new(
                "eidolon_surface",
                json!("legacy-import"),
            )],
        );

        assert!(outcome.is_rewritten());
        let rewritten: Value = serde_json::from_slice(outcome.body()).unwrap();
        assert_eq!(rewritten["service"], json!("docs"));
        assert_eq!(rewritten["eidolon_surface"], json!("legacy-import"));
    }

    #[test]
    fn rewrite_plan_selects_one_json_operation_without_priority_masking() {
        let original = br#"{"openapi":"3.0.0","info":{"title":"demo","version":"0"},"paths":{}}"#;
        let meta = SurfaceResponseMeta::new(
            200,
            vec![SurfaceHeader::new("content-type", "application/json")],
            original.len(),
        );
        let path_item = json!({"get":{"responses":{"200":{"description":"ok"}}}});

        let openapi_outcome = rewrite_response_body(
            &meta,
            original,
            &RewritePlan::openapi_paths(vec![OpenApiPathInsertion::new(
                "/api/v2/import/reconcile",
                path_item.clone(),
            )]),
        );

        assert_eq!(openapi_outcome.disposition(), RewriteDisposition::Rewritten);
        let openapi_rewritten: Value = serde_json::from_slice(openapi_outcome.body()).unwrap();
        assert_eq!(
            openapi_rewritten["paths"]["/api/v2/import/reconcile"],
            path_item
        );
        assert!(openapi_rewritten.get("eidolon_surface").is_none());

        let json_outcome = rewrite_response_body(
            &meta,
            original,
            &RewritePlan::json_fields(vec![JsonFieldInsertion::new(
                "eidolon_surface",
                json!("legacy-import"),
            )]),
        );

        assert_eq!(json_outcome.disposition(), RewriteDisposition::Rewritten);
        let json_rewritten: Value = serde_json::from_slice(json_outcome.body()).unwrap();
        assert_eq!(json_rewritten["eidolon_surface"], json!("legacy-import"));
        assert!(json_rewritten["paths"].as_object().unwrap().is_empty());
    }

    #[test]
    fn rewrite_outcome_distinguishes_unchanged_rewritten_and_refused() {
        let meta = SurfaceResponseMeta::new(
            200,
            vec![SurfaceHeader::new("content-type", "text/html")],
            0,
        );

        let unchanged = rewrite_response_body(&meta, b"<html></html>", &RewritePlan::default());
        assert_eq!(unchanged.disposition(), RewriteDisposition::Unchanged);
        assert_eq!(unchanged.refusal(), None);

        let rewritten = rewrite_response_body(
            &meta,
            b"<html><body></body></html>",
            &RewritePlan::html(HtmlInsertion::new("<div></div>")),
        );
        assert_eq!(rewritten.disposition(), RewriteDisposition::Rewritten);
        assert_eq!(rewritten.refusal(), None);

        let refused = rewrite_response_body(
            &meta,
            b"<html><body></body></html>",
            &RewritePlan::html(HtmlInsertion::new("<script>alert(1)</script>")),
        );
        assert_eq!(refused.disposition(), RewriteDisposition::Refused);
        assert_eq!(
            refused.refusal(),
            Some(&RewriteRefusal::HtmlSnippetDeniedByDenylist)
        );
    }

    #[test]
    fn refuses_html_snippet_that_matches_rewrite_denylist() {
        let original = b"<html><body></body></html>";

        let outcome = rewrite_html(
            original,
            &HtmlInsertion::new(r#"<img src="/x" onerror="alert(1)">"#),
        );

        assert_eq!(outcome.body(), original);
        assert_eq!(
            outcome.refusal(),
            Some(&RewriteRefusal::HtmlSnippetDeniedByDenylist)
        );
        assert_eq!(
            outcome.refusal().unwrap().to_string(),
            "HTML snippet matched the rewrite denylist"
        );
    }

    #[test]
    fn refuses_oversize_body_without_changing_bytes() {
        let original = vec![b'a'; MAX_REWRITE_BODY_BYTES + 1];

        let outcome = rewrite_html(&original, &HtmlInsertion::new("<div></div>"));

        assert_eq!(outcome.body(), original.as_slice());
        assert_eq!(outcome.disposition(), RewriteDisposition::Refused);
        assert_eq!(
            outcome.refusal(),
            Some(&RewriteRefusal::BodyTooLarge {
                actual: MAX_REWRITE_BODY_BYTES + 1,
                limit: MAX_REWRITE_BODY_BYTES
            })
        );
    }

    #[test]
    fn rewrite_body_limit_allows_exactly_the_configured_limit() {
        let original = vec![b'a'; MAX_REWRITE_BODY_BYTES];

        assert_eq!(ensure_bounded_body(&original), Ok(()));
        assert_eq!(MAX_REWRITE_BODY_BYTES, 256 * 1024);
    }

    #[test]
    fn inline_event_handler_detection_does_not_treat_prefix_without_equals_as_handler() {
        assert!(html_snippet_passes_rewrite_denylist(
            r#"<div onload class="passive"></div>"#
        ));
    }
}
