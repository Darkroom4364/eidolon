use std::{
    env,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    thread,
};

use serde_json::Value;

const DEFAULT_ADDR: &str = "127.0.0.1:9001";
const ADDR_ENV: &str = "EIDOLON_LAB_TARGET_ADDR";
const OWNED_CLUSTER_LAB_ENV: &str = "EIDOLON_OWNED_CLUSTER_LAB";
const PROFILE_ENV: &str = "EIDOLON_LAB_TARGET_PROFILE";
const DEFAULT_PROFILE: &str = "default";
const NEGATIVE_CONTROL_PROFILE: &str = "qualification_negative_control";
const SHIELD_LAB_PROBE_HEADER: &str = "X-Shield-Lab-Probe";
const SHIELD_LAB_PROBE_ID_PREFIX: &str = "shield-probe-";
const MAX_SHIELD_LAB_PROBE_ID_LEN: usize = 64;
const SECURITY_HEADERS: &[(&str, &str)] = &[
    (
        "Content-Security-Policy",
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    ),
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
];

fn main() -> io::Result<()> {
    let addr = env::var(ADDR_ENV).unwrap_or_else(|_| DEFAULT_ADDR.to_string());
    let owned_cluster_lab = env_flag_enabled(OWNED_CLUSTER_LAB_ENV);
    let profile = TargetProfile::from_env()?;
    ensure_allowed_lab_addr(&addr, owned_cluster_lab)?;

    let listener = TcpListener::bind(&addr)?;
    println!("eidolon-demo-target listening on http://{addr}");
    println!("target profile: {}", profile.as_str());
    if owned_cluster_lab {
        println!("owned cluster lab enabled via {OWNED_CLUSTER_LAB_ENV}=1");
    } else {
        println!("local owned-target lab only; set {ADDR_ENV}=127.0.0.1:<port> to change the port");
    }

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    if let Err(error) = handle_connection(stream, profile) {
                        eprintln!("connection error: {error}");
                    }
                });
            }
            Err(error) => eprintln!("accept error: {error}"),
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetProfile {
    Default,
    QualificationNegativeControl,
}

impl TargetProfile {
    fn from_env() -> io::Result<Self> {
        match env::var(PROFILE_ENV) {
            Ok(value) => match value.as_str() {
                DEFAULT_PROFILE => Ok(Self::Default),
                NEGATIVE_CONTROL_PROFILE => Ok(Self::QualificationNegativeControl),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "{PROFILE_ENV} must be one of: {DEFAULT_PROFILE}, {NEGATIVE_CONTROL_PROFILE}"
                    ),
                )),
            },
            Err(env::VarError::NotPresent) => Ok(Self::Default),
            Err(env::VarError::NotUnicode(_)) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{PROFILE_ENV} must be valid utf-8"),
            )),
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Default => DEFAULT_PROFILE,
            Self::QualificationNegativeControl => NEGATIVE_CONTROL_PROFILE,
        }
    }
}

fn ensure_allowed_lab_addr(addr: &str, owned_cluster_lab: bool) -> io::Result<()> {
    let socket_addr = addr.parse::<SocketAddr>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{ADDR_ENV} must be a socket address such as 127.0.0.1:9001: {error}"),
        )
    })?;

    if owned_cluster_lab || socket_addr.ip().is_loopback() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{ADDR_ENV} must bind to a loopback address for the local lab"),
        ))
    }
}

fn env_flag_enabled(name: &str) -> bool {
    matches!(
        env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

fn handle_connection(mut stream: TcpStream, profile: TargetProfile) -> io::Result<()> {
    let mut buffer = [0; 8192];
    let bytes_read = stream.read(&mut buffer)?;
    if bytes_read == 0 {
        return Ok(());
    }

    let request = Request::parse(&buffer[..bytes_read]);
    audit_protected_upstream_probe(&request)?;
    let response = route_request(profile, &request);
    stream.write_all(&response.to_http_bytes())?;
    stream.flush()
}

fn audit_protected_upstream_probe(request: &Request) -> io::Result<()> {
    let Some(event) = protected_upstream_probe_audit_event(request) else {
        return Ok(());
    };

    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{event}")?;
    stdout.flush()
}

fn protected_upstream_probe_audit_event(request: &Request) -> Option<Value> {
    let route = match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/api/v2/import/reconcile") => "api_v2_import_reconcile",
        ("POST", "/api/v1/imports") => "api_v1_imports",
        _ => return None,
    };

    let mut event = serde_json::json!({
        "event": "protected_upstream_probe_observed",
        "method": "POST",
        "route": route,
    });
    if let Some(probe_id) = protected_upstream_probe_id(request) {
        event["probe_id"] = Value::String(probe_id.to_string());
    }
    Some(event)
}

fn protected_upstream_probe_id(request: &Request) -> Option<&str> {
    let mut probe_headers = request
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(SHIELD_LAB_PROBE_HEADER))
        .map(|(_, value)| value.as_str());
    let probe_id = probe_headers.next()?;
    if probe_headers.next().is_some() || !is_safe_shield_lab_probe_id(probe_id) {
        return None;
    }

    Some(probe_id)
}

fn is_safe_shield_lab_probe_id(value: &str) -> bool {
    if value.len() > MAX_SHIELD_LAB_PROBE_ID_LEN {
        return false;
    }

    let Some(suffix) = value.strip_prefix(SHIELD_LAB_PROBE_ID_PREFIX) else {
        return false;
    };
    let bytes = suffix.as_bytes();
    !bytes.is_empty()
        && bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn parse(bytes: &[u8]) -> Self {
        let header_end = bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|index| index + 4)
            .unwrap_or(bytes.len());
        let header_bytes = &bytes[..header_end.min(bytes.len())];
        let body = if header_end <= bytes.len() {
            bytes[header_end..].to_vec()
        } else {
            Vec::new()
        };
        let request = String::from_utf8_lossy(header_bytes);
        let mut lines = request.lines();
        let request_line = lines.next().unwrap_or_default();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_string();
        let path = parts
            .next()
            .unwrap_or("/")
            .split('?')
            .next()
            .unwrap_or("/")
            .to_string();
        let headers = lines
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                Some((name.trim().to_string(), value.trim().to_string()))
            })
            .collect();

        Self {
            method,
            path,
            headers,
            body,
        }
    }

    #[cfg(test)]
    fn for_test(method: &str, path: &str) -> Self {
        Self {
            method: method.to_string(),
            path: path.to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    #[cfg(test)]
    fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    #[cfg(test)]
    fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find_map(|(header_name, header_value)| {
            if header_name.eq_ignore_ascii_case(name) {
                Some(header_value.as_str())
            } else {
                None
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Response {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    body: String,
}

impl Response {
    fn ok_html(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            reason: "OK",
            content_type: "text/html; charset=utf-8",
            body: body.into(),
        }
    }

    fn ok_json(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            reason: "OK",
            content_type: "application/json",
            body: body.into(),
        }
    }

    fn accepted_json(body: impl Into<String>) -> Self {
        Self {
            status: 202,
            reason: "Accepted",
            content_type: "application/json",
            body: body.into(),
        }
    }

    fn bad_request_json(body: impl Into<String>) -> Self {
        Self {
            status: 400,
            reason: "Bad Request",
            content_type: "application/json",
            body: body.into(),
        }
    }

    fn unsupported_media_type_json(body: impl Into<String>) -> Self {
        Self {
            status: 415,
            reason: "Unsupported Media Type",
            content_type: "application/json",
            body: body.into(),
        }
    }

    fn not_found(path: &str) -> Self {
        Self {
            status: 404,
            reason: "Not Found",
            content_type: "application/json",
            body: format!(
                r#"{{"error":"not_found","path":"{}","target":"eidolon-demo-target"}}"#,
                escape_json(path)
            ),
        }
    }

    fn method_not_allowed(method: &str, path: &str) -> Self {
        Self {
            status: 405,
            reason: "Method Not Allowed",
            content_type: "application/json",
            body: format!(
                r#"{{"error":"method_not_allowed","method":"{}","path":"{}"}}"#,
                escape_json(method),
                escape_json(path)
            ),
        }
    }

    fn to_http_bytes(&self) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\n",
            self.status, self.reason, self.content_type,
        );
        for (name, value) in SECURITY_HEADERS {
            response.push_str(name);
            response.push_str(": ");
            response.push_str(value);
            response.push_str("\r\n");
        }
        response.push_str(&format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.body.len(),
            self.body,
        ));
        response.into_bytes()
    }
}

fn route_request(profile: TargetProfile, request: &Request) -> Response {
    match (profile, request.method.as_str(), request.path.as_str()) {
        (TargetProfile::Default, "GET", "/") => Response::ok_html(home_page()),
        (_, "GET", "/health") => {
            Response::ok_json(r#"{"status":"ok","target":"eidolon-demo-target"}"#)
        }
        (TargetProfile::Default, "GET", "/docs") => Response::ok_html(docs_page()),
        (TargetProfile::Default, "GET", "/openapi.json") => Response::ok_json(openapi_document()),
        (TargetProfile::Default, "GET", "/api/v1/projects") => Response::ok_json(projects_json()),
        (TargetProfile::Default, "GET", path) if path.starts_with("/api/v1/projects/") => {
            project_detail(path)
        }
        (TargetProfile::Default, "POST", "/api/v1/imports") => create_import(request),
        (TargetProfile::Default, "GET", path) if path.starts_with("/api/v1/imports/") => {
            import_detail(path)
        }
        (TargetProfile::QualificationNegativeControl, "GET", "/") => {
            Response::ok_html(qualification_negative_control_home_page())
        }
        (TargetProfile::QualificationNegativeControl, "GET", "/docs") => {
            Response::ok_html(qualification_negative_control_docs_page())
        }
        (TargetProfile::QualificationNegativeControl, "GET", "/openapi.json") => {
            Response::ok_json(qualification_negative_control_openapi_document())
        }
        (TargetProfile::Default, method, path @ ("/" | "/docs" | "/openapi.json")) => {
            Response::method_not_allowed(method, path)
        }
        (TargetProfile::Default, method, path @ "/api/v1/projects") => {
            Response::method_not_allowed(method, path)
        }
        (_, "POST", path) if path.starts_with("/api/") => Response::not_found(path),
        (_, _, path) => Response::not_found(path),
    }
}

fn create_import(request: &Request) -> Response {
    let Some(content_type) = request.header("Content-Type") else {
        return Response::unsupported_media_type_json(
            r#"{"error":"unsupported_media_type","expected":"application/json"}"#,
        );
    };
    if !content_type.eq_ignore_ascii_case("application/json")
        && !content_type
            .to_ascii_lowercase()
            .starts_with("application/json;")
    {
        return Response::unsupported_media_type_json(
            r#"{"error":"unsupported_media_type","expected":"application/json"}"#,
        );
    }

    let payload = match serde_json::from_slice::<Value>(&request.body) {
        Ok(Value::Object(object)) => object,
        Ok(_) => {
            return Response::bad_request_json(
                r#"{"error":"invalid_request","message":"request body must be a JSON object"}"#,
            )
        }
        Err(_) => {
            return Response::bad_request_json(
                r#"{"error":"invalid_request","message":"request body must be valid JSON"}"#,
            )
        }
    };

    let source = payload.get("source").and_then(Value::as_str).map(str::trim);
    if source.map(str::is_empty).unwrap_or(true) {
        return Response::bad_request_json(
            r#"{"error":"invalid_request","message":"source must be a non-empty string"}"#,
        );
    }

    if let Some(mode) = payload.get("mode") {
        if mode.as_str() != Some("synthetic") {
            return Response::bad_request_json(
                r#"{"error":"invalid_request","message":"mode must be \"synthetic\" when provided"}"#,
            );
        }
    }

    Response::accepted_json(import_job_json("demo-import-1"))
}

fn home_page() -> &'static str {
    r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Eidolon Demo Target</title></head>
<body>
  <main>
    <h1>Eidolon Demo Target</h1>
    <p>Local-only synthetic project tracker for Eidolon Lab.</p>
    <nav>
      <a href="/docs">Docs</a>
      <a href="/openapi.json">OpenAPI</a>
      <a href="/api/v1/projects">Projects API</a>
    </nav>
  </main>
</body>
</html>"#
}

fn qualification_negative_control_home_page() -> &'static str {
    r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Eidolon Qualification Target</title></head>
<body>
  <main>
    <h1>Eidolon Qualification Target</h1>
    <p>Intentionally simple owned target for scanner negative-control qualification.</p>
    <nav>
      <a href="/docs">Docs</a>
      <a href="/openapi.json">OpenAPI</a>
      <a href="/health">Health</a>
    </nav>
  </main>
</body>
</html>"#
}

fn docs_page() -> &'static str {
    r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Demo Target Docs</title></head>
<body>
  <main>
    <h1>Demo Target Docs</h1>
    <p>This local target exposes normal project and import APIs for Eidolon Lab.</p>
    <h2>Projects</h2>
    <p>Use <code>GET /api/v1/projects</code> to list synthetic projects.</p>
    <h2>Imports</h2>
    <p>Use <code>POST /api/v1/imports</code> to create a synthetic import job.</p>
    <p>No endpoint in this target is intentionally vulnerable.</p>
  </main>
</body>
</html>"#
}

fn qualification_negative_control_docs_page() -> &'static str {
    r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Qualification Target Docs</title></head>
<body>
  <main>
    <h1>Qualification Target Docs</h1>
    <p>This owned target is intentionally simple and is used as a negative control for scanner qualification.</p>
    <h2>Supported endpoint</h2>
    <p>Use <code>GET /health</code> to verify the service is reachable.</p>
    <p>No project, import, authentication, or write surfaces are exposed in this profile.</p>
  </main>
</body>
</html>"#
}

fn openapi_document() -> &'static str {
    r#"{
  "openapi": "3.0.3",
  "info": {
    "title": "Eidolon Demo Target",
    "version": "0.1.0",
    "description": "Local-only synthetic project tracker for Eidolon Lab."
  },
  "paths": {
    "/health": {
      "get": {
        "summary": "Health check",
        "responses": {
          "200": { "description": "Target is healthy" }
        }
      }
    },
    "/api/v1/projects": {
      "get": {
        "summary": "List synthetic projects",
        "responses": {
          "200": { "description": "Project list" }
        }
      }
    },
    "/api/v1/projects/{id}": {
      "get": {
        "summary": "Get a synthetic project",
        "parameters": [
          { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }
        ],
        "responses": {
          "200": { "description": "Project detail" },
          "404": { "description": "Project not found" }
        }
      }
    },
    "/api/v1/imports": {
      "post": {
        "summary": "Create a synthetic import job",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["source"],
                "properties": {
                  "source": { "type": "string", "minLength": 1 },
                  "mode": { "type": "string", "enum": ["synthetic"] }
                }
              }
            }
          }
        },
        "responses": {
          "202": { "description": "Import accepted" },
          "400": { "description": "Invalid import request" },
          "415": { "description": "Unsupported media type" }
        }
      }
    },
    "/api/v1/imports/{id}": {
      "get": {
        "summary": "Get synthetic import status",
        "parameters": [
          { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }
        ],
        "responses": {
          "200": { "description": "Import status" }
        }
      }
    }
  }
}"#
}

fn qualification_negative_control_openapi_document() -> &'static str {
    r#"{
  "openapi": "3.0.3",
  "info": {
    "title": "Eidolon Qualification Negative Control Target",
    "version": "0.1.0",
    "description": "Intentionally simple owned target for scanner negative-control qualification."
  },
  "paths": {
    "/health": {
      "get": {
        "summary": "Health check",
        "responses": {
          "200": { "description": "Target is healthy" }
        }
      }
    }
  }
}"#
}

fn projects_json() -> &'static str {
    r#"{
  "projects": [
    {
      "id": "alpha",
      "name": "Alpha Migration",
      "owner": "platform",
      "status": "active"
    },
    {
      "id": "bravo",
      "name": "Bravo Reporting",
      "owner": "analytics",
      "status": "planning"
    }
  ]
}"#
}

fn project_detail(path: &str) -> Response {
    match path.trim_start_matches("/api/v1/projects/") {
        "alpha" => Response::ok_json(
            r#"{"id":"alpha","name":"Alpha Migration","owner":"platform","status":"active"}"#,
        ),
        "bravo" => Response::ok_json(
            r#"{"id":"bravo","name":"Bravo Reporting","owner":"analytics","status":"planning"}"#,
        ),
        _ => Response::not_found(path),
    }
}

fn import_detail(path: &str) -> Response {
    let id = path.trim_start_matches("/api/v1/imports/");
    match id {
        "demo-import-1" => Response::ok_json(import_job_json(id)),
        _ => Response::not_found(path),
    }
}

fn import_job_json(id: &str) -> String {
    format!(
        r#"{{"id":"{}","status":"accepted","mode":"synthetic","writes":"none"}}"#,
        escape_json(id)
    )
}

fn escape_json(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn must_ok<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{context}: {error}"),
        }
    }

    #[test]
    fn default_lab_address_is_loopback() {
        must_ok(
            ensure_allowed_lab_addr(DEFAULT_ADDR, false),
            "default address should be loopback",
        );
    }

    #[test]
    fn non_loopback_lab_address_is_rejected() {
        let error =
            ensure_allowed_lab_addr("0.0.0.0:9001", false).expect_err("wildcard bind is rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn owned_cluster_lab_allows_non_loopback_bind() {
        must_ok(
            ensure_allowed_lab_addr("0.0.0.0:9001", true),
            "owned cluster lab should allow non-loopback bind",
        );
    }

    #[test]
    fn exposes_normal_docs_and_openapi() {
        assert_eq!(
            route_request(TargetProfile::Default, &Request::for_test("GET", "/docs")).status,
            200
        );
        let openapi = route_request(
            TargetProfile::Default,
            &Request::for_test("GET", "/openapi.json"),
        );
        assert_eq!(openapi.status, 200);
        assert!(openapi.body.contains(r#""openapi": "3.0.3""#));
        assert!(openapi.body.contains("/api/v1/imports"));
        assert!(openapi.body.contains(r#""required": ["source"]"#));
    }

    #[test]
    fn project_routes_return_synthetic_data() {
        let list = route_request(
            TargetProfile::Default,
            &Request::for_test("GET", "/api/v1/projects"),
        );
        assert_eq!(list.status, 200);
        assert!(list.body.contains("Alpha Migration"));

        let detail = route_request(
            TargetProfile::Default,
            &Request::for_test("GET", "/api/v1/projects/alpha"),
        );
        assert_eq!(detail.status, 200);
        assert!(detail.body.contains(r#""id":"alpha""#));
    }

    #[test]
    fn import_post_requires_valid_json_request() {
        let response = route_request(
            TargetProfile::Default,
            &Request::for_test("POST", "/api/v1/imports")
                .with_header("Content-Type", "application/json")
                .with_body(br#"{"source":"lab","mode":"synthetic"}"#.to_vec()),
        );
        assert_eq!(response.status, 202);
        assert!(response.body.contains(r#""writes":"none""#));
    }

    #[test]
    fn import_post_rejects_malformed_or_non_json_bodies() {
        let malformed = route_request(
            TargetProfile::Default,
            &Request::for_test("POST", "/api/v1/imports")
                .with_header("Content-Type", "application/json")
                .with_body(br#"{"source":"lab""#.to_vec()),
        );
        assert_eq!(malformed.status, 400);

        let missing_source = route_request(
            TargetProfile::Default,
            &Request::for_test("POST", "/api/v1/imports")
                .with_header("Content-Type", "application/json")
                .with_body(br#"{"mode":"synthetic"}"#.to_vec()),
        );
        assert_eq!(missing_source.status, 400);

        let plain_text = route_request(
            TargetProfile::Default,
            &Request::for_test("POST", "/api/v1/imports")
                .with_header("Content-Type", "text/plain")
                .with_body(b"hello".to_vec()),
        );
        assert_eq!(plain_text.status, 415);
    }

    #[test]
    fn responses_include_browser_hardening_headers() {
        let response = route_request(TargetProfile::Default, &Request::for_test("GET", "/docs"));
        let bytes = response.to_http_bytes();
        let raw = String::from_utf8(bytes).expect("response should be utf8");

        assert!(raw.contains(
            "Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'\r\n"
        ));
        assert!(raw.contains("X-Frame-Options: DENY\r\n"));
        assert!(raw.contains("X-Content-Type-Options: nosniff\r\n"));
        assert!(raw.contains("Referrer-Policy: no-referrer\r\n"));
    }

    #[test]
    fn import_status_only_returns_known_synthetic_job() {
        let known = route_request(
            TargetProfile::Default,
            &Request::for_test("GET", "/api/v1/imports/demo-import-1"),
        );
        assert_eq!(known.status, 200);
        assert!(known.body.contains(r#""id":"demo-import-1""#));

        let unknown = route_request(
            TargetProfile::Default,
            &Request::for_test("GET", "/api/v1/imports/not-a-real-import-xyz"),
        );
        assert_eq!(unknown.status, 404);
    }

    #[test]
    fn legacy_bait_route_is_not_real_target_behavior() {
        let response = route_request(
            TargetProfile::Default,
            &Request::for_test("POST", "/api/v2/import/reconcile"),
        );
        assert_eq!(response.status, 404);
    }

    #[test]
    fn valid_shield_lab_probe_emits_only_the_safe_probe_id() {
        let request = Request::for_test("POST", "/api/v2/import/reconcile")
            .with_header("x-shield-lab-probe", "shield-probe-20260724-a1b2c3d4");

        assert_eq!(
            protected_upstream_probe_audit_event(&request),
            Some(serde_json::json!({
                "event": "protected_upstream_probe_observed",
                "method": "POST",
                "probe_id": "shield-probe-20260724-a1b2c3d4",
                "route": "api_v2_import_reconcile",
            }))
        );
    }

    #[test]
    fn shield_lab_probe_audits_the_protected_import_write_route() {
        let request = Request::for_test("POST", "/api/v1/imports")
            .with_header("x-shield-lab-probe", "shield-probe-escape-a1b2c3d4");

        assert_eq!(
            protected_upstream_probe_audit_event(&request),
            Some(serde_json::json!({
                "event": "protected_upstream_probe_observed",
                "method": "POST",
                "probe_id": "shield-probe-escape-a1b2c3d4",
                "route": "api_v1_imports",
            }))
        );
    }

    #[test]
    fn shield_lab_probe_audit_rejects_untrusted_header_values() {
        let invalid_values = [
            "",
            "arbitrary",
            "shield-probe-",
            "shield-probe-UPPERCASE",
            "shield-probe-leading space",
            "shield-probe-json\"escape",
            "shield-probe-unicode-\u{e9}",
            "shield-probe-trailing-",
            "shield-probe-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ];

        for value in invalid_values {
            let request = Request::for_test("POST", "/api/v2/import/reconcile")
                .with_header(SHIELD_LAB_PROBE_HEADER, value);
            assert_eq!(
                protected_upstream_probe_audit_event(&request),
                Some(serde_json::json!({
                    "event": "protected_upstream_probe_observed",
                    "method": "POST",
                    "route": "api_v2_import_reconcile",
                })),
                "unsafe probe header leaked into the audit: {value:?}"
            );
        }
    }

    #[test]
    fn shield_lab_probe_audit_requires_the_exact_route() {
        let valid_probe_id = "shield-probe-20260724-a1b2c3d4";
        let wrong_method = Request::for_test("GET", "/api/v2/import/reconcile")
            .with_header(SHIELD_LAB_PROBE_HEADER, valid_probe_id);
        let wrong_path = Request::for_test("POST", "/api/v1/projects")
            .with_header(SHIELD_LAB_PROBE_HEADER, valid_probe_id);

        for request in [wrong_method, wrong_path] {
            assert_eq!(protected_upstream_probe_audit_event(&request), None);
        }
    }

    #[test]
    fn reconcile_probe_audit_survives_missing_or_duplicate_markers() {
        let missing_header = Request::for_test("POST", "/api/v2/import/reconcile");
        let duplicate_header = Request::for_test("POST", "/api/v2/import/reconcile")
            .with_header(SHIELD_LAB_PROBE_HEADER, "shield-probe-20260724-a1b2c3d4")
            .with_header(SHIELD_LAB_PROBE_HEADER, "shield-probe-other");

        for request in [missing_header, duplicate_header] {
            assert_eq!(
                protected_upstream_probe_audit_event(&request),
                Some(serde_json::json!({
                    "event": "protected_upstream_probe_observed",
                    "method": "POST",
                    "route": "api_v2_import_reconcile",
                }))
            );
        }
    }

    #[test]
    fn qualification_negative_control_profile_exposes_only_minimal_surface() {
        let docs = route_request(
            TargetProfile::QualificationNegativeControl,
            &Request::for_test("GET", "/docs"),
        );
        assert_eq!(docs.status, 200);
        assert!(docs.body.contains("negative control"));

        let openapi = route_request(
            TargetProfile::QualificationNegativeControl,
            &Request::for_test("GET", "/openapi.json"),
        );
        assert_eq!(openapi.status, 200);
        assert!(openapi.body.contains(r#""/health""#));
        assert!(!openapi.body.contains("/api/v1/imports"));

        let projects = route_request(
            TargetProfile::QualificationNegativeControl,
            &Request::for_test("GET", "/api/v1/projects"),
        );
        assert_eq!(projects.status, 404);

        let imports = route_request(
            TargetProfile::QualificationNegativeControl,
            &Request::for_test("POST", "/api/v1/imports"),
        );
        assert_eq!(imports.status, 404);
    }
}
