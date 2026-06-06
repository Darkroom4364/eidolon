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
    ensure_allowed_lab_addr(&addr, owned_cluster_lab)?;

    let listener = TcpListener::bind(&addr)?;
    println!("eidolon-demo-target listening on http://{addr}");
    if owned_cluster_lab {
        println!("owned cluster lab enabled via {OWNED_CLUSTER_LAB_ENV}=1");
    } else {
        println!("local owned-target lab only; set {ADDR_ENV}=127.0.0.1:<port> to change the port");
    }

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(|| {
                    if let Err(error) = handle_connection(stream) {
                        eprintln!("connection error: {error}");
                    }
                });
            }
            Err(error) => eprintln!("accept error: {error}"),
        }
    }

    Ok(())
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

fn handle_connection(mut stream: TcpStream) -> io::Result<()> {
    let mut buffer = [0; 8192];
    let bytes_read = stream.read(&mut buffer)?;
    if bytes_read == 0 {
        return Ok(());
    }

    let request = Request::parse(&buffer[..bytes_read]);
    let response = route_request(&request);
    stream.write_all(&response.to_http_bytes())?;
    stream.flush()
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

fn route_request(request: &Request) -> Response {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") => Response::ok_html(home_page()),
        ("GET", "/health") => {
            Response::ok_json(r#"{"status":"ok","target":"eidolon-demo-target"}"#)
        }
        ("GET", "/docs") => Response::ok_html(docs_page()),
        ("GET", "/openapi.json") => Response::ok_json(openapi_document()),
        ("GET", "/api/v1/projects") => Response::ok_json(projects_json()),
        ("GET", path) if path.starts_with("/api/v1/projects/") => project_detail(path),
        ("POST", "/api/v1/imports") => create_import(request),
        ("GET", path) if path.starts_with("/api/v1/imports/") => import_detail(path),
        ("POST", path) if path.starts_with("/api/") => Response::not_found(path),
        (method, path @ ("/" | "/health" | "/docs" | "/openapi.json" | "/api/v1/projects")) => {
            Response::method_not_allowed(method, path)
        }
        (_, path) => Response::not_found(path),
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

    #[test]
    fn default_lab_address_is_loopback() {
        ensure_allowed_lab_addr(DEFAULT_ADDR, false).expect("default address should be loopback");
    }

    #[test]
    fn non_loopback_lab_address_is_rejected() {
        let error =
            ensure_allowed_lab_addr("0.0.0.0:9001", false).expect_err("wildcard bind is rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn owned_cluster_lab_allows_non_loopback_bind() {
        ensure_allowed_lab_addr("0.0.0.0:9001", true)
            .expect("owned cluster lab should allow non-loopback bind");
    }

    #[test]
    fn exposes_normal_docs_and_openapi() {
        assert_eq!(
            route_request(&Request::for_test("GET", "/docs")).status,
            200
        );
        let openapi = route_request(&Request::for_test("GET", "/openapi.json"));
        assert_eq!(openapi.status, 200);
        assert!(openapi.body.contains(r#""openapi": "3.0.3""#));
        assert!(openapi.body.contains("/api/v1/imports"));
        assert!(openapi.body.contains(r#""required": ["source"]"#));
    }

    #[test]
    fn project_routes_return_synthetic_data() {
        let list = route_request(&Request::for_test("GET", "/api/v1/projects"));
        assert_eq!(list.status, 200);
        assert!(list.body.contains("Alpha Migration"));

        let detail = route_request(&Request::for_test("GET", "/api/v1/projects/alpha"));
        assert_eq!(detail.status, 200);
        assert!(detail.body.contains(r#""id":"alpha""#));
    }

    #[test]
    fn import_post_requires_valid_json_request() {
        let response = route_request(
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
            &Request::for_test("POST", "/api/v1/imports")
                .with_header("Content-Type", "application/json")
                .with_body(br#"{"source":"lab""#.to_vec()),
        );
        assert_eq!(malformed.status, 400);

        let missing_source = route_request(
            &Request::for_test("POST", "/api/v1/imports")
                .with_header("Content-Type", "application/json")
                .with_body(br#"{"mode":"synthetic"}"#.to_vec()),
        );
        assert_eq!(missing_source.status, 400);

        let plain_text = route_request(
            &Request::for_test("POST", "/api/v1/imports")
                .with_header("Content-Type", "text/plain")
                .with_body(b"hello".to_vec()),
        );
        assert_eq!(plain_text.status, 415);
    }

    #[test]
    fn responses_include_browser_hardening_headers() {
        let response = route_request(&Request::for_test("GET", "/docs"));
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
        let known = route_request(&Request::for_test("GET", "/api/v1/imports/demo-import-1"));
        assert_eq!(known.status, 200);
        assert!(known.body.contains(r#""id":"demo-import-1""#));

        let unknown = route_request(&Request::for_test(
            "GET",
            "/api/v1/imports/not-a-real-import-xyz",
        ));
        assert_eq!(unknown.status, 404);
    }

    #[test]
    fn legacy_bait_route_is_not_real_target_behavior() {
        let response = route_request(&Request::for_test("POST", "/api/v2/import/reconcile"));
        assert_eq!(response.status, 404);
    }
}
