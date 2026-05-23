use std::{
    env,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    thread,
};

const DEFAULT_ADDR: &str = "127.0.0.1:9001";
const ADDR_ENV: &str = "EIDOLON_LAB_TARGET_ADDR";
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
    ensure_loopback_addr(&addr)?;

    let listener = TcpListener::bind(&addr)?;
    println!("eidolon-demo-target listening on http://{addr}");
    println!("local owned-target lab only; set {ADDR_ENV}=127.0.0.1:<port> to change the port");

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

fn ensure_loopback_addr(addr: &str) -> io::Result<()> {
    let socket_addr = addr.parse::<SocketAddr>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{ADDR_ENV} must be a socket address such as 127.0.0.1:9001: {error}"),
        )
    })?;

    if socket_addr.ip().is_loopback() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{ADDR_ENV} must bind to a loopback address for the local lab"),
        ))
    }
}

fn handle_connection(mut stream: TcpStream) -> io::Result<()> {
    let mut buffer = [0; 8192];
    let bytes_read = stream.read(&mut buffer)?;
    if bytes_read == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let request_line = request.lines().next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or("/");
    let path = path.split('?').next().unwrap_or(path);

    let response = route_request(method, path);
    stream.write_all(&response.to_http_bytes())?;
    stream.flush()
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

fn route_request(method: &str, path: &str) -> Response {
    match (method, path) {
        ("GET", "/") => Response::ok_html(home_page()),
        ("GET", "/health") => {
            Response::ok_json(r#"{"status":"ok","target":"eidolon-demo-target"}"#)
        }
        ("GET", "/docs") => Response::ok_html(docs_page()),
        ("GET", "/openapi.json") => Response::ok_json(openapi_document()),
        ("GET", "/api/v1/projects") => Response::ok_json(projects_json()),
        ("GET", path) if path.starts_with("/api/v1/projects/") => project_detail(path),
        ("POST", "/api/v1/imports") => Response::accepted_json(import_job_json("demo-import-1")),
        ("GET", path) if path.starts_with("/api/v1/imports/") => import_detail(path),
        ("POST", path) if path.starts_with("/api/") => Response::not_found(path),
        (method, path @ ("/" | "/health" | "/docs" | "/openapi.json" | "/api/v1/projects")) => {
            Response::method_not_allowed(method, path)
        }
        (_, path) => Response::not_found(path),
    }
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
        "responses": {
          "202": { "description": "Import accepted" }
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
        ensure_loopback_addr(DEFAULT_ADDR).expect("default address should be loopback");
    }

    #[test]
    fn non_loopback_lab_address_is_rejected() {
        let error = ensure_loopback_addr("0.0.0.0:9001").expect_err("wildcard bind is rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn exposes_normal_docs_and_openapi() {
        assert_eq!(route_request("GET", "/docs").status, 200);
        let openapi = route_request("GET", "/openapi.json");
        assert_eq!(openapi.status, 200);
        assert!(openapi.body.contains(r#""openapi": "3.0.3""#));
        assert!(openapi.body.contains("/api/v1/imports"));
    }

    #[test]
    fn project_routes_return_synthetic_data() {
        let list = route_request("GET", "/api/v1/projects");
        assert_eq!(list.status, 200);
        assert!(list.body.contains("Alpha Migration"));

        let detail = route_request("GET", "/api/v1/projects/alpha");
        assert_eq!(detail.status, 200);
        assert!(detail.body.contains(r#""id":"alpha""#));
    }

    #[test]
    fn import_post_returns_synthetic_no_write_job() {
        let response = route_request("POST", "/api/v1/imports");
        assert_eq!(response.status, 202);
        assert!(response.body.contains(r#""writes":"none""#));
    }

    #[test]
    fn responses_include_browser_hardening_headers() {
        let response = route_request("GET", "/docs");
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
        let known = route_request("GET", "/api/v1/imports/demo-import-1");
        assert_eq!(known.status, 200);
        assert!(known.body.contains(r#""id":"demo-import-1""#));

        let unknown = route_request("GET", "/api/v1/imports/not-a-real-import-xyz");
        assert_eq!(unknown.status, 404);
    }

    #[test]
    fn legacy_bait_route_is_not_real_target_behavior() {
        let response = route_request("POST", "/api/v2/import/reconcile");
        assert_eq!(response.status, 404);
    }
}
