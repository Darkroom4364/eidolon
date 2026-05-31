use std::time::Duration;

use crate::surface::{SurfaceAction, SurfaceHeader, SurfaceRequestMeta, SurfaceResponse};
use serde_json::json;

pub const DECOY_RECONCILE_PATH: &str = "/api/v2/import/reconcile";
pub const MAX_CONTROLLED_REALITY_ACTION_DEPTH: u32 = 4;
pub const DEFAULT_TARPIT_DELAY: Duration = Duration::from_millis(25);
pub const MAX_TARPIT_DELAY: Duration = Duration::from_secs(5);
pub const DEFAULT_RETRY_AFTER_SECONDS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlledRealityConfig {
    pub max_action_depth: u32,
    pub tarpit_delay: Duration,
    pub retry_after_seconds: u64,
}

impl Default for ControlledRealityConfig {
    fn default() -> Self {
        Self {
            max_action_depth: MAX_CONTROLLED_REALITY_ACTION_DEPTH,
            tarpit_delay: DEFAULT_TARPIT_DELAY,
            retry_after_seconds: DEFAULT_RETRY_AFTER_SECONDS,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct ControlledRealityResponder;

impl ControlledRealityResponder {
    pub fn decide(&self, request: &SurfaceRequestMeta, depth: u32) -> SurfaceAction {
        SurfaceAction::ControlledReality {
            reason: format!("controlled reality served synthetic response at action depth {depth}"),
            response: self.response_for(request, depth),
        }
    }

    pub fn fail_closed_response(&self, request: &SurfaceRequestMeta) -> Option<SurfaceResponse> {
        (is_decoy_write(request)).then(|| {
            json_response(
                403,
                json!({
                    "status": "blocked",
                    "synthetic": true,
                    "reason": "known controlled-reality write path failed closed",
                    "path": request.path,
                }),
            )
        })
    }

    pub fn is_controlled_branch(&self, request: &SurfaceRequestMeta) -> bool {
        is_controlled_branch_path(&request.path)
    }

    fn response_for(&self, request: &SurfaceRequestMeta, depth: u32) -> SurfaceResponse {
        if request.path == DECOY_RECONCILE_PATH {
            return reconcile_response(request, depth);
        }

        json_response(
            404,
            json!({
                "status": "not_found",
                "synthetic": true,
                "path": request.path,
                "message": "controlled reality has no matching synthetic resource",
            }),
        )
    }
}

pub fn rate_limited_response(retry_after_seconds: u64) -> SurfaceResponse {
    SurfaceResponse::new(
        429,
        vec![
            SurfaceHeader::new("Content-Type", "application/json; charset=utf-8"),
            SurfaceHeader::new("Retry-After", retry_after_seconds.to_string()),
            SurfaceHeader::new("X-Eidolon-Synthetic", "true"),
        ],
        serde_json::to_vec(&json!({
            "status": "rate_limited",
            "synthetic": true,
            "retry_after_seconds": retry_after_seconds,
        }))
        .expect("static rate-limit JSON should serialize"),
    )
}

pub fn is_decoy_write(request: &SurfaceRequestMeta) -> bool {
    request.path == DECOY_RECONCILE_PATH && is_unsafe_method(&request.method)
}

pub fn is_controlled_branch_path(path: &str) -> bool {
    path == DECOY_RECONCILE_PATH
}

fn reconcile_response(request: &SurfaceRequestMeta, depth: u32) -> SurfaceResponse {
    match request.method.as_str() {
        "GET" => json_response(
            200,
            json!({
                "status": "ready",
                "synthetic": true,
                "path": DECOY_RECONCILE_PATH,
                "queued_jobs": 2,
                "input_origin": "external_client_request",
                "trust_boundary": "public_import_api_to_reconciliation_worker",
                "authorization_model": "legacy_header_only",
                "action_depth": depth,
            }),
        ),
        "POST" | "PUT" | "PATCH" | "DELETE" => json_response(
            202,
            json!({
                "status": "queued",
                "synthetic": true,
                "write_committed": false,
                "path": DECOY_RECONCILE_PATH,
                "input_origin": "external_client_request",
                "trust_boundary": "public_import_api_to_reconciliation_worker",
                "authorization_model": "legacy_header_only",
                "accepted_untrusted_fields": [
                    "source",
                    "source_url",
                    "tenant_id",
                    "reconcile_mode"
                ],
                "validation": {
                    "source_url_verified": false,
                    "tenant_ownership_checked": false
                },
                "action_depth": depth,
            }),
        ),
        _ => json_response(
            405,
            json!({
                "status": "method_not_allowed",
                "synthetic": true,
                "path": DECOY_RECONCILE_PATH,
                "action_depth": depth,
            }),
        ),
    }
}

fn json_response(status: u16, body: serde_json::Value) -> SurfaceResponse {
    SurfaceResponse::new(
        status,
        vec![
            SurfaceHeader::new("Content-Type", "application/json; charset=utf-8"),
            SurfaceHeader::new("X-Eidolon-Synthetic", "true"),
        ],
        serde_json::to_vec(&body).expect("controlled-reality JSON should serialize"),
    )
}

fn is_unsafe_method(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH" | "DELETE")
}

#[cfg(test)]
mod tests {
    use crate::surface::SurfaceRequestMeta;

    use super::*;

    fn request(method: &str, path: &str) -> SurfaceRequestMeta {
        SurfaceRequestMeta::new(method, path, Vec::new(), 0)
    }

    #[test]
    fn default_controlled_reality_config_matches_lab_contract() {
        assert_eq!(
            ControlledRealityConfig::default(),
            ControlledRealityConfig {
                max_action_depth: 4,
                tarpit_delay: Duration::from_millis(25),
                retry_after_seconds: 30,
            }
        );
        assert_eq!(MAX_TARPIT_DELAY, Duration::from_secs(5));
    }

    #[test]
    fn decoy_write_returns_synthetic_no_write_response() {
        let responder = ControlledRealityResponder;
        let action = responder.decide(&request("POST", DECOY_RECONCILE_PATH), 1);

        let SurfaceAction::ControlledReality { response, .. } = action else {
            panic!("expected controlled reality response");
        };

        assert_eq!(response.status, 202);
        let body = String::from_utf8(response.body).expect("body should be utf8");
        assert!(body.contains(r#""write_committed":false"#));
        assert!(body.contains(r#""input_origin":"external_client_request""#));
        assert!(body.contains(r#""authorization_model":"legacy_header_only""#));
        assert!(body.contains(r#""source_url_verified":false"#));
        assert!(response
            .headers
            .iter()
            .any(|header| header.name == "X-Eidolon-Synthetic"));
    }

    #[test]
    fn fail_closed_only_handles_known_decoy_write_paths() {
        let responder = ControlledRealityResponder;

        assert!(responder
            .fail_closed_response(&request("POST", DECOY_RECONCILE_PATH))
            .is_some());
        assert!(responder
            .fail_closed_response(&request("GET", DECOY_RECONCILE_PATH))
            .is_none());
        assert!(responder
            .fail_closed_response(&request("POST", "/api/v1/imports"))
            .is_none());
    }

    #[test]
    fn rate_limited_response_uses_configured_retry_after() {
        let response = rate_limited_response(7);

        assert_eq!(response.status, 429);
        assert!(response
            .headers
            .iter()
            .any(|header| header.name == "Retry-After" && header.value == "7"));
        assert!(String::from_utf8(response.body)
            .expect("body should be utf8")
            .contains(r#""retry_after_seconds":7"#));
    }

    #[test]
    fn unsupported_decoy_methods_return_method_not_allowed() {
        let responder = ControlledRealityResponder;
        let action = responder.decide(&request("OPTIONS", DECOY_RECONCILE_PATH), 1);

        let SurfaceAction::ControlledReality { response, .. } = action else {
            panic!("expected controlled reality response");
        };

        assert_eq!(response.status, 405);
        assert!(String::from_utf8(response.body)
            .expect("body should be utf8")
            .contains(r#""status":"method_not_allowed""#));
    }
}
