use crate::surface::{SurfaceAction, SurfaceHeader, SurfaceRequestMeta, SurfaceResponse};
use serde_json::json;

pub const DECOY_RECONCILE_PATH: &str = "/api/v2/import/reconcile";
pub const MAX_CONTROLLED_REALITY_ACTION_DEPTH: u32 = 4;

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

pub fn rate_limited_response() -> SurfaceResponse {
    SurfaceResponse::new(
        429,
        vec![
            SurfaceHeader::new("Content-Type", "application/json; charset=utf-8"),
            SurfaceHeader::new("Retry-After", "30"),
            SurfaceHeader::new("X-Eidolon-Synthetic", "true"),
        ],
        serde_json::to_vec(&json!({
            "status": "rate_limited",
            "synthetic": true,
            "retry_after_seconds": 30,
        }))
        .expect("static rate-limit JSON should serialize"),
    )
}

pub fn is_decoy_write(request: &SurfaceRequestMeta) -> bool {
    request.path == DECOY_RECONCILE_PATH && is_unsafe_method(&request.method)
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
    fn decoy_write_returns_synthetic_no_write_response() {
        let responder = ControlledRealityResponder;
        let action = responder.decide(&request("POST", DECOY_RECONCILE_PATH), 1);

        let SurfaceAction::ControlledReality { response, .. } = action else {
            panic!("expected controlled reality response");
        };

        assert_eq!(response.status, 202);
        assert!(String::from_utf8(response.body)
            .expect("body should be utf8")
            .contains(r#""write_committed":false"#));
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
}
