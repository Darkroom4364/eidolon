use std::time::Duration;

use crate::{
    policy_store::{ControlledRealityProgress, ControlledRealityRequestAction},
    surface::{
        ResponseCachePolicy, SurfaceAction, SurfaceHeader, SurfaceRequestMeta, SurfaceResponse,
    },
};
use eidolon_core::{
    ControlledRealityArtifactId, ControlledRealityArtifactRef, ControlledRealityArtifactSha256,
    ControlledRealityBranch, ControlledRealityInteraction, ControlledRealityInteractionAction,
    ControlledRealityJobId, ControlledRealityWorkflowState, RequestId, RoutingDecision, SessionId,
};
use serde_json::json;
use sha2::{Digest, Sha256};

pub const DECOY_RECONCILE_PATH: &str = "/api/v2/import/reconcile";
pub const DECOY_RECONCILE_JOBS_PATH: &str = "/api/v2/import/reconcile/jobs";
pub const DECOY_RECONCILE_JOBS_PREFIX: &str = "/api/v2/import/reconcile/jobs/";
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

#[derive(Debug, Clone, PartialEq)]
pub struct ControlledRealityDecision {
    pub action: SurfaceAction,
    pub interaction: Option<ControlledRealityInteraction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlledRealityExpectedResponse {
    pub status: u16,
    pub routing_decision: RoutingDecision,
    pub interaction: Option<ControlledRealityInteraction>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlledRealityRequestKind {
    BranchRead,
    JobSubmitted,
    StatusRead,
    ArtifactRead,
    MethodRejected,
    UnknownResource,
}

impl ControlledRealityRequestKind {
    pub fn store_action(self) -> ControlledRealityRequestAction {
        match self {
            Self::BranchRead => ControlledRealityRequestAction::BranchRead,
            Self::JobSubmitted => ControlledRealityRequestAction::JobSubmitted,
            Self::StatusRead => ControlledRealityRequestAction::StatusRead,
            Self::ArtifactRead => ControlledRealityRequestAction::ArtifactRead,
            Self::MethodRejected => ControlledRealityRequestAction::MethodRejected,
            Self::UnknownResource => ControlledRealityRequestAction::UnknownResource,
        }
    }
}

impl ControlledRealityResponder {
    pub fn classify(
        &self,
        session_id: SessionId,
        origin_request_id: Option<RequestId>,
        request: &SurfaceRequestMeta,
    ) -> ControlledRealityRequestKind {
        if request.path == DECOY_RECONCILE_PATH {
            return match request.method.as_str() {
                "GET" => ControlledRealityRequestKind::BranchRead,
                "POST" => ControlledRealityRequestKind::JobSubmitted,
                _ => ControlledRealityRequestKind::MethodRejected,
            };
        }

        let Some(origin_request_id) = origin_request_id else {
            return ControlledRealityRequestKind::UnknownResource;
        };
        let resources = synthetic_resources(session_id, origin_request_id);
        if request.path == resources.status_path {
            return if request.method == "GET" {
                ControlledRealityRequestKind::StatusRead
            } else {
                ControlledRealityRequestKind::MethodRejected
            };
        }
        if request.path == resources.artifact_path {
            return if request.method == "GET" {
                ControlledRealityRequestKind::ArtifactRead
            } else {
                ControlledRealityRequestKind::MethodRejected
            };
        }

        ControlledRealityRequestKind::UnknownResource
    }

    pub fn decide(
        &self,
        session_id: SessionId,
        _request: &SurfaceRequestMeta,
        kind: ControlledRealityRequestKind,
        progress: ControlledRealityProgress,
    ) -> ControlledRealityDecision {
        let resources = progress
            .origin_request_id
            .map(|origin_request_id| synthetic_resources(session_id, origin_request_id));
        let interaction = resources
            .as_ref()
            .and_then(|resources| interaction_for(kind, progress, resources));
        ControlledRealityDecision {
            action: SurfaceAction::ControlledReality {
                reason: format!(
                    "controlled reality served synthetic response at action depth {}",
                    progress.depth
                ),
                response: response_for(kind, progress, resources.as_ref()),
            },
            interaction,
        }
    }

    pub fn expected_response(
        &self,
        session_id: SessionId,
        progress: ControlledRealityProgress,
        action: ControlledRealityRequestAction,
        depth_limit: u32,
    ) -> ControlledRealityExpectedResponse {
        if progress.depth > depth_limit {
            return ControlledRealityExpectedResponse {
                status: 429,
                routing_decision: RoutingDecision::RateLimited,
                interaction: None,
            };
        }

        let request_kind = match action {
            ControlledRealityRequestAction::BranchRead => ControlledRealityRequestKind::BranchRead,
            ControlledRealityRequestAction::JobSubmitted => {
                ControlledRealityRequestKind::JobSubmitted
            }
            ControlledRealityRequestAction::StatusRead => ControlledRealityRequestKind::StatusRead,
            ControlledRealityRequestAction::ArtifactRead => {
                ControlledRealityRequestKind::ArtifactRead
            }
            ControlledRealityRequestAction::MethodRejected => {
                ControlledRealityRequestKind::MethodRejected
            }
            ControlledRealityRequestAction::UnknownResource => {
                ControlledRealityRequestKind::UnknownResource
            }
        };
        let resources = progress
            .origin_request_id
            .map(|origin_request_id| synthetic_resources(session_id, origin_request_id));
        ControlledRealityExpectedResponse {
            status: response_for(request_kind, progress, resources.as_ref()).status,
            routing_decision: RoutingDecision::ControlledReality,
            interaction: resources
                .as_ref()
                .and_then(|resources| interaction_for(request_kind, progress, resources)),
        }
    }

    pub fn fail_closed_bait_action_response(
        &self,
        request: &SurfaceRequestMeta,
    ) -> SurfaceResponse {
        json_response(
            403,
            json!({
                "status": "blocked",
                "synthetic": true,
                "reason": "configured unsafe bait action failed closed",
                "path": request.path,
            }),
        )
    }

    pub fn is_controlled_branch(&self, request: &SurfaceRequestMeta) -> bool {
        is_controlled_branch_path(&request.path)
    }

    pub fn fail_closed_follow_up_response(&self) -> SurfaceResponse {
        json_response(
            404,
            json!({
                "status": "not_found",
                "synthetic": true,
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
    .with_cache_policy(ResponseCachePolicy::PrivateNoStore)
}

pub fn is_controlled_branch_path(path: &str) -> bool {
    path == DECOY_RECONCILE_PATH || is_controlled_follow_up_path(path)
}

pub fn is_controlled_follow_up_path(path: &str) -> bool {
    path == DECOY_RECONCILE_JOBS_PATH || path.starts_with(DECOY_RECONCILE_JOBS_PREFIX)
}

#[derive(Debug, Clone)]
struct SyntheticResources {
    job_id: ControlledRealityJobId,
    status_path: String,
    artifact_path: String,
    artifact: ControlledRealityArtifactRef,
    artifact_body: serde_json::Value,
}

fn synthetic_resources(session_id: SessionId, origin_request_id: RequestId) -> SyntheticResources {
    let job_id = ControlledRealityJobId::new(synthetic_id(
        "job",
        "eidolon:import-reconcile:job:v1",
        session_id,
        origin_request_id,
    ))
    .expect("generated job id should satisfy the typed contract");
    let artifact_id = ControlledRealityArtifactId::new(synthetic_id(
        "artifact",
        "eidolon:import-reconcile:artifact:v1",
        session_id,
        origin_request_id,
    ))
    .expect("generated artifact id should satisfy the typed contract");
    let status_path = format!("{DECOY_RECONCILE_JOBS_PREFIX}{}", job_id.as_str());
    let artifact_path = format!("{status_path}/result");
    let artifact_body = json!({
        "schema_version": 1,
        "artifact_id": artifact_id.as_str(),
        "job_id": job_id.as_str(),
        "kind": "reconciliation_summary",
        "synthetic": true,
        "write_committed": false,
        "summary": {
            "records_examined": 7,
            "changes_planned": 2,
            "changes_committed": 0,
            "tenant_ownership_checked": false,
            "source_url_verified": false
        }
    });
    let artifact_bytes =
        serde_json::to_vec(&artifact_body).expect("static synthetic artifact should serialize");
    let artifact = ControlledRealityArtifactRef {
        artifact_id,
        sha256: ControlledRealityArtifactSha256::new(digest_hex(&Sha256::digest(&artifact_bytes)))
            .expect("generated artifact digest should satisfy the typed contract"),
    };

    SyntheticResources {
        job_id,
        status_path,
        artifact_path,
        artifact,
        artifact_body,
    }
}

fn synthetic_id(
    prefix: &str,
    domain: &str,
    session_id: SessionId,
    origin_request_id: RequestId,
) -> String {
    let mut digest = Sha256::new();
    digest.update(domain.as_bytes());
    digest.update(session_id.0.as_bytes());
    digest.update(origin_request_id.0.as_bytes());
    let digest = digest.finalize();
    format!("{prefix}_{}", digest_hex(&digest[..8]))
}

fn digest_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn interaction_for(
    kind: ControlledRealityRequestKind,
    progress: ControlledRealityProgress,
    resources: &SyntheticResources,
) -> Option<ControlledRealityInteraction> {
    let origin_request_id = progress.origin_request_id?;
    let action = match kind {
        ControlledRealityRequestKind::JobSubmitted
            if progress.to_state != ControlledRealityWorkflowState::Ready =>
        {
            ControlledRealityInteractionAction::JobSubmitted
        }
        ControlledRealityRequestKind::StatusRead
            if progress.from_state != ControlledRealityWorkflowState::Ready =>
        {
            ControlledRealityInteractionAction::StatusRead
        }
        ControlledRealityRequestKind::ArtifactRead
            if progress.to_state == ControlledRealityWorkflowState::Completed =>
        {
            ControlledRealityInteractionAction::ArtifactRead {
                artifact: resources.artifact.clone(),
            }
        }
        ControlledRealityRequestKind::BranchRead
        | ControlledRealityRequestKind::JobSubmitted
        | ControlledRealityRequestKind::StatusRead
        | ControlledRealityRequestKind::ArtifactRead
        | ControlledRealityRequestKind::MethodRejected
        | ControlledRealityRequestKind::UnknownResource => return None,
    };

    Some(ControlledRealityInteraction {
        branch: ControlledRealityBranch::ImportReconcile,
        origin_request_id,
        from_state: progress.from_state,
        to_state: progress.to_state,
        job_id: resources.job_id.clone(),
        action,
    })
}

fn response_for(
    kind: ControlledRealityRequestKind,
    progress: ControlledRealityProgress,
    resources: Option<&SyntheticResources>,
) -> SurfaceResponse {
    match kind {
        ControlledRealityRequestKind::BranchRead => {
            workflow_status_response(200, progress.to_state, progress.depth, resources)
        }
        ControlledRealityRequestKind::JobSubmitted => match progress.to_state {
            ControlledRealityWorkflowState::Ready => {
                workflow_status_response(409, progress.to_state, progress.depth, resources)
            }
            ControlledRealityWorkflowState::Queued => {
                workflow_status_response(202, progress.to_state, progress.depth, resources)
            }
            ControlledRealityWorkflowState::Completed => {
                workflow_status_response(200, progress.to_state, progress.depth, resources)
            }
        },
        ControlledRealityRequestKind::StatusRead => {
            if progress.from_state == ControlledRealityWorkflowState::Ready {
                unknown_resource_response(progress.depth)
            } else {
                workflow_status_response(200, progress.to_state, progress.depth, resources)
            }
        }
        ControlledRealityRequestKind::ArtifactRead => match progress.to_state {
            ControlledRealityWorkflowState::Completed => {
                let Some(resources) = resources else {
                    return unknown_resource_response(progress.depth);
                };
                let mut response = json_response(200, resources.artifact_body.clone());
                response.headers.push(SurfaceHeader::new(
                    "X-Eidolon-Artifact-Sha256",
                    resources.artifact.sha256.as_str(),
                ));
                response
            }
            ControlledRealityWorkflowState::Queued => json_response(
                409,
                json!({
                    "status": workflow_state_name(progress.to_state),
                    "synthetic": true,
                    "write_committed": false,
                    "action_depth": progress.depth,
                }),
            ),
            ControlledRealityWorkflowState::Ready => unknown_resource_response(progress.depth),
        },
        ControlledRealityRequestKind::MethodRejected => json_response(
            405,
            json!({
                "status": "method_not_allowed",
                "synthetic": true,
                "write_committed": false,
                "action_depth": progress.depth,
            }),
        ),
        ControlledRealityRequestKind::UnknownResource => unknown_resource_response(progress.depth),
    }
}

fn workflow_status_response(
    status: u16,
    state: ControlledRealityWorkflowState,
    depth: u32,
    resources: Option<&SyntheticResources>,
) -> SurfaceResponse {
    let mut body = json!({
        "status": workflow_state_name(state),
        "synthetic": true,
        "write_committed": false,
        "path": DECOY_RECONCILE_PATH,
        "action_depth": depth,
    });

    if let Some(resources) = resources.filter(|_| state != ControlledRealityWorkflowState::Ready) {
        body["job_id"] = json!(resources.job_id.as_str());
        body["status_path"] = json!(resources.status_path);
        if state == ControlledRealityWorkflowState::Completed {
            body["artifact"] = json!({
                "artifact_id": resources.artifact.artifact_id.as_str(),
                "path": resources.artifact_path,
                "sha256": resources.artifact.sha256.as_str(),
            });
        }
    }
    if state == ControlledRealityWorkflowState::Queued {
        body["accepted_untrusted_fields"] =
            json!(["source", "source_url", "tenant_id", "reconcile_mode"]);
        body["validation"] = json!({
            "source_url_verified": false,
            "tenant_ownership_checked": false,
        });
    }

    json_response(status, body)
}

fn unknown_resource_response(depth: u32) -> SurfaceResponse {
    json_response(
        404,
        json!({
            "status": "not_found",
            "synthetic": true,
            "write_committed": false,
            "message": "controlled reality has no matching synthetic resource",
            "action_depth": depth,
        }),
    )
}

fn workflow_state_name(state: ControlledRealityWorkflowState) -> &'static str {
    match state {
        ControlledRealityWorkflowState::Ready => "ready",
        ControlledRealityWorkflowState::Queued => "queued",
        ControlledRealityWorkflowState::Completed => "completed",
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
    .with_cache_policy(ResponseCachePolicy::PrivateNoStore)
}

pub fn is_unsafe_method(method: &str) -> bool {
    !["GET", "HEAD", "OPTIONS", "TRACE"]
        .iter()
        .any(|safe_method| method.eq_ignore_ascii_case(safe_method))
}

#[cfg(test)]
mod tests {
    use crate::surface::{ResponseCachePolicy, SurfaceRequestMeta};
    use serde_json::Value;

    use super::*;

    fn request(method: &str, path: &str) -> SurfaceRequestMeta {
        SurfaceRequestMeta::new(method, path, Vec::new(), 0)
    }

    fn progress(
        depth: u32,
        from_state: ControlledRealityWorkflowState,
        to_state: ControlledRealityWorkflowState,
        origin_request_id: Option<RequestId>,
    ) -> ControlledRealityProgress {
        ControlledRealityProgress {
            depth,
            from_state,
            to_state,
            origin_request_id,
        }
    }

    fn response(decision: ControlledRealityDecision) -> SurfaceResponse {
        let SurfaceAction::ControlledReality { response, .. } = decision.action else {
            panic!("expected controlled reality response");
        };
        response
    }

    fn json_body(response: &SurfaceResponse) -> Value {
        serde_json::from_slice(&response.body).expect("body should be json")
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
    fn submitted_job_is_stable_synthetic_and_no_write() {
        let responder = ControlledRealityResponder;
        let session_id = SessionId::new();
        let origin_request_id = RequestId::new();
        let request = request("POST", DECOY_RECONCILE_PATH);
        let kind = responder.classify(session_id, None, &request);
        let decision = responder.decide(
            session_id,
            &request,
            kind,
            progress(
                1,
                ControlledRealityWorkflowState::Ready,
                ControlledRealityWorkflowState::Queued,
                Some(origin_request_id),
            ),
        );
        let interaction = decision
            .interaction
            .clone()
            .expect("submission should emit typed workflow metadata");
        let response = response(decision);
        let body = json_body(&response);

        assert_eq!(response.status, 202);
        assert_eq!(body["status"], "queued");
        assert_eq!(body["write_committed"], false);
        assert_eq!(body["job_id"], interaction.job_id.as_str());
        assert_eq!(interaction.origin_request_id, origin_request_id);
        assert_eq!(
            interaction.action,
            ControlledRealityInteractionAction::JobSubmitted
        );
        assert_eq!(response.cache_policy, ResponseCachePolicy::PrivateNoStore);
        assert!(response
            .headers
            .iter()
            .any(|header| header.name == "X-Eidolon-Synthetic"));
    }

    #[test]
    fn job_status_and_artifact_form_one_deterministic_lifecycle() {
        let responder = ControlledRealityResponder;
        let session_id = SessionId::new();
        let origin_request_id = RequestId::new();
        let resources = synthetic_resources(session_id, origin_request_id);

        let status_request = request("GET", &resources.status_path);
        assert_eq!(
            responder.classify(session_id, Some(origin_request_id), &status_request),
            ControlledRealityRequestKind::StatusRead
        );
        let status_decision = responder.decide(
            session_id,
            &status_request,
            ControlledRealityRequestKind::StatusRead,
            progress(
                2,
                ControlledRealityWorkflowState::Queued,
                ControlledRealityWorkflowState::Completed,
                Some(origin_request_id),
            ),
        );
        let status_interaction = status_decision
            .interaction
            .expect("status should emit typed workflow metadata");
        let status_response = response(ControlledRealityDecision {
            action: status_decision.action,
            interaction: None,
        });
        let status_body = json_body(&status_response);
        assert_eq!(status_body["status"], "completed");
        assert_eq!(status_body["job_id"], resources.job_id.as_str());
        assert_eq!(
            status_body["artifact"]["artifact_id"],
            resources.artifact.artifact_id.as_str()
        );
        assert_eq!(
            status_interaction.action,
            ControlledRealityInteractionAction::StatusRead
        );

        let artifact_request = request("GET", &resources.artifact_path);
        assert_eq!(
            responder.classify(session_id, Some(origin_request_id), &artifact_request),
            ControlledRealityRequestKind::ArtifactRead
        );
        let first = responder.decide(
            session_id,
            &artifact_request,
            ControlledRealityRequestKind::ArtifactRead,
            progress(
                3,
                ControlledRealityWorkflowState::Completed,
                ControlledRealityWorkflowState::Completed,
                Some(origin_request_id),
            ),
        );
        let first_interaction = first
            .interaction
            .clone()
            .expect("artifact read should emit typed workflow metadata");
        let first_response = response(first);
        let second_response = response(responder.decide(
            session_id,
            &artifact_request,
            ControlledRealityRequestKind::ArtifactRead,
            progress(
                4,
                ControlledRealityWorkflowState::Completed,
                ControlledRealityWorkflowState::Completed,
                Some(origin_request_id),
            ),
        ));

        assert_eq!(first_response.status, 200);
        assert_eq!(first_response.body, second_response.body);
        let ControlledRealityInteractionAction::ArtifactRead { artifact } =
            first_interaction.action
        else {
            panic!("expected artifact interaction");
        };
        assert_eq!(artifact, resources.artifact);
        assert_eq!(
            artifact.sha256.as_str(),
            digest_hex(&Sha256::digest(&first_response.body))
        );
        assert!(first_response.headers.iter().any(|header| {
            header.name == "X-Eidolon-Artifact-Sha256" && header.value == artifact.sha256.as_str()
        }));
    }

    #[test]
    fn identifiers_are_bound_to_session_and_origin_request() {
        let session = SessionId::new();
        let origin = RequestId::new();
        let same = synthetic_resources(session, origin);
        let repeated = synthetic_resources(session, origin);
        let other_session = synthetic_resources(SessionId::new(), origin);
        let other_origin = synthetic_resources(session, RequestId::new());

        assert_eq!(same.job_id, repeated.job_id);
        assert_eq!(same.artifact, repeated.artifact);
        assert_ne!(same.job_id, other_session.job_id);
        assert_ne!(same.job_id, other_origin.job_id);
    }

    #[test]
    fn wrong_session_resource_is_unknown_and_never_reflected() {
        let responder = ControlledRealityResponder;
        let owner = synthetic_resources(SessionId::new(), RequestId::new());
        let other_session = SessionId::new();
        let other_origin = RequestId::new();
        let request = request("GET", &owner.status_path);
        let kind = responder.classify(other_session, Some(other_origin), &request);
        let decision = responder.decide(
            other_session,
            &request,
            kind,
            progress(
                2,
                ControlledRealityWorkflowState::Queued,
                ControlledRealityWorkflowState::Queued,
                Some(other_origin),
            ),
        );
        let response = response(decision.clone());
        let body = String::from_utf8(response.body).expect("body should be utf8");

        assert_eq!(kind, ControlledRealityRequestKind::UnknownResource);
        assert_eq!(response.status, 404);
        assert!(decision.interaction.is_none());
        assert!(!body.contains(owner.job_id.as_str()));
    }

    #[test]
    fn controlled_follow_up_namespace_includes_collection_root() {
        assert!(is_controlled_follow_up_path(
            "/api/v2/import/reconcile/jobs"
        ));
        assert!(is_controlled_follow_up_path(
            "/api/v2/import/reconcile/jobs/job_0123456789abcdef"
        ));
        assert!(!is_controlled_follow_up_path(
            "/api/v2/import/reconcile/jobs-not-owned"
        ));
    }

    #[test]
    fn fail_closed_bait_action_response_is_generic_and_synthetic() {
        let responder = ControlledRealityResponder;
        let response =
            responder.fail_closed_bait_action_response(&request("POST", "/custom/unsafe-action"));

        assert_eq!(response.status, 403);
        assert_eq!(response.cache_policy, ResponseCachePolicy::PrivateNoStore);
        assert!(String::from_utf8(response.body)
            .expect("body should be utf8")
            .contains("configured unsafe bait action failed closed"));
    }

    #[test]
    fn unsafe_methods_are_case_insensitive() {
        for method in ["POST", "put", "Patch", "DELETE", "CONNECT", "PROPFIND"] {
            assert!(is_unsafe_method(method), "{method} should be unsafe");
        }
        for method in ["GET", "HEAD", "OPTIONS", "TRACE"] {
            assert!(!is_unsafe_method(method), "{method} should be safe");
        }
    }

    #[test]
    fn rate_limited_response_uses_configured_retry_after() {
        let response = rate_limited_response(7);

        assert_eq!(response.status, 429);
        assert_eq!(response.cache_policy, ResponseCachePolicy::PrivateNoStore);
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
        let session_id = SessionId::new();
        let request = request("OPTIONS", DECOY_RECONCILE_PATH);
        let kind = responder.classify(session_id, None, &request);
        let decision = responder.decide(
            session_id,
            &request,
            kind,
            progress(
                1,
                ControlledRealityWorkflowState::Ready,
                ControlledRealityWorkflowState::Ready,
                None,
            ),
        );
        let response = response(decision.clone());

        assert_eq!(kind, ControlledRealityRequestKind::MethodRejected);
        assert_eq!(response.status, 405);
        assert!(decision.interaction.is_none());
        assert!(String::from_utf8(response.body)
            .expect("body should be utf8")
            .contains(r#""status":"method_not_allowed""#));
    }
}
