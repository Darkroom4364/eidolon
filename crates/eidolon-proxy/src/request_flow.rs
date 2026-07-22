//! Request-evaluation spine: session resolution, policy transitions, surface
//! selection, bait action handling, and upstream forwarding.

use std::{
    fs,
    io::{self, Write},
    net::{IpAddr, TcpStream},
    path::Path,
    sync::{Arc, Mutex},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use eidolon_bait::{render_bait_for_session, BaitActionMatch, BaitRegistry};
use eidolon_core::{
    Bait, BaitClass, BaitHeaderValueMintStatus, BaitId, DiscoveryReconScore, Event, EventKind,
    EventSource, ExposureId, PolicyState, RequestId, RoutingDecision, SafeHeaderObservation,
    SessionId,
};
use serde_json::{json, Value};

use crate::{
    controlled_reality::{rate_limited_response, DECOY_RECONCILE_PATH},
    event_log::FileEventLogWriter,
    http::{
        effective_request_host, invalid_data, normalize_request_target, read_http_request,
        read_http_response, HttpHeader, HttpRequest, HttpResponse,
    },
    ingress_identity,
    policy::{self, InterventionMode},
    runtime::{configure_client_stream, connect_upstream, ProxyRuntime},
    session::{self, SessionContext},
    session_auth::enforcement_rank,
    surface::{
        rewrite_response_body, RewritePlan, SurfaceAction, SurfaceHeader, SurfaceRequestMeta,
        SurfaceResponse, SurfaceResponseMeta,
    },
    surface_content::{bait_surface_response, owned_openapi_discovery_response},
};

pub const DOCS_DISCOVERY_TARGET: &str = "/docs";
pub const OPENAPI_DISCOVERY_TARGET: &str = "/openapi.json";
pub const LEGACY_IMPORT_OPENAPI_QUERY: &str = "eidolon_surface=legacy-import";
pub const SAFE_HEADER_NAMES: &[&str] = &[
    "accept",
    "authorization",
    "content-type",
    "cookie",
    "referer",
    "user-agent",
    "x-api-key",
    "x-eidolon-ingress-identity-expires-at",
    "x-eidolon-ingress-identity-label",
    "x-eidolon-ingress-identity-source",
    "x-eidolon-ingress-trust-tier",
    "x-eidolon-ingress-verification-strength",
    "x-eidolon-ingress-actor-kind",
    "x-eidolon-ingress-verified-category",
    "x-eidolon-ingress-attestation-ref",
    "x-eidolon-ingress-vendor-score",
    "x-eidolon-ingress-vendor-score-kind",
    "x-eidolon-ingress-vendor-score-scale",
    "x-eidolon-ingress-detection-ids",
    "x-eidolon-ingress-edge-action",
];

pub fn is_openapi_discovery_request(request: &SurfaceRequestMeta, bait: &Bait) -> bool {
    request.method == "GET"
        && request.path == bait.surface
        && matches!(
            request.query.as_deref(),
            None | Some(LEGACY_IMPORT_OPENAPI_QUERY)
        )
}

pub fn is_legacy_openapi_discovery_query(request: &SurfaceRequestMeta) -> bool {
    request.method == "GET"
        && request.path == OPENAPI_DISCOVERY_TARGET
        && request.query.as_deref() == Some(LEGACY_IMPORT_OPENAPI_QUERY)
}

pub fn linked_bait_surface_kind(
    runtime: &ProxyRuntime,
    request: &SurfaceRequestMeta,
) -> Option<policy::LinkedBaitSurfaceKind> {
    if request.method != "GET" {
        return None;
    }

    runtime
        .bait_registry
        .baits()
        .iter()
        .find(|bait| bait.bait_class != BaitClass::OpenApi && bait.surface == request.path)
        .map(|_| {
            if request.path.starts_with("/docs/") {
                policy::LinkedBaitSurfaceKind::Docs
            } else if request.path.starts_with("/assets/") {
                policy::LinkedBaitSurfaceKind::Assets
            } else {
                policy::LinkedBaitSurfaceKind::Other
            }
        })
}

pub fn is_blind_decoy_write_probe(
    runtime: &ProxyRuntime,
    session_id: SessionId,
    request: &SurfaceRequestMeta,
) -> bool {
    blind_decoy_write_probe_path_kind(runtime, session_id, request).is_some()
}

pub fn blind_decoy_write_probe_path_kind(
    runtime: &ProxyRuntime,
    session_id: SessionId,
    request: &SurfaceRequestMeta,
) -> Option<policy::DecoyWriteProbePathKind> {
    if !matches!(request.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
        return None;
    }

    let headers: Vec<(&str, &str)> = surface_header_pairs(&request.headers).collect();
    if runtime
        .bait_registry
        .match_action_for_session(
            &request.method,
            &request.path,
            headers.iter().copied(),
            session_id,
            runtime.bait_signing_secret.as_deref(),
        )
        .ok()
        .flatten()
        .is_some()
        || runtime
            .bait_registry
            .match_action_shape(&request.method, &request.path, headers.iter().copied())
            .is_some()
    {
        return None;
    }

    runtime.bait_registry.baits().iter().find(|bait| {
        bait.expected_action
            .method
            .eq_ignore_ascii_case(&request.method)
            && bait.expected_action.path == request.path
            && bait.expected_action.header_name.is_some()
    })?;

    Some(if request.path == DECOY_RECONCILE_PATH {
        policy::DecoyWriteProbePathKind::Reconcile
    } else {
        policy::DecoyWriteProbePathKind::Other
    })
}

pub fn is_aggregated_discovery_recon_candidate_request(
    runtime: &ProxyRuntime,
    session_id: SessionId,
    request: &SurfaceRequestMeta,
) -> bool {
    discovery_surface_kind(runtime, request).is_some()
        || linked_bait_surface_kind(runtime, request).is_some()
        || is_blind_decoy_write_probe(runtime, session_id, request)
}

pub fn discovery_surface_kind(
    runtime: &ProxyRuntime,
    request: &SurfaceRequestMeta,
) -> Option<policy::DiscoverySurfaceKind> {
    if request.method != "GET" {
        return None;
    }
    if request.path == DOCS_DISCOVERY_TARGET {
        return Some(policy::DiscoverySurfaceKind::Docs);
    }

    runtime
        .bait_registry
        .bait_for_class(BaitClass::OpenApi)
        .filter(|bait| is_openapi_discovery_request(request, bait))
        .map(|_| policy::DiscoverySurfaceKind::OpenApi)
}

pub fn is_success_status(status: u16) -> bool {
    (200..300).contains(&status)
}

pub fn handle_connection(mut client_stream: TcpStream, runtime: &ProxyRuntime) -> io::Result<()> {
    configure_client_stream(&client_stream)?;

    let client_peer_addr = client_stream.peer_addr().ok();
    let client_peer = client_peer_addr.as_ref().map(ToString::to_string);
    let client_peer_ip = client_peer_addr.map(|addr| addr.ip());
    let Some(request) = read_http_request(&mut client_stream)? else {
        write_debug(
            runtime,
            "connection_closed_without_request",
            None,
            json!({
                "client_peer": client_peer,
            }),
        )?;
        return Ok(());
    };

    let intervention_mode = intervention_mode_from_control_file(&runtime.intervention_control_path);
    let path = normalized_event_path(&request)?;
    let surface_request = surface_request_meta(&request, &path);
    let request_id = RequestId::new();
    let session = effective_session_context(
        runtime,
        &request,
        &surface_request,
        client_peer_ip,
        request_id,
    )?;
    let mut policy_state = policy_state_for_session(runtime, session.session_id)?;
    if let Some(floor) = session.enforcement_floor {
        if enforcement_rank(floor) > enforcement_rank(policy_state) {
            write_debug(
                runtime,
                "session_enforcement_floor_applied",
                Some(session.session_id),
                json!({
                    "loaded_policy_state": policy_state,
                    "enforcement_floor": floor,
                }),
            )?;
            set_policy_state_for_session(runtime, session.session_id, floor)?;
            policy_state = floor;
        }
    }
    note_session_enforcement(runtime, client_peer_ip, session.session_id, policy_state);
    let starting_policy_state = policy_state;
    let mut policy_reason_override = None;
    let discovery_recon_state =
        update_discovery_recon_state_for_request(runtime, session.session_id, &surface_request)?;
    let discovery_recon_score =
        policy::aggregated_discovery_recon_score(&session.ingress_signals, discovery_recon_state);
    let mut discovery_recon_threshold = policy::discovery_recon_aggregation_score_threshold();
    if intervention_mode.interventions_enabled() {
        if let Some(transition) = policy::transition_to_suspicious_from_ingress_signals(
            policy_state,
            &surface_request.path,
            &runtime.trusted_bait_soften_path_prefixes,
            &session.ingress_identity,
            &session.ingress_signals,
        ) {
            write_debug(
                runtime,
                "policy_transition_selected",
                Some(session.session_id),
                json!({
                    "from": transition.from,
                    "to": transition.to,
                    "reason": transition.reason.as_str(),
                }),
            )?;
            set_policy_state_for_session(runtime, session.session_id, transition.to)?;
            write_event(
                &runtime.event_log,
                &policy::policy_changed_event(session.session_id, request_id, &transition),
            )?;
            policy_state = transition.to;
        } else if let Some(transition) = policy::transition_to_suspicious_from_discovery_fanout(
            policy_state,
            &surface_request.path,
            &session.ingress_identity,
            discovery_recon_state.fanout,
        ) {
            write_debug(
                runtime,
                "policy_transition_selected",
                Some(session.session_id),
                json!({
                    "from": transition.from,
                    "to": transition.to,
                    "reason": transition.reason.as_str(),
                }),
            )?;
            set_policy_state_for_session(runtime, session.session_id, transition.to)?;
            write_event(
                &runtime.event_log,
                &policy::policy_changed_event(session.session_id, request_id, &transition),
            )?;
            policy_state = transition.to;
        } else if let Some(transition) =
            policy::transition_to_suspicious_from_aggregated_discovery_recon(
                policy_state,
                &surface_request.path,
                is_aggregated_discovery_recon_candidate_request(
                    runtime,
                    session.session_id,
                    &surface_request,
                ),
                &session.ingress_identity,
                &session.ingress_signals,
                discovery_recon_state,
            )
        {
            write_debug(
                runtime,
                "policy_transition_selected",
                Some(session.session_id),
                json!({
                    "from": transition.from,
                    "to": transition.to,
                    "reason": transition.reason.as_str(),
                }),
            )?;
            set_policy_state_for_session(runtime, session.session_id, transition.to)?;
            write_event(
                &runtime.event_log,
                &policy::policy_changed_event(session.session_id, request_id, &transition),
            )?;
            policy_state = transition.to;
        }
        if starting_policy_state == PolicyState::Suspicious {
            if let Some(transition) =
                policy::transition_to_rate_limited_from_suspicious_discovery_recon(
                    policy_state,
                    &surface_request.path,
                    discovery_surface_kind(runtime, &surface_request).is_some(),
                    blind_decoy_write_probe_path_kind(
                        runtime,
                        session.session_id,
                        &surface_request,
                    )
                    .is_some(),
                    &session.ingress_identity,
                    &session.ingress_signals,
                    discovery_recon_state,
                )
            {
                write_debug(
                    runtime,
                    "policy_transition_selected",
                    Some(session.session_id),
                    json!({
                        "from": transition.from,
                        "to": transition.to,
                        "reason": transition.reason.as_str(),
                    }),
                )?;
                set_policy_state_for_session(runtime, session.session_id, transition.to)?;
                write_event(
                    &runtime.event_log,
                    &policy::policy_changed_event(session.session_id, request_id, &transition),
                )?;
                discovery_recon_threshold = policy::discovery_recon_rate_limit_score_threshold();
                policy_state = transition.to;
            }
        } else if starting_policy_state == PolicyState::RateLimited {
            if let Some(transition) = policy::transition_to_blocked_from_repeated_discovery_recon(
                policy_state,
                &surface_request.path,
                discovery_surface_kind(runtime, &surface_request).is_some(),
                blind_decoy_write_probe_path_kind(runtime, session.session_id, &surface_request)
                    .is_some(),
                &session.ingress_identity,
                &session.ingress_signals,
                discovery_recon_state,
            ) {
                write_debug(
                    runtime,
                    "policy_transition_selected",
                    Some(session.session_id),
                    json!({
                        "from": transition.from,
                        "to": transition.to,
                        "reason": transition.reason.as_str(),
                    }),
                )?;
                set_policy_state_for_session(runtime, session.session_id, transition.to)?;
                write_event(
                    &runtime.event_log,
                    &policy::policy_changed_event(session.session_id, request_id, &transition),
                )?;
                discovery_recon_threshold = policy::discovery_recon_rate_limit_score_threshold();
                policy_reason_override = Some(transition.reason);
                policy_state = transition.to;
            }
        }
    }
    write_debug(
        runtime,
        "request_received",
        Some(session.session_id),
        json!({
            "client_peer": client_peer,
            "method": request.method.as_str(),
            "target_form": debug_target_form(&request.target),
            "request_host": effective_request_host(&request),
            "path": debug_path(&path),
            "query_present": debug_query_present(&path),
            "http_version": request.version.as_str(),
            "body_len": request.body.len(),
            "header_count": request.headers.len(),
            "safe_headers": safe_header_observations(&request.headers),
            "session_source": debug_session_source(session.source),
            "ingress_identity": &session.ingress_identity,
            "authenticated_ingress_rule_rejection":
                &session.authenticated_ingress_rule_rejection,
            "local_ingress_trust_scope_rejection":
                &session.local_ingress_trust_scope_rejection,
            "ingress_signals": &session.ingress_signals,
            "trusted_ingress_local_soften_path_prefixes":
                &session.trusted_bait_soften_path_prefixes,
            "discovery_surface_fanout":
                debug_discovery_surface_fanout(discovery_recon_state.fanout),
            "discovery_request_count": discovery_recon_state.request_count,
            "discovery_query_seen": discovery_recon_state.query_seen,
            "discovery_legacy_openapi_query_seen":
                discovery_recon_state.legacy_openapi_query_seen,
            "discovery_linked_bait_surface_seen":
                discovery_recon_state.linked_bait_surface_seen,
            "discovery_linked_bait_surface_classes":
                discovery_recon_state.linked_bait_surface_classes,
            "discovery_decoy_write_probe_seen":
                discovery_recon_state.decoy_write_probe_seen,
            "discovery_decoy_write_probe_count":
                discovery_recon_state.decoy_write_probe_count,
            "discovery_decoy_write_probe_path_classes":
                discovery_recon_state.decoy_write_probe_path_classes,
            "discovery_recon_score": {
                "repeated_discovery_score": discovery_recon_score.repeated_discovery_score,
                "query_score": discovery_recon_score.query_score,
                "legacy_openapi_query_score":
                    discovery_recon_score.legacy_openapi_query_score,
                "linked_bait_surface_score":
                    discovery_recon_score.linked_bait_surface_score,
                "linked_bait_class_fanout_bonus":
                    discovery_recon_score.linked_bait_class_fanout_bonus,
                "decoy_write_probe_score":
                    discovery_recon_score.decoy_write_probe_score,
                "decoy_write_probe_path_fanout_bonus":
                    discovery_recon_score.decoy_write_probe_path_fanout_bonus,
                "detection_score": discovery_recon_score.detection_score,
                "total": discovery_recon_score.total,
                "threshold": discovery_recon_threshold,
            },
            "policy_state": policy_state,
            "intervention_mode": debug_intervention_mode(intervention_mode),
        }),
    )?;

    if !intervention_mode.interventions_enabled() {
        if let Some(response) = runtime
            .controlled_reality
            .fail_closed_response(&surface_request)
        {
            write_debug(
                runtime,
                "interventions_disabled_fail_closed",
                Some(session.session_id),
                json!({
                    "method": request.method.as_str(),
                    "path": debug_path(&surface_request.path),
                    "query_present": surface_request.query.is_some(),
                    "response_status": response.status,
                    "response_body_len": response.body.len(),
                }),
            )?;
            let decision = policy::PolicyDecision::new(
                policy_state,
                RoutingDecision::EidolonOwned,
                "interventions disabled; known controlled-reality write path failed closed",
            );

            return write_direct_response(DirectResponseContext {
                client_stream,
                runtime,
                session: &session,
                request: &request,
                path: &path,
                request_id,
                decision: &decision,
                discovery_recon_score,
                discovery_recon_threshold,
                response,
                intervention_mode,
                surface_requested_intervention: true,
            });
        }

        if let Some(unsafe_match) = classify_unsafe_bait_action(
            runtime,
            &request.method,
            &surface_request.path,
            header_pairs(&request.headers),
        ) {
            let prior_same_bait_exposure =
                if let UnsafeBaitActionMatch::HeaderPresent(matched) = &unsafe_match {
                    Some(write_bait_action_near_miss_event(
                        runtime,
                        &session,
                        request_id,
                        policy_state,
                        &matched.bait,
                        &request.method,
                        &surface_request.path,
                    )?)
                } else {
                    None
                };
            write_debug(
                runtime,
                "interventions_disabled_fail_closed",
                Some(session.session_id),
                json!({
                    "method": request.method.as_str(),
                    "path": debug_path(&surface_request.path),
                    "query_present": surface_request.query.is_some(),
                    "bait_id": &unsafe_match.bait().id,
                    "prior_same_bait_exposure": prior_same_bait_exposure,
                }),
            )?;
            let decision = policy::PolicyDecision::new(
                policy_state,
                RoutingDecision::EidolonOwned,
                "interventions disabled; unsafe bait action shape failed closed",
            );

            return write_direct_response(DirectResponseContext {
                client_stream,
                runtime,
                session: &session,
                request: &request,
                path: &path,
                request_id,
                decision: &decision,
                discovery_recon_score,
                discovery_recon_threshold,
                response: surface_text_response(403, "blocked by eidolon policy\n"),
                intervention_mode,
                surface_requested_intervention: true,
            });
        }
    }

    let mut decision = policy::decide_for_state(policy_state, intervention_mode);
    if let Some(reason) = policy_reason_override {
        decision =
            policy::PolicyDecision::new(decision.policy_state, decision.routing_decision, reason);
    }
    let controller_surface_action = if intervention_mode.interventions_enabled() {
        match decision.routing_decision {
            RoutingDecision::ProtectedUpstream => runtime
                .surface_controller
                .decide(&surface_request, session.session_id)?,
            RoutingDecision::ControlledReality => {
                let (action, transition) = controlled_reality_action(
                    runtime,
                    session.session_id,
                    &surface_request,
                    decision.reason.clone(),
                )?;
                if let Some(transition) = transition {
                    write_debug(
                        runtime,
                        "policy_transition_selected",
                        Some(session.session_id),
                        json!({
                            "from": transition.from,
                            "to": transition.to,
                            "reason": transition.reason.as_str(),
                        }),
                    )?;
                    set_policy_state_for_session(runtime, session.session_id, transition.to)?;
                    write_event(
                        &runtime.event_log,
                        &policy::policy_changed_event(session.session_id, request_id, &transition),
                    )?;
                    let blocked_decision = policy::PolicyDecision::new(
                        transition.to,
                        action.routing_decision(),
                        transition.reason.clone(),
                    );
                    write_debug(
                        runtime,
                        "surface_action_selected",
                        Some(session.session_id),
                        json!({
                            "policy_state": blocked_decision.policy_state,
                            "policy_routing_decision": blocked_decision.routing_decision,
                            "policy_reason": blocked_decision.reason.as_str(),
                            "controller_surface_action": debug_surface_action(&action),
                            "candidate_surface_action": debug_surface_action(&action),
                            "surface_action": debug_surface_action(&action),
                            "surface_requested_intervention": true,
                            "trusted_ingress_softened_surface": false,
                            "trusted_ingress_softening_reason": Value::Null,
                            "trusted_bait_soften_path_prefixes": &runtime.trusted_bait_soften_path_prefixes,
                            "trusted_ingress_local_soften_path_prefixes":
                                &session.trusted_bait_soften_path_prefixes,
                        }),
                    )?;
                    let SurfaceAction::EidolonOwned { response } = action else {
                        panic!("blocked controlled-reality action should be eidolon owned");
                    };
                    return write_direct_response(DirectResponseContext {
                        client_stream,
                        runtime,
                        session: &session,
                        request: &request,
                        path: &path,
                        request_id,
                        decision: &blocked_decision,
                        discovery_recon_score,
                        discovery_recon_threshold,
                        response,
                        intervention_mode,
                        surface_requested_intervention: true,
                    });
                }
                action
            }
            RoutingDecision::RateLimited => SurfaceAction::RateLimited {
                reason: decision.reason.clone(),
                response: rate_limited_response(
                    runtime.controlled_reality_config.retry_after_seconds,
                ),
            },
            RoutingDecision::EidolonOwned => SurfaceAction::EidolonOwned {
                response: surface_text_response(403, "blocked by eidolon policy\n"),
            },
            RoutingDecision::RewrittenUpstream => {
                return Err(invalid_data(
                    "policy requested rewritten upstream without a surface rewrite plan",
                ));
            }
        }
    } else {
        SurfaceAction::ProtectedUpstream
    };
    let candidate_surface_action = strengthen_surface_action_for_suspicious_discovery(
        runtime,
        session.session_id,
        decision.policy_state,
        &surface_request,
        controller_surface_action.clone(),
    )?;
    let (surface_action, trusted_ingress_softening_reason) =
        maybe_soften_surface_action_for_trusted_ingress(
            &runtime.trusted_bait_soften_path_prefixes,
            &session,
            decision.policy_state,
            &surface_request,
            candidate_surface_action.clone(),
        );
    let mut effective_decision = policy::PolicyDecision::new(
        decision.policy_state,
        surface_action.routing_decision(),
        trusted_ingress_softening_reason
            .clone()
            .unwrap_or_else(|| decision.reason.clone()),
    );
    let surface_requested_intervention =
        !matches!(&candidate_surface_action, SurfaceAction::ProtectedUpstream);
    write_debug(
        runtime,
        "surface_action_selected",
        Some(session.session_id),
        json!({
            "policy_state": decision.policy_state,
            "policy_routing_decision": decision.routing_decision,
            "policy_reason": decision.reason.as_str(),
            "controller_surface_action": debug_surface_action(&controller_surface_action),
            "candidate_surface_action": debug_surface_action(&candidate_surface_action),
            "surface_action": debug_surface_action(&surface_action),
            "surface_requested_intervention": surface_requested_intervention,
            "trusted_ingress_softened_surface": trusted_ingress_softening_reason.is_some(),
            "trusted_ingress_softening_reason": trusted_ingress_softening_reason,
            "trusted_bait_soften_path_prefixes": &runtime.trusted_bait_soften_path_prefixes,
            "trusted_ingress_local_soften_path_prefixes":
                &session.trusted_bait_soften_path_prefixes,
        }),
    )?;
    if let Some(transition) = maybe_transition_to_blocked_from_reality_escape_attempt(
        runtime,
        &session,
        &request,
        &surface_request,
        request_id,
        &effective_decision,
    )? {
        write_debug(
            runtime,
            "policy_transition_selected",
            Some(session.session_id),
            json!({
                "from": transition.from,
                "to": transition.to,
                "reason": transition.reason.as_str(),
            }),
        )?;
        set_policy_state_for_session(runtime, session.session_id, transition.to)?;
        write_event(
            &runtime.event_log,
            &policy::policy_changed_event(session.session_id, request_id, &transition),
        )?;
        let blocked_decision = policy::PolicyDecision::new(
            transition.to,
            RoutingDecision::EidolonOwned,
            transition.reason.clone(),
        );
        let blocked_response = surface_text_response(403, "blocked by eidolon policy\n");
        let blocked_surface_action = SurfaceAction::EidolonOwned {
            response: blocked_response.clone(),
        };
        write_debug(
            runtime,
            "surface_action_selected",
            Some(session.session_id),
            json!({
                "policy_state": blocked_decision.policy_state,
                "policy_routing_decision": blocked_decision.routing_decision,
                "policy_reason": blocked_decision.reason.as_str(),
                "controller_surface_action": debug_surface_action(&controller_surface_action),
                "candidate_surface_action": debug_surface_action(&candidate_surface_action),
                "surface_action": debug_surface_action(&blocked_surface_action),
                "surface_requested_intervention": true,
                "trusted_ingress_softened_surface": false,
                "trusted_ingress_softening_reason": Value::Null,
                "trusted_bait_soften_path_prefixes": &runtime.trusted_bait_soften_path_prefixes,
                "trusted_ingress_local_soften_path_prefixes":
                    &session.trusted_bait_soften_path_prefixes,
            }),
        )?;
        return write_direct_response(DirectResponseContext {
            client_stream,
            runtime,
            session: &session,
            request: &request,
            path: &path,
            request_id,
            decision: &blocked_decision,
            discovery_recon_score,
            discovery_recon_threshold,
            response: blocked_response,
            intervention_mode,
            surface_requested_intervention: true,
        });
    }

    if intervention_mode.interventions_enabled()
        && (matches!(&surface_action, SurfaceAction::ProtectedUpstream)
            || (decision.policy_state == PolicyState::RateLimited
                && matches!(&surface_action, SurfaceAction::RateLimited { .. })))
    {
        if let Some(action_match) = runtime
            .bait_registry
            .match_action_for_session(
                &request.method,
                &surface_request.path,
                header_pairs(&request.headers),
                session.session_id,
                runtime.bait_signing_secret.as_deref(),
            )
            .map_err(|error| invalid_data(error.to_string()))?
        {
            let action_exposure_id =
                bait_action_exposure_id(runtime, &session, &action_match.bait.id)?;
            let header_value_mint_status = if action_match.header_value_mint_status
                == Some(BaitHeaderValueMintStatus::ExpiredSessionValue)
            {
                Some(BaitHeaderValueMintStatus::ExpiredSessionValue)
            } else {
                mark_bait_action_replay_if_needed(runtime, session.session_id, &action_match.bait)?
            };
            let mint_not_fresh = matches!(
                header_value_mint_status,
                Some(BaitHeaderValueMintStatus::ReplaySeen)
                    | Some(BaitHeaderValueMintStatus::ExpiredSessionValue)
            );
            effective_decision = policy::PolicyDecision::new(
                decision.policy_state,
                RoutingDecision::EidolonOwned,
                match header_value_mint_status {
                    Some(BaitHeaderValueMintStatus::ReplaySeen) => {
                        "session-minted bait proof replay detected; unsafe bait action held Eidolon-owned"
                    }
                    Some(BaitHeaderValueMintStatus::ExpiredSessionValue) => {
                        "session-minted bait proof expired before use; unsafe bait action held Eidolon-owned"
                    }
                    _ => "bait-derived decoy action intercepted before protected upstream",
                },
            );
            write_event(
                &runtime.event_log,
                &request_seen_event(
                    &request,
                    &path,
                    &session,
                    request_id,
                    &effective_decision,
                    discovery_recon_score,
                    discovery_recon_threshold,
                ),
            )?;
            write_bait_action_observed_event_with_exposure(
                runtime,
                &session,
                request_id,
                decision.policy_state,
                BaitActionObservation {
                    bait: &action_match.bait,
                    method: &request.method,
                    path: &surface_request.path,
                    exposure_id: action_exposure_id.clone(),
                    prior_same_bait_exposure: action_exposure_id.is_some(),
                    header_value_mint_status,
                },
            )?;
            write_debug(
                runtime,
                "bait_action_match",
                Some(session.session_id),
                json!({
                    "bait_id": &action_match.bait.id,
                    "method": request.method.as_str(),
                    "path": debug_path(&surface_request.path),
                    "query_present": surface_request.query.is_some(),
                    "matched_prior_exposure": action_exposure_id.is_some(),
                    "exposure_id": &action_exposure_id,
                    "header_value_mint_status":
                        header_value_mint_status.map(|status| format!("{status:?}")),
                }),
            )?;

            if mint_not_fresh {
                write_debug(
                    runtime,
                    "bait_action_non_fresh_rejected",
                    Some(session.session_id),
                    json!({
                        "bait_id": &action_match.bait.id,
                        "method": request.method.as_str(),
                        "path": debug_path(&surface_request.path),
                        "query_present": surface_request.query.is_some(),
                        "header_value_mint_status":
                            header_value_mint_status.map(|status| format!("{status:?}")),
                    }),
                )?;
                write_event(
                    &runtime.event_log,
                    &policy::policy_intervention_event(
                        session.session_id,
                        request_id,
                        &effective_decision,
                    ),
                )?;
                let mut response = bait_action_synthetic_response();
                apply_response_headers(&mut response, &session);
                write_event(
                    &runtime.event_log,
                    &policy::response_audit_event(
                        session.session_id,
                        request_id,
                        &effective_decision,
                        response.status,
                    ),
                )?;
                write_debug(
                    runtime,
                    "response_served",
                    Some(session.session_id),
                    json!({
                        "route": "bait_action_direct",
                        "decision": {
                            "policy_state": effective_decision.policy_state,
                            "routing_decision": effective_decision.routing_decision,
                            "reason": effective_decision.reason.as_str(),
                        },
                        "response": debug_response_fields(&response),
                    }),
                )?;

                client_stream.write_all(&response.to_http_bytes())?;
                return client_stream.flush();
            } else {
                let mut response = if let Some(transition) =
                    policy::transition_after_correlated_bait_action(decision.policy_state)
                        .filter(|_| action_exposure_id.is_some())
                {
                    write_debug(
                        runtime,
                        "policy_transition_selected",
                        Some(session.session_id),
                        json!({
                            "from": transition.from,
                            "to": transition.to,
                            "reason": transition.reason.as_str(),
                        }),
                    )?;
                    set_policy_state_for_session(runtime, session.session_id, transition.to)?;
                    write_event(
                        &runtime.event_log,
                        &policy::policy_changed_event(session.session_id, request_id, &transition),
                    )?;
                    let (action, controlled_transition) = controlled_reality_action(
                        runtime,
                        session.session_id,
                        &surface_request,
                        transition.reason.clone(),
                    )?;
                    effective_decision = if let Some(controlled_transition) = controlled_transition
                    {
                        write_debug(
                            runtime,
                            "policy_transition_selected",
                            Some(session.session_id),
                            json!({
                                "from": controlled_transition.from,
                                "to": controlled_transition.to,
                                "reason": controlled_transition.reason.as_str(),
                            }),
                        )?;
                        set_policy_state_for_session(
                            runtime,
                            session.session_id,
                            controlled_transition.to,
                        )?;
                        write_event(
                            &runtime.event_log,
                            &policy::policy_changed_event(
                                session.session_id,
                                request_id,
                                &controlled_transition,
                            ),
                        )?;
                        policy::PolicyDecision::new(
                            controlled_transition.to,
                            action.routing_decision(),
                            controlled_transition.reason.clone(),
                        )
                    } else {
                        direct_surface_decision(transition.to, &action, transition.reason)
                    };
                    write_event(
                        &runtime.event_log,
                        &policy::policy_intervention_event(
                            session.session_id,
                            request_id,
                            &effective_decision,
                        ),
                    )?;
                    direct_surface_response(action)
                        .expect("controlled reality action should produce direct response")
                } else {
                    write_event(
                        &runtime.event_log,
                        &policy::policy_intervention_event(
                            session.session_id,
                            request_id,
                            &effective_decision,
                        ),
                    )?;
                    bait_action_synthetic_response()
                };
                apply_response_headers(&mut response, &session);
                write_event(
                    &runtime.event_log,
                    &policy::response_audit_event(
                        session.session_id,
                        request_id,
                        &effective_decision,
                        response.status,
                    ),
                )?;
                write_debug(
                    runtime,
                    "response_served",
                    Some(session.session_id),
                    json!({
                        "route": "bait_action_direct",
                        "decision": {
                            "policy_state": effective_decision.policy_state,
                            "routing_decision": effective_decision.routing_decision,
                            "reason": effective_decision.reason.as_str(),
                        },
                        "response": debug_response_fields(&response),
                    }),
                )?;

                client_stream.write_all(&response.to_http_bytes())?;
                return client_stream.flush();
            }
        }
    }

    if intervention_mode.interventions_enabled()
        && matches!(&surface_action, SurfaceAction::ProtectedUpstream)
    {
        if let Some(unsafe_match) = classify_unsafe_bait_action(
            runtime,
            &request.method,
            &surface_request.path,
            header_pairs(&request.headers),
        ) {
            if let UnsafeBaitActionMatch::HeaderPresent(action_shape_match) = &unsafe_match {
                let prior_same_bait_exposure = write_bait_action_near_miss_event(
                    runtime,
                    &session,
                    request_id,
                    decision.policy_state,
                    &action_shape_match.bait,
                    &request.method,
                    &surface_request.path,
                )?;
                write_debug(
                    runtime,
                    "bait_action_near_miss",
                    Some(session.session_id),
                    json!({
                        "bait_id": &action_shape_match.bait.id,
                        "method": request.method.as_str(),
                        "path": debug_path(&surface_request.path),
                        "query_present": surface_request.query.is_some(),
                        "prior_same_bait_exposure": prior_same_bait_exposure,
                    }),
                )?;

                if let Some(transition) =
                    policy::transition_to_rate_limited_from_same_bait_near_miss(
                        decision.policy_state,
                        &surface_request.path,
                        &action_shape_match.bait.id,
                        prior_same_bait_exposure,
                    )
                {
                    write_debug(
                        runtime,
                        "policy_transition_selected",
                        Some(session.session_id),
                        json!({
                            "from": transition.from,
                            "to": transition.to,
                            "reason": transition.reason.as_str(),
                        }),
                    )?;
                    set_policy_state_for_session(runtime, session.session_id, transition.to)?;
                    write_event(
                        &runtime.event_log,
                        &policy::policy_changed_event(session.session_id, request_id, &transition),
                    )?;
                    let response = rate_limited_response(
                        runtime.controlled_reality_config.retry_after_seconds,
                    );
                    let action = SurfaceAction::RateLimited {
                        reason: transition.reason.clone(),
                        response: response.clone(),
                    };
                    effective_decision =
                        direct_surface_decision(transition.to, &action, transition.reason);
                    return write_direct_response(DirectResponseContext {
                        client_stream,
                        runtime,
                        session: &session,
                        request: &request,
                        path: &path,
                        request_id,
                        decision: &effective_decision,
                        discovery_recon_score,
                        discovery_recon_threshold,
                        response,
                        intervention_mode,
                        surface_requested_intervention: true,
                    });
                }
            }

            // Invariant: a recognized unsafe bait action shape never reaches
            // the protected upstream. Missing, malformed, or mismatched proofs
            // change evidence confidence, never the routing boundary.
            effective_decision = policy::PolicyDecision::new(
                decision.policy_state,
                RoutingDecision::EidolonOwned,
                "unsafe bait action shape held Eidolon-owned; proof missing, malformed, or mismatched",
            );
            return write_direct_response(DirectResponseContext {
                client_stream,
                runtime,
                session: &session,
                request: &request,
                path: &path,
                request_id,
                decision: &effective_decision,
                discovery_recon_score,
                discovery_recon_threshold,
                response: surface_text_response(202, "accepted\n"),
                intervention_mode,
                surface_requested_intervention: true,
            });
        }
    }

    if intervention_mode.interventions_enabled()
        && decision.policy_state == PolicyState::RateLimited
        && matches!(&surface_action, SurfaceAction::RateLimited { .. })
        && runtime
            .bait_registry
            .match_action_for_session(
                &request.method,
                &surface_request.path,
                header_pairs(&request.headers),
                session.session_id,
                runtime.bait_signing_secret.as_deref(),
            )
            .map_err(|error| invalid_data(error.to_string()))?
            .is_none()
    {
        if let Some(action_shape_match) = runtime.bait_registry.match_action_shape(
            &request.method,
            &surface_request.path,
            header_pairs(&request.headers),
        ) {
            let prior_same_bait_exposure = write_bait_action_near_miss_event(
                runtime,
                &session,
                request_id,
                decision.policy_state,
                &action_shape_match.bait,
                &request.method,
                &surface_request.path,
            )?;
            write_debug(
                runtime,
                "bait_action_near_miss",
                Some(session.session_id),
                json!({
                    "bait_id": &action_shape_match.bait.id,
                    "method": request.method.as_str(),
                    "path": debug_path(&surface_request.path),
                    "query_present": surface_request.query.is_some(),
                    "prior_same_bait_exposure": prior_same_bait_exposure,
                }),
            )?;

            if let Some(transition) =
                policy::transition_to_blocked_from_repeated_same_bait_near_miss(
                    decision.policy_state,
                    &surface_request.path,
                    &action_shape_match.bait.id,
                    prior_same_bait_exposure,
                )
            {
                write_debug(
                    runtime,
                    "policy_transition_selected",
                    Some(session.session_id),
                    json!({
                        "from": transition.from,
                        "to": transition.to,
                        "reason": transition.reason.as_str(),
                    }),
                )?;
                set_policy_state_for_session(runtime, session.session_id, transition.to)?;
                write_event(
                    &runtime.event_log,
                    &policy::policy_changed_event(session.session_id, request_id, &transition),
                )?;
                effective_decision = policy::PolicyDecision::new(
                    transition.to,
                    RoutingDecision::EidolonOwned,
                    transition.reason.clone(),
                );
                return write_direct_response(DirectResponseContext {
                    client_stream,
                    runtime,
                    session: &session,
                    request: &request,
                    path: &path,
                    request_id,
                    decision: &effective_decision,
                    discovery_recon_score,
                    discovery_recon_threshold,
                    response: surface_text_response(403, "blocked by eidolon policy\n"),
                    intervention_mode,
                    surface_requested_intervention: true,
                });
            }
        }
    }

    if let Some(mut response) = direct_surface_response(surface_action.clone()) {
        effective_decision = direct_surface_decision(
            decision.policy_state,
            &surface_action,
            decision.reason.clone(),
        );
        write_request_and_policy_events(
            runtime,
            &request_seen_event(
                &request,
                &path,
                &session,
                request_id,
                &effective_decision,
                discovery_recon_score,
                discovery_recon_threshold,
            ),
            request_id,
            &effective_decision,
            intervention_mode,
            surface_requested_intervention,
        )?;
        apply_response_headers(&mut response, &session);
        if let Some(bait) = bait_exposure_for_direct_surface(
            &decision,
            &surface_action,
            &surface_request,
            &runtime.bait_registry,
        ) {
            write_bait_exposed_event(
                runtime,
                &session,
                request_id,
                decision.policy_state,
                bait,
                surface_request.path.clone(),
            )?;
        }
        write_event(
            &runtime.event_log,
            &policy::response_audit_event(
                session.session_id,
                request_id,
                &effective_decision,
                response.status,
            ),
        )?;
        write_debug(
            runtime,
            "response_served",
            Some(session.session_id),
            json!({
                "route": "direct_surface",
                "decision": {
                    "policy_state": effective_decision.policy_state,
                    "routing_decision": effective_decision.routing_decision,
                    "reason": effective_decision.reason.as_str(),
                },
                "response": debug_response_fields(&response),
            }),
        )?;

        client_stream.write_all(&response.to_http_bytes())?;
        return client_stream.flush();
    }

    // Safety invariant: a recognized unsafe bait action shape never reaches
    // the protected upstream. Every earlier flow should already have held such
    // requests Eidolon-owned; this choke point enforces the invariant even if
    // a future routing change reopens a fall-through.
    if let Some(unsafe_match) = classify_unsafe_bait_action(
        runtime,
        &request.method,
        &surface_request.path,
        header_pairs(&request.headers),
    ) {
        let prior_same_bait_exposure =
            if let UnsafeBaitActionMatch::HeaderPresent(matched) = &unsafe_match {
                Some(write_bait_action_near_miss_event(
                    runtime,
                    &session,
                    request_id,
                    decision.policy_state,
                    &matched.bait,
                    &request.method,
                    &surface_request.path,
                )?)
            } else {
                None
            };
        write_debug(
            runtime,
            "unsafe_bait_action_final_guard",
            Some(session.session_id),
            json!({
                "bait_id": &unsafe_match.bait().id,
                "method": request.method.as_str(),
                "path": debug_path(&surface_request.path),
                "query_present": surface_request.query.is_some(),
                "prior_same_bait_exposure": prior_same_bait_exposure,
            }),
        )?;
        let guard_decision = policy::PolicyDecision::new(
            decision.policy_state,
            RoutingDecision::EidolonOwned,
            "unsafe bait action shape caught by the final fail-closed guard",
        );
        return write_direct_response(DirectResponseContext {
            client_stream,
            runtime,
            session: &session,
            request: &request,
            path: &path,
            request_id,
            decision: &guard_decision,
            discovery_recon_score,
            discovery_recon_threshold,
            response: surface_text_response(202, "accepted\n"),
            intervention_mode,
            surface_requested_intervention: true,
        });
    }

    let upstream_request_decision = upstream_request_decision(
        decision.policy_state,
        &surface_action,
        effective_decision.reason.clone(),
    );
    write_event(
        &runtime.event_log,
        &request_seen_event(
            &request,
            &path,
            &session,
            request_id,
            &upstream_request_decision,
            discovery_recon_score,
            discovery_recon_threshold,
        ),
    )?;
    if intervention_mode == InterventionMode::Disabled {
        write_event(
            &runtime.event_log,
            &policy::policy_intervention_event(
                session.session_id,
                request_id,
                &upstream_request_decision,
            ),
        )?;
    }

    let upstream_request = request.to_upstream_bytes(&runtime.upstream)?;
    write_debug(
        runtime,
        "upstream_request_forwarding",
        Some(session.session_id),
        json!({
            "method": request.method.as_str(),
            "path": debug_path(&path),
            "query_present": debug_query_present(&path),
            "connect_addr": runtime.upstream.connect_addr.as_str(),
            "request_bytes": upstream_request.len(),
        }),
    )?;
    let mut upstream_stream = connect_upstream(&runtime.upstream)?;
    upstream_stream.write_all(&upstream_request)?;
    upstream_stream.flush()?;

    let mut response = read_http_response(&mut upstream_stream)?;
    write_debug(
        runtime,
        "upstream_response_received",
        Some(session.session_id),
        json!({
            "status": response.status,
            "body_len": response.body.len(),
            "header_count": response.headers.len(),
            "surface_requested_intervention": surface_requested_intervention,
        }),
    )?;
    let mut pending_bait_exposure = None;
    if let SurfaceAction::RewrittenUpstream { plan } = surface_action {
        let meta = surface_response_meta(&response, &path);
        if is_success_status(response.status) {
            let outcome = rewrite_response_body(&meta, &response.body, &plan);
            write_debug(
                runtime,
                "surface_rewrite_evaluated",
                Some(session.session_id),
                json!({
                    "plan": debug_rewrite_plan(&plan),
                    "disposition": debug_rewrite_disposition(outcome.disposition()),
                    "refusal": outcome.refusal().map(ToString::to_string),
                    "original_body_len": response.body.len(),
                    "output_body_len": outcome.body().len(),
                    "surface_path": debug_path(&path),
                    "query_present": debug_query_present(&path),
                }),
            )?;
            if outcome.is_rewritten() {
                effective_decision = policy::PolicyDecision::new(
                    decision.policy_state,
                    RoutingDecision::RewrittenUpstream,
                    "surface controller rewrote upstream response",
                );
                if let Some(bait) = runtime.bait_registry.bait_for_class(BaitClass::OpenApi) {
                    if is_openapi_discovery_request(&surface_request, bait) {
                        pending_bait_exposure =
                            Some((bait.clone(), surface_request.target.clone()));
                    }
                }
            } else if let Some(refusal) = outcome.refusal() {
                effective_decision = policy::PolicyDecision::new(
                    decision.policy_state,
                    RoutingDecision::ProtectedUpstream,
                    format!("surface controller rewrite refused; forwarded original upstream response: {refusal}"),
                );
            } else {
                effective_decision = policy::PolicyDecision::new(
                    decision.policy_state,
                    RoutingDecision::ProtectedUpstream,
                    "surface controller rewrite made no changes; forwarded original upstream response",
                );
            }
            response.body = outcome.into_body();
        } else {
            write_debug(
                runtime,
                "surface_rewrite_skipped",
                Some(session.session_id),
                json!({
                    "reason": "non_success_upstream_response",
                    "status": response.status,
                    "plan": debug_rewrite_plan(&plan),
                }),
            )?;
            effective_decision = policy::PolicyDecision::new(
                decision.policy_state,
                RoutingDecision::ProtectedUpstream,
                "surface controller skipped rewrite for non-success upstream response",
            );
        }
    }
    apply_response_headers(&mut response, &session);

    if surface_requested_intervention {
        write_event(
            &runtime.event_log,
            &policy::policy_intervention_event(session.session_id, request_id, &effective_decision),
        )?;
    }
    if let Some((bait, surface)) = pending_bait_exposure {
        write_bait_exposed_event(
            runtime,
            &session,
            request_id,
            decision.policy_state,
            &bait,
            surface,
        )?;
    }
    write_event(
        &runtime.event_log,
        &policy::response_audit_event(
            session.session_id,
            request_id,
            &effective_decision,
            response.status,
        ),
    )?;
    write_debug(
        runtime,
        "response_served",
        Some(session.session_id),
        json!({
            "route": "upstream",
            "decision": {
                "policy_state": effective_decision.policy_state,
                "routing_decision": effective_decision.routing_decision,
                "reason": effective_decision.reason.as_str(),
            },
            "response": debug_response_fields(&response),
        }),
    )?;

    client_stream.write_all(&response.to_http_bytes())?;
    client_stream.flush()
}

pub fn maybe_transition_to_blocked_from_reality_escape_attempt(
    runtime: &ProxyRuntime,
    session: &SessionContext,
    request: &HttpRequest,
    surface_request: &SurfaceRequestMeta,
    request_id: RequestId,
    decision: &policy::PolicyDecision,
) -> io::Result<Option<policy::PolicyTransition>> {
    if decision.policy_state != PolicyState::ControlledReality {
        return Ok(None);
    }
    if runtime
        .controlled_reality
        .is_controlled_branch(surface_request)
    {
        clear_reality_escape_attempts_for_session(runtime, session.session_id)?;
        return Ok(None);
    }
    if decision.policy_state != PolicyState::ControlledReality
        || !matches!(
            decision.routing_decision,
            RoutingDecision::ControlledReality | RoutingDecision::RateLimited
        )
    {
        return Ok(None);
    }
    let attempt_count = note_reality_escape_attempt_for_session(runtime, session.session_id)?;

    write_debug(
        runtime,
        "reality_escape_attempt",
        Some(session.session_id),
        json!({
            "method": request.method.as_str(),
            "path": debug_path(&surface_request.path),
            "query_present": surface_request.query.is_some(),
            "policy_state": decision.policy_state,
            "routing_decision": decision.routing_decision,
            "attempt_count": attempt_count,
        }),
    )?;

    write_event(
        &runtime.event_log,
        &policy::reality_escape_attempt_event(
            session.session_id,
            request_id,
            decision.policy_state,
            request.method.clone(),
            redacted_event_target(&surface_request.path),
            decision.routing_decision,
            "controlled session requested a path outside the configured controlled-reality branch",
        ),
    )?;

    Ok(
        policy::transition_to_blocked_from_repeated_reality_escape_attempt(
            decision.policy_state,
            &surface_request.path,
            attempt_count,
        ),
    )
}

pub struct DirectResponseContext<'a> {
    pub client_stream: TcpStream,
    pub runtime: &'a ProxyRuntime,
    pub session: &'a SessionContext,
    pub request: &'a HttpRequest,
    pub path: &'a str,
    pub request_id: RequestId,
    pub decision: &'a policy::PolicyDecision,
    pub discovery_recon_score: policy::DiscoveryReconAggregationScore,
    pub discovery_recon_threshold: u8,
    pub response: SurfaceResponse,
    pub intervention_mode: InterventionMode,
    pub surface_requested_intervention: bool,
}

pub fn write_direct_response(context: DirectResponseContext<'_>) -> io::Result<()> {
    let DirectResponseContext {
        mut client_stream,
        runtime,
        session,
        request,
        path,
        request_id,
        decision,
        discovery_recon_score,
        discovery_recon_threshold,
        response,
        intervention_mode,
        surface_requested_intervention,
    } = context;

    write_request_and_policy_events(
        runtime,
        &request_seen_event(
            request,
            path,
            session,
            request_id,
            decision,
            discovery_recon_score,
            discovery_recon_threshold,
        ),
        request_id,
        decision,
        intervention_mode,
        surface_requested_intervention,
    )?;

    let mut response = surface_response_to_http(response);
    apply_response_headers(&mut response, session);
    write_event(
        &runtime.event_log,
        &policy::response_audit_event(session.session_id, request_id, decision, response.status),
    )?;
    write_debug(
        runtime,
        "response_served",
        Some(session.session_id),
        json!({
            "request_id": request_id.0,
            "route": "direct_response",
            "decision": {
                "policy_state": decision.policy_state,
                "routing_decision": decision.routing_decision,
                "reason": decision.reason.as_str(),
            },
            "response": debug_response_fields(&response),
        }),
    )?;

    client_stream.write_all(&response.to_http_bytes())?;
    client_stream.flush()
}

pub fn policy_state_for_session(
    runtime: &ProxyRuntime,
    session_id: SessionId,
) -> io::Result<PolicyState> {
    let store = runtime
        .policy_store
        .lock()
        .map_err(|_| io::Error::other("policy state store lock poisoned"))?;

    Ok(store.policy_state(session_id))
}

/// Best-effort enforcement-floor feedback for peer continuity. The policy
/// store remains authoritative; a poisoned authority lock only weakens the
/// rotation-abuse safety net for later requests, never current routing.
pub fn note_session_enforcement(
    runtime: &ProxyRuntime,
    client_peer_ip: Option<IpAddr>,
    session_id: SessionId,
    policy_state: PolicyState,
) {
    let now_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    if let Ok(mut authority) = runtime.session_authority.lock() {
        authority.note_enforcement(client_peer_ip, session_id, policy_state, now_unix_secs);
    }
}

pub fn set_policy_state_for_session(
    runtime: &ProxyRuntime,
    session_id: SessionId,
    policy_state: PolicyState,
) -> io::Result<()> {
    let mut store = runtime
        .policy_store
        .lock()
        .map_err(|_| io::Error::other("policy state store lock poisoned"))?;

    store.set_policy_state(session_id, policy_state)
}

pub fn note_reality_escape_attempt_for_session(
    runtime: &ProxyRuntime,
    session_id: SessionId,
) -> io::Result<u32> {
    let mut store = runtime
        .policy_store
        .lock()
        .map_err(|_| io::Error::other("policy state store lock poisoned"))?;

    store.note_reality_escape_attempt(session_id)
}

pub fn clear_reality_escape_attempts_for_session(
    runtime: &ProxyRuntime,
    session_id: SessionId,
) -> io::Result<()> {
    let mut store = runtime
        .policy_store
        .lock()
        .map_err(|_| io::Error::other("policy state store lock poisoned"))?;

    store.clear_reality_escape_attempts(session_id)
}

pub fn update_discovery_recon_state_for_request(
    runtime: &ProxyRuntime,
    session_id: SessionId,
    request: &SurfaceRequestMeta,
) -> io::Result<policy::DiscoveryReconState> {
    let mut store = runtime
        .policy_store
        .lock()
        .map_err(|_| io::Error::other("policy state store lock poisoned"))?;

    if let Some(kind) = discovery_surface_kind(runtime, request) {
        return store.note_discovery_surface_request(
            session_id,
            kind,
            request.query.is_some(),
            is_legacy_openapi_discovery_query(request),
        );
    }

    if let Some(kind) = linked_bait_surface_kind(runtime, request) {
        return store.note_linked_bait_surface_request(session_id, kind);
    }

    if let Some(kind) = blind_decoy_write_probe_path_kind(runtime, session_id, request) {
        return store.note_decoy_write_probe(session_id, kind);
    }

    let record = store.record(session_id);
    Ok(policy::DiscoveryReconState {
        fanout: record.discovery_surface_fanout,
        request_count: record.discovery_request_count,
        query_seen: record.discovery_query_seen,
        legacy_openapi_query_seen: record.discovery_legacy_openapi_query_seen,
        linked_bait_surface_seen: record.discovery_linked_bait_surface_fanout.any_seen(),
        linked_bait_surface_classes: record
            .discovery_linked_bait_surface_fanout
            .distinct_surface_count(),
        decoy_write_probe_seen: record.discovery_decoy_write_probe_count > 0,
        decoy_write_probe_count: record.discovery_decoy_write_probe_count,
        decoy_write_probe_path_classes: record
            .discovery_decoy_write_probe_fanout
            .distinct_path_count(),
    })
}

pub fn controlled_reality_action(
    runtime: &ProxyRuntime,
    session_id: SessionId,
    request: &SurfaceRequestMeta,
    default_reason: String,
) -> io::Result<(SurfaceAction, Option<policy::PolicyTransition>)> {
    let depth = {
        let mut store = runtime
            .policy_store
            .lock()
            .map_err(|_| io::Error::other("policy state store lock poisoned"))?;
        store.increment_controlled_reality_depth(session_id)?
    };

    let depth_limit = runtime.controlled_reality_config.max_action_depth;
    if depth > depth_limit {
        let tarpit_delay = runtime.controlled_reality_config.tarpit_delay;
        if !tarpit_delay.is_zero() {
            thread::sleep(tarpit_delay);
        }
        let transition = policy::transition_to_blocked_from_repeated_controlled_reality_depth_limit(
            PolicyState::ControlledReality,
            &request.path,
            depth,
            depth_limit,
        );
        let action = if transition.is_some() {
            SurfaceAction::EidolonOwned {
                response: surface_text_response(403, "blocked by eidolon policy\n"),
            }
        } else {
            SurfaceAction::RateLimited {
                reason: format!(
                    "controlled reality action depth {depth} exceeded limit {depth_limit}; tarpit delay {}ms",
                    tarpit_delay.as_millis()
                ),
                response: rate_limited_response(
                    runtime.controlled_reality_config.retry_after_seconds,
                ),
            }
        };
        write_debug(
            runtime,
            "controlled_reality_action_selected",
            Some(session_id),
            json!({
                "depth": depth,
                "depth_limit": depth_limit,
                "tarpit_ms": tarpit_delay.as_millis(),
                "transition": transition.as_ref().map(|selected| json!({
                    "from": selected.from,
                    "to": selected.to,
                    "reason": selected.reason.as_str(),
                })),
                "action": debug_surface_action(&action),
            }),
        )?;
        return Ok((action, transition));
    }

    let mut action = runtime.controlled_reality.decide(request, depth);
    if let SurfaceAction::ControlledReality { reason, .. } = &mut action {
        if depth == 1 {
            *reason = default_reason;
        }
    }
    write_debug(
        runtime,
        "controlled_reality_action_selected",
        Some(session_id),
        json!({
            "depth": depth,
            "depth_limit": depth_limit,
            "action": debug_surface_action(&action),
        }),
    )?;

    Ok((action, None))
}

pub fn bait_exposure_for_direct_surface<'a>(
    policy_decision: &policy::PolicyDecision,
    surface_action: &SurfaceAction,
    surface_request: &SurfaceRequestMeta,
    bait_registry: &'a BaitRegistry,
) -> Option<&'a Bait> {
    if policy_decision.routing_decision != RoutingDecision::ProtectedUpstream
        || !matches!(surface_action, SurfaceAction::EidolonOwned { .. })
        || surface_request.method != "GET"
    {
        return None;
    }

    bait_registry
        .bait_for_surface(&surface_request.path)
        .or_else(|| {
            (policy_decision.policy_state == PolicyState::Suspicious
                && surface_request.path == DOCS_DISCOVERY_TARGET)
                .then(|| bait_registry.bait_for_class(BaitClass::Docs))
                .flatten()
        })
}

pub fn strengthen_surface_action_for_suspicious_discovery(
    runtime: &ProxyRuntime,
    session_id: SessionId,
    policy_state: PolicyState,
    surface_request: &SurfaceRequestMeta,
    controller_surface_action: SurfaceAction,
) -> io::Result<SurfaceAction> {
    if policy_state != PolicyState::Suspicious
        || surface_request.method != "GET"
        || !matches!(
            &controller_surface_action,
            SurfaceAction::RewrittenUpstream { .. }
        )
    {
        return Ok(controller_surface_action);
    }

    if surface_request.path == DOCS_DISCOVERY_TARGET {
        let Some(bait) = runtime.bait_registry.bait_for_class(BaitClass::Docs) else {
            return Ok(controller_surface_action);
        };
        let bait =
            render_bait_for_session(bait, session_id, runtime.bait_signing_secret.as_deref())
                .map_err(|error| invalid_data(error.to_string()))?;

        return Ok(SurfaceAction::EidolonOwned {
            response: bait_surface_response(&bait, &runtime.bait_content),
        });
    }

    let Some(bait) = runtime.bait_registry.bait_for_class(BaitClass::OpenApi) else {
        return Ok(controller_surface_action);
    };
    if surface_request.path != OPENAPI_DISCOVERY_TARGET
        || !is_openapi_discovery_request(surface_request, bait)
    {
        return Ok(controller_surface_action);
    }
    let bait = render_bait_for_session(bait, session_id, runtime.bait_signing_secret.as_deref())
        .map_err(|error| invalid_data(error.to_string()))?;

    Ok(SurfaceAction::EidolonOwned {
        response: owned_openapi_discovery_response(&bait, &runtime.bait_content.openapi),
    })
}

pub fn upstream_request_decision(
    policy_state: PolicyState,
    surface_action: &SurfaceAction,
    default_reason: String,
) -> policy::PolicyDecision {
    match surface_action {
        SurfaceAction::RewrittenUpstream { .. } => policy::PolicyDecision::new(
            policy_state,
            RoutingDecision::ProtectedUpstream,
            "surface controller requested upstream response rewrite; request forwarded to protected upstream before rewrite outcome",
        ),
        _ => policy::PolicyDecision::protected_upstream(policy_state, default_reason),
    }
}

pub fn write_bait_exposed_event(
    runtime: &ProxyRuntime,
    session: &SessionContext,
    request_id: RequestId,
    policy_state: PolicyState,
    bait: &Bait,
    surface: impl Into<String>,
) -> io::Result<ExposureId> {
    let exposure_id = ExposureId(format!("exp-{}", SessionId::new().0));
    let surface = surface.into();
    let mut exposures = runtime
        .bait_exposures
        .lock()
        .map_err(|_| io::Error::other("bait exposure store lock poisoned"))?;

    write_event(
        &runtime.event_log,
        &Event::new(
            session.session_id,
            EventSource::SurfaceController,
            policy_state,
            EventKind::BaitExposed {
                bait_id: bait.id.clone(),
                exposure_id: exposure_id.clone(),
                surface: redacted_event_target(&surface),
                header_value_mint: bait.header_value_mint_audit(),
            },
        )
        .with_request_id(request_id),
    )?;

    exposures.record_exposure(session.session_id, bait.id.clone(), exposure_id.clone());
    write_debug(
        runtime,
        "bait_exposed",
        Some(session.session_id),
        json!({
            "request_id": request_id.0,
            "bait_id": &bait.id,
            "bait_class": bait.bait_class,
            "surface": debug_path(&bait.surface),
            "requested_surface": debug_path(&surface),
            "exposure_id": &exposure_id,
            "stored_exposure_count": exposures.exposures.len(),
        }),
    )?;
    Ok(exposure_id)
}

pub fn bait_action_exposure_id(
    runtime: &ProxyRuntime,
    session: &SessionContext,
    bait_id: &BaitId,
) -> io::Result<Option<ExposureId>> {
    let exposures = runtime
        .bait_exposures
        .lock()
        .map_err(|_| io::Error::other("bait exposure store lock poisoned"))?;

    Ok(exposures.exposure_for_action(session.session_id, bait_id))
}

pub struct BaitActionObservation<'a> {
    pub bait: &'a Bait,
    pub method: &'a str,
    pub path: &'a str,
    pub exposure_id: Option<ExposureId>,
    pub prior_same_bait_exposure: bool,
    pub header_value_mint_status: Option<BaitHeaderValueMintStatus>,
}

pub fn mark_bait_action_replay_if_needed(
    runtime: &ProxyRuntime,
    session_id: SessionId,
    bait: &Bait,
) -> io::Result<Option<BaitHeaderValueMintStatus>> {
    if bait.header_value_mint_audit().is_none() {
        return Ok(None);
    }

    let mut replays = runtime
        .bait_action_replays
        .lock()
        .map_err(|_| io::Error::other("bait replay store lock poisoned"))?;
    let replay_seen = replays.mark_and_check_replay(session_id, bait.id.clone());

    Ok(Some(if replay_seen {
        BaitHeaderValueMintStatus::ReplaySeen
    } else {
        BaitHeaderValueMintStatus::MatchedSessionValue
    }))
}

pub fn write_bait_action_observed_event_with_exposure(
    runtime: &ProxyRuntime,
    session: &SessionContext,
    request_id: RequestId,
    policy_state: PolicyState,
    observation: BaitActionObservation<'_>,
) -> io::Result<()> {
    let BaitActionObservation {
        bait,
        method,
        path,
        exposure_id,
        prior_same_bait_exposure,
        header_value_mint_status,
    } = observation;
    let matched_prior_exposure = exposure_id.is_some();
    write_event(
        &runtime.event_log,
        &Event::new(
            session.session_id,
            EventSource::BaitEngine,
            policy_state,
            EventKind::BaitActionObserved {
                bait_id: bait.id.clone(),
                exposure_id: exposure_id.clone(),
                method: method.to_string(),
                path: redacted_event_target(path),
                header_value_mint: bait.header_value_mint_audit(),
                header_value_mint_status,
            },
        )
        .with_request_id(request_id),
    )?;

    write_debug(
        runtime,
        "bait_action_observed",
        Some(session.session_id),
        json!({
            "request_id": request_id.0,
            "bait_id": &bait.id,
            "method": method,
            "path": debug_path(path),
            "query_present": debug_query_present(path),
            "matched_prior_exposure": matched_prior_exposure,
            "prior_same_bait_exposure": prior_same_bait_exposure,
            "exposure_id": &exposure_id,
        }),
    )
}

pub fn write_bait_action_near_miss_event(
    runtime: &ProxyRuntime,
    session: &SessionContext,
    request_id: RequestId,
    policy_state: PolicyState,
    bait: &Bait,
    method: &str,
    path: &str,
) -> io::Result<bool> {
    let prior_same_bait_exposure = bait_action_exposure_id(runtime, session, &bait.id)?.is_some();
    write_bait_action_observed_event_with_exposure(
        runtime,
        session,
        request_id,
        policy_state,
        BaitActionObservation {
            bait,
            method,
            path,
            exposure_id: None,
            prior_same_bait_exposure,
            header_value_mint_status: bait
                .header_value_mint_audit()
                .map(|_| BaitHeaderValueMintStatus::SessionValueMismatch),
        },
    )?;

    Ok(prior_same_bait_exposure)
}

/// How a request matched a configured unsafe bait action shape.
pub enum UnsafeBaitActionMatch {
    /// The request presented the expected proof header; the value may be
    /// wrong, malformed, or mint-mismatched. Produces an explicit near-miss
    /// observation as the rejection outcome.
    HeaderPresent(Box<BaitActionMatch>),
    /// Only the method/path shape matched; no proof material was presented.
    /// Stays unattributed (no bait action observation) so blind write probes
    /// keep their recon-only evidence meaning.
    ShapeOnly(Box<BaitActionMatch>),
}

impl UnsafeBaitActionMatch {
    pub fn bait(&self) -> &Bait {
        match self {
            Self::HeaderPresent(matched) | Self::ShapeOnly(matched) => &matched.bait,
        }
    }
}

/// Classify a request against the unsafe bait action shapes in the active
/// profile. Proof presence selects the evidence treatment; neither arm may
/// reach the protected upstream.
pub fn classify_unsafe_bait_action<'h, I>(
    runtime: &ProxyRuntime,
    method: &str,
    path: &str,
    headers: I,
) -> Option<UnsafeBaitActionMatch>
where
    I: IntoIterator<Item = (&'h str, &'h str)>,
{
    let headers: Vec<(&str, &str)> = headers.into_iter().collect();
    if let Some(matched) =
        runtime
            .bait_registry
            .match_action_shape(method, path, headers.iter().copied())
    {
        return Some(UnsafeBaitActionMatch::HeaderPresent(Box::new(matched)));
    }

    runtime
        .bait_registry
        .match_unsafe_action_shape(method, path)
        .map(|matched| UnsafeBaitActionMatch::ShapeOnly(Box::new(matched)))
}

pub fn bait_action_synthetic_response() -> HttpResponse {
    surface_response_to_http(surface_text_response(202, "accepted\n"))
}

pub fn surface_header_pairs(headers: &[SurfaceHeader]) -> impl Iterator<Item = (&str, &str)> {
    headers
        .iter()
        .map(|header| (header.name.as_str(), header.value.as_str()))
}

pub fn header_pairs(headers: &[HttpHeader]) -> impl Iterator<Item = (&str, &str)> {
    headers
        .iter()
        .map(|header| (header.name.as_str(), header.value.as_str()))
}

pub fn surface_request_meta(request: &HttpRequest, path: &str) -> SurfaceRequestMeta {
    SurfaceRequestMeta::new(
        request.method.clone(),
        path.to_string(),
        surface_headers(&request.headers),
        request.body.len(),
    )
}

pub fn surface_response_meta(response: &HttpResponse, path: &str) -> SurfaceResponseMeta {
    SurfaceResponseMeta::for_surface(
        response.status,
        path.to_string(),
        surface_headers(&response.headers),
        response.body.len(),
    )
}

pub fn surface_headers(headers: &[HttpHeader]) -> Vec<SurfaceHeader> {
    headers
        .iter()
        .map(|header| SurfaceHeader::new(header.name.clone(), header.value.clone()))
        .collect()
}

pub fn direct_surface_response(action: SurfaceAction) -> Option<HttpResponse> {
    match action {
        SurfaceAction::EidolonOwned { response }
        | SurfaceAction::ControlledReality { response, .. }
        | SurfaceAction::RateLimited { response, .. } => Some(surface_response_to_http(response)),
        SurfaceAction::ProtectedUpstream | SurfaceAction::RewrittenUpstream { .. } => None,
    }
}

pub fn direct_surface_decision(
    policy_state: PolicyState,
    action: &SurfaceAction,
    default_reason: String,
) -> policy::PolicyDecision {
    match action {
        SurfaceAction::ProtectedUpstream => {
            policy::PolicyDecision::protected_upstream(policy_state, default_reason)
        }
        SurfaceAction::EidolonOwned { .. } => {
            let reason = if policy_state == PolicyState::Blocked {
                default_reason
            } else {
                "surface controller served eidolon-owned response".to_string()
            };
            policy::PolicyDecision::new(policy_state, RoutingDecision::EidolonOwned, reason)
        }
        SurfaceAction::ControlledReality { reason, .. } => policy::PolicyDecision::new(
            policy_state,
            RoutingDecision::ControlledReality,
            reason.clone(),
        ),
        SurfaceAction::RateLimited { reason, .. } => {
            policy::PolicyDecision::new(policy_state, RoutingDecision::RateLimited, reason.clone())
        }
        SurfaceAction::RewrittenUpstream { .. } => policy::PolicyDecision::new(
            policy_state,
            RoutingDecision::RewrittenUpstream,
            "surface controller requested upstream response rewrite",
        ),
    }
}

pub fn surface_text_response(status: u16, body: impl Into<Vec<u8>>) -> SurfaceResponse {
    SurfaceResponse::new(
        status,
        vec![SurfaceHeader::new(
            "Content-Type",
            "text/plain; charset=utf-8",
        )],
        body,
    )
}

pub fn surface_response_to_http(response: SurfaceResponse) -> HttpResponse {
    HttpResponse {
        version: "HTTP/1.1".to_string(),
        status: response.status,
        reason: reason_phrase(response.status).to_string(),
        headers: response
            .headers
            .into_iter()
            .map(|header| HttpHeader {
                name: header.name,
                value: header.value,
            })
            .collect(),
        body: response.body,
    }
}

pub fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Unknown Status",
    }
}

pub fn normalized_event_path(request: &HttpRequest) -> io::Result<String> {
    Ok(normalize_request_target(&request.target)?.to_string())
}

pub fn event_discovery_recon_score(
    score: policy::DiscoveryReconAggregationScore,
    threshold: u8,
) -> DiscoveryReconScore {
    if score.total == 0 {
        return DiscoveryReconScore::default();
    }

    DiscoveryReconScore {
        repeated_discovery_score: score.repeated_discovery_score,
        query_score: score.query_score,
        legacy_openapi_query_score: score.legacy_openapi_query_score,
        linked_bait_surface_score: score.linked_bait_surface_score,
        linked_bait_class_fanout_bonus: score.linked_bait_class_fanout_bonus,
        decoy_write_probe_score: score.decoy_write_probe_score,
        decoy_write_probe_path_fanout_bonus: score.decoy_write_probe_path_fanout_bonus,
        detection_score: score.detection_score,
        total: score.total,
        threshold,
    }
}

pub fn request_seen_event(
    request: &HttpRequest,
    path: &str,
    session: &SessionContext,
    request_id: RequestId,
    decision: &policy::PolicyDecision,
    discovery_recon_score: policy::DiscoveryReconAggregationScore,
    discovery_recon_threshold: u8,
) -> Event {
    Event::new(
        session.session_id,
        EventSource::Proxy,
        decision.policy_state,
        EventKind::RequestSeen {
            method: request.method.clone(),
            path: redacted_event_target(path),
            safe_headers: safe_header_observations(&request.headers),
            ingress_identity: session.ingress_identity.clone(),
            authenticated_ingress_rule_rejection: session
                .authenticated_ingress_rule_rejection
                .clone(),
            local_ingress_trust_scope_rejection: session
                .local_ingress_trust_scope_rejection
                .clone(),
            trusted_ingress_soften_match: session.trusted_ingress_soften_match.clone(),
            ingress_signals: session.ingress_signals.clone(),
            discovery_recon_score: event_discovery_recon_score(
                discovery_recon_score,
                discovery_recon_threshold,
            ),
            routing_decision: decision.routing_decision,
        },
    )
    .with_request_id(request_id)
}

pub fn write_request_and_policy_events(
    runtime: &ProxyRuntime,
    request_event: &Event,
    request_id: RequestId,
    decision: &policy::PolicyDecision,
    intervention_mode: InterventionMode,
    surface_requested_intervention: bool,
) -> io::Result<()> {
    write_event(&runtime.event_log, request_event)?;

    if intervention_mode == InterventionMode::Disabled
        || surface_requested_intervention
        || decision.routing_decision != RoutingDecision::ProtectedUpstream
    {
        write_event(
            &runtime.event_log,
            &policy::policy_intervention_event(request_event.session_id, request_id, decision),
        )?;
    }

    Ok(())
}

pub fn safe_header_observations(headers: &[HttpHeader]) -> Vec<SafeHeaderObservation> {
    SAFE_HEADER_NAMES
        .iter()
        .map(|name| SafeHeaderObservation {
            name: (*name).to_string(),
            present: headers
                .iter()
                .any(|header| header.name.eq_ignore_ascii_case(name)),
        })
        .collect()
}

pub fn apply_response_headers(response: &mut HttpResponse, session: &SessionContext) {
    let connection_nominated_headers: Vec<String> = response
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("connection"))
        .flat_map(|header| header.value.split(','))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect();

    for name in connection_nominated_headers {
        response.remove_header(&name);
    }

    for name in [
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
    ] {
        response.remove_header(name);
    }

    response.set_header("Connection", "close");
    response.set_header("Content-Length", response.body.len().to_string());

    if let Some(set_cookie) = session.set_cookie_value() {
        response.append_header(session::SET_COOKIE_HEADER_NAME, set_cookie);
    }
}

pub fn write_event(log: &Arc<Mutex<FileEventLogWriter>>, event: &Event) -> io::Result<()> {
    let mut log = log
        .lock()
        .map_err(|_| io::Error::other("event log lock poisoned"))?;
    log.write_event(event)
}

pub fn effective_session_context(
    runtime: &ProxyRuntime,
    request: &HttpRequest,
    surface_request: &SurfaceRequestMeta,
    client_peer_ip: Option<IpAddr>,
    request_id: RequestId,
) -> io::Result<SessionContext> {
    let headers: Vec<(&str, &str)> = header_pairs(&request.headers).collect();
    let request_host = effective_request_host(request);
    let now_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    let mut session = {
        let mut authority = runtime
            .session_authority
            .lock()
            .map_err(|_| io::Error::other("session authority lock poisoned"))?;
        session::derive_session_from_headers(
            &mut authority,
            headers.iter().copied(),
            client_peer_ip,
            now_unix_secs,
        )
    };
    write_debug(
        runtime,
        "session_resolved",
        Some(session.session_id),
        json!({
            "request_id": request_id.0,
            "session_source": match session.source {
                session::SessionSource::Cookie => "cookie",
                session::SessionSource::Generated => "generated",
            },
            "cookie_outcome": session.cookie_outcome.as_str(),
            "key_status": session.key_status.map(|status| status.as_str()),
            "presented_key_version": session.presented_key_version,
            "active_key_version": session.active_key_version,
            "continuity_outcome": session.continuity_outcome.as_str(),
            "enforcement_floor": session.enforcement_floor,
        }),
    )?;
    session.ingress_identity = session::authenticated_ingress_identity_from_headers(
        headers.iter().copied(),
        runtime.ingress_transport_auth_secret.as_deref(),
    );
    session.ingress_signals = session::authenticated_ingress_advisory_signals_from_headers(
        headers.iter().copied(),
        runtime.ingress_transport_auth_secret.as_deref(),
    );
    let local_trust_evaluation = runtime.ingress_identity_resolver.evaluate(
        &request.method,
        &surface_request.path,
        request_host.as_deref(),
        client_peer_ip,
        headers.iter().copied(),
    );
    session.local_ingress_trust_scope_rejection = local_trust_evaluation.scope_rejection;
    let local_trust = local_trust_evaluation.resolved;
    let authenticated_trust_evaluation = runtime.ingress_identity_resolver.evaluate_authenticated(
        &session.ingress_identity,
        &session.ingress_signals,
        &request.method,
        &surface_request.path,
    );
    session.authenticated_ingress_rule_rejection =
        authenticated_trust_evaluation.rule_rejection.clone();
    let authenticated_trust = authenticated_trust_evaluation.resolved;
    if runtime
        .ingress_identity_resolver
        .has_authenticated_entries()
        && authenticated_trust.is_none()
        && ingress_identity::requires_authenticated_rule(&session.ingress_identity)
    {
        session.ingress_identity =
            ingress_identity::downgrade_to_weakly_asserted(session.ingress_identity.clone());
    }
    let merged_identity = ingress_identity::merge_ingress_identity(
        session.ingress_identity.clone(),
        local_trust.as_ref().map(|trust| trust.identity.clone()),
    );
    session.trusted_ingress_soften_match = authenticated_trust
        .as_ref()
        .and_then(|trust| {
            trusted_ingress_soften_match(trust, &merged_identity, &surface_request.path)
        })
        .or_else(|| {
            local_trust.as_ref().and_then(|trust| {
                trusted_ingress_soften_match(trust, &merged_identity, &surface_request.path)
            })
        });
    session.trusted_bait_soften_path_prefixes = session
        .trusted_ingress_soften_match
        .as_ref()
        .map(|scope| scope.bait_soften_path_prefixes.clone());
    session.ingress_identity = merged_identity;

    Ok(session)
}

pub fn trusted_ingress_soften_match(
    trust: &ingress_identity::ResolvedIngressTrust,
    merged_identity: &eidolon_core::IngressIdentity,
    request_path: &str,
) -> Option<eidolon_core::TrustedIngressSoftenMatch> {
    if merged_identity != &trust.identity {
        return None;
    }

    let bait_soften_path_prefixes = trust.bait_soften_path_prefixes.clone()?;
    Some(eidolon_core::TrustedIngressSoftenMatch {
        label: trust.identity.label.clone(),
        source: trust.identity.source,
        trust_tier: trust.identity.trust_tier,
        methods: trust.methods.clone(),
        path_prefixes: trust.path_prefixes.clone(),
        request_path_softened: bait_soften_path_prefixes
            .iter()
            .any(|prefix| request_path.starts_with(prefix)),
        bait_soften_path_prefixes,
        user_agent_substrings: trust.user_agent_substrings.clone().unwrap_or_default(),
        hosts: trust.hosts.clone().unwrap_or_default(),
        source_cidrs: trust.source_cidrs.clone().unwrap_or_default(),
        required_header_names: trust.required_header_names.clone(),
        verified_categories: trust.verified_categories.clone(),
    })
}

pub fn maybe_soften_surface_action_for_trusted_ingress(
    trusted_bait_soften_path_prefixes: &[String],
    session: &SessionContext,
    policy_state: PolicyState,
    surface_request: &SurfaceRequestMeta,
    surface_action: SurfaceAction,
) -> (SurfaceAction, Option<String>) {
    if !matches!(policy_state, PolicyState::Normal | PolicyState::Observe) {
        return (surface_action, None);
    }
    if surface_request.method != "GET" {
        return (surface_action, None);
    }
    if !ingress_identity::softens_bait_surface_exposure(&session.ingress_identity) {
        return (surface_action, None);
    }
    if !trusted_bait_soften_path_prefixes
        .iter()
        .any(|prefix| surface_request.path.starts_with(prefix))
    {
        return (surface_action, None);
    }
    if let Some(local_soften_path_prefixes) = &session.trusted_bait_soften_path_prefixes {
        if !local_soften_path_prefixes
            .iter()
            .any(|prefix| surface_request.path.starts_with(prefix))
        {
            return (surface_action, None);
        }
    }
    if !matches!(
        &surface_action,
        SurfaceAction::EidolonOwned { .. } | SurfaceAction::RewrittenUpstream { .. }
    ) {
        return (surface_action, None);
    }

    (
        SurfaceAction::ProtectedUpstream,
        Some(
            "trusted ingress identity suppressed bait surface intervention before runtime suspicion was established"
                .to_string(),
        ),
    )
}

pub fn write_debug(
    runtime: &ProxyRuntime,
    event: &str,
    session_id: Option<SessionId>,
    fields: Value,
) -> io::Result<()> {
    let Some(log) = &runtime.debug_log else {
        return Ok(());
    };

    let observed_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    let record = json!({
        "schema_version": 1,
        "run_kind": "eidolon_proxy_debug",
        "observed_at_unix_ms": observed_at_unix_ms,
        "event": event,
        "session_id": session_id,
        "fields": fields,
    });

    let mut log = log
        .lock()
        .map_err(|_| io::Error::other("debug log lock poisoned"))?;
    log.write_record(&record)
}

pub fn debug_path(target: &str) -> String {
    let query_index = target.find('?');
    let fragment_index = target.find('#');
    let end = match (query_index, fragment_index) {
        (Some(query), Some(fragment)) => query.min(fragment),
        (Some(query), None) => query,
        (None, Some(fragment)) => fragment,
        (None, None) => target.len(),
    };

    target[..end].to_string()
}

pub fn redacted_event_target(target: &str) -> String {
    let (target_without_fragment, fragment_present) = target
        .split_once('#')
        .map_or((target, false), |(target, _)| (target, true));
    let (path, query) = target_without_fragment
        .split_once('?')
        .map_or((target_without_fragment, None), |(path, query)| {
            (path, Some(query))
        });

    let mut redacted = path.to_string();
    if let Some(query) = query {
        redacted.push('?');
        redacted.push_str(&redacted_event_query(query));
    }
    if fragment_present {
        redacted.push_str("#<redacted>");
    }

    redacted
}

pub fn redacted_event_query(query: &str) -> String {
    let redacted_pairs: Vec<String> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let key = pair.split_once('=').map_or(pair, |(key, _)| key);
            if key.is_empty() {
                "<redacted>".to_string()
            } else {
                format!("{key}=<redacted>")
            }
        })
        .collect();

    if redacted_pairs.is_empty() {
        "<redacted>".to_string()
    } else {
        redacted_pairs.join("&")
    }
}

pub fn debug_query_present(target: &str) -> bool {
    target.contains('?')
}

pub fn debug_target_form(target: &str) -> &'static str {
    if target.starts_with('/') {
        "origin_form"
    } else if target.starts_with("http://") {
        "absolute_http_form"
    } else if target == "*" {
        "asterisk_form"
    } else {
        "unknown"
    }
}

pub fn debug_session_source(source: session::SessionSource) -> &'static str {
    match source {
        session::SessionSource::Cookie => "cookie",
        session::SessionSource::Generated => "generated",
    }
}

pub fn debug_intervention_mode(mode: InterventionMode) -> &'static str {
    match mode {
        InterventionMode::Enabled => "enabled",
        InterventionMode::Disabled => "disabled",
    }
}

pub fn debug_discovery_surface_fanout(fanout: policy::DiscoverySurfaceFanout) -> Value {
    json!({
        "docs_seen": fanout.docs_seen,
        "openapi_seen": fanout.openapi_seen,
        "distinct_surfaces": fanout.distinct_surface_count(),
    })
}

pub fn debug_response_fields(response: &HttpResponse) -> Value {
    json!({
        "status": response.status,
        "body_len": response.body.len(),
        "header_count": response.headers.len(),
        "set_cookie": response
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case(session::SET_COOKIE_HEADER_NAME)),
    })
}

pub fn debug_surface_action(action: &SurfaceAction) -> Value {
    match action {
        SurfaceAction::ProtectedUpstream => json!({
            "type": "protected_upstream",
        }),
        SurfaceAction::RewrittenUpstream { plan } => json!({
            "type": "rewritten_upstream",
            "plan": debug_rewrite_plan(plan),
        }),
        SurfaceAction::EidolonOwned { response } => json!({
            "type": "eidolon_owned",
            "response_status": response.status,
            "response_body_len": response.body.len(),
            "response_header_count": response.headers.len(),
        }),
        SurfaceAction::ControlledReality { reason, response } => json!({
            "type": "controlled_reality",
            "reason": reason,
            "response_status": response.status,
            "response_body_len": response.body.len(),
            "response_header_count": response.headers.len(),
        }),
        SurfaceAction::RateLimited { reason, response } => json!({
            "type": "rate_limited",
            "reason": reason,
            "response_status": response.status,
            "response_body_len": response.body.len(),
            "response_header_count": response.headers.len(),
        }),
    }
}

pub fn debug_rewrite_plan(plan: &RewritePlan) -> &'static str {
    match &plan.operation {
        Some(operation) if operation.is_empty() => "empty",
        Some(crate::surface::RewriteOperation::Html(_)) => "html",
        Some(crate::surface::RewriteOperation::RobotsTxt(_)) => "robots_txt",
        Some(crate::surface::RewriteOperation::OpenApiPaths(_)) => "openapi_paths",
        Some(crate::surface::RewriteOperation::JsonFields(_)) => "json_fields",
        None => "none",
    }
}

pub fn debug_rewrite_disposition(disposition: crate::surface::RewriteDisposition) -> &'static str {
    match disposition {
        crate::surface::RewriteDisposition::Unchanged => "unchanged",
        crate::surface::RewriteDisposition::Rewritten => "rewritten",
        crate::surface::RewriteDisposition::Refused => "refused",
    }
}

pub fn intervention_mode_from_control_file(path: &Path) -> InterventionMode {
    match fs::read_to_string(path) {
        Ok(value) if intervention_control_disables(&value) => InterventionMode::Disabled,
        Ok(_) => InterventionMode::Enabled,
        Err(error) if error.kind() == io::ErrorKind::NotFound => InterventionMode::Enabled,
        Err(error) => {
            eprintln!(
                "intervention control file `{}` could not be read; disabling interventions: {error}",
                path.display()
            );
            InterventionMode::Disabled
        }
    }
}

pub fn intervention_control_disables(value: &str) -> bool {
    let value = value.trim();
    value.eq_ignore_ascii_case("disabled")
        || value.eq_ignore_ascii_case("disable")
        || value.eq_ignore_ascii_case("off")
        || value == "0"
}
