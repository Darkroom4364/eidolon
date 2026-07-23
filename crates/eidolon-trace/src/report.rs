use std::fmt::Write;

use eidolon_core::{
    BaitHeaderValueMintAudit, BaitHeaderValueMintStatus,
    EdgeAuthenticatedIngressRuleRejectionHistory, EdgeBaitHeaderValueMintAudit, EdgeEvidenceRef,
    EdgeLocalIngressTrustScopeRejectionHistory, EdgeObservedBaitHeaderValueMint,
    EdgePolicySnapshot, EdgeRecommendation, EdgeRecommendedAction, EdgeRequestLinkage,
    EdgeRequestRef, EdgeTrustedIngressSoftenHistory, EidolonEdgeDecisionExport, EventKind,
    IngressAdvisorySignals, PolicyState, PostContainmentPersistenceKind,
    PreContainmentPersistenceClass, PreContainmentPersistenceKind, RoutingDecision,
    POST_CONTAINMENT_PERSISTENCE_REASON_FAMILY, PRE_CONTAINMENT_PERSISTENCE_REASON_FAMILY,
    TRUSTED_INGRESS_CONTRACT_VERSION,
};

use crate::evidence::{trace_metric_summary_for_timeline, ProofOutcome};
use crate::{
    evidence_bundle_for_timeline, BaitActionEvidence, BaitExposureEvidence, EvidenceBundle,
    SessionTimeline, TimelineEvent, TimelineEventRef,
};

pub fn render_markdown_report(timeline: &SessionTimeline) -> String {
    let bundle = evidence_bundle_for_timeline(timeline);
    render_evidence_markdown(timeline, &bundle)
}

pub fn render_evidence_markdown(timeline: &SessionTimeline, bundle: &EvidenceBundle) -> String {
    let mut report = String::new();

    push_line(&mut report, format_args!("# Eidolon Trace Report"));
    report.push('\n');
    push_line(
        &mut report,
        format_args!("- Session: `{}`", bundle.session_id.0),
    );
    push_line(
        &mut report,
        format_args!("- Score: `{}`", bundle.score.points),
    );
    push_line(
        &mut report,
        format_args!(
            "- Confidence: `{}`",
            snake_case_debug(&bundle.score.confidence)
        ),
    );
    if let Some(policy_state) = bundle.policy_state {
        push_line(
            &mut report,
            format_args!(
                "- Current policy state: `{}`",
                snake_case_debug(&policy_state)
            ),
        );
    }
    push_line(
        &mut report,
        format_args!(
            "- Safety note: this report is behavioral evidence from the owned lab trace. It is not proof of AI identity and does not include request bodies, secret header values, or raw query values."
        ),
    );
    if let Some(summary) = latest_ingress_signal_summary(timeline) {
        push_line(
            &mut report,
            format_args!("- Ingress advisory signals: `{}`", summary),
        );
    }

    render_metric_summary(timeline, bundle, &mut report);

    push_line(&mut report, format_args!("\n## Score Reasons"));
    if bundle.score.reasons.is_empty() {
        push_line(&mut report, format_args!("- No score reasons recorded."));
    } else {
        for reason in &bundle.score.reasons {
            push_line(&mut report, format_args!("- {}", markdown_text(reason)));
        }
    }

    push_line(&mut report, format_args!("\n## Bait Chain"));
    if bundle.matched_actions.is_empty() {
        push_line(
            &mut report,
            format_args!("- No confirmed bait exposure to action chain."),
        );
    } else {
        for action in &bundle.matched_actions {
            if let Some(exposure) = action
                .matched_exposure
                .and_then(|event_ref| exposure_by_ref(bundle, event_ref))
            {
                push_line(
                    &mut report,
                    format_args!(
                        "- Exposure `{}` on `{}` at line `{}` matched action `{}` `{}` at line `{}`.",
                        inline_code(&exposure.exposure_id.0),
                        inline_code(&report_target(&exposure.surface)),
                        exposure.event_ref.line_number,
                        inline_code(&action.method),
                        inline_code(&report_target(&action.path)),
                        action.event_ref.line_number
                    ),
                );
            }
        }
    }

    if !bundle.unmatched_actions.is_empty() {
        push_line(
            &mut report,
            format_args!("\n## Unconfirmed Bait-Shaped Actions"),
        );
        for action in &bundle.unmatched_actions {
            push_line(
                &mut report,
                format_args!(
                    "- `{}` `{}` for bait `{}` at line `{}`: {}.",
                    inline_code(&action.method),
                    inline_code(&report_target(&action.path)),
                    inline_code(&action.bait_id.0),
                    action.event_ref.line_number,
                    unconfirmed_action_reason(action)
                ),
            );
        }
    }

    push_line(&mut report, format_args!("\n## Policy Actions"));
    if bundle.policy_events.is_empty() {
        push_line(
            &mut report,
            format_args!("- No policy action events recorded."),
        );
    } else {
        push_line(
            &mut report,
            format_args!("| Line | Kind | Policy State | Decision | Status | Reason |"),
        );
        push_line(
            &mut report,
            format_args!("| --- | --- | --- | --- | --- | --- |"),
        );
        for event in &bundle.policy_events {
            push_line(
                &mut report,
                format_args!(
                    "| {} | `{}` | `{}` | {} | {} | {} |",
                    event.event_ref.line_number,
                    snake_case_debug(&event.kind),
                    snake_case_debug(&event.policy_state),
                    optional_decision(event.routing_decision),
                    optional_status(event.status),
                    optional_reason(event.reason.as_deref())
                ),
            );
        }
    }

    report.push_str(&render_replay_view(timeline, bundle));

    report
}

fn render_metric_summary(timeline: &SessionTimeline, bundle: &EvidenceBundle, report: &mut String) {
    let summary = trace_metric_summary_for_timeline(timeline, bundle);

    push_line(report, format_args!("\n## Metrics Summary"));
    push_line(report, format_args!("| Metric | Value |"));
    push_line(report, format_args!("| --- | --- |"));
    push_line(
        report,
        format_args!(
            "| `time_to_first_bait_action_seconds` | {} |",
            optional_seconds(summary.time_to_first_bait_action_seconds)
        ),
    );
    push_line(
        report,
        format_args!("| `bait_follow_rate` | `{:.3}` |", summary.bait_follow_rate),
    );
    push_line(
        report,
        format_args!(
            "| `trace_confidence_score` | `{}` |",
            summary.trace_confidence_score
        ),
    );
    push_line(
        report,
        format_args!(
            "| `real_surface_requests_after_containment` | {} |",
            optional_usize(summary.real_surface_requests_after_containment)
        ),
    );
    push_line(
        report,
        format_args!(
            "| `controlled_reality_dwell_seconds` | {} |",
            optional_seconds(summary.controlled_reality_dwell_seconds)
        ),
    );
    push_line(
        report,
        format_args!(
            "| `controlled_reality_action_depth` | `{}` |",
            summary.controlled_reality_action_depth
        ),
    );
    push_line(
        report,
        format_args!(
            "| `controlled_reality_branch_count` | `{}` |",
            summary.controlled_reality_branch_count
        ),
    );
}

pub fn render_replay_view(timeline: &SessionTimeline, bundle: &EvidenceBundle) -> String {
    let mut replay = String::new();

    push_line(&mut replay, format_args!("\n## Replay"));
    push_line(
        &mut replay,
        format_args!("| Line | Order | Time | Source | Policy | Event | Summary |"),
    );
    push_line(
        &mut replay,
        format_args!("| --- | --- | --- | --- | --- | --- | --- |"),
    );

    for event in &timeline.events {
        push_line(
            &mut replay,
            format_args!(
                "| {} | {} | `{}` | `{}` | `{}` | `{}` | {} |",
                event.line_number,
                event.file_order,
                event.event.observed_at.to_rfc3339(),
                snake_case_debug(&event.event.source),
                snake_case_debug(&event.event.policy_state),
                event_kind_name(&event.event.kind),
                replay_summary(event, bundle)
            ),
        );
    }

    replay
}

fn push_line(buffer: &mut String, args: std::fmt::Arguments<'_>) {
    let _ = buffer.write_fmt(args);
    buffer.push('\n');
}

pub fn edge_decision_export_for_timeline(
    timeline: &SessionTimeline,
) -> Option<EidolonEdgeDecisionExport> {
    let bundle = evidence_bundle_for_timeline(timeline);
    edge_decision_export_for_evidence(timeline, &bundle)
}

pub fn edge_decision_export_for_evidence(
    timeline: &SessionTimeline,
    bundle: &EvidenceBundle,
) -> Option<EidolonEdgeDecisionExport> {
    let latest_request = timeline.events.iter().rev().find_map(|event| {
        let EventKind::RequestSeen {
            method,
            path,
            ingress_identity,
            authenticated_ingress_rule_rejection,
            local_ingress_trust_scope_rejection,
            trusted_ingress_soften_match,
            ingress_signals,
            discovery_recon_score,
            routing_decision,
            ..
        } = &event.event.kind
        else {
            return None;
        };

        Some((
            event,
            method.clone(),
            report_target(path),
            ingress_identity.clone(),
            authenticated_ingress_rule_rejection.clone(),
            local_ingress_trust_scope_rejection.clone(),
            trusted_ingress_soften_match.clone(),
            ingress_signals.clone(),
            discovery_recon_score.clone(),
            *routing_decision,
        ))
    })?;

    let (
        request_event,
        method,
        path,
        ingress_identity,
        authenticated_ingress_rule_rejection,
        local_ingress_trust_scope_rejection,
        trusted_ingress_soften_match,
        ingress_signals,
        discovery_recon_score,
        request_routing_decision,
    ) = latest_request;
    let linked_request_id = request_event.event.request_id;
    let event_belongs_to_linked_request = |event_ref: &TimelineEventRef| -> bool {
        let Some(linked_request_id) = linked_request_id else {
            return false;
        };
        timeline_event_by_ref(timeline, *event_ref)
            .is_some_and(|event| event.event.request_id == Some(linked_request_id))
    };
    let request_linkage = if linked_request_id.is_some() {
        EdgeRequestLinkage::Linked
    } else {
        EdgeRequestLinkage::UnknownLegacy
    };
    let latest_policy_routing_event = bundle.policy_events.iter().rev().find(|event| {
        event.routing_decision.is_some() && event_belongs_to_linked_request(&event.event_ref)
    });
    let fallback_policy_snapshot_event = latest_policy_routing_event.or(bundle
        .policy_events
        .last()
        .filter(|event| event_belongs_to_linked_request(&event.event_ref)));
    let policy_state = fallback_policy_snapshot_event
        .map(|event| event.policy_state)
        .or(if linked_request_id.is_some() {
            bundle.policy_state
        } else {
            None
        })
        .unwrap_or(request_event.event.policy_state);
    let latest_policy_reason_event = preferred_policy_reason_event(bundle, policy_state)
        .filter(|event| event_belongs_to_linked_request(&event.event_ref));
    let routing_decision = latest_policy_routing_event
        .and_then(|event| event.routing_decision)
        .unwrap_or(request_routing_decision);
    let reason = latest_policy_reason_event
        .and_then(|event| event.reason.clone())
        .unwrap_or_else(|| "latest request routing decision".to_string());
    let latest_request_bait_action = latest_request_bait_action_event(timeline, request_event);
    let edge_recommendation =
        edge_recommendation_for(policy_state, routing_decision, reason.as_str());
    let pre_containment_persistence_class =
        pre_containment_persistence_class_for(policy_state, reason.as_str());
    let pre_containment_persistence_kind =
        pre_containment_persistence_kind_for(policy_state, reason.as_str());
    let post_containment_persistence_kind =
        post_containment_persistence_kind_for(policy_state, reason.as_str());

    Some(EidolonEdgeDecisionExport {
        contract_version: TRUSTED_INGRESS_CONTRACT_VERSION.to_string(),
        observed_at: request_event.event.observed_at,
        session_id: bundle.session_id,
        request: EdgeRequestRef {
            method,
            path,
            request_id: linked_request_id,
        },
        ingress_identity,
        authenticated_ingress_rule_rejection,
        local_ingress_trust_scope_rejection,
        trusted_ingress_soften_match,
        ingress_signals,
        discovery_recon_score,
        policy: EdgePolicySnapshot {
            state: policy_state,
            routing_decision,
            reason,
            pre_containment_persistence_class,
            pre_containment_persistence_kind,
            post_containment_persistence_kind,
        },
        evidence: EdgeEvidenceRef {
            event_schema_version: request_event.event.schema_version,
            event_ids: edge_export_event_ids(
                timeline,
                request_event,
                latest_request_bait_action,
                [latest_policy_reason_event, latest_policy_routing_event],
            ),
            bundle_ref: format!("session:{}", bundle.session_id.0),
            request_linkage,
            authenticated_ingress_rule_rejection_histories:
                edge_authenticated_ingress_rule_rejection_histories(timeline),
            local_ingress_trust_scope_rejection_histories:
                edge_local_ingress_trust_scope_rejection_histories(timeline),
            trusted_ingress_soften_histories: edge_trusted_ingress_soften_histories(timeline),
            bait_header_value_mints: edge_bait_header_value_mints(bundle),
            latest_bait_header_value_mint: latest_request_bait_action
                .and_then(edge_observed_bait_header_value_mint),
        },
        edge_recommendation,
        deployment_context: None,
    })
}

fn edge_authenticated_ingress_rule_rejection_histories(
    timeline: &SessionTimeline,
) -> Vec<EdgeAuthenticatedIngressRuleRejectionHistory> {
    let mut histories: Vec<EdgeAuthenticatedIngressRuleRejectionHistory> = Vec::new();

    for timeline_event in &timeline.events {
        let EventKind::RequestSeen {
            authenticated_ingress_rule_rejection: Some(rejection),
            ..
        } = &timeline_event.event.kind
        else {
            continue;
        };

        if let Some(existing) = histories.iter_mut().find(|history| {
            history.label == rejection.label
                && history.source == rejection.source
                && history.trust_tier == rejection.trust_tier
                && history.not_before == rejection.not_before
                && history.expires_at == rejection.expires_at
                && history.methods == rejection.methods
                && history.path_prefixes == rejection.path_prefixes
                && history.bait_soften_path_prefixes == rejection.bait_soften_path_prefixes
                && history.verified_categories == rejection.verified_categories
        }) {
            if !existing.reasons.contains(&rejection.reason) {
                existing.reasons.push(rejection.reason);
            }
            continue;
        }

        histories.push(EdgeAuthenticatedIngressRuleRejectionHistory {
            label: rejection.label.clone(),
            source: rejection.source,
            trust_tier: rejection.trust_tier,
            not_before: rejection.not_before,
            expires_at: rejection.expires_at,
            methods: rejection.methods.clone(),
            path_prefixes: rejection.path_prefixes.clone(),
            bait_soften_path_prefixes: rejection.bait_soften_path_prefixes.clone(),
            verified_categories: rejection.verified_categories.clone(),
            reasons: vec![rejection.reason],
        });
    }

    histories
}

fn edge_bait_header_value_mints(bundle: &EvidenceBundle) -> Vec<EdgeBaitHeaderValueMintAudit> {
    let mut audits = Vec::new();

    for exposure in &bundle.bait_exposures {
        push_edge_bait_header_value_mint(
            &mut audits,
            &exposure.bait_id,
            exposure.header_value_mint.as_ref(),
        );
    }
    for action in bundle
        .matched_actions
        .iter()
        .chain(bundle.unmatched_actions.iter())
    {
        push_edge_bait_header_value_mint(
            &mut audits,
            &action.bait_id,
            action.header_value_mint.as_ref(),
        );
    }

    audits
}

fn edge_trusted_ingress_soften_histories(
    timeline: &SessionTimeline,
) -> Vec<EdgeTrustedIngressSoftenHistory> {
    let mut histories: Vec<EdgeTrustedIngressSoftenHistory> = Vec::new();

    for timeline_event in &timeline.events {
        let EventKind::RequestSeen {
            trusted_ingress_soften_match: Some(trusted_match),
            ..
        } = &timeline_event.event.kind
        else {
            continue;
        };

        if let Some(existing) = histories.iter_mut().find(|history| {
            history.label == trusted_match.label
                && history.source == trusted_match.source
                && history.trust_tier == trusted_match.trust_tier
                && history.methods == trusted_match.methods
                && history.path_prefixes == trusted_match.path_prefixes
                && history.bait_soften_path_prefixes == trusted_match.bait_soften_path_prefixes
                && history.user_agent_substrings == trusted_match.user_agent_substrings
                && history.hosts == trusted_match.hosts
                && history.source_cidrs == trusted_match.source_cidrs
                && history.required_header_names == trusted_match.required_header_names
                && history.verified_categories == trusted_match.verified_categories
        }) {
            if trusted_match.request_path_softened {
                existing.saw_request_path_softened = true;
            } else {
                existing.saw_request_path_unsoftened = true;
            }
            continue;
        }

        histories.push(EdgeTrustedIngressSoftenHistory {
            label: trusted_match.label.clone(),
            source: trusted_match.source,
            trust_tier: trusted_match.trust_tier,
            methods: trusted_match.methods.clone(),
            path_prefixes: trusted_match.path_prefixes.clone(),
            bait_soften_path_prefixes: trusted_match.bait_soften_path_prefixes.clone(),
            user_agent_substrings: trusted_match.user_agent_substrings.clone(),
            hosts: trusted_match.hosts.clone(),
            source_cidrs: trusted_match.source_cidrs.clone(),
            required_header_names: trusted_match.required_header_names.clone(),
            verified_categories: trusted_match.verified_categories.clone(),
            saw_request_path_softened: trusted_match.request_path_softened,
            saw_request_path_unsoftened: !trusted_match.request_path_softened,
        });
    }

    histories
}

fn edge_local_ingress_trust_scope_rejection_histories(
    timeline: &SessionTimeline,
) -> Vec<EdgeLocalIngressTrustScopeRejectionHistory> {
    let mut histories: Vec<EdgeLocalIngressTrustScopeRejectionHistory> = Vec::new();

    for timeline_event in &timeline.events {
        let EventKind::RequestSeen {
            local_ingress_trust_scope_rejection: Some(rejection),
            ..
        } = &timeline_event.event.kind
        else {
            continue;
        };

        if let Some(existing) = histories.iter_mut().find(|history| {
            history.label == rejection.label
                && history.source == rejection.source
                && history.trust_tier == rejection.trust_tier
                && history.not_before == rejection.not_before
                && history.expires_at == rejection.expires_at
                && history.methods == rejection.methods
                && history.path_prefixes == rejection.path_prefixes
                && history.bait_soften_path_prefixes == rejection.bait_soften_path_prefixes
                && history.user_agent_substrings == rejection.user_agent_substrings
                && history.hosts == rejection.hosts
                && history.source_cidrs == rejection.source_cidrs
                && history.required_header_names == rejection.required_header_names
        }) {
            if !existing.reasons.contains(&rejection.reason) {
                existing.reasons.push(rejection.reason);
            }
            continue;
        }

        histories.push(EdgeLocalIngressTrustScopeRejectionHistory {
            label: rejection.label.clone(),
            source: rejection.source,
            trust_tier: rejection.trust_tier,
            not_before: rejection.not_before,
            expires_at: rejection.expires_at,
            methods: rejection.methods.clone(),
            path_prefixes: rejection.path_prefixes.clone(),
            bait_soften_path_prefixes: rejection.bait_soften_path_prefixes.clone(),
            user_agent_substrings: rejection.user_agent_substrings.clone(),
            hosts: rejection.hosts.clone(),
            source_cidrs: rejection.source_cidrs.clone(),
            required_header_names: rejection.required_header_names.clone(),
            reasons: vec![rejection.reason],
        });
    }

    histories
}

fn push_edge_bait_header_value_mint(
    audits: &mut Vec<EdgeBaitHeaderValueMintAudit>,
    bait_id: &eidolon_core::BaitId,
    mint: Option<&BaitHeaderValueMintAudit>,
) {
    let Some(mint) = mint else {
        return;
    };

    let audit = EdgeBaitHeaderValueMintAudit {
        bait_id: bait_id.clone(),
        header_name: mint.header_name.clone(),
        kind: mint.kind,
        prefix: mint.prefix.clone(),
    };
    if !audits.contains(&audit) {
        audits.push(audit);
    }
}

fn edge_export_event_ids(
    timeline: &SessionTimeline,
    request_event: &TimelineEvent,
    bait_action_event: Option<&TimelineEvent>,
    policy_events: [Option<&crate::PolicyEventEvidence>; 2],
) -> Vec<uuid::Uuid> {
    let mut event_ids = vec![request_event.event.id];

    if let Some(bait_action_event) = bait_action_event {
        if bait_action_event.event.id != request_event.event.id {
            event_ids.push(bait_action_event.event.id);
        }
    }

    for policy_event in policy_events.into_iter().flatten() {
        if let Some(timeline_event) = timeline_event_by_ref(timeline, policy_event.event_ref) {
            if timeline_event.event.id != request_event.event.id
                && !event_ids.contains(&timeline_event.event.id)
            {
                event_ids.push(timeline_event.event.id);
            }
        }
    }

    event_ids
}

fn latest_request_bait_action_event<'a>(
    timeline: &'a SessionTimeline,
    request_event: &TimelineEvent,
) -> Option<&'a TimelineEvent> {
    // Strict causal join: only a bait action carrying this request's explicit
    // id belongs to it. Legacy events without request ids are not joined by
    // window or method/path heuristics (engineering operating policy invariant
    // 5); the caller degrades the export to `unknown_legacy` instead.
    let linked_request_id = request_event.event.request_id?;

    timeline.events.iter().rev().find(|event| {
        event.event.request_id == Some(linked_request_id)
            && matches!(event.event.kind, EventKind::BaitActionObserved { .. })
    })
}

fn edge_observed_bait_header_value_mint(
    event: &TimelineEvent,
) -> Option<EdgeObservedBaitHeaderValueMint> {
    let EventKind::BaitActionObserved {
        bait_id,
        header_value_mint,
        header_value_mint_status,
        ..
    } = &event.event.kind
    else {
        return None;
    };
    let mint = header_value_mint.as_ref()?;
    let status = (*header_value_mint_status)?;

    Some(EdgeObservedBaitHeaderValueMint {
        bait_id: bait_id.clone(),
        header_name: mint.header_name.clone(),
        kind: mint.kind,
        prefix: mint.prefix.clone(),
        status,
    })
}

fn timeline_event_by_ref(
    timeline: &SessionTimeline,
    event_ref: TimelineEventRef,
) -> Option<&TimelineEvent> {
    timeline.events.iter().find(|event| {
        event.file_order == event_ref.file_order && event.line_number == event_ref.line_number
    })
}

fn edge_recommendation_for(
    policy_state: PolicyState,
    routing_decision: RoutingDecision,
    reason: &str,
) -> EdgeRecommendation {
    if reason.contains("trusted ingress identity suppressed bait surface intervention") {
        return EdgeRecommendation {
            action: EdgeRecommendedAction::Allow,
            ttl_seconds: Some(300),
            reason_codes: vec!["trusted_identity".to_string(), "bait_softened".to_string()],
        };
    }

    if matches!(
        policy_state,
        PolicyState::ControlledReality | PolicyState::RateLimited | PolicyState::Blocked
    ) || matches!(
        routing_decision,
        RoutingDecision::ControlledReality
            | RoutingDecision::RateLimited
            | RoutingDecision::EidolonOwned
    ) {
        let mut reason_codes = vec![
            "eidolon_runtime_enforcement".to_string(),
            snake_case_debug(&routing_decision),
        ];
        reason_codes.extend(grouped_enforcement_reason_codes(policy_state, reason));
        return EdgeRecommendation {
            action: EdgeRecommendedAction::PreserveEidolonRouting,
            ttl_seconds: Some(300),
            reason_codes,
        };
    }

    if policy_state == PolicyState::Suspicious {
        return EdgeRecommendation {
            action: EdgeRecommendedAction::Observe,
            ttl_seconds: None,
            reason_codes: vec!["suspicious_session".to_string()],
        };
    }

    EdgeRecommendation {
        action: EdgeRecommendedAction::Observe,
        ttl_seconds: None,
        reason_codes: vec![snake_case_debug(&routing_decision)],
    }
}

fn grouped_enforcement_reason_codes(policy_state: PolicyState, reason: &str) -> Vec<String> {
    if matches!(
        policy_state,
        PolicyState::RateLimited | PolicyState::Blocked
    ) {
        if policy_state == PolicyState::RateLimited {
            if let Some(class) = PreContainmentPersistenceClass::from_reason(reason) {
                return vec![
                    PRE_CONTAINMENT_PERSISTENCE_REASON_FAMILY.to_string(),
                    class.code().to_string(),
                ];
            }
        } else if let Some(kind) = PreContainmentPersistenceKind::from_reason(reason) {
            return vec![
                PRE_CONTAINMENT_PERSISTENCE_REASON_FAMILY.to_string(),
                kind.detail_code().to_string(),
            ];
        }
    } else {
        return Vec::new();
    }

    if let Some(kind) = PostContainmentPersistenceKind::from_reason(reason) {
        return vec![
            POST_CONTAINMENT_PERSISTENCE_REASON_FAMILY.to_string(),
            kind.detail_code().to_string(),
        ];
    }

    Vec::new()
}

fn pre_containment_persistence_class_for(
    policy_state: PolicyState,
    reason: &str,
) -> Option<PreContainmentPersistenceClass> {
    matches!(
        policy_state,
        PolicyState::RateLimited | PolicyState::Blocked
    )
    .then(|| PreContainmentPersistenceClass::from_reason(reason))
    .flatten()
}

fn pre_containment_persistence_kind_for(
    policy_state: PolicyState,
    reason: &str,
) -> Option<PreContainmentPersistenceKind> {
    (policy_state == PolicyState::Blocked)
        .then(|| PreContainmentPersistenceKind::from_reason(reason))
        .flatten()
}

fn post_containment_persistence_kind_for(
    policy_state: PolicyState,
    reason: &str,
) -> Option<PostContainmentPersistenceKind> {
    (policy_state == PolicyState::Blocked)
        .then(|| PostContainmentPersistenceKind::from_reason(reason))
        .flatten()
}

fn preferred_policy_reason_event(
    bundle: &EvidenceBundle,
    policy_state: PolicyState,
) -> Option<&crate::PolicyEventEvidence> {
    if matches!(
        policy_state,
        PolicyState::RateLimited | PolicyState::Blocked
    ) {
        if let Some(event) = bundle.policy_events.iter().rev().find(|event| {
            let Some(reason) = event.reason.as_deref() else {
                return false;
            };

            match policy_state {
                PolicyState::RateLimited => {
                    PreContainmentPersistenceClass::from_reason(reason).is_some()
                }
                PolicyState::Blocked => {
                    PreContainmentPersistenceKind::from_reason(reason).is_some()
                        || PostContainmentPersistenceKind::from_reason(reason).is_some()
                }
                _ => false,
            }
        }) {
            return Some(event);
        }
    }

    bundle
        .policy_events
        .iter()
        .rev()
        .find(|event| event.reason.is_some())
}

fn latest_ingress_signal_summary(timeline: &SessionTimeline) -> Option<String> {
    let signals = timeline.events.iter().rev().find_map(|event| {
        let EventKind::RequestSeen {
            ingress_signals, ..
        } = &event.event.kind
        else {
            return None;
        };

        (!ingress_signals.is_empty()).then_some(ingress_signals)
    })?;

    ingress_signal_summary(signals)
}

fn ingress_signal_summary(signals: &IngressAdvisorySignals) -> Option<String> {
    let mut parts = Vec::new();
    if signals.verification_strength != Default::default() {
        parts.push(format!(
            "verification={}",
            snake_case_debug(&signals.verification_strength)
        ));
    }
    if signals.actor_kind != Default::default() {
        parts.push(format!("actor={}", snake_case_debug(&signals.actor_kind)));
    }
    if let Some(category) = &signals.verified_category {
        parts.push(format!("category={category}"));
    }
    if let Some(attestation_ref) = &signals.attestation_ref {
        parts.push(format!("attestation_ref={attestation_ref}"));
    }
    if let Some(vendor_score) = signals.vendor_score {
        let mut value = format!("vendor_score={vendor_score}");
        if let Some(kind) = &signals.vendor_score_kind {
            value.push_str(&format!(" kind={kind}"));
        }
        if let Some(scale) = &signals.vendor_score_scale {
            value.push_str(&format!(" scale={scale}"));
        }
        parts.push(value);
    }
    if !signals.detection_ids.is_empty() {
        parts.push(format!("detection_ids={}", signals.detection_ids.join(",")));
    }
    if let Some(edge_action) = signals.edge_action {
        parts.push(format!("edge_hint={}", snake_case_debug(&edge_action)));
    }

    (!parts.is_empty()).then(|| parts.join("; "))
}

fn replay_summary(event: &TimelineEvent, bundle: &EvidenceBundle) -> String {
    match &event.event.kind {
        EventKind::RequestSeen {
            method,
            path,
            safe_headers,
            routing_decision,
            ..
        } => {
            let present_headers: Vec<&str> = safe_headers
                .iter()
                .filter(|header| header.present)
                .map(|header| header.name.as_str())
                .collect();
            let headers = if present_headers.is_empty() {
                "safe headers: none".to_string()
            } else {
                format!("safe headers present: {}", present_headers.join(", "))
            };
            format!(
                "`{}` `{}` routed `{}`; {}",
                inline_code(method),
                inline_code(&report_target(path)),
                snake_case_debug(routing_decision),
                markdown_text(&headers)
            )
        }
        EventKind::ResponseServed {
            status,
            routing_decision,
        } => format!(
            "served status `{status}` with routing `{}`",
            snake_case_debug(routing_decision)
        ),
        EventKind::BaitExposed {
            bait_id,
            exposure_id,
            surface,
            header_value_mint,
        } => format!(
            "exposed bait `{}` as exposure `{}` on surface `{}`{}",
            inline_code(&bait_id.0),
            inline_code(&exposure_id.0),
            inline_code(&report_target(surface)),
            bait_header_value_mint_summary(header_value_mint.as_ref(), None)
        ),
        EventKind::BaitActionObserved {
            bait_id,
            exposure_id,
            method,
            path,
            header_value_mint,
            header_value_mint_status,
        } => {
            let event_ref = event.event_ref();
            let status = if bundle
                .matched_actions
                .iter()
                .any(|action| action.event_ref == event_ref)
            {
                "confirmed match"
            } else {
                "unconfirmed bait-shaped action"
            };
            format!(
                "{}: `{}` `{}` for bait `{}` with exposure `{}`{}",
                status,
                inline_code(method),
                inline_code(&report_target(path)),
                inline_code(&bait_id.0),
                inline_code(exposure_id.as_ref().map_or("none", |id| id.0.as_str())),
                bait_header_value_mint_summary(
                    header_value_mint.as_ref(),
                    *header_value_mint_status,
                )
            )
        }
        EventKind::PolicyChanged { from, to, reason } => format!(
            "policy changed from `{}` to `{}`: {}",
            snake_case_debug(from),
            snake_case_debug(to),
            markdown_text(reason)
        ),
        EventKind::PolicyDecision {
            routing_decision,
            reason,
        } => format!(
            "policy decision `{}`: {}",
            snake_case_debug(routing_decision),
            markdown_text(reason)
        ),
        EventKind::ControlledRealityEntered { reason } => {
            format!("controlled reality entered: {}", markdown_text(reason))
        }
        EventKind::RateLimitApplied { reason } => {
            format!("rate limit applied: {}", markdown_text(reason))
        }
        EventKind::RealityEscapeAttempt {
            method,
            path,
            routing_decision,
            reason,
        } => format!(
            "reality escape attempt `{}` `{}` routed `{}`: {}",
            inline_code(method),
            inline_code(&report_target(path)),
            snake_case_debug(routing_decision),
            markdown_text(reason)
        ),
    }
}

fn exposure_by_ref(
    bundle: &EvidenceBundle,
    event_ref: TimelineEventRef,
) -> Option<&BaitExposureEvidence> {
    bundle
        .bait_exposures
        .iter()
        .find(|exposure| exposure.event_ref == event_ref)
}

fn unconfirmed_action_reason(action: &BaitActionEvidence) -> &'static str {
    match action.proof_outcome() {
        ProofOutcome::Rejected => match action.header_value_mint_status {
            Some(BaitHeaderValueMintStatus::ReplaySeen) => {
                "proof rejected as a replay; excluded from confirmed evidence"
            }
            Some(BaitHeaderValueMintStatus::ExpiredSessionValue) => {
                "proof rejected as expired; excluded from confirmed evidence"
            }
            Some(BaitHeaderValueMintStatus::SessionValueMismatch) => {
                "proof rejected as mismatched; excluded from confirmed evidence"
            }
            Some(BaitHeaderValueMintStatus::ReplayStateCapacityExceeded) => {
                "proof rejected because replay capacity was exceeded; excluded from confirmed evidence"
            }
            Some(BaitHeaderValueMintStatus::ReplayStateUnavailable) => {
                "proof rejected because durable replay state was unavailable; excluded from confirmed evidence"
            }
            Some(BaitHeaderValueMintStatus::MissingSessionValue) => {
                "proof rejected because the session proof was missing; excluded from confirmed evidence"
            }
            Some(BaitHeaderValueMintStatus::MalformedSessionValue) => {
                "proof rejected as malformed; excluded from confirmed evidence"
            }
            Some(BaitHeaderValueMintStatus::MatchedSessionValue) | None => {
                "proof rejected; excluded from confirmed evidence"
            }
        },
        ProofOutcome::Unknown => {
            if action.matched_exposure.is_some() {
                "exposure matched, but the proof validity is unverifiable (no status recorded)"
            } else {
                "no status recorded for a mint-enabled bait proof; not counted as confirmed"
            }
        }
        ProofOutcome::Accepted => {
            if action.prior_same_bait_exposure.is_some() {
                "same bait was exposed earlier, but the action did not carry the matching exposure identifier"
            } else {
                "no prior matching exposure was recorded for this session"
            }
        }
    }
}

fn bait_header_value_mint_summary(
    mint: Option<&BaitHeaderValueMintAudit>,
    status: Option<BaitHeaderValueMintStatus>,
) -> String {
    let Some(mint) = mint else {
        return String::new();
    };

    let mut summary = format!(
        "; session-minted header `{}` kind `{}` prefix `{}`",
        mint.header_name,
        snake_case_debug(&mint.kind),
        mint.prefix
    );
    if let Some(status) = status {
        summary.push_str(&format!(" status `{}`", snake_case_debug(&status)));
    }
    summary
}

fn optional_decision(decision: Option<RoutingDecision>) -> String {
    decision
        .map(|decision| format!("`{}`", snake_case_debug(&decision)))
        .unwrap_or_else(|| "-".to_string())
}

fn optional_status(status: Option<u16>) -> String {
    status
        .map(|status| format!("`{status}`"))
        .unwrap_or_else(|| "-".to_string())
}

fn optional_reason(reason: Option<&str>) -> String {
    reason
        .map(markdown_text)
        .filter(|reason| !reason.is_empty())
        .unwrap_or_else(|| "-".to_string())
}

fn optional_seconds(seconds: Option<f64>) -> String {
    seconds
        .map(|seconds| format!("`{seconds:.3}`"))
        .unwrap_or_else(|| "`null`".to_string())
}

fn optional_usize(value: Option<usize>) -> String {
    value
        .map(|value| format!("`{value}`"))
        .unwrap_or_else(|| "`null`".to_string())
}

fn event_kind_name(kind: &EventKind) -> &'static str {
    match kind {
        EventKind::RequestSeen { .. } => "request_seen",
        EventKind::ResponseServed { .. } => "response_served",
        EventKind::BaitExposed { .. } => "bait_exposed",
        EventKind::BaitActionObserved { .. } => "bait_action_observed",
        EventKind::PolicyChanged { .. } => "policy_changed",
        EventKind::PolicyDecision { .. } => "policy_decision",
        EventKind::ControlledRealityEntered { .. } => "controlled_reality_entered",
        EventKind::RateLimitApplied { .. } => "rate_limit_applied",
        EventKind::RealityEscapeAttempt { .. } => "reality_escape_attempt",
    }
}

fn report_target(value: &str) -> String {
    let (target_without_fragment, fragment) = value
        .split_once('#')
        .map_or((value, None), |(target, fragment)| (target, Some(fragment)));
    let (path, query) = target_without_fragment
        .split_once('?')
        .map_or((target_without_fragment, None), |(path, query)| {
            (path, Some(query))
        });

    let mut redacted = path.to_string();
    if query.is_some() {
        redacted.push_str("?<redacted>");
    }
    if fragment.is_some() {
        redacted.push_str("#<redacted>");
    }
    redacted
}

fn snake_case_debug(value: &impl std::fmt::Debug) -> String {
    let mut output = String::new();
    for (index, character) in format!("{value:?}").chars().enumerate() {
        if character.is_ascii_uppercase() {
            if index > 0 {
                output.push('_');
            }
            output.push(character.to_ascii_lowercase());
        } else {
            output.push(character);
        }
    }
    output
}

fn inline_code(value: &str) -> String {
    markdown_text(&value.replace('`', "'"))
}

fn markdown_text(value: &str) -> String {
    value.replace('|', "\\|").replace(['\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use chrono::{TimeDelta, TimeZone, Utc};
    use eidolon_core::{
        BaitId, DiscoveryReconScore, EdgeRecommendedAction, Event, EventKind, EventSource,
        ExposureId, IngressActorKind, IngressAdvisorySignals, IngressIdentity,
        IngressIdentitySource, IngressTrustTier, IngressVerificationStrength, PolicyState,
        RequestId, RoutingDecision, SafeHeaderObservation, SessionId,
        TRUSTED_INGRESS_CONTRACT_VERSION,
    };

    use crate::{evidence_bundle_for_timeline, TimelineEvent};

    use super::*;

    fn must_some<T>(value: Option<T>, context: &str) -> T {
        match value {
            Some(value) => value,
            None => panic!("{context}"),
        }
    }

    fn timeline(events: Vec<Event>) -> SessionTimeline {
        let session_id = events[0].session_id;
        SessionTimeline {
            session_id,
            events: events
                .into_iter()
                .enumerate()
                .map(|(index, event)| TimelineEvent {
                    file_order: index,
                    line_number: index + 1,
                    event,
                })
                .collect(),
        }
    }

    fn request(session_id: SessionId) -> Event {
        Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::Observe,
            EventKind::RequestSeen {
                method: "GET".to_string(),
                path: "/docs/legacy-import".to_string(),
                safe_headers: vec![
                    SafeHeaderObservation {
                        name: "authorization".to_string(),
                        present: true,
                    },
                    SafeHeaderObservation {
                        name: "cookie".to_string(),
                        present: true,
                    },
                ],
                ingress_identity: IngressIdentity::default(),
                authenticated_ingress_rule_rejection: None,
                local_ingress_trust_scope_rejection: None,
                trusted_ingress_soften_match: None,
                ingress_signals: Default::default(),
                discovery_recon_score: Default::default(),
                routing_decision: RoutingDecision::EidolonOwned,
            },
        )
    }

    fn request_with_ingress_signals(session_id: SessionId) -> Event {
        Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::Observe,
            EventKind::RequestSeen {
                method: "GET".to_string(),
                path: "/openapi.json".to_string(),
                safe_headers: Vec::new(),
                ingress_identity: IngressIdentity::default(),
                authenticated_ingress_rule_rejection: None,
                local_ingress_trust_scope_rejection: None,
                trusted_ingress_soften_match: None,
                ingress_signals: IngressAdvisorySignals {
                    verification_strength: IngressVerificationStrength::Cryptographic,
                    actor_kind: IngressActorKind::AgenticBrowser,
                    verified_category: Some("AI Assistant".to_string()),
                    attestation_ref: Some("jkt:sha256:ba3e64".to_string()),
                    vendor_score: Some(12),
                    vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                    vendor_score_scale: Some("1-99".to_string()),
                    detection_ids: vec!["3355446".to_string()],
                    edge_action: Some(EdgeRecommendedAction::Allow),
                },
                discovery_recon_score: DiscoveryReconScore {
                    detection_score: 2,
                    query_score: 1,
                    total: 3,
                    threshold: 3,
                    ..DiscoveryReconScore::default()
                },
                routing_decision: RoutingDecision::ProtectedUpstream,
            },
        )
    }

    fn exposure(session_id: SessionId) -> Event {
        Event::new(
            session_id,
            EventSource::SurfaceController,
            PolicyState::Observe,
            EventKind::BaitExposed {
                bait_id: BaitId("rel_2025_04_b7f2".to_string()),
                exposure_id: ExposureId("exp-1".to_string()),
                surface: "/docs/legacy-import".to_string(),
                header_value_mint: None,
            },
        )
    }

    fn action(session_id: SessionId, exposure_id: Option<&str>) -> Event {
        Event::new(
            session_id,
            EventSource::BaitEngine,
            PolicyState::Observe,
            EventKind::BaitActionObserved {
                bait_id: BaitId("rel_2025_04_b7f2".to_string()),
                exposure_id: exposure_id.map(|id| ExposureId(id.to_string())),
                method: "POST".to_string(),
                path: "/api/v2/import/reconcile".to_string(),
                header_value_mint: None,
                header_value_mint_status: None,
            },
        )
    }

    #[test]
    fn report_labels_rejected_linked_action_only_as_rejected() {
        let session_id = SessionId::new();
        let mint_audit = eidolon_core::BaitHeaderValueMintAudit {
            header_name: "X-Trace".to_string(),
            kind: eidolon_core::HeaderValueMintKind::SessionHmacSha256V1,
            prefix: "test".to_string(),
        };
        let minted_exposure = Event::new(
            session_id,
            EventSource::SurfaceController,
            PolicyState::Observe,
            EventKind::BaitExposed {
                bait_id: BaitId("minted-trace".to_string()),
                exposure_id: ExposureId("exp-1".to_string()),
                surface: "/docs/minted-trace".to_string(),
                header_value_mint: Some(mint_audit.clone()),
            },
        );
        let replayed_action = Event::new(
            session_id,
            EventSource::BaitEngine,
            PolicyState::Observe,
            EventKind::BaitActionObserved {
                bait_id: BaitId("minted-trace".to_string()),
                exposure_id: Some(ExposureId("exp-1".to_string())),
                method: "POST".to_string(),
                path: "/api/v2/import/reconcile".to_string(),
                header_value_mint: Some(mint_audit),
                header_value_mint_status: Some(eidolon_core::BaitHeaderValueMintStatus::ReplaySeen),
            },
        );

        let report = render_markdown_report(&timeline(vec![minted_exposure, replayed_action]));

        assert!(report.contains("- No confirmed bait exposure to action chain."));
        assert!(report.contains("proof rejected as a replay; excluded from confirmed evidence"));
        assert!(report.contains("unconfirmed bait-shaped action"));
        assert!(!report.contains("confirmed match"));
    }

    fn policy(session_id: SessionId) -> Event {
        Event::new(
            session_id,
            EventSource::PolicyRouter,
            PolicyState::Observe,
            EventKind::PolicyDecision {
                routing_decision: RoutingDecision::EidolonOwned,
                reason: "bait-derived action intercepted".to_string(),
            },
        )
    }

    fn controlled_reality_entered(session_id: SessionId) -> Event {
        Event::new(
            session_id,
            EventSource::PolicyRouter,
            PolicyState::ControlledReality,
            EventKind::ControlledRealityEntered {
                reason: "confirmed bait-derived action".to_string(),
            },
        )
    }

    fn routed_request(
        session_id: SessionId,
        policy_state: PolicyState,
        routing_decision: RoutingDecision,
    ) -> Event {
        Event::new(
            session_id,
            EventSource::Proxy,
            policy_state,
            EventKind::RequestSeen {
                method: "GET".to_string(),
                path: "/admin/decoy".to_string(),
                safe_headers: Vec::new(),
                ingress_identity: IngressIdentity::default(),
                authenticated_ingress_rule_rejection: None,
                local_ingress_trust_scope_rejection: None,
                trusted_ingress_soften_match: None,
                ingress_signals: Default::default(),
                discovery_recon_score: Default::default(),
                routing_decision,
            },
        )
    }

    fn routed_response(
        session_id: SessionId,
        policy_state: PolicyState,
        routing_decision: RoutingDecision,
    ) -> Event {
        Event::new(
            session_id,
            EventSource::Proxy,
            policy_state,
            EventKind::ResponseServed {
                status: 200,
                routing_decision,
            },
        )
    }

    fn at(mut event: Event, seconds: i64) -> Event {
        event.observed_at = Utc
            .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
            .single()
            .expect("test timestamp should be valid")
            + TimeDelta::seconds(seconds);
        event
    }

    #[test]
    fn report_contains_score_bait_chain_policy_and_safety_note() {
        let session_id = SessionId::new();
        let timeline = timeline(vec![
            request(session_id),
            exposure(session_id),
            action(session_id, Some("exp-1")),
            policy(session_id),
        ]);

        let report = render_markdown_report(&timeline);

        assert!(report.contains("# Eidolon Trace Report"));
        assert!(report.contains("Confidence: `confirmed_bait_derived_chain`"));
        assert!(report.contains("Safety note"));
        assert!(report.contains("Exposure `exp-1`"));
        assert!(report.contains("Policy Actions"));
        assert!(report.contains("bait-derived action intercepted"));
        assert!(report.contains("## Replay"));
    }

    #[test]
    fn report_lists_latest_ingress_advisory_signal_summary() {
        let session_id = SessionId::new();
        let timeline = timeline(vec![request_with_ingress_signals(session_id)]);

        let report = render_markdown_report(&timeline);

        assert!(report.contains("Ingress advisory signals"));
        assert!(report.contains("verification=cryptographic"));
        assert!(report.contains("actor=agentic_browser"));
        assert!(report.contains("vendor_score=12 kind=automation_likelihood_inverse scale=1-99"));
        assert!(report.contains("edge_hint=allow"));
    }

    #[test]
    fn replay_labels_only_exactly_matched_bait_actions_as_confirmed() {
        let session_id = SessionId::new();
        let timeline = timeline(vec![
            exposure(session_id),
            action(session_id, Some("exp-1")),
            action(session_id, None),
        ]);

        let report = render_markdown_report(&timeline);

        assert!(report.contains("confirmed match: `POST` `/api/v2/import/reconcile`"));
        assert!(
            report.contains("unconfirmed bait-shaped action: `POST` `/api/v2/import/reconcile`")
        );
    }

    #[test]
    fn report_contains_metric_summary_for_controlled_reality() {
        let session_id = SessionId::new();
        let timeline = timeline(vec![
            at(exposure(session_id), 0),
            at(action(session_id, Some("exp-1")), 3),
            at(controlled_reality_entered(session_id), 10),
            at(
                routed_request(
                    session_id,
                    PolicyState::ControlledReality,
                    RoutingDecision::ControlledReality,
                ),
                12,
            ),
            at(
                routed_response(
                    session_id,
                    PolicyState::ControlledReality,
                    RoutingDecision::ControlledReality,
                ),
                18,
            ),
            at(
                routed_request(
                    session_id,
                    PolicyState::RateLimited,
                    RoutingDecision::RateLimited,
                ),
                20,
            ),
            at(
                routed_request(
                    session_id,
                    PolicyState::Observe,
                    RoutingDecision::ProtectedUpstream,
                ),
                25,
            ),
        ]);

        let report = render_markdown_report(&timeline);

        assert!(report.contains("## Metrics Summary"));
        assert!(report.contains("| `time_to_first_bait_action_seconds` | `3.000` |"));
        assert!(report.contains("| `bait_follow_rate` | `1.000` |"));
        assert!(report.contains("| `trace_confidence_score` | `85` |"));
        assert!(report.contains("| `real_surface_requests_after_containment` | `1` |"));
        assert!(report.contains("| `controlled_reality_dwell_seconds` | `10.000` |"));
        assert!(report.contains("| `controlled_reality_action_depth` | `2` |"));
        assert!(report.contains("| `controlled_reality_branch_count` | `1` |"));
    }

    #[test]
    fn replay_uses_metadata_without_secret_values_or_bodies() {
        let session_id = SessionId::new();
        let timeline = timeline(vec![request(session_id)]);
        let bundle = evidence_bundle_for_timeline(&timeline);

        let replay = render_replay_view(&timeline, &bundle);

        assert!(replay.contains("safe headers present: authorization, cookie"));
        assert!(!replay.contains("Bearer"));
        assert!(!replay.contains("eidolon_session="));
        assert!(!replay.contains("body"));
    }

    #[test]
    fn report_redacts_query_values_from_paths_and_surfaces() {
        let session_id = SessionId::new();
        let timeline = timeline(vec![
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Observe,
                EventKind::RequestSeen {
                    method: "GET".to_string(),
                    path:
                        "/oauth/callback?code=authcode-secret&state=session-secret#fragment-secret"
                            .to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity::default(),
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: None,
                    trusted_ingress_soften_match: None,
                    ingress_signals: Default::default(),
                    discovery_recon_score: Default::default(),
                    routing_decision: RoutingDecision::ProtectedUpstream,
                },
            ),
            Event::new(
                session_id,
                EventSource::SurfaceController,
                PolicyState::Observe,
                EventKind::BaitExposed {
                    bait_id: BaitId("rel_2025_04_b7f2".to_string()),
                    exposure_id: ExposureId("exp-1".to_string()),
                    surface: "/docs/legacy-import?download_token=surface-secret".to_string(),
                    header_value_mint: None,
                },
            ),
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Observe,
                EventKind::RequestSeen {
                    method: "POST".to_string(),
                    path: "/api/v2/import/reconcile".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity::default(),
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: None,
                    trusted_ingress_soften_match: None,
                    ingress_signals: Default::default(),
                    discovery_recon_score: Default::default(),
                    routing_decision: RoutingDecision::ControlledReality,
                },
            ),
            Event::new(
                session_id,
                EventSource::BaitEngine,
                PolicyState::Observe,
                EventKind::BaitActionObserved {
                    bait_id: BaitId("rel_2025_04_b7f2".to_string()),
                    exposure_id: Some(ExposureId("exp-1".to_string())),
                    method: "POST".to_string(),
                    path: "/api/v2/import/reconcile?api_key=action-secret".to_string(),
                    header_value_mint: None,
                    header_value_mint_status: None,
                },
            ),
        ]);

        let report = render_markdown_report(&timeline);

        assert!(!report.contains("authcode-secret"));
        assert!(!report.contains("session-secret"));
        assert!(!report.contains("fragment-secret"));
        assert!(!report.contains("surface-secret"));
        assert!(!report.contains("action-secret"));
        assert!(report.contains("/oauth/callback?<redacted>#<redacted>"));
        assert!(report.contains("/docs/legacy-import?<redacted>"));
        assert!(report.contains("/api/v2/import/reconcile?<redacted>"));
        assert_eq!(report_target("/docs?sk_live_secret"), "/docs?<redacted>");
        assert_eq!(report_target("/docs?sk_live_secret=x"), "/docs?<redacted>");
    }

    #[test]
    fn edge_export_redacts_the_entire_query_component() {
        let session_id = SessionId::new();
        let mut request = request(session_id);
        let EventKind::RequestSeen { path, .. } = &mut request.kind else {
            panic!("request helper must produce request_seen");
        };
        *path = "/docs?sk_live_secret=x".to_string();
        let timeline = timeline(vec![request]);

        let export = edge_decision_export_for_timeline(&timeline).expect("request should export");

        assert_eq!(export.request.path, "/docs?<redacted>");
    }

    #[test]
    fn report_lists_unconfirmed_bait_shaped_actions() {
        let session_id = SessionId::new();
        let timeline = timeline(vec![exposure(session_id), action(session_id, None)]);

        let report = render_markdown_report(&timeline);

        assert!(report.contains("No confirmed bait exposure to action chain"));
        assert!(report.contains("Unconfirmed Bait-Shaped Actions"));
        assert!(report.contains("did not carry the matching exposure identifier"));
    }

    #[test]
    fn edge_decision_export_uses_allow_for_trusted_bait_softening() {
        let session_id = SessionId::new();
        let rid = RequestId::new();
        let timeline = timeline(vec![
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Observe,
                EventKind::RequestSeen {
                    method: "GET".to_string(),
                    path: "/docs/legacy-import".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity {
                        source: IngressIdentitySource::LocalAllowlist,
                        trust_tier: IngressTrustTier::Allowlisted,
                        label: Some("internal-crawler".to_string()),
                        not_before: None,
                        expires_at: None,
                    },
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: None,
                    trusted_ingress_soften_match: Some(eidolon_core::TrustedIngressSoftenMatch {
                        label: Some("internal-crawler".to_string()),
                        source: IngressIdentitySource::LocalAllowlist,
                        trust_tier: IngressTrustTier::Allowlisted,
                        methods: vec!["GET".to_string()],
                        path_prefixes: vec!["/docs".to_string()],
                        bait_soften_path_prefixes: vec!["/docs".to_string()],
                        user_agent_substrings: vec!["internal-crawler".to_string()],
                        hosts: vec!["127.0.0.1".to_string()],
                        source_cidrs: vec!["127.0.0.1/32".to_string()],
                        required_header_names: vec!["X-Eidolon-Trusted-Actor".to_string()],
                        verified_categories: Vec::new(),
                        request_path_softened: true,
                    }),
                    ingress_signals: IngressAdvisorySignals {
                        verification_strength: IngressVerificationStrength::High,
                        actor_kind: IngressActorKind::Crawler,
                        verified_category: Some("Search Engine".to_string()),
                        attestation_ref: None,
                        vendor_score: Some(12),
                        vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                        vendor_score_scale: Some("1-99".to_string()),
                        detection_ids: vec!["3355446".to_string()],
                        edge_action: Some(EdgeRecommendedAction::Allow),
                    },
                    discovery_recon_score: DiscoveryReconScore {
                        detection_score: 2,
                        query_score: 1,
                        total: 3,
                        threshold: 3,
                        ..DiscoveryReconScore::default()
                    },
                    routing_decision: RoutingDecision::ProtectedUpstream,
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::PolicyRouter,
                PolicyState::Observe,
                EventKind::PolicyDecision {
                    routing_decision: RoutingDecision::ProtectedUpstream,
                    reason: "trusted ingress identity suppressed bait surface intervention before runtime suspicion was established".to_string(),
                },
            )
            .with_request_id(rid),
        ]);

        let export = must_some(
            edge_decision_export_for_timeline(&timeline),
            "edge decision export should exist",
        );

        assert_eq!(export.contract_version, TRUSTED_INGRESS_CONTRACT_VERSION);
        assert_eq!(export.request.path, "/docs/legacy-import");
        assert_eq!(
            export.ingress_identity.label.as_deref(),
            Some("internal-crawler")
        );
        assert_eq!(
            export
                .trusted_ingress_soften_match
                .as_ref()
                .and_then(|scope| scope.label.as_deref()),
            Some("internal-crawler")
        );
        assert_eq!(
            export
                .trusted_ingress_soften_match
                .as_ref()
                .map(|scope| scope.request_path_softened),
            Some(true)
        );
        assert_eq!(export.ingress_signals.vendor_score, Some(12));
        assert_eq!(
            export.ingress_signals.edge_action,
            Some(EdgeRecommendedAction::Allow)
        );
        assert_eq!(export.discovery_recon_score.detection_score, 2);
        assert_eq!(export.discovery_recon_score.query_score, 1);
        assert_eq!(export.discovery_recon_score.total, 3);
        assert_eq!(export.discovery_recon_score.threshold, 3);
        assert_eq!(export.evidence.trusted_ingress_soften_histories.len(), 1);
        assert_eq!(
            export.evidence.trusted_ingress_soften_histories[0]
                .label
                .as_deref(),
            Some("internal-crawler")
        );
        assert!(export.evidence.trusted_ingress_soften_histories[0].saw_request_path_softened);
        assert!(!export.evidence.trusted_ingress_soften_histories[0].saw_request_path_unsoftened);
        assert_eq!(
            export.edge_recommendation.action,
            EdgeRecommendedAction::Allow
        );
        assert_eq!(
            export.edge_recommendation.reason_codes,
            vec!["trusted_identity".to_string(), "bait_softened".to_string()]
        );
    }

    #[test]
    fn edge_decision_export_preserves_eidolon_routing_for_containment() {
        let session_id = SessionId::new();
        let timeline = timeline(vec![
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::ControlledReality,
                EventKind::RequestSeen {
                    method: "POST".to_string(),
                    path: "/api/v2/import/reconcile".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity::default(),
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: None,
                    trusted_ingress_soften_match: None,
                    ingress_signals: Default::default(),
                    discovery_recon_score: Default::default(),
                    routing_decision: RoutingDecision::ControlledReality,
                },
            ),
            Event::new(
                session_id,
                EventSource::PolicyRouter,
                PolicyState::ControlledReality,
                EventKind::ControlledRealityEntered {
                    reason: "confirmed bait-derived action".to_string(),
                },
            ),
        ]);

        let export = must_some(
            edge_decision_export_for_timeline(&timeline),
            "edge decision export should exist",
        );

        assert_eq!(
            export.edge_recommendation.action,
            EdgeRecommendedAction::PreserveEidolonRouting
        );
        assert_eq!(export.policy.state, PolicyState::ControlledReality);
        assert_eq!(
            export.policy.routing_decision,
            RoutingDecision::ControlledReality
        );
        assert!(export
            .edge_recommendation
            .reason_codes
            .contains(&"eidolon_runtime_enforcement".to_string()));
    }

    #[test]
    fn edge_decision_export_preserves_trusted_soften_history_after_containment() {
        let session_id = SessionId::new();
        let rid = RequestId::new();
        let timeline = timeline(vec![
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Observe,
                EventKind::RequestSeen {
                    method: "GET".to_string(),
                    path: "/docs?topic=imports".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity {
                        source: IngressIdentitySource::LocalAllowlist,
                        trust_tier: IngressTrustTier::Allowlisted,
                        label: Some("docs-crawler".to_string()),
                        not_before: None,
                        expires_at: None,
                    },
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: None,
                    trusted_ingress_soften_match: Some(eidolon_core::TrustedIngressSoftenMatch {
                        label: Some("docs-crawler".to_string()),
                        source: IngressIdentitySource::LocalAllowlist,
                        trust_tier: IngressTrustTier::Allowlisted,
                        methods: vec!["GET".to_string()],
                        path_prefixes: vec!["/docs".to_string(), "/openapi.json".to_string()],
                        bait_soften_path_prefixes: vec!["/docs".to_string()],
                        user_agent_substrings: vec!["eidolon-docs-crawler".to_string()],
                        hosts: vec!["127.0.0.1".to_string()],
                        source_cidrs: vec!["127.0.0.1/32".to_string()],
                        required_header_names: vec!["X-Eidolon-Trusted-Actor".to_string()],
                        verified_categories: Vec::new(),
                        request_path_softened: true,
                    }),
                    ingress_signals: Default::default(),
                    discovery_recon_score: DiscoveryReconScore {
                        query_score: 1,
                        total: 1,
                        threshold: 3,
                        ..DiscoveryReconScore::default()
                    },
                    routing_decision: RoutingDecision::ProtectedUpstream,
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Observe,
                EventKind::RequestSeen {
                    method: "GET".to_string(),
                    path: "/openapi.json".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity {
                        source: IngressIdentitySource::LocalAllowlist,
                        trust_tier: IngressTrustTier::Allowlisted,
                        label: Some("docs-crawler".to_string()),
                        not_before: None,
                        expires_at: None,
                    },
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: None,
                    trusted_ingress_soften_match: Some(eidolon_core::TrustedIngressSoftenMatch {
                        label: Some("docs-crawler".to_string()),
                        source: IngressIdentitySource::LocalAllowlist,
                        trust_tier: IngressTrustTier::Allowlisted,
                        methods: vec!["GET".to_string()],
                        path_prefixes: vec!["/docs".to_string(), "/openapi.json".to_string()],
                        bait_soften_path_prefixes: vec!["/docs".to_string()],
                        user_agent_substrings: vec!["eidolon-docs-crawler".to_string()],
                        hosts: vec!["127.0.0.1".to_string()],
                        source_cidrs: vec!["127.0.0.1/32".to_string()],
                        required_header_names: vec!["X-Eidolon-Trusted-Actor".to_string()],
                        verified_categories: Vec::new(),
                        request_path_softened: false,
                    }),
                    ingress_signals: Default::default(),
                    discovery_recon_score: DiscoveryReconScore {
                        repeated_discovery_score: 2,
                        query_score: 1,
                        total: 3,
                        threshold: 3,
                        ..DiscoveryReconScore::default()
                    },
                    routing_decision: RoutingDecision::ProtectedUpstream,
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::PolicyRouter,
                PolicyState::Suspicious,
                EventKind::PolicyChanged {
                    from: PolicyState::Observe,
                    to: PolicyState::Suspicious,
                    reason: "session recon discovery-surface fanout promoted request to suspicious"
                        .to_string(),
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Suspicious,
                EventKind::RequestSeen {
                    method: "POST".to_string(),
                    path: "/api/v2/import/reconcile".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity::default(),
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: None,
                    trusted_ingress_soften_match: None,
                    ingress_signals: Default::default(),
                    discovery_recon_score: DiscoveryReconScore {
                        repeated_discovery_score: 2,
                        query_score: 1,
                        total: 3,
                        threshold: 3,
                        ..DiscoveryReconScore::default()
                    },
                    routing_decision: RoutingDecision::EidolonOwned,
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::PolicyRouter,
                PolicyState::ControlledReality,
                EventKind::PolicyChanged {
                    from: PolicyState::Suspicious,
                    to: PolicyState::ControlledReality,
                    reason: "confirmed bait-derived action moved session into controlled reality"
                        .to_string(),
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::ControlledReality,
                EventKind::ResponseServed {
                    status: 202,
                    routing_decision: RoutingDecision::ControlledReality,
                },
            )
            .with_request_id(rid),
        ]);

        let export = must_some(
            edge_decision_export_for_timeline(&timeline),
            "edge decision export should exist",
        );

        assert_eq!(export.policy.state, PolicyState::ControlledReality);
        assert!(export.trusted_ingress_soften_match.is_none());
        assert_eq!(export.evidence.trusted_ingress_soften_histories.len(), 1);
        assert_eq!(
            export.evidence.trusted_ingress_soften_histories[0]
                .label
                .as_deref(),
            Some("docs-crawler")
        );
        assert!(export.evidence.trusted_ingress_soften_histories[0].saw_request_path_softened);
        assert!(export.evidence.trusted_ingress_soften_histories[0].saw_request_path_unsoftened);
    }

    #[test]
    fn edge_decision_export_preserves_local_trust_scope_rejections() {
        let session_id = SessionId::new();
        let timeline = timeline(vec![
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Observe,
                EventKind::RequestSeen {
                    method: "GET".to_string(),
                    path: "/docs?topic=imports".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity::default(),
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: Some(
                        eidolon_core::LocalIngressTrustScopeRejection {
                            label: Some("docs-crawler".to_string()),
                            source: IngressIdentitySource::LocalAllowlist,
                            trust_tier: IngressTrustTier::Allowlisted,
                            not_before: None,
                            expires_at: None,
                            methods: vec!["GET".to_string()],
                            path_prefixes: vec!["/docs".to_string()],
                            bait_soften_path_prefixes: vec!["/docs".to_string()],
                            user_agent_substrings: vec!["eidolon-docs-crawler".to_string()],
                            hosts: vec!["docs.example.test".to_string()],
                            source_cidrs: vec!["127.0.0.1/32".to_string()],
                            required_header_names: vec!["X-Eidolon-Trusted-Actor".to_string()],
                            reason:
                                eidolon_core::LocalIngressTrustScopeRejectionReason::HostMismatch,
                        },
                    ),
                    trusted_ingress_soften_match: None,
                    ingress_signals: Default::default(),
                    discovery_recon_score: Default::default(),
                    routing_decision: RoutingDecision::RewrittenUpstream,
                },
            ),
            Event::new(
                session_id,
                EventSource::PolicyRouter,
                PolicyState::Observe,
                EventKind::PolicyDecision {
                    routing_decision: RoutingDecision::RewrittenUpstream,
                    reason: "request stayed baited after local allowlist host scope mismatch"
                        .to_string(),
                },
            ),
        ]);

        let export = must_some(
            edge_decision_export_for_timeline(&timeline),
            "edge decision export should exist",
        );

        let rejection = export
            .local_ingress_trust_scope_rejection
            .expect("local trust scope rejection should be exported");
        assert_eq!(rejection.label.as_deref(), Some("docs-crawler"));
        assert_eq!(
            rejection.reason,
            eidolon_core::LocalIngressTrustScopeRejectionReason::HostMismatch
        );
        assert_eq!(rejection.hosts, vec!["docs.example.test".to_string()]);
    }

    #[test]
    fn edge_decision_export_preserves_local_trust_scope_rejection_history() {
        let session_id = SessionId::new();
        let timeline = timeline(vec![
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Observe,
                EventKind::RequestSeen {
                    method: "GET".to_string(),
                    path: "/docs?topic=imports".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity::default(),
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: Some(
                        eidolon_core::LocalIngressTrustScopeRejection {
                            label: Some("docs-crawler".to_string()),
                            source: IngressIdentitySource::LocalAllowlist,
                            trust_tier: IngressTrustTier::Allowlisted,
                            not_before: None,
                            expires_at: None,
                            methods: vec!["GET".to_string()],
                            path_prefixes: vec!["/docs".to_string()],
                            bait_soften_path_prefixes: vec!["/docs".to_string()],
                            user_agent_substrings: vec!["eidolon-docs-crawler".to_string()],
                            hosts: vec!["docs.example.test".to_string()],
                            source_cidrs: vec!["127.0.0.1/32".to_string()],
                            required_header_names: vec!["X-Eidolon-Trusted-Actor".to_string()],
                            reason:
                                eidolon_core::LocalIngressTrustScopeRejectionReason::HostMismatch,
                        },
                    ),
                    trusted_ingress_soften_match: None,
                    ingress_signals: Default::default(),
                    discovery_recon_score: Default::default(),
                    routing_decision: RoutingDecision::RewrittenUpstream,
                },
            ),
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::ControlledReality,
                EventKind::RequestSeen {
                    method: "POST".to_string(),
                    path: "/api/v2/import/reconcile".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity::default(),
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: None,
                    trusted_ingress_soften_match: None,
                    ingress_signals: Default::default(),
                    discovery_recon_score: Default::default(),
                    routing_decision: RoutingDecision::ControlledReality,
                },
            ),
            Event::new(
                session_id,
                EventSource::PolicyRouter,
                PolicyState::ControlledReality,
                EventKind::PolicyDecision {
                    routing_decision: RoutingDecision::ControlledReality,
                    reason: "confirmed bait-derived action moved session into controlled reality"
                        .to_string(),
                },
            ),
        ]);

        let export = must_some(
            edge_decision_export_for_timeline(&timeline),
            "edge decision export should exist",
        );

        assert!(export.local_ingress_trust_scope_rejection.is_none());
        assert_eq!(
            export
                .evidence
                .local_ingress_trust_scope_rejection_histories
                .len(),
            1
        );
        let history = &export
            .evidence
            .local_ingress_trust_scope_rejection_histories[0];
        assert_eq!(history.label.as_deref(), Some("docs-crawler"));
        assert_eq!(history.hosts, vec!["docs.example.test".to_string()]);
        assert_eq!(
            history.reasons,
            vec![eidolon_core::LocalIngressTrustScopeRejectionReason::HostMismatch]
        );
    }

    #[test]
    fn edge_decision_export_includes_deduped_bait_header_value_mint_audits() {
        let session_id = SessionId::new();
        let rid = RequestId::new();
        let mint = BaitHeaderValueMintAudit {
            header_name: "X-Minted-Trace".to_string(),
            kind: eidolon_core::HeaderValueMintKind::SessionHmacSha256V1,
            prefix: "minted".to_string(),
        };
        let timeline = timeline(vec![
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Observe,
                EventKind::RequestSeen {
                    method: "GET".to_string(),
                    path: "/docs/minted-trace".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity::default(),
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: None,
                    trusted_ingress_soften_match: None,
                    ingress_signals: Default::default(),
                    discovery_recon_score: Default::default(),
                    routing_decision: RoutingDecision::ProtectedUpstream,
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::SurfaceController,
                PolicyState::Observe,
                EventKind::BaitExposed {
                    bait_id: BaitId("minted_trace".to_string()),
                    exposure_id: ExposureId("exp-minted".to_string()),
                    surface: "/docs/minted-trace".to_string(),
                    header_value_mint: Some(mint.clone()),
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Observe,
                EventKind::RequestSeen {
                    method: "POST".to_string(),
                    path: "/api/v2/import/reconcile".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity::default(),
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: None,
                    trusted_ingress_soften_match: None,
                    ingress_signals: Default::default(),
                    discovery_recon_score: Default::default(),
                    routing_decision: RoutingDecision::ControlledReality,
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::BaitEngine,
                PolicyState::Observe,
                EventKind::BaitActionObserved {
                    bait_id: BaitId("minted_trace".to_string()),
                    exposure_id: Some(ExposureId("exp-minted".to_string())),
                    method: "POST".to_string(),
                    path: "/api/v2/import/reconcile".to_string(),
                    header_value_mint: Some(mint),
                    header_value_mint_status: Some(BaitHeaderValueMintStatus::MatchedSessionValue),
                },
            )
            .with_request_id(rid),
            policy(session_id).with_request_id(rid),
        ]);

        let export = must_some(
            edge_decision_export_for_timeline(&timeline),
            "edge decision export should exist",
        );

        assert_eq!(export.evidence.bait_header_value_mints.len(), 1);
        assert_eq!(
            export.evidence.bait_header_value_mints[0].bait_id,
            BaitId("minted_trace".to_string())
        );
        assert_eq!(
            export.evidence.bait_header_value_mints[0].header_name,
            "X-Minted-Trace"
        );
        assert_eq!(export.evidence.bait_header_value_mints[0].prefix, "minted");
        assert_eq!(
            export.evidence.latest_bait_header_value_mint,
            Some(EdgeObservedBaitHeaderValueMint {
                bait_id: BaitId("minted_trace".to_string()),
                header_name: "X-Minted-Trace".to_string(),
                kind: eidolon_core::HeaderValueMintKind::SessionHmacSha256V1,
                prefix: "minted".to_string(),
                status: BaitHeaderValueMintStatus::MatchedSessionValue,
            })
        );
    }

    #[test]
    fn edge_decision_export_never_combines_events_from_interleaved_requests() {
        let session_id = SessionId::new();
        let rid_a = RequestId::new();
        let rid_b = RequestId::new();
        let rate_limit_reason = "repeated same-bait near misses moved session to rate limit";
        let timeline = timeline(vec![
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Suspicious,
                EventKind::RequestSeen {
                    method: "POST".to_string(),
                    path: "/api/v2/import/reconcile".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity::default(),
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: None,
                    trusted_ingress_soften_match: None,
                    ingress_signals: Default::default(),
                    discovery_recon_score: Default::default(),
                    routing_decision: RoutingDecision::RateLimited,
                },
            )
            .with_request_id(rid_a),
            Event::new(
                session_id,
                EventSource::PolicyRouter,
                PolicyState::RateLimited,
                EventKind::PolicyDecision {
                    routing_decision: RoutingDecision::RateLimited,
                    reason: rate_limit_reason.to_string(),
                },
            )
            .with_request_id(rid_a),
            Event::new(
                session_id,
                EventSource::PolicyRouter,
                PolicyState::RateLimited,
                EventKind::RateLimitApplied {
                    reason: rate_limit_reason.to_string(),
                },
            )
            .with_request_id(rid_a),
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Observe,
                EventKind::RequestSeen {
                    method: "GET".to_string(),
                    path: "/docs/legacy-import".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity::default(),
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: None,
                    trusted_ingress_soften_match: None,
                    ingress_signals: Default::default(),
                    discovery_recon_score: Default::default(),
                    routing_decision: RoutingDecision::ProtectedUpstream,
                },
            )
            .with_request_id(rid_b),
        ]);

        let export = must_some(
            edge_decision_export_for_timeline(&timeline),
            "edge decision export should exist",
        );

        assert_eq!(export.request.request_id, Some(rid_b));
        assert_eq!(export.evidence.request_linkage, EdgeRequestLinkage::Linked);
        assert_eq!(
            export.policy.routing_decision,
            RoutingDecision::ProtectedUpstream,
            "export for request B must not inherit request A's rate-limit routing"
        );
        assert!(
            !export.policy.reason.contains("near misses"),
            "export for request B must not inherit request A's policy reason"
        );
        let request_b_event_id = timeline.events[3].event.id;
        assert_eq!(
            export.evidence.event_ids,
            vec![request_b_event_id],
            "export event ids must not mix events from different requests"
        );
    }

    #[test]
    fn edge_decision_export_marks_legacy_unlinked_sessions_unknown() {
        let session_id = SessionId::new();
        let mint = BaitHeaderValueMintAudit {
            header_name: "X-Minted-Trace".to_string(),
            kind: eidolon_core::HeaderValueMintKind::SessionHmacSha256V1,
            prefix: "minted".to_string(),
        };
        let timeline = timeline(vec![
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Observe,
                EventKind::RequestSeen {
                    method: "POST".to_string(),
                    path: "/api/v2/import/reconcile".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity::default(),
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: None,
                    trusted_ingress_soften_match: None,
                    ingress_signals: Default::default(),
                    discovery_recon_score: Default::default(),
                    routing_decision: RoutingDecision::ProtectedUpstream,
                },
            ),
            Event::new(
                session_id,
                EventSource::SurfaceController,
                PolicyState::Observe,
                EventKind::BaitExposed {
                    bait_id: BaitId("minted_trace".to_string()),
                    exposure_id: ExposureId("exp-minted".to_string()),
                    surface: "/docs/minted-trace".to_string(),
                    header_value_mint: Some(mint.clone()),
                },
            ),
            Event::new(
                session_id,
                EventSource::BaitEngine,
                PolicyState::Observe,
                EventKind::BaitActionObserved {
                    bait_id: BaitId("minted_trace".to_string()),
                    exposure_id: Some(ExposureId("exp-minted".to_string())),
                    method: "POST".to_string(),
                    path: "/api/v2/import/reconcile".to_string(),
                    header_value_mint: Some(mint),
                    header_value_mint_status: Some(BaitHeaderValueMintStatus::MatchedSessionValue),
                },
            ),
            Event::new(
                session_id,
                EventSource::PolicyRouter,
                PolicyState::Observe,
                EventKind::PolicyDecision {
                    routing_decision: RoutingDecision::EidolonOwned,
                    reason: "bait-derived action intercepted".to_string(),
                },
            ),
        ]);

        let export = must_some(
            edge_decision_export_for_timeline(&timeline),
            "edge decision export should exist",
        );

        assert_eq!(
            export.evidence.request_linkage,
            EdgeRequestLinkage::UnknownLegacy
        );
        assert_eq!(export.request.request_id, None);
        assert_eq!(export.policy.state, PolicyState::Observe);
        assert_eq!(
            export.policy.routing_decision,
            RoutingDecision::ProtectedUpstream
        );
        assert_eq!(export.policy.reason, "latest request routing decision");
        assert_eq!(export.evidence.latest_bait_header_value_mint, None);
        assert_eq!(export.evidence.event_ids, vec![timeline.events[0].event.id]);
    }

    #[test]
    fn edge_decision_export_pairs_bait_action_with_same_request_id() {
        let session_id = SessionId::new();
        let surface_rid = RequestId::new();
        let rid = RequestId::new();
        let mint = BaitHeaderValueMintAudit {
            header_name: "X-Minted-Trace".to_string(),
            kind: eidolon_core::HeaderValueMintKind::SessionHmacSha256V1,
            prefix: "minted".to_string(),
        };
        let timeline = timeline(vec![
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Observe,
                EventKind::RequestSeen {
                    method: "GET".to_string(),
                    path: "/docs/minted-trace".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity::default(),
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: None,
                    trusted_ingress_soften_match: None,
                    ingress_signals: Default::default(),
                    discovery_recon_score: Default::default(),
                    routing_decision: RoutingDecision::ProtectedUpstream,
                },
            )
            .with_request_id(surface_rid),
            Event::new(
                session_id,
                EventSource::SurfaceController,
                PolicyState::Observe,
                EventKind::BaitExposed {
                    bait_id: BaitId("minted_trace".to_string()),
                    exposure_id: ExposureId("exp-minted".to_string()),
                    surface: "/docs/minted-trace".to_string(),
                    header_value_mint: Some(mint.clone()),
                },
            )
            .with_request_id(surface_rid),
            Event::new(
                session_id,
                EventSource::BaitEngine,
                PolicyState::Observe,
                EventKind::BaitActionObserved {
                    bait_id: BaitId("minted_trace".to_string()),
                    exposure_id: None,
                    method: "POST".to_string(),
                    path: "/api/v2/import/reconcile".to_string(),
                    header_value_mint: Some(mint),
                    header_value_mint_status: Some(BaitHeaderValueMintStatus::SessionValueMismatch),
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Observe,
                EventKind::RequestSeen {
                    method: "POST".to_string(),
                    path: "/api/v2/import/reconcile".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity::default(),
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: None,
                    trusted_ingress_soften_match: None,
                    ingress_signals: Default::default(),
                    discovery_recon_score: Default::default(),
                    routing_decision: RoutingDecision::ProtectedUpstream,
                },
            )
            .with_request_id(rid),
        ]);

        let export = must_some(
            edge_decision_export_for_timeline(&timeline),
            "edge decision export should exist",
        );

        assert_eq!(export.request.method, "POST");
        assert_eq!(export.request.path, "/api/v2/import/reconcile");
        assert_eq!(export.request.request_id, Some(rid));
        assert_eq!(export.evidence.request_linkage, EdgeRequestLinkage::Linked);
        assert_eq!(
            export.evidence.latest_bait_header_value_mint,
            Some(EdgeObservedBaitHeaderValueMint {
                bait_id: BaitId("minted_trace".to_string()),
                header_name: "X-Minted-Trace".to_string(),
                kind: eidolon_core::HeaderValueMintKind::SessionHmacSha256V1,
                prefix: "minted".to_string(),
                status: BaitHeaderValueMintStatus::SessionValueMismatch,
            })
        );
        assert_eq!(export.evidence.event_ids.len(), 2);
    }

    #[test]
    fn edge_decision_export_does_not_pair_bait_action_from_other_request_id() {
        let session_id = SessionId::new();
        let surface_rid = RequestId::new();
        let other_rid = RequestId::new();
        let rid = RequestId::new();
        let mint = BaitHeaderValueMintAudit {
            header_name: "X-Minted-Trace".to_string(),
            kind: eidolon_core::HeaderValueMintKind::SessionHmacSha256V1,
            prefix: "minted".to_string(),
        };
        let timeline = timeline(vec![
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Observe,
                EventKind::RequestSeen {
                    method: "GET".to_string(),
                    path: "/docs/minted-trace".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity::default(),
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: None,
                    trusted_ingress_soften_match: None,
                    ingress_signals: Default::default(),
                    discovery_recon_score: Default::default(),
                    routing_decision: RoutingDecision::ProtectedUpstream,
                },
            )
            .with_request_id(surface_rid),
            Event::new(
                session_id,
                EventSource::SurfaceController,
                PolicyState::Observe,
                EventKind::BaitExposed {
                    bait_id: BaitId("minted_trace".to_string()),
                    exposure_id: ExposureId("exp-minted".to_string()),
                    surface: "/docs/minted-trace".to_string(),
                    header_value_mint: Some(mint.clone()),
                },
            )
            .with_request_id(surface_rid),
            Event::new(
                session_id,
                EventSource::BaitEngine,
                PolicyState::Observe,
                EventKind::BaitActionObserved {
                    bait_id: BaitId("minted_trace".to_string()),
                    exposure_id: None,
                    method: "POST".to_string(),
                    path: "/api/v2/import/reconcile".to_string(),
                    header_value_mint: Some(mint),
                    header_value_mint_status: Some(BaitHeaderValueMintStatus::SessionValueMismatch),
                },
            )
            .with_request_id(other_rid),
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Observe,
                EventKind::RequestSeen {
                    method: "POST".to_string(),
                    path: "/api/v2/import/reconcile".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity::default(),
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: None,
                    trusted_ingress_soften_match: None,
                    ingress_signals: Default::default(),
                    discovery_recon_score: Default::default(),
                    routing_decision: RoutingDecision::ProtectedUpstream,
                },
            )
            .with_request_id(rid),
        ]);

        let export = must_some(
            edge_decision_export_for_timeline(&timeline),
            "edge decision export should exist",
        );

        assert_eq!(export.request.method, "POST");
        assert_eq!(export.request.path, "/api/v2/import/reconcile");
        assert_eq!(export.request.request_id, Some(rid));
        assert_eq!(export.evidence.request_linkage, EdgeRequestLinkage::Linked);
        assert_eq!(export.evidence.latest_bait_header_value_mint, None);
        assert_eq!(export.evidence.event_ids.len(), 1);
    }

    #[test]
    fn edge_decision_export_groups_rate_limited_discovery_recon_into_shared_family() {
        let session_id = SessionId::new();
        let rid = RequestId::new();
        let timeline = timeline(vec![
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::RateLimited,
                EventKind::RequestSeen {
                    method: "GET".to_string(),
                    path: "/docs".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity::default(),
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: None,
                    trusted_ingress_soften_match: None,
                    ingress_signals: Default::default(),
                    discovery_recon_score: DiscoveryReconScore {
                        repeated_discovery_score: 2,
                        query_score: 1,
                        legacy_openapi_query_score: 2,
                        linked_bait_surface_score: 0,
                        linked_bait_class_fanout_bonus: 0,
                        decoy_write_probe_score: 0,
                        decoy_write_probe_path_fanout_bonus: 0,
                        detection_score: 0,
                        total: 5,
                        threshold: 5,
                    },
                    routing_decision: RoutingDecision::RateLimited,
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::PolicyRouter,
                PolicyState::RateLimited,
                EventKind::PolicyChanged {
                    from: PolicyState::Suspicious,
                    to: PolicyState::RateLimited,
                    reason: "suspicious discovery recon persistence moved session to rate limited: path=/docs actor_kind=agentic_browser vendor_score=35 discovery_requests=2 distinct_surfaces=2 query_seen=true legacy_openapi_query_seen=true linked_bait_surface_seen=false linked_bait_surface_classes=0 decoy_write_probe_seen=false decoy_write_probe_count=0 decoy_write_probe_path_classes=0 detection_count=0 repeated_discovery_score=2 query_score=1 legacy_openapi_query_score=2 linked_bait_surface_score=0 linked_bait_class_fanout_bonus=0 decoy_write_probe_score=0 decoy_write_probe_path_fanout_bonus=0 detection_score=0 recon_score=5 recon_rate_limit_threshold=5 persistence_class=discovery_recon".to_string(),
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::RateLimited,
                EventKind::RateLimitApplied {
                    reason: "suspicious discovery recon persistence moved session to rate limited: path=/docs actor_kind=agentic_browser vendor_score=35 discovery_requests=2 distinct_surfaces=2 query_seen=true legacy_openapi_query_seen=true linked_bait_surface_seen=false linked_bait_surface_classes=0 decoy_write_probe_seen=false decoy_write_probe_count=0 decoy_write_probe_path_classes=0 detection_count=0 repeated_discovery_score=2 query_score=1 legacy_openapi_query_score=2 linked_bait_surface_score=0 linked_bait_class_fanout_bonus=0 decoy_write_probe_score=0 decoy_write_probe_path_fanout_bonus=0 detection_score=0 recon_score=5 recon_rate_limit_threshold=5 persistence_class=discovery_recon".to_string(),
                },
            )
            .with_request_id(rid),
        ]);

        let export = must_some(
            edge_decision_export_for_timeline(&timeline),
            "edge decision export should exist",
        );

        assert_eq!(
            export.edge_recommendation.reason_codes,
            vec![
                "eidolon_runtime_enforcement".to_string(),
                "rate_limited".to_string(),
                "pre_containment_persistence".to_string(),
                "discovery_recon".to_string(),
            ]
        );
        assert_eq!(
            export.policy.pre_containment_persistence_class,
            Some(PreContainmentPersistenceClass::DiscoveryRecon)
        );
        assert_eq!(export.policy.pre_containment_persistence_kind, None);
    }

    #[test]
    fn edge_decision_export_groups_rate_limited_same_bait_near_miss_into_shared_family() {
        let session_id = SessionId::new();
        let rid = RequestId::new();
        let timeline = timeline(vec![
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::RateLimited,
                EventKind::RequestSeen {
                    method: "POST".to_string(),
                    path: "/api/v2/import/reconcile".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity::default(),
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: None,
                    trusted_ingress_soften_match: None,
                    ingress_signals: Default::default(),
                    discovery_recon_score: Default::default(),
                    routing_decision: RoutingDecision::RateLimited,
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::PolicyRouter,
                PolicyState::RateLimited,
                EventKind::PolicyChanged {
                    from: PolicyState::Suspicious,
                    to: PolicyState::RateLimited,
                    reason: "suspicious same-bait near miss after exposure moved session to rate limited: path=/api/v2/import/reconcile bait_id=rel_2025_04_b7f2 persistence_class=same_bait_near_miss".to_string(),
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::RateLimited,
                EventKind::RateLimitApplied {
                    reason: "suspicious same-bait near miss after exposure moved session to rate limited: path=/api/v2/import/reconcile bait_id=rel_2025_04_b7f2 persistence_class=same_bait_near_miss".to_string(),
                },
            )
            .with_request_id(rid),
        ]);

        let export = must_some(
            edge_decision_export_for_timeline(&timeline),
            "edge decision export should exist",
        );

        assert_eq!(
            export.edge_recommendation.reason_codes,
            vec![
                "eidolon_runtime_enforcement".to_string(),
                "rate_limited".to_string(),
                "pre_containment_persistence".to_string(),
                "same_bait_near_miss".to_string(),
            ]
        );
        assert_eq!(
            export.policy.pre_containment_persistence_class,
            Some(PreContainmentPersistenceClass::SameBaitNearMiss)
        );
        assert_eq!(export.policy.pre_containment_persistence_kind, None);
    }

    #[test]
    fn edge_decision_export_prefers_structured_rate_limit_reason_over_generic_policy_decision() {
        let session_id = SessionId::new();
        let rid = RequestId::new();
        let timeline = timeline(vec![
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::RateLimited,
                EventKind::RequestSeen {
                    method: "GET".to_string(),
                    path: "/docs".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity::default(),
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: None,
                    trusted_ingress_soften_match: None,
                    ingress_signals: IngressAdvisorySignals {
                        actor_kind: eidolon_core::IngressActorKind::AgenticBrowser,
                        vendor_score: Some(35),
                        vendor_score_kind: Some("automation_likelihood_inverse".to_string()),
                        detection_ids: vec!["3355446".to_string(), "445566".to_string()],
                        ..Default::default()
                    },
                    discovery_recon_score: DiscoveryReconScore {
                        repeated_discovery_score: 2,
                        query_score: 1,
                        detection_score: 2,
                        total: 5,
                        threshold: 5,
                        ..Default::default()
                    },
                    routing_decision: RoutingDecision::RateLimited,
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::PolicyRouter,
                PolicyState::RateLimited,
                EventKind::RateLimitApplied {
                    reason: "suspicious discovery recon persistence moved session to rate limited: path=/docs actor_kind=agentic_browser vendor_score=35 discovery_requests=2 distinct_surfaces=1 query_seen=true legacy_openapi_query_seen=false linked_bait_surface_seen=false linked_bait_surface_classes=0 decoy_write_probe_seen=false decoy_write_probe_count=0 decoy_write_probe_path_classes=0 detection_count=2 repeated_discovery_score=2 query_score=1 legacy_openapi_query_score=0 linked_bait_surface_score=0 linked_bait_class_fanout_bonus=0 decoy_write_probe_score=0 decoy_write_probe_path_fanout_bonus=0 detection_score=2 recon_score=5 recon_rate_limit_threshold=5 persistence_class=discovery_recon".to_string(),
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::PolicyRouter,
                PolicyState::RateLimited,
                EventKind::PolicyDecision {
                    routing_decision: RoutingDecision::RateLimited,
                    reason: "rate limited policy throttles the request".to_string(),
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::RateLimited,
                EventKind::ResponseServed {
                    status: 429,
                    routing_decision: RoutingDecision::RateLimited,
                },
            )
            .with_request_id(rid),
        ]);

        let export = must_some(
            edge_decision_export_for_timeline(&timeline),
            "edge decision export should exist",
        );

        assert!(export
            .policy
            .reason
            .contains("suspicious discovery recon persistence moved session to rate limited"));
        assert_eq!(
            export.edge_recommendation.reason_codes,
            vec![
                "eidolon_runtime_enforcement".to_string(),
                "rate_limited".to_string(),
                "pre_containment_persistence".to_string(),
                "discovery_recon".to_string(),
            ]
        );
        assert_eq!(
            export.policy.pre_containment_persistence_class,
            Some(PreContainmentPersistenceClass::DiscoveryRecon)
        );
    }

    #[test]
    fn edge_decision_export_groups_repeated_escape_block_into_shared_family() {
        let session_id = SessionId::new();
        let rid = RequestId::new();
        let timeline = timeline(vec![
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Blocked,
                EventKind::RequestSeen {
                    method: "GET".to_string(),
                    path: "/api/v1/projects".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity::default(),
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: None,
                    trusted_ingress_soften_match: None,
                    ingress_signals: Default::default(),
                    discovery_recon_score: Default::default(),
                    routing_decision: RoutingDecision::EidolonOwned,
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::PolicyRouter,
                PolicyState::Blocked,
                EventKind::PolicyChanged {
                    from: PolicyState::ControlledReality,
                    to: PolicyState::Blocked,
                    reason: "controlled session repeatedly probed outside the controlled-reality branch and moved session to blocked: path=/api/v1/projects attempt_count=2 post_containment_persistence_kind=controlled_reality_branch_escape".to_string(),
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Blocked,
                EventKind::ResponseServed {
                    status: 403,
                    routing_decision: RoutingDecision::EidolonOwned,
                },
            )
            .with_request_id(rid),
        ]);

        let export = must_some(
            edge_decision_export_for_timeline(&timeline),
            "edge decision export should exist",
        );

        assert!(export.policy.reason.contains(
            "controlled session repeatedly probed outside the controlled-reality branch"
        ));
        assert_eq!(
            export.edge_recommendation.reason_codes,
            vec![
                "eidolon_runtime_enforcement".to_string(),
                "eidolon_owned".to_string(),
                "post_containment_persistence".to_string(),
                "controlled_reality_branch_escape".to_string(),
            ]
        );
        assert_eq!(
            export.policy.post_containment_persistence_kind,
            Some(PostContainmentPersistenceKind::ControlledRealityBranchEscape)
        );
    }

    #[test]
    fn edge_decision_export_groups_repeated_near_miss_block_into_shared_family() {
        let session_id = SessionId::new();
        let rid = RequestId::new();
        let timeline = timeline(vec![
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Blocked,
                EventKind::RequestSeen {
                    method: "POST".to_string(),
                    path: "/api/v2/import/reconcile".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity::default(),
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: None,
                    trusted_ingress_soften_match: None,
                    ingress_signals: Default::default(),
                    discovery_recon_score: Default::default(),
                    routing_decision: RoutingDecision::EidolonOwned,
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::PolicyRouter,
                PolicyState::Blocked,
                EventKind::PolicyChanged {
                    from: PolicyState::RateLimited,
                    to: PolicyState::Blocked,
                    reason: "rate-limited same-bait near miss retry moved session to blocked: path=/api/v2/import/reconcile bait_id=rel_2025_04_b7f2 persistence_class=same_bait_near_miss persistence_kind=same_bait_near_miss_retry".to_string(),
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Blocked,
                EventKind::ResponseServed {
                    status: 403,
                    routing_decision: RoutingDecision::EidolonOwned,
                },
            )
            .with_request_id(rid),
        ]);

        let export = must_some(
            edge_decision_export_for_timeline(&timeline),
            "edge decision export should exist",
        );

        assert!(export
            .policy
            .reason
            .contains("rate-limited same-bait near miss retry moved session to blocked"));
        assert_eq!(
            export.edge_recommendation.reason_codes,
            vec![
                "eidolon_runtime_enforcement".to_string(),
                "eidolon_owned".to_string(),
                "pre_containment_persistence".to_string(),
                "same_bait_near_miss_retry".to_string(),
            ]
        );
        assert_eq!(
            export.policy.pre_containment_persistence_class,
            Some(PreContainmentPersistenceClass::SameBaitNearMiss)
        );
        assert_eq!(
            export.policy.pre_containment_persistence_kind,
            Some(PreContainmentPersistenceKind::SameBaitNearMissRetry)
        );
    }

    #[test]
    fn edge_decision_export_groups_repeated_discovery_recon_block_into_shared_family() {
        let session_id = SessionId::new();
        let rid = RequestId::new();
        let timeline = timeline(vec![
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Blocked,
                EventKind::RequestSeen {
                    method: "GET".to_string(),
                    path: "/docs".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity::default(),
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: None,
                    trusted_ingress_soften_match: None,
                    ingress_signals: Default::default(),
                    discovery_recon_score: DiscoveryReconScore {
                        repeated_discovery_score: 2,
                        query_score: 1,
                        legacy_openapi_query_score: 2,
                        linked_bait_surface_score: 0,
                        linked_bait_class_fanout_bonus: 0,
                        decoy_write_probe_score: 0,
                        decoy_write_probe_path_fanout_bonus: 0,
                        detection_score: 0,
                        total: 5,
                        threshold: 5,
                    },
                    routing_decision: RoutingDecision::EidolonOwned,
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::PolicyRouter,
                PolicyState::Blocked,
                EventKind::PolicyChanged {
                    from: PolicyState::RateLimited,
                    to: PolicyState::Blocked,
                    reason: "rate-limited discovery recon retry moved session to blocked: path=/docs actor_kind=agentic_browser vendor_score=35 discovery_requests=3 distinct_surfaces=2 query_seen=true legacy_openapi_query_seen=true linked_bait_surface_seen=false linked_bait_surface_classes=0 decoy_write_probe_seen=false decoy_write_probe_count=0 decoy_write_probe_path_classes=0 detection_count=0 repeated_discovery_score=2 query_score=1 legacy_openapi_query_score=2 linked_bait_surface_score=0 linked_bait_class_fanout_bonus=0 decoy_write_probe_score=0 decoy_write_probe_path_fanout_bonus=0 detection_score=0 recon_score=5 recon_block_threshold=5 persistence_class=discovery_recon persistence_kind=discovery_recon_retry".to_string(),
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Blocked,
                EventKind::ResponseServed {
                    status: 403,
                    routing_decision: RoutingDecision::EidolonOwned,
                },
            )
            .with_request_id(rid),
        ]);

        let export = must_some(
            edge_decision_export_for_timeline(&timeline),
            "edge decision export should exist",
        );

        assert!(export
            .policy
            .reason
            .contains("rate-limited discovery recon retry moved session to blocked"));
        assert_eq!(
            export.edge_recommendation.reason_codes,
            vec![
                "eidolon_runtime_enforcement".to_string(),
                "eidolon_owned".to_string(),
                "pre_containment_persistence".to_string(),
                "discovery_recon_retry".to_string(),
            ]
        );
        assert_eq!(
            export.policy.pre_containment_persistence_class,
            Some(PreContainmentPersistenceClass::DiscoveryRecon)
        );
        assert_eq!(
            export.policy.pre_containment_persistence_kind,
            Some(PreContainmentPersistenceKind::DiscoveryReconRetry)
        );
    }

    #[test]
    fn edge_decision_export_groups_blind_write_recon_block_into_write_family() {
        let session_id = SessionId::new();
        let rid = RequestId::new();
        let timeline = timeline(vec![
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Blocked,
                EventKind::RequestSeen {
                    method: "POST".to_string(),
                    path: "/api/v2/import/validate".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity::default(),
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: None,
                    trusted_ingress_soften_match: None,
                    ingress_signals: Default::default(),
                    discovery_recon_score: DiscoveryReconScore {
                        repeated_discovery_score: 0,
                        query_score: 1,
                        legacy_openapi_query_score: 0,
                        linked_bait_surface_score: 0,
                        linked_bait_class_fanout_bonus: 0,
                        decoy_write_probe_score: 3,
                        decoy_write_probe_path_fanout_bonus: 1,
                        detection_score: 0,
                        total: 5,
                        threshold: 5,
                    },
                    routing_decision: RoutingDecision::EidolonOwned,
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::PolicyRouter,
                PolicyState::Blocked,
                EventKind::PolicyChanged {
                    from: PolicyState::RateLimited,
                    to: PolicyState::Blocked,
                    reason: "rate-limited discovery recon retry moved session to blocked: path=/api/v2/import/validate actor_kind=agentic_browser vendor_score=35 discovery_requests=1 distinct_surfaces=1 query_seen=true legacy_openapi_query_seen=false linked_bait_surface_seen=false linked_bait_surface_classes=0 decoy_write_probe_seen=true decoy_write_probe_count=2 decoy_write_probe_path_classes=2 detection_count=0 repeated_discovery_score=0 query_score=1 legacy_openapi_query_score=0 linked_bait_surface_score=0 linked_bait_class_fanout_bonus=0 decoy_write_probe_score=3 decoy_write_probe_path_fanout_bonus=1 detection_score=0 recon_score=5 recon_block_threshold=5 persistence_class=write_recon persistence_kind=write_recon_retry".to_string(),
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Blocked,
                EventKind::ResponseServed {
                    status: 403,
                    routing_decision: RoutingDecision::EidolonOwned,
                },
            )
            .with_request_id(rid),
        ]);

        let export = must_some(
            edge_decision_export_for_timeline(&timeline),
            "edge decision export should exist",
        );

        assert!(export
            .policy
            .reason
            .contains("rate-limited discovery recon retry moved session to blocked"));
        assert_eq!(
            export.edge_recommendation.reason_codes,
            vec![
                "eidolon_runtime_enforcement".to_string(),
                "eidolon_owned".to_string(),
                "pre_containment_persistence".to_string(),
                "write_recon_retry".to_string(),
            ]
        );
        assert_eq!(
            export.policy.pre_containment_persistence_class,
            Some(PreContainmentPersistenceClass::WriteRecon)
        );
        assert_eq!(
            export.policy.pre_containment_persistence_kind,
            Some(PreContainmentPersistenceKind::WriteReconRetry)
        );
    }

    #[test]
    fn edge_decision_export_groups_depth_limit_block_into_shared_family() {
        let session_id = SessionId::new();
        let rid = RequestId::new();
        let timeline = timeline(vec![
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Blocked,
                EventKind::RequestSeen {
                    method: "GET".to_string(),
                    path: "/api/v2/import/reconcile".to_string(),
                    safe_headers: Vec::new(),
                    ingress_identity: IngressIdentity::default(),
                    authenticated_ingress_rule_rejection: None,
                    local_ingress_trust_scope_rejection: None,
                    trusted_ingress_soften_match: None,
                    ingress_signals: Default::default(),
                    discovery_recon_score: Default::default(),
                    routing_decision: RoutingDecision::EidolonOwned,
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::PolicyRouter,
                PolicyState::Blocked,
                EventKind::PolicyChanged {
                    from: PolicyState::ControlledReality,
                    to: PolicyState::Blocked,
                    reason: "controlled-reality probe continued after depth-limit throttle and moved session to blocked: path=/api/v2/import/reconcile depth=6 depth_limit=4 post_containment_persistence_kind=controlled_reality_depth_limit".to_string(),
                },
            )
            .with_request_id(rid),
            Event::new(
                session_id,
                EventSource::Proxy,
                PolicyState::Blocked,
                EventKind::ResponseServed {
                    status: 403,
                    routing_decision: RoutingDecision::EidolonOwned,
                },
            )
            .with_request_id(rid),
        ]);

        let export = must_some(
            edge_decision_export_for_timeline(&timeline),
            "edge decision export should exist",
        );

        assert!(export
            .policy
            .reason
            .contains("controlled-reality probe continued after depth-limit throttle"));
        assert_eq!(
            export.edge_recommendation.reason_codes,
            vec![
                "eidolon_runtime_enforcement".to_string(),
                "eidolon_owned".to_string(),
                "post_containment_persistence".to_string(),
                "controlled_reality_depth_limit".to_string(),
            ]
        );
        assert_eq!(
            export.policy.post_containment_persistence_kind,
            Some(PostContainmentPersistenceKind::ControlledRealityDepthLimit)
        );
    }

    #[test]
    fn markdown_text_replaces_newlines_with_spaces_for_table_cells() {
        assert_eq!(markdown_text("first\nsecond\rthird"), "first second third");
    }

    #[test]
    fn snake_case_debug_handles_adjacent_initial_capitals() {
        struct Ab;

        impl std::fmt::Debug for Ab {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("AB")
            }
        }

        assert_eq!(snake_case_debug(&Ab), "a_b");
    }
}
