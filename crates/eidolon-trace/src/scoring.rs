use eidolon_core::{ConfidenceBand, Event, Score};

use crate::{
    build_session_timelines,
    evidence::{
        bait_action_confirmation_failure, collect_evidence, confirms_bait_action,
        BaitActionConfirmationFailureReason, EvidenceBundle, ProofOutcome,
    },
    SessionTimeline, TimelineEvent,
};

pub fn score_events(events: &[Event]) -> Score {
    let timeline_events = events
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, event)| TimelineEvent {
            file_order: index,
            line_number: index + 1,
            event,
        });
    let timelines = build_session_timelines(timeline_events);

    score_timelines(&timelines)
}

pub fn score_timelines(timelines: &[SessionTimeline]) -> Score {
    timelines
        .iter()
        .map(score_timeline)
        .max_by_key(|score| (confidence_rank(score.confidence), score.points))
        .unwrap_or_else(low_score)
}

pub fn score_timeline(timeline: &SessionTimeline) -> Score {
    score_evidence(&collect_evidence(timeline))
}

pub fn score_evidence(bundle: &EvidenceBundle) -> Score {
    let mut points = 0;
    let mut reasons = Vec::new();
    let exposed = !bundle.bait_exposures.is_empty();
    let confirmed = bundle
        .matched_actions
        .iter()
        .any(|action| confirms_bait_action(bundle, action));
    let rejected = bundle
        .unmatched_actions
        .iter()
        .any(|action| action.proof_outcome() == ProofOutcome::Rejected);
    let near_miss = bundle.unmatched_actions.iter().any(|action| {
        action.proof_outcome() != ProofOutcome::Rejected
            && action.prior_same_bait_exposure.is_some()
    });
    let unknown_linked = bundle.unmatched_actions.iter().any(|action| {
        action.proof_outcome() == ProofOutcome::Unknown && action.matched_exposure.is_some()
    });
    let exact_unconfirmed = bundle.unmatched_actions.iter().find_map(|action| {
        (action.proof_outcome() == ProofOutcome::Accepted && action.matched_exposure.is_some())
            .then(|| bait_action_confirmation_failure(bundle, action))
            .flatten()
    });
    let acted = bundle
        .unmatched_actions
        .iter()
        .any(|action| action.proof_outcome() != ProofOutcome::Rejected);

    if exposed {
        points += 15;
        reasons.push("controlled bait was exposed to the session".to_string());
    }

    if confirmed {
        points += 70;
        reasons.push("session performed an action matching bait-derived evidence".to_string());
    } else if near_miss {
        points += 50;
        reasons.push(
            "session performed a same-bait action after exposure, but correlation identifiers did not match"
                .to_string(),
        );
    } else if unknown_linked {
        points += 40;
        reasons.push(
            "session performed an action matching a recorded exposure, but the proof validity is unverifiable; not counted as confirmed"
                .to_string(),
        );
    } else if let Some(failure) = exact_unconfirmed {
        points += 40;
        reasons.push(confirmation_failure_score_reason(failure).to_string());
    } else if acted {
        points += 40;
        reasons.push(
            "session performed a bait-shaped action without a matching recorded exposure"
                .to_string(),
        );
    }

    if rejected {
        reasons.push(
            "rejected bait proof observed (replay, expiry, or mismatch); excluded from confirmed evidence and scoring"
                .to_string(),
        );
    }

    let confidence = if confirmed {
        ConfidenceBand::ConfirmedBaitDerivedChain
    } else if near_miss {
        ConfidenceBand::High
    } else if acted || unknown_linked || points >= 20 {
        ConfidenceBand::Medium
    } else {
        ConfidenceBand::Low
    };

    Score {
        points,
        confidence,
        reasons,
    }
}

fn confirmation_failure_score_reason(failure: BaitActionConfirmationFailureReason) -> &'static str {
    match failure {
        BaitActionConfirmationFailureReason::MissingCorrelationMetadata => {
            "session performed an action with a matching exposure identifier, but correlation metadata was incomplete; not counted as confirmed"
        }
        BaitActionConfirmationFailureReason::MissingOrDuplicateRequestObservation => {
            "session performed an action with a matching exposure, but request identity was missing or ambiguous; not counted as confirmed"
        }
        BaitActionConfirmationFailureReason::RequestShapeMismatch => {
            "session performed an action with a matching exposure, but request method, path, or identity did not match; not counted as confirmed"
        }
        BaitActionConfirmationFailureReason::UnsafeActionRouting => {
            "session performed an action with a matching exposure, but the action was not held Eidolon-owned; not counted as confirmed"
        }
        BaitActionConfirmationFailureReason::InvalidEventOrder => {
            "session performed an action with a matching exposure, but request and evidence order was invalid; not counted as confirmed"
        }
        BaitActionConfirmationFailureReason::ProofAuditMismatch => {
            "session performed an action with a matching exposure, but its proof audit did not match; not counted as confirmed"
        }
    }
}

fn low_score() -> Score {
    Score {
        points: 0,
        confidence: ConfidenceBand::Low,
        reasons: Vec::new(),
    }
}

fn confidence_rank(confidence: ConfidenceBand) -> i32 {
    match confidence {
        ConfidenceBand::Low => 0,
        ConfidenceBand::Medium => 1,
        ConfidenceBand::High => 2,
        ConfidenceBand::ConfirmedBaitDerivedChain => 3,
    }
}

#[cfg(test)]
mod tests {
    use eidolon_core::{
        BaitClass, BaitId, Event, EventKind, EventSource, ExposureId, IngressIdentity, PolicyState,
        RequestId, RoutingDecision, SessionId,
    };

    use super::*;

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

    fn bait_exposed(session_id: SessionId) -> Event {
        bait_exposed_with(session_id, "rel_2025_04_b7f2", "exp-1")
    }

    fn bait_exposed_with(session_id: SessionId, bait_id: &str, exposure_id: &str) -> Event {
        Event::new(
            session_id,
            EventSource::SurfaceController,
            PolicyState::Observe,
            EventKind::BaitExposed {
                bait_id: BaitId(bait_id.to_string()),
                bait_class: Some(BaitClass::Docs),
                exposure_id: ExposureId(exposure_id.to_string()),
                surface: "/docs/legacy-import".to_string(),
                header_value_mint: None,
            },
        )
        .with_request_id(RequestId::new())
    }

    fn bait_action(session_id: SessionId) -> Event {
        bait_action_with(session_id, "rel_2025_04_b7f2", Some("exp-1"))
    }

    fn bait_action_with(session_id: SessionId, bait_id: &str, exposure_id: Option<&str>) -> Event {
        Event::new(
            session_id,
            EventSource::BaitEngine,
            PolicyState::Observe,
            EventKind::BaitActionObserved {
                bait_id: BaitId(bait_id.to_string()),
                bait_class: Some(BaitClass::Docs),
                exposure_id: exposure_id.map(|exposure_id| ExposureId(exposure_id.to_string())),
                method: "POST".to_string(),
                path: "/api/v2/import/reconcile".to_string(),
                header_value_mint: None,
                header_value_mint_status: None,
            },
        )
        .with_request_id(RequestId::new())
    }

    fn with_bait_class(mut event: Event, bait_class: Option<BaitClass>) -> Event {
        match &mut event.kind {
            EventKind::BaitExposed {
                bait_class: event_class,
                ..
            }
            | EventKind::BaitActionObserved {
                bait_class: event_class,
                ..
            } => *event_class = bait_class,
            other => panic!("expected bait event, got {other:?}"),
        }
        event
    }

    fn request_for_bait_event(event: &Event, routing_decision: RoutingDecision) -> Event {
        let request_id = event
            .request_id
            .expect("bait test events must carry request ids");
        let (method, path) = match &event.kind {
            EventKind::BaitExposed { surface, .. } => ("GET", surface.as_str()),
            EventKind::BaitActionObserved { method, path, .. } => (method.as_str(), path.as_str()),
            other => panic!("expected bait event, got {other:?}"),
        };

        request_seen_with(event.session_id, request_id, method, path, routing_decision)
    }

    fn confirmed_chain(exposure: Event, action: Event) -> Vec<Event> {
        vec![
            request_for_bait_event(&exposure, RoutingDecision::ProtectedUpstream),
            exposure,
            request_for_bait_event(&action, RoutingDecision::EidolonOwned),
            action,
        ]
    }

    fn request_seen_with(
        session_id: SessionId,
        request_id: RequestId,
        method: &str,
        path: &str,
        routing_decision: RoutingDecision,
    ) -> Event {
        Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::Observe,
            EventKind::RequestSeen {
                method: method.to_string(),
                path: path.to_string(),
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
        .with_request_id(request_id)
    }

    fn request_seen(session_id: SessionId, path: &str) -> Event {
        Event::new(
            session_id,
            EventSource::Proxy,
            PolicyState::Observe,
            EventKind::RequestSeen {
                method: "POST".to_string(),
                path: path.to_string(),
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
    }

    #[test]
    fn exact_bait_chain_is_confirmed() {
        let session_id = SessionId::new();
        let score = score_timeline(&timeline(confirmed_chain(
            bait_exposed(session_id),
            bait_action(session_id),
        )));

        assert_eq!(score.points, 85);
        assert_eq!(score.confidence, ConfidenceBand::ConfirmedBaitDerivedChain);
        assert_eq!(score.reasons.len(), 2);
        assert!(score.reasons[0].contains("controlled bait was exposed"));
    }

    #[test]
    fn exact_exposure_with_upstream_action_routing_explains_boundary_failure() {
        let session_id = SessionId::new();
        let exposure = bait_exposed(session_id);
        let action = bait_action(session_id);
        let score = score_timeline(&timeline(vec![
            request_for_bait_event(&exposure, RoutingDecision::ProtectedUpstream),
            exposure,
            request_for_bait_event(&action, RoutingDecision::ProtectedUpstream),
            action,
        ]));

        assert_eq!(score.points, 55);
        assert_eq!(score.confidence, ConfidenceBand::Medium);
        assert!(score
            .reasons
            .iter()
            .any(|reason| reason.contains("not held Eidolon-owned")));
        assert!(!score
            .reasons
            .iter()
            .any(|reason| reason.contains("without a matching recorded exposure")));
    }

    #[test]
    fn legacy_requestless_classless_events_remain_visible_but_unconfirmed() {
        let session_id = SessionId::new();
        let mut exposure = with_bait_class(bait_exposed(session_id), None);
        exposure.request_id = None;
        let mut action = with_bait_class(bait_action(session_id), None);
        action.request_id = None;
        let bundle = collect_evidence(&timeline(vec![exposure, action]));
        let score = score_evidence(&bundle);

        assert_eq!(bundle.bait_exposures.len(), 1);
        assert!(bundle.matched_actions.is_empty());
        assert_eq!(bundle.unmatched_actions.len(), 1);
        assert_eq!(score.points, 55);
        assert_eq!(score.confidence, ConfidenceBand::Medium);
        assert_ne!(score.confidence, ConfidenceBand::ConfirmedBaitDerivedChain);
    }

    #[test]
    fn exact_ids_with_mismatched_classes_are_not_confirmed() {
        let session_id = SessionId::new();
        let score = score_timeline(&timeline(confirmed_chain(
            with_bait_class(bait_exposed(session_id), Some(BaitClass::Docs)),
            with_bait_class(bait_action(session_id), Some(BaitClass::HiddenRoute)),
        )));

        assert_eq!(score.points, 55);
        assert_eq!(score.confidence, ConfidenceBand::Medium);
        assert_ne!(score.confidence, ConfidenceBand::ConfirmedBaitDerivedChain);
        assert!(score
            .reasons
            .iter()
            .any(|reason| reason.contains("without a matching recorded exposure")));
    }

    #[test]
    fn exposure_without_action_scores_low() {
        let session_id = SessionId::new();
        let score = score_timeline(&timeline(vec![bait_exposed(session_id)]));

        assert_eq!(score.points, 15);
        assert_eq!(score.confidence, ConfidenceBand::Low);
    }

    #[test]
    fn action_without_exposure_is_medium_not_confirmed() {
        let session_id = SessionId::new();
        let score = score_timeline(&timeline(vec![bait_action(session_id)]));

        assert_eq!(score.points, 40);
        assert_eq!(score.confidence, ConfidenceBand::Medium);
        assert!(score.reasons[0].contains("without a matching"));
    }

    #[test]
    fn same_bait_action_after_exposure_with_missing_id_is_high_not_confirmed() {
        let session_id = SessionId::new();
        let score = score_timeline(&timeline(vec![
            bait_exposed(session_id),
            bait_action_with(session_id, "rel_2025_04_b7f2", None),
        ]));

        assert_eq!(score.points, 65);
        assert_eq!(score.confidence, ConfidenceBand::High);
        assert!(score.reasons[1].contains("correlation identifiers did not match"));
    }

    fn minted_action_with(
        session_id: SessionId,
        exposure_id: Option<&str>,
        status: Option<eidolon_core::BaitHeaderValueMintStatus>,
    ) -> Event {
        Event::new(
            session_id,
            EventSource::BaitEngine,
            PolicyState::Observe,
            EventKind::BaitActionObserved {
                bait_id: BaitId("rel_2025_04_b7f2".to_string()),
                bait_class: Some(BaitClass::Docs),
                exposure_id: exposure_id.map(|id| ExposureId(id.to_string())),
                method: "POST".to_string(),
                path: "/api/v2/import/reconcile".to_string(),
                header_value_mint: Some(mint_audit()),
                header_value_mint_status: status,
            },
        )
        .with_request_id(RequestId::new())
    }

    fn mint_audit() -> eidolon_core::BaitHeaderValueMintAudit {
        eidolon_core::BaitHeaderValueMintAudit {
            header_name: "X-Trace".to_string(),
            kind: eidolon_core::HeaderValueMintKind::SessionHmacSha256V1,
            prefix: "test".to_string(),
        }
    }

    fn minted_exposure(session_id: SessionId, bait_id: &str, exposure_id: &str) -> Event {
        Event::new(
            session_id,
            EventSource::SurfaceController,
            PolicyState::Observe,
            EventKind::BaitExposed {
                bait_id: BaitId(bait_id.to_string()),
                bait_class: Some(BaitClass::Docs),
                exposure_id: ExposureId(exposure_id.to_string()),
                surface: "/docs/legacy-import".to_string(),
                header_value_mint: Some(mint_audit()),
            },
        )
        .with_request_id(RequestId::new())
    }

    #[test]
    fn replayed_proof_after_exposure_scores_no_confirmed_chain() {
        let session_id = SessionId::new();
        let score = score_timeline(&timeline(confirmed_chain(
            minted_exposure(session_id, "rel_2025_04_b7f2", "exp-1"),
            minted_action_with(
                session_id,
                Some("exp-1"),
                Some(eidolon_core::BaitHeaderValueMintStatus::ReplaySeen),
            ),
        )));

        assert_eq!(score.points, 15);
        assert_eq!(score.confidence, ConfidenceBand::Low);
        assert!(score
            .reasons
            .iter()
            .any(|reason| reason.contains("excluded from confirmed evidence and scoring")));
    }

    #[test]
    fn expired_proof_after_exposure_scores_no_confirmed_chain() {
        let session_id = SessionId::new();
        let score = score_timeline(&timeline(confirmed_chain(
            minted_exposure(session_id, "rel_2025_04_b7f2", "exp-1"),
            minted_action_with(
                session_id,
                Some("exp-1"),
                Some(eidolon_core::BaitHeaderValueMintStatus::ExpiredSessionValue),
            ),
        )));

        assert_eq!(score.points, 15);
        assert_eq!(score.confidence, ConfidenceBand::Low);
        assert!(score
            .reasons
            .iter()
            .any(|reason| reason.contains("excluded from confirmed evidence and scoring")));
    }

    #[test]
    fn mismatched_proof_after_exposure_scores_no_confirmed_chain() {
        let session_id = SessionId::new();
        let score = score_timeline(&timeline(confirmed_chain(
            minted_exposure(session_id, "rel_2025_04_b7f2", "exp-1"),
            minted_action_with(
                session_id,
                Some("exp-1"),
                Some(eidolon_core::BaitHeaderValueMintStatus::SessionValueMismatch),
            ),
        )));

        assert_eq!(score.points, 15);
        assert_eq!(score.confidence, ConfidenceBand::Low);
        assert!(score
            .reasons
            .iter()
            .any(|reason| reason.contains("excluded from confirmed evidence and scoring")));
    }

    #[test]
    fn unknown_mint_status_after_exposure_is_medium_not_confirmed() {
        let session_id = SessionId::new();
        let score = score_timeline(&timeline(confirmed_chain(
            minted_exposure(session_id, "rel_2025_04_b7f2", "exp-1"),
            minted_action_with(session_id, Some("exp-1"), None),
        )));

        assert_eq!(score.points, 55);
        assert_eq!(score.confidence, ConfidenceBand::Medium);
        assert_ne!(score.confidence, ConfidenceBand::ConfirmedBaitDerivedChain);
        assert!(score
            .reasons
            .iter()
            .any(|reason| reason.contains("unverifiable")));
    }

    #[test]
    fn mixed_session_confirms_from_accepted_proof_and_flags_rejected() {
        let session_id = SessionId::new();
        let mut minted_exposure = minted_exposure(session_id, "minted-trace", "exp-minted");
        let EventKind::BaitExposed { surface, .. } = &mut minted_exposure.kind else {
            panic!("expected bait exposure");
        };
        *surface = "/docs/minted-trace".to_string();
        let replayed_action = Event::new(
            session_id,
            EventSource::BaitEngine,
            PolicyState::Observe,
            EventKind::BaitActionObserved {
                bait_id: BaitId("minted-trace".to_string()),
                bait_class: Some(BaitClass::Docs),
                exposure_id: Some(ExposureId("exp-minted".to_string())),
                method: "POST".to_string(),
                path: "/api/v2/import/reconcile".to_string(),
                header_value_mint: Some(mint_audit()),
                header_value_mint_status: Some(eidolon_core::BaitHeaderValueMintStatus::ReplaySeen),
            },
        )
        .with_request_id(RequestId::new());
        let mut events = confirmed_chain(minted_exposure, replayed_action);
        events.extend(confirmed_chain(
            bait_exposed(session_id),
            bait_action(session_id),
        ));
        let score = score_timeline(&timeline(events));

        assert_eq!(score.points, 85);
        assert_eq!(score.confidence, ConfidenceBand::ConfirmedBaitDerivedChain);
        assert!(score
            .reasons
            .iter()
            .any(|reason| reason.contains("matching bait-derived evidence")));
        assert!(score
            .reasons
            .iter()
            .any(|reason| reason.contains("excluded from confirmed evidence and scoring")));
    }

    #[test]
    fn wrong_session_exposure_and_action_are_not_confirmed() {
        let score = score_events(&[
            bait_exposed(SessionId::new()),
            bait_action(SessionId::new()),
        ]);

        assert_eq!(score.points, 40);
        assert_eq!(score.confidence, ConfidenceBand::Medium);
        assert!(score.reasons[0].contains("without a matching"));
    }

    #[test]
    fn action_before_exposure_is_not_confirmed_or_high() {
        let session_id = SessionId::new();
        let score = score_timeline(&timeline(vec![
            bait_action(session_id),
            bait_exposed(session_id),
        ]));

        assert_eq!(score.points, 55);
        assert_eq!(score.confidence, ConfidenceBand::Medium);
        assert!(score.reasons[1].contains("without a matching"));
    }

    #[test]
    fn mismatched_exposure_id_is_high_but_not_confirmed() {
        let session_id = SessionId::new();
        let score = score_timeline(&timeline(vec![
            bait_exposed_with(session_id, "rel_2025_04_b7f2", "exp-1"),
            bait_action_with(session_id, "rel_2025_04_b7f2", Some("exp-2")),
        ]));

        assert_eq!(score.confidence, ConfidenceBand::High);
    }

    #[test]
    fn mismatched_bait_id_is_medium_not_high() {
        let session_id = SessionId::new();
        let score = score_timeline(&timeline(vec![
            bait_exposed_with(session_id, "rel_2025_04_b7f2", "exp-1"),
            bait_action_with(session_id, "different", Some("exp-1")),
        ]));

        assert_eq!(score.confidence, ConfidenceBand::Medium);
    }

    #[test]
    fn sham_surface_without_bait_exposure_scores_low() {
        let session_id = SessionId::new();
        let score = score_timeline(&timeline(vec![
            request_seen(session_id, "/docs/sham-import"),
            request_seen(session_id, "/api/v2/import/reconcile"),
        ]));

        assert_eq!(score.points, 0);
        assert_eq!(score.confidence, ConfidenceBand::Low);
        assert!(score.reasons.is_empty());
    }

    #[test]
    fn near_miss_request_does_not_score() {
        let session_id = SessionId::new();
        let score = score_timeline(&timeline(vec![request_seen(
            session_id,
            "/api/v2/import/reconcile",
        )]));

        assert_eq!(score.points, 0);
        assert_eq!(score.confidence, ConfidenceBand::Low);
        assert!(score.reasons.is_empty());
    }

    #[test]
    fn score_timelines_returns_strongest_session_score() {
        let exposed_session = SessionId::new();
        let confirmed_session = SessionId::new();
        let timelines = vec![
            timeline(vec![bait_exposed(exposed_session)]),
            timeline(confirmed_chain(
                bait_exposed(confirmed_session),
                bait_action(confirmed_session),
            )),
        ];

        let score = score_timelines(&timelines);

        assert_eq!(score.confidence, ConfidenceBand::ConfirmedBaitDerivedChain);
    }

    #[test]
    fn score_timelines_uses_points_as_tie_breaker_within_confidence_band() {
        let action_only_session = SessionId::new();
        let action_before_exposure_session = SessionId::new();
        let timelines = vec![
            timeline(vec![bait_action(action_only_session)]),
            timeline(vec![
                bait_action(action_before_exposure_session),
                bait_exposed(action_before_exposure_session),
            ]),
        ];

        let score = score_timelines(&timelines);

        assert_eq!(score.confidence, ConfidenceBand::Medium);
        assert_eq!(score.points, 55);
    }

    #[test]
    fn confidence_rank_order_is_stable_for_timeline_selection() {
        assert!(
            confidence_rank(ConfidenceBand::ConfirmedBaitDerivedChain)
                > confidence_rank(ConfidenceBand::High)
        );
        assert!(confidence_rank(ConfidenceBand::High) > confidence_rank(ConfidenceBand::Medium));
        assert!(confidence_rank(ConfidenceBand::Medium) > confidence_rank(ConfidenceBand::Low));
    }
}
