mod evidence;
mod reader;
mod report;
mod scoring;
mod timeline;

pub use evidence::{
    evidence_bundle_for_timeline, BaitActionEvidence, BaitExposureEvidence, BaselineComparison,
    ControlledRealityInteractionEvidence, EvidenceBundle, ObservedSurface, PolicyEventEvidence,
    PolicyEvidenceKind, ProofOutcome,
};
pub use reader::{
    read_events_jsonl, read_events_jsonl_file, read_events_jsonl_file_with_archives, TraceReadError,
};
pub use report::{
    edge_decision_export_for_evidence, edge_decision_export_for_timeline, render_evidence_markdown,
    render_markdown_report, render_replay_view,
};
pub use scoring::{score_events, score_evidence, score_timeline, score_timelines};
pub use timeline::{build_session_timelines, SessionTimeline, TimelineEvent, TimelineEventRef};
