mod evidence;
mod reader;
mod report;
mod scoring;
mod timeline;

pub use evidence::{
    evidence_bundle_for_timeline, BaitActionEvidence, BaitExposureEvidence, BaselineComparison,
    EvidenceBundle, ObservedSurface, PolicyEventEvidence, PolicyEvidenceKind,
};
pub use reader::{read_events_jsonl, read_events_jsonl_file, TraceReadError};
pub use report::{render_evidence_markdown, render_markdown_report, render_replay_view};
pub use scoring::{score_events, score_evidence, score_timeline, score_timelines};
pub use timeline::{build_session_timelines, SessionTimeline, TimelineEvent, TimelineEventRef};
