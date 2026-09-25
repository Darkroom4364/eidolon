//! Bounded, offline scoring for synthetic semantic-canary fixtures.
//!
//! This crate accepts caller-supplied bytes only. It does not read files or use
//! network, DNS, callbacks, browser/tool automation, credentials, subprocesses,
//! or runtime-control APIs.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SCHEMA_VERSION: u16 = 1;
pub const SCORER_VERSION: &str = "v1-lexical-baseline";
pub const MAX_CORPUS_BYTES: usize = 64 * 1024;
pub const MAX_CASES: usize = 64;
pub const MAX_ID_BYTES: usize = 64;
pub const MAX_TEXT_BYTES: usize = 1024;

pub const CANONICAL_CORPUS: &[u8] = include_bytes!("../fixtures/semantic-canary-v1.json");
pub const HELD_OUT_CORPUS: &[u8] = include_bytes!("../fixtures/semantic-canary-heldout-v1.json");
pub const QUALIFICATION_REPETITIONS: u8 = 3;
pub const QUALIFICATION_FIXED_SEED: u64 = 0x5345_4d43_414e_4152;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusInput {
    schema_version: u16,
    corpus_version: String,
    cases: Vec<CaseInput>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseInput {
    id: String,
    class: FixtureClass,
    reference: String,
    candidate: String,
    expected: Decision,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureClass {
    Equivalent,
    Contradiction,
    LexicalOverlapHardNegative,
    BenignNearNeighbor,
    ExactCopy,
    Unrelated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Equivalent,
    Contradiction,
    Unrelated,
    Abstain,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CaseResult {
    pub id: String,
    pub class: FixtureClass,
    pub expected: Decision,
    pub observed: Decision,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BenchmarkReport {
    pub schema_version: u16,
    pub scorer_version: &'static str,
    pub corpus_version: String,
    pub corpus_sha256: String,
    pub cases_scored: u32,
    pub abstained: u32,
    pub confusion: BTreeMap<Decision, BTreeMap<Decision, u32>>,
    pub class_confusion: BTreeMap<FixtureClass, BTreeMap<Decision, u32>>,
    pub results: Vec<CaseResult>,
}

/// Summary-only artifact intended for qualification export. It deliberately has
/// no fixture text, candidate text, or per-case identifiers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BenchmarkSummary {
    pub schema_version: u16,
    pub scorer_version: &'static str,
    pub corpus_version: String,
    pub corpus_sha256: String,
    pub cases_scored: u32,
    pub abstained: u32,
    pub confusion: BTreeMap<Decision, BTreeMap<Decision, u32>>,
    pub class_confusion: BTreeMap<FixtureClass, BTreeMap<Decision, u32>>,
    pub limitations: [&'static str; 3],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QualificationReport {
    pub fixed_seed: u64,
    pub repetitions: u8,
    pub held_out: bool,
    pub summary: BenchmarkSummary,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BenchmarkError {
    CorpusTooLarge { actual: usize, maximum: usize },
    InvalidJson(String),
    UnsupportedSchema { actual: u16 },
    InvalidCorpusVersion,
    TooManyCases { actual: usize, maximum: usize },
    InvalidCase { id: String, reason: &'static str },
}

impl std::fmt::Display for BenchmarkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CorpusTooLarge { actual, maximum } => {
                write!(f, "corpus is {actual} bytes; maximum is {maximum}")
            }
            Self::InvalidJson(error) => write!(f, "invalid corpus JSON: {error}"),
            Self::UnsupportedSchema { actual } => write!(f, "unsupported schema version: {actual}"),
            Self::InvalidCorpusVersion => f.write_str("invalid corpus version"),
            Self::TooManyCases { actual, maximum } => {
                write!(f, "corpus has {actual} cases; maximum is {maximum}")
            }
            Self::InvalidCase { id, reason } => write!(f, "invalid case {id:?}: {reason}"),
        }
    }
}

impl std::error::Error for BenchmarkError {}

/// Parses and deterministically scores a bounded, synthetic corpus.
pub fn score_corpus_json(input: &[u8]) -> Result<BenchmarkReport, BenchmarkError> {
    if input.len() > MAX_CORPUS_BYTES {
        return Err(BenchmarkError::CorpusTooLarge {
            actual: input.len(),
            maximum: MAX_CORPUS_BYTES,
        });
    }
    let corpus: CorpusInput = serde_json::from_slice(input)
        .map_err(|error| BenchmarkError::InvalidJson(error.to_string()))?;
    if corpus.schema_version != SCHEMA_VERSION {
        return Err(BenchmarkError::UnsupportedSchema {
            actual: corpus.schema_version,
        });
    }
    if !valid_identifier(&corpus.corpus_version, MAX_ID_BYTES) {
        return Err(BenchmarkError::InvalidCorpusVersion);
    }
    if corpus.cases.len() > MAX_CASES {
        return Err(BenchmarkError::TooManyCases {
            actual: corpus.cases.len(),
            maximum: MAX_CASES,
        });
    }

    let mut ids = BTreeSet::new();
    let mut confusion = BTreeMap::<Decision, BTreeMap<Decision, u32>>::new();
    let mut class_confusion = BTreeMap::<FixtureClass, BTreeMap<Decision, u32>>::new();
    let mut results = Vec::with_capacity(corpus.cases.len());
    let mut abstained = 0;
    for case in corpus.cases {
        validate_case(&case, &mut ids)?;
        let observed = classify(&case.reference, &case.candidate);
        if observed == Decision::Abstain {
            abstained += 1;
        }
        *confusion
            .entry(case.expected)
            .or_default()
            .entry(observed)
            .or_default() += 1;
        *class_confusion
            .entry(case.class)
            .or_default()
            .entry(observed)
            .or_default() += 1;
        results.push(CaseResult {
            id: case.id,
            class: case.class,
            expected: case.expected,
            observed,
        });
    }
    Ok(BenchmarkReport {
        schema_version: SCHEMA_VERSION,
        scorer_version: SCORER_VERSION,
        corpus_version: corpus.corpus_version,
        corpus_sha256: hex_digest(input),
        cases_scored: results.len() as u32,
        abstained,
        confusion,
        class_confusion,
        results,
    })
}

/// Produces a summary-only artifact. No raw fixture or prediction text is exported.
pub fn summarize_report(report: &BenchmarkReport) -> BenchmarkSummary {
    BenchmarkSummary {
        schema_version: report.schema_version,
        scorer_version: report.scorer_version,
        corpus_version: report.corpus_version.clone(),
        corpus_sha256: report.corpus_sha256.clone(),
        cases_scored: report.cases_scored,
        abstained: report.abstained,
        confusion: report.confusion.clone(),
        class_confusion: report.class_confusion.clone(),
        limitations: [
            "offline synthetic benchmark inference only",
            "not runtime causal evidence, routing, containment, or policy input",
            "not actor, model, vendor, intent, autonomy, or maliciousness attribution",
        ],
    }
}

/// Serializes a summary-only artifact without raw fixture/prediction text.
pub fn export_report_summary_json(report: &BenchmarkReport) -> Result<Vec<u8>, BenchmarkError> {
    serde_json::to_vec_pretty(&summarize_report(report))
        .map_err(|error| BenchmarkError::InvalidJson(error.to_string()))
}

/// Repeats deterministic scoring of the checked-in held-out corpus under a
/// documented fixed seed. The lexical baseline consumes no randomness; the seed
/// is qualification metadata that pins future compatible scorer runs.
pub fn qualify_held_out() -> Result<QualificationReport, BenchmarkError> {
    let first = score_corpus_json(HELD_OUT_CORPUS)?;
    for _ in 1..QUALIFICATION_REPETITIONS {
        if score_corpus_json(HELD_OUT_CORPUS)? != first {
            return Err(BenchmarkError::InvalidJson(
                "non-deterministic qualification result".to_owned(),
            ));
        }
    }
    Ok(QualificationReport {
        fixed_seed: QUALIFICATION_FIXED_SEED,
        repetitions: QUALIFICATION_REPETITIONS,
        held_out: true,
        summary: summarize_report(&first),
    })
}

fn validate_case(case: &CaseInput, ids: &mut BTreeSet<String>) -> Result<(), BenchmarkError> {
    let invalid = |reason| BenchmarkError::InvalidCase {
        id: case.id.clone(),
        reason,
    };
    if !valid_identifier(&case.id, MAX_ID_BYTES) || !ids.insert(case.id.clone()) {
        return Err(invalid("id must be unique ASCII slug"));
    }
    if case.reference.is_empty() || case.candidate.is_empty() {
        return Err(invalid("text must not be empty"));
    }
    if case.reference.len() > MAX_TEXT_BYTES || case.candidate.len() > MAX_TEXT_BYTES {
        return Err(invalid("text exceeds byte limit"));
    }
    if !safe_synthetic_text(&case.reference) || !safe_synthetic_text(&case.candidate) {
        return Err(invalid("text violates synthetic fixture policy"));
    }
    let aligned = match case.class {
        FixtureClass::Equivalent | FixtureClass::ExactCopy => case.expected == Decision::Equivalent,
        FixtureClass::Contradiction => case.expected == Decision::Contradiction,
        FixtureClass::LexicalOverlapHardNegative | FixtureClass::BenignNearNeighbor => {
            case.expected == Decision::Abstain
        }
        FixtureClass::Unrelated => case.expected == Decision::Unrelated,
    };
    if !aligned {
        return Err(invalid("class and expected decision disagree"));
    }
    Ok(())
}

fn valid_identifier(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
}

fn safe_synthetic_text(value: &str) -> bool {
    value.is_ascii()
        && !value.contains("http://")
        && !value.contains("https://")
        && !value.contains('@')
        && !value.contains("secret")
        && !value.contains("password")
}

fn classify(reference: &str, candidate: &str) -> Decision {
    if normalize(reference) == normalize(candidate) {
        return Decision::Equivalent;
    }
    let left = tokens(reference);
    let right = tokens(candidate);
    if left.is_empty() || right.is_empty() {
        return Decision::Abstain;
    }
    let overlap = left.intersection(&right).count();
    let smaller = left.len().min(right.len());
    let negated = contains_negation(candidate);
    if negated && overlap * 2 >= smaller {
        return Decision::Contradiction;
    }
    if overlap == 0 {
        return Decision::Unrelated;
    }
    if overlap * 4 >= smaller * 3 {
        return Decision::Equivalent;
    }
    Decision::Abstain
}

fn normalize(value: &str) -> String {
    tokens(value).into_iter().collect::<Vec<_>>().join(" ")
}
fn tokens(value: &str) -> BTreeSet<String> {
    value
        .to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|word| {
            !word.is_empty()
                && !matches!(
                    *word,
                    "a" | "an"
                        | "the"
                        | "after"
                        | "before"
                        | "with"
                        | "and"
                        | "or"
                        | "is"
                        | "are"
                        | "local"
                )
        })
        .map(str::to_owned)
        .collect()
}
fn contains_negation(value: &str) -> bool {
    tokens(value).contains("not") || tokens(value).contains("never") || tokens(value).contains("no")
}
fn hex_digest(input: &[u8]) -> String {
    Sha256::digest(input)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_corpus_scores_deterministically() {
        let first = score_corpus_json(CANONICAL_CORPUS).unwrap();
        let second = score_corpus_json(CANONICAL_CORPUS).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.cases_scored, 5);
        assert_eq!(first.abstained, 2);
        assert!(first
            .results
            .iter()
            .all(|result| result.expected == result.observed));
        assert_eq!(first.corpus_sha256.len(), 64);
    }
    #[test]
    fn held_out_qualification_is_repeated_separate_and_exact() {
        let canonical = score_corpus_json(CANONICAL_CORPUS).unwrap();
        let held_out = score_corpus_json(HELD_OUT_CORPUS).unwrap();
        let qualification = qualify_held_out().unwrap();
        assert_ne!(canonical.corpus_sha256, held_out.corpus_sha256);
        assert_eq!(held_out.corpus_version, "heldout_v1");
        assert_eq!(held_out.cases_scored, 6);
        assert!(held_out
            .results
            .iter()
            .all(|result| result.expected == result.observed));
        assert_eq!(qualification.fixed_seed, QUALIFICATION_FIXED_SEED);
        assert_eq!(qualification.repetitions, QUALIFICATION_REPETITIONS);
        assert!(qualification.held_out);
        assert_eq!(qualification.summary, summarize_report(&held_out));
        let canonical_ids: BTreeSet<_> =
            canonical.results.iter().map(|result| &result.id).collect();
        assert!(held_out
            .results
            .iter()
            .all(|result| !canonical_ids.contains(&result.id)));
    }
    #[test]
    fn summary_export_has_no_raw_text_or_case_identifiers() {
        let report = score_corpus_json(HELD_OUT_CORPUS).unwrap();
        let export = String::from_utf8(export_report_summary_json(&report).unwrap()).unwrap();
        for forbidden in [
            "reference",
            "candidate",
            "results",
            "heldout_equivalent_reordered",
            "Synthetic kiln",
            "amber tiles",
        ] {
            assert!(!export.contains(forbidden), "export leaked {forbidden:?}");
        }
        assert!(export.contains("corpus_sha256"));
        assert!(export.contains("limitations"));
        assert!(export.contains("heldout_v1"));
    }
    #[test]
    fn rejects_checked_in_invalid_controls() {
        assert!(matches!(
            score_corpus_json(include_bytes!("../fixtures/invalid/malformed.json")),
            Err(BenchmarkError::InvalidJson(_))
        ));
        assert!(matches!(
            score_corpus_json(include_bytes!("../fixtures/invalid/unknown-schema.json")),
            Err(BenchmarkError::UnsupportedSchema { .. })
        ));
        assert!(matches!(
            score_corpus_json(include_bytes!("../fixtures/invalid/unknown-field.json")),
            Err(BenchmarkError::InvalidJson(_))
        ));
        assert!(matches!(
            score_corpus_json(include_bytes!("../fixtures/invalid/oversize-text.json")),
            Err(BenchmarkError::InvalidCase { .. })
        ));
    }
    #[test]
    fn rejects_bounds_and_unsafe_text() {
        assert!(matches!(
            score_corpus_json(&vec![b'x'; MAX_CORPUS_BYTES + 1]),
            Err(BenchmarkError::CorpusTooLarge { .. })
        ));
        let unsafe_case = br#"{"schema_version":1,"corpus_version":"v1","cases":[{"id":"unsafe","class":"equivalent","reference":"https://example.test","candidate":"https://example.test","expected":"equivalent"}]}"#;
        assert!(matches!(
            score_corpus_json(unsafe_case),
            Err(BenchmarkError::InvalidCase { .. })
        ));
    }
    #[test]
    fn crate_dependencies_remain_capability_allowlisted() {
        let manifest = include_str!("../Cargo.toml");
        for forbidden in [
            "eidolon-proxy",
            "eidolon-trace",
            "eidolon-bait",
            "eidolon-core",
            "hyper",
            "tokio",
            "reqwest",
            "dns",
            "browser",
            "webdriver",
            "command",
            "subprocess",
            "credential",
        ] {
            assert!(
                !manifest.contains(forbidden),
                "forbidden dependency: {forbidden}"
            );
        }
        for allowed in ["serde.workspace", "serde_json.workspace", "sha2.workspace"] {
            assert!(manifest.contains(allowed));
        }
    }
}
