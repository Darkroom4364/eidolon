use std::{
    collections::BTreeSet,
    fs, io,
    path::{Component, Path},
};

use eidolon_proxy::production_runtime::fuzzing::{
    evaluate_both, AcceptedRequest, ConnectionOutcome, DriverError, Observation, RequestOutcome,
    MAX_FUZZ_INPUT_BYTES,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const MANIFEST_BYTES: &[u8] = include_bytes!("../corpus/production_http1_request.json");
const EXPECTED_SCHEMA: &str = "eidolon.production-http1-corpus/v1";
const EXPECTED_TARGET: &str = "production_http1_request";
const CORPUS_PREFIX: &str = "corpus/production_http1_request";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    target: String,
    max_input_bytes: usize,
    seeds: Vec<Seed>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Seed {
    name: String,
    file: String,
    sha256: String,
    expected: ExpectedObservation,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedObservation {
    request_kind: String,
    policy_rejection: Option<String>,
    accepted: Option<ExpectedAcceptedRequest>,
    connection_kind: String,
    transport_rejection: Option<String>,
    response_sha256: String,
    response_length: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedAcceptedRequest {
    method: String,
    canonical_target: String,
    version: String,
    headers: Vec<[String; 2]>,
    body_hex: String,
}

#[derive(Debug, PartialEq, Eq)]
enum VerificationError {
    ManifestJson,
    ManifestIdentity,
    EmptyCorpus,
    CorpusRead,
    CorpusFileSet,
    InvalidSeedName(String),
    DuplicateSeedName(String),
    DuplicateSeedFile(String),
    InvalidSeedPath(String),
    SeedRead(String),
    SeedDigest(String),
    SeedTooLarge(String),
    InvalidExpectedOutcome(String),
    Driver { name: String, error: DriverError },
    DifferentialMismatch(String),
    OutcomeMismatch(String),
}

#[derive(Debug, PartialEq, Eq)]
struct VerificationReport {
    seeds: usize,
    total_bytes: usize,
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            Some(((high << 4) | low) as u8)
        })
        .collect()
}

fn valid_seed_path(name: &str, file: &str) -> bool {
    let path = Path::new(file);
    let expected_file_name = format!("{name}.raw");
    !path.is_absolute()
        && path.starts_with(CORPUS_PREFIX)
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && path.file_name().and_then(|value| value.to_str()) == Some(expected_file_name.as_str())
}

fn expected_contract_is_valid(expected: &ExpectedObservation) -> bool {
    let request_valid = match expected.request_kind.as_str() {
        "no_complete_request" | "client_disconnected" => {
            expected.policy_rejection.is_none() && expected.accepted.is_none()
        }
        "policy_rejected" => {
            expected
                .policy_rejection
                .as_deref()
                .is_some_and(|value| !value.is_empty())
                && expected.accepted.is_none()
        }
        "accepted" => {
            expected.policy_rejection.is_none()
                && expected.accepted.as_ref().is_some_and(|accepted| {
                    decode_hex(&accepted.body_hex).is_some()
                        && !accepted.method.is_empty()
                        && !accepted.version.is_empty()
                })
        }
        _ => false,
    };
    let connection_valid = match expected.connection_kind.as_str() {
        "clean" | "incomplete" | "other_transport_failure" => {
            expected.transport_rejection.is_none()
        }
        "pre_service_rejected" => expected
            .transport_rejection
            .as_deref()
            .is_some_and(|value| !value.is_empty()),
        _ => false,
    };
    request_valid
        && connection_valid
        && expected.response_sha256.len() == 64
        && expected
            .response_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn accepted_matches(expected: &ExpectedAcceptedRequest, actual: &AcceptedRequest) -> bool {
    let Some(body) = decode_hex(&expected.body_hex) else {
        return false;
    };
    expected.method == actual.method
        && expected.canonical_target == actual.target
        && expected.version == actual.version
        && expected.headers.len() == actual.headers.len()
        && expected
            .headers
            .iter()
            .zip(&actual.headers)
            .all(|(expected, actual)| expected[0] == actual.0 && expected[1] == actual.1)
        && body == actual.body
}

fn observation_matches(expected: &ExpectedObservation, actual: &Observation) -> bool {
    let request_matches = match (
        expected.request_kind.as_str(),
        expected.policy_rejection.as_deref(),
        expected.accepted.as_ref(),
        &actual.request,
    ) {
        ("no_complete_request", None, None, RequestOutcome::NoCompleteRequest) => true,
        ("client_disconnected", None, None, RequestOutcome::ClientDisconnected) => true,
        ("policy_rejected", Some(expected), None, RequestOutcome::PolicyRejected(actual)) => {
            expected == actual.audit_code()
        }
        ("accepted", None, Some(expected), RequestOutcome::Accepted(actual)) => {
            accepted_matches(expected, actual)
        }
        _ => false,
    };
    let connection_matches = match (
        expected.connection_kind.as_str(),
        expected.transport_rejection.as_deref(),
        actual.connection,
    ) {
        ("clean", None, ConnectionOutcome::Clean)
        | ("incomplete", None, ConnectionOutcome::Incomplete)
        | ("other_transport_failure", None, ConnectionOutcome::OtherTransportFailure) => true,
        ("pre_service_rejected", Some(expected), ConnectionOutcome::PreServiceRejected(actual)) => {
            expected == actual.audit_code()
        }
        _ => false,
    };
    request_matches
        && connection_matches
        && expected.response_length == actual.response_bytes.len()
        && expected.response_sha256 == sha256(&actual.response_bytes)
}

fn verify_manifest_with<F>(
    manifest_bytes: &[u8],
    available_files: &BTreeSet<String>,
    mut load_seed: F,
) -> Result<VerificationReport, VerificationError>
where
    F: FnMut(&str) -> io::Result<Vec<u8>>,
{
    let manifest: Manifest =
        serde_json::from_slice(manifest_bytes).map_err(|_| VerificationError::ManifestJson)?;
    if manifest.schema != EXPECTED_SCHEMA
        || manifest.target != EXPECTED_TARGET
        || manifest.max_input_bytes != MAX_FUZZ_INPUT_BYTES
    {
        return Err(VerificationError::ManifestIdentity);
    }
    if manifest.seeds.is_empty() {
        return Err(VerificationError::EmptyCorpus);
    }

    let mut names = BTreeSet::new();
    let mut files = BTreeSet::new();
    for seed in &manifest.seeds {
        if seed.name.is_empty()
            || !seed
                .name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(VerificationError::InvalidSeedName(seed.name.clone()));
        }
        if !names.insert(seed.name.clone()) {
            return Err(VerificationError::DuplicateSeedName(seed.name.clone()));
        }
        if !files.insert(seed.file.clone()) {
            return Err(VerificationError::DuplicateSeedFile(seed.file.clone()));
        }
        if !valid_seed_path(&seed.name, &seed.file) {
            return Err(VerificationError::InvalidSeedPath(seed.name.clone()));
        }
        if !expected_contract_is_valid(&seed.expected) {
            return Err(VerificationError::InvalidExpectedOutcome(seed.name.clone()));
        }
    }
    if &files != available_files {
        return Err(VerificationError::CorpusFileSet);
    }

    let mut total_bytes = 0_usize;
    for seed in &manifest.seeds {
        let bytes =
            load_seed(&seed.file).map_err(|_| VerificationError::SeedRead(seed.name.clone()))?;
        if sha256(&bytes) != seed.sha256 {
            return Err(VerificationError::SeedDigest(seed.name.clone()));
        }
        if bytes.len() > manifest.max_input_bytes {
            return Err(VerificationError::SeedTooLarge(seed.name.clone()));
        }
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| VerificationError::SeedTooLarge(seed.name.clone()))?;

        let (whole, fragmented) =
            evaluate_both(&bytes).map_err(|error| VerificationError::Driver {
                name: seed.name.clone(),
                error,
            })?;
        if whole != fragmented {
            return Err(VerificationError::DifferentialMismatch(seed.name.clone()));
        }
        if !observation_matches(&seed.expected, &whole) {
            return Err(VerificationError::OutcomeMismatch(seed.name.clone()));
        }
    }
    Ok(VerificationReport {
        seeds: manifest.seeds.len(),
        total_bytes,
    })
}

fn read_checked_seed(path: &str) -> io::Result<Vec<u8>> {
    fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
}

fn checked_corpus_files() -> Result<BTreeSet<String>, VerificationError> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join(CORPUS_PREFIX);
    let entries = fs::read_dir(directory).map_err(|_| VerificationError::CorpusRead)?;
    let mut files = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|_| VerificationError::CorpusRead)?;
        if !entry
            .file_type()
            .map_err(|_| VerificationError::CorpusRead)?
            .is_file()
        {
            return Err(VerificationError::CorpusRead);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| VerificationError::CorpusRead)?;
        files.insert(format!("{CORPUS_PREFIX}/{name}"));
    }
    Ok(files)
}

fn lock_value(block: &str, key: &str) -> Option<String> {
    let prefix = format!("{key} = \"");
    block.lines().find_map(|line| {
        line.strip_prefix(&prefix)
            .and_then(|value| value.strip_suffix('"'))
            .map(str::to_string)
    })
}

fn registry_packages(lockfile: &Path) -> BTreeSet<(String, String, String)> {
    let lockfile = fs::read_to_string(lockfile).expect("candidate lockfile should be readable");
    lockfile
        .split("[[package]]")
        .skip(1)
        .filter_map(|block| {
            let source = lock_value(block, "source")?;
            if !source.starts_with("registry+") {
                return None;
            }
            Some((
                lock_value(block, "name").expect("registry package should have a name"),
                lock_value(block, "version").expect("registry package should have a version"),
                source,
            ))
        })
        .collect()
}

#[test]
fn corpus_manifest_digests_and_dual_schedule_outcomes_match() {
    let available_files = checked_corpus_files().expect("checked-in corpus should be readable");
    let report = verify_manifest_with(MANIFEST_BYTES, &available_files, read_checked_seed)
        .expect("checked-in corpus must match its strict manifest and production outcomes");
    assert_eq!(report.seeds, 12);
    assert_eq!(report.total_bytes, 1_077);
}

#[test]
fn fuzz_lock_matches_candidate_registry_versions_plus_exact_fuzz_runtime() {
    let fuzz_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let candidate_lock = fuzz_root
        .parent()
        .expect("fuzz workspace should have a repository parent")
        .join("Cargo.lock");
    let registry = "registry+https://github.com/rust-lang/crates.io-index".to_string();
    let mut expected = registry_packages(&candidate_lock);
    expected.extend([
        (
            "arbitrary".to_string(),
            "1.4.2".to_string(),
            registry.clone(),
        ),
        (
            "jobserver".to_string(),
            "0.1.35".to_string(),
            registry.clone(),
        ),
        ("libfuzzer-sys".to_string(), "0.4.13".to_string(), registry),
    ]);
    assert_eq!(
        registry_packages(&fuzz_root.join("Cargo.lock")),
        expected,
        "fuzz/Cargo.lock must preserve every candidate registry version and add only the exact fuzz runtime"
    );
}

#[test]
fn changed_expected_outcome_fails_closed() {
    let available_files = checked_corpus_files().expect("checked-in corpus should be readable");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(MANIFEST_BYTES).expect("checked-in manifest should parse");
    manifest["seeds"][0]["expected"]["accepted"]["canonical_target"] =
        serde_json::Value::String("/changed".to_string());
    let changed = serde_json::to_vec(&manifest).expect("changed manifest should encode");
    assert_eq!(
        verify_manifest_with(&changed, &available_files, read_checked_seed),
        Err(VerificationError::OutcomeMismatch(
            "positive_origin_canonical".to_string()
        ))
    );
}

#[test]
fn changed_seed_byte_fails_before_replay() {
    let available_files = checked_corpus_files().expect("checked-in corpus should be readable");
    let result = verify_manifest_with(MANIFEST_BYTES, &available_files, |path| {
        let mut bytes = read_checked_seed(path)?;
        if path.ends_with("positive_origin_canonical.raw") {
            bytes[0] ^= 1;
        }
        Ok(bytes)
    });
    assert_eq!(
        result,
        Err(VerificationError::SeedDigest(
            "positive_origin_canonical".to_string()
        ))
    );
}

#[test]
fn unmanifested_corpus_file_fails_closed() {
    let mut available_files = checked_corpus_files().expect("checked-in corpus should be readable");
    available_files.insert(format!("{CORPUS_PREFIX}/unmanifested.raw"));
    assert_eq!(
        verify_manifest_with(MANIFEST_BYTES, &available_files, read_checked_seed),
        Err(VerificationError::CorpusFileSet)
    );
}
