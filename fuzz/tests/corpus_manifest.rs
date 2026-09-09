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
    if !value.len().is_multiple_of(2) {
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

const CARGO_REGISTRY_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";
const CARGO_LOCK_PREAMBLE: &str = "# This file is automatically @generated by Cargo.\n\
# It is not intended for manual editing.\n\
version = 4\n";

type RegistryPackage = (String, String, String, String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockParityError {
    UnsupportedSyntax,
    RegistrySetMismatch,
}

#[derive(Default)]
struct LockPackage {
    name: Option<String>,
    version: Option<String>,
    source: Option<String>,
    checksum: Option<String>,
    dependencies_seen: bool,
}

fn set_lock_field(field: &mut Option<String>, value: String) -> Result<(), LockParityError> {
    if field.replace(value).is_some() {
        return Err(LockParityError::UnsupportedSyntax);
    }
    Ok(())
}

fn parse_lock_string_assignment(line: &str) -> Result<(&str, String), LockParityError> {
    let (key, encoded) = line
        .split_once(" = ")
        .ok_or(LockParityError::UnsupportedSyntax)?;
    if key.is_empty()
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        return Err(LockParityError::UnsupportedSyntax);
    }
    let value = encoded
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .filter(|value| !value.is_empty() && !value.contains(['"', '\\']))
        .ok_or(LockParityError::UnsupportedSyntax)?;
    Ok((key, value.to_string()))
}

fn finish_lock_package(
    package: Option<LockPackage>,
    registry: &mut BTreeSet<RegistryPackage>,
) -> Result<(), LockParityError> {
    let Some(package) = package else {
        return Ok(());
    };
    let name = package.name.ok_or(LockParityError::UnsupportedSyntax)?;
    let version = package.version.ok_or(LockParityError::UnsupportedSyntax)?;
    match package.source {
        Some(source) if source.starts_with("registry+") => {
            let checksum = package.checksum.ok_or(LockParityError::UnsupportedSyntax)?;
            if registry
                .iter()
                .any(|(existing_name, existing_version, existing_source, _)| {
                    existing_name == &name
                        && existing_version == &version
                        && existing_source == &source
                })
            {
                return Err(LockParityError::UnsupportedSyntax);
            }
            if !registry.insert((name, version, source, checksum)) {
                return Err(LockParityError::UnsupportedSyntax);
            }
        }
        Some(_) | None if package.checksum.is_some() => {
            return Err(LockParityError::UnsupportedSyntax);
        }
        Some(_) | None => {}
    }
    Ok(())
}

fn registry_packages(lockfile: &str) -> Result<BTreeSet<RegistryPackage>, LockParityError> {
    let lockfile = lockfile
        .strip_prefix(CARGO_LOCK_PREAMBLE)
        .ok_or(LockParityError::UnsupportedSyntax)?;
    let mut registry = BTreeSet::new();
    let mut package = None;
    let mut package_count = 0_usize;
    let mut in_dependencies = false;

    for line in lockfile.lines() {
        if in_dependencies {
            if line == "]" {
                in_dependencies = false;
            } else if !(line.starts_with(" \"")
                && line.ends_with("\",")
                && !line[2..line.len() - 2].contains(['"', '\\']))
            {
                return Err(LockParityError::UnsupportedSyntax);
            }
            continue;
        }

        if line.is_empty() {
            continue;
        }
        if line == "[[package]]" {
            finish_lock_package(package.take(), &mut registry)?;
            package = Some(LockPackage::default());
            package_count += 1;
            continue;
        }

        let package = package.as_mut().ok_or(LockParityError::UnsupportedSyntax)?;
        if line == "dependencies = [" {
            if package.dependencies_seen {
                return Err(LockParityError::UnsupportedSyntax);
            }
            package.dependencies_seen = true;
            in_dependencies = true;
            continue;
        }
        let (key, value) = parse_lock_string_assignment(line)?;
        match key {
            "name" => set_lock_field(&mut package.name, value)?,
            "version" => set_lock_field(&mut package.version, value)?,
            "source" => set_lock_field(&mut package.source, value)?,
            "checksum" => set_lock_field(&mut package.checksum, value)?,
            _ => return Err(LockParityError::UnsupportedSyntax),
        }
    }

    if in_dependencies || package_count == 0 {
        return Err(LockParityError::UnsupportedSyntax);
    }
    finish_lock_package(package, &mut registry)?;
    Ok(registry)
}

fn registry_package(name: &str, version: &str, checksum: &str) -> RegistryPackage {
    (
        name.to_string(),
        version.to_string(),
        CARGO_REGISTRY_SOURCE.to_string(),
        checksum.to_string(),
    )
}

fn fuzz_runtime_packages() -> BTreeSet<RegistryPackage> {
    BTreeSet::from([
        registry_package(
            "arbitrary",
            "1.4.2",
            "c3d036a3c4ab069c7b410a2ce876bd74808d2d0888a82667669f8e783a898bf1",
        ),
        registry_package(
            "jobserver",
            "0.1.35",
            "1c00acbd29eabad4a2392fa0e921c874934dbbf4194312ad20f04a0ed67a3cb3",
        ),
        registry_package(
            "libfuzzer-sys",
            "0.4.13",
            "a9fd2f41a1cba099f79a0b6b6c35656cf7c03351a7bae8ff0f28f25270f929d2",
        ),
    ])
}

fn verify_registry_package_parity(
    candidate_lock: &str,
    fuzz_lock: &str,
    allowed_additions: &BTreeSet<RegistryPackage>,
) -> Result<(), LockParityError> {
    let mut expected = registry_packages(candidate_lock)?;
    expected.extend(allowed_additions.iter().cloned());
    if registry_packages(fuzz_lock)? != expected {
        return Err(LockParityError::RegistrySetMismatch);
    }
    Ok(())
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
    let candidate_lock =
        fs::read_to_string(candidate_lock).expect("candidate lockfile should be readable");
    let fuzz_lock =
        fs::read_to_string(fuzz_root.join("Cargo.lock")).expect("fuzz lockfile should be readable");
    verify_registry_package_parity(&candidate_lock, &fuzz_lock, &fuzz_runtime_packages())
        .expect("fuzz/Cargo.lock must preserve every candidate registry identity and add only the exact fuzz runtime");
}

fn test_registry_lock(packages: &[(&str, &str, &str)]) -> String {
    let mut lockfile = String::from(CARGO_LOCK_PREAMBLE);
    for (name, version, checksum) in packages {
        lockfile.push_str(&format!(
            "\n[[package]]\nname = \"{name}\"\nversion = \"{version}\"\nsource = \"{CARGO_REGISTRY_SOURCE}\"\nchecksum = \"{checksum}\"\n"
        ));
    }
    lockfile
}

#[test]
fn lock_parser_rejects_formatting_outside_the_generated_grammar() {
    let lockfile = test_registry_lock(&[("shared", "1.0.0", "abc123")]);
    let indented = lockfile.replacen("source = ", " source = ", 1);
    assert_eq!(
        registry_packages(&indented),
        Err(LockParityError::UnsupportedSyntax)
    );
}

#[test]
fn lock_parser_rejects_duplicate_identity_fields() {
    let lockfile = test_registry_lock(&[("shared", "1.0.0", "abc123")]);
    let duplicate = lockfile.replacen(
        "version = \"1.0.0\"",
        "version = \"1.0.0\"\nversion = \"1.0.0\"",
        1,
    );
    assert_eq!(
        registry_packages(&duplicate),
        Err(LockParityError::UnsupportedSyntax)
    );
}

#[test]
fn lock_parser_rejects_duplicate_registry_package_identity() {
    let lockfile =
        test_registry_lock(&[("shared", "1.0.0", "abc123"), ("shared", "1.0.0", "def456")]);
    assert_eq!(
        registry_packages(&lockfile),
        Err(LockParityError::UnsupportedSyntax)
    );
}

#[test]
fn lock_parity_rejects_an_omitted_candidate_package() {
    let candidate =
        test_registry_lock(&[("first", "1.0.0", "abc123"), ("second", "2.0.0", "def456")]);
    let fuzz = test_registry_lock(&[("first", "1.0.0", "abc123")]);
    assert_eq!(
        verify_registry_package_parity(&candidate, &fuzz, &BTreeSet::new()),
        Err(LockParityError::RegistrySetMismatch)
    );
}

#[test]
fn lock_parity_rejects_registry_identity_drift() {
    let candidate = test_registry_lock(&[("shared", "1.0.0", "abc123")]);
    let fuzz = test_registry_lock(&[("shared", "1.0.1", "abc123")]);
    assert_eq!(
        verify_registry_package_parity(&candidate, &fuzz, &BTreeSet::new()),
        Err(LockParityError::RegistrySetMismatch)
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
