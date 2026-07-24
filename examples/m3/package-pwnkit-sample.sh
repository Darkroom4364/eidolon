#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

SAMPLE_DIR="${1:-}"
FINAL_BUNDLE_DIR="${2:-}"
BUNDLE_DIR=""
STAGING_DIR=""
INPUT_SNAPSHOT_DIR=""

usage() {
  cat <<'USAGE'
Usage: examples/m3/package-pwnkit-sample.sh <sample-dir> <bundle-dir>

Packages a completed examples/m3/run-pwnkit-sample.sh output directory into a
commit-safe M3 evidence bundle reconstructed from typed public allowlists.

Inputs:
  <sample-dir>/pwnkit-stability-sample.json
  <sample-dir>/run-*/pwnkit-summary.json
  <sample-dir>/run-*/agent-replay-trace-summary.json

Outputs:
  <bundle-dir>/README.md
  <bundle-dir>/pwnkit-stability-sample.json
  <bundle-dir>/run-*/pwnkit-summary.redacted.json
  <bundle-dir>/run-*/agent-replay-trace-summary.json
  <bundle-dir>/SHA256SUMS

The public bundle omits unknown fields, raw pwnkit artifacts, commands, URLs,
scope values, session/proof identifiers, free-form notes, and raw event logs.
USAGE
}

fail() {
  echo "error: $*" >&2
  exit 2
}

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    fail "missing required tool: $command_name"
  fi
}

sha256_file() {
  local path="$1"

  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path"
    return
  fi

  shasum -a 256 "$path"
}

validate_single_json_object() {
  local path="$1"
  local label="$2"

  jq -e -s '
    length == 1
    and (.[0] | type == "object")
  ' "$path" >/dev/null || fail "$label must contain exactly one JSON object: $path"
}

validate_run_name() {
  local run_name="$1"

  if [[ ! "$run_name" =~ ^run-[1-9][0-9]*$ ]]; then
    fail "invalid run directory name: $run_name"
  fi
}

ensure_bundle_target_available() {
  if [[ -L "$FINAL_BUNDLE_DIR" ]]; then
    fail "bundle path must not be a symlink: $FINAL_BUNDLE_DIR"
  fi
  if [[ -e "$FINAL_BUNDLE_DIR" && ! -d "$FINAL_BUNDLE_DIR" ]]; then
    fail "bundle path exists and is not a directory: $FINAL_BUNDLE_DIR"
  fi
  if [[ -d "$FINAL_BUNDLE_DIR" ]] \
    && [[ -n "$(find "$FINAL_BUNDLE_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    fail "bundle directory must be empty: $FINAL_BUNDLE_DIR"
  fi
}

cleanup_stage() {
  if [[ -n "$STAGING_DIR" && -d "$STAGING_DIR" ]]; then
    rm -rf -- "$STAGING_DIR"
  fi
}

begin_staging() {
  local parent_dir
  parent_dir="$(dirname "$FINAL_BUNDLE_DIR")"
  mkdir -p "$parent_dir"
  STAGING_DIR="$(mktemp -d "$parent_dir/.eidolon-pwnkit-bundle.XXXXXX")"
  BUNDLE_DIR="$STAGING_DIR"
  trap cleanup_stage EXIT INT TERM
}

snapshot_inputs() {
  local source_sample_dir="$SAMPLE_DIR"
  local source_run_dir
  local found_run=false

  [[ ! -L "$source_sample_dir/pwnkit-stability-sample.json" ]] \
    || fail "sample summary must not be a symlink: $source_sample_dir/pwnkit-stability-sample.json"
  INPUT_SNAPSHOT_DIR="$BUNDLE_DIR/.source"
  mkdir -p "$INPUT_SNAPSHOT_DIR"
  cp \
    "$source_sample_dir/pwnkit-stability-sample.json" \
    "$INPUT_SNAPSHOT_DIR/pwnkit-stability-sample.json"

  for source_run_dir in "$source_sample_dir"/run-*; do
    [[ -d "$source_run_dir" ]] || continue
    local run_name
    local snapshot_run_dir
    found_run=true
    run_name="$(basename "$source_run_dir")"
    validate_run_name "$run_name"
    [[ ! -L "$source_run_dir" ]] \
      || fail "run directory must not be a symlink: $source_run_dir"
    [[ -f "$source_run_dir/pwnkit-summary.json" ]] \
      || fail "missing run summary: $source_run_dir/pwnkit-summary.json"
    [[ -f "$source_run_dir/agent-replay-trace-summary.json" ]] \
      || fail "missing agent trace summary: $source_run_dir/agent-replay-trace-summary.json"
    [[ ! -L "$source_run_dir/pwnkit-summary.json" ]] \
      || fail "run summary must not be a symlink: $source_run_dir/pwnkit-summary.json"
    [[ ! -L "$source_run_dir/agent-replay-trace-summary.json" ]] \
      || fail "agent trace summary must not be a symlink: $source_run_dir/agent-replay-trace-summary.json"

    snapshot_run_dir="$INPUT_SNAPSHOT_DIR/$run_name"
    mkdir -p "$snapshot_run_dir"
    cp \
      "$source_run_dir/pwnkit-summary.json" \
      "$snapshot_run_dir/pwnkit-summary.json"
    cp \
      "$source_run_dir/agent-replay-trace-summary.json" \
      "$snapshot_run_dir/agent-replay-trace-summary.json"
  done

  [[ "$found_run" == true ]] \
    || fail "sample directory contains no run-* directories: $source_sample_dir"
  SAMPLE_DIR="$INPUT_SNAPSHOT_DIR"
}

discard_input_snapshot() {
  rm -rf -- "$INPUT_SNAPSHOT_DIR"
  INPUT_SNAPSHOT_DIR=""
}

publish_bundle() {
  if [[ -d "$FINAL_BUNDLE_DIR" ]]; then
    rmdir "$FINAL_BUNDLE_DIR"
  fi
  mv "$STAGING_DIR" "$FINAL_BUNDLE_DIR"
  STAGING_DIR=""
  BUNDLE_DIR="$FINAL_BUNDLE_DIR"
  trap - EXIT INT TERM
}

redact_json() {
  local constructor="$1"
  local input="$2"
  local output="$3"
  local temp_output="${output}.tmp"

  jq -e -L "$SCRIPT_DIR" \
    "include \"public-evidence-contract\"; $constructor" \
    "$input" > "$temp_output"
  [[ -s "$temp_output" ]] || fail "redaction produced no output for: $input"
  mv "$temp_output" "$output"
}

validate_public_contract() {
  local constructor="$1"
  local input="$2"
  local label="$3"

  jq -e -L "$SCRIPT_DIR" \
    "include \"public-evidence-contract\"; $constructor | true" \
    "$input" >/dev/null || fail "invalid $label public contract: $input"
}

sample_value() {
  local filter="$1"
  jq -r "($filter) as \$value | if \$value == null then \"unknown\" else \$value end" \
    "$BUNDLE_DIR/pwnkit-stability-sample.json"
}

write_readme() {
  local collected_on
  local valid_count
  local ready
  local heads
  local versions
  local fixture_ids
  local evidence_tracks
  local environments
  local db_saved_counts
  local direct_counts
  local eidolon_counts
  local claim_counts
  local observed_gaps
  local proxy_trace_count
  local strict_controlled_count
  local strict_without_findings_count

  collected_on="$(date -u +%F)"
  valid_count="$(sample_value '.valid_summary_count')"
  ready="$(sample_value '.strict_stability.ready_for_stability_claim')"
  heads="$(jq -r '(.runner_git_heads // []) | map("`" + . + "`") | join(", ")' "$BUNDLE_DIR/pwnkit-stability-sample.json")"
  versions="$(jq -r '(.runner_package_versions // []) | map("`" + . + "`") | join(", ")' "$BUNDLE_DIR/pwnkit-stability-sample.json")"
  fixture_ids="$(jq -r '(.runner_pwnkit_fixture_ids // []) | map("`" + . + "`") | join(", ")' "$BUNDLE_DIR/pwnkit-stability-sample.json")"
  evidence_tracks="$(jq -r '(.evidence_tracks // []) | map("`" + . + "`") | join(", ")' "$BUNDLE_DIR/pwnkit-stability-sample.json")"
  environments="$(jq -r '(.runner_environments // []) | map("`" + . + "`") | join(", ")' "$BUNDLE_DIR/pwnkit-stability-sample.json")"
  db_saved_counts="$(jq -r '[.finding_reconciliation.direct_db_saved_finding_total // 0, .finding_reconciliation.eidolon_db_saved_finding_total // 0] | map(tostring) | join("/")' "$BUNDLE_DIR/pwnkit-stability-sample.json")"
  direct_counts="$(jq -r '[(.artifacts // [])[] | (.direct_finding_count // 0)] | join("/")' "$BUNDLE_DIR/pwnkit-stability-sample.json")"
  eidolon_counts="$(jq -r '[(.artifacts // [])[] | (.eidolon_finding_count // 0)] | join("/")' "$BUNDLE_DIR/pwnkit-stability-sample.json")"
  claim_counts="$(jq -r '(.claim_level_counts // []) | map("`" + .claim_level + "`: `" + (.count|tostring) + "`") | join(", ")' "$BUNDLE_DIR/pwnkit-stability-sample.json")"
  observed_gaps="$(jq -r '(.evidence_gap_diagnostics.observed_gaps // []) | map("`" + . + "`") | join(", ")' "$BUNDLE_DIR/pwnkit-stability-sample.json")"
  proxy_trace_count="$(sample_value '.evidence_gap_diagnostics.proxy_trace_controlled_reality_run_count')"
  strict_controlled_count="$(sample_value '.evidence_gap_diagnostics.pwnkit_strict_controlled_reality_run_count')"
  strict_without_findings_count="$(sample_value '.evidence_gap_diagnostics.strict_controlled_reality_without_eidolon_finding_run_count')"

  {
    printf '# M3 pwnkit Sample Evidence\n\n'
    printf 'Lab-only evidence bundle packaged on %s.\n\n' "$collected_on"
    printf '## Scope\n\n'
    printf -- '- Boundary: owned loopback lab.\n'
    printf -- '- Source sample directory: omitted from the committed bundle.\n'
    printf -- '- pwnkit runner head(s): %s.\n' "${heads:-unknown}"
    printf -- '- pwnkit package version(s): %s.\n' "${versions:-unknown}"
    printf -- '- pwnkit pinned fixture id(s): %s.\n' "${fixture_ids:-none}"
    printf -- '- evidence track(s): %s.\n' "${evidence_tracks:-unknown}"
    printf -- '- runner environment(s): %s.\n\n' "${environments:-unknown}"
    printf '## Disclosure Contract\n\n'
    printf 'Every JSON object is reconstructed from a typed public allowlist. Unknown fields, raw URLs, commands, scope values, session/proof identifiers, free-form notes, query values, and private artifacts are omitted. Invalid retained field types fail packaging.\n\n'
    printf 'Checksums protect the packaged bytes against accidental change. Redaction and checksums do not establish that an observation is true or that an inferred claim is correct.\n\n'
    printf '## Contents\n\n'
    printf -- '- `pwnkit-stability-sample.json`: narrowed sample aggregate.\n'
    printf -- '- `run-*/pwnkit-summary.redacted.json`: narrowed per-run summary.\n'
    printf -- '- `run-*/agent-replay-trace-summary.json`: event-specific trace summary.\n'
    printf -- '- `SHA256SUMS`: checksums for packaged evidence files.\n\n'
    printf '## Result\n\n'
    printf -- '- valid summaries: `%s`\n' "$valid_count"
    printf -- '- claim levels: %s\n' "${claim_counts:-unknown}"
    printf -- '- direct findings: `%s`\n' "${direct_counts:-unknown}"
    printf -- '- Eidolon findings: `%s`\n' "${eidolon_counts:-unknown}"
    printf -- '- DB-saved findings direct/Eidolon: `%s`\n' "${db_saved_counts:-unknown}"
    printf -- '- proxy trace controlled-reality runs: `%s`\n' "$proxy_trace_count"
    printf -- '- strict pwnkit controlled-reality runs: `%s`\n' "$strict_controlled_count"
    printf -- '- strict controlled-reality runs without Eidolon findings: `%s`\n' "$strict_without_findings_count"
    printf -- '- evidence gaps: %s\n' "${observed_gaps:-unknown}"
    printf -- '- `strict_stability.ready_for_stability_claim`: `%s`\n\n' "$ready"
    printf 'This remains Lab-only evidence and does not establish production readiness, attacker identity, semantic truth, or stability beyond the recorded sample.\n'
  } > "$BUNDLE_DIR/README.md"
}

write_checksums() {
  (
    cd "$BUNDLE_DIR"
    find . -type f ! -name SHA256SUMS | sort | while read -r path; do
      sha256_file "${path#./}"
    done
  ) > "$BUNDLE_DIR/SHA256SUMS"
}

preflight_inputs() {
  local sample_summary="$SAMPLE_DIR/pwnkit-stability-sample.json"
  local found_run=false
  local run_dir

  validate_single_json_object "$sample_summary" "sample summary"
  validate_public_contract \
    public_sample_summary \
    "$sample_summary" \
    "sample summary"
  "$SCRIPT_DIR/check-pwnkit-sample-health.sh" "$sample_summary"

  for run_dir in "$SAMPLE_DIR"/run-*; do
    [[ -d "$run_dir" ]] || continue
    found_run=true
    validate_run_name "$(basename "$run_dir")"
    [[ -f "$run_dir/pwnkit-summary.json" ]] \
      || fail "missing run summary: $run_dir/pwnkit-summary.json"
    [[ -f "$run_dir/agent-replay-trace-summary.json" ]] \
      || fail "missing agent trace summary: $run_dir/agent-replay-trace-summary.json"
    validate_single_json_object \
      "$run_dir/pwnkit-summary.json" \
      "run summary"
    validate_single_json_object \
      "$run_dir/agent-replay-trace-summary.json" \
      "agent trace summary"
    validate_public_contract \
      public_pwnkit_summary \
      "$run_dir/pwnkit-summary.json" \
      "run summary"
    validate_public_contract \
      public_agent_trace \
      "$run_dir/agent-replay-trace-summary.json" \
      "agent trace summary"
  done

  [[ "$found_run" == true ]] \
    || fail "sample directory contains no run-* directories: $SAMPLE_DIR"
}

package_bundle() {
  local sample_summary="$SAMPLE_DIR/pwnkit-stability-sample.json"
  local run_dir

  redact_json \
    public_sample_summary \
    "$sample_summary" \
    "$BUNDLE_DIR/pwnkit-stability-sample.json"

  for run_dir in "$SAMPLE_DIR"/run-*; do
    [[ -d "$run_dir" ]] || continue
    local run_name
    local output_run_dir
    run_name="$(basename "$run_dir")"
    output_run_dir="$BUNDLE_DIR/$run_name"
    mkdir -p "$output_run_dir"

    redact_json \
      public_pwnkit_summary \
      "$run_dir/pwnkit-summary.json" \
      "$output_run_dir/pwnkit-summary.redacted.json"
    redact_json \
      public_agent_trace \
      "$run_dir/agent-replay-trace-summary.json" \
      "$output_run_dir/agent-replay-trace-summary.json"
  done

  discard_input_snapshot
  write_readme
  write_checksums
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  if [[ -z "$SAMPLE_DIR" || -z "$FINAL_BUNDLE_DIR" ]]; then
    usage >&2
    exit 2
  fi

  require_command jq
  if ! command -v sha256sum >/dev/null 2>&1 \
    && ! command -v shasum >/dev/null 2>&1; then
    fail "missing required tool: sha256sum or shasum"
  fi
  [[ -d "$SAMPLE_DIR" ]] \
    || fail "sample directory does not exist: $SAMPLE_DIR"
  [[ -f "$SAMPLE_DIR/pwnkit-stability-sample.json" ]] \
    || fail "missing sample summary: $SAMPLE_DIR/pwnkit-stability-sample.json"

  ensure_bundle_target_available
  begin_staging
  snapshot_inputs
  preflight_inputs
  package_bundle
  publish_bundle

  echo "packaged pwnkit evidence bundle: $FINAL_BUNDLE_DIR"
}

main "$@"
