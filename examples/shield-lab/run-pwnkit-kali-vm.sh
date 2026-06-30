#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
source "$REPO_ROOT/examples/lib/local-lab.sh"

RUN_COUNT="${1:-${EIDOLON_M4_SAMPLE_RUNS:-3}}"
SAMPLE_DIR="${2:-${EIDOLON_M4_SAMPLE_DIR:-/tmp/eidolon-m4-orbstack-pwnkit-$(date +%Y%m%d-%H%M%S)}}"
EDGE_HOST_ALIAS="${EIDOLON_SHIELD_EDGE_HOST_ALIAS:-host.internal}"
TARGET_URL="${EIDOLON_LAB_TARGET_URL:-http://${EDGE_HOST_ALIAS}:31081}"
PROXY_URL="${EIDOLON_LAB_PROXY_URL:-http://${EDGE_HOST_ALIAS}:31080}"
EIDOLON_M3_RUNNER_ENVIRONMENT="${EIDOLON_M3_RUNNER_ENVIRONMENT:-kali_vm}"
EIDOLON_M3_NETWORK_TOPOLOGY="${EIDOLON_M3_NETWORK_TOPOLOGY:-kali_vm_to_orbstack_nodeport}"
EIDOLON_SHIELD_KALI_VM_DRY_RUN="${EIDOLON_SHIELD_KALI_VM_DRY_RUN:-0}"
EIDOLON_SHIELD_ALLOW_NON_KALI_VM="${EIDOLON_SHIELD_ALLOW_NON_KALI_VM:-0}"
EIDOLON_SHIELD_KALI_VM_PREFLIGHT="${EIDOLON_SHIELD_KALI_VM_PREFLIGHT:-0}"
EIDOLON_M3_PWNKIT_FIXTURE_ID="${EIDOLON_M3_PWNKIT_FIXTURE_ID:-}"
EIDOLON_M3_PWNKIT_EVIDENCE_TRACK="${EIDOLON_M3_PWNKIT_EVIDENCE_TRACK:-}"
EIDOLON_M3_PWNKIT_MAX_ATTEMPTS="${EIDOLON_M3_PWNKIT_MAX_ATTEMPTS:-3}"
EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS="${EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS:-1800}"
EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS="${EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS:-60}"
PWNKIT_SOURCE_DIR="${PWNKIT_SOURCE_DIR-$HOME/Projects/pwnkit}"

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/run-pwnkit-kali-vm.sh [--preflight] [run-count] [sample-dir]

Runs the Kali-VM pwnkit validation path against the OrbStack Kubernetes Shield
lab. This is the M4 deployment topology:

  Kali VM -> OrbStack host NodePort -> Eidolon shield / direct target

Defaults:
  direct baseline:  http://host.internal:31081
  shield baseline:  http://host.internal:31080

Environment:
  EIDOLON_SHIELD_EDGE_HOST_ALIAS  Host alias visible inside the Kali VM.
                                  Defaults to host.internal.
  EIDOLON_LAB_TARGET_URL          Direct target URL. Defaults to
                                  http://host.internal:31081.
  EIDOLON_LAB_PROXY_URL           Shield edge URL. Defaults to
                                  http://host.internal:31080.
  EIDOLON_M4_SAMPLE_RUNS          Run count if [run-count] is omitted.
  EIDOLON_M4_SAMPLE_DIR           Sample root if [sample-dir] is omitted.
  EIDOLON_SHIELD_KALI_VM_DRY_RUN  Write the sample plan without scanning.
  EIDOLON_SHIELD_KALI_VM_PREFLIGHT
                                  Validate Kali+NodePort runner plumbing only.
  EIDOLON_SHIELD_ALLOW_NON_KALI_VM
                                  Allow plan-only diagnostics outside Kali.
                                  Requires EIDOLON_SHIELD_KALI_VM_DRY_RUN=1.
  EIDOLON_M3_PWNKIT_MAX_ATTEMPTS  Attempts per sample run. Defaults to 3.
  EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS
                                  Scan-leg timeout. Defaults to 1800.
  EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS
                                  Runner heartbeat interval. Defaults to 60.
  EIDOLON_M3_PWNKIT_FIXTURE_ID    Optional pinned pwnkit fixture label.
  EIDOLON_M3_PWNKIT_EVIDENCE_TRACK
                                  Optional track override: upstream_current,
                                  local_patched_pwnkit, or historical_stale.
  Linked host manifests are supported via:
    examples/shield-lab/collect-kali-vm-sample.sh --host-bundle-dir --edge-decisions
  PWNKIT_SOURCE_DIR               Local pwnkit source checkout. Defaults to
                                  ~/Projects/pwnkit.

The wrapper enforces:
  EIDOLON_M3_RUNNER_ENVIRONMENT=kali_vm
  EIDOLON_M3_NETWORK_TOPOLOGY=kali_vm_to_orbstack_nodeport

This wrapper does not manage OrbStack Kubernetes itself. Deploy the Shield lab
from the macOS host first, then run this script inside the Kali VM.
USAGE
}

truthy() {
  local value
  value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$value" in
    1|true|yes|on)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

fail() {
  echo "error: $*" >&2
  exit 2
}

os_release_value() {
  local key="$1"
  local line

  if [[ ! -f /etc/os-release ]]; then
    return
  fi

  line="$(grep -E "^${key}=" /etc/os-release 2>/dev/null | sed -n '1p' || true)"
  line="${line#*=}"
  line="${line%\"}"
  line="${line#\"}"
  printf '%s' "$line"
}

is_kali_linux() {
  if truthy "${EIDOLON_M4_TEST_FORCE_NON_KALI:-0}"; then
    return 1
  fi

  [[ "$(uname -s 2>/dev/null || true)" == "Linux" ]] || return 1
  [[ "$(os_release_value ID)" == "kali" ]]
}

require_positive_integer() {
  local name="$1"
  local value="$2"

  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
    fail "$name must be a positive integer, got: $value"
  fi
}

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    fail "missing required tool: $command_name"
  fi
}

require_vm_contract() {
  local on_kali=0

  if [[ "$EIDOLON_M3_RUNNER_ENVIRONMENT" != "kali_vm" ]]; then
    fail "EIDOLON_M3_RUNNER_ENVIRONMENT must be kali_vm for this wrapper"
  fi

  if [[ "$EIDOLON_M3_NETWORK_TOPOLOGY" != "kali_vm_to_orbstack_nodeport" ]]; then
    fail "EIDOLON_M3_NETWORK_TOPOLOGY must be kali_vm_to_orbstack_nodeport for this wrapper"
  fi

  if is_kali_linux; then
    on_kali=1
  fi

  if [[ "$on_kali" -eq 0 ]] && ! truthy "$EIDOLON_SHIELD_ALLOW_NON_KALI_VM"; then
    fail "run this inside a Kali Linux VM, or set EIDOLON_SHIELD_ALLOW_NON_KALI_VM=1 for plan-only diagnostics"
  fi

  if [[ "$on_kali" -eq 0 ]] && ! truthy "$EIDOLON_SHIELD_KALI_VM_DRY_RUN"; then
    fail "EIDOLON_SHIELD_ALLOW_NON_KALI_VM is only allowed with EIDOLON_SHIELD_KALI_VM_DRY_RUN=1"
  fi
}

require_evidence_track_contract() {
  case "$EIDOLON_M3_PWNKIT_EVIDENCE_TRACK" in
    local_patched_pwnkit)
      if [[ -z "$EIDOLON_M3_PWNKIT_FIXTURE_ID" ]]; then
        fail "EIDOLON_M3_PWNKIT_FIXTURE_ID is required when EIDOLON_M3_PWNKIT_EVIDENCE_TRACK=local_patched_pwnkit"
      fi
      ;;
    upstream_current)
      if [[ -n "$EIDOLON_M3_PWNKIT_FIXTURE_ID" ]]; then
        fail "EIDOLON_M3_PWNKIT_FIXTURE_ID must be unset when EIDOLON_M3_PWNKIT_EVIDENCE_TRACK=upstream_current"
      fi
      ;;
  esac
}

canonicalize_path_allow_missing() {
  local path="$1"
  local current="$path"
  local suffix=""
  local base
  local resolved

  while [[ ! -e "$current" ]]; do
    base="$(basename "$current")"
    suffix="/$base$suffix"
    current="$(dirname "$current")"
  done

  if [[ ! -d "$current" ]]; then
    fail "sample-dir must resolve through directories only: $path"
  fi

  resolved="$(cd "$current" && pwd -P)"
  if [[ "$resolved" == "/" ]]; then
    printf '/%s' "${suffix#/}"
  else
    printf '%s%s' "$resolved" "$suffix"
  fi
}

require_sample_dir_outside_repo() {
  local resolved_sample_dir

  if [[ "$SAMPLE_DIR" != /* ]]; then
    fail "sample-dir must be an absolute path outside the Eidolon repo"
  fi

  resolved_sample_dir="$(canonicalize_path_allow_missing "$SAMPLE_DIR")"
  case "$resolved_sample_dir" in
    "$REPO_ROOT"|"$REPO_ROOT"/*)
      fail "sample-dir must be outside the Eidolon repo so pwnkit is not handed repo-local artifact paths"
      ;;
  esac
}

require_orbstack_nodeport_urls() {
  local target_host proxy_host

  eidolon_lab_require_http_url "EIDOLON_LAB_TARGET_URL" "$TARGET_URL"
  eidolon_lab_require_http_url "EIDOLON_LAB_PROXY_URL" "$PROXY_URL"
  target_host="$(eidolon_lab_host_for_url "EIDOLON_LAB_TARGET_URL" "$TARGET_URL")"
  proxy_host="$(eidolon_lab_host_for_url "EIDOLON_LAB_PROXY_URL" "$PROXY_URL")"

  if [[ "$target_host" != "$proxy_host" ]]; then
    fail "EIDOLON_LAB_TARGET_URL and EIDOLON_LAB_PROXY_URL must share the same host in this topology"
  fi

  if [[ "$target_host" == "localhost" || "$target_host" == "::1" || "$target_host" =~ ^127(\.[0-9]{1,3}){3}$ ]]; then
    fail "OrbStack NodePort validation must not use loopback URLs; use host.internal or an explicit host alias"
  fi
}

write_dry_run_plan() {
  local plan_file="$SAMPLE_DIR/sample-plan.txt"

  mkdir -p "$SAMPLE_DIR"
  for ((run_index = 1; run_index <= RUN_COUNT; run_index++)); do
    mkdir -p "$SAMPLE_DIR/run-$run_index/private"
  done

  {
    printf 'run_count=%s\n' "$RUN_COUNT"
    printf 'sample_dir=%s\n' "$SAMPLE_DIR"
    printf 'target_url=%s\n' "$TARGET_URL"
    printf 'proxy_url=%s\n' "$PROXY_URL"
    printf 'runner_environment=%s\n' "$EIDOLON_M3_RUNNER_ENVIRONMENT"
    printf 'network_topology=%s\n' "$EIDOLON_M3_NETWORK_TOPOLOGY"
    printf 'pwnkit_max_attempts=%s\n' "$EIDOLON_M3_PWNKIT_MAX_ATTEMPTS"
    printf 'pwnkit_timeout_seconds=%s\n' "$EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS"
    printf 'pwnkit_heartbeat_seconds=%s\n' "$EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS"
    printf 'pwnkit_fixture_id=%s\n' "${EIDOLON_M3_PWNKIT_FIXTURE_ID:-none}"
    printf 'pwnkit_evidence_track=%s\n' "${EIDOLON_M3_PWNKIT_EVIDENCE_TRACK:-auto}"
    printf 'pwnkit_source_dir=%s\n' "${PWNKIT_SOURCE_DIR:-none}"
    printf 'artifacts_are_vm_local=true\n'
    printf 'host_side_evidence_export_required=true\n'
    printf 'host_linked_manifest_supported=true\n'
  } > "$plan_file"

  echo "dry-run sample plan: $plan_file"
}

observability_timestamp() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

append_run_hypothesis() {
  local run_dir="$1"
  local stage="$2"
  local hypothesis="$3"
  local confidence="$4"
  local planned_check="$5"
  local status="${6:-planned}"

  mkdir -p "$run_dir"
  jq -cn \
    --arg timestamp "$(observability_timestamp)" \
    --arg stage "$stage" \
    --arg hypothesis "$hypothesis" \
    --arg confidence "$confidence" \
    --arg planned_check "$planned_check" \
    --arg status "$status" \
    '{
      timestamp: $timestamp,
      stage: $stage,
      hypothesis: $hypothesis,
      confidence: $confidence,
      planned_check: $planned_check,
      status: $status,
      source: "shield_lab_kali_wrapper"
    }' >> "$run_dir/hypotheses.jsonl"
}

append_run_action() {
  local run_dir="$1"
  local stage="$2"
  local action="$3"
  local reason="$4"
  local outcome="$5"
  local note="${6:-}"

  mkdir -p "$run_dir"
  jq -cn \
    --arg timestamp "$(observability_timestamp)" \
    --arg stage "$stage" \
    --arg action "$action" \
    --arg reason "$reason" \
    --arg outcome "$outcome" \
    --arg note "$note" \
    '{
      timestamp: $timestamp,
      stage: $stage,
      action: $action,
      reason: $reason,
      outcome: $outcome,
      note: (if $note == "" then null else $note end),
      source: "shield_lab_kali_wrapper"
    }' >> "$run_dir/actions.jsonl"
}

write_run_bootstrap_summary() {
  local run_dir="$1"
  local attempt="$2"

  mkdir -p "$run_dir"
  jq -n \
    --arg generated_at "$(observability_timestamp)" \
    --arg target_url "$TARGET_URL" \
    --arg proxy_url "$PROXY_URL" \
    --arg network_topology "$EIDOLON_M3_NETWORK_TOPOLOGY" \
    --arg runner_environment "$EIDOLON_M3_RUNNER_ENVIRONMENT" \
    --argjson attempt "$attempt" \
    '{
      schema_version: 1,
      run_kind: "pwnkit_agent_summary",
      boundary: "scanner_qualification",
      generated_at: $generated_at,
      status: "queued",
      stage: "wrapper_bootstrap",
      current_attempt: $attempt,
      current_leg: null,
      latest_note: "wrapper prepared the run directory before invoking pwnkit",
      target_url: $target_url,
      proxy_url: $proxy_url,
      environment: {
        runner_environment: $runner_environment,
        runner_environment_source: "env_override",
        network_topology: $network_topology
      },
      observability: {
        hypotheses_file: "hypotheses.jsonl",
        actions_file: "actions.jsonl",
        tool_results_dir: "tool-results"
      },
      artifact_presence: {
        runner_metadata: false,
        eidolon_report: false,
        direct_report: false
      },
      artifact_counts: {
        hypotheses: 0,
        actions: 0,
        tool_results: 0
      }
    }' > "$run_dir/agent-summary.json"
}

run_preflight() {
  local preflight_dir="$SAMPLE_DIR/private/kali-nodeport-preflight"

  require_command curl
  require_command jq
  require_command sqlite3
  require_command git

  mkdir -p "$preflight_dir"
  curl -fsS "$TARGET_URL/openapi.json" >/dev/null
  curl -fsS "$PROXY_URL/openapi.json" >/dev/null

  EIDOLON_LAB_TARGET_URL="$TARGET_URL" \
    EIDOLON_LAB_PROXY_URL="$PROXY_URL" \
    EIDOLON_M3_PIN_SESSION="${EIDOLON_M3_PIN_SESSION:-1}" \
    EIDOLON_M3_PWNKIT_MAX_ATTEMPTS="$EIDOLON_M3_PWNKIT_MAX_ATTEMPTS" \
    EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS="$EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS" \
    EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS="$EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS" \
    EIDOLON_M3_RUNNER_ENVIRONMENT="$EIDOLON_M3_RUNNER_ENVIRONMENT" \
    EIDOLON_M3_NETWORK_TOPOLOGY="$EIDOLON_M3_NETWORK_TOPOLOGY" \
    EIDOLON_M3_PWNKIT_FIXTURE_ID="$EIDOLON_M3_PWNKIT_FIXTURE_ID" \
    EIDOLON_M3_PWNKIT_EVIDENCE_TRACK="$EIDOLON_M3_PWNKIT_EVIDENCE_TRACK" \
    PWNKIT_SOURCE_DIR="$PWNKIT_SOURCE_DIR" \
    "$REPO_ROOT/examples/m3/pwnkit-codex.sh" preflight "$preflight_dir" >/dev/null
  EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE="${EIDOLON_M3_ALLOW_UNFRESH_PWNKIT_SOURCE:-0}" \
    "$REPO_ROOT/examples/m3/check-pwnkit-runner-freshness.sh" \
    "$preflight_dir/pwnkit-runner-metadata.json"

  echo "orbstack-kali preflight ok: $preflight_dir"
}

summary_has_only_transient_agent_errors() {
  local summary_file="$1"

  [[ -f "$summary_file" ]] || return 1

  jq -e '
    [
      .runs.direct.agent_error_diagnostics.class_counts[]?,
      .runs.eidolon.agent_error_diagnostics.class_counts[]?
    ] as $classes
    | ($classes | map(.count // 0) | add // 0) > 0
    and all(
      $classes[];
      .error_class == "codex_backend_timeout"
      or .error_class == "codex_backend_api_error"
    )
  ' "$summary_file" >/dev/null
}

archive_run_attempt() {
  local run_index="$1"
  local attempt="$2"
  local run_dir="$3"
  local archive_dir="$SAMPLE_DIR/private/run-$run_index-attempt-$attempt"

  mkdir -p "$SAMPLE_DIR/private"
  mv "$run_dir" "$archive_dir"
  echo "orbstack shield sample archived failed run $run_index attempt $attempt -> $archive_dir" >&2
}

run_one_sample() {
  local run_index="$1"
  local run_dir="$SAMPLE_DIR/run-$run_index"
  local attempt=1

  while :; do
    mkdir -p "$run_dir/private"
    append_run_hypothesis \
      "$run_dir" \
      "transfer_control" \
      "scanner signal should survive the Kali VM to OrbStack NodePort transfer while Eidolon still presents baited owned surfaces" \
      "medium" \
      "run both the Eidolon and direct pwnkit legs against the host.internal NodePort endpoints"
    append_run_action \
      "$run_dir" \
      "transfer_control" \
      "launch_kali_nodeport_comparison" \
      "start the VM-hosted pwnkit comparison against the direct and shielded NodePort surfaces" \
      "started" \
      "run_index=${run_index} attempt=${attempt}"
    write_run_bootstrap_summary "$run_dir" "$attempt"
    echo "orbstack shield sample run $run_index/$RUN_COUNT attempt $attempt/$EIDOLON_M3_PWNKIT_MAX_ATTEMPTS -> $run_dir" >&2

    local runner_status=0
    set +e
    EIDOLON_LAB_TARGET_URL="$TARGET_URL" \
      EIDOLON_LAB_PROXY_URL="$PROXY_URL" \
      EIDOLON_M3_PIN_SESSION="${EIDOLON_M3_PIN_SESSION:-1}" \
      EIDOLON_M3_PWNKIT_MAX_ATTEMPTS="$EIDOLON_M3_PWNKIT_MAX_ATTEMPTS" \
      EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS="$EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS" \
      EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS="$EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS" \
      EIDOLON_M3_RUNNER_ENVIRONMENT="$EIDOLON_M3_RUNNER_ENVIRONMENT" \
      EIDOLON_M3_NETWORK_TOPOLOGY="$EIDOLON_M3_NETWORK_TOPOLOGY" \
      EIDOLON_M3_PWNKIT_FIXTURE_ID="$EIDOLON_M3_PWNKIT_FIXTURE_ID" \
      EIDOLON_M3_PWNKIT_EVIDENCE_TRACK="$EIDOLON_M3_PWNKIT_EVIDENCE_TRACK" \
      PWNKIT_SOURCE_DIR="$PWNKIT_SOURCE_DIR" \
      "$REPO_ROOT/examples/m3/pwnkit-codex.sh" all "$run_dir"
    runner_status="$?"
    set -e

    "$REPO_ROOT/examples/m3/collect-pwnkit-codex.sh" "$run_dir" > "$run_dir/pwnkit-summary.json"

    local health_status=0
    EIDOLON_M3_ALLOW_AGENT_ERRORS="${EIDOLON_M3_ALLOW_AGENT_ERRORS:-0}" \
      "$REPO_ROOT/examples/m3/check-pwnkit-summary-health.sh" "$run_dir/pwnkit-summary.json" \
      || health_status="$?"
    if [[ "$runner_status" -ne 0 && "$health_status" -eq 0 ]]; then
      health_status="$runner_status"
    fi

    if [[ "$health_status" -eq 0 ]]; then
      return 0
    fi

    if ! truthy "${EIDOLON_M3_ALLOW_AGENT_ERRORS:-0}" \
      && (( attempt < EIDOLON_M3_PWNKIT_MAX_ATTEMPTS )) \
      && summary_has_only_transient_agent_errors "$run_dir/pwnkit-summary.json"; then
      echo "warning: orbstack shield sample run $run_index attempt $attempt/$EIDOLON_M3_PWNKIT_MAX_ATTEMPTS recorded only transient Codex backend errors; retrying" >&2
      archive_run_attempt "$run_index" "$attempt" "$run_dir"
      attempt=$((attempt + 1))
      continue
    fi

    return "$health_status"
  done
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  require_positive_integer "run-count" "$RUN_COUNT"
  require_positive_integer "EIDOLON_M3_PWNKIT_MAX_ATTEMPTS" "$EIDOLON_M3_PWNKIT_MAX_ATTEMPTS"
  require_positive_integer "EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS" "$EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS"
  require_positive_integer "EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS" "$EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS"
  require_vm_contract
  require_evidence_track_contract
  require_orbstack_nodeport_urls
  require_sample_dir_outside_repo

  if truthy "$EIDOLON_SHIELD_KALI_VM_PREFLIGHT"; then
    run_preflight
    exit 0
  fi

  if truthy "$EIDOLON_SHIELD_KALI_VM_DRY_RUN"; then
    write_dry_run_plan
    exit 0
  fi

  run_preflight

  local run_dirs=()
  for ((run_index = 1; run_index <= RUN_COUNT; run_index++)); do
    run_one_sample "$run_index"
    run_dirs+=("$SAMPLE_DIR/run-$run_index")
  done

  "$REPO_ROOT/examples/m3/collect-pwnkit-sample.sh" "${run_dirs[@]}" \
    > "$SAMPLE_DIR/pwnkit-stability-sample.json"
  EIDOLON_M3_ALLOW_AGENT_ERRORS="${EIDOLON_M3_ALLOW_AGENT_ERRORS:-0}" \
    "$REPO_ROOT/examples/m3/check-pwnkit-sample-health.sh" \
    "$SAMPLE_DIR/pwnkit-stability-sample.json"

  echo "orbstack shield sample summary: $SAMPLE_DIR/pwnkit-stability-sample.json"
}

if [[ "${1:-}" == "--preflight" ]]; then
  EIDOLON_SHIELD_KALI_VM_PREFLIGHT=1
  shift
  RUN_COUNT="${1:-${EIDOLON_M4_SAMPLE_RUNS:-3}}"
  SAMPLE_DIR="${2:-${EIDOLON_M4_SAMPLE_DIR:-/tmp/eidolon-m4-orbstack-pwnkit-$(date +%Y%m%d-%H%M%S)}}"
fi

main "$@"
