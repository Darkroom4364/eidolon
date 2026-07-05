#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
source "$REPO_ROOT/examples/lib/local-lab.sh"

RUN_COUNT="${1:-${EIDOLON_MICROVM_SAMPLE_RUNS:-1}}"
SAMPLE_DIR="${2:-${EIDOLON_MICROVM_SAMPLE_DIR:-/tmp/eidolon-microvm-pwnkit-$(date +%Y%m%d-%H%M%S)}}"
EDGE_HOST_ALIAS="${EIDOLON_MICROVM_EDGE_HOST_ALIAS:-host.internal}"
TARGET_URL="${EIDOLON_LAB_TARGET_URL:-http://${EDGE_HOST_ALIAS}:31081}"
PROXY_URL="${EIDOLON_LAB_PROXY_URL:-http://${EDGE_HOST_ALIAS}:31080}"
RUNNER_ENVIRONMENT="${EIDOLON_M4_RUNNER_ENVIRONMENT:-microvm}"
NETWORK_TOPOLOGY="${EIDOLON_MICROVM_NETWORK_TOPOLOGY:-microvm_to_orbstack_nodeport}"
HYPERVISOR="${EIDOLON_MICROVM_HYPERVISOR:-firecracker}"
GUEST_PROFILE="${EIDOLON_MICROVM_GUEST_PROFILE:-microvm_min}"
GUEST_PROFILE_CONFIG_BASENAME="${GUEST_PROFILE//_/-}"
PLAN_TEMPLATE_PATH="${EIDOLON_MICROVM_PLAN_TEMPLATE_PATH:-$SCRIPT_DIR/configs/default-run-plan.json}"
GUEST_PROFILE_CONFIG_PATH="${EIDOLON_MICROVM_GUEST_PROFILE_CONFIG_PATH:-$SCRIPT_DIR/configs/guest-profile-${GUEST_PROFILE_CONFIG_BASENAME}.json}"
DRY_RUN="${EIDOLON_MICROVM_DRY_RUN:-1}"
PWNKIT_SOURCE_DIR="${PWNKIT_SOURCE_DIR:-$HOME/Projects/pwnkit}"
MAX_ATTEMPTS="${EIDOLON_M3_PWNKIT_MAX_ATTEMPTS:-3}"
TIMEOUT_SECONDS="${EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS:-1800}"
HEARTBEAT_SECONDS="${EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS:-60}"
FIXTURE_ID="${EIDOLON_M3_PWNKIT_FIXTURE_ID:-}"
EVIDENCE_TRACK="${EIDOLON_M3_PWNKIT_EVIDENCE_TRACK:-}"

usage() {
  cat <<'USAGE'
Usage: examples/microvm/run-pwnkit-microvm.sh [run-count] [sample-dir]

Writes a dry-run-only pwnkit microVM execution plan. This scaffold defines the
future host/guest contract but does not launch a live guest yet.

Defaults:
  direct baseline:  http://host.internal:31081
  shield baseline:  http://host.internal:31080

Environment:
  EIDOLON_MICROVM_SAMPLE_RUNS      Run count if [run-count] is omitted.
  EIDOLON_MICROVM_SAMPLE_DIR       Sample root if [sample-dir] is omitted.
  EIDOLON_MICROVM_EDGE_HOST_ALIAS  Host alias visible from the future guest.
                                   Defaults to host.internal.
  EIDOLON_LAB_TARGET_URL           Direct target URL.
  EIDOLON_LAB_PROXY_URL            Shield URL.
  EIDOLON_MICROVM_HYPERVISOR       Planned hypervisor. Defaults to firecracker.
  EIDOLON_MICROVM_GUEST_PROFILE    Planned guest profile. Defaults to
                                   microvm_min.
  EIDOLON_MICROVM_PLAN_TEMPLATE_PATH
                                   Plan template metadata file.
  EIDOLON_MICROVM_GUEST_PROFILE_CONFIG_PATH
                                   Guest profile metadata file.
  EIDOLON_MICROVM_NETWORK_TOPOLOGY microvm_to_orbstack_nodeport or
                                   microvm_isolated_local.
  EIDOLON_MICROVM_DRY_RUN          Must remain true for this scaffold.
                                   Defaults to 1.
  EIDOLON_M3_PWNKIT_MAX_ATTEMPTS   Attempts per run. Defaults to 3.
  EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS
                                   Timeout per run. Defaults to 1800.
  EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS
                                   Heartbeat interval. Defaults to 60.
  EIDOLON_M3_PWNKIT_FIXTURE_ID     Optional pinned fixture identifier.
  EIDOLON_M3_PWNKIT_EVIDENCE_TRACK Optional track override.
  PWNKIT_SOURCE_DIR                Local pwnkit checkout. Defaults to
                                   ~/Projects/pwnkit.

The generated sample plan records:
  runner_environment = microvm
  network_topology   = microvm_to_orbstack_nodeport or microvm_isolated_local
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

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    fail "missing required tool: $command_name"
  fi
}

require_positive_integer() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
    fail "$name must be a positive integer, got: $value"
  fi
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
      fail "sample-dir must be outside the Eidolon repo"
      ;;
  esac
}

require_microvm_contract() {
  if [[ "$RUNNER_ENVIRONMENT" != "microvm" ]]; then
    fail "EIDOLON_M4_RUNNER_ENVIRONMENT must be microvm for this wrapper"
  fi

  case "$NETWORK_TOPOLOGY" in
    microvm_to_orbstack_nodeport|microvm_isolated_local)
      ;;
    *)
      fail "unsupported microVM network topology: $NETWORK_TOPOLOGY"
      ;;
  esac

  case "$HYPERVISOR" in
    firecracker|cloud_hypervisor|qemu)
      ;;
    *)
      fail "unsupported planned hypervisor: $HYPERVISOR"
      ;;
  esac

  case "$GUEST_PROFILE" in
    microvm_min|microvm_kali_compat)
      ;;
    *)
      fail "unsupported guest profile: $GUEST_PROFILE"
      ;;
  esac

  if ! truthy "$DRY_RUN"; then
    fail "live microVM execution is not implemented yet; keep EIDOLON_MICROVM_DRY_RUN=1"
  fi
}

require_config_paths() {
  [[ -f "$PLAN_TEMPLATE_PATH" ]] || fail "plan template not found: $PLAN_TEMPLATE_PATH"
  [[ -f "$GUEST_PROFILE_CONFIG_PATH" ]] || fail "guest profile config not found: $GUEST_PROFILE_CONFIG_PATH"

  jq -e '
    .schema_version == 1
    and .run_kind == "pwnkit_microvm_plan"
  ' "$PLAN_TEMPLATE_PATH" >/dev/null || fail "invalid plan template: $PLAN_TEMPLATE_PATH"

  jq -e --arg guest_profile "$GUEST_PROFILE" '
    .schema_version == 1
    and .guest_profile == $guest_profile
  ' "$GUEST_PROFILE_CONFIG_PATH" >/dev/null || fail "invalid guest profile config: $GUEST_PROFILE_CONFIG_PATH"
}

require_orbstack_nodeport_urls_if_needed() {
  local target_host proxy_host

  if [[ "$NETWORK_TOPOLOGY" != "microvm_to_orbstack_nodeport" ]]; then
    return
  fi

  eidolon_lab_require_http_url "EIDOLON_LAB_TARGET_URL" "$TARGET_URL"
  eidolon_lab_require_http_url "EIDOLON_LAB_PROXY_URL" "$PROXY_URL"
  target_host="$(eidolon_lab_host_for_url "EIDOLON_LAB_TARGET_URL" "$TARGET_URL")"
  proxy_host="$(eidolon_lab_host_for_url "EIDOLON_LAB_PROXY_URL" "$PROXY_URL")"

  if [[ "$target_host" != "$proxy_host" ]]; then
    fail "EIDOLON_LAB_TARGET_URL and EIDOLON_LAB_PROXY_URL must share the same host"
  fi

  if [[ "$target_host" == "localhost" || "$target_host" == "::1" || "$target_host" =~ ^127(\.[0-9]{1,3}){3}$ ]]; then
    fail "microVM NodePort validation must not use loopback URLs; use host.internal or an explicit host alias"
  fi
}

write_sample_plan() {
  local plan_file="$SAMPLE_DIR/sample-plan.json"
  local runs_json

  mkdir -p "$SAMPLE_DIR"
  for ((run_index = 1; run_index <= RUN_COUNT; run_index++)); do
    mkdir -p "$SAMPLE_DIR/run-$run_index/private"
  done

  runs_json="$(
    jq -n --argjson run_count "$RUN_COUNT" '
      [range(1; $run_count + 1) | {
        run_index: .,
        guest_id: ("microvm-run-" + (. | tostring)),
        artifact_dir: ("run-" + (. | tostring)),
        private_dir: ("run-" + (. | tostring) + "/private"),
        output_files: [
          "agent-summary.json",
          "hypotheses.jsonl",
          "actions.jsonl",
          "guest-trace.jsonl",
          "heartbeat.jsonl",
          "exit-status.json",
          "stdout.log",
          "stderr.log",
          "serial-console.log",
          "vm-metadata.json"
        ]
      }]'
  )"

  jq -n \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg repo_root "$REPO_ROOT" \
    --arg sample_dir "$SAMPLE_DIR" \
    --arg target_url "$TARGET_URL" \
    --arg proxy_url "$PROXY_URL" \
    --arg runner_environment "$RUNNER_ENVIRONMENT" \
    --arg network_topology "$NETWORK_TOPOLOGY" \
    --arg hypervisor "$HYPERVISOR" \
    --arg guest_profile "$GUEST_PROFILE" \
    --arg plan_template_path "$PLAN_TEMPLATE_PATH" \
    --arg guest_profile_config_path "$GUEST_PROFILE_CONFIG_PATH" \
    --arg pwnkit_source_dir "$PWNKIT_SOURCE_DIR" \
    --arg fixture_id "$FIXTURE_ID" \
    --arg evidence_track "$EVIDENCE_TRACK" \
    --argjson run_count "$RUN_COUNT" \
    --argjson max_attempts "$MAX_ATTEMPTS" \
    --argjson timeout_seconds "$TIMEOUT_SECONDS" \
    --argjson heartbeat_seconds "$HEARTBEAT_SECONDS" \
    --argjson runs "$runs_json" \
    '{
      schema_version: 1,
      run_kind: "pwnkit_microvm_sample_plan",
      generated_at_utc: $generated_at,
      mode: "dry_run",
      implemented: false,
      repo_root: $repo_root,
      sample_dir: $sample_dir,
      runner_environment: $runner_environment,
      network_topology: $network_topology,
      hypervisor: $hypervisor,
      guest_profile: $guest_profile,
      plan_template_path: $plan_template_path,
      guest_profile_config_path: $guest_profile_config_path,
      target_url: $target_url,
      proxy_url: $proxy_url,
      pwnkit_source_dir: $pwnkit_source_dir,
      run_count: $run_count,
      constraints: {
        artifacts_are_guest_local: true,
        host_side_evidence_export_required: true,
        host_linked_manifest_supported: true,
        repo_mount_writable: false,
        guest_credentials_passthrough: false
      },
      timeouts: {
        max_attempts: $max_attempts,
        timeout_seconds: $timeout_seconds,
        heartbeat_seconds: $heartbeat_seconds
      },
      qualification: {
        fixture_id: (if $fixture_id == "" then null else $fixture_id end),
        evidence_track: (if $evidence_track == "" then null else $evidence_track end)
      },
      planned_outputs: {
        sample_manifest: "pwnkit-stability-sample.json",
        guest_serial_log: "serial-console.log"
      },
      runs: $runs
    }' > "$plan_file"

  echo "dry-run microVM sample plan: $plan_file"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

require_command jq
require_positive_integer "run-count" "$RUN_COUNT"
require_positive_integer "EIDOLON_M3_PWNKIT_MAX_ATTEMPTS" "$MAX_ATTEMPTS"
require_positive_integer "EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS" "$TIMEOUT_SECONDS"
require_positive_integer "EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS" "$HEARTBEAT_SECONDS"
require_sample_dir_outside_repo
require_microvm_contract
require_config_paths
require_orbstack_nodeport_urls_if_needed
write_sample_plan
