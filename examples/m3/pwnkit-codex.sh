#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/../lib/local-lab.sh"

MODE="${1:-all}"
ARTIFACT_DIR="${2:-${EIDOLON_M3_ARTIFACT_DIR:-/tmp/eidolon-m3-pwnkit-$(date +%Y%m%d-%H%M%S)}}"
TARGET_URL="${EIDOLON_LAB_TARGET_URL:-http://127.0.0.1:9001}"
PROXY_URL="${EIDOLON_LAB_PROXY_URL:-http://127.0.0.1:8080}"
PWNKIT_DEPTH="${PWNKIT_DEPTH:-quick}"
PWNKIT_MODE="${PWNKIT_MODE:-web}"
PWNKIT_RUNTIME="${PWNKIT_RUNTIME:-codex}"
PWNKIT_RATE_LIMIT="${PWNKIT_RATE_LIMIT:-2}"
PWNKIT_SOURCE_DIR="${PWNKIT_SOURCE_DIR-$HOME/Projects/pwnkit}"
EIDOLON_M3_PWNKIT_MAX_ATTEMPTS="${EIDOLON_M3_PWNKIT_MAX_ATTEMPTS:-2}"
EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS="${EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS:-900}"
EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS="${EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS:-60}"
PWNKIT_FEATURE_CODEX_LIVE_TARGETS="${PWNKIT_FEATURE_CODEX_LIVE_TARGETS:-}"
EIDOLON_M3_CODEX_AUTH_FILE="${EIDOLON_M3_CODEX_AUTH_FILE:-$HOME/.codex/auth.json}"
EIDOLON_M3_PIN_SESSION="${EIDOLON_M3_PIN_SESSION:-0}"
EIDOLON_M3_SESSION_ID="${EIDOLON_M3_SESSION_ID:-}"
EIDOLON_M3_ALLOW_STALE_PWNKIT_DIST="${EIDOLON_M3_ALLOW_STALE_PWNKIT_DIST:-0}"
EIDOLON_M3_RUNNER_ENVIRONMENT="${EIDOLON_M3_RUNNER_ENVIRONMENT:-auto}"
EIDOLON_M3_NETWORK_TOPOLOGY="${EIDOLON_M3_NETWORK_TOPOLOGY:-same_host_loopback}"
EIDOLON_M3_PWNKIT_FIXTURE_ID="${EIDOLON_M3_PWNKIT_FIXTURE_ID:-}"
EIDOLON_M3_PWNKIT_EVIDENCE_TRACK="${EIDOLON_M3_PWNKIT_EVIDENCE_TRACK:-}"

usage() {
  cat <<'USAGE'
Usage: examples/m3/pwnkit-codex.sh [all|eidolon|direct|preflight] [artifact-dir]

Runs an authorized local pwnkit Codex scan against the Eidolon proxy and/or the
direct demo target. The demo target and proxy must already be running unless
MODE is preflight.

Environment:
  EIDOLON_LAB_TARGET_URL    Direct demo target URL. Defaults to http://127.0.0.1:9001.
  EIDOLON_LAB_PROXY_URL     Eidolon proxy URL. Defaults to http://127.0.0.1:8080.
  EIDOLON_M3_ARTIFACT_DIR   Artifact directory if [artifact-dir] is omitted.
  PWNKIT_SOURCE_DIR         Local pwnkit source checkout. Defaults to
                            ~/Projects/pwnkit. The runner invokes
                            $PWNKIT_SOURCE_DIR/dist/pwnkit.js and does not
                            fall back to globally installed pwnkit packages.
  PWNKIT_NODE_ENTRY         Explicit path to a built pwnkit dist/pwnkit.js
                            entrypoint. Overrides PWNKIT_SOURCE_DIR.
  PWNKIT_BIN                Explicit pwnkit command override for tests or
                            diagnostics. Overrides PWNKIT_SOURCE_DIR.
  PWNKIT_DEPTH              pwnkit depth. Defaults to quick.
  PWNKIT_MODE               pwnkit mode. Defaults to web.
  PWNKIT_RUNTIME            pwnkit runtime. Defaults to codex.
  PWNKIT_RATE_LIMIT         pwnkit --rate-limit value. Defaults to 2.
  EIDOLON_M3_PWNKIT_MAX_ATTEMPTS
                            Attempts for stateless pwnkit legs when a transient
                            Codex backend error is recorded. Defaults to 2.
                            Stateful Eidolon legs are not retried in-place.
  EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS
                            Wall-clock timeout for each pwnkit scan leg.
                            Defaults to 900 seconds.
  EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS
                            Emit sanitized runner progress every N seconds
                            while pwnkit runs. Defaults to 60 seconds.
  PWNKIT_FEATURE_CODEX_LIVE_TARGETS
                            Optional legacy pwnkit feature flag. Not set by
                            default; current pwnkit Codex live scans use the
                            direct ChatGPT Codex provider.
  EIDOLON_M3_CODEX_AUTH_FILE
                            Optional Codex auth JSON path. Defaults to
                            ~/.codex/auth.json. When PWNKIT_RUNTIME=codex and
                            PWNKIT_CHATGPT_* token env is unset, the runner
                            passes a fresh tokens.access_token from this file
                            only to the pwnkit subprocess, falling back to
                            tokens.refresh_token when no usable access token
                            exists.
  EIDOLON_M3_PIN_SESSION    If true, pass one fixed eidolon_session cookie to
                            the Eidolon leg. Defaults to 0.
  EIDOLON_M3_SESSION_ID     Optional UUID for EIDOLON_M3_PIN_SESSION.
  EIDOLON_M3_ALLOW_STALE_PWNKIT_DIST
                            If true, skip the source-checkout dist freshness
                            guard. Defaults to 0.
  EIDOLON_M3_RUNNER_ENVIRONMENT
                            Runner environment label for evidence metadata.
                            Defaults to auto; examples: host_mac, kali_vm,
                            linux_host.
  EIDOLON_M3_NETWORK_TOPOLOGY
                            Network topology label for evidence metadata.
                            Defaults to same_host_loopback. Use
                            kali_vm_to_orbstack_nodeport for the OrbStack
                            Shield lab NodePort path.
  EIDOLON_M3_PWNKIT_FIXTURE_ID
                            Optional safe label for archived/private pinned
                            pwnkit fixtures. Current-main claims should leave
                            this unset and require origin/main freshness.
  EIDOLON_M3_PWNKIT_EVIDENCE_TRACK
                            Optional explicit evidence track. Allowed values:
                            upstream_current, local_patched_pwnkit,
                            historical_stale. When unset, collectors infer the
                            track from runner freshness metadata.

The runner writes one pwnkit scope file per scan leg and always passes
`--scope`. This keeps pwnkit's shell-mode auth injection active for the
pinned-session Eidolon leg and fails closed if a leg target falls outside the
generated host scope.

For source checkouts, keep a built checkout at PWNKIT_SOURCE_DIR, or set
PWNKIT_NODE_ENTRY to a specific built dist/pwnkit.js. This runner refuses
obviously stale ignored dist bundles unless EIDOLON_M3_ALLOW_STALE_PWNKIT_DIST=1
is set. Current pwnkit bundles also enforce their own build-commit freshness;
rebuild with `(cd "$PWNKIT_SOURCE_DIR" && pnpm run build)` after changing the
checkout.

Some pwnkit builds exit nonzero after writing a valid JSON report with findings.
This runner keeps those reports and continues; missing or invalid reports remain
fatal.

Current pwnkit builds may append a human `cost: ...` footer after the JSON report.
The runner stores raw stdout as `pwnkit-<leg>.stdout.log` and normalizes the JSON
report into `pwnkit-<leg>.json` before validation. It also preserves
`pwnkit-<leg>.db`; collectors use that SQLite scan/event/session ledger for
execution health and keep DB-saved candidate findings distinct from final JSON
findings.

The preflight mode validates local runner plumbing, writes scope files and
`pwnkit-runner-metadata.json`, and exits before running pwnkit scans.
USAGE
}

resolve_pwnkit_command() {
  local source_entry

  if [[ -n "${PWNKIT_NODE_ENTRY:-}" ]]; then
    if [[ ! -f "$PWNKIT_NODE_ENTRY" ]]; then
      echo "error: PWNKIT_NODE_ENTRY does not exist: $PWNKIT_NODE_ENTRY" >&2
      exit 2
    fi
    validate_pwnkit_node_entry "$PWNKIT_NODE_ENTRY"
    set_pwnkit_node_command "$PWNKIT_NODE_ENTRY" "PWNKIT_NODE_ENTRY"
    return
  fi

  if [[ -n "${PWNKIT_BIN:-}" ]]; then
    if ! command -v "$PWNKIT_BIN" >/dev/null 2>&1; then
      echo "error: PWNKIT_BIN command not found: $PWNKIT_BIN" >&2
      exit 2
    fi
    PWNKIT_COMMAND=("$PWNKIT_BIN")
    PWNKIT_COMMAND_SOURCE="PWNKIT_BIN"
    return
  fi

  if [[ -n "$PWNKIT_SOURCE_DIR" ]]; then
    source_entry="$PWNKIT_SOURCE_DIR/dist/pwnkit.js"
    if [[ ! -d "$PWNKIT_SOURCE_DIR" ]]; then
      echo "error: PWNKIT_SOURCE_DIR does not exist: $PWNKIT_SOURCE_DIR" >&2
      echo "       set PWNKIT_SOURCE_DIR to the local pwnkit checkout or set PWNKIT_NODE_ENTRY/PWNKIT_BIN explicitly" >&2
      exit 2
    fi
    if [[ ! -f "$source_entry" ]]; then
      echo "error: local pwnkit source checkout is not built: $source_entry" >&2
      echo "       run: (cd \"$PWNKIT_SOURCE_DIR\" && pnpm run build)" >&2
      echo "       or set PWNKIT_NODE_ENTRY/PWNKIT_BIN explicitly for diagnostics." >&2
      exit 2
    fi
    validate_pwnkit_node_entry "$source_entry"
    set_pwnkit_node_command "$source_entry" "PWNKIT_SOURCE_DIR"
    return
  fi

  echo "error: could not find local pwnkit source checkout; set PWNKIT_SOURCE_DIR or set PWNKIT_NODE_ENTRY/PWNKIT_BIN explicitly" >&2
  exit 2
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

mtime_seconds() {
  local path="$1"

  if stat -f %m "$path" >/dev/null 2>&1; then
    stat -f %m "$path"
    return
  fi

  stat -c %Y "$path"
}

pwnkit_repo_dir_for_entry() {
  local entry="$1"
  local entry_dir
  local repo_dir

  entry_dir="$(cd "$(dirname "$entry")" && pwd -P)"
  if [[ "$(basename "$entry_dir")" != "dist" || "$(basename "$entry")" != "pwnkit.js" ]]; then
    return 1
  fi

  repo_dir="$(cd "$entry_dir/.." && pwd -P)"
  if ! git -C "$repo_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    return 1
  fi

  printf '%s\n' "$repo_dir"
}

validate_pwnkit_node_entry() {
  local entry="$1"
  local repo_dir
  local head_time
  local dist_time

  if truthy "$EIDOLON_M3_ALLOW_STALE_PWNKIT_DIST"; then
    return
  fi

  if ! repo_dir="$(pwnkit_repo_dir_for_entry "$entry")"; then
    return
  fi

  head_time="$(git -C "$repo_dir" log -1 --format=%ct 2>/dev/null || true)"
  dist_time="$(mtime_seconds "$entry")"
  if [[ -n "$head_time" && "$dist_time" -lt "$head_time" ]]; then
    echo "error: pwnkit dist bundle is older than the source checkout HEAD: $entry" >&2
    echo "       run: (cd \"$repo_dir\" && pnpm run build)" >&2
    echo "       or set EIDOLON_M3_ALLOW_STALE_PWNKIT_DIST=1 to bypass." >&2
    exit 2
  fi

  if grep -q 'codex_mcp_runner\|PWNKIT_FEATURE_CODEX_LIVE_TARGETS' "$entry"; then
    echo "error: pwnkit dist bundle still contains the removed Codex MCP live runner: $entry" >&2
    echo "       run: (cd \"$repo_dir\" && pnpm run build)" >&2
    echo "       or set EIDOLON_M3_ALLOW_STALE_PWNKIT_DIST=1 to bypass." >&2
    exit 2
  fi
}

set_pwnkit_node_command() {
  local entry="$1"
  local source="$2"

  PWNKIT_COMMAND=(node "$entry")
  PWNKIT_COMMAND_SOURCE="$source"
  PWNKIT_ENTRY_PATH="$entry"
}

json_bool() {
  if truthy "$1"; then
    printf 'true'
  else
    printf 'false'
  fi
}

observability_timestamp() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

relative_artifact_path() {
  local path="$1"

  if [[ -z "$path" ]]; then
    printf ''
    return
  fi

  case "$path" in
    "$ARTIFACT_DIR"/*)
      printf '%s' "${path#$ARTIFACT_DIR/}"
      ;;
    *)
      printf '%s' "$path"
      ;;
  esac
}

jsonl_line_count() {
  local path="$1"

  if [[ -f "$path" ]]; then
    awk 'END { print NR + 0 }' "$path"
  else
    printf '0'
  fi
}

tool_result_json_count() {
  if [[ -d "$OBS_TOOL_RESULTS_DIR" ]]; then
    find "$OBS_TOOL_RESULTS_DIR" -type f -name '*.json' | wc -l | tr -d ' '
  else
    printf '0'
  fi
}

initialize_observability() {
  OBS_HYPOTHESES_FILE="$ARTIFACT_DIR/hypotheses.jsonl"
  OBS_ACTIONS_FILE="$ARTIFACT_DIR/actions.jsonl"
  OBS_TOOL_RESULTS_DIR="$ARTIFACT_DIR/tool-results"
  OBS_SUMMARY_FILE="$ARTIFACT_DIR/agent-summary.json"

  mkdir -p "$OBS_TOOL_RESULTS_DIR"
  touch "$OBS_HYPOTHESES_FILE" "$OBS_ACTIONS_FILE"
}

record_hypothesis() {
  local stage="$1"
  local hypothesis="$2"
  local confidence="$3"
  local planned_check="$4"
  local status="${5:-planned}"
  local leg="${6:-}"

  jq -cn \
    --arg timestamp "$(observability_timestamp)" \
    --arg stage "$stage" \
    --arg hypothesis "$hypothesis" \
    --arg confidence "$confidence" \
    --arg planned_check "$planned_check" \
    --arg status "$status" \
    --arg leg "$leg" \
    '{
      timestamp: $timestamp,
      stage: $stage,
      hypothesis: $hypothesis,
      confidence: $confidence,
      planned_check: $planned_check,
      status: $status,
      leg: (if $leg == "" then null else $leg end)
    }' >> "$OBS_HYPOTHESES_FILE"
}

record_action() {
  local stage="$1"
  local action="$2"
  local target="$3"
  local reason="$4"
  local outcome="$5"
  local leg="${6:-}"
  local note="${7:-}"

  jq -cn \
    --arg timestamp "$(observability_timestamp)" \
    --arg stage "$stage" \
    --arg action "$action" \
    --arg target "$target" \
    --arg reason "$reason" \
    --arg outcome "$outcome" \
    --arg leg "$leg" \
    --arg note "$note" \
    '{
      timestamp: $timestamp,
      stage: $stage,
      action: $action,
      target: $target,
      reason: $reason,
      outcome: $outcome,
      leg: (if $leg == "" then null else $leg end),
      note: (if $note == "" then null else $note end)
    }' >> "$OBS_ACTIONS_FILE"
}

update_agent_summary() {
  local status="$1"
  local stage="$2"
  local current_leg="$3"
  local current_attempt="$4"
  local latest_note="${5:-}"
  local eidolon_report_present=false
  local direct_report_present=false
  local runner_metadata_present=false
  local hypothesis_count
  local action_count
  local tool_result_count
  local runner_environment
  local runner_environment_source

  hypothesis_count="$(jsonl_line_count "$OBS_HYPOTHESES_FILE")"
  action_count="$(jsonl_line_count "$OBS_ACTIONS_FILE")"
  tool_result_count="$(tool_result_json_count)"
  runner_environment="$(runner_environment_value)"
  runner_environment_source="$(runner_environment_source_value)"

  [[ -f "$ARTIFACT_DIR/pwnkit-eidolon.json" ]] && eidolon_report_present=true
  [[ -f "$ARTIFACT_DIR/pwnkit-direct.json" ]] && direct_report_present=true
  [[ -f "$ARTIFACT_DIR/pwnkit-runner-metadata.json" ]] && runner_metadata_present=true

  jq -n \
    --arg generated_at "$(observability_timestamp)" \
    --arg artifact_dir "$ARTIFACT_DIR" \
    --arg mode "$MODE" \
    --arg status "$status" \
    --arg stage "$stage" \
    --arg current_leg "$current_leg" \
    --arg current_attempt "$current_attempt" \
    --arg latest_note "$latest_note" \
    --arg target_url "$TARGET_URL" \
    --arg proxy_url "$PROXY_URL" \
    --arg runner_environment "$runner_environment" \
    --arg runner_environment_source "$runner_environment_source" \
    --arg network_topology "$EIDOLON_M3_NETWORK_TOPOLOGY" \
    --arg observations_hypotheses_file "$(relative_artifact_path "$OBS_HYPOTHESES_FILE")" \
    --arg observations_actions_file "$(relative_artifact_path "$OBS_ACTIONS_FILE")" \
    --arg observations_tool_results_dir "$(relative_artifact_path "$OBS_TOOL_RESULTS_DIR")" \
    --argjson current_attempt_num "$(if [[ -n "$current_attempt" ]]; then printf '%s' "$current_attempt"; else printf 'null'; fi)" \
    --argjson hypothesis_count "$hypothesis_count" \
    --argjson action_count "$action_count" \
    --argjson tool_result_count "$tool_result_count" \
    --argjson eidolon_report_present "$(json_bool "$eidolon_report_present")" \
    --argjson direct_report_present "$(json_bool "$direct_report_present")" \
    --argjson runner_metadata_present "$(json_bool "$runner_metadata_present")" \
    '{
      schema_version: 1,
      run_kind: "pwnkit_agent_summary",
      boundary: "scanner_qualification",
      generated_at: $generated_at,
      artifact_dir: $artifact_dir,
      mode: $mode,
      status: $status,
      stage: $stage,
      current_leg: (if $current_leg == "" then null else $current_leg end),
      current_attempt: $current_attempt_num,
      latest_note: (if $latest_note == "" then null else $latest_note end),
      target_url: $target_url,
      proxy_url: $proxy_url,
      environment: {
        runner_environment: $runner_environment,
        runner_environment_source: $runner_environment_source,
        network_topology: $network_topology
      },
      observability: {
        hypotheses_file: $observations_hypotheses_file,
        actions_file: $observations_actions_file,
        tool_results_dir: $observations_tool_results_dir
      },
      artifact_presence: {
        runner_metadata: $runner_metadata_present,
        eidolon_report: $eidolon_report_present,
        direct_report: $direct_report_present
      },
      artifact_counts: {
        hypotheses: $hypothesis_count,
        actions: $action_count,
        tool_results: $tool_result_count
      }
    }' > "$OBS_SUMMARY_FILE"
}

write_scan_tool_result() {
  local label="$1"
  local attempt="$2"
  local url="$3"
  local scope_file="$4"
  local output_json="$5"
  local output_stdout="$6"
  local output_db="$7"
  local output_stderr="$8"
  local exit_code="$9"
  local report_valid="${10}"
  local finding_count_value="${11}"
  local agent_error_count="${12}"
  local transient_error_count="${13}"
  local result_status="${14}"
  local result_path="$OBS_TOOL_RESULTS_DIR/pwnkit-$label-attempt-$attempt.json"

  jq -n \
    --arg generated_at "$(observability_timestamp)" \
    --arg label "$label" \
    --arg target_url "$url" \
    --arg scope_file "$(relative_artifact_path "$scope_file")" \
    --arg output_json "$(relative_artifact_path "$output_json")" \
    --arg output_stdout "$(relative_artifact_path "$output_stdout")" \
    --arg output_db "$(relative_artifact_path "$output_db")" \
    --arg output_stderr "$(relative_artifact_path "$output_stderr")" \
    --arg result_status "$result_status" \
    --argjson attempt "$attempt" \
    --argjson exit_code "$exit_code" \
    --argjson report_valid "$(json_bool "$report_valid")" \
    --argjson finding_count "$finding_count_value" \
    --argjson agent_error_count "$agent_error_count" \
    --argjson transient_error_count "$transient_error_count" \
    --argjson timeout_seconds "$EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS" \
    '{
      schema_version: 1,
      run_kind: "pwnkit_tool_result",
      boundary: "scanner_qualification",
      generated_at: $generated_at,
      tool: "pwnkit",
      label: $label,
      attempt: $attempt,
      status: $result_status,
      target_url: $target_url,
      timeout_seconds: $timeout_seconds,
      scope_file: $scope_file,
      output_json: $output_json,
      output_stdout: $output_stdout,
      output_db: $output_db,
      output_stderr: $output_stderr,
      exit_code: $exit_code,
      report_valid: $report_valid,
      finding_count: $finding_count,
      agent_error_count: $agent_error_count,
      transient_error_count: $transient_error_count
    }' > "$result_path"
}

validate_fixture_id() {
  if [[ -z "$EIDOLON_M3_PWNKIT_FIXTURE_ID" ]]; then
    return
  fi

  if [[ ! "$EIDOLON_M3_PWNKIT_FIXTURE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]]; then
    echo "error: EIDOLON_M3_PWNKIT_FIXTURE_ID must be 1-128 chars using only letters, numbers, '.', '_', ':', or '-'" >&2
    exit 2
  fi
}

validate_evidence_track() {
  if [[ -z "$EIDOLON_M3_PWNKIT_EVIDENCE_TRACK" ]]; then
    return
  fi

  case "$EIDOLON_M3_PWNKIT_EVIDENCE_TRACK" in
    upstream_current|local_patched_pwnkit|historical_stale)
      ;;
    *)
      echo "error: EIDOLON_M3_PWNKIT_EVIDENCE_TRACK must be upstream_current, local_patched_pwnkit, or historical_stale" >&2
      exit 2
      ;;
  esac
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

detect_runner_environment() {
  case "$(uname -s 2>/dev/null || true)" in
    Darwin)
      printf 'host_mac'
      ;;
    Linux)
      if [[ "$(os_release_value ID)" == "kali" ]]; then
        printf 'kali_vm'
      else
        printf 'linux_host'
      fi
      ;;
    *)
      printf 'unknown'
      ;;
  esac
}

runner_environment_value() {
  if [[ "$EIDOLON_M3_RUNNER_ENVIRONMENT" == "auto" ]]; then
    detect_runner_environment
  else
    printf '%s' "$EIDOLON_M3_RUNNER_ENVIRONMENT"
  fi
}

runner_environment_source_value() {
  if [[ "$EIDOLON_M3_RUNNER_ENVIRONMENT" == "auto" ]]; then
    printf 'auto_detect'
  else
    printf 'env_override'
  fi
}

tool_version() {
  local tool="$1"
  local output=""

  if ! command -v "$tool" >/dev/null 2>&1; then
    return
  fi

  case "$tool" in
    bash|curl|node|python3|sqlite3|cargo|nmap|sqlmap)
      output="$("$tool" --version 2>&1 || true)"
      ;;
    jq)
      output="$(jq --version 2>&1 || true)"
      ;;
    ffuf)
      output="$(ffuf -V 2>&1 || ffuf --version 2>&1 || true)"
      ;;
    gobuster)
      output="$(gobuster version 2>&1 || gobuster --version 2>&1 || true)"
      ;;
    nikto)
      output="$(nikto -Version 2>&1 || nikto --version 2>&1 || true)"
      ;;
    *)
      output="$("$tool" --version 2>&1 || true)"
      ;;
  esac

  printf '%s' "$output" | sed -n '1p' | tr '\n' ' ' | cut -c1-200
}

tool_fingerprint_json() {
  local tools=(
    bash
    curl
    jq
    node
    python3
    sqlite3
    cargo
    nmap
    sqlmap
    ffuf
    gobuster
    nikto
  )
  local name
  local present
  local version

  {
    for name in "${tools[@]}"; do
      present=false
      version=""
      if command -v "$name" >/dev/null 2>&1; then
        present=true
        version="$(tool_version "$name")"
      fi

      jq -n \
        --arg name "$name" \
        --arg version "$version" \
        --argjson present "$(json_bool "$present")" \
        '{
          name: $name,
          present: $present,
          version: (if $version == "" then null else $version end)
        }'
    done
  } | jq -s '.'
}

require_positive_integer() {
  local name="$1"
  local value="$2"

  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
    echo "error: $name must be a positive integer, got: $value" >&2
    exit 2
  fi
}

resolve_pwnkit_codex_auth() {
  local access_token
  local access_token_expires_at
  local account_id
  local now_seconds
  local refresh_token

  PWNKIT_CODEX_AUTH_SOURCE="not_codex"
  PWNKIT_CODEX_ACCESS_TOKEN=""
  PWNKIT_CODEX_ACCOUNT_ID=""
  PWNKIT_CODEX_OAUTH_REFRESH_TOKEN=""

  if [[ "$PWNKIT_RUNTIME" != "codex" ]]; then
    return
  fi

  if [[ -n "${PWNKIT_CHATGPT_ACCESS_TOKEN:-}" ]]; then
    PWNKIT_CODEX_AUTH_SOURCE="access_token_env"
    return
  fi

  if [[ -n "${PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN:-}" ]]; then
    PWNKIT_CODEX_AUTH_SOURCE="refresh_token_env"
    return
  fi

  if [[ ! -f "$EIDOLON_M3_CODEX_AUTH_FILE" ]]; then
    PWNKIT_CODEX_AUTH_SOURCE="unset"
    return
  fi

  access_token="$(
    jq -er '
      (.tokens.access_token // .access_token // empty)
      | select(type == "string" and length > 0)
    ' "$EIDOLON_M3_CODEX_AUTH_FILE" 2>/dev/null || true
  )"
  if [[ -n "$access_token" ]]; then
    access_token_expires_at="$(access_token_expiry_seconds "$access_token" || true)"
    now_seconds="$(date -u '+%s')"
    if [[ "$access_token_expires_at" =~ ^[0-9]+$ ]] \
      && (( access_token_expires_at > now_seconds + 300 )); then
      account_id="$(
        jq -er '
          (.tokens.account_id // .account_id // empty)
          | select(type == "string" and length > 0)
        ' "$EIDOLON_M3_CODEX_AUTH_FILE" 2>/dev/null || true
      )"
      PWNKIT_CODEX_AUTH_SOURCE="codex_auth_file_access_token"
      PWNKIT_CODEX_ACCESS_TOKEN="$access_token"
      PWNKIT_CODEX_ACCOUNT_ID="$account_id"
      return
    fi
  fi

  refresh_token="$(
    jq -er '
      (.tokens.refresh_token // .refresh_token // empty)
      | select(type == "string" and length > 0)
    ' "$EIDOLON_M3_CODEX_AUTH_FILE" 2>/dev/null || true
  )"

  if [[ -n "$refresh_token" ]]; then
    PWNKIT_CODEX_AUTH_SOURCE="codex_auth_file_refresh_token"
    PWNKIT_CODEX_OAUTH_REFRESH_TOKEN="$refresh_token"
  else
    PWNKIT_CODEX_AUTH_SOURCE="unset"
  fi
}

access_token_expiry_seconds() {
  local access_token="$1"

  if ! command -v node >/dev/null 2>&1; then
    return 1
  fi

  printf '%s' "$access_token" | node -e '
    const fs = require("fs");
    const token = fs.readFileSync(0, "utf8").trim();
    const payload = token.split(".")[1];
    if (!payload) process.exit(1);
    try {
      const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
      if (typeof claims.exp !== "number" || !Number.isFinite(claims.exp)) {
        process.exit(1);
      }
      process.stdout.write(String(Math.floor(claims.exp)));
    } catch {
      process.exit(1);
    }
  '
}

require_jq() {
  local context="$1"

  if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq is required to $context" >&2
    exit 2
  fi
}

write_pwnkit_scope_file() {
  local label="$1"
  local url="$2"
  local scope_file="$ARTIFACT_DIR/pwnkit-$label-scope.json"
  local host
  local bracketed_host=""

  host="$(eidolon_lab_host_for_url "$label target URL" "$url")"
  if [[ "$host" == *:* ]]; then
    bracketed_host="[$host]"
  fi

  require_jq "write pwnkit scope files"
  jq -n \
    --arg host "$host" \
    --arg bracketed_host "$bracketed_host" \
    '{
      in_scope: ([ $host, $bracketed_host ] | map(select(. != "")) | unique),
      out_of_scope: []
    }' > "$scope_file"

  printf '%s' "$scope_file"
}

require_supported_target_urls() {
  case "$EIDOLON_M3_NETWORK_TOPOLOGY" in
    same_host_loopback|same_vm_loopback|vm_loopback_forward)
      eidolon_lab_require_loopback_url "EIDOLON_LAB_TARGET_URL" "$TARGET_URL"
      eidolon_lab_require_loopback_url "EIDOLON_LAB_PROXY_URL" "$PROXY_URL"
      ;;
    kali_vm_to_orbstack_nodeport)
      eidolon_lab_require_http_url "EIDOLON_LAB_TARGET_URL" "$TARGET_URL"
      eidolon_lab_require_http_url "EIDOLON_LAB_PROXY_URL" "$PROXY_URL"
      ;;
    *)
      eidolon_lab_require_loopback_url "EIDOLON_LAB_TARGET_URL" "$TARGET_URL"
      eidolon_lab_require_loopback_url "EIDOLON_LAB_PROXY_URL" "$PROXY_URL"
      ;;
  esac
}

write_runner_metadata() {
  local metadata_file="$ARTIFACT_DIR/pwnkit-runner-metadata.json"
  local pwnkit_command_quoted
  local pwnkit_entry_mtime=""
  local pwnkit_repo_dir=""
  local pwnkit_git_head=""
  local pwnkit_git_head_short=""
  local pwnkit_git_head_time=""
  local pwnkit_git_branch=""
  local pwnkit_package_version=""
  local pwnkit_git_dirty=""
  local pwnkit_origin_main_head=""
  local pwnkit_origin_main_head_short=""
  local pwnkit_origin_main_ahead=""
  local pwnkit_origin_main_behind=""
  local pwnkit_origin_fetch_url=""
  local pwnkit_origin_push_url=""
  local origin_relation=""
  local allow_stale_dist
  local pin_session
  local runner_environment
  local runner_environment_source
  local tool_fingerprint

  require_jq "write pwnkit runner metadata"

  printf -v pwnkit_command_quoted '%q ' "${PWNKIT_COMMAND[@]}"
  pwnkit_command_quoted="${pwnkit_command_quoted% }"
  if [[ -n "${PWNKIT_ENTRY_PATH:-}" && -f "$PWNKIT_ENTRY_PATH" ]]; then
    pwnkit_entry_mtime="$(mtime_seconds "$PWNKIT_ENTRY_PATH")"
    if pwnkit_repo_dir="$(pwnkit_repo_dir_for_entry "$PWNKIT_ENTRY_PATH")"; then
      pwnkit_git_head="$(git -C "$pwnkit_repo_dir" rev-parse HEAD 2>/dev/null || true)"
      if [[ -n "$pwnkit_git_head" ]]; then
        pwnkit_git_head_short="${pwnkit_git_head:0:12}"
      fi
      pwnkit_git_head_time="$(git -C "$pwnkit_repo_dir" log -1 --format=%ct 2>/dev/null || true)"
      pwnkit_git_branch="$(git -C "$pwnkit_repo_dir" symbolic-ref --quiet --short HEAD 2>/dev/null || true)"
      if [[ -f "$pwnkit_repo_dir/package.json" ]]; then
        pwnkit_package_version="$(jq -r '.version // empty' "$pwnkit_repo_dir/package.json" 2>/dev/null || true)"
      fi
      pwnkit_git_dirty=false
      if [[ -n "$(git -C "$pwnkit_repo_dir" status --porcelain 2>/dev/null)" ]]; then
        pwnkit_git_dirty=true
      fi
      pwnkit_origin_fetch_url="$(git -C "$pwnkit_repo_dir" remote get-url origin 2>/dev/null || true)"
      pwnkit_origin_push_url="$(git -C "$pwnkit_repo_dir" remote get-url --push origin 2>/dev/null || true)"
      pwnkit_origin_main_head="$(git -C "$pwnkit_repo_dir" rev-parse refs/remotes/origin/main 2>/dev/null || true)"
      if [[ -n "$pwnkit_origin_main_head" ]]; then
        pwnkit_origin_main_head_short="${pwnkit_origin_main_head:0:12}"
        origin_relation="$(git -C "$pwnkit_repo_dir" rev-list --left-right --count HEAD...refs/remotes/origin/main 2>/dev/null || true)"
        if [[ "$origin_relation" =~ ^([0-9]+)[[:space:]]+([0-9]+)$ ]]; then
          pwnkit_origin_main_ahead="${BASH_REMATCH[1]}"
          pwnkit_origin_main_behind="${BASH_REMATCH[2]}"
        fi
      fi
    else
      pwnkit_repo_dir=""
    fi
  fi

  allow_stale_dist="$(json_bool "$EIDOLON_M3_ALLOW_STALE_PWNKIT_DIST")"
  pin_session="$(json_bool "$EIDOLON_M3_PIN_SESSION")"
  runner_environment="$(runner_environment_value)"
  runner_environment_source="$(runner_environment_source_value)"
  tool_fingerprint="$(tool_fingerprint_json)"

  jq -n \
    --arg created_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    --arg mode "$MODE" \
    --arg target_url "$TARGET_URL" \
    --arg proxy_url "$PROXY_URL" \
    --arg pwnkit_depth "$PWNKIT_DEPTH" \
    --arg pwnkit_mode "$PWNKIT_MODE" \
    --arg pwnkit_runtime "$PWNKIT_RUNTIME" \
    --arg pwnkit_rate_limit "$PWNKIT_RATE_LIMIT" \
    --argjson pwnkit_max_attempts "$EIDOLON_M3_PWNKIT_MAX_ATTEMPTS" \
    --argjson pwnkit_timeout_seconds "$EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS" \
    --argjson pwnkit_heartbeat_seconds "$EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS" \
    --arg pwnkit_feature_codex_live_targets "$PWNKIT_FEATURE_CODEX_LIVE_TARGETS" \
    --arg pwnkit_command "$pwnkit_command_quoted" \
    --arg pwnkit_command_source "${PWNKIT_COMMAND_SOURCE:-unknown}" \
    --arg pwnkit_source_dir "$PWNKIT_SOURCE_DIR" \
    --arg pwnkit_entry_path "${PWNKIT_ENTRY_PATH:-}" \
    --arg pwnkit_entry_mtime "$pwnkit_entry_mtime" \
    --arg pwnkit_repo_dir "$pwnkit_repo_dir" \
    --arg pwnkit_package_version "$pwnkit_package_version" \
    --arg pwnkit_git_head "$pwnkit_git_head" \
    --arg pwnkit_git_head_short "$pwnkit_git_head_short" \
    --arg pwnkit_git_head_time "$pwnkit_git_head_time" \
    --arg pwnkit_git_branch "$pwnkit_git_branch" \
    --arg pwnkit_git_dirty "$pwnkit_git_dirty" \
    --arg pwnkit_origin_main_head "$pwnkit_origin_main_head" \
    --arg pwnkit_origin_main_head_short "$pwnkit_origin_main_head_short" \
    --arg pwnkit_origin_main_ahead "$pwnkit_origin_main_ahead" \
    --arg pwnkit_origin_main_behind "$pwnkit_origin_main_behind" \
    --arg pwnkit_origin_fetch_url "$pwnkit_origin_fetch_url" \
    --arg pwnkit_origin_push_url "$pwnkit_origin_push_url" \
    --arg pwnkit_fixture_id "$EIDOLON_M3_PWNKIT_FIXTURE_ID" \
    --arg pwnkit_evidence_track "$EIDOLON_M3_PWNKIT_EVIDENCE_TRACK" \
    --arg pwnkit_codex_auth_source "$PWNKIT_CODEX_AUTH_SOURCE" \
    --arg pwnkit_eidolon_scope_file "$PWNKIT_EIDOLON_SCOPE_FILE" \
    --arg pwnkit_direct_scope_file "$PWNKIT_DIRECT_SCOPE_FILE" \
    --arg runner_environment "$runner_environment" \
    --arg runner_environment_source "$runner_environment_source" \
    --arg network_topology "$EIDOLON_M3_NETWORK_TOPOLOGY" \
    --arg kernel_name "$(uname -s 2>/dev/null || true)" \
    --arg kernel_release "$(uname -r 2>/dev/null || true)" \
    --arg kernel_version "$(uname -v 2>/dev/null || true)" \
    --arg machine_arch "$(uname -m 2>/dev/null || true)" \
    --arg os_release_id "$(os_release_value ID)" \
    --arg os_release_version_id "$(os_release_value VERSION_ID)" \
    --slurpfile pwnkit_eidolon_scope "$PWNKIT_EIDOLON_SCOPE_FILE" \
    --slurpfile pwnkit_direct_scope "$PWNKIT_DIRECT_SCOPE_FILE" \
    --argjson allow_stale_dist "$allow_stale_dist" \
    --argjson pin_session "$pin_session" \
    --argjson tool_fingerprint "$tool_fingerprint" \
    '{
      schema_version: 1,
      run_kind: "m3_pwnkit_codex_runner",
      created_at: $created_at,
      mode: $mode,
      urls: {
        target: $target_url,
        proxy: $proxy_url
      },
      environment: {
        runner_environment: $runner_environment,
        runner_environment_source: $runner_environment_source,
        network_topology: $network_topology,
        os: {
          kernel_name: (if $kernel_name == "" then null else $kernel_name end),
          kernel_release: (if $kernel_release == "" then null else $kernel_release end),
          kernel_version: (if $kernel_version == "" then null else $kernel_version end),
          machine_arch: (if $machine_arch == "" then null else $machine_arch end),
          os_release_id: (if $os_release_id == "" then null else $os_release_id end),
          os_release_version_id: (
            if $os_release_version_id == "" then null else $os_release_version_id end
          )
        },
        tool_fingerprint: $tool_fingerprint
      },
      pwnkit: {
        evidence_track: (
          if $pwnkit_evidence_track != "" then
            $pwnkit_evidence_track
          elif $allow_stale_dist then
            "historical_stale"
          elif $pwnkit_git_dirty == "true" then
            "local_patched_pwnkit"
          elif $pwnkit_origin_main_ahead != ""
            and (($pwnkit_origin_main_ahead | tonumber) > 0) then
            "local_patched_pwnkit"
          elif $pwnkit_git_dirty == "false"
            and $pwnkit_origin_main_ahead != ""
            and $pwnkit_origin_main_behind != ""
            and (($pwnkit_origin_main_ahead | tonumber) == 0)
            and (($pwnkit_origin_main_behind | tonumber) == 0) then
            "upstream_current"
          elif $pwnkit_origin_main_behind != ""
            and (($pwnkit_origin_main_behind | tonumber) > 0) then
            "historical_stale"
          elif $pwnkit_fixture_id != ""
            and $pwnkit_git_head != ""
            and $pwnkit_git_dirty == "false" then
            "local_patched_pwnkit"
          else
            null
          end
        ),
        depth: $pwnkit_depth,
        mode: $pwnkit_mode,
        runtime: $pwnkit_runtime,
        rate_limit: $pwnkit_rate_limit,
        max_attempts: $pwnkit_max_attempts,
        timeout_seconds: $pwnkit_timeout_seconds,
        heartbeat_seconds: $pwnkit_heartbeat_seconds,
        feature_codex_live_targets: (
          if $pwnkit_feature_codex_live_targets == "" then null
          else $pwnkit_feature_codex_live_targets
          end
        ),
        command: $pwnkit_command,
        command_source: $pwnkit_command_source,
        source_dir: (
          if $pwnkit_command_source == "PWNKIT_SOURCE_DIR" and $pwnkit_source_dir != "" then
            $pwnkit_source_dir
          else
            null
          end
        ),
        entry_path: (if $pwnkit_entry_path == "" then null else $pwnkit_entry_path end),
        entry_mtime_seconds: (
          if $pwnkit_entry_mtime == "" then null
          else ($pwnkit_entry_mtime | tonumber)
          end
        ),
        repo_dir: (if $pwnkit_repo_dir == "" then null else $pwnkit_repo_dir end),
        package_version: (
          if $pwnkit_package_version == "" then null else $pwnkit_package_version end
        ),
        git_head: (if $pwnkit_git_head == "" then null else $pwnkit_git_head end),
        git_head_short: (
          if $pwnkit_git_head_short == "" then null else $pwnkit_git_head_short end
        ),
        git_head_time_seconds: (
          if $pwnkit_git_head_time == "" then null
          else ($pwnkit_git_head_time | tonumber)
          end
        ),
        git_branch: (
          if $pwnkit_git_branch == "" then null else $pwnkit_git_branch end
        ),
        git_dirty: (
          if $pwnkit_git_dirty == "" then null else ($pwnkit_git_dirty == "true") end
        ),
        remote_origin: {
          fetch_url: (
            if $pwnkit_origin_fetch_url == "" then null else $pwnkit_origin_fetch_url end
          ),
          push_url: (
            if $pwnkit_origin_push_url == "" then null else $pwnkit_origin_push_url end
          )
        },
        origin_main: {
          head: (
            if $pwnkit_origin_main_head == "" then null else $pwnkit_origin_main_head end
          ),
          head_short: (
            if $pwnkit_origin_main_head_short == "" then null else $pwnkit_origin_main_head_short end
          ),
          ahead: (
            if $pwnkit_origin_main_ahead == "" then null
            else ($pwnkit_origin_main_ahead | tonumber)
            end
          ),
          behind: (
            if $pwnkit_origin_main_behind == "" then null
            else ($pwnkit_origin_main_behind | tonumber)
            end
          ),
          in_sync: (
            if $pwnkit_origin_main_ahead == "" or $pwnkit_origin_main_behind == "" then
              null
            else
              (($pwnkit_origin_main_ahead | tonumber) == 0
                and ($pwnkit_origin_main_behind | tonumber) == 0)
            end
          )
        },
        fixture: {
          id: (if $pwnkit_fixture_id == "" then null else $pwnkit_fixture_id end),
          pinned: ($pwnkit_fixture_id != "")
        },
        codex_auth: {
          source: $pwnkit_codex_auth_source,
          auto_loaded_access_token: (
            $pwnkit_codex_auth_source == "codex_auth_file_access_token"
          ),
          auto_loaded_refresh_token: (
            $pwnkit_codex_auth_source == "codex_auth_file_refresh_token"
          )
        },
        stale_dist_guard_bypassed: $allow_stale_dist,
        scopes: {
          eidolon: {
            path: $pwnkit_eidolon_scope_file,
            in_scope: ($pwnkit_eidolon_scope[0].in_scope // []),
            out_of_scope: ($pwnkit_eidolon_scope[0].out_of_scope // [])
          },
          direct: {
            path: $pwnkit_direct_scope_file,
            in_scope: ($pwnkit_direct_scope[0].in_scope // []),
            out_of_scope: ($pwnkit_direct_scope[0].out_of_scope // [])
          }
        }
      },
      eidolon: {
        pinned_session_enabled: $pin_session
      }
    }' > "$metadata_file"
}

new_session_id() {
  if ! command -v uuidgen >/dev/null 2>&1; then
    echo "error: EIDOLON_M3_PIN_SESSION requires uuidgen or EIDOLON_M3_SESSION_ID" >&2
    exit 2
  fi

  uuidgen | tr '[:upper:]' '[:lower:]'
}

validate_session_id() {
  local session_id="$1"

  if [[ ! "$session_id" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
    echo "error: EIDOLON_M3_SESSION_ID must be a UUID, got: $session_id" >&2
    exit 2
  fi
}

write_eidolon_auth_file() {
  local label="$1"
  local auth_file="$ARTIFACT_DIR/pwnkit-$label-auth.json"

  printf '{"type":"cookie","value":"eidolon_session=%s"}\n' \
    "$PINNED_EIDOLON_SESSION_ID" > "$auth_file"
  printf '%s\n' "$PINNED_EIDOLON_SESSION_ID" > "$ARTIFACT_DIR/pinned-eidolon-session-id.txt"
  printf '%s' "$auth_file"
}

valid_pwnkit_report() {
  local report_file="$1"

  if [[ ! -s "$report_file" ]]; then
    return 1
  fi

  if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq is required to validate nonzero pwnkit reports" >&2
    return 1
  fi

  jq -e 'type == "object" and (.findings | type == "array")' "$report_file" >/dev/null 2>&1
}

normalize_pwnkit_report() {
  local raw_stdout="$1"
  local output_json="$2"
  local normalized_tmp="$output_json.tmp"

  cp "$raw_stdout" "$output_json"
  if valid_pwnkit_report "$output_json"; then
    return 0
  fi

  sed '/^cost: /d;/^PWNKIT_RESULT=/d' "$raw_stdout" > "$normalized_tmp"
  mv "$normalized_tmp" "$output_json"
  valid_pwnkit_report "$output_json"
}

has_findings() {
  local report_file="$1"
  jq -e '(.findings // []) | length > 0' "$report_file" >/dev/null
}

finding_count() {
  local report_file="$1"
  jq -r '(.findings // []) | length' "$report_file"
}

pwnkit_db_scalar() {
  local db_file="$1"
  local query="$2"

  if [[ ! -f "$db_file" ]] || ! command -v sqlite3 >/dev/null 2>&1; then
    printf '0'
    return
  fi

  sqlite3 "$db_file" "$query" 2>/dev/null || printf '0'
}

pwnkit_agent_error_count() {
  local db_file="$1"

  pwnkit_db_scalar "$db_file" \
    "select count(*)
     from pipeline_events
     where eventType = 'agent_error'
       and lower(coalesce(json_extract(payload, '$.error'), ''))
         not like 'transient (retry %';"
}

pwnkit_transient_agent_error_count() {
  local db_file="$1"

  pwnkit_db_scalar "$db_file" \
    "with agent_errors as (
       select lower(coalesce(json_extract(payload, '$.error'), '')) as error
       from pipeline_events
       where eventType = 'agent_error'
         and lower(coalesce(json_extract(payload, '$.error'), ''))
           not like 'transient (retry %'
     )
     select count(*) from agent_errors
     where error not like '%refresh token%'
       and error not like '%token refresh failed%'
       and error not like '%401%'
       and error not like '%invalid_request_error%'
       and error not like '%authentication%'
       and error like '%codex backend%'
       and (
         error like '%timed out%'
         or error like '%timeout%'
         or error like '%api error%'
       );"
}

record_pwnkit_runner_agent_error() {
  local db_file="$1"
  local event_id="$2"
  local error="$3"
  local payload
  local escaped_payload
  local timestamp_ms

  if ! command -v sqlite3 >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
    return
  fi

  payload="$(
    jq -cn \
      --arg error "$error" \
      --arg source "eidolon_m3_pwnkit_runner" \
      '{error: $error, source: $source}'
  )"
  escaped_payload="$(printf '%s' "$payload" | sed "s/'/''/g")"
  timestamp_ms="$(date +%s)000"

  sqlite3 "$db_file" "
    create table if not exists pipeline_events (
      id text primary key,
      scanId text not null,
      stage text not null,
      eventType text not null,
      findingId text,
      agentRole text,
      payload text not null default '{}',
      timestamp integer not null
    );
    insert or replace into pipeline_events
      (id, scanId, stage, eventType, findingId, agentRole, payload, timestamp)
    values
      ('$event_id', 'eidolon-runner', 'runner', 'agent_error', null, 'runner', '$escaped_payload', $timestamp_ms);
  " >/dev/null 2>&1 || true
}

stderr_has_transient_agent_error() {
  local stderr_file="$1"

  [[ -f "$stderr_file" ]] \
    && grep -Eiq 'codex backend.*((timed out|timeout)|api error)' "$stderr_file" \
    && ! grep -Eiq '(refresh token|token refresh failed|401|invalid_request_error|authentication)' "$stderr_file"
}

run_command_with_timeout() {
  local timeout_seconds="$1"
  local output_stdout="$2"
  local output_stderr="$3"
  local label="$4"
  local attempt="$5"
  shift 5

  local timeout_marker="$output_stderr.timeout"
  local command_pid
  local timeout_watcher_pid
  local heartbeat_watcher_pid
  local start_seconds
  local elapsed_seconds
  local status

  rm -f "$timeout_marker"
  start_seconds="$(date -u '+%s')"
  echo "m3 pwnkit heartbeat label=$label attempt=$attempt status=started timeout_seconds=$timeout_seconds heartbeat_seconds=$EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS" >&2
  "$@" > "$output_stdout" 2> "$output_stderr" &
  command_pid="$!"
  (
    sleep "$timeout_seconds"
    if kill -0 "$command_pid" >/dev/null 2>&1; then
      : > "$timeout_marker"
      echo "m3 pwnkit heartbeat label=$label attempt=$attempt status=timeout elapsed_seconds=$timeout_seconds timeout_seconds=$timeout_seconds" >&2
      kill "$command_pid" >/dev/null 2>&1 || true
      sleep 2
      kill -KILL "$command_pid" >/dev/null 2>&1 || true
    fi
  ) &
  timeout_watcher_pid="$!"
  (
    while :; do
      sleep "$EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS"
      if ! kill -0 "$command_pid" >/dev/null 2>&1; then
        exit 0
      fi
      elapsed_seconds=$(( $(date -u '+%s') - start_seconds ))
      echo "m3 pwnkit heartbeat label=$label attempt=$attempt status=running elapsed_seconds=$elapsed_seconds timeout_seconds=$timeout_seconds" >&2
    done
  ) &
  heartbeat_watcher_pid="$!"

  wait "$command_pid" 2>/dev/null
  status="$?"
  kill "$timeout_watcher_pid" >/dev/null 2>&1 || true
  kill "$heartbeat_watcher_pid" >/dev/null 2>&1 || true
  wait "$timeout_watcher_pid" >/dev/null 2>&1 || true
  wait "$heartbeat_watcher_pid" >/dev/null 2>&1 || true

  if [[ -f "$timeout_marker" ]]; then
    status=124
  fi
  rm -f "$timeout_marker"
  elapsed_seconds=$(( $(date -u '+%s') - start_seconds ))
  echo "m3 pwnkit heartbeat label=$label attempt=$attempt status=finished elapsed_seconds=$elapsed_seconds exit_code=$status" >&2
  return "$status"
}

archive_scan_attempt() {
  local label="$1"
  local attempt="$2"
  local output_json="$3"
  local output_stdout="$4"
  local output_db="$5"
  local output_stderr="$6"
  local attempt_dir="$ARTIFACT_DIR/private/pwnkit-$label-attempt-$attempt"
  local artifact

  mkdir -p "$attempt_dir"
  for artifact in "$output_json" "$output_stdout" "$output_db" "$output_stderr"; do
    if [[ -e "$artifact" ]]; then
      mv "$artifact" "$attempt_dir/"
    fi
  done
}

scan_can_retry_in_place() {
  local label="$1"

  case "$label" in
    direct)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

run_scan() {
  local label="$1"
  local url="$2"
  local output_json="$ARTIFACT_DIR/pwnkit-$label.json"
  local output_stdout="$ARTIFACT_DIR/pwnkit-$label.stdout.log"
  local output_db="$ARTIFACT_DIR/pwnkit-$label.db"
  local output_stderr="$ARTIFACT_DIR/pwnkit-$label.stderr.log"
  local attempt=1
  local exit_code=0
  local scope_file
  local -a scan_args=(
    scan
    --target "$url"
    --mode "$PWNKIT_MODE"
    --depth "$PWNKIT_DEPTH"
    --runtime "$PWNKIT_RUNTIME"
    --format json
    --db-path "$output_db"
    --rate-limit "$PWNKIT_RATE_LIMIT"
  )

  local existing_artifact
  for existing_artifact in \
    "$output_json" \
    "$output_stdout" \
    "$output_db" \
    "$output_stderr"; do
    if [[ -e "$existing_artifact" ]]; then
      echo "error: refusing to reuse pwnkit $label artifacts; path already exists: $existing_artifact" >&2
      echo "       use a fresh artifact directory so SQLite rows cannot mix across scans" >&2
      return 2
    fi
  done

  case "$label" in
    eidolon)
      scope_file="$PWNKIT_EIDOLON_SCOPE_FILE"
      ;;
    direct)
      scope_file="$PWNKIT_DIRECT_SCOPE_FILE"
      ;;
    *)
      echo "error: unknown pwnkit scan label: $label" >&2
      return 2
      ;;
  esac
  scan_args+=(--scope "$scope_file")

  if [[ "$label" == "eidolon" && "$PIN_EIDOLON_SESSION" == true ]]; then
    scan_args+=(--auth "$(write_eidolon_auth_file "$label")")
  fi
  scan_args+=(--verbose)

  echo "m3 pwnkit $label -> $url" >&2
  record_hypothesis \
    "scan" \
    "pwnkit ${label} leg should produce a valid report against the configured ${label} target" \
    "medium" \
    "run pwnkit ${label} and inspect the normalized report plus stderr/stdout artifacts" \
    "planned" \
    "$label"

  while :; do
    update_agent_summary \
      "running" \
      "scan" \
      "$label" \
      "$attempt" \
      "starting pwnkit ${label} attempt ${attempt}"
    record_action \
      "scan" \
      "run_pwnkit_scan" \
      "$label" \
      "collect the ${label} leg artifacts and determine whether a valid report is produced" \
      "started" \
      "$label" \
      "attempt ${attempt}"
    set +e
    (
      export PWNKIT_NO_UPDATE_CHECK=1
      case "$PWNKIT_CODEX_AUTH_SOURCE" in
        codex_auth_file_access_token)
          unset PWNKIT_CHATGPT_ACCOUNT_ID
          export PWNKIT_CHATGPT_ACCESS_TOKEN="$PWNKIT_CODEX_ACCESS_TOKEN"
          if [[ -n "$PWNKIT_CODEX_ACCOUNT_ID" ]]; then
            export PWNKIT_CHATGPT_ACCOUNT_ID="$PWNKIT_CODEX_ACCOUNT_ID"
          fi
          ;;
        codex_auth_file_refresh_token)
          unset PWNKIT_CHATGPT_ACCOUNT_ID
          export PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN="$PWNKIT_CODEX_OAUTH_REFRESH_TOKEN"
          ;;
      esac
      if [[ -n "$PWNKIT_FEATURE_CODEX_LIVE_TARGETS" ]]; then
        export PWNKIT_FEATURE_CODEX_LIVE_TARGETS
      fi
      if truthy "$EIDOLON_M3_ALLOW_STALE_PWNKIT_DIST"; then
        export PWNKIT_ALLOW_STALE_SOURCE_DIST=1
      fi

      run_command_with_timeout \
        "$EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS" \
        "$output_stdout" \
        "$output_stderr" \
        "$label" \
        "$attempt" \
        "${PWNKIT_COMMAND[@]}" "${scan_args[@]}"
    )
    exit_code=$?
    set -e
    if [[ "$exit_code" -eq 124 ]]; then
      local timeout_error
      timeout_error="ChatGPT (Codex backend) API request timed out after Eidolon runner wall-clock timeout ${EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS}s for pwnkit $label attempt $attempt"
      printf 'warning: %s\n' "$timeout_error" >> "$output_stderr"
      record_pwnkit_runner_agent_error \
        "$output_db" \
        "eidolon-runner-timeout-$label-$attempt" \
        "$timeout_error"
    fi
    normalize_pwnkit_report "$output_stdout" "$output_json" || true

    local transient_error_count
    local agent_error_count
    transient_error_count="$(pwnkit_transient_agent_error_count "$output_db")"
    agent_error_count="$(pwnkit_agent_error_count "$output_db")"
    if [[ "$transient_error_count" -eq 0 ]] \
      && [[ "$exit_code" -ne 0 ]] \
      && stderr_has_transient_agent_error "$output_stderr"; then
      transient_error_count=1
    fi

    local report_valid=false
    local finding_count_value=0
    local action_outcome="failed"
    if valid_pwnkit_report "$output_json"; then
      report_valid=true
      finding_count_value="$(finding_count "$output_json")"
      if [[ "$exit_code" -eq 0 ]]; then
        action_outcome="completed"
      elif [[ "$exit_code" -eq 1 && "$finding_count_value" -gt 0 ]]; then
        action_outcome="completed_with_findings"
      elif [[ "$exit_code" -eq 4 ]]; then
        action_outcome="cost_ceiling_exceeded"
      else
        action_outcome="report_after_failure"
      fi
    elif [[ "$transient_error_count" -gt 0 ]]; then
      action_outcome="transient_backend_error"
    fi

    write_scan_tool_result \
      "$label" \
      "$attempt" \
      "$url" \
      "$scope_file" \
      "$output_json" \
      "$output_stdout" \
      "$output_db" \
      "$output_stderr" \
      "$exit_code" \
      "$report_valid" \
      "$finding_count_value" \
      "$agent_error_count" \
      "$transient_error_count" \
      "$action_outcome"

    if scan_can_retry_in_place "$label" \
      && [[ "$transient_error_count" -gt 0 ]] \
      && (( attempt < EIDOLON_M3_PWNKIT_MAX_ATTEMPTS )); then
      record_hypothesis \
        "retry" \
        "a retry of the ${label} leg may succeed because only transient Codex backend errors were recorded" \
        "medium" \
        "archive the failed attempt and rerun the same ${label} scan in place" \
        "planned" \
        "$label"
      record_action \
        "retry" \
        "archive_and_retry_pwnkit_scan" \
        "$label" \
        "only transient Codex backend errors were recorded" \
        "retrying" \
        "$label" \
        "attempt ${attempt}"
      update_agent_summary \
        "retrying" \
        "retry" \
        "$label" \
        "$attempt" \
        "retrying ${label} after transient backend error"
      echo "warning: pwnkit $label attempt $attempt/$EIDOLON_M3_PWNKIT_MAX_ATTEMPTS recorded transient Codex backend error; retrying with failed artifacts archived under private/" >&2
      archive_scan_attempt \
        "$label" \
        "$attempt" \
        "$output_json" \
        "$output_stdout" \
        "$output_db" \
        "$output_stderr"
      attempt=$((attempt + 1))
      continue
    fi

    if [[ "$agent_error_count" -gt 0 ]]; then
      echo "warning: pwnkit $label completed with sanitized agent_error count=$agent_error_count" >&2
    fi
    record_action \
      "scan" \
      "run_pwnkit_scan" \
      "$label" \
      "collect the ${label} leg artifacts and determine whether a valid report is produced" \
      "$action_outcome" \
      "$label" \
      "attempt ${attempt}"
    update_agent_summary \
      "$action_outcome" \
      "scan" \
      "$label" \
      "$attempt" \
      "finished pwnkit ${label} attempt ${attempt} with outcome ${action_outcome}"
    break
  done

  if [[ "$exit_code" -eq 0 ]]; then
    if valid_pwnkit_report "$output_json"; then
      return 0
    fi

    echo "error: pwnkit $label exited 0 without a valid report; see $output_json" \
      >&2
    return 2
  fi

  if [[ "$exit_code" -eq 1 ]] \
    && valid_pwnkit_report "$output_json" \
    && has_findings "$output_json"; then
    echo "warning: pwnkit $label exited 1 after writing a valid report with $(finding_count "$output_json") findings; continuing" \
      >&2
    return 0
  fi

  if [[ "$exit_code" -eq 4 ]]; then
    echo "error: pwnkit $label stopped at its cost ceiling; partial artifacts are diagnostic only" >&2
    return 4
  fi

  if valid_pwnkit_report "$output_json"; then
    echo "error: pwnkit $label exited $exit_code with a valid report but no findings; see $output_stderr" \
      >&2
    return "$exit_code"
  fi

  echo "error: pwnkit $label exited $exit_code without a valid report; see $output_stderr" \
    >&2
  return "$exit_code"
}

main() {
  if [[ "$MODE" == "-h" || "$MODE" == "--help" ]]; then
    usage
    exit 0
  fi

  require_supported_target_urls
  require_positive_integer \
    "EIDOLON_M3_PWNKIT_MAX_ATTEMPTS" \
    "$EIDOLON_M3_PWNKIT_MAX_ATTEMPTS"
  require_positive_integer \
    "EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS" \
    "$EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS"
  require_positive_integer \
    "EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS" \
    "$EIDOLON_M3_PWNKIT_HEARTBEAT_SECONDS"
  validate_fixture_id
  validate_evidence_track
  mkdir -p "$ARTIFACT_DIR"
  printf '%s\n' "$ARTIFACT_DIR" > "$ARTIFACT_DIR/artifact-dir.txt"
  initialize_observability

  PIN_EIDOLON_SESSION=false
  PINNED_EIDOLON_SESSION_ID=""
  if truthy "$EIDOLON_M3_PIN_SESSION"; then
    PIN_EIDOLON_SESSION=true
    PINNED_EIDOLON_SESSION_ID="${EIDOLON_M3_SESSION_ID:-$(new_session_id)}"
    validate_session_id "$PINNED_EIDOLON_SESSION_ID"
  fi

  declare -a PWNKIT_COMMAND
  PWNKIT_COMMAND_SOURCE="unknown"
  PWNKIT_ENTRY_PATH=""
  PWNKIT_CODEX_AUTH_SOURCE="not_codex"
  PWNKIT_CODEX_ACCESS_TOKEN=""
  PWNKIT_CODEX_ACCOUNT_ID=""
  PWNKIT_CODEX_OAUTH_REFRESH_TOKEN=""
  resolve_pwnkit_command
  PWNKIT_EIDOLON_SCOPE_FILE="$(write_pwnkit_scope_file "eidolon" "$PROXY_URL")"
  PWNKIT_DIRECT_SCOPE_FILE="$(write_pwnkit_scope_file "direct" "$TARGET_URL")"
  resolve_pwnkit_codex_auth
  write_runner_metadata
  record_hypothesis \
    "setup" \
    "the runner metadata and scope files should be sufficient to explain the scan environment before pwnkit executes" \
    "high" \
    "write runner metadata plus per-leg scope files into the artifact directory" \
    "planned"
  record_action \
    "setup" \
    "write_runner_metadata" \
    "artifact_dir" \
    "capture runtime, auth source, scope, and environment details before scanning" \
    "completed"
  update_agent_summary \
    "initialized" \
    "setup" \
    "" \
    "" \
    "runner metadata and scope files written"

  case "$MODE" in
    preflight)
      record_action \
        "preflight" \
        "complete_preflight" \
        "artifact_dir" \
        "validate local runner plumbing without executing live scans" \
        "completed"
      jq -n \
        --arg generated_at "$(observability_timestamp)" \
        --arg metadata_file "$(relative_artifact_path "$ARTIFACT_DIR/pwnkit-runner-metadata.json")" \
        --arg eidolon_scope "$(relative_artifact_path "$PWNKIT_EIDOLON_SCOPE_FILE")" \
        --arg direct_scope "$(relative_artifact_path "$PWNKIT_DIRECT_SCOPE_FILE")" \
        '{
          schema_version: 1,
          run_kind: "pwnkit_tool_result",
          boundary: "scanner_qualification",
          generated_at: $generated_at,
          tool: "pwnkit_runner_preflight",
          status: "completed",
          metadata_file: $metadata_file,
          scopes: {
            eidolon: $eidolon_scope,
            direct: $direct_scope
          }
        }' > "$OBS_TOOL_RESULTS_DIR/preflight.json"
      update_agent_summary \
        "preflight_complete" \
        "preflight" \
        "" \
        "" \
        "preflight completed without executing live scans"
      echo "m3 pwnkit preflight: $ARTIFACT_DIR" >&2
      ;;
    all)
      run_scan "eidolon" "$PROXY_URL"
      run_scan "direct" "$TARGET_URL"
      ;;
    eidolon)
      run_scan "eidolon" "$PROXY_URL"
      ;;
    direct)
      run_scan "direct" "$TARGET_URL"
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac

  local final_status="completed"
  if [[ "$MODE" == "preflight" ]]; then
    final_status="preflight_complete"
  fi

  update_agent_summary \
    "$final_status" \
    "finalize" \
    "" \
    "" \
    "runner finished"

  echo "artifacts: $ARTIFACT_DIR" >&2
}

main "$@"
