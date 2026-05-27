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
EIDOLON_M3_PWNKIT_MAX_ATTEMPTS="${EIDOLON_M3_PWNKIT_MAX_ATTEMPTS:-2}"
EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS="${EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS:-900}"
PWNKIT_FEATURE_CODEX_LIVE_TARGETS="${PWNKIT_FEATURE_CODEX_LIVE_TARGETS:-}"
EIDOLON_M3_CODEX_AUTH_FILE="${EIDOLON_M3_CODEX_AUTH_FILE:-$HOME/.codex/auth.json}"
EIDOLON_M3_PIN_SESSION="${EIDOLON_M3_PIN_SESSION:-0}"
EIDOLON_M3_SESSION_ID="${EIDOLON_M3_SESSION_ID:-}"
EIDOLON_M3_ALLOW_STALE_PWNKIT_DIST="${EIDOLON_M3_ALLOW_STALE_PWNKIT_DIST:-0}"
EIDOLON_M3_RUNNER_ENVIRONMENT="${EIDOLON_M3_RUNNER_ENVIRONMENT:-auto}"
EIDOLON_M3_NETWORK_TOPOLOGY="${EIDOLON_M3_NETWORK_TOPOLOGY:-same_host_loopback}"
EIDOLON_M3_PWNKIT_FIXTURE_ID="${EIDOLON_M3_PWNKIT_FIXTURE_ID:-}"

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
  PWNKIT_NODE_ENTRY         Path to a built pwnkit dist/pwnkit.js entrypoint.
  PWNKIT_BIN                pwnkit command name when PWNKIT_NODE_ENTRY is unset.
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
                            Defaults to same_host_loopback.
  EIDOLON_M3_PWNKIT_FIXTURE_ID
                            Optional safe label for archived/private pinned
                            pwnkit fixtures. Current-main claims should leave
                            this unset and require origin/main freshness.

The runner writes one pwnkit scope file per scan leg and always passes
`--scope`. This keeps pwnkit's shell-mode auth injection active for the
pinned-session Eidolon leg and fails closed if a leg target falls outside the
generated loopback scope.

For source checkouts, either set PWNKIT_NODE_ENTRY or keep a built checkout at
~/Projects/pwnkit/dist/pwnkit.js. This runner refuses obviously stale ignored
dist bundles unless EIDOLON_M3_ALLOW_STALE_PWNKIT_DIST=1 is set.

Some pwnkit builds exit nonzero after writing a valid JSON report with findings.
This runner keeps those reports and continues; missing or invalid reports remain
fatal.

Current pwnkit builds may append a human `cost: ...` footer after the JSON report.
The runner stores raw stdout as `pwnkit-<leg>.stdout.log` and normalizes the JSON
report into `pwnkit-<leg>.json` before validation.

The preflight mode validates local runner plumbing, writes scope files and
`pwnkit-runner-metadata.json`, and exits before running pwnkit scans.
USAGE
}

resolve_pwnkit_command() {
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

  if [[ -f "$HOME/Projects/pwnkit/dist/pwnkit.js" ]]; then
    validate_pwnkit_node_entry "$HOME/Projects/pwnkit/dist/pwnkit.js"
    set_pwnkit_node_command "$HOME/Projects/pwnkit/dist/pwnkit.js" "default_source_checkout"
    return
  fi

  if command -v pwnkit >/dev/null 2>&1; then
    PWNKIT_COMMAND=(pwnkit)
    PWNKIT_COMMAND_SOURCE="PATH:pwnkit"
    return
  fi

  if command -v pwnkit-cli >/dev/null 2>&1; then
    PWNKIT_COMMAND=(pwnkit-cli)
    PWNKIT_COMMAND_SOURCE="PATH:pwnkit-cli"
    return
  fi

  echo "error: could not find pwnkit; set PWNKIT_NODE_ENTRY or PWNKIT_BIN" >&2
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

validate_fixture_id() {
  if [[ -z "$EIDOLON_M3_PWNKIT_FIXTURE_ID" ]]; then
    return
  fi

  if [[ ! "$EIDOLON_M3_PWNKIT_FIXTURE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]]; then
    echo "error: EIDOLON_M3_PWNKIT_FIXTURE_ID must be 1-128 chars using only letters, numbers, '.', '_', ':', or '-'" >&2
    exit 2
  fi
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

  host="$(eidolon_lab_loopback_host_for_url "$label target URL" "$url")"
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

write_runner_metadata() {
  local metadata_file="$ARTIFACT_DIR/pwnkit-runner-metadata.json"
  local pwnkit_command_quoted
  local pwnkit_entry_mtime=""
  local pwnkit_repo_dir=""
  local pwnkit_git_head=""
  local pwnkit_git_head_short=""
  local pwnkit_git_head_time=""
  local pwnkit_package_version=""
  local pwnkit_git_dirty=""
  local pwnkit_origin_main_head=""
  local pwnkit_origin_main_head_short=""
  local pwnkit_origin_main_ahead=""
  local pwnkit_origin_main_behind=""
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
      if [[ -f "$pwnkit_repo_dir/package.json" ]]; then
        pwnkit_package_version="$(jq -r '.version // empty' "$pwnkit_repo_dir/package.json" 2>/dev/null || true)"
      fi
      pwnkit_git_dirty=false
      if [[ -n "$(git -C "$pwnkit_repo_dir" status --porcelain 2>/dev/null)" ]]; then
        pwnkit_git_dirty=true
      fi
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
    --arg pwnkit_feature_codex_live_targets "$PWNKIT_FEATURE_CODEX_LIVE_TARGETS" \
    --arg pwnkit_command "$pwnkit_command_quoted" \
    --arg pwnkit_command_source "${PWNKIT_COMMAND_SOURCE:-unknown}" \
    --arg pwnkit_entry_path "${PWNKIT_ENTRY_PATH:-}" \
    --arg pwnkit_entry_mtime "$pwnkit_entry_mtime" \
    --arg pwnkit_repo_dir "$pwnkit_repo_dir" \
    --arg pwnkit_package_version "$pwnkit_package_version" \
    --arg pwnkit_git_head "$pwnkit_git_head" \
    --arg pwnkit_git_head_short "$pwnkit_git_head_short" \
    --arg pwnkit_git_head_time "$pwnkit_git_head_time" \
    --arg pwnkit_git_dirty "$pwnkit_git_dirty" \
    --arg pwnkit_origin_main_head "$pwnkit_origin_main_head" \
    --arg pwnkit_origin_main_head_short "$pwnkit_origin_main_head_short" \
    --arg pwnkit_origin_main_ahead "$pwnkit_origin_main_ahead" \
    --arg pwnkit_origin_main_behind "$pwnkit_origin_main_behind" \
    --arg pwnkit_fixture_id "$EIDOLON_M3_PWNKIT_FIXTURE_ID" \
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
        depth: $pwnkit_depth,
        mode: $pwnkit_mode,
        runtime: $pwnkit_runtime,
        rate_limit: $pwnkit_rate_limit,
        max_attempts: $pwnkit_max_attempts,
        timeout_seconds: $pwnkit_timeout_seconds,
        feature_codex_live_targets: (
          if $pwnkit_feature_codex_live_targets == "" then null
          else $pwnkit_feature_codex_live_targets
          end
        ),
        command: $pwnkit_command,
        command_source: $pwnkit_command_source,
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
        git_dirty: (
          if $pwnkit_git_dirty == "" then null else ($pwnkit_git_dirty == "true") end
        ),
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
    "select count(*) from pipeline_events where eventType = 'agent_error';"
}

pwnkit_transient_agent_error_count() {
  local db_file="$1"

  pwnkit_db_scalar "$db_file" \
    "with agent_errors as (
       select lower(coalesce(json_extract(payload, '$.error'), '')) as error
       from pipeline_events
       where eventType = 'agent_error'
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
  shift 3

  if command -v timeout >/dev/null 2>&1; then
    timeout "$timeout_seconds" "$@" > "$output_stdout" 2> "$output_stderr"
    local status="$?"
    if [[ "$status" -eq 124 || "$status" -eq 137 ]]; then
      return 124
    fi
    return "$status"
  fi

  local timeout_marker="$output_stderr.timeout"
  local command_pid
  local watcher_pid
  local status

  rm -f "$timeout_marker"
  "$@" > "$output_stdout" 2> "$output_stderr" &
  command_pid="$!"
  (
    sleep "$timeout_seconds"
    if kill -0 "$command_pid" >/dev/null 2>&1; then
      : > "$timeout_marker"
      kill "$command_pid" >/dev/null 2>&1 || true
      sleep 2
      kill -KILL "$command_pid" >/dev/null 2>&1 || true
    fi
  ) &
  watcher_pid="$!"

  wait "$command_pid" 2>/dev/null
  status="$?"
  kill "$watcher_pid" >/dev/null 2>&1 || true
  wait "$watcher_pid" >/dev/null 2>&1 || true

  if [[ -f "$timeout_marker" ]]; then
    status=124
  fi
  rm -f "$timeout_marker"
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
  local -a pwnkit_env=(
    PWNKIT_NO_UPDATE_CHECK=1
  )
  case "$PWNKIT_CODEX_AUTH_SOURCE" in
    codex_auth_file_access_token)
      pwnkit_env=(-u PWNKIT_CHATGPT_ACCOUNT_ID "${pwnkit_env[@]}")
      pwnkit_env+=(PWNKIT_CHATGPT_ACCESS_TOKEN="$PWNKIT_CODEX_ACCESS_TOKEN")
      if [[ -n "$PWNKIT_CODEX_ACCOUNT_ID" ]]; then
        pwnkit_env+=(PWNKIT_CHATGPT_ACCOUNT_ID="$PWNKIT_CODEX_ACCOUNT_ID")
      fi
      ;;
    codex_auth_file_refresh_token)
      pwnkit_env=(-u PWNKIT_CHATGPT_ACCOUNT_ID "${pwnkit_env[@]}")
      pwnkit_env+=(
        PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN="$PWNKIT_CODEX_OAUTH_REFRESH_TOKEN"
      )
      ;;
  esac
  if [[ -n "$PWNKIT_FEATURE_CODEX_LIVE_TARGETS" ]]; then
    pwnkit_env+=(PWNKIT_FEATURE_CODEX_LIVE_TARGETS="$PWNKIT_FEATURE_CODEX_LIVE_TARGETS")
  fi

  while :; do
    set +e
    run_command_with_timeout \
      "$EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS" \
      "$output_stdout" \
      "$output_stderr" \
      env "${pwnkit_env[@]}" "${PWNKIT_COMMAND[@]}" "${scan_args[@]}"
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

    if scan_can_retry_in_place "$label" \
      && [[ "$transient_error_count" -gt 0 ]] \
      && (( attempt < EIDOLON_M3_PWNKIT_MAX_ATTEMPTS )); then
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

  if valid_pwnkit_report "$output_json" && has_findings "$output_json"; then
    echo "warning: pwnkit $label exited $exit_code after writing a valid report with $(finding_count "$output_json") findings; continuing" \
      >&2
    return 0
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

  eidolon_lab_require_loopback_url "EIDOLON_LAB_TARGET_URL" "$TARGET_URL"
  eidolon_lab_require_loopback_url "EIDOLON_LAB_PROXY_URL" "$PROXY_URL"
  require_positive_integer \
    "EIDOLON_M3_PWNKIT_MAX_ATTEMPTS" \
    "$EIDOLON_M3_PWNKIT_MAX_ATTEMPTS"
  require_positive_integer \
    "EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS" \
    "$EIDOLON_M3_PWNKIT_TIMEOUT_SECONDS"
  validate_fixture_id
  mkdir -p "$ARTIFACT_DIR"
  printf '%s\n' "$ARTIFACT_DIR" > "$ARTIFACT_DIR/artifact-dir.txt"

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

  case "$MODE" in
    preflight)
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

  echo "artifacts: $ARTIFACT_DIR" >&2
}

main "$@"
