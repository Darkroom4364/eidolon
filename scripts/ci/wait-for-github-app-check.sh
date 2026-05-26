#!/usr/bin/env bash
set -euo pipefail

APP_SLUG="${FOXGUARD_APP_SLUG:-foxguard}"
CHECK_NAME="${FOXGUARD_CHECK_NAME:-}"
ACCEPTABLE_CONCLUSIONS="${FOXGUARD_ACCEPTABLE_CONCLUSIONS:-success}"
REQUIRED="${FOXGUARD_REQUIRED:-0}"
MAX_WAIT_SECONDS="${FOXGUARD_MAX_WAIT_SECONDS:-600}"
POLL_SECONDS="${FOXGUARD_POLL_SECONDS:-15}"
REPOSITORY="${GITHUB_REPOSITORY:-}"
PRIMARY_SHA="${FOXGUARD_HEAD_SHA:-${GITHUB_SHA:-}}"
FALLBACK_SHA="${FOXGUARD_FALLBACK_SHA:-}"

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

truthy() {
  local value
  value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$value" in
    1|true|yes|on|required)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

candidate_shas() {
  local seen=""
  local sha

  for sha in "$PRIMARY_SHA" "$FALLBACK_SHA"; do
    if [[ -n "$sha" && " $seen " != *" $sha "* ]]; then
      printf '%s\n' "$sha"
      seen="$seen $sha"
    fi
  done
}

foxguard_runs_json() {
  local sha="$1"

  gh api \
    -H "Accept: application/vnd.github+json" \
    "repos/$REPOSITORY/commits/$sha/check-runs?filter=all&per_page=100" \
    | jq --arg app "$APP_SLUG" --arg check "$CHECK_NAME" '
      [.check_runs[]
        | select(((.app.slug // .app.name // "") | ascii_downcase) == ($app | ascii_downcase))
        | select($check == "" or .name == $check)]
    '
}

run_count() {
  local runs="$1"
  jq 'length' <<<"$runs"
}

pending_count() {
  local runs="$1"
  jq '[.[] | select(.status != "completed")] | length' <<<"$runs"
}

failed_runs() {
  local runs="$1"
  jq -r --arg conclusions "$ACCEPTABLE_CONCLUSIONS" '
    ($conclusions | split(",") | map(gsub("^\\s+|\\s+$"; ""))) as $allowed
    | .[]
    | select(.status == "completed")
    | select((.conclusion // "") as $conclusion | ($allowed | index($conclusion)) | not)
    | "\(.name):\(.conclusion // "missing-conclusion")"
  ' <<<"$runs"
}

summarize_runs() {
  local runs="$1"

  jq -r '
    if length == 0 then
      "no matching check runs"
    else
      [.[] | "\(.name)=\(.status)/\(.conclusion // "pending")"] | join(", ")
    end
  ' <<<"$runs"
}

wait_for_foxguard() {
  local deadline=$((SECONDS + MAX_WAIT_SECONDS))
  local sha
  local runs
  local count
  local pending
  local failed
  local found_any

  while (( SECONDS <= deadline )); do
    found_any=0

    while IFS= read -r sha; do
      runs="$(foxguard_runs_json "$sha")"
      count="$(run_count "$runs")"

      if (( count == 0 )); then
        echo "Foxguard check not found on $sha yet"
        continue
      fi
      found_any=1

      pending="$(pending_count "$runs")"
      if (( pending > 0 )); then
        echo "Foxguard pending on $sha: $(summarize_runs "$runs")"
        break
      fi

      failed="$(failed_runs "$runs")"
      if [[ -n "$failed" ]]; then
        echo "Foxguard completed with non-acceptable conclusion(s) on $sha:" >&2
        echo "$failed" >&2
        return 1
      fi

      echo "Foxguard passed on $sha: $(summarize_runs "$runs")"
      return 0
    done < <(candidate_shas)

    if (( found_any == 0 )) && ! truthy "$REQUIRED"; then
      echo "Foxguard check was not found; passing because FOXGUARD_REQUIRED is not enabled"
      echo "Set FOXGUARD_REQUIRED=1 after the Foxguard GitHub App is installed and posting checks"
      return 0
    fi

    sleep "$POLL_SECONDS"
  done

  if ! truthy "$REQUIRED"; then
    echo "Foxguard check did not complete within ${MAX_WAIT_SECONDS}s; passing because FOXGUARD_REQUIRED is not enabled"
    echo "Set FOXGUARD_REQUIRED=1 after the Foxguard GitHub App is installed and posting checks"
    return 0
  fi

  echo "Foxguard check did not complete within ${MAX_WAIT_SECONDS}s" >&2
  return 1
}

main() {
  require_command gh
  require_command jq
  require_positive_integer FOXGUARD_MAX_WAIT_SECONDS "$MAX_WAIT_SECONDS"
  require_positive_integer FOXGUARD_POLL_SECONDS "$POLL_SECONDS"

  if [[ -z "$REPOSITORY" ]]; then
    fail "GITHUB_REPOSITORY is required"
  fi
  if [[ -z "$PRIMARY_SHA" ]]; then
    fail "FOXGUARD_HEAD_SHA or GITHUB_SHA is required"
  fi
  if [[ -z "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]]; then
    fail "GH_TOKEN or GITHUB_TOKEN is required"
  fi

  wait_for_foxguard
}

main "$@"
