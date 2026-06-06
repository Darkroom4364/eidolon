#!/usr/bin/env bash
set -euo pipefail

KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
EXPECTED_CONTEXT="${EIDOLON_SHIELD_EXPECT_CONTEXT:-orbstack}"

TARGET="${1:-all}"
FOLLOW=0
TAIL_LINES=50
DRY_RUN=0

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/logs-orbstack.sh [proxy|target|all] [--follow] [--tail N] [--dry-run]

Streams or prints logs for the OrbStack Shield lab workloads.
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

kubectl_cmd() {
  "$KUBECTL_BIN" "$@"
}

run_logged_command() {
  local label="$1"
  shift

  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '[%s] ' "$label"
    printf '%q ' "$@"
    printf '\n'
    return 0
  fi

  "$@"
}

if [[ "$TARGET" == "-h" || "$TARGET" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "$TARGET" != "proxy" && "$TARGET" != "target" && "$TARGET" != "all" ]]; then
  fail "target must be one of: proxy, target, all"
fi

shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --follow)
      FOLLOW=1
      ;;
    --tail)
      shift || fail "missing value for --tail"
      [[ "$1" =~ ^[0-9]+$ ]] || fail "--tail must be a non-negative integer"
      TAIL_LINES="$1"
      ;;
    --dry-run)
      DRY_RUN=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
  shift
done

require_command "$KUBECTL_BIN"

context="$(kubectl_cmd config current-context)"
if [[ "$context" != "$EXPECTED_CONTEXT" ]]; then
  fail "expected kubectl current-context to be ${EXPECTED_CONTEXT}, got: ${context}"
fi

proxy_cmd=("$KUBECTL_BIN" -n shield-system logs "--tail=${TAIL_LINES}" deploy/eidolon-shield-proxy)
target_cmd=("$KUBECTL_BIN" -n shield-targets logs "--tail=${TAIL_LINES}" deploy/eidolon-owned-demo-target)

if [[ "$FOLLOW" -eq 1 ]]; then
  proxy_cmd=("$KUBECTL_BIN" -n shield-system logs -f "--tail=${TAIL_LINES}" deploy/eidolon-shield-proxy)
  target_cmd=("$KUBECTL_BIN" -n shield-targets logs -f "--tail=${TAIL_LINES}" deploy/eidolon-owned-demo-target)
fi

case "$TARGET" in
  proxy)
    run_logged_command proxy "${proxy_cmd[@]}"
    ;;
  target)
    run_logged_command target "${target_cmd[@]}"
    ;;
  all)
    if [[ "$FOLLOW" -eq 1 ]]; then
      if [[ "$DRY_RUN" -eq 1 ]]; then
        run_logged_command proxy "${proxy_cmd[@]}"
        run_logged_command target "${target_cmd[@]}"
        exit 0
      fi

      trap 'kill 0 2>/dev/null || true' INT TERM EXIT
      "${proxy_cmd[@]}" | sed 's/^/[proxy] /' &
      "${target_cmd[@]}" | sed 's/^/[target] /' &
      wait
    else
      printf '== proxy ==\n'
      run_logged_command proxy "${proxy_cmd[@]}"
      printf '\n== target ==\n'
      run_logged_command target "${target_cmd[@]}"
    fi
    ;;
esac
