#!/usr/bin/env bash
set -euo pipefail

MATRIX_FILE="${1:-}"
EIDOLON_M3_ALLOW_UNHEALTHY_PROMOTION_MATRIX="${EIDOLON_M3_ALLOW_UNHEALTHY_PROMOTION_MATRIX:-0}"

usage() {
  cat <<'USAGE'
Usage: examples/m3/check-pwnkit-promotion-matrix-health.sh <pwnkit-promotion-matrix.json>

Fails closed when an M3 pwnkit promotion matrix is not healthy enough to
interpret. The check prints only sanitized aggregate matrix_health booleans,
counts, runner git heads, and runner package versions.

Environment:
  EIDOLON_M3_ALLOW_UNHEALTHY_PROMOTION_MATRIX
      Set to exactly 1 to allow unhealthy promotion matrices for diagnostics.
      Defaults to 0.
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

print_sanitized_matrix_health() {
  jq -r '
    def safe_token:
      tostring
      | if test("^[A-Za-z0-9._:+-]+$") then . else "<redacted>" end;
    def bool_or_unknown($value):
      if $value == null then "unknown" else ($value | tostring) end;
    def count_or_unknown($value):
      if ($value | type) == "number" then ($value | tostring) else "unknown" end;
    (.matrix_health // {}) as $health
    | "       matrix_health.ready_for_matrix_interpretation=\(bool_or_unknown($health.ready_for_matrix_interpretation))",
      "       matrix_health.all_variants_observed=\(bool_or_unknown($health.all_variants_observed))",
      "       matrix_health.all_observed_samples_agent_error_free=\(bool_or_unknown($health.all_observed_samples_agent_error_free))",
      "       matrix_health.all_observed_source_checkouts_clean=\(bool_or_unknown($health.all_observed_source_checkouts_clean))",
      "       matrix_health.all_observed_source_checkouts_synced=\(bool_or_unknown($health.all_observed_source_checkouts_synced))",
      "       matrix_health.missing_variant_count=\(count_or_unknown($health.missing_variant_count))",
      "       matrix_health.total_pwnkit_agent_errors=\(count_or_unknown($health.total_pwnkit_agent_errors))",
      "       matrix_health.source_checkout_clean_variant_count=\(count_or_unknown($health.source_checkout_clean_variant_count))",
      "       matrix_health.source_checkout_synced_variant_count=\(count_or_unknown($health.source_checkout_synced_variant_count))",
      "       matrix_health.runner_git_heads=\((($health.runner_git_heads // []) | map(safe_token) | join(",")) // "")",
      "       matrix_health.runner_package_versions=\((($health.runner_package_versions // []) | map(safe_token) | join(",")) // "")"
  ' "$MATRIX_FILE" >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ -z "$MATRIX_FILE" || ! -f "$MATRIX_FILE" ]]; then
  fail "pwnkit promotion matrix not found; pass pwnkit-promotion-matrix.json"
fi

require_command jq

if [[ "$EIDOLON_M3_ALLOW_UNHEALTHY_PROMOTION_MATRIX" == "1" ]]; then
  exit 0
fi

ready="$(
  jq -r '.matrix_health.ready_for_matrix_interpretation == true' \
    "$MATRIX_FILE" 2>/dev/null
)" || fail "invalid pwnkit promotion matrix JSON"

if [[ "$ready" == "true" ]]; then
  exit 0
fi

echo "error: pwnkit promotion matrix is not healthy enough to interpret" >&2
echo "       fix missing variants, pwnkit agent errors, or runner source drift before interpreting matrix results." >&2
echo "       set EIDOLON_M3_ALLOW_UNHEALTHY_PROMOTION_MATRIX=1 only for diagnostic no-signal runs." >&2
print_sanitized_matrix_health
exit 1
