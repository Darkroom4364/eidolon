#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
EVIDENCE_DIR="$REPO_ROOT/docs/evidence/m3"

if ! command -v rg >/dev/null 2>&1; then
  echo "error: missing required tool: rg" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "error: missing required tool: jq" >&2
  exit 2
fi

if [[ ! -d "$EVIDENCE_DIR" ]]; then
  echo "error: evidence directory not found: $EVIDENCE_DIR" >&2
  exit 2
fi

if rg -n '"runner_command"|/Users/|/private/tmp|/tmp/eidolon|/tmp/pwnkit|node /tmp|node /Users' "$EVIDENCE_DIR"; then
  echo "error: committed M3 evidence contains local runner paths" >&2
  exit 1
fi

while IFS= read -r matrix_file; do
  jq -e '
    .run_kind == "m3_pwnkit_promotion_matrix"
    and (.matrix_health | type == "object")
    and (.matrix_health.ready_for_matrix_interpretation | type == "boolean")
    and (.matrix_health.all_variants_observed | type == "boolean")
    and (.matrix_health.all_observed_samples_agent_error_free | type == "boolean")
    and (.matrix_health.all_observed_source_checkouts_clean | type == "boolean")
    and (.matrix_health.all_observed_source_checkouts_synced | type == "boolean")
    and (.matrix_health.missing_variant_count | type == "number")
    and (.matrix_health.total_pwnkit_agent_errors | type == "number")
  ' "$matrix_file" >/dev/null || {
    echo "error: committed promotion matrix is missing matrix_health gate: $matrix_file" >&2
    exit 1
  }
done < <(find "$EVIDENCE_DIR" -name pwnkit-promotion-matrix.json -print)

printf 'packaged evidence redaction checks passed\n'
