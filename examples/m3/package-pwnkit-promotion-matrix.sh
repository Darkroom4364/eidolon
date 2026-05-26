#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

MATRIX_DIR="${1:-}"
BUNDLE_DIR="${2:-}"

usage() {
  cat <<'USAGE'
Usage: examples/m3/package-pwnkit-promotion-matrix.sh <matrix-dir> <bundle-dir>

Packages a completed examples/m3/run-pwnkit-promotion-matrix.sh output
directory into a commit-safe M3 evidence bundle.

Inputs:
  <matrix-dir>/bait-promotion-variants.json
  <matrix-dir>/pwnkit-promotion-matrix.json
  <matrix-dir>/<variant-id>/pwnkit-stability-sample.json
  <matrix-dir>/<variant-id>/run-*/pwnkit-summary.json
  <matrix-dir>/<variant-id>/run-*/agent-replay-trace-summary.json

Outputs:
  <bundle-dir>/README.md
  <bundle-dir>/bait-promotion-variants.json
  <bundle-dir>/pwnkit-promotion-matrix.json
  <bundle-dir>/variants/<variant-id>/...
  <bundle-dir>/SHA256SUMS

Environment:
  EIDOLON_M3_ALLOW_UNHEALTHY_PROMOTION_MATRIX
    If set to 1, allow packaging matrices whose matrix_health gate is not ready.
    Use only for diagnostic bundles, not commit-ready M3 evidence claims.

The bundle intentionally omits raw pwnkit DBs, auth JSON, stdout/stderr logs,
full proxy event logs, raw pwnkit agent error text, and private Eidolon debug
logs from every variant.
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

validate_variant_id() {
  local variant_id="$1"

  if [[ ! "$variant_id" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]]; then
    fail "invalid variant_id: $variant_id"
  fi
}

ensure_empty_bundle_dir() {
  if [[ -e "$BUNDLE_DIR" && ! -d "$BUNDLE_DIR" ]]; then
    fail "bundle path exists and is not a directory: $BUNDLE_DIR"
  fi

  if [[ -d "$BUNDLE_DIR" ]] && [[ -n "$(find "$BUNDLE_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    fail "bundle directory must be empty: $BUNDLE_DIR"
  fi

  mkdir -p "$BUNDLE_DIR"
}

validate_matrix_summary() {
  jq -e '
    .schema_version == 1
    and .run_kind == "m3_pwnkit_promotion_matrix"
    and .boundary == "owned_loopback_lab"
    and (.variants | type == "array")
  ' "$MATRIX_SUMMARY" >/dev/null || fail "invalid matrix summary: $MATRIX_SUMMARY"
}

check_matrix_health() {
  local checker="$SCRIPT_DIR/check-pwnkit-promotion-matrix-health.sh"

  if [[ ! -x "$checker" ]]; then
    fail "promotion matrix health checker is not executable: $checker"
  fi

  "$checker" "$MATRIX_SUMMARY"
}

redact_matrix_summary() {
  local input="$1"
  local output="$2"

  jq '
    def safe_profile:
      if type == "string" and startswith("/") then
        "<absolute-path-omitted>"
      else
        .
      end;
    def safe_path:
      if type == "string" then split("?")[0] | split("#")[0] else . end;
    def clean_no_signal_diagnostics:
      if . == null then
        null
      else
        (if has("proxy_path_counts") then
          . + {
            proxy_path_counts: [
              (.proxy_path_counts // [])[] |
              {
                path: ((.path // .value) | safe_path),
                count
              }
            ]
          }
        else
          .
        end)
        | if has("variants") then
            . + {
              variants: [
                (.variants // [])[] |
                . + {
                  proxy_path_counts: [
                    (.proxy_path_counts // [])[] |
                    {
                      path: ((.path // .value) | safe_path),
                      count
                    }
                  ]
                }
              ]
            }
          else
            .
          end
      end;
    {
      schema_version,
      run_kind,
      generated_at,
      boundary,
      variant_count,
      observed_variant_count,
      observation_class_counts,
      matrix_health,
      no_signal_diagnostics: (.no_signal_diagnostics | clean_no_signal_diagnostics),
      ready_for_differential_finding_claim_variants,
      ready_for_stability_claim_variants,
      variants: [
        (.variants // [])[] |
        {
          variant_id,
          bait_profile: (.bait_profile | safe_profile),
          hypothesis,
          knobs,
          expected_observation,
          present,
          missing_reason,
          observation_class,
          variant_bundle_dir: (
            if .present then "variants/" + .variant_id else null end
          ),
          sample_generated_at,
          sample_run_kind,
          artifact_count,
          valid_summary_count,
          counts,
          rates,
          claim_level_counts,
          weakest_claim_level,
          strongest_claim_level,
          runner_git_heads,
          runner_package_versions,
          runner_pwnkit_fixture_ids,
          source_checkout,
          no_signal_diagnostics: (.no_signal_diagnostics | clean_no_signal_diagnostics),
          differential_findings,
          strict_stability
        }
      ],
      redaction: {
        source_matrix_dir_omitted: true,
        source_variant_sample_dirs_omitted: true,
        raw_run_summaries_omitted: true,
        raw_pwnkit_artifacts_omitted: true,
        raw_agent_error_text_omitted: true,
        raw_proxy_events_omitted: true,
        private_debug_logs_omitted: true
      }
    }
  ' "$input" > "$output"
}

redact_manifest() {
  local input="$1"
  local output="$2"

  jq '
    def safe_profile:
      if type == "string" and startswith("/") then
        "<absolute-path-omitted>"
      else
        .
      end;
    {
      schema_version,
      run_kind,
      boundary,
      variants: [
        (.variants // [])[] |
        {
          variant_id,
          bait_profile: (.bait_profile | safe_profile),
          hypothesis,
          knobs,
          expected_observation
        }
      ],
      redaction: {
        absolute_bait_profile_paths_omitted: true
      }
    }
  ' "$input" > "$output"
}

matrix_value() {
  local filter="$1"
  jq -r "$filter // \"unknown\"" "$BUNDLE_DIR/pwnkit-promotion-matrix.json"
}

write_readme() {
  local collected_on
  local variant_count
  local observed_count
  local class_counts
  local differential_variants
  local stability_variants

  collected_on="$(date -u +%F)"
  variant_count="$(matrix_value '.variant_count')"
  observed_count="$(matrix_value '.observed_variant_count')"
  class_counts="$(jq -r '(.observation_class_counts // []) | map("`" + .observation_class + "`: `" + (.count|tostring) + "`") | join(", ")' "$BUNDLE_DIR/pwnkit-promotion-matrix.json")"
  differential_variants="$(jq -r '(.ready_for_differential_finding_claim_variants // []) | map("`" + . + "`") | join(", ")' "$BUNDLE_DIR/pwnkit-promotion-matrix.json")"
  stability_variants="$(jq -r '(.ready_for_stability_claim_variants // []) | map("`" + . + "`") | join(", ")' "$BUNDLE_DIR/pwnkit-promotion-matrix.json")"

  {
    printf '# M3 pwnkit Promotion Matrix Evidence\n\n'
    printf 'Lab-only evidence bundle packaged on %s.\n\n' "$collected_on"
    printf '## Scope\n\n'
    printf -- '- Boundary: owned loopback lab.\n'
    printf -- '- Source matrix directory: omitted from the committed bundle.\n'
    printf -- '- Matrix variants: `%s` total, `%s` observed.\n\n' "$variant_count" "$observed_count"
    printf '## Contents\n\n'
    printf -- '- `bait-promotion-variants.json`: matrix manifest used for the run.\n'
    printf -- '- `pwnkit-promotion-matrix.json`: redacted matrix-level aggregate.\n'
    printf -- '- `variants/<variant-id>/`: redacted sample evidence bundle for each observed variant.\n'
    printf -- '- `SHA256SUMS`: checksums for committed evidence files.\n\n'
    printf '## Redaction\n\n'
    printf 'This bundle intentionally omits raw artifacts from every variant:\n\n'
    printf -- '- pwnkit SQLite databases\n'
    printf -- '- pwnkit auth JSON files\n'
    printf -- '- raw stdout and stderr logs\n'
    printf -- '- full proxy JSONL event logs\n'
    printf -- '- private Eidolon debug logs\n'
    printf -- '- raw pwnkit agent error text\n'
    printf -- '- raw requested-path arrays and tool evidence labels from pwnkit summaries\n\n'
    printf 'The matrix summary omits source sample directory paths and points observed variants at their redacted bundle directories.\n\n'
    printf '## Result\n\n'
    printf -- '- observation classes: %s\n' "${class_counts:-unknown}"
    printf -- '- differential-finding-ready variants: %s\n' "${differential_variants:-none}"
    printf -- '- stability-claim-ready variants: %s\n\n' "${stability_variants:-none}"
    printf 'This remains Lab-only evidence. It does not claim production readiness, autonomous-attacker identity, or stability beyond the recorded pwnkit head(s).\n'
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

package_variant() {
  local variant_id="$1"
  local source_variant_dir="$MATRIX_DIR/$variant_id"
  local output_variant_dir="$BUNDLE_DIR/variants/$variant_id"

  validate_variant_id "$variant_id"
  if [[ ! -d "$source_variant_dir" ]]; then
    fail "missing observed variant directory: $source_variant_dir"
  fi

  "$SCRIPT_DIR/package-pwnkit-sample.sh" "$source_variant_dir" "$output_variant_dir" >/dev/null
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  if [[ -z "$MATRIX_DIR" || -z "$BUNDLE_DIR" ]]; then
    usage >&2
    exit 2
  fi

  require_command jq
  if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    fail "missing required tool: sha256sum or shasum"
  fi

  if [[ ! -d "$MATRIX_DIR" ]]; then
    fail "matrix directory does not exist: $MATRIX_DIR"
  fi

  MATRIX_MANIFEST="$MATRIX_DIR/bait-promotion-variants.json"
  MATRIX_SUMMARY="$MATRIX_DIR/pwnkit-promotion-matrix.json"
  if [[ ! -f "$MATRIX_MANIFEST" ]]; then
    fail "missing matrix manifest: $MATRIX_MANIFEST"
  fi
  if [[ ! -f "$MATRIX_SUMMARY" ]]; then
    fail "missing matrix summary: $MATRIX_SUMMARY"
  fi

  validate_matrix_summary
  check_matrix_health
  ensure_empty_bundle_dir
  redact_manifest "$MATRIX_MANIFEST" "$BUNDLE_DIR/bait-promotion-variants.json"
  redact_matrix_summary "$MATRIX_SUMMARY" "$BUNDLE_DIR/pwnkit-promotion-matrix.json"

  local variant_count
  variant_count="$(jq '.variants | length' "$MATRIX_SUMMARY")"
  for ((index = 0; index < variant_count; index++)); do
    local variant_id
    local present
    variant_id="$(jq -r ".variants[$index].variant_id" "$MATRIX_SUMMARY")"
    present="$(jq -r ".variants[$index].present" "$MATRIX_SUMMARY")"
    validate_variant_id "$variant_id"
    if [[ "$present" == "true" ]]; then
      package_variant "$variant_id"
    fi
  done

  write_readme
  write_checksums

  echo "packaged pwnkit promotion matrix bundle: $BUNDLE_DIR"
}

main "$@"
