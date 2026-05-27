#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: examples/m3/collect-pwnkit-promotion-matrix.sh <manifest> <matrix-dir>

Aggregates per-variant pwnkit-stability-sample.json files into one M3
bait-promotion matrix summary.

Requires jq.
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

validate_variant_id() {
  local variant_id="$1"

  if [[ ! "$variant_id" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]]; then
    fail "invalid variant_id: $variant_id"
  fi
}

validate_manifest() {
  jq -e '
    .schema_version == 1
    and .run_kind == "m3_pwnkit_promotion_matrix_manifest"
    and .boundary == "owned_loopback_lab"
    and (.variants | type == "array")
    and (.variants | length > 0)
    and all(.variants[]; (
      (.variant_id | type == "string")
      and (.bait_profile == null or (.bait_profile | type == "string"))
      and (.expected_observation | type == "string")
    ))
  ' "$MANIFEST" >/dev/null || fail "invalid M3 pwnkit promotion manifest: $MANIFEST"
}

emit_missing_variant() {
  local variant_json="$1"
  local sample_dir="$2"

  jq -cn \
    --argjson variant "$variant_json" \
    --arg sample_dir "$sample_dir" \
    '{
      variant_id: $variant.variant_id,
      bait_profile: $variant.bait_profile,
      hypothesis: ($variant.hypothesis // null),
      knobs: ($variant.knobs // []),
      expected_observation: $variant.expected_observation,
      sample_dir: $sample_dir,
      present: false,
      missing_reason: "pwnkit-stability-sample.json not found",
      observation_class: "missing",
      artifact_count: 0,
      valid_summary_count: 0,
      counts: {},
      rates: {},
      claim_level_counts: [],
      weakest_claim_level: "missing",
      strongest_claim_level: "missing",
      runner_git_heads: [],
      runner_package_versions: [],
      runner_pwnkit_fixture_ids: [],
      source_checkout: null,
      no_signal_diagnostics: null,
      differential_findings: null,
      strict_stability: null
    }'
}

emit_present_variant() {
  local variant_json="$1"
  local sample_dir="$2"
  local sample_file="$3"
  local sample_json

  sample_json="$(jq -c '.' "$sample_file")"

  jq -cn \
    --argjson variant "$variant_json" \
    --argjson sample "$sample_json" \
    --arg sample_dir "$sample_dir" \
    '
      def observation_class($sample):
        if (($sample.counts.positive_differential_findings // 0) > 0) then
          "promoted_finding"
        elif (($sample.counts.eidolon_findings // 0) > 0) then
          "eidolon_finding_without_positive_delta"
        elif (($sample.counts.controlled_reality_entered // 0) > 0) then
          "behavior_only"
        elif (($sample.counts.same_session_confirmed_bait_action // 0) > 0) then
          "same_session_action_only"
        elif (($sample.counts.bait_action_observed // 0) > 0) then
          "bait_action_only"
        elif (($sample.counts.bait_reached // 0) > 0) then
          "bait_reached_only"
        elif (($sample.counts.target_interaction_observed // 0) > 0) then
          "target_interaction_only"
        else
          "no_signal"
        end;

      {
        variant_id: $variant.variant_id,
        bait_profile: $variant.bait_profile,
        hypothesis: ($variant.hypothesis // null),
        knobs: ($variant.knobs // []),
        expected_observation: $variant.expected_observation,
        sample_dir: $sample_dir,
        present: true,
        missing_reason: null,
        observation_class: observation_class($sample),
        sample_generated_at: ($sample.generated_at // null),
        sample_run_kind: ($sample.run_kind // null),
        artifact_count: ($sample.artifact_count // 0),
        valid_summary_count: ($sample.valid_summary_count // 0),
        counts: {
          missing_summary: ($sample.counts.missing_summary // 0),
          target_interaction_observed: ($sample.counts.target_interaction_observed // 0),
          bait_reached: ($sample.counts.bait_reached // 0),
          bait_action_observed: ($sample.counts.bait_action_observed // 0),
          same_session_confirmed_bait_action: (
            $sample.counts.same_session_confirmed_bait_action // 0
          ),
          controlled_reality_entered: ($sample.counts.controlled_reality_entered // 0),
          direct_quiet: ($sample.counts.direct_quiet // 0),
          direct_findings: ($sample.counts.direct_findings // 0),
          eidolon_findings: ($sample.counts.eidolon_findings // 0),
          positive_differential_findings: (
            $sample.counts.positive_differential_findings // 0
          ),
          bait_reached_without_eidolon_findings: (
            $sample.counts.bait_reached_without_eidolon_findings // 0
          ),
          bait_action_without_eidolon_findings: (
            $sample.counts.bait_action_without_eidolon_findings // 0
          ),
          controlled_reality_without_eidolon_findings: (
            $sample.counts.controlled_reality_without_eidolon_findings // 0
          ),
          pinned_session_present: ($sample.counts.pinned_session_present // 0),
          pinned_cookie_preserved: ($sample.counts.pinned_cookie_preserved // 0)
        },
        rates: {
          target_interaction_rate: ($sample.rates.target_interaction_rate // null),
          bait_reach_rate: ($sample.rates.bait_reach_rate // null),
          bait_action_rate: ($sample.rates.bait_action_rate // null),
          same_session_confirmed_bait_action_rate: (
            $sample.rates.same_session_confirmed_bait_action_rate // null
          ),
          controlled_reality_entry_rate: (
            $sample.rates.controlled_reality_entry_rate // null
          ),
          direct_quiet_rate: ($sample.rates.direct_quiet_rate // null),
          eidolon_finding_rate: ($sample.rates.eidolon_finding_rate // null),
          positive_differential_finding_rate: (
            $sample.rates.positive_differential_finding_rate // null
          ),
          pinned_cookie_preservation_rate: (
            $sample.rates.pinned_cookie_preservation_rate // null
          )
        },
        claim_level_counts: ($sample.claim_level_counts // []),
        weakest_claim_level: ($sample.weakest_claim_level // "missing"),
        strongest_claim_level: ($sample.strongest_claim_level // "missing"),
        runner_git_heads: ($sample.runner_git_heads // []),
        runner_package_versions: ($sample.runner_package_versions // []),
        runner_pwnkit_fixture_ids: ($sample.runner_pwnkit_fixture_ids // []),
        source_checkout: ($sample.source_checkout // null),
        no_signal_diagnostics: ($sample.no_signal_diagnostics // null),
        differential_findings: ($sample.differential_findings // null),
        strict_stability: ($sample.strict_stability // null)
      }'
}

emit_variant() {
  local index="$1"
  local variant_json
  local variant_id
  local sample_dir
  local sample_file

  variant_json="$(jq -c ".variants[$index]" "$MANIFEST")"
  variant_id="$(jq -r ".variants[$index].variant_id" "$MANIFEST")"
  validate_variant_id "$variant_id"

  sample_dir="$MATRIX_DIR/$variant_id"
  sample_file="$sample_dir/pwnkit-stability-sample.json"

  if [[ ! -f "$sample_file" ]]; then
    emit_missing_variant "$variant_json" "$sample_dir"
    return
  fi

  emit_present_variant "$variant_json" "$sample_dir" "$sample_file"
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  if [[ "$#" -ne 2 ]]; then
    usage >&2
    exit 2
  fi

  require_command jq

  MANIFEST="$1"
  MATRIX_DIR="$2"

  if [[ ! -f "$MANIFEST" ]]; then
    fail "manifest not found: $MANIFEST"
  fi
  if [[ ! -d "$MATRIX_DIR" ]]; then
    fail "matrix directory not found: $MATRIX_DIR"
  fi

  validate_manifest

  local variant_count
  variant_count="$(jq '.variants | length' "$MANIFEST")"

  for ((index = 0; index < variant_count; index++)); do
    emit_variant "$index"
  done | jq -s \
    --arg manifest_path "$MANIFEST" \
    --arg matrix_dir "$MATRIX_DIR" \
    --arg boundary "$(jq -r '.boundary' "$MANIFEST")" \
    '
      def observation_class_counts:
        sort_by(.observation_class)
        | group_by(.observation_class)
        | map({observation_class: .[0].observation_class, count: length});

      def agent_error_total($variant):
        ($variant.no_signal_diagnostics.totals.direct_pwnkit_agent_errors // 0)
        + ($variant.no_signal_diagnostics.totals.eidolon_pwnkit_agent_errors // 0);

      . as $variants
      | ($variants | map(select(.present))) as $observed
      | {
          schema_version: 1,
          run_kind: "m3_pwnkit_promotion_matrix",
          generated_at: (now | todateiso8601),
          boundary: $boundary,
          manifest_path: $manifest_path,
          matrix_dir: $matrix_dir,
          variant_count: ($variants | length),
          observed_variant_count: ($observed | length),
          observation_class_counts: ($variants | observation_class_counts),
          matrix_health: {
            missing_variant_count: ($variants | map(select(.present | not)) | length),
            all_variants_observed: (
              ($variants | length) > 0
              and ($observed | length) == ($variants | length)
            ),
            total_pwnkit_agent_errors: (
              $observed | map(agent_error_total(.)) | add // 0
            ),
            all_observed_samples_agent_error_free: (
              ($observed | length) > 0
              and all($observed[]; agent_error_total(.) == 0)
            ),
            source_checkout_clean_variant_count: (
              $observed
              | map(select(.source_checkout.all_runners_clean == true))
              | length
            ),
            source_checkout_synced_variant_count: (
              $observed
              | map(select(.source_checkout.all_runners_origin_main_synced == true))
              | length
            ),
            all_observed_source_checkouts_clean: (
              ($observed | length) > 0
              and all($observed[]; .source_checkout.all_runners_clean == true)
            ),
            all_observed_source_checkouts_synced: (
              ($observed | length) > 0
              and all($observed[]; .source_checkout.all_runners_origin_main_synced == true)
            ),
            runner_git_heads: ($observed | map(.runner_git_heads[]?) | unique),
            runner_package_versions: (
              $observed | map(.runner_package_versions[]?) | unique
            ),
            runner_pwnkit_fixture_ids: (
              $observed | map(.runner_pwnkit_fixture_ids[]?) | unique
            ),
            ready_for_matrix_interpretation: (
              ($variants | length) > 0
              and ($observed | length) == ($variants | length)
              and all($observed[]; agent_error_total(.) == 0)
              and all($observed[]; .source_checkout.all_runners_clean == true)
              and all($observed[]; .source_checkout.all_runners_origin_main_synced == true)
            )
          },
          no_signal_diagnostics: {
            variant_count: (
              $variants | map(select(.observation_class == "no_signal")) | length
            ),
            likely_cause_counts: (
              $variants
              | map(
                  select(.observation_class == "no_signal")
                  | (.no_signal_diagnostics.likely_cause // "unknown")
                )
              | sort
              | group_by(.)
              | map({likely_cause: .[0], count: length})
            ),
            variants: (
              $variants
              | map(
                  select(.observation_class == "no_signal")
                  | {
                      variant_id,
                      likely_cause: (.no_signal_diagnostics.likely_cause // "unknown"),
                      next_questions: (.no_signal_diagnostics.next_questions // []),
                      totals: (.no_signal_diagnostics.totals // null),
                      proxy_path_counts: (
                        .no_signal_diagnostics.proxy_path_counts // []
                      )
                    }
                )
            )
          },
          ready_for_differential_finding_claim_variants: (
            $variants
            | map(select(.differential_findings.ready_for_differential_finding_claim == true))
            | map(.variant_id)
          ),
          ready_for_stability_claim_variants: (
            $variants
            | map(select(.strict_stability.ready_for_stability_claim == true))
            | map(.variant_id)
          ),
          variants: $variants
        }
    '
}

main "$@"
