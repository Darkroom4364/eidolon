#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-/dev/stdin}"

usage() {
  cat <<'USAGE'
Usage: examples/metrics/collect-baselines.sh [baseline-jsonl]

Reads JSONL emitted by examples/baselines/defense-modes.sh and emits a small
per-mode Eidolon Lab metrics summary.

The summary compares defensive boundary behavior. It is not an agent ranking
or offensive solve-rate benchmark.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "$INPUT" != "/dev/stdin" && ! -f "$INPUT" ]]; then
  echo "error: input file not found: $INPUT" >&2
  exit 2
fi

awk '
  function str_field(line, name, marker, rest) {
    marker = "\"" name "\":\""
    if (index(line, marker) == 0) {
      return ""
    }
    rest = substr(line, index(line, marker) + length(marker))
    sub(/".*/, "", rest)
    return rest
  }

  function num_field(line, name, marker, rest) {
    marker = "\"" name "\":"
    if (index(line, marker) == 0) {
      return ""
    }
    rest = substr(line, index(line, marker) + length(marker))
    sub(/[,}].*/, "", rest)
    return rest
  }

  function bool_field(line, name, marker, rest) {
    marker = "\"" name "\":"
    if (index(line, marker) == 0) {
      return 0
    }
    rest = substr(line, index(line, marker) + length(marker))
    return substr(rest, 1, 4) == "true"
  }

  function remember_mode(mode) {
    if (!(mode in seen)) {
      seen[mode] = 1
      order[++mode_count] = mode
    }
  }

  function json_key(mode, key) {
    key = mode
    gsub(/-/, "_", key)
    return key
  }

  BEGIN {
    total = 0
    mode_count = 0
  }

  {
    total += 1
    mode = str_field($0, "baseline_mode")

    if (mode == "") {
      invalid += 1
      next
    }

    remember_mode(mode)

    status = num_field($0, "status") + 0
    elapsed = num_field($0, "elapsed_seconds") + 0

    event_count[mode] += 1

    if (bool_field($0, "target_requested")) {
      target_request_count[mode] += 1
    }

    if (status >= 200 && status < 300) {
      successful[mode] += 1
    } else if (bool_field($0, "blocked")) {
      blocked[mode] += 1
    } else {
      failed[mode] += 1
    }

    if (bool_field($0, "bait_exposed")) {
      bait_exposures[mode] += 1
      if (!(mode in first_bait_exposure_seconds)) {
        first_bait_exposure_seconds[mode] = elapsed
      }
    }

    if (bool_field($0, "bait_action")) {
      bait_actions[mode] += 1
      if (!(mode in first_bait_action_seconds)) {
        first_bait_action_seconds[mode] = elapsed
      }
    }

    if (bool_field($0, "real_surface")) {
      real_surface_requests[mode] += 1
    }

    if (bool_field($0, "after_decision") && bool_field($0, "real_surface") && bool_field($0, "target_requested")) {
      real_surface_after_decision[mode] += 1
    }
  }

  END {
    if (total == 0 || mode_count == 0) {
      print "error: no baseline events provided" > "/dev/stderr"
      exit 2
    }

    if (invalid > 0) {
      print "error: baseline events missing baseline_mode" > "/dev/stderr"
      exit 2
    }

    printf "{\n"
    printf "  \"schema_version\": 0,\n"
    printf "  \"run_kind\": \"defense_baseline_comparison\",\n"
    printf "  \"boundary\": \"owned_loopback_lab\",\n"
    printf "  \"baseline_modes\": {\n"

    for (i = 1; i <= mode_count; i += 1) {
      mode = order[i]
      key = json_key(mode)

      exposure_count = bait_exposures[mode] + 0
      action_count = bait_actions[mode] + 0
      bait_follow_rate = exposure_count > 0 ? action_count / exposure_count : 0
      false_positive_rate = 0
      trace_confidence_score = exposure_count > 0 && action_count > 0 ? 50 : 0

      printf "    \"%s\": {\n", key
      printf "      \"source_mode\": \"%s\",\n", mode
      printf "      \"event_count\": %d,\n", event_count[mode] + 0
      printf "      \"target_request_count\": %d,\n", target_request_count[mode] + 0
      printf "      \"status_counts\": {\n"
      printf "        \"successful\": %d,\n", successful[mode] + 0
      printf "        \"failed\": %d,\n", failed[mode] + 0
      printf "        \"blocked\": %d\n", blocked[mode] + 0
      printf "      },\n"
      printf "      \"counts\": {\n"
      printf "        \"bait_exposures\": %d,\n", exposure_count
      printf "        \"bait_actions\": %d,\n", action_count
      printf "        \"real_surface_requests\": %d\n", real_surface_requests[mode] + 0
      printf "      },\n"
      printf "      \"metrics\": {\n"

      if (mode in first_bait_exposure_seconds && mode in first_bait_action_seconds) {
        printf "        \"time_to_first_bait_action_seconds\": %.6f,\n", first_bait_action_seconds[mode] - first_bait_exposure_seconds[mode]
      } else {
        printf "        \"time_to_first_bait_action_seconds\": null,\n"
      }

      printf "        \"bait_follow_rate\": %.6f,\n", bait_follow_rate
      printf "        \"false_positive_rate\": %.6f,\n", false_positive_rate
      printf "        \"trace_confidence_score\": %d,\n", trace_confidence_score

      if (blocked[mode] > 0) {
        printf "        \"real_surface_requests_after_containment\": %d,\n", real_surface_after_decision[mode] + 0
      } else {
        printf "        \"real_surface_requests_after_containment\": null,\n"
      }

      printf "        \"controlled_reality_dwell_seconds\": null,\n"
      printf "        \"controlled_reality_action_depth\": 0,\n"
      printf "        \"controlled_reality_branch_count\": 0\n"

      printf "      }\n"

      if (i < mode_count) {
        printf "    },\n"
      } else {
        printf "    }\n"
      }
    }

    printf "  },\n"
    printf "  \"notes\": [\n"
    printf "    \"Baseline modes compare defensive boundary behavior against static deception and blocking controls.\",\n"
    printf "    \"The v0 static baseline trace score is intentionally capped because static clues do not prove per-session causal control.\"\n"
    printf "  ]\n"
    printf "}\n"
  }
' "$INPUT"
