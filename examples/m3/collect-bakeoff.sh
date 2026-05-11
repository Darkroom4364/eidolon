#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-/dev/stdin}"

usage() {
  cat <<'USAGE'
Usage: examples/m3/collect-bakeoff.sh [m3-bakeoff-jsonl]

Reads JSONL emitted by examples/m3/bakeoff.sh and emits a small M3 bakeoff
summary. The summary compares Eidolon boundary behavior and static baselines;
it is not an agent ranking or offensive solve-rate benchmark.
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

  function json_key(value, key) {
    key = value
    gsub(/-/, "_", key)
    return key
  }

  function remember_mode(mode) {
    if (!(mode in seen_mode)) {
      seen_mode[mode] = 1
      mode_order[++mode_count] = mode
    }
  }

  function remember_class(mode, bait_class, combined) {
    combined = mode SUBSEP bait_class
    if (!(combined in seen_class)) {
      seen_class[combined] = 1
      class_count[mode] += 1
      class_order[mode, class_count[mode]] = bait_class
    }
  }

  function confidence_score(mode, actions, exposures) {
    if (actions == 0 || exposures == 0) {
      return 0
    }
    if (mode == "eidolon-mvp") {
      return 85
    }
    if (mode == "static-token" || mode == "static-honeypot") {
      return 50
    }
    return 0
  }

  function optional_first_action(mode, key, prefix) {
    if (prefix == "mode") {
      if (mode in first_exposure_seconds && mode in first_action_seconds) {
        printf "        \"time_to_first_bait_action_seconds\": %.6f,\n", first_action_seconds[mode] - first_exposure_seconds[mode]
      } else {
        printf "        \"time_to_first_bait_action_seconds\": null,\n"
      }
    } else {
      key = prefix
      if (key in first_class_exposure_seconds && key in first_class_action_seconds) {
        printf "            \"time_to_first_bait_action_seconds\": %.6f,\n", first_class_action_seconds[key] - first_class_exposure_seconds[key]
      } else {
        printf "            \"time_to_first_bait_action_seconds\": null,\n"
      }
    }
  }

  BEGIN {
    total = 0
    mode_count = 0
    runner_kind = ""
  }

  {
    total += 1
    mode = str_field($0, "defense_mode")
    bait_class = str_field($0, "bait_class")
    step = str_field($0, "step")

    if (mode == "" || bait_class == "") {
      invalid += 1
      next
    }

    current_runner = str_field($0, "runner_kind")
    if (runner_kind == "" && current_runner != "") {
      runner_kind = current_runner
    }

    remember_mode(mode)
    remember_class(mode, bait_class)

    key = mode SUBSEP bait_class
    status = num_field($0, "status") + 0
    elapsed = num_field($0, "elapsed_seconds") + 0

    event_count[mode] += 1
    class_event_count[key] += 1

    if (step == "exposure") {
      scenario_count[mode] += 1
      class_scenario_count[key] += 1
    }

    request_sent = bool_field($0, "request_sent")
    if (request_sent) {
      request_count[mode] += 1
      class_request_count[key] += 1
    }

    if (request_sent && status >= 200 && status < 300) {
      successful[mode] += 1
      class_successful[key] += 1
    } else if (bool_field($0, "blocked")) {
      blocked[mode] += 1
      class_blocked[key] += 1
    } else if (request_sent) {
      failed[mode] += 1
      class_failed[key] += 1
    } else {
      skipped[mode] += 1
      class_skipped[key] += 1
    }

    if (bool_field($0, "bait_exposed")) {
      bait_exposures[mode] += 1
      class_bait_exposures[key] += 1
      if (!(mode in first_exposure_seconds)) {
        first_exposure_seconds[mode] = elapsed
      }
      if (!(key in first_class_exposure_seconds)) {
        first_class_exposure_seconds[key] = elapsed
      }
    }

    if (bool_field($0, "bait_action")) {
      bait_actions[mode] += 1
      class_bait_actions[key] += 1
      if (!(mode in first_action_seconds)) {
        first_action_seconds[mode] = elapsed
      }
      if (!(key in first_class_action_seconds)) {
        first_class_action_seconds[key] = elapsed
      }
    }

    if (bool_field($0, "false_positive")) {
      false_positives[mode] += 1
      class_false_positives[key] += 1
    }

    if (bool_field($0, "after_decision") && bool_field($0, "real_surface") && bool_field($0, "protected_upstream_reached")) {
      protected_after_decision[mode] += 1
      class_protected_after_decision[key] += 1
    }
  }

  END {
    if (total == 0 || mode_count == 0) {
      print "error: no M3 bakeoff events provided" > "/dev/stderr"
      exit 2
    }

    if (invalid > 0) {
      print "error: M3 bakeoff events missing defense_mode or bait_class" > "/dev/stderr"
      exit 2
    }

    printf "{\n"
    printf "  \"schema_version\": 0,\n"
    printf "  \"run_kind\": \"m3_bakeoff_comparison\",\n"
    printf "  \"boundary\": \"owned_loopback_lab\",\n"
    runner_output = runner_kind
    if (runner_output == "") {
      runner_output = "unknown"
    }
    printf "  \"runner_kind\": \"%s\",\n", runner_output
    printf "  \"defense_modes\": {\n"

    for (i = 1; i <= mode_count; i += 1) {
      mode = mode_order[i]
      mode_key = json_key(mode)
      exposure_count = bait_exposures[mode] + 0
      action_count = bait_actions[mode] + 0
      scenarios = scenario_count[mode] + 0
      bait_follow_rate = exposure_count > 0 ? action_count / exposure_count : 0
      false_positive_rate = scenarios > 0 ? (false_positives[mode] + 0) / scenarios : 0
      score = confidence_score(mode, action_count, exposure_count)

      printf "    \"%s\": {\n", mode_key
      printf "      \"source_mode\": \"%s\",\n", mode
      printf "      \"event_count\": %d,\n", event_count[mode] + 0
      printf "      \"request_count\": %d,\n", request_count[mode] + 0
      printf "      \"status_counts\": {\n"
      printf "        \"successful\": %d,\n", successful[mode] + 0
      printf "        \"failed\": %d,\n", failed[mode] + 0
      printf "        \"blocked\": %d,\n", blocked[mode] + 0
      printf "        \"skipped\": %d\n", skipped[mode] + 0
      printf "      },\n"
      printf "      \"counts\": {\n"
      printf "        \"bait_exposures\": %d,\n", exposure_count
      printf "        \"bait_actions\": %d,\n", action_count
      printf "        \"protected_upstream_after_decision\": %d\n", protected_after_decision[mode] + 0
      printf "      },\n"
      printf "      \"metrics\": {\n"
      optional_first_action(mode, "", "mode")
      printf "        \"bait_follow_rate\": %.6f,\n", bait_follow_rate
      printf "        \"false_positive_rate\": %.6f,\n", false_positive_rate
      printf "        \"trace_confidence_score\": %d,\n", score
      if (action_count > 0 || blocked[mode] > 0) {
        printf "        \"real_surface_requests_after_containment\": %d,\n", protected_after_decision[mode] + 0
      } else {
        printf "        \"real_surface_requests_after_containment\": null,\n"
      }
      if (mode == "eidolon-mvp" && action_count > 0) {
        printf "        \"controlled_reality_dwell_seconds\": 0.000000,\n"
      } else {
        printf "        \"controlled_reality_dwell_seconds\": null,\n"
      }
      controlled_depth = 0
      controlled_branches = 0
      if (mode == "eidolon-mvp") {
        controlled_depth = action_count
        if (action_count > 0) {
          controlled_branches = 1
        }
      }
      printf "        \"controlled_reality_action_depth\": %d,\n", controlled_depth
      printf "        \"controlled_reality_branch_count\": %d\n", controlled_branches
      printf "      },\n"
      printf "      \"bait_classes\": {\n"

      for (j = 1; j <= class_count[mode]; j += 1) {
        bait_class = class_order[mode, j]
        key = mode SUBSEP bait_class
        class_exposures = class_bait_exposures[key] + 0
        class_actions = class_bait_actions[key] + 0
        class_scenarios = class_scenario_count[key] + 0
        class_follow_rate = class_exposures > 0 ? class_actions / class_exposures : 0
        class_false_positive_rate = class_scenarios > 0 ? (class_false_positives[key] + 0) / class_scenarios : 0

        printf "        \"%s\": {\n", bait_class
        printf "          \"event_count\": %d,\n", class_event_count[key] + 0
        printf "          \"counts\": {\n"
        printf "            \"bait_exposures\": %d,\n", class_exposures
        printf "            \"bait_actions\": %d,\n", class_actions
        printf "            \"protected_upstream_after_decision\": %d\n", class_protected_after_decision[key] + 0
        printf "          },\n"
        printf "          \"metrics\": {\n"
        optional_first_action(mode, "", key)
        printf "            \"bait_follow_rate\": %.6f,\n", class_follow_rate
        printf "            \"false_positive_rate\": %.6f,\n", class_false_positive_rate
        printf "            \"trace_confidence_score\": %d,\n", confidence_score(mode, class_actions, class_exposures)
        if (class_actions > 0 || class_blocked[key] > 0) {
          printf "            \"real_surface_requests_after_containment\": %d\n", class_protected_after_decision[key] + 0
        } else {
          printf "            \"real_surface_requests_after_containment\": null\n"
        }
        printf "          }\n"

        if (j < class_count[mode]) {
          printf "        },\n"
        } else {
          printf "        }\n"
        }
      }

      printf "      }\n"
      if (i < mode_count) {
        printf "    },\n"
      } else {
        printf "    }\n"
      }
    }

    printf "  },\n"
    printf "  \"notes\": [\n"
    printf "    \"M3 scripted bakeoff summaries compare boundary behavior across the same owned Lab target and five bait classes.\",\n"
    printf "    \"This artifact is runner plumbing; final M3 uniqueness claims require authorized agentic/scanner runs and proxy trace artifacts.\"\n"
    printf "  ]\n"
    printf "}\n"
  }
' "$INPUT"
