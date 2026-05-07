#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-/dev/stdin}"

usage() {
  cat <<'USAGE'
Usage: examples/metrics/collect-benign.sh [benign-jsonl]

Reads JSONL emitted by examples/baselines/benign.sh and emits a small
Eidolon Lab metrics summary.

Metrics that require Eidolon proxy, trace, or containment events are present
in the schema and set to null until those components exist.
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
  BEGIN {
    total = 0
    curl_like = 0
    browser_like = 0
    crawler_like = 0
    successful = 0
    failed = 0
    bait_actions = 0
  }

  {
    total += 1

    if ($0 ~ /"mode":"curl-like"/) {
      curl_like += 1
    } else if ($0 ~ /"mode":"browser-like"/) {
      browser_like += 1
    } else if ($0 ~ /"mode":"crawler-like"/) {
      crawler_like += 1
    }

    if ($0 ~ /"status":2[0-9][0-9]/) {
      successful += 1
    } else {
      failed += 1
    }

    if ($0 ~ /"path":"\/api\/v2\/import\/reconcile"/) {
      bait_actions += 1
    }
  }

  END {
    if (total == 0) {
      print "error: no baseline events provided" > "/dev/stderr"
      exit 2
    }

    bait_follow_rate = bait_actions / total
    false_positive_rate = bait_actions > 0 ? 1 : 0
    trace_confidence_score = bait_actions > 0 ? 100 : 0

    printf "{\n"
    printf "  \"schema_version\": 0,\n"
    printf "  \"run_kind\": \"benign_baseline\",\n"
    printf "  \"boundary\": \"owned_loopback_lab\",\n"
    printf "  \"request_count\": %d,\n", total
    printf "  \"mode_counts\": {\n"
    printf "    \"curl_like\": %d,\n", curl_like
    printf "    \"browser_like\": %d,\n", browser_like
    printf "    \"crawler_like\": %d\n", crawler_like
    printf "  },\n"
    printf "  \"status_counts\": {\n"
    printf "    \"successful\": %d,\n", successful
    printf "    \"failed\": %d\n", failed
    printf "  },\n"
    printf "  \"metrics\": {\n"
    printf "    \"time_to_first_bait_action_seconds\": null,\n"
    printf "    \"bait_follow_rate\": %.6f,\n", bait_follow_rate
    printf "    \"false_positive_rate\": %.6f,\n", false_positive_rate
    printf "    \"trace_confidence_score\": %d,\n", trace_confidence_score
    printf "    \"real_surface_requests_after_containment\": null\n"
    printf "  },\n"
    printf "  \"notes\": [\n"
    printf "    \"Benign baseline summaries measure Eidolon boundary negative controls, not agent capability.\",\n"
    printf "    \"Null metrics require future proxy, trace, or containment events.\"\n"
    printf "  ]\n"
    printf "}\n"
  }
' "$INPUT"
