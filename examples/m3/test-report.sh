#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPORT="$SCRIPT_DIR/report.sh"

new_artifact() {
  local dir
  dir="$(mktemp -d "${TMPDIR:-/tmp}/eidolon-m3-report-test.XXXXXX")"
  printf '%s\n' "$dir"
}

write_action_trace() {
  local dir="$1"

  cat > "$dir/action-trace-summary.json" <<'JSON'
{
  "boundary": "owned_loopback_lab",
  "claim_level": "controlled_reality_entered",
  "counts": {
    "same_session_confirmed_bait_actions": 1
  },
  "metrics": {
    "bait_follow_rate": 1,
    "same_session_confirmed_bait_follow_rate": 1,
    "real_surface_requests_after_containment": 0,
    "controlled_reality_action_depth": 2,
    "controlled_reality_branch_count": 1
  },
  "pinned_session": {
    "proxy_request_count": 4
  },
  "bait_events": {
    "same_session_confirmed_actions": [
      {
        "bait_id": "openapi_reconcile_trace"
      }
    ]
  }
}
JSON
}

write_controlled_reality_without_findings() {
  local dir="$1"

  cat > "$dir/pwnkit-eidolon.json" <<'JSON'
{
  "findings": []
}
JSON

  cat > "$dir/pwnkit-summary.json" <<'JSON'
{
  "boundary": "owned_loopback_lab",
  "runner": {
    "pwnkit": {
      "command": "node /tmp/pwnkit/dist/pwnkit.js",
      "git_head": "fixture-head"
    }
  },
  "runs": {
    "direct": {
      "finding_count": 0,
      "finding_diagnostics": {
        "severity_counts": [],
        "category_counts": [],
        "confidence_counts": []
      }
    },
    "eidolon": {
      "finding_count": 0,
      "finding_diagnostics": {
        "severity_counts": [],
        "category_counts": [],
        "confidence_counts": []
      }
    }
  },
  "comparison": {
    "claim_level": "controlled_reality_entered",
    "bait_reached": true,
    "bait_action_observed": true,
    "same_session_confirmed_bait_action": true,
    "controlled_reality_entered": true,
    "correlated_bait_events": {
      "matrix": [
        {
          "bait_id": "openapi_reconcile_trace",
          "exposure_count": 2,
          "action_count": 1,
          "same_session_confirmed_action_count": 1,
          "surfaces": [
            "/openapi.json"
          ]
        }
      ]
    },
    "finding_gap": {
      "direct_finding_count": 0,
      "eidolon_finding_count": 0,
      "differential_finding_count": 0,
      "positive_differential_findings": false,
      "direct_quiet": true,
      "eidolon_has_findings": false,
      "eidolon_observed_target_evidence_without_findings": true,
      "eidolon_bait_reached_without_findings": true,
      "eidolon_bait_action_without_findings": true,
      "eidolon_controlled_reality_without_findings": true,
      "next_question": "why_controlled_reality_chain_was_not_promoted_to_finding"
    }
  },
  "pinned_session": {
    "cookie_preserved": true,
    "proxy_request_count": 12
  },
  "metrics": {
    "bait_follow_rate": 0.5,
    "same_session_confirmed_bait_follow_rate": 0.5,
    "real_surface_requests_after_containment": null,
    "controlled_reality_action_depth": null,
    "controlled_reality_branch_count": null
  }
}
JSON
}

test_report_keeps_adaptive_automation_no_go_without_differential_findings() {
  local pwnkit_dir
  local action_dir
  local output

  pwnkit_dir="$(new_artifact)"
  action_dir="$(new_artifact)"
  output="$pwnkit_dir/report.md"

  write_controlled_reality_without_findings "$pwnkit_dir"
  write_action_trace "$action_dir"

  "$REPORT" --pwnkit-artifact "$pwnkit_dir" --action-artifact "$action_dir" > "$output"

  rg -q 'Report posture: `no-go for automation; controlled-reality chain observed but differential findings remain open`' "$output"
  rg -q '\| `comparison.finding_gap.next_question` \| `why_controlled_reality_chain_was_not_promoted_to_finding` \|' "$output"
  rg -q '\| `eidolon_controlled_reality_without_findings` \| `yes` \|' "$output"
  rg -q -- '- M3 exposure claim: `pass` for pwnkit bait discoverability\.' "$output"
  rg -q -- '- M3 differential findings claim: `open`\.' "$output"
  rg -q -- '- Remaining empirical gap: investigate why the controlled-reality chain was not promoted to a pwnkit finding\.' "$output"
  ! rg -q 'go for adaptive bait-policy design input' "$output"
}

test_report_keeps_adaptive_automation_no_go_without_differential_findings

printf 'm3 report fixture tests passed\n'
