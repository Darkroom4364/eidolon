# Public bundle constructors. Every object is rebuilt from named fields so
# unknown input keys cannot cross the disclosure boundary.

def pe_type_error($name; $expected):
  error($name + " must be " + $expected);

def pe_optional_type($name; $expected):
  if . == null or type == $expected then
    .
  else
    pe_type_error($name; $expected)
  end;

def pe_expect($name; $expected):
  if . == $expected then
    .
  else
    error($name + " must equal " + ($expected | tojson))
  end;

def pe_text($name):
  pe_optional_type($name; "string")
  | if . == null then
      null
    elif (length > 1024) or (test("^[ -~]*$") | not) then
      error($name + " must be bounded printable ASCII")
    else
      .
    end;

def pe_identifier($name):
  pe_text($name)
  | if . == null then
      null
    elif test("^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$") then
      .
    else
      error($name + " must be a bounded identifier")
    end;

def pe_bool($name):
  pe_optional_type($name; "boolean");

def pe_required_bool($name):
  if type == "boolean" then
    .
  else
    pe_type_error($name; "boolean")
  end;

def pe_number($name):
  pe_optional_type($name; "number");

def pe_integer($name):
  pe_number($name)
  | if . == null or (floor == .) then
      .
    else
      error($name + " must be an integer")
    end;

def pe_array($name):
  if . == null then
    []
  elif type == "array" then
    .
  else
    pe_type_error($name; "array")
  end;

def pe_object($name):
  if type == "object" then
    .
  else
    pe_type_error($name; "object")
  end;

def pe_identifier_list($name):
  pe_array($name)
  | [
      to_entries[] as $entry
      | $entry.value
      | pe_identifier($name + "[" + ($entry.key | tostring) + "]")
    ];

def pe_package_version($name):
  if . == null then
    null
  elif type == "string"
    and test(
      "^v?[0-9]+([.][0-9]+){1,3}([+-][0-9A-Za-z][0-9A-Za-z.-]{0,63})?$"
    )
  then
    .
  else
    error($name + " must be a bounded package version")
  end;

def pe_package_version_list($name):
  pe_array($name)
  | [
      to_entries[] as $entry
      | $entry.value
      | pe_package_version($name + "[" + ($entry.key | tostring) + "]")
    ];

def pe_fixture_id($name):
  if . == null then
    null
  elif type == "string"
    and (
      test(
        "^(eidolon-m3|pwnkit)-[A-Za-z0-9.-]{1,96}-[0-9]{4}-[0-9]{2}-[0-9]{2}$"
      )
      or test("^pwnkit-v[0-9]+([.][0-9]+){2}-private$")
      or . == "pwnkit-local-patched"
    )
  then
    .
  else
    error($name + " must be a dated Eidolon or pwnkit fixture identifier")
  end;

def pe_fixture_id_list($name):
  pe_array($name)
  | [
      to_entries[] as $entry
      | $entry.value
      | pe_fixture_id($name + "[" + ($entry.key | tostring) + "]")
    ];

def pe_timestamp($name):
  if type != "string" then
    pe_type_error($name; "RFC3339 UTC timestamp")
  elif test(
    "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,9})?Z$"
  ) then
    .
  else
    error($name + " must be an RFC3339 UTC timestamp")
  end;

def pe_optional_timestamp($name):
  if . == null then
    null
  else
    pe_timestamp($name)
  end;

def pe_missing_reason($name):
  if . == null
    or . == "pwnkit-summary.json not found"
    or . == "pwnkit-stability-sample.json not found"
  then
    .
  else
    error($name + " must be a known missing-artifact reason")
  end;

def pe_safe_path($name):
  if type != "string" then
    pe_type_error($name; "string path")
  elif (length > 2048)
    or (startswith("/") | not)
    or startswith("//")
    or (test("[[:cntrl:]]"))
  then
    error($name + " must be a bounded absolute request path")
  else
    split("?")[0] | split("#")[0]
  end;

def pe_path_list($name):
  pe_array($name)
  | [
      to_entries[] as $entry
      | $entry.value
      | pe_safe_path($name + "[" + ($entry.key | tostring) + "]")
    ];

def pe_claim_count:
  pe_object("claim_level_counts[]")
  | {
      claim_level: (.claim_level | pe_identifier("claim_level_counts[].claim_level")),
      count: (.count | pe_integer("claim_level_counts[].count"))
    };

def pe_value_count($field; $name):
  pe_object($name + "[]")
  | {
      ($field): (.[$field] | pe_identifier($name + "[]." + $field)),
      count: (.count | pe_integer($name + "[].count"))
    };

def pe_error_class($name):
  if . == "codex_token_refresh_failed"
    or . == "codex_authentication_failed"
    or . == "codex_backend_timeout"
    or . == "codex_backend_api_error"
    or . == "agent_api_timeout"
    or . == "agent_api_error"
    or . == "pwnkit_agent_error"
  then
    .
  else
    error($name + " must be a known sanitized error class")
  end;

def pe_error_class_count($name):
  pe_object($name + "[]")
  | {
      error_class: (.error_class | pe_error_class($name + "[].error_class")),
      count: (.count | pe_integer($name + "[].count"))
    };

def pe_tool_fingerprint:
  pe_object("runner_tool_fingerprint[]")
  | {
      name: (.name | pe_identifier("runner_tool_fingerprint[].name")),
      present: (.present | pe_bool("runner_tool_fingerprint[].present"))
    };

def pe_tool_fingerprint_summary:
  pe_object("tool_fingerprint_summary[]")
  | {
      name: (.name | pe_identifier("tool_fingerprint_summary[].name")),
      present_count: (
        .present_count | pe_integer("tool_fingerprint_summary[].present_count")
      ),
      missing_count: (
        .missing_count | pe_integer("tool_fingerprint_summary[].missing_count")
      )
    };

def pe_runner_os:
  if . == null then
    null
  else
    pe_object("runner_os")
    | {
        kernel_name: (.kernel_name | pe_identifier("runner_os.kernel_name")),
        machine_arch: (.machine_arch | pe_identifier("runner_os.machine_arch"))
      }
  end;

def pe_fixture:
  if . == null then
    null
  else
    pe_object("runner_pwnkit_fixture")
    | {
        id: (.id | pe_fixture_id("runner_pwnkit_fixture.id")),
        pinned: (.pinned | pe_bool("runner_pwnkit_fixture.pinned"))
      }
  end;

def pe_sample_counts:
  pe_object("counts")
  | {
      missing_summary: (.missing_summary | pe_integer("counts.missing_summary")),
      target_interaction_observed: (
        .target_interaction_observed
        | pe_integer("counts.target_interaction_observed")
      ),
      bait_reached: (.bait_reached | pe_integer("counts.bait_reached")),
      bait_action_observed: (
        .bait_action_observed | pe_integer("counts.bait_action_observed")
      ),
      same_session_confirmed_bait_action: (
        .same_session_confirmed_bait_action
        | pe_integer("counts.same_session_confirmed_bait_action")
      ),
      controlled_reality_entered: (
        .controlled_reality_entered
        | pe_integer("counts.controlled_reality_entered")
      ),
      direct_quiet: (.direct_quiet | pe_integer("counts.direct_quiet")),
      direct_findings: (.direct_findings | pe_integer("counts.direct_findings")),
      eidolon_findings: (
        .eidolon_findings | pe_integer("counts.eidolon_findings")
      ),
      positive_differential_findings: (
        .positive_differential_findings
        | pe_integer("counts.positive_differential_findings")
      ),
      bait_reached_without_eidolon_findings: (
        .bait_reached_without_eidolon_findings
        | pe_integer("counts.bait_reached_without_eidolon_findings")
      ),
      bait_action_without_eidolon_findings: (
        .bait_action_without_eidolon_findings
        | pe_integer("counts.bait_action_without_eidolon_findings")
      ),
      controlled_reality_without_eidolon_findings: (
        .controlled_reality_without_eidolon_findings
        | pe_integer("counts.controlled_reality_without_eidolon_findings")
      ),
      pinned_session_present: (
        .pinned_session_present | pe_integer("counts.pinned_session_present")
      ),
      pinned_cookie_preserved: (
        .pinned_cookie_preserved | pe_integer("counts.pinned_cookie_preserved")
      )
    };

def pe_sample_rates:
  pe_object("rates")
  | {
      target_interaction_rate: (
        .target_interaction_rate | pe_number("rates.target_interaction_rate")
      ),
      bait_reach_rate: (.bait_reach_rate | pe_number("rates.bait_reach_rate")),
      bait_action_rate: (
        .bait_action_rate | pe_number("rates.bait_action_rate")
      ),
      same_session_confirmed_bait_action_rate: (
        .same_session_confirmed_bait_action_rate
        | pe_number("rates.same_session_confirmed_bait_action_rate")
      ),
      controlled_reality_entry_rate: (
        .controlled_reality_entry_rate
        | pe_number("rates.controlled_reality_entry_rate")
      ),
      direct_quiet_rate: (
        .direct_quiet_rate | pe_number("rates.direct_quiet_rate")
      ),
      eidolon_finding_rate: (
        .eidolon_finding_rate | pe_number("rates.eidolon_finding_rate")
      ),
      positive_differential_finding_rate: (
        .positive_differential_finding_rate
        | pe_number("rates.positive_differential_finding_rate")
      ),
      pinned_cookie_preservation_rate: (
        .pinned_cookie_preservation_rate
        | pe_number("rates.pinned_cookie_preservation_rate")
      )
    };

def pe_source_checkout:
  if . == null then
    null
  else
    pe_object("source_checkout")
    | {
        clean_runner_count: (
          .clean_runner_count | pe_integer("source_checkout.clean_runner_count")
        ),
        dirty_runner_count: (
          .dirty_runner_count | pe_integer("source_checkout.dirty_runner_count")
        ),
        unknown_dirty_runner_count: (
          .unknown_dirty_runner_count
          | pe_integer("source_checkout.unknown_dirty_runner_count")
        ),
        origin_main_synced_count: (
          .origin_main_synced_count
          | pe_integer("source_checkout.origin_main_synced_count")
        ),
        origin_main_drifted_count: (
          .origin_main_drifted_count
          | pe_integer("source_checkout.origin_main_drifted_count")
        ),
        unknown_origin_main_sync_count: (
          .unknown_origin_main_sync_count
          | pe_integer("source_checkout.unknown_origin_main_sync_count")
        ),
        pinned_fixture_count: (
          .pinned_fixture_count | pe_integer("source_checkout.pinned_fixture_count")
        ),
        all_runners_pinned_fixture: (
          .all_runners_pinned_fixture
          | pe_bool("source_checkout.all_runners_pinned_fixture")
        ),
        all_runners_clean: (
          .all_runners_clean | pe_bool("source_checkout.all_runners_clean")
        ),
        all_runners_origin_main_synced: (
          .all_runners_origin_main_synced
          | pe_bool("source_checkout.all_runners_origin_main_synced")
        ),
        runner_source_claim_safe: (
          .runner_source_claim_safe
          | pe_bool("source_checkout.runner_source_claim_safe")
        )
      }
  end;

def pe_finding_reconciliation:
  if . == null then
    null
  else
    pe_object("finding_reconciliation")
    | {
        final_json_finding_count: (
          .final_json_finding_count
          | pe_integer("finding_reconciliation.final_json_finding_count")
        ),
        db_saved_finding_count: (
          .db_saved_finding_count
          | pe_integer("finding_reconciliation.db_saved_finding_count")
        ),
        db_active_finding_count: (
          .db_active_finding_count
          | pe_integer("finding_reconciliation.db_active_finding_count")
        ),
        counts_match: (
          .counts_match | pe_bool("finding_reconciliation.counts_match")
        ),
        db_saved_findings_omitted_from_final_json: (
          .db_saved_findings_omitted_from_final_json
          | pe_bool(
              "finding_reconciliation.db_saved_findings_omitted_from_final_json"
            )
        )
      }
  end;

def pe_aggregate_finding_reconciliation:
  pe_object("finding_reconciliation")
  | {
      sample_size: (
        .sample_size | pe_integer("finding_reconciliation.sample_size")
      ),
      direct_final_json_finding_total: (
        .direct_final_json_finding_total
        | pe_integer("finding_reconciliation.direct_final_json_finding_total")
      ),
      eidolon_final_json_finding_total: (
        .eidolon_final_json_finding_total
        | pe_integer("finding_reconciliation.eidolon_final_json_finding_total")
      ),
      direct_db_saved_finding_total: (
        .direct_db_saved_finding_total
        | pe_integer("finding_reconciliation.direct_db_saved_finding_total")
      ),
      eidolon_db_saved_finding_total: (
        .eidolon_db_saved_finding_total
        | pe_integer("finding_reconciliation.eidolon_db_saved_finding_total")
      ),
      direct_db_active_finding_total: (
        .direct_db_active_finding_total
        | pe_integer("finding_reconciliation.direct_db_active_finding_total")
      ),
      eidolon_db_active_finding_total: (
        .eidolon_db_active_finding_total
        | pe_integer("finding_reconciliation.eidolon_db_active_finding_total")
      ),
      direct_db_saved_findings_omitted_run_count: (
        .direct_db_saved_findings_omitted_run_count
        | pe_integer(
            "finding_reconciliation.direct_db_saved_findings_omitted_run_count"
          )
      ),
      eidolon_db_saved_findings_omitted_run_count: (
        .eidolon_db_saved_findings_omitted_run_count
        | pe_integer(
            "finding_reconciliation.eidolon_db_saved_findings_omitted_run_count"
          )
      ),
      positive_eidolon_db_saved_finding_delta_run_count: (
        .positive_eidolon_db_saved_finding_delta_run_count
        | pe_integer(
            "finding_reconciliation.positive_eidolon_db_saved_finding_delta_run_count"
          )
      ),
      positive_eidolon_db_active_finding_delta_run_count: (
        .positive_eidolon_db_active_finding_delta_run_count
        | pe_integer(
            "finding_reconciliation.positive_eidolon_db_active_finding_delta_run_count"
          )
      ),
      any_db_saved_findings_omitted_from_final_json: (
        .any_db_saved_findings_omitted_from_final_json
        | pe_bool(
            "finding_reconciliation.any_db_saved_findings_omitted_from_final_json"
          )
      ),
      final_json_counts_still_drive_finding_claims: (
        .final_json_counts_still_drive_finding_claims
        | pe_bool(
            "finding_reconciliation.final_json_counts_still_drive_finding_claims"
          )
      )
    };

def pe_path_count($output_key; $name):
  pe_object($name + "[]")
  | {
      ($output_key): (
        (
          if has("path") then
            .path
          elif has("value") then
            .value
          else
            null
          end
        )
        | pe_safe_path($name + "[]." + $output_key)
      ),
      count: (.count | pe_integer($name + "[].count"))
    };

def pe_no_signal_totals:
  if . == null then
    null
  else
    pe_object("no_signal_diagnostics.totals")
    | {
        direct_pwnkit_tool_artifacts: (
          .direct_pwnkit_tool_artifacts
          | pe_integer("no_signal_diagnostics.totals.direct_pwnkit_tool_artifacts")
        ),
        eidolon_pwnkit_tool_artifacts: (
          .eidolon_pwnkit_tool_artifacts
          | pe_integer("no_signal_diagnostics.totals.eidolon_pwnkit_tool_artifacts")
        ),
        direct_pwnkit_agent_errors: (
          .direct_pwnkit_agent_errors
          | pe_integer("no_signal_diagnostics.totals.direct_pwnkit_agent_errors")
        ),
        eidolon_pwnkit_agent_errors: (
          .eidolon_pwnkit_agent_errors
          | pe_integer("no_signal_diagnostics.totals.eidolon_pwnkit_agent_errors")
        ),
        direct_pwnkit_request_artifacts: (
          .direct_pwnkit_request_artifacts
          | pe_integer(
              "no_signal_diagnostics.totals.direct_pwnkit_request_artifacts"
            )
        ),
        eidolon_pwnkit_request_artifacts: (
          .eidolon_pwnkit_request_artifacts
          | pe_integer(
              "no_signal_diagnostics.totals.eidolon_pwnkit_request_artifacts"
            )
        ),
        eidolon_proxy_requests: (
          .eidolon_proxy_requests
          | pe_integer("no_signal_diagnostics.totals.eidolon_proxy_requests")
        ),
        correlated_target_requests: (
          .correlated_target_requests
          | pe_integer("no_signal_diagnostics.totals.correlated_target_requests")
        ),
        uncorrelated_eidolon_proxy_requests: (
          .uncorrelated_eidolon_proxy_requests
          | pe_integer(
              "no_signal_diagnostics.totals.uncorrelated_eidolon_proxy_requests"
            )
        )
      }
  end;

def pe_no_signal_diagnostics:
  if . == null then
    null
  else
    pe_object("no_signal_diagnostics")
    | {
        sample_size: (
          .sample_size | pe_integer("no_signal_diagnostics.sample_size")
        ),
        no_target_interaction_run_count: (
          .no_target_interaction_run_count
          | pe_integer("no_signal_diagnostics.no_target_interaction_run_count")
        ),
        all_runs_no_target_interaction: (
          .all_runs_no_target_interaction
          | pe_bool("no_signal_diagnostics.all_runs_no_target_interaction")
        ),
        runs_with_eidolon_pwnkit_request_artifacts: (
          .runs_with_eidolon_pwnkit_request_artifacts
          | pe_integer(
              "no_signal_diagnostics.runs_with_eidolon_pwnkit_request_artifacts"
            )
        ),
        runs_with_eidolon_proxy_requests: (
          .runs_with_eidolon_proxy_requests
          | pe_integer("no_signal_diagnostics.runs_with_eidolon_proxy_requests")
        ),
        runs_with_proxy_requests_but_no_pwnkit_request_artifacts: (
          .runs_with_proxy_requests_but_no_pwnkit_request_artifacts
          | pe_integer(
              "no_signal_diagnostics.runs_with_proxy_requests_but_no_pwnkit_request_artifacts"
            )
        ),
        runs_with_eidolon_agent_errors: (
          .runs_with_eidolon_agent_errors
          | pe_integer("no_signal_diagnostics.runs_with_eidolon_agent_errors")
        ),
        runs_with_eidolon_codex_token_refresh_failure: (
          .runs_with_eidolon_codex_token_refresh_failure
          | pe_integer(
              "no_signal_diagnostics.runs_with_eidolon_codex_token_refresh_failure"
            )
        ),
        runs_with_eidolon_codex_backend_timeout: (
          .runs_with_eidolon_codex_backend_timeout
          | pe_integer(
              "no_signal_diagnostics.runs_with_eidolon_codex_backend_timeout"
            )
        ),
        runs_with_eidolon_codex_backend_error: (
          .runs_with_eidolon_codex_backend_error
          | pe_integer(
              "no_signal_diagnostics.runs_with_eidolon_codex_backend_error"
            )
        ),
        runs_with_pinned_session_but_no_cookie_preservation: (
          .runs_with_pinned_session_but_no_cookie_preservation
          | pe_integer(
              "no_signal_diagnostics.runs_with_pinned_session_but_no_cookie_preservation"
            )
        ),
        totals: (.totals | pe_no_signal_totals),
        proxy_path_counts: [
          (.proxy_path_counts | pe_array("no_signal_diagnostics.proxy_path_counts"))[]
          | pe_path_count("path"; "no_signal_diagnostics.proxy_path_counts")
        ],
        eidolon_agent_error_class_counts: [
          (
            .eidolon_agent_error_class_counts
            | pe_array("no_signal_diagnostics.eidolon_agent_error_class_counts")
          )[]
          | pe_error_class_count(
              "no_signal_diagnostics.eidolon_agent_error_class_counts"
            )
        ],
        likely_cause: (
          .likely_cause | pe_identifier("no_signal_diagnostics.likely_cause")
        )
      }
  end;

def pe_differential_findings:
  if . == null then
    null
  else
    pe_object("differential_findings")
    | {
        minimum_sample_size: (
          .minimum_sample_size
          | pe_integer("differential_findings.minimum_sample_size")
        ),
        sample_size: (
          .sample_size | pe_integer("differential_findings.sample_size")
        ),
        direct_finding_run_count: (
          .direct_finding_run_count
          | pe_integer("differential_findings.direct_finding_run_count")
        ),
        eidolon_finding_run_count: (
          .eidolon_finding_run_count
          | pe_integer("differential_findings.eidolon_finding_run_count")
        ),
        positive_differential_run_count: (
          .positive_differential_run_count
          | pe_integer("differential_findings.positive_differential_run_count")
        ),
        bait_reached_without_eidolon_finding_run_count: (
          .bait_reached_without_eidolon_finding_run_count
          | pe_integer(
              "differential_findings.bait_reached_without_eidolon_finding_run_count"
            )
        ),
        bait_action_without_eidolon_finding_run_count: (
          .bait_action_without_eidolon_finding_run_count
          | pe_integer(
              "differential_findings.bait_action_without_eidolon_finding_run_count"
            )
        ),
        controlled_reality_without_eidolon_finding_run_count: (
          .controlled_reality_without_eidolon_finding_run_count
          | pe_integer(
              "differential_findings.controlled_reality_without_eidolon_finding_run_count"
            )
        ),
        all_direct_quiet: (
          .all_direct_quiet | pe_bool("differential_findings.all_direct_quiet")
        ),
        ready_for_differential_finding_claim: (
          .ready_for_differential_finding_claim
          | pe_bool("differential_findings.ready_for_differential_finding_claim")
        )
      }
  end;

def pe_evidence_gap_diagnostics:
  if . == null then
    null
  else
    pe_object("evidence_gap_diagnostics")
    | {
        sample_size: (
          .sample_size | pe_integer("evidence_gap_diagnostics.sample_size")
        ),
        proxy_trace_present_run_count: (
          .proxy_trace_present_run_count
          | pe_integer("evidence_gap_diagnostics.proxy_trace_present_run_count")
        ),
        proxy_trace_controlled_reality_run_count: (
          .proxy_trace_controlled_reality_run_count
          | pe_integer(
              "evidence_gap_diagnostics.proxy_trace_controlled_reality_run_count"
            )
        ),
        proxy_trace_real_surface_quiet_run_count: (
          .proxy_trace_real_surface_quiet_run_count
          | pe_integer(
              "evidence_gap_diagnostics.proxy_trace_real_surface_quiet_run_count"
            )
        ),
        pwnkit_strict_controlled_reality_run_count: (
          .pwnkit_strict_controlled_reality_run_count
          | pe_integer(
              "evidence_gap_diagnostics.pwnkit_strict_controlled_reality_run_count"
            )
        ),
        pwnkit_strict_same_session_run_count: (
          .pwnkit_strict_same_session_run_count
          | pe_integer(
              "evidence_gap_diagnostics.pwnkit_strict_same_session_run_count"
            )
        ),
        proxy_trace_without_strict_controlled_reality_run_count: (
          .proxy_trace_without_strict_controlled_reality_run_count
          | pe_integer(
              "evidence_gap_diagnostics.proxy_trace_without_strict_controlled_reality_run_count"
            )
        ),
        strict_controlled_reality_without_eidolon_finding_run_count: (
          .strict_controlled_reality_without_eidolon_finding_run_count
          | pe_integer(
              "evidence_gap_diagnostics.strict_controlled_reality_without_eidolon_finding_run_count"
            )
        ),
        positive_differential_without_strict_controlled_reality_run_count: (
          .positive_differential_without_strict_controlled_reality_run_count
          | pe_integer(
              "evidence_gap_diagnostics.positive_differential_without_strict_controlled_reality_run_count"
            )
        ),
        matching_proxy_exposure_not_pwnkit_correlated_run_count: (
          .matching_proxy_exposure_not_pwnkit_correlated_run_count
          | pe_integer(
              "evidence_gap_diagnostics.matching_proxy_exposure_not_pwnkit_correlated_run_count"
            )
        ),
        matching_proxy_exposure_crawl_start_path_run_count: (
          .matching_proxy_exposure_crawl_start_path_run_count
          | pe_integer(
              "evidence_gap_diagnostics.matching_proxy_exposure_crawl_start_path_run_count"
            )
        ),
        strict_correlation_gap_likely_causes: [
          (
            .strict_correlation_gap_likely_causes
            | pe_array(
                "evidence_gap_diagnostics.strict_correlation_gap_likely_causes"
              )
          )[]
          | pe_value_count(
              "likely_cause";
              "evidence_gap_diagnostics.strict_correlation_gap_likely_causes"
            )
        ],
        all_proxy_trace_contained: (
          .all_proxy_trace_contained
          | pe_bool("evidence_gap_diagnostics.all_proxy_trace_contained")
        ),
        all_strict_pwnkit_controlled_reality: (
          .all_strict_pwnkit_controlled_reality
          | pe_bool(
              "evidence_gap_diagnostics.all_strict_pwnkit_controlled_reality"
            )
        ),
        all_strict_controlled_reality_promoted_to_findings: (
          .all_strict_controlled_reality_promoted_to_findings
          | pe_bool(
              "evidence_gap_diagnostics.all_strict_controlled_reality_promoted_to_findings"
            )
        ),
        observed_gaps: (
          .observed_gaps
          | pe_identifier_list("evidence_gap_diagnostics.observed_gaps")
        )
      }
  end;

def pe_strict_stability:
  if . == null then
    null
  else
    pe_object("strict_stability")
    | {
        minimum_sample_size: (
          .minimum_sample_size | pe_integer("strict_stability.minimum_sample_size")
        ),
        sample_size: (.sample_size | pe_integer("strict_stability.sample_size")),
        all_summaries_present: (
          .all_summaries_present | pe_bool("strict_stability.all_summaries_present")
        ),
        all_execution_ids_present: (
          .all_execution_ids_present
          | pe_bool("strict_stability.all_execution_ids_present")
        ),
        all_execution_ids_distinct: (
          .all_execution_ids_distinct
          | pe_bool("strict_stability.all_execution_ids_distinct")
        ),
        all_run_provenance_valid: (
          .all_run_provenance_valid
          | pe_bool("strict_stability.all_run_provenance_valid")
        ),
        all_proxy_event_logs_present: (
          .all_proxy_event_logs_present
          | pe_bool("strict_stability.all_proxy_event_logs_present")
        ),
        all_proxy_event_log_digests_distinct: (
          .all_proxy_event_log_digests_distinct
          | pe_bool("strict_stability.all_proxy_event_log_digests_distinct")
        ),
        single_runner_git_head: (
          .single_runner_git_head
          | pe_bool("strict_stability.single_runner_git_head")
        ),
        single_evidence_track: (
          .single_evidence_track
          | pe_bool("strict_stability.single_evidence_track")
        ),
        all_target_interaction_observed: (
          .all_target_interaction_observed
          | pe_bool("strict_stability.all_target_interaction_observed")
        ),
        all_same_session_confirmed_bait_action: (
          .all_same_session_confirmed_bait_action
          | pe_bool("strict_stability.all_same_session_confirmed_bait_action")
        ),
        all_controlled_reality_entered: (
          .all_controlled_reality_entered
          | pe_bool("strict_stability.all_controlled_reality_entered")
        ),
        all_direct_quiet: (
          .all_direct_quiet | pe_bool("strict_stability.all_direct_quiet")
        ),
        all_pinned_cookie_preserved: (
          .all_pinned_cookie_preserved
          | pe_bool("strict_stability.all_pinned_cookie_preserved")
        ),
        all_runners_clean: (
          .all_runners_clean | pe_bool("strict_stability.all_runners_clean")
        ),
        all_runners_origin_main_synced: (
          .all_runners_origin_main_synced
          | pe_bool("strict_stability.all_runners_origin_main_synced")
        ),
        all_runners_pinned_fixture: (
          .all_runners_pinned_fixture
          | pe_bool("strict_stability.all_runners_pinned_fixture")
        ),
        runner_source_claim_safe: (
          .runner_source_claim_safe
          | pe_bool("strict_stability.runner_source_claim_safe")
        ),
        ready_for_stability_claim: (
          .ready_for_stability_claim
          | pe_bool("strict_stability.ready_for_stability_claim")
        )
      }
  end;

def pe_pwnkit_events:
  if . == null then
    null
  else
    pe_object("pwnkit_events")
    | {
        pipeline_events: (
          .pipeline_events | pe_integer("pwnkit_events.pipeline_events")
        ),
        tool_artifacts: (
          .tool_artifacts | pe_integer("pwnkit_events.tool_artifacts")
        ),
        tool_counts: [
          (.tool_counts | pe_array("pwnkit_events.tool_counts"))[]
          | pe_value_count("tool"; "pwnkit_events.tool_counts")
        ],
        crawl_artifacts: [
          (.crawl_artifacts | pe_array("pwnkit_events.crawl_artifacts"))[]
          | pe_object("pwnkit_events.crawl_artifacts[]")
          | {
              timestamp_ms: (
                .timestamp_ms
                | pe_integer("pwnkit_events.crawl_artifacts[].timestamp_ms")
              ),
              start_path: (
                .start_path
                | pe_safe_path("pwnkit_events.crawl_artifacts[].start_path")
              ),
              depth: (
                .depth | pe_integer("pwnkit_events.crawl_artifacts[].depth")
              ),
              pages_visited: (
                .pages_visited
                | pe_integer("pwnkit_events.crawl_artifacts[].pages_visited")
              )
            }
        ]
      }
  end;

def pe_target_evidence_diagnostics:
  if . == null then
    null
  else
    pe_object("target_evidence_diagnostics")
    | {
        request_artifact_count: (
          .request_artifact_count
          | pe_integer("target_evidence_diagnostics.request_artifact_count")
        ),
        http_request_artifact_count: (
          .http_request_artifact_count
          | pe_integer("target_evidence_diagnostics.http_request_artifact_count")
        ),
        bash_http_output_request_count: (
          .bash_http_output_request_count
          | pe_integer(
              "target_evidence_diagnostics.bash_http_output_request_count"
            )
        ),
        crawl_artifact_count: (
          .crawl_artifact_count
          | pe_integer("target_evidence_diagnostics.crawl_artifact_count")
        ),
        crawl_start_paths: (
          .crawl_start_paths
          | pe_path_list("target_evidence_diagnostics.crawl_start_paths")
        ),
        observed_request_evidence_without_findings: (
          .observed_request_evidence_without_findings
          | pe_bool(
              "target_evidence_diagnostics.observed_request_evidence_without_findings"
            )
        )
      }
  end;

def pe_agent_error_diagnostics:
  if . == null then
    null
  else
    pe_object("agent_error_diagnostics")
    | {
        count: (.count | pe_integer("agent_error_diagnostics.count")),
        stage_counts: [
          (.stage_counts | pe_array("agent_error_diagnostics.stage_counts"))[]
          | pe_object("agent_error_diagnostics.stage_counts[]")
          | {
              stage: (
                .stage | pe_identifier("agent_error_diagnostics.stage_counts[].stage")
              ),
              agentRole: (
                .agentRole
                | pe_identifier("agent_error_diagnostics.stage_counts[].agentRole")
              ),
              count: (
                .count | pe_integer("agent_error_diagnostics.stage_counts[].count")
              )
            }
        ],
        class_counts: [
          (.class_counts | pe_array("agent_error_diagnostics.class_counts"))[]
          | pe_error_class_count("agent_error_diagnostics.class_counts")
        ],
        has_agent_error: (
          .has_agent_error | pe_bool("agent_error_diagnostics.has_agent_error")
        ),
        has_codex_token_refresh_failure: (
          .has_codex_token_refresh_failure
          | pe_bool("agent_error_diagnostics.has_codex_token_refresh_failure")
        ),
        has_codex_authentication_failure: (
          .has_codex_authentication_failure
          | pe_bool("agent_error_diagnostics.has_codex_authentication_failure")
        ),
        has_codex_backend_api_error: (
          .has_codex_backend_api_error
          | pe_bool("agent_error_diagnostics.has_codex_backend_api_error")
        ),
        has_codex_backend_timeout: (
          .has_codex_backend_timeout
          | pe_bool("agent_error_diagnostics.has_codex_backend_timeout")
        )
      }
  end;

def pe_correlated_counts:
  pe_object("correlated_counts")
  | {
      target_requests: (
        .target_requests | pe_integer("correlated_counts.target_requests")
      ),
      bait_exposures: (
        .bait_exposures | pe_integer("correlated_counts.bait_exposures")
      ),
      bait_actions: (
        .bait_actions | pe_integer("correlated_counts.bait_actions")
      ),
      same_session_confirmed_bait_actions: (
        .same_session_confirmed_bait_actions
        | pe_integer("correlated_counts.same_session_confirmed_bait_actions")
      ),
      controlled_reality_entries: (
        .controlled_reality_entries
        | pe_integer("correlated_counts.controlled_reality_entries")
      )
    };

def pe_pinned_session:
  if . == null then
    null
  else
    pe_object("pinned_session")
    | {
        present: (.present | pe_bool("pinned_session.present")),
        cookie_preserved: (
          .cookie_preserved | pe_bool("pinned_session.cookie_preserved")
        ),
        proxy_request_count: (
          .proxy_request_count | pe_integer("pinned_session.proxy_request_count")
        ),
        correlated_target_request_count: (
          .correlated_target_request_count
          | pe_integer("pinned_session.correlated_target_request_count")
        ),
        correlated_bait_exposure_count: (
          .correlated_bait_exposure_count
          | pe_integer("pinned_session.correlated_bait_exposure_count")
        ),
        correlated_bait_action_count: (
          .correlated_bait_action_count
          | pe_integer("pinned_session.correlated_bait_action_count")
        ),
        same_session_confirmed_bait_action_count: (
          .same_session_confirmed_bait_action_count
          | pe_integer("pinned_session.same_session_confirmed_bait_action_count")
        ),
        controlled_reality_entry_count: (
          .controlled_reality_entry_count
          | pe_integer("pinned_session.controlled_reality_entry_count")
        ),
        same_session_confirmation_possible: (
          .same_session_confirmation_possible
          | pe_bool("pinned_session.same_session_confirmation_possible")
        )
      }
  end;

def pe_bait_matrix:
  pe_array("bait_matrix")
  | [
      .[]
      | pe_object("bait_matrix[]")
      | {
          bait_id: (.bait_id | pe_identifier("bait_matrix[].bait_id")),
          exposure_count: (
            .exposure_count | pe_integer("bait_matrix[].exposure_count")
          ),
          action_count: (.action_count | pe_integer("bait_matrix[].action_count")),
          same_session_confirmed_action_count: (
            .same_session_confirmed_action_count
            | pe_integer("bait_matrix[].same_session_confirmed_action_count")
          ),
          surfaces: (.surfaces | pe_path_list("bait_matrix[].surfaces")),
          action_paths: (
            .action_paths | pe_path_list("bait_matrix[].action_paths")
          )
        }
    ];

def pe_target_correlation_diagnostics:
  if . == null then
    null
  else
    pe_object("target_correlation_diagnostics")
    | {
        pwnkit_eidolon_tool_artifact_count: (
          .pwnkit_eidolon_tool_artifact_count
          | pe_integer(
              "target_correlation_diagnostics.pwnkit_eidolon_tool_artifact_count"
            )
        ),
        pwnkit_eidolon_request_artifact_count: (
          .pwnkit_eidolon_request_artifact_count
          | pe_integer(
              "target_correlation_diagnostics.pwnkit_eidolon_request_artifact_count"
            )
        ),
        pwnkit_eidolon_agent_error_count: (
          .pwnkit_eidolon_agent_error_count
          | pe_integer(
              "target_correlation_diagnostics.pwnkit_eidolon_agent_error_count"
            )
        ),
        pwnkit_eidolon_agent_error_classes: [
          (
            .pwnkit_eidolon_agent_error_classes
            | pe_array(
                "target_correlation_diagnostics.pwnkit_eidolon_agent_error_classes"
              )
          )[]
          | pe_error_class_count(
              "target_correlation_diagnostics.pwnkit_eidolon_agent_error_classes"
            )
        ],
        eidolon_proxy_request_count: (
          .eidolon_proxy_request_count
          | pe_integer("target_correlation_diagnostics.eidolon_proxy_request_count")
        ),
        correlated_target_request_count: (
          .correlated_target_request_count
          | pe_integer(
              "target_correlation_diagnostics.correlated_target_request_count"
            )
        ),
        uncorrelated_proxy_request_count: (
          .uncorrelated_proxy_request_count
          | pe_integer(
              "target_correlation_diagnostics.uncorrelated_proxy_request_count"
            )
        ),
        likely_cause: (
          .likely_cause | pe_identifier("target_correlation_diagnostics.likely_cause")
        )
      }
  end;

def pe_finding_gap:
  if . == null then
    null
  else
    pe_object("finding_gap")
    | {
        direct_finding_count: (
          .direct_finding_count | pe_integer("finding_gap.direct_finding_count")
        ),
        eidolon_finding_count: (
          .eidolon_finding_count | pe_integer("finding_gap.eidolon_finding_count")
        ),
        differential_finding_count: (
          .differential_finding_count
          | pe_integer("finding_gap.differential_finding_count")
        ),
        positive_differential_findings: (
          .positive_differential_findings
          | pe_bool("finding_gap.positive_differential_findings")
        ),
        direct_quiet: (.direct_quiet | pe_bool("finding_gap.direct_quiet")),
        eidolon_has_findings: (
          .eidolon_has_findings | pe_bool("finding_gap.eidolon_has_findings")
        ),
        eidolon_observed_target_evidence_without_findings: (
          .eidolon_observed_target_evidence_without_findings
          | pe_bool(
              "finding_gap.eidolon_observed_target_evidence_without_findings"
            )
        ),
        eidolon_bait_reached_without_findings: (
          .eidolon_bait_reached_without_findings
          | pe_bool("finding_gap.eidolon_bait_reached_without_findings")
        ),
        eidolon_bait_action_without_findings: (
          .eidolon_bait_action_without_findings
          | pe_bool("finding_gap.eidolon_bait_action_without_findings")
        ),
        eidolon_controlled_reality_without_findings: (
          .eidolon_controlled_reality_without_findings
          | pe_bool("finding_gap.eidolon_controlled_reality_without_findings")
        )
      }
  end;

def pe_finding_export_gap:
  if . == null then
    null
  else
    pe_object("finding_export_gap")
    | {
        direct_final_json_finding_count: (
          .direct_final_json_finding_count
          | pe_integer("finding_export_gap.direct_final_json_finding_count")
        ),
        eidolon_final_json_finding_count: (
          .eidolon_final_json_finding_count
          | pe_integer("finding_export_gap.eidolon_final_json_finding_count")
        ),
        direct_db_saved_finding_count: (
          .direct_db_saved_finding_count
          | pe_integer("finding_export_gap.direct_db_saved_finding_count")
        ),
        eidolon_db_saved_finding_count: (
          .eidolon_db_saved_finding_count
          | pe_integer("finding_export_gap.eidolon_db_saved_finding_count")
        ),
        direct_db_active_finding_count: (
          .direct_db_active_finding_count
          | pe_integer("finding_export_gap.direct_db_active_finding_count")
        ),
        eidolon_db_active_finding_count: (
          .eidolon_db_active_finding_count
          | pe_integer("finding_export_gap.eidolon_db_active_finding_count")
        ),
        direct_db_saved_findings_omitted_from_final_json: (
          .direct_db_saved_findings_omitted_from_final_json
          | pe_bool(
              "finding_export_gap.direct_db_saved_findings_omitted_from_final_json"
            )
        ),
        eidolon_db_saved_findings_omitted_from_final_json: (
          .eidolon_db_saved_findings_omitted_from_final_json
          | pe_bool(
              "finding_export_gap.eidolon_db_saved_findings_omitted_from_final_json"
            )
        ),
        any_db_saved_findings_omitted_from_final_json: (
          .any_db_saved_findings_omitted_from_final_json
          | pe_bool(
              "finding_export_gap.any_db_saved_findings_omitted_from_final_json"
            )
        ),
        positive_eidolon_db_saved_finding_delta: (
          .positive_eidolon_db_saved_finding_delta
          | pe_bool("finding_export_gap.positive_eidolon_db_saved_finding_delta")
        ),
        positive_eidolon_db_active_finding_delta: (
          .positive_eidolon_db_active_finding_delta
          | pe_bool("finding_export_gap.positive_eidolon_db_active_finding_delta")
        ),
        final_json_counts_still_drive_finding_gap: (
          .final_json_counts_still_drive_finding_gap
          | pe_bool("finding_export_gap.final_json_counts_still_drive_finding_gap")
        )
      }
  end;

def pe_unconfirmed_action:
  pe_object("strict_correlation_gap.unconfirmed_actions[]")
  | {
      bait_id: (
        .bait_id
        | pe_identifier("strict_correlation_gap.unconfirmed_actions[].bait_id")
      ),
      action_path: (
        .action_path
        | pe_safe_path("strict_correlation_gap.unconfirmed_actions[].action_path")
      ),
      has_exposure_id: (
        .has_exposure_id
        | pe_bool("strict_correlation_gap.unconfirmed_actions[].has_exposure_id")
      ),
      matching_proxy_exposure_count: (
        .matching_proxy_exposure_count
        | pe_integer(
            "strict_correlation_gap.unconfirmed_actions[].matching_proxy_exposure_count"
          )
      ),
      matching_strict_exposure_count: (
        .matching_strict_exposure_count
        | pe_integer(
            "strict_correlation_gap.unconfirmed_actions[].matching_strict_exposure_count"
          )
      ),
      matching_proxy_exposure_surfaces: (
        .matching_proxy_exposure_surfaces
        | pe_path_list(
            "strict_correlation_gap.unconfirmed_actions[].matching_proxy_exposure_surfaces"
          )
      ),
      matching_proxy_exposure_crawl_start_paths: (
        .matching_proxy_exposure_crawl_start_paths
        | pe_path_list(
            "strict_correlation_gap.unconfirmed_actions[].matching_proxy_exposure_crawl_start_paths"
          )
      ),
      reason: (
        .reason
        | pe_identifier("strict_correlation_gap.unconfirmed_actions[].reason")
      )
    };

def pe_strict_correlation_gap:
  if . == null then
    null
  else
    pe_object("strict_correlation_gap")
    | {
        proxy_confirmed_action_count: (
          .proxy_confirmed_action_count
          | pe_integer("strict_correlation_gap.proxy_confirmed_action_count")
        ),
        strict_correlated_action_count: (
          .strict_correlated_action_count
          | pe_integer("strict_correlation_gap.strict_correlated_action_count")
        ),
        strict_confirmed_action_count: (
          .strict_confirmed_action_count
          | pe_integer("strict_correlation_gap.strict_confirmed_action_count")
        ),
        unconfirmed_strict_action_count: (
          .unconfirmed_strict_action_count
          | pe_integer("strict_correlation_gap.unconfirmed_strict_action_count")
        ),
        proxy_confirmed_action_not_strict_count: (
          .proxy_confirmed_action_not_strict_count
          | pe_integer(
              "strict_correlation_gap.proxy_confirmed_action_not_strict_count"
            )
        ),
        matching_proxy_exposure_not_pwnkit_correlated_count: (
          .matching_proxy_exposure_not_pwnkit_correlated_count
          | pe_integer(
              "strict_correlation_gap.matching_proxy_exposure_not_pwnkit_correlated_count"
            )
        ),
        unconfirmed_actions: [
          (
            .unconfirmed_actions
            | pe_array("strict_correlation_gap.unconfirmed_actions")
          )[]
          | pe_unconfirmed_action
        ],
        crawl_artifact_count: (
          .crawl_artifact_count
          | pe_integer("strict_correlation_gap.crawl_artifact_count")
        ),
        crawl_artifact_start_paths: (
          .crawl_artifact_start_paths
          | pe_path_list("strict_correlation_gap.crawl_artifact_start_paths")
        ),
        matching_proxy_exposure_crawl_start_path_count: (
          .matching_proxy_exposure_crawl_start_path_count
          | pe_integer(
              "strict_correlation_gap.matching_proxy_exposure_crawl_start_path_count"
            )
        ),
        matching_proxy_exposure_crawl_start_paths: (
          .matching_proxy_exposure_crawl_start_paths
          | pe_path_list(
              "strict_correlation_gap.matching_proxy_exposure_crawl_start_paths"
            )
        ),
        likely_cause: (
          .likely_cause | pe_identifier("strict_correlation_gap.likely_cause")
        ),
        likely_missing_artifact_class: (
          .likely_missing_artifact_class
          | pe_identifier("strict_correlation_gap.likely_missing_artifact_class")
        )
      }
  end;

def pe_proxy_summary:
  if . == null then
    null
  else
    pe_object("eidolon_proxy")
    | {
        present: (.present | pe_bool("eidolon_proxy.present")),
        event_count: (
          .event_count | pe_integer("eidolon_proxy.event_count")
        ),
        request_count: (
          .request_count | pe_integer("eidolon_proxy.request_count")
        ),
        protected_upstream_request_count: (
          .protected_upstream_request_count
          | pe_integer("eidolon_proxy.protected_upstream_request_count")
        ),
        bait_exposure_count: (
          .bait_exposure_count | pe_integer("eidolon_proxy.bait_exposure_count")
        ),
        bait_action_count: (
          .bait_action_count | pe_integer("eidolon_proxy.bait_action_count")
        ),
        controlled_reality_entry_count: (
          .controlled_reality_entry_count
          | pe_integer("eidolon_proxy.controlled_reality_entry_count")
        ),
        kind_counts: [
          (.kind_counts | pe_array("eidolon_proxy.kind_counts"))[]
          | pe_value_count("kind"; "eidolon_proxy.kind_counts")
        ],
        routing_counts: [
          (.routing_counts | pe_array("eidolon_proxy.routing_counts"))[]
          | pe_value_count("routing_decision"; "eidolon_proxy.routing_counts")
        ],
        request_path_counts: [
          (.request_path_counts | pe_array("eidolon_proxy.request_path_counts"))[]
          | pe_path_count("value"; "eidolon_proxy.request_path_counts")
        ],
        bait_matrix: (.bait_matrix | pe_bait_matrix)
      }
  end;

def pe_artifact_metrics:
  if . == null then
    null
  else
    pe_object("metrics")
    | {
        bait_follow_rate: (
          .bait_follow_rate | pe_number("metrics.bait_follow_rate")
        ),
        same_session_confirmed_bait_follow_rate: (
          .same_session_confirmed_bait_follow_rate
          | pe_number("metrics.same_session_confirmed_bait_follow_rate")
        )
      }
  end;

def pe_agent_trace_summary:
  if . == null then
    null
  else
    pe_object("agent_trace")
    | {
        claim_level: (.claim_level | pe_identifier("agent_trace.claim_level")),
        real_surface_requests_after_containment: (
          .real_surface_requests_after_containment
          | pe_integer("agent_trace.real_surface_requests_after_containment")
        ),
        controlled_reality_action_depth: (
          .controlled_reality_action_depth
          | pe_integer("agent_trace.controlled_reality_action_depth")
        ),
        controlled_reality_branch_count: (
          .controlled_reality_branch_count
          | pe_integer("agent_trace.controlled_reality_branch_count")
        )
      }
  end;

def pe_trace_gap:
  if . == null then
    null
  else
    pe_object("trace_gap")
    | {
        proxy_trace_present: (
          .proxy_trace_present | pe_bool("trace_gap.proxy_trace_present")
        ),
        proxy_trace_claim_level: (
          .proxy_trace_claim_level | pe_identifier("trace_gap.proxy_trace_claim_level")
        ),
        proxy_trace_controlled_reality_entered: (
          .proxy_trace_controlled_reality_entered
          | pe_bool("trace_gap.proxy_trace_controlled_reality_entered")
        ),
        proxy_trace_real_surface_quiet: (
          .proxy_trace_real_surface_quiet
          | pe_bool("trace_gap.proxy_trace_real_surface_quiet")
        ),
        pwnkit_strict_claim_level: (
          .pwnkit_strict_claim_level
          | pe_identifier("trace_gap.pwnkit_strict_claim_level")
        ),
        pwnkit_strict_same_session_confirmed: (
          .pwnkit_strict_same_session_confirmed
          | pe_bool("trace_gap.pwnkit_strict_same_session_confirmed")
        ),
        pwnkit_strict_controlled_reality_entered: (
          .pwnkit_strict_controlled_reality_entered
          | pe_bool("trace_gap.pwnkit_strict_controlled_reality_entered")
        ),
        proxy_trace_controlled_reality_without_strict_confirmation: (
          .proxy_trace_controlled_reality_without_strict_confirmation
          | pe_bool(
              "trace_gap.proxy_trace_controlled_reality_without_strict_confirmation"
            )
        ),
        strict_controlled_reality_without_eidolon_finding: (
          .strict_controlled_reality_without_eidolon_finding
          | pe_bool(
              "trace_gap.strict_controlled_reality_without_eidolon_finding"
            )
        ),
        positive_differential_without_strict_controlled_reality: (
          .positive_differential_without_strict_controlled_reality
          | pe_bool(
              "trace_gap.positive_differential_without_strict_controlled_reality"
            )
        )
      }
  end;

def pe_sample_artifact:
  pe_object("artifacts[]")
  | {
      artifact_dir: "<source-artifact-path-omitted>",
      present: (.present | pe_bool("artifacts[].present")),
      missing_reason: (
        .missing_reason | pe_missing_reason("artifacts[].missing_reason")
      ),
      evidence_track: (
        .evidence_track | pe_identifier("artifacts[].evidence_track")
      ),
      runner_git_head: (
        .runner_git_head | pe_identifier("artifacts[].runner_git_head")
      ),
      runner_package_version: (
        .runner_package_version
        | pe_package_version("artifacts[].runner_package_version")
      ),
      runner_git_dirty: (
        .runner_git_dirty | pe_bool("artifacts[].runner_git_dirty")
      ),
      runner_origin_main_in_sync: (
        .runner_origin_main_in_sync
        | pe_bool("artifacts[].runner_origin_main_in_sync")
      ),
      runner_pwnkit_fixture: (.runner_pwnkit_fixture | pe_fixture),
      runner_pwnkit_fixture_id: (
        .runner_pwnkit_fixture_id
        | pe_fixture_id("artifacts[].runner_pwnkit_fixture_id")
      ),
      stale_dist_guard_bypassed: (
        .stale_dist_guard_bypassed
        | pe_bool("artifacts[].stale_dist_guard_bypassed")
      ),
      runner_environment: (
        .runner_environment | pe_identifier("artifacts[].runner_environment")
      ),
      runner_environment_source: (
        .runner_environment_source
        | pe_identifier("artifacts[].runner_environment_source")
      ),
      runner_network_topology: (
        .runner_network_topology
        | pe_identifier("artifacts[].runner_network_topology")
      ),
      runner_os: (.runner_os | pe_runner_os),
      runner_tool_fingerprint: [
        (
          .runner_tool_fingerprint
          | pe_array("artifacts[].runner_tool_fingerprint")
        )[]
        | pe_tool_fingerprint
      ],
      claim_level: (.claim_level | pe_identifier("artifacts[].claim_level")),
      conclusion: (.conclusion | pe_identifier("artifacts[].conclusion")),
      target_interaction_observed: (
        .target_interaction_observed
        | pe_bool("artifacts[].target_interaction_observed")
      ),
      bait_reached: (.bait_reached | pe_bool("artifacts[].bait_reached")),
      bait_action_observed: (
        .bait_action_observed | pe_bool("artifacts[].bait_action_observed")
      ),
      same_session_confirmed_bait_action: (
        .same_session_confirmed_bait_action
        | pe_bool("artifacts[].same_session_confirmed_bait_action")
      ),
      controlled_reality_entered: (
        .controlled_reality_entered
        | pe_bool("artifacts[].controlled_reality_entered")
      ),
      direct_finding_count: (
        .direct_finding_count | pe_integer("artifacts[].direct_finding_count")
      ),
      eidolon_finding_count: (
        .eidolon_finding_count | pe_integer("artifacts[].eidolon_finding_count")
      ),
      direct_final_json_finding_count: (
        .direct_final_json_finding_count
        | pe_integer("artifacts[].direct_final_json_finding_count")
      ),
      eidolon_final_json_finding_count: (
        .eidolon_final_json_finding_count
        | pe_integer("artifacts[].eidolon_final_json_finding_count")
      ),
      direct_db_saved_finding_count: (
        .direct_db_saved_finding_count
        | pe_integer("artifacts[].direct_db_saved_finding_count")
      ),
      eidolon_db_saved_finding_count: (
        .eidolon_db_saved_finding_count
        | pe_integer("artifacts[].eidolon_db_saved_finding_count")
      ),
      direct_db_active_finding_count: (
        .direct_db_active_finding_count
        | pe_integer("artifacts[].direct_db_active_finding_count")
      ),
      eidolon_db_active_finding_count: (
        .eidolon_db_active_finding_count
        | pe_integer("artifacts[].eidolon_db_active_finding_count")
      ),
      finding_reconciliation: {
        direct: (.finding_reconciliation.direct | pe_finding_reconciliation),
        eidolon: (.finding_reconciliation.eidolon | pe_finding_reconciliation)
      },
      pwnkit_events: {
        direct: (.pwnkit_events.direct | pe_pwnkit_events),
        eidolon: (.pwnkit_events.eidolon | pe_pwnkit_events)
      },
      target_evidence_diagnostics: {
        direct: (
          .target_evidence_diagnostics.direct | pe_target_evidence_diagnostics
        ),
        eidolon: (
          .target_evidence_diagnostics.eidolon | pe_target_evidence_diagnostics
        )
      },
      agent_error_diagnostics: {
        direct: (.agent_error_diagnostics.direct | pe_agent_error_diagnostics),
        eidolon: (.agent_error_diagnostics.eidolon | pe_agent_error_diagnostics)
      },
      eidolon_proxy: (.eidolon_proxy | pe_proxy_summary),
      target_correlation_diagnostics: (
        .target_correlation_diagnostics | pe_target_correlation_diagnostics
      ),
      finding_gap: (.finding_gap | pe_finding_gap),
      finding_export_gap: (.finding_export_gap | pe_finding_export_gap),
      strict_correlation_gap: (
        .strict_correlation_gap | pe_strict_correlation_gap
      ),
      correlated_counts: (.correlated_counts | pe_correlated_counts),
      pinned_session: (.pinned_session | pe_pinned_session),
      metrics: (.metrics | pe_artifact_metrics),
      agent_trace: (.agent_trace | pe_agent_trace_summary),
      trace_gap: (.trace_gap | pe_trace_gap)
    };

def public_sample_summary:
  pe_object("sample summary")
  | {
      schema_version: (.schema_version | pe_expect("schema_version"; 1)),
      run_kind: (
        .run_kind | pe_expect("run_kind"; "m3_pwnkit_codex_sample")
      ),
      generated_at: (.generated_at | pe_timestamp("generated_at")),
      artifact_count: (.artifact_count | pe_integer("artifact_count")),
      valid_summary_count: (
        .valid_summary_count | pe_integer("valid_summary_count")
      ),
      counts: (.counts | pe_sample_counts),
      rates: (.rates | pe_sample_rates),
      claim_level_counts: [
        (.claim_level_counts | pe_array("claim_level_counts"))[]
        | pe_claim_count
      ],
      weakest_claim_level: (
        .weakest_claim_level | pe_identifier("weakest_claim_level")
      ),
      strongest_claim_level: (
        .strongest_claim_level | pe_identifier("strongest_claim_level")
      ),
      runner_git_heads: (
        .runner_git_heads | pe_identifier_list("runner_git_heads")
      ),
      runner_package_versions: (
        .runner_package_versions
        | pe_package_version_list("runner_package_versions")
      ),
      runner_pwnkit_fixture_ids: (
        .runner_pwnkit_fixture_ids
        | pe_fixture_id_list("runner_pwnkit_fixture_ids")
      ),
      evidence_track_counts: [
        (.evidence_track_counts | pe_array("evidence_track_counts"))[]
        | pe_value_count("evidence_track"; "evidence_track_counts")
      ],
      evidence_tracks: (
        .evidence_tracks | pe_identifier_list("evidence_tracks")
      ),
      single_evidence_track: (
        .single_evidence_track | pe_bool("single_evidence_track")
      ),
      mixed_evidence_tracks: (
        .mixed_evidence_tracks | pe_bool("mixed_evidence_tracks")
      ),
      unknown_evidence_track_count: (
        .unknown_evidence_track_count
        | pe_integer("unknown_evidence_track_count")
      ),
      runner_environments: (
        .runner_environments | pe_identifier_list("runner_environments")
      ),
      runner_network_topologies: (
        .runner_network_topologies
        | pe_identifier_list("runner_network_topologies")
      ),
      tool_fingerprint_summary: [
        (.tool_fingerprint_summary | pe_array("tool_fingerprint_summary"))[]
        | pe_tool_fingerprint_summary
      ],
      source_checkout: (.source_checkout | pe_source_checkout),
      finding_reconciliation: (
        .finding_reconciliation | pe_aggregate_finding_reconciliation
      ),
      no_signal_diagnostics: (
        .no_signal_diagnostics | pe_no_signal_diagnostics
      ),
      differential_findings: (
        .differential_findings | pe_differential_findings
      ),
      evidence_gap_diagnostics: (
        .evidence_gap_diagnostics | pe_evidence_gap_diagnostics
      ),
      strict_stability: (.strict_stability | pe_strict_stability),
      artifacts: [
        (.artifacts | pe_array("artifacts"))[]
        | pe_sample_artifact
      ],
      redaction: {
        raw_run_summaries_omitted: true,
        raw_requested_paths_omitted: true,
        raw_tool_evidence_labels_omitted: true,
        raw_agent_error_text_omitted: true,
        raw_pwnkit_artifacts_omitted: true,
        raw_proxy_events_omitted: true,
        private_debug_logs_omitted: true,
        source_artifact_paths_omitted: true,
        runner_command_paths_omitted: true,
        session_identifiers_omitted: true,
        free_form_notes_omitted: true,
        unknown_fields_omitted: true
      }
    };

def pe_runner_environment:
  if . == null then
    null
  else
    pe_object("runner.environment")
    | {
        runner_environment: (
          .runner_environment
          | pe_identifier("runner.environment.runner_environment")
        ),
        runner_environment_source: (
          .runner_environment_source
          | pe_identifier("runner.environment.runner_environment_source")
        ),
        network_topology: (
          .network_topology | pe_identifier("runner.environment.network_topology")
        ),
        os: (.os | pe_runner_os),
        tool_fingerprint: [
          (.tool_fingerprint | pe_array("runner.environment.tool_fingerprint"))[]
          | pe_tool_fingerprint
        ]
      }
  end;

def pe_origin_main:
  if . == null then
    null
  else
    pe_object("runner.pwnkit.origin_main")
    | {
        in_sync: (.in_sync | pe_bool("runner.pwnkit.origin_main.in_sync"))
      }
  end;

def pe_runner_pwnkit:
  pe_object("runner.pwnkit")
  | {
      depth: (.depth | pe_identifier("runner.pwnkit.depth")),
      mode: (.mode | pe_identifier("runner.pwnkit.mode")),
      runtime: (.runtime | pe_identifier("runner.pwnkit.runtime")),
      rate_limit: (.rate_limit | pe_identifier("runner.pwnkit.rate_limit")),
      command_source: (
        .command_source | pe_identifier("runner.pwnkit.command_source")
      ),
      package_version: (
        .package_version | pe_package_version("runner.pwnkit.package_version")
      ),
      git_head: (.git_head | pe_identifier("runner.pwnkit.git_head")),
      git_head_short: (
        .git_head_short | pe_identifier("runner.pwnkit.git_head_short")
      ),
      git_head_time_seconds: (
        .git_head_time_seconds | pe_integer("runner.pwnkit.git_head_time_seconds")
      ),
      git_dirty: (.git_dirty | pe_bool("runner.pwnkit.git_dirty")),
      origin_main: (.origin_main | pe_origin_main),
      evidence_track: (
        .evidence_track | pe_identifier("runner.pwnkit.evidence_track")
      ),
      fixture: (.fixture | pe_fixture),
      stale_dist_guard_bypassed: (
        .stale_dist_guard_bypassed
        | pe_bool("runner.pwnkit.stale_dist_guard_bypassed")
      )
    };

def pe_scan_run($name):
  pe_object($name)
  | {
      scan_depth: (.scan_depth | pe_identifier($name + ".scan_depth")),
      duration_ms: (.duration_ms | pe_number($name + ".duration_ms")),
      finding_count: (.finding_count | pe_integer($name + ".finding_count")),
      final_json_finding_count: (
        .final_json_finding_count
        | pe_integer($name + ".final_json_finding_count")
      ),
      db_saved_finding_count: (
        .db_saved_finding_count
        | pe_integer($name + ".db_saved_finding_count")
      ),
      db_active_finding_count: (
        .db_active_finding_count
        | pe_integer($name + ".db_active_finding_count")
      ),
      warning_count: (
        (.warnings | pe_array($name + ".warnings") | length)
        | pe_integer($name + ".warning_count")
      ),
      pwnkit_events: (.pwnkit_events | pe_pwnkit_events),
      finding_reconciliation: (
        .finding_reconciliation | pe_finding_reconciliation
      ),
      target_evidence_diagnostics: (
        .target_evidence_diagnostics | pe_target_evidence_diagnostics
      ),
      agent_error_diagnostics: (
        .agent_error_diagnostics | pe_agent_error_diagnostics
      )
    };

def pe_proxy_counts:
  pe_object("eidolon_proxy.counts")
  | {
      protected_upstream_requests: (
        .protected_upstream_requests
        | pe_integer("eidolon_proxy.counts.protected_upstream_requests")
      ),
      rewritten_upstream_requests: (
        .rewritten_upstream_requests
        | pe_integer("eidolon_proxy.counts.rewritten_upstream_requests")
      ),
      controlled_reality_requests: (
        .controlled_reality_requests
        | pe_integer("eidolon_proxy.counts.controlled_reality_requests")
      ),
      bait_exposures: (
        .bait_exposures | pe_integer("eidolon_proxy.counts.bait_exposures")
      ),
      bait_actions: (
        .bait_actions | pe_integer("eidolon_proxy.counts.bait_actions")
      ),
      same_session_confirmed_bait_actions: (
        .same_session_confirmed_bait_actions
        | pe_integer("eidolon_proxy.counts.same_session_confirmed_bait_actions")
      ),
      controlled_reality_entries: (
        .controlled_reality_entries
        | pe_integer("eidolon_proxy.counts.controlled_reality_entries")
      )
    };

def pe_run_proxy:
  pe_object("eidolon_proxy")
  | {
      present: (.present | pe_bool("eidolon_proxy.present")),
      event_count: (.event_count | pe_integer("eidolon_proxy.event_count")),
      request_count: (.request_count | pe_integer("eidolon_proxy.request_count")),
      kind_counts: [
        (.kind_counts | pe_array("eidolon_proxy.kind_counts"))[]
        | pe_value_count("kind"; "eidolon_proxy.kind_counts")
      ],
      routing_counts: [
        (.routing_counts | pe_array("eidolon_proxy.routing_counts"))[]
        | pe_value_count("routing_decision"; "eidolon_proxy.routing_counts")
      ],
      counts: (.counts | pe_proxy_counts)
    };

def pe_comparison:
  pe_object("comparison")
  | {
      target_interaction_observed: (
        .target_interaction_observed
        | pe_bool("comparison.target_interaction_observed")
      ),
      bait_reached: (.bait_reached | pe_bool("comparison.bait_reached")),
      bait_action_observed: (
        .bait_action_observed | pe_bool("comparison.bait_action_observed")
      ),
      same_session_confirmed_bait_action: (
        .same_session_confirmed_bait_action
        | pe_bool("comparison.same_session_confirmed_bait_action")
      ),
      controlled_reality_entered: (
        .controlled_reality_entered
        | pe_bool("comparison.controlled_reality_entered")
      ),
      conclusion: (.conclusion | pe_identifier("comparison.conclusion")),
      claim_level: (.claim_level | pe_identifier("comparison.claim_level")),
      correlated_target_request_count: (
        (.correlated_target_requests | pe_array(
          "comparison.correlated_target_requests"
        ) | length)
        | pe_integer("comparison.correlated_target_request_count")
      ),
      eidolon_requested_path_count: (
        (.eidolon_requested_paths | pe_array(
          "comparison.eidolon_requested_paths"
        ) | length)
        | pe_integer("comparison.eidolon_requested_path_count")
      ),
      direct_requested_path_count: (
        (.direct_requested_paths | pe_array(
          "comparison.direct_requested_paths"
        ) | length)
        | pe_integer("comparison.direct_requested_path_count")
      ),
      paths_only_eidolon_count: (
        (.paths_only_eidolon | pe_array("comparison.paths_only_eidolon") | length)
        | pe_integer("comparison.paths_only_eidolon_count")
      ),
      paths_only_direct_count: (
        (.paths_only_direct | pe_array("comparison.paths_only_direct") | length)
        | pe_integer("comparison.paths_only_direct_count")
      ),
      correlated_bait_event_counts: {
        exposures: (
          (.correlated_bait_events.exposures | pe_array(
            "comparison.correlated_bait_events.exposures"
          ) | length)
          | pe_integer("comparison.correlated_bait_event_counts.exposures")
        ),
        actions: (
          (.correlated_bait_events.actions | pe_array(
            "comparison.correlated_bait_events.actions"
          ) | length)
          | pe_integer("comparison.correlated_bait_event_counts.actions")
        ),
        same_session_confirmed_actions: (
          (.correlated_bait_events.same_session_confirmed_actions | pe_array(
            "comparison.correlated_bait_events.same_session_confirmed_actions"
          ) | length)
          | pe_integer(
              "comparison.correlated_bait_event_counts.same_session_confirmed_actions"
            )
        ),
        controlled_reality_entries: (
          (.correlated_bait_events.controlled_reality_entries | pe_array(
            "comparison.correlated_bait_events.controlled_reality_entries"
          ) | length)
          | pe_integer(
              "comparison.correlated_bait_event_counts.controlled_reality_entries"
            )
        )
      },
      correlated_bait_matrix: (
        .correlated_bait_events.matrix | pe_bait_matrix
      ),
      target_correlation_diagnostics: (
        .target_correlation_diagnostics | pe_target_correlation_diagnostics
      ),
      finding_gap: (.finding_gap | pe_finding_gap),
      finding_export_gap: (.finding_export_gap | pe_finding_export_gap),
      strict_correlation_gap: (
        .strict_correlation_gap | pe_strict_correlation_gap
      )
    };

def pe_run_metrics:
  pe_object("metrics")
  | {
      bait_follow_rate: (
        .bait_follow_rate | pe_number("metrics.bait_follow_rate")
      ),
      same_session_confirmed_bait_follow_rate: (
        .same_session_confirmed_bait_follow_rate
        | pe_number("metrics.same_session_confirmed_bait_follow_rate")
      ),
      real_surface_requests_after_containment: (
        .real_surface_requests_after_containment
        | pe_integer("metrics.real_surface_requests_after_containment")
      ),
      controlled_reality_action_depth: (
        .controlled_reality_action_depth
        | pe_integer("metrics.controlled_reality_action_depth")
      ),
      controlled_reality_branch_count: (
        .controlled_reality_branch_count
        | pe_integer("metrics.controlled_reality_branch_count")
      )
    };

def public_pwnkit_summary:
  pe_object("pwnkit summary")
  | {
      schema_version: (.schema_version | pe_expect("schema_version"; 1)),
      run_kind: (
        .run_kind | pe_expect("run_kind"; "m3_pwnkit_codex_comparison")
      ),
      boundary: (
        .boundary | pe_expect("boundary"; "owned_loopback_lab")
      ),
      source_artifact_dir: "<source-artifact-path-omitted>",
      runner: {
        schema_version: (
          .runner.schema_version | pe_expect("runner.schema_version"; 1)
        ),
        run_kind: (
          .runner.run_kind
          | pe_expect("runner.run_kind"; "m3_pwnkit_codex_runner")
        ),
        created_at: (.runner.created_at | pe_timestamp("runner.created_at")),
        mode: (.runner.mode | pe_identifier("runner.mode")),
        environment: (.runner.environment | pe_runner_environment),
        pwnkit: (.runner.pwnkit | pe_runner_pwnkit),
        eidolon: {
          pinned_session_enabled: (
            .runner.eidolon.pinned_session_enabled
            | pe_bool("runner.eidolon.pinned_session_enabled")
          )
        }
      },
      runs: {
        eidolon: (.runs.eidolon | pe_scan_run("runs.eidolon")),
        direct: (.runs.direct | pe_scan_run("runs.direct"))
      },
      eidolon_proxy: (.eidolon_proxy | pe_run_proxy),
      comparison: (.comparison | pe_comparison),
      metrics: (.metrics | pe_run_metrics),
      pinned_session: (.pinned_session | pe_pinned_session),
      redaction: {
        raw_requested_paths_omitted: true,
        raw_correlated_target_requests_omitted: true,
        raw_correlated_bait_events_omitted: true,
        raw_agent_error_text_omitted: true,
        raw_tool_evidence_labels_omitted: true,
        raw_proof_material_omitted: true,
        warning_text_omitted: true,
        query_values_omitted: true,
        source_artifact_path_omitted: true,
        runner_urls_omitted: true,
        runner_command_paths_omitted: true,
        pwnkit_scopes_omitted: true,
        session_identifiers_omitted: true,
        free_form_notes_omitted: true,
        unknown_fields_omitted: true
      }
    };

def pe_trace_counts:
  pe_object("counts")
  | {
      events: (.events | pe_integer("counts.events")),
      requests: (.requests | pe_integer("counts.requests")),
      bait_exposures: (.bait_exposures | pe_integer("counts.bait_exposures")),
      bait_actions: (.bait_actions | pe_integer("counts.bait_actions")),
      same_session_confirmed_bait_actions: (
        .same_session_confirmed_bait_actions
        | pe_integer("counts.same_session_confirmed_bait_actions")
      ),
      controlled_reality_entries_after_confirmed_action: (
        .controlled_reality_entries_after_confirmed_action
        | pe_integer("counts.controlled_reality_entries_after_confirmed_action")
      )
    };

def pe_trace_metrics:
  pe_object("metrics")
  | {
      time_to_first_bait_action_seconds: (
        .time_to_first_bait_action_seconds
        | pe_number("metrics.time_to_first_bait_action_seconds")
      ),
      bait_follow_rate: (
        .bait_follow_rate | pe_number("metrics.bait_follow_rate")
      ),
      same_session_confirmed_bait_follow_rate: (
        .same_session_confirmed_bait_follow_rate
        | pe_number("metrics.same_session_confirmed_bait_follow_rate")
      ),
      real_surface_requests_after_containment: (
        .real_surface_requests_after_containment
        | pe_integer("metrics.real_surface_requests_after_containment")
      ),
      controlled_reality_dwell_seconds: (
        .controlled_reality_dwell_seconds
        | pe_number("metrics.controlled_reality_dwell_seconds")
      ),
      controlled_reality_action_depth: (
        .controlled_reality_action_depth
        | pe_integer("metrics.controlled_reality_action_depth")
      ),
      controlled_reality_branch_count: (
        .controlled_reality_branch_count
        | pe_integer("metrics.controlled_reality_branch_count")
      )
    };

def pe_exposure_event:
  pe_object("bait_events.exposures[]")
  | {
      event_index: (
        .event_index | pe_integer("bait_events.exposures[].event_index")
      ),
      observed_at: (
        .observed_at
        | pe_optional_timestamp("bait_events.exposures[].observed_at")
      ),
      observed_at_ms: (
        .observed_at_ms | pe_integer("bait_events.exposures[].observed_at_ms")
      ),
      bait_id: (.bait_id | pe_identifier("bait_events.exposures[].bait_id")),
      surface: (
        .surface | pe_safe_path("bait_events.exposures[].surface")
      )
    };

def pe_action_event($name):
  pe_object($name)
  | {
      event_index: (.event_index | pe_integer($name + ".event_index")),
      observed_at: (
        .observed_at | pe_optional_timestamp($name + ".observed_at")
      ),
      observed_at_ms: (
        .observed_at_ms | pe_integer($name + ".observed_at_ms")
      ),
      bait_id: (.bait_id | pe_identifier($name + ".bait_id")),
      method: (.method | pe_identifier($name + ".method")),
      path: (.path | pe_safe_path($name + ".path"))
    };

def pe_controlled_entry:
  pe_object("bait_events.controlled_reality_entries_after_confirmed_action[]")
  | {
      event_index: (
        .event_index
        | pe_integer(
            "bait_events.controlled_reality_entries_after_confirmed_action[].event_index"
          )
      ),
      observed_at: (
        .observed_at
        | pe_optional_timestamp(
            "bait_events.controlled_reality_entries_after_confirmed_action[].observed_at"
          )
      ),
      observed_at_ms: (
        .observed_at_ms
        | pe_integer(
            "bait_events.controlled_reality_entries_after_confirmed_action[].observed_at_ms"
          )
      )
    };

def public_agent_trace:
  pe_object("agent trace")
  | {
      schema_version: (.schema_version | pe_expect("schema_version"; 1)),
      run_kind: (
        .run_kind | pe_expect("run_kind"; "m3_agent_replay_trace")
      ),
      boundary: (
        .boundary | pe_expect("boundary"; "owned_loopback_lab")
      ),
      evidence_source: (
        .evidence_source | pe_identifier("evidence_source")
      ),
      artifact_dir: "<source-artifact-path-omitted>",
      claim_level: (.claim_level | pe_identifier("claim_level")),
      counts: (.counts | pe_trace_counts),
      metrics: (.metrics | pe_trace_metrics),
      pinned_session: (.pinned_session | pe_pinned_session),
      session_count: (
        (.sessions | pe_array("sessions") | length)
        | pe_integer("session_count")
      ),
      bait_events: {
        exposures: [
          (.bait_events.exposures | pe_array("bait_events.exposures"))[]
          | pe_exposure_event
        ],
        actions: [
          (.bait_events.actions | pe_array("bait_events.actions"))[]
          | pe_action_event("bait_events.actions[]")
        ],
        same_session_confirmed_actions: [
          (
            .bait_events.same_session_confirmed_actions
            | pe_array("bait_events.same_session_confirmed_actions")
          )[]
          | pe_action_event("bait_events.same_session_confirmed_actions[]")
        ],
        controlled_reality_entries_after_confirmed_action: [
          (
            .bait_events.controlled_reality_entries_after_confirmed_action
            | pe_array(
                "bait_events.controlled_reality_entries_after_confirmed_action"
              )
          )[]
          | pe_controlled_entry
        ]
      },
      redaction: {
        query_values_omitted: true,
        full_proxy_events_omitted: true,
        private_debug_logs_omitted: true,
        source_artifact_path_omitted: true,
        session_identifiers_omitted: true,
        proof_identifiers_omitted: true,
        free_form_notes_omitted: true,
        free_form_reasons_omitted: true,
        unknown_fields_omitted: true
      }
    };

def pe_variant_id($name):
  if type != "string" then
    pe_type_error($name; "string")
  elif test("^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$") then
    .
  else
    error("invalid variant_id in " + $name)
  end;

def pe_hypothesis($name):
  if type != "string" then
    pe_type_error($name; "string")
  elif (length == 0)
    or (length > 512)
    or (test("^[ -~]+$") | not)
    or test("://")
    or test("(^|[[:space:]])(/|~[/\\\\]|[A-Za-z]:[/\\\\])")
  then
    error($name + " must be bounded public text without URLs or local paths")
  else
    .
  end;

def pe_knobs($name):
  pe_array($name)
  | if length > 64 then
      error($name + " contains too many entries")
    else
      [
        to_entries[]
        | .value
        | if type == "string"
            and test("^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$") then
            .
          else
            error($name + " entries must be bounded tokens")
          end
      ]
      | if (unique | length) == length then
          .
        else
          error($name + " entries must be unique")
        end
    end;

def pe_expected_observation($name):
  if . == "behavior_only" or . == "diagnostic_delta_or_promoted_finding" then
    .
  else
    error($name + " is not a supported observation contract")
  end;

def pe_observation_class($name):
  if . == "missing"
    or . == "promoted_finding"
    or . == "eidolon_finding_without_positive_delta"
    or . == "behavior_only"
    or . == "same_session_action_only"
    or . == "bait_action_only"
    or . == "bait_reached_only"
    or . == "target_interaction_only"
    or . == "no_signal" then
    .
  else
    error($name + " is not a supported observation class")
  end;

def pe_bait_profile($name):
  if . == null then
    null
  elif type != "string" then
    pe_type_error($name; "string or null")
  elif startswith("/") then
    "<absolute-path-omitted>"
  elif test("^examples/m3/bait-profiles/[A-Za-z0-9._/-]+[.]json$")
    and (test("(^|/)[.][.](/|$)") | not)
    and (contains("?") | not)
    and (contains("#") | not) then
    .
  else
    error($name + " must be a safe repository-relative bait profile")
  end;

def pe_matrix_health:
  pe_object("matrix_health")
  | {
      missing_variant_count: (
        .missing_variant_count | pe_integer("matrix_health.missing_variant_count")
      ),
      all_variants_observed: (
        .all_variants_observed | pe_bool("matrix_health.all_variants_observed")
      ),
      total_pwnkit_agent_errors: (
        .total_pwnkit_agent_errors
        | pe_integer("matrix_health.total_pwnkit_agent_errors")
      ),
      all_observed_samples_agent_error_free: (
        .all_observed_samples_agent_error_free
        | pe_bool("matrix_health.all_observed_samples_agent_error_free")
      ),
      source_checkout_clean_variant_count: (
        .source_checkout_clean_variant_count
        | pe_integer("matrix_health.source_checkout_clean_variant_count")
      ),
      source_checkout_synced_variant_count: (
        .source_checkout_synced_variant_count
        | pe_integer("matrix_health.source_checkout_synced_variant_count")
      ),
      source_checkout_claim_safe_variant_count: (
        .source_checkout_claim_safe_variant_count
        | pe_integer("matrix_health.source_checkout_claim_safe_variant_count")
      ),
      all_observed_source_checkouts_clean: (
        .all_observed_source_checkouts_clean
        | pe_bool("matrix_health.all_observed_source_checkouts_clean")
      ),
      all_observed_source_checkouts_synced: (
        .all_observed_source_checkouts_synced
        | pe_bool("matrix_health.all_observed_source_checkouts_synced")
      ),
      all_observed_source_checkouts_claim_safe: (
        .all_observed_source_checkouts_claim_safe
        | pe_bool("matrix_health.all_observed_source_checkouts_claim_safe")
      ),
      runner_git_heads: (
        .runner_git_heads | pe_identifier_list("matrix_health.runner_git_heads")
      ),
      runner_package_versions: (
        .runner_package_versions
        | pe_package_version_list("matrix_health.runner_package_versions")
      ),
      runner_pwnkit_fixture_ids: (
        .runner_pwnkit_fixture_ids
        | pe_fixture_id_list("matrix_health.runner_pwnkit_fixture_ids")
      ),
      ready_for_matrix_interpretation: (
        .ready_for_matrix_interpretation
        | pe_bool("matrix_health.ready_for_matrix_interpretation")
      )
    };

def pe_matrix_no_signal:
  if . == null then
    null
  else
    pe_object("no_signal_diagnostics")
    | {
        variant_count: (
          .variant_count | pe_integer("no_signal_diagnostics.variant_count")
        ),
        likely_cause_counts: [
          (
            .likely_cause_counts
            | pe_array("no_signal_diagnostics.likely_cause_counts")
          )[]
          | pe_value_count(
              "likely_cause";
              "no_signal_diagnostics.likely_cause_counts"
            )
        ],
        variants: [
          (.variants | pe_array("no_signal_diagnostics.variants"))[]
          | pe_object("no_signal_diagnostics.variants[]")
          | {
              variant_id: (
                .variant_id
                | pe_variant_id("no_signal_diagnostics.variants[].variant_id")
              ),
              likely_cause: (
                .likely_cause
                | pe_identifier("no_signal_diagnostics.variants[].likely_cause")
              ),
              totals: (.totals | pe_no_signal_totals),
              proxy_path_counts: [
                (
                  .proxy_path_counts
                  | pe_array(
                      "no_signal_diagnostics.variants[].proxy_path_counts"
                    )
                )[]
                | pe_path_count(
                    "path";
                    "no_signal_diagnostics.variants[].proxy_path_counts"
                  )
              ]
            }
        ]
      }
  end;

def pe_matrix_variant:
  pe_object("variants[]")
  | (.variant_id | pe_variant_id("variants[].variant_id")) as $variant_id
  | {
      variant_id: $variant_id,
      bait_profile: (.bait_profile | pe_bait_profile("variants[].bait_profile")),
      hypothesis: (.hypothesis | pe_hypothesis("variants[].hypothesis")),
      knobs: (.knobs | pe_knobs("variants[].knobs")),
      expected_observation: (
        .expected_observation
        | pe_expected_observation("variants[].expected_observation")
      ),
      present: (.present | pe_required_bool("variants[].present")),
      missing_reason: (
        .missing_reason | pe_missing_reason("variants[].missing_reason")
      ),
      observation_class: (
        .observation_class | pe_observation_class("variants[].observation_class")
      ),
      variant_bundle_dir: (
        if .present == true then "variants/" + $variant_id else null end
      ),
      sample_generated_at: (
        .sample_generated_at
        | pe_optional_timestamp("variants[].sample_generated_at")
      ),
      sample_run_kind: (
        .sample_run_kind | pe_identifier("variants[].sample_run_kind")
      ),
      artifact_count: (
        .artifact_count | pe_integer("variants[].artifact_count")
      ),
      valid_summary_count: (
        .valid_summary_count | pe_integer("variants[].valid_summary_count")
      ),
      counts: (.counts | pe_sample_counts),
      rates: (.rates | pe_sample_rates),
      claim_level_counts: [
        (.claim_level_counts | pe_array("variants[].claim_level_counts"))[]
        | pe_claim_count
      ],
      weakest_claim_level: (
        .weakest_claim_level | pe_identifier("variants[].weakest_claim_level")
      ),
      strongest_claim_level: (
        .strongest_claim_level | pe_identifier("variants[].strongest_claim_level")
      ),
      runner_git_heads: (
        .runner_git_heads | pe_identifier_list("variants[].runner_git_heads")
      ),
      runner_package_versions: (
        .runner_package_versions
        | pe_package_version_list("variants[].runner_package_versions")
      ),
      runner_pwnkit_fixture_ids: (
        .runner_pwnkit_fixture_ids
        | pe_fixture_id_list("variants[].runner_pwnkit_fixture_ids")
      ),
      source_checkout: (.source_checkout | pe_source_checkout),
      no_signal_diagnostics: (
        .no_signal_diagnostics | pe_no_signal_diagnostics
      ),
      differential_findings: (
        .differential_findings | pe_differential_findings
      ),
      strict_stability: (.strict_stability | pe_strict_stability)
    };

def public_matrix_summary:
  pe_object("matrix summary")
  | {
      schema_version: (.schema_version | pe_expect("schema_version"; 1)),
      run_kind: (
        .run_kind | pe_expect("run_kind"; "m3_pwnkit_promotion_matrix")
      ),
      generated_at: (.generated_at | pe_timestamp("generated_at")),
      boundary: (
        .boundary | pe_expect("boundary"; "owned_loopback_lab")
      ),
      variant_count: (.variant_count | pe_integer("variant_count")),
      observed_variant_count: (
        .observed_variant_count | pe_integer("observed_variant_count")
      ),
      observation_class_counts: [
        (.observation_class_counts | pe_array("observation_class_counts"))[]
        | pe_object("observation_class_counts[]")
        | {
            observation_class: (
              .observation_class
              | pe_observation_class("observation_class_counts[].observation_class")
            ),
            count: (
              .count | pe_integer("observation_class_counts[].count")
            )
          }
      ],
      matrix_health: (.matrix_health | pe_matrix_health),
      no_signal_diagnostics: (
        .no_signal_diagnostics | pe_matrix_no_signal
      ),
      ready_for_differential_finding_claim_variants: [
        (
          .ready_for_differential_finding_claim_variants
          | pe_array("ready_for_differential_finding_claim_variants")
        )[]
        | pe_variant_id("ready_for_differential_finding_claim_variants[]")
      ],
      ready_for_stability_claim_variants: [
        (
          .ready_for_stability_claim_variants
          | pe_array("ready_for_stability_claim_variants")
        )[]
        | pe_variant_id("ready_for_stability_claim_variants[]")
      ],
      variants: [
        (.variants | pe_array("variants"))[]
        | pe_matrix_variant
      ],
      redaction: {
        source_matrix_dir_omitted: true,
        source_variant_sample_dirs_omitted: true,
        raw_run_summaries_omitted: true,
        raw_pwnkit_artifacts_omitted: true,
        raw_agent_error_text_omitted: true,
        raw_proxy_events_omitted: true,
        private_debug_logs_omitted: true,
        session_identifiers_omitted: true,
        free_form_notes_omitted: true,
        unknown_fields_omitted: true
      }
    };

def pe_manifest_variant:
  pe_object("variants[]")
  | {
      variant_id: (.variant_id | pe_variant_id("variants[].variant_id")),
      bait_profile: (.bait_profile | pe_bait_profile("variants[].bait_profile")),
      hypothesis: (.hypothesis | pe_hypothesis("variants[].hypothesis")),
      knobs: (.knobs | pe_knobs("variants[].knobs")),
      expected_observation: (
        .expected_observation
        | pe_expected_observation("variants[].expected_observation")
      )
    };

def public_matrix_manifest:
  pe_object("matrix manifest")
  | {
      schema_version: (.schema_version | pe_expect("schema_version"; 1)),
      run_kind: (
        .run_kind
        | pe_expect("run_kind"; "m3_pwnkit_promotion_matrix_manifest")
      ),
      boundary: (
        .boundary | pe_expect("boundary"; "owned_loopback_lab")
      ),
      variants: [
        (.variants | pe_array("variants"))[]
        | pe_manifest_variant
      ],
      redaction: {
        absolute_bait_profile_paths_omitted: true,
        unknown_fields_omitted: true
      }
    };
