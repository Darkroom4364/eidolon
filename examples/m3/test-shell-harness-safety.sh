#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-shell-harness-test.XXXXXX"
}

write_fake_curl() {
  local root="$1"
  local bin_dir="$root/bin"

  mkdir -p "$bin_dir"
  cat > "$bin_dir/curl" <<'SH'
#!/usr/bin/env bash
printf '%s' "${EIDOLON_FAKE_CURL_STATUS:-200}"
SH
  chmod +x "$bin_dir/curl"
}

test_baseline_rejects_query_base_url() {
  local output
  local status=0

  output="$(
    EIDOLON_LAB_BASE_URL='http://127.0.0.1:9101?token=secret' \
      "$REPO_ROOT/examples/baselines/benign.sh" curl-like 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'must not include a path, query, or fragment' <<<"$output"
}

test_pwnkit_runner_rejects_query_base_url() {
  local output
  local status=0

  output="$(
    EIDOLON_LAB_TARGET_URL='http://127.0.0.1:9101?token=secret' \
      "$SCRIPT_DIR/pwnkit-codex.sh" preflight "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'must not include a path, query, or fragment' <<<"$output"
}

test_benign_jsonl_is_valid_with_stubbed_curl() {
  local temp_dir
  local output
  temp_dir="$(new_temp_dir)"
  output="$temp_dir/benign.jsonl"
  write_fake_curl "$temp_dir"

  PATH="$temp_dir/bin:$PATH" \
    EIDOLON_LAB_BASE_URL=http://127.0.0.1:9101 \
    "$REPO_ROOT/examples/baselines/benign.sh" curl-like > "$output"

  jq -s -e '
    length == 4
    and all(.[]; .mode == "curl-like" and .status == 200)
  ' "$output" >/dev/null
}

test_defense_jsonl_is_valid_with_stubbed_curl() {
  local temp_dir
  local output
  temp_dir="$(new_temp_dir)"
  output="$temp_dir/defense.jsonl"
  write_fake_curl "$temp_dir"

  PATH="$temp_dir/bin:$PATH" \
    EIDOLON_LAB_BASE_URL=http://127.0.0.1:9101 \
    "$REPO_ROOT/examples/baselines/defense-modes.sh" waf-style-block > "$output"

  jq -s -e '
    length == 4
    and any(.[]; .blocked == true and .status == 403)
    and all(.[]; .baseline_mode == "waf-style-block")
  ' "$output" >/dev/null
}

test_bakeoff_jsonl_escapes_runner_kind() {
  local temp_dir
  local output
  local runner_kind='scripted "probe" \ path'
  temp_dir="$(new_temp_dir)"
  output="$temp_dir/bakeoff.jsonl"
  write_fake_curl "$temp_dir"

  PATH="$temp_dir/bin:$PATH" \
    EIDOLON_LAB_TARGET_URL=http://127.0.0.1:9101 \
    EIDOLON_LAB_PROXY_URL=http://127.0.0.1:9102 \
    EIDOLON_M3_RUNNER_KIND="$runner_kind" \
    "$SCRIPT_DIR/bakeoff.sh" no-defense > "$output"

  jq -s -e --arg runner_kind "$runner_kind" '
    length == 15
    and all(.[]; .runner_kind == $runner_kind and .status == 200)
  ' "$output" >/dev/null
}

test_baseline_rejects_query_base_url
test_pwnkit_runner_rejects_query_base_url
test_benign_jsonl_is_valid_with_stubbed_curl
test_defense_jsonl_is_valid_with_stubbed_curl
test_bakeoff_jsonl_escapes_runner_kind

printf 'shell harness safety fixture tests passed\n'
