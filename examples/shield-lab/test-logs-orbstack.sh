#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
LOGS_SCRIPT="$SCRIPT_DIR/logs-orbstack.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-shield-logs-test.XXXXXX"
}

make_stub_kubectl() {
  local dir="$1"

  cat > "$dir/kubectl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

case "$*" in
  "config current-context")
    printf 'orbstack\n'
    ;;
  *)
    printf 'stub logs for %s\n' "$*"
    ;;
esac
SH

  chmod +x "$dir/kubectl"
}

test_proxy_dry_run_prints_expected_command() {
  local temp_dir
  local output
  temp_dir="$(new_temp_dir)"
  make_stub_kubectl "$temp_dir"

  output="$(
    KUBECTL_BIN="$temp_dir/kubectl" \
      "$LOGS_SCRIPT" proxy --tail 25 --dry-run
  )"

  rg -q '\[proxy\].*-n shield-system logs --tail=25 deploy/eidolon-shield-proxy' <<<"$output"
}

test_all_follow_dry_run_lists_both_streams() {
  local temp_dir
  local output
  temp_dir="$(new_temp_dir)"
  make_stub_kubectl "$temp_dir"

  output="$(
    KUBECTL_BIN="$temp_dir/kubectl" \
      "$LOGS_SCRIPT" all --follow --tail 7 --dry-run
  )"

  rg -q '\[proxy\].*-n shield-system logs -f --tail=7 deploy/eidolon-shield-proxy' <<<"$output"
  rg -q '\[target\].*-n shield-targets logs -f --tail=7 deploy/eidolon-owned-demo-target' <<<"$output"
}

test_invalid_target_is_rejected() {
  local temp_dir
  local output
  local status=0
  temp_dir="$(new_temp_dir)"
  make_stub_kubectl "$temp_dir"

  output="$(
    KUBECTL_BIN="$temp_dir/kubectl" \
      "$LOGS_SCRIPT" bogus --dry-run 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'target must be one of: proxy, target, all' <<<"$output"
}

test_proxy_dry_run_prints_expected_command
test_all_follow_dry_run_lists_both_streams
test_invalid_target_is_rejected

printf 'shield-lab logs checks passed\n'
