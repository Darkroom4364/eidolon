#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RUNNER="$SCRIPT_DIR/run-pwnkit-parity-kali-vm.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-m3-parity-kali-wrapper-test.XXXXXX"
}

init_fake_upstream_repo() {
  local repo_root="$1"

  mkdir -p "$repo_root/dist"
  printf 'console.log("pwnkit");\n' > "$repo_root/dist/pwnkit.js"
  git -C "$repo_root" init -q
  git -C "$repo_root" config user.email test@example.com
  git -C "$repo_root" config user.name "Fixture Test"
  git -C "$repo_root" add dist/pwnkit.js
  git -C "$repo_root" commit -q -m "init fixture"
  git -C "$repo_root" update-ref refs/remotes/origin/main HEAD
}

init_fake_local_patched_repo() {
  local repo_root="$1"

  mkdir -p "$repo_root/dist"
  printf 'console.log("pwnkit");\n' > "$repo_root/dist/pwnkit.js"
  git -C "$repo_root" init -q
  git -C "$repo_root" config user.email test@example.com
  git -C "$repo_root" config user.name "Fixture Test"
  git -C "$repo_root" add dist/pwnkit.js
  git -C "$repo_root" commit -q -m "init fixture"
  git -C "$repo_root" rev-parse HEAD
}

test_help_mentions_summary_output() {
  "$RUNNER" --help | rg -q 'pwnkit-parity-summary.json'
  "$RUNNER" --help | rg -q 'run-pwnkit-upstream-current-kali-vm.sh'
  "$RUNNER" --help | rg -q 'run-pwnkit-local-patched-kali-vm.sh'
}

test_dry_run_creates_subplans_for_both_tracks() {
  local upstream_repo local_repo local_head parity_dir

  upstream_repo="$(new_temp_dir)"
  local_repo="$(new_temp_dir)"
  init_fake_upstream_repo "$upstream_repo"
  local_head="$(init_fake_local_patched_repo "$local_repo")"
  parity_dir="$(new_temp_dir)"

  EIDOLON_M3_ALLOW_NON_KALI_VM=1 \
    EIDOLON_M3_KALI_VM_DRY_RUN=1 \
    EIDOLON_M3_PARITY_UPSTREAM_PWNKIT_SOURCE_DIR="$upstream_repo" \
    EIDOLON_M3_PARITY_LOCAL_PATCHED_PWNKIT_SOURCE_DIR="$local_repo" \
    EIDOLON_M3_LOCAL_PATCHED_PWNKIT_HEAD="$local_head" \
    "$RUNNER" 2 "$parity_dir" >/dev/null

  [[ -f "$parity_dir/parity-plan.txt" ]]
  [[ -f "$parity_dir/upstream-current/sample-plan.txt" ]]
  [[ -f "$parity_dir/local-patched/sample-plan.txt" ]]
  rg -q "^parity_summary=$parity_dir/pwnkit-parity-summary.json$" "$parity_dir/parity-plan.txt"
  rg -q '^pwnkit_evidence_track=upstream_current$' "$parity_dir/upstream-current/sample-plan.txt"
  rg -q '^pwnkit_evidence_track=local_patched_pwnkit$' "$parity_dir/local-patched/sample-plan.txt"
  rg -q "^pwnkit_source_dir=$upstream_repo$" "$parity_dir/upstream-current/sample-plan.txt"
  rg -q "^pwnkit_source_dir=$local_repo$" "$parity_dir/local-patched/sample-plan.txt"
}

test_help_mentions_summary_output
test_dry_run_creates_subplans_for_both_tracks

printf 'run-pwnkit-parity-kali-vm fixture tests passed\n'
