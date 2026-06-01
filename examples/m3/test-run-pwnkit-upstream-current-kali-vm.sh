#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RUNNER="$SCRIPT_DIR/run-pwnkit-upstream-current-kali-vm.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-m3-upstream-current-kali-wrapper-test.XXXXXX"
}

init_fake_pwnkit_repo() {
  local repo_root="$1"

  mkdir -p "$repo_root/dist"
  printf 'console.log("pwnkit");\n' > "$repo_root/dist/pwnkit.js"
  git -C "$repo_root" init -q
  git -C "$repo_root" config user.email test@example.com
  git -C "$repo_root" config user.name "Fixture Test"
  git -C "$repo_root" add dist/pwnkit.js
  git -C "$repo_root" commit -q -m "init fixture"
  git -C "$repo_root" update-ref refs/remotes/origin/main HEAD
  git -C "$repo_root" rev-parse HEAD
}

test_help_mentions_upstream_current_contract() {
  "$RUNNER" --help | rg -q 'upstream-current pwnkit'
  "$RUNNER" --help | rg -q 'EIDOLON_M3_UPSTREAM_CURRENT_REF=origin/main'
  "$RUNNER" --help | rg -q 'EIDOLON_M3_PWNKIT_EVIDENCE_TRACK=upstream_current'
}

test_dry_run_uses_upstream_current_defaults() {
  local repo_root
  local sample_dir

  repo_root="$(new_temp_dir)"
  init_fake_pwnkit_repo "$repo_root" >/dev/null
  sample_dir="$(new_temp_dir)"

  EIDOLON_M3_ALLOW_NON_KALI_VM=1 \
    EIDOLON_M3_KALI_VM_DRY_RUN=1 \
    PWNKIT_SOURCE_DIR="$repo_root" \
    "$RUNNER" 2 "$sample_dir" >/dev/null

  [[ -f "$sample_dir/sample-plan.txt" ]]
  rg -q '^pwnkit_fixture_id=none$' "$sample_dir/sample-plan.txt"
  rg -q '^pwnkit_evidence_track=upstream_current$' "$sample_dir/sample-plan.txt"
  rg -q "^pwnkit_source_dir=$repo_root$" "$sample_dir/sample-plan.txt"
}

test_rejects_dirty_checkout() {
  local repo_root
  local output
  local status=0

  repo_root="$(new_temp_dir)"
  init_fake_pwnkit_repo "$repo_root" >/dev/null
  printf '// dirty\n' >> "$repo_root/dist/pwnkit.js"

  output="$(
    EIDOLON_M3_ALLOW_NON_KALI_VM=1 \
      EIDOLON_M3_KALI_VM_DRY_RUN=1 \
      PWNKIT_SOURCE_DIR="$repo_root" \
      "$RUNNER" 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'upstream-current pwnkit checkout must be clean' <<<"$output"
}

test_rejects_head_mismatch() {
  local repo_root
  local output
  local status=0

  repo_root="$(new_temp_dir)"
  init_fake_pwnkit_repo "$repo_root" >/dev/null
  printf '// second\n' >> "$repo_root/dist/pwnkit.js"
  git -C "$repo_root" add dist/pwnkit.js
  git -C "$repo_root" commit -q -m "drift"

  output="$(
    EIDOLON_M3_ALLOW_NON_KALI_VM=1 \
      EIDOLON_M3_KALI_VM_DRY_RUN=1 \
      PWNKIT_SOURCE_DIR="$repo_root" \
      "$RUNNER" 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'upstream-current pwnkit checkout head mismatch' <<<"$output"
}

test_rejects_fixture_id_override() {
  local repo_root
  local output
  local status=0

  repo_root="$(new_temp_dir)"
  init_fake_pwnkit_repo "$repo_root" >/dev/null

  output="$(
    EIDOLON_M3_ALLOW_NON_KALI_VM=1 \
      EIDOLON_M3_KALI_VM_DRY_RUN=1 \
      EIDOLON_M3_PWNKIT_FIXTURE_ID=local-fixture \
      PWNKIT_SOURCE_DIR="$repo_root" \
      "$RUNNER" 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'EIDOLON_M3_PWNKIT_FIXTURE_ID must be unset' <<<"$output"
}

test_rejects_conflicting_evidence_track() {
  local repo_root
  local output
  local status=0

  repo_root="$(new_temp_dir)"
  init_fake_pwnkit_repo "$repo_root" >/dev/null

  output="$(
    EIDOLON_M3_ALLOW_NON_KALI_VM=1 \
      EIDOLON_M3_KALI_VM_DRY_RUN=1 \
      EIDOLON_M3_PWNKIT_EVIDENCE_TRACK=local_patched_pwnkit \
      PWNKIT_SOURCE_DIR="$repo_root" \
      "$RUNNER" 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'only supports EIDOLON_M3_PWNKIT_EVIDENCE_TRACK=upstream_current' <<<"$output"
}

test_help_mentions_upstream_current_contract
test_dry_run_uses_upstream_current_defaults
test_rejects_dirty_checkout
test_rejects_head_mismatch
test_rejects_fixture_id_override
test_rejects_conflicting_evidence_track

printf 'run-pwnkit-upstream-current-kali-vm fixture tests passed\n'
