#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RUNNER="$SCRIPT_DIR/run-pwnkit-local-patched-kali-vm.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-m3-local-patched-kali-wrapper-test.XXXXXX"
}

canonicalize_dir() {
  local dir_path="$1"
  (
    cd "$dir_path"
    pwd -P
  )
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
  git -C "$repo_root" rev-parse HEAD
}

advance_fake_pwnkit_repo() {
  local repo_root="$1"

  printf '// drift\n' >> "$repo_root/dist/pwnkit.js"
  git -C "$repo_root" add dist/pwnkit.js
  git -C "$repo_root" commit -q -m "drift"
}

test_help_mentions_validated_fixture() {
  "$RUNNER" --help | rg -q 'eidolon-m3-local-patched-report-fix-2026-06-01'
  "$RUNNER" --help | rg -q '18c7b3b46f77f9860ed603006a64aed7f8c9475e'
  "$RUNNER" --help | rg -q 'local_patched_pwnkit'
}

test_dry_run_uses_local_patched_defaults() {
  local repo_root
  local head
  local sample_dir

  repo_root="$(new_temp_dir)"
  head="$(init_fake_pwnkit_repo "$repo_root")"
  sample_dir="$(new_temp_dir)"

  EIDOLON_M3_ALLOW_NON_KALI_VM=1 \
    EIDOLON_M3_KALI_VM_DRY_RUN=1 \
    PWNKIT_SOURCE_DIR="$repo_root" \
    EIDOLON_M3_LOCAL_PATCHED_PWNKIT_HEAD="$head" \
    "$RUNNER" 2 "$sample_dir" >/dev/null

  [[ -f "$sample_dir/sample-plan.txt" ]]
  rg -q '^pwnkit_fixture_id=eidolon-m3-local-patched-report-fix-2026-06-01$' "$sample_dir/sample-plan.txt"
  rg -q '^pwnkit_evidence_track=local_patched_pwnkit$' "$sample_dir/sample-plan.txt"
  rg -q "^pwnkit_source_dir=$repo_root$" "$sample_dir/sample-plan.txt"
}

test_rejects_dirty_checkout() {
  local repo_root
  local head
  local output
  local status=0

  repo_root="$(new_temp_dir)"
  head="$(init_fake_pwnkit_repo "$repo_root")"
  printf '// dirty\n' >> "$repo_root/dist/pwnkit.js"

  output="$(
    EIDOLON_M3_ALLOW_NON_KALI_VM=1 \
      EIDOLON_M3_KALI_VM_DRY_RUN=1 \
      PWNKIT_SOURCE_DIR="$repo_root" \
      EIDOLON_M3_LOCAL_PATCHED_PWNKIT_HEAD="$head" \
      "$RUNNER" 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'local patched pwnkit checkout must be clean' <<<"$output"
}

test_rejects_head_mismatch() {
  local repo_root
  local output
  local status=0

  repo_root="$(new_temp_dir)"
  init_fake_pwnkit_repo "$repo_root" >/dev/null

  output="$(
    EIDOLON_M3_ALLOW_NON_KALI_VM=1 \
      EIDOLON_M3_KALI_VM_DRY_RUN=1 \
      PWNKIT_SOURCE_DIR="$repo_root" \
      "$RUNNER" 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'local patched pwnkit checkout head mismatch' <<<"$output"
}

test_rejects_conflicting_evidence_track() {
  local repo_root
  local head
  local output
  local status=0

  repo_root="$(new_temp_dir)"
  head="$(init_fake_pwnkit_repo "$repo_root")"

  output="$(
    EIDOLON_M3_ALLOW_NON_KALI_VM=1 \
      EIDOLON_M3_KALI_VM_DRY_RUN=1 \
      EIDOLON_M3_PWNKIT_EVIDENCE_TRACK=upstream_current \
      PWNKIT_SOURCE_DIR="$repo_root" \
      EIDOLON_M3_LOCAL_PATCHED_PWNKIT_HEAD="$head" \
      "$RUNNER" 1 "$(new_temp_dir)" 2>&1
  )" || status="$?"

  [[ "$status" -eq 2 ]]
  rg -q 'only supports EIDOLON_M3_PWNKIT_EVIDENCE_TRACK=local_patched_pwnkit' <<<"$output"
}

test_accepts_explicit_git_worktree_path() {
  local repo_root
  local head
  local worktree_path
  local sample_dir

  repo_root="$(new_temp_dir)"
  head="$(init_fake_pwnkit_repo "$repo_root")"
  worktree_path="$(new_temp_dir)"
  rm -rf "$worktree_path"
  git -C "$repo_root" worktree add --detach "$worktree_path" "$head" >/dev/null
  sample_dir="$(new_temp_dir)"

  EIDOLON_M3_ALLOW_NON_KALI_VM=1 \
    EIDOLON_M3_KALI_VM_DRY_RUN=1 \
    PWNKIT_SOURCE_DIR="$worktree_path" \
    EIDOLON_M3_LOCAL_PATCHED_PWNKIT_HEAD="$head" \
    "$RUNNER" 1 "$sample_dir" >/dev/null

  rg -q "^pwnkit_source_dir=$worktree_path$" "$sample_dir/sample-plan.txt"
}

test_auto_discovers_matching_worktree() {
  local fake_home
  local repo_root
  local head
  local worktree_path
  local resolved_worktree_path
  local sample_dir

  fake_home="$(new_temp_dir)"
  mkdir -p "$fake_home/Projects"
  repo_root="$fake_home/Projects/pwnkit"
  mkdir -p "$repo_root"
  head="$(init_fake_pwnkit_repo "$repo_root")"
  worktree_path="$fake_home/Projects/pwnkit-local-patched"
  git -C "$repo_root" worktree add --detach "$worktree_path" "$head" >/dev/null
  resolved_worktree_path="$(canonicalize_dir "$worktree_path")"
  advance_fake_pwnkit_repo "$repo_root" >/dev/null
  sample_dir="$(new_temp_dir)"

  HOME="$fake_home" \
    EIDOLON_M3_ALLOW_NON_KALI_VM=1 \
    EIDOLON_M3_KALI_VM_DRY_RUN=1 \
    EIDOLON_M3_LOCAL_PATCHED_PWNKIT_HEAD="$head" \
    "$RUNNER" 1 "$sample_dir" >/dev/null

  rg -q "^pwnkit_source_dir=$resolved_worktree_path$" "$sample_dir/sample-plan.txt"
}

test_help_mentions_validated_fixture
test_dry_run_uses_local_patched_defaults
test_rejects_dirty_checkout
test_rejects_head_mismatch
test_rejects_conflicting_evidence_track
test_accepts_explicit_git_worktree_path
test_auto_discovers_matching_worktree

printf 'run-pwnkit-local-patched-kali-vm fixture tests passed\n'
