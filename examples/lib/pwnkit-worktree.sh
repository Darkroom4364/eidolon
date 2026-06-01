#!/usr/bin/env bash

pwnkit_worktree_is_git_checkout() {
  local repo_dir="$1"

  [[ -d "$repo_dir" ]] || return 1
  git -C "$repo_dir" rev-parse --show-toplevel >/dev/null 2>&1
}

pwnkit_worktree_list_paths() {
  local repo_dir="$1"

  git -C "$repo_dir" worktree list --porcelain 2>/dev/null \
    | sed -n 's/^worktree //p'
}

pwnkit_worktree_find_clean_path_by_head() {
  local repo_dir="$1"
  local target_head="$2"
  local path
  local actual_head
  local status_output

  while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    actual_head="$(git -C "$path" rev-parse HEAD 2>/dev/null || true)"
    [[ "$actual_head" == "$target_head" ]] || continue
    status_output="$(git -C "$path" status --short 2>/dev/null || true)"
    if [[ -z "$status_output" ]]; then
      printf '%s\n' "$path"
      return 0
    fi
  done < <(pwnkit_worktree_list_paths "$repo_dir")

  return 1
}
