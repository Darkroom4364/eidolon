#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RUNNER="$SCRIPT_DIR/pwnkit-codex.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-m3-pwnkit-runner-test.XXXXXX"
}

init_fake_pwnkit_checkout() {
  local repo="$1"

  git -C "$repo" init -q
  git -C "$repo" config user.email "eidolon@example.test"
  git -C "$repo" config user.name "Eidolon Test"
  mkdir -p "$repo/dist"

  cat > "$repo/package.json" <<'JSON'
{"name":"pwnkit-cli","version":"9.8.7","type":"module"}
JSON
  cat > "$repo/dist/pwnkit.js" <<'JS'
#!/usr/bin/env node
console.log(JSON.stringify({ findings: [] }));
JS
  chmod +x "$repo/dist/pwnkit.js"

  git -C "$repo" add package.json dist/pwnkit.js
  GIT_AUTHOR_DATE="2026-01-01T00:00:00Z" \
    GIT_COMMITTER_DATE="2026-01-01T00:00:00Z" \
    git -C "$repo" commit -q -m "fixture pwnkit"
  git -C "$repo" update-ref refs/remotes/origin/main HEAD
  touch "$repo/dist/pwnkit.js"
}

test_source_checkout_metadata_records_version_and_origin_sync() {
  local repo
  local artifact
  repo="$(new_temp_dir)"
  artifact="$(new_temp_dir)"
  init_fake_pwnkit_checkout "$repo"

  EIDOLON_LAB_TARGET_URL=http://127.0.0.1:9101 \
    EIDOLON_LAB_PROXY_URL=http://127.0.0.1:9102 \
    PWNKIT_NODE_ENTRY="$repo/dist/pwnkit.js" \
    "$RUNNER" direct "$artifact" >/dev/null

  jq -e '
    .pwnkit.package_version == "9.8.7"
    and (.pwnkit.git_head | type == "string")
    and (.pwnkit.git_head_short | length) == 12
    and .pwnkit.git_dirty == false
    and .pwnkit.origin_main.head == .pwnkit.git_head
    and .pwnkit.origin_main.head_short == .pwnkit.git_head_short
    and .pwnkit.origin_main.ahead == 0
    and .pwnkit.origin_main.behind == 0
    and .pwnkit.origin_main.in_sync == true
  ' "$artifact/pwnkit-runner-metadata.json" >/dev/null
  jq -e '.findings == []' "$artifact/pwnkit-direct.json" >/dev/null
}

test_source_checkout_metadata_records_origin_drift() {
  local repo
  local artifact
  local previous_head
  repo="$(new_temp_dir)"
  artifact="$(new_temp_dir)"
  init_fake_pwnkit_checkout "$repo"
  previous_head="$(git -C "$repo" rev-parse HEAD)"

  printf '\n// local change\n' >> "$repo/dist/pwnkit.js"
  git -C "$repo" add dist/pwnkit.js
  GIT_AUTHOR_DATE="2026-01-02T00:00:00Z" \
    GIT_COMMITTER_DATE="2026-01-02T00:00:00Z" \
    git -C "$repo" commit -q -m "local runner change"
  git -C "$repo" update-ref refs/remotes/origin/main "$previous_head"
  touch "$repo/dist/pwnkit.js"

  EIDOLON_LAB_TARGET_URL=http://127.0.0.1:9101 \
    EIDOLON_LAB_PROXY_URL=http://127.0.0.1:9102 \
    PWNKIT_NODE_ENTRY="$repo/dist/pwnkit.js" \
    "$RUNNER" direct "$artifact" >/dev/null

  jq -e '
    .pwnkit.git_dirty == false
    and .pwnkit.origin_main.ahead == 1
    and .pwnkit.origin_main.behind == 0
    and .pwnkit.origin_main.in_sync == false
  ' "$artifact/pwnkit-runner-metadata.json" >/dev/null
}

test_source_checkout_metadata_records_dirty_worktree() {
  local repo
  local artifact
  repo="$(new_temp_dir)"
  artifact="$(new_temp_dir)"
  init_fake_pwnkit_checkout "$repo"
  printf 'scratch\n' > "$repo/untracked.txt"

  EIDOLON_LAB_TARGET_URL=http://127.0.0.1:9101 \
    EIDOLON_LAB_PROXY_URL=http://127.0.0.1:9102 \
    PWNKIT_NODE_ENTRY="$repo/dist/pwnkit.js" \
    "$RUNNER" direct "$artifact" >/dev/null

  jq -e '.pwnkit.git_dirty == true' "$artifact/pwnkit-runner-metadata.json" >/dev/null
}

test_preflight_writes_metadata_and_scopes_without_scan() {
  local repo
  local artifact
  repo="$(new_temp_dir)"
  artifact="$(new_temp_dir)"
  init_fake_pwnkit_checkout "$repo"

  EIDOLON_LAB_TARGET_URL=http://127.0.0.1:9101 \
    EIDOLON_LAB_PROXY_URL=http://127.0.0.1:9102 \
    PWNKIT_NODE_ENTRY="$repo/dist/pwnkit.js" \
    "$RUNNER" preflight "$artifact" >/dev/null

  [[ -f "$artifact/pwnkit-runner-metadata.json" ]]
  [[ -f "$artifact/pwnkit-eidolon-scope.json" ]]
  [[ -f "$artifact/pwnkit-direct-scope.json" ]]
  [[ ! -f "$artifact/pwnkit-direct.json" ]]
  [[ ! -f "$artifact/pwnkit-eidolon.json" ]]
  jq -e '
    .mode == "preflight"
    and .pwnkit.command_source == "PWNKIT_NODE_ENTRY"
    and .pwnkit.origin_main.in_sync == true
    and .pwnkit.scopes.eidolon.in_scope == ["127.0.0.1"]
    and .pwnkit.scopes.direct.in_scope == ["127.0.0.1"]
  ' "$artifact/pwnkit-runner-metadata.json" >/dev/null
}

test_source_checkout_metadata_records_version_and_origin_sync
test_source_checkout_metadata_records_origin_drift
test_source_checkout_metadata_records_dirty_worktree
test_preflight_writes_metadata_and_scopes_without_scan

printf 'pwnkit-codex runner fixture tests passed\n'
