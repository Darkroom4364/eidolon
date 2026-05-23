#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RUNNER="$SCRIPT_DIR/pwnkit-codex.sh"
EIDOLON_M3_TEST_EMPTY_AUTH="$(mktemp "${TMPDIR:-/tmp}/eidolon-m3-empty-codex-auth.XXXXXX")"
export EIDOLON_M3_CODEX_AUTH_FILE="$EIDOLON_M3_TEST_EMPTY_AUTH"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-m3-pwnkit-runner-test.XXXXXX"
}

make_access_token() {
  local exp="$1"

  node -e '
    const exp = Number(process.argv[1]);
    const encode = (value) => Buffer
      .from(JSON.stringify(value))
      .toString("base64url");
    process.stdout.write(`${encode({ alg: "none", typ: "JWT" })}.${encode({ exp })}.signature`);
  ' "$exp"
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

test_auto_loads_fresh_codex_access_token_from_auth_file_without_recording_secret() {
  local repo
  local artifact
  local auth_file
  local access_token
  repo="$(new_temp_dir)"
  artifact="$(new_temp_dir)"
  auth_file="$artifact/codex-auth.json"
  access_token="$(make_access_token "$(( $(date -u '+%s') + 3600 ))")"
  init_fake_pwnkit_checkout "$repo"

  cat > "$repo/dist/pwnkit.js" <<'JS'
#!/usr/bin/env node
if (process.env.PWNKIT_CHATGPT_ACCESS_TOKEN !== process.env.EXPECTED_ACCESS_TOKEN) {
  console.error("missing pwnkit access token");
  process.exit(7);
}
if (process.env.PWNKIT_CHATGPT_ACCOUNT_ID !== "fixture-account-id") {
  console.error("missing pwnkit account id");
  process.exit(7);
}
if (process.env.PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN) {
  console.error("refresh token should not be passed when access token is usable");
  process.exit(7);
}
console.log(JSON.stringify({ findings: [] }));
JS
  chmod +x "$repo/dist/pwnkit.js"
  git -C "$repo" add dist/pwnkit.js
  GIT_AUTHOR_DATE="2026-01-03T00:00:00Z" \
    GIT_COMMITTER_DATE="2026-01-03T00:00:00Z" \
    git -C "$repo" commit -q -m "require codex auth env"
  git -C "$repo" update-ref refs/remotes/origin/main HEAD
  touch "$repo/dist/pwnkit.js"

  jq -n \
    --arg access_token "$access_token" \
    --arg refresh_token "fixture-refresh-token" \
    --arg account_id "fixture-account-id" \
    '{tokens: {
      access_token: $access_token,
      refresh_token: $refresh_token,
      account_id: $account_id
    }}' > "$auth_file"

  env \
    -u PWNKIT_CHATGPT_ACCESS_TOKEN \
    -u PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN \
    EIDOLON_LAB_TARGET_URL=http://127.0.0.1:9101 \
    EIDOLON_LAB_PROXY_URL=http://127.0.0.1:9102 \
    EIDOLON_M3_CODEX_AUTH_FILE="$auth_file" \
    EXPECTED_ACCESS_TOKEN="$access_token" \
    PWNKIT_CHATGPT_ACCOUNT_ID=stale-account-id \
    PWNKIT_NODE_ENTRY="$repo/dist/pwnkit.js" \
    "$RUNNER" direct "$artifact" >/dev/null

  jq -e '
    .pwnkit.codex_auth.source == "codex_auth_file_access_token"
    and .pwnkit.codex_auth.auto_loaded_access_token == true
    and .pwnkit.codex_auth.auto_loaded_refresh_token == false
  ' "$artifact/pwnkit-runner-metadata.json" >/dev/null
  ! rg -q --fixed-strings "$access_token" "$artifact/pwnkit-runner-metadata.json"
  ! rg -q --fixed-strings "$access_token" "$artifact/pwnkit-direct.json"
  ! rg -q --fixed-strings "$access_token" "$artifact/pwnkit-direct.stdout.log"
  ! rg -q --fixed-strings "$access_token" "$artifact/pwnkit-direct.stderr.log"
  ! rg -q 'fixture-account-id' "$artifact/pwnkit-runner-metadata.json"
  ! rg -q 'fixture-account-id' "$artifact/pwnkit-direct.json"
  ! rg -q 'fixture-account-id' "$artifact/pwnkit-direct.stdout.log"
  ! rg -q 'fixture-account-id' "$artifact/pwnkit-direct.stderr.log"
  ! rg -q 'stale-account-id' "$artifact/pwnkit-runner-metadata.json"
  ! rg -q 'stale-account-id' "$artifact/pwnkit-direct.json"
  ! rg -q 'stale-account-id' "$artifact/pwnkit-direct.stdout.log"
  ! rg -q 'stale-account-id' "$artifact/pwnkit-direct.stderr.log"
  ! rg -q 'fixture-refresh-token' "$artifact/pwnkit-runner-metadata.json"
  ! rg -q 'fixture-refresh-token' "$artifact/pwnkit-direct.json"
  ! rg -q 'fixture-refresh-token' "$artifact/pwnkit-direct.stdout.log"
  ! rg -q 'fixture-refresh-token' "$artifact/pwnkit-direct.stderr.log"
}

test_auto_loads_codex_refresh_token_from_auth_file_without_usable_access_token() {
  local repo
  local artifact
  local auth_file
  local access_token
  repo="$(new_temp_dir)"
  artifact="$(new_temp_dir)"
  auth_file="$artifact/codex-auth.json"
  access_token="$(make_access_token "$(( $(date -u '+%s') - 3600 ))")"
  init_fake_pwnkit_checkout "$repo"

  cat > "$repo/dist/pwnkit.js" <<'JS'
#!/usr/bin/env node
if (process.env.PWNKIT_CHATGPT_ACCESS_TOKEN) {
  console.error("access token should not be passed when it is unusable");
  process.exit(7);
}
if (process.env.PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN !== "fixture-refresh-token") {
  console.error("missing pwnkit refresh token");
  process.exit(7);
}
if (Object.prototype.hasOwnProperty.call(process.env, "PWNKIT_CHATGPT_ACCOUNT_ID")) {
  console.error("stale account id should not be passed with refresh fallback");
  process.exit(7);
}
console.log(JSON.stringify({ findings: [] }));
JS
  chmod +x "$repo/dist/pwnkit.js"
  git -C "$repo" add dist/pwnkit.js
  GIT_AUTHOR_DATE="2026-01-04T00:00:00Z" \
    GIT_COMMITTER_DATE="2026-01-04T00:00:00Z" \
    git -C "$repo" commit -q -m "require codex refresh fallback env"
  git -C "$repo" update-ref refs/remotes/origin/main HEAD
  touch "$repo/dist/pwnkit.js"

  jq -n \
    --arg access_token "$access_token" \
    --arg refresh_token "fixture-refresh-token" \
    '{tokens: {
      access_token: $access_token,
      refresh_token: $refresh_token
    }}' > "$auth_file"

  env \
    -u PWNKIT_CHATGPT_ACCESS_TOKEN \
    -u PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN \
    EIDOLON_LAB_TARGET_URL=http://127.0.0.1:9101 \
    EIDOLON_LAB_PROXY_URL=http://127.0.0.1:9102 \
    EIDOLON_M3_CODEX_AUTH_FILE="$auth_file" \
    PWNKIT_CHATGPT_ACCOUNT_ID=stale-account-id \
    PWNKIT_NODE_ENTRY="$repo/dist/pwnkit.js" \
    "$RUNNER" direct "$artifact" >/dev/null

  jq -e '
    .pwnkit.codex_auth.source == "codex_auth_file_refresh_token"
    and .pwnkit.codex_auth.auto_loaded_access_token == false
    and .pwnkit.codex_auth.auto_loaded_refresh_token == true
  ' "$artifact/pwnkit-runner-metadata.json" >/dev/null
  ! rg -q --fixed-strings "$access_token" "$artifact/pwnkit-runner-metadata.json"
  ! rg -q --fixed-strings "$access_token" "$artifact/pwnkit-direct.json"
  ! rg -q --fixed-strings "$access_token" "$artifact/pwnkit-direct.stdout.log"
  ! rg -q --fixed-strings "$access_token" "$artifact/pwnkit-direct.stderr.log"
  ! rg -q 'stale-account-id' "$artifact/pwnkit-runner-metadata.json"
  ! rg -q 'stale-account-id' "$artifact/pwnkit-direct.json"
  ! rg -q 'stale-account-id' "$artifact/pwnkit-direct.stdout.log"
  ! rg -q 'stale-account-id' "$artifact/pwnkit-direct.stderr.log"
  ! rg -q 'fixture-refresh-token' "$artifact/pwnkit-runner-metadata.json"
  ! rg -q 'fixture-refresh-token' "$artifact/pwnkit-direct.json"
  ! rg -q 'fixture-refresh-token' "$artifact/pwnkit-direct.stdout.log"
  ! rg -q 'fixture-refresh-token' "$artifact/pwnkit-direct.stderr.log"
}

test_source_checkout_metadata_records_version_and_origin_sync
test_source_checkout_metadata_records_origin_drift
test_source_checkout_metadata_records_dirty_worktree
test_preflight_writes_metadata_and_scopes_without_scan
test_auto_loads_fresh_codex_access_token_from_auth_file_without_recording_secret
test_auto_loads_codex_refresh_token_from_auth_file_without_usable_access_token

printf 'pwnkit-codex runner fixture tests passed\n'
