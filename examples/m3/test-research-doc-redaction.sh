#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"

if ! command -v rg >/dev/null 2>&1; then
  echo "error: missing required tool: rg" >&2
  exit 2
fi

docs=(
  "$REPO_ROOT/docs/research-note-m3.md"
  "$REPO_ROOT/docs/research-report-m3.md"
)

if rg -n '/Users/|/private/tmp|node /Users|node /tmp|artifact directory: `/tmp' -- "${docs[@]}"; then
  echo "error: M3 research docs contain local runner or artifact paths" >&2
  exit 1
fi

printf 'M3 research doc redaction checks passed\n'
