#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
EVIDENCE_DIR="$REPO_ROOT/docs/evidence/m3"

if ! command -v rg >/dev/null 2>&1; then
  echo "error: missing required tool: rg" >&2
  exit 2
fi

if [[ ! -d "$EVIDENCE_DIR" ]]; then
  echo "error: evidence directory not found: $EVIDENCE_DIR" >&2
  exit 2
fi

if rg -n '"runner_command"|/Users/|/private/tmp|/tmp/eidolon|/tmp/pwnkit|node /tmp|node /Users' "$EVIDENCE_DIR"; then
  echo "error: committed M3 evidence contains local runner paths" >&2
  exit 1
fi

printf 'packaged evidence redaction checks passed\n'
