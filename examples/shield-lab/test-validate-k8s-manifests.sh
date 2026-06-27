#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
VALIDATE_SCRIPT="$SCRIPT_DIR/validate-k8s-manifests.sh"

output="$("$VALIDATE_SCRIPT")"

rg -q '^validated examples/shield-lab/k8s/base$' <<<"$output"
rg -q '^validated examples/shield-lab/k8s/orbstack$' <<<"$output"
rg -q '^validated examples/shield-lab/k8s/kind$' <<<"$output"

printf 'shield-lab k8s manifest validation checks passed\n'
