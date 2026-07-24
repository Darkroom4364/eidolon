#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi

docker build \
  -f "${repo_root}/examples/shield-lab/Dockerfile.eidolon-proxy" \
  -t eidolon-shield-proxy:local \
  "${repo_root}"
docker build \
  -f "${repo_root}/examples/shield-lab/Dockerfile.demo-target" \
  -t eidolon-owned-demo-target:local \
  "${repo_root}"
docker build \
  -f "${repo_root}/examples/shield-lab/Dockerfile.controlled-reality-backend" \
  -t eidolon-controlled-reality:local \
  "${repo_root}"

printf '%s\n' \
  "Images built:" \
  "  eidolon-shield-proxy:local" \
  "  eidolon-owned-demo-target:local" \
  "  eidolon-controlled-reality:local"
