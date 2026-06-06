#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi

echo "Building eidolon-shield-proxy:local"
docker build \
  -f "${repo_root}/examples/shield-lab/Dockerfile.eidolon-proxy" \
  -t eidolon-shield-proxy:local \
  "${repo_root}"

echo "Building eidolon-owned-demo-target:local"
docker build \
  -f "${repo_root}/examples/shield-lab/Dockerfile.demo-target" \
  -t eidolon-owned-demo-target:local \
  "${repo_root}"

echo "Images built:"
echo "  eidolon-shield-proxy:local"
echo "  eidolon-owned-demo-target:local"
