#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
RUBY_BIN="${RUBY_BIN:-ruby}"
MANIFEST_PATHS=(
  "examples/shield-lab/k8s/base"
  "examples/shield-lab/k8s/orbstack"
  "examples/shield-lab/k8s/kind"
)

usage() {
  cat <<'USAGE'
Usage: examples/shield-lab/validate-k8s-manifests.sh

Builds the shield-lab base and overlay kustomizations and performs a cluster-free
structural validation pass over the rendered YAML. This validates that each
rendered document parses as Kubernetes-style YAML and includes apiVersion,
kind, and metadata.name.
USAGE
}

fail() {
  echo "error: $*" >&2
  exit 1
}

require_command() {
  local command_name="$1"
  command -v "$command_name" >/dev/null 2>&1 || fail "missing required tool: $command_name"
}

validate_manifest_stream() {
  local manifest_path="$1"
  local rendered_yaml="$2"

  if [[ -z "$rendered_yaml" ]]; then
    fail "${manifest_path} rendered no YAML"
  fi

  printf '%s' "$rendered_yaml" | "$RUBY_BIN" -e '
    require "yaml"

    manifest_path = ARGV.fetch(0)
    raw = STDIN.read
    docs = YAML.load_stream(raw)
    docs.compact!

    abort("error: #{manifest_path} rendered no YAML documents") if docs.empty?

    docs.each_with_index do |doc, index|
      unless doc.is_a?(Hash)
        abort("error: #{manifest_path} document #{index + 1} is not a mapping")
      end

      api_version = doc["apiVersion"]
      kind = doc["kind"]
      metadata = doc["metadata"]
      name = metadata.is_a?(Hash) ? metadata["name"] : nil

      if api_version.to_s.empty? || kind.to_s.empty? || name.to_s.empty?
        abort(
          "error: #{manifest_path} document #{index + 1} is missing apiVersion, kind, or metadata.name"
        )
      end
    end
  ' "$manifest_path"
}

validate_kind_overlay_shape() {
  local rendered_yaml="$1"

  printf '%s' "$rendered_yaml" | "$RUBY_BIN" -e '
    require "yaml"

    docs = YAML.load_stream(STDIN.read)
    docs.compact!

    node_port_services = docs.select do |doc|
      doc.is_a?(Hash) &&
        doc["kind"] == "Service" &&
        doc.dig("spec", "type") == "NodePort"
    end

    unless node_port_services.empty?
      names = node_port_services.map { |doc| doc.dig("metadata", "name") || "<unnamed>" }
      abort("error: kind overlay must not render NodePort services: #{names.join(", ")}")
    end
  '
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

require_command "$KUBECTL_BIN"
require_command "$RUBY_BIN"

cd "$REPO_ROOT"

for manifest_path in "${MANIFEST_PATHS[@]}"; do
  rendered_yaml="$("$KUBECTL_BIN" kustomize "$manifest_path")"
  validate_manifest_stream "$manifest_path" "$rendered_yaml"
  if [[ "$manifest_path" == "examples/shield-lab/k8s/kind" ]]; then
    validate_kind_overlay_shape "$rendered_yaml"
  fi
  echo "validated ${manifest_path}"
done
