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
    fail_with = ->(message) { abort("error: kind overlay #{message}") }
    find_doc = lambda do |kind, name, namespace|
      docs.find do |doc|
        doc.is_a?(Hash) &&
          doc["kind"] == kind &&
          doc.dig("metadata", "name") == name &&
          doc.dig("metadata", "namespace") == namespace
      end
    end
    validate_non_root = lambda do |deployment, label, needs_state_volume|
      pod_spec = deployment&.dig("spec", "template", "spec")
      container = pod_spec&.dig("containers", 0)
      pod_security = pod_spec&.fetch("securityContext", {})
      security = container&.fetch("securityContext", {})

      fail_with.call("#{label} must run as non-root user 65532") unless
        pod_security["runAsNonRoot"] == true &&
        pod_security["runAsUser"] == 65_532 &&
        pod_security["runAsGroup"] == 65_532
      fail_with.call("#{label} must use RuntimeDefault seccomp") unless
        pod_security.dig("seccompProfile", "type") == "RuntimeDefault"
      fail_with.call("#{label} state volume must use fsGroup 65532") if
        needs_state_volume && pod_security["fsGroup"] != 65_532
      fail_with.call("#{label} root filesystem must be read-only") unless
        security["readOnlyRootFilesystem"] == true
      fail_with.call("#{label} privilege escalation must be disabled") unless
        security["allowPrivilegeEscalation"] == false
      fail_with.call("#{label} must drop all capabilities") unless
        security.dig("capabilities", "drop") == ["ALL"]
    end

    node_port_services = docs.select do |doc|
      doc.is_a?(Hash) &&
        doc["kind"] == "Service" &&
        doc.dig("spec", "type") == "NodePort"
    end

    unless node_port_services.empty?
      names = node_port_services.map { |doc| doc.dig("metadata", "name") || "<unnamed>" }
      abort("error: kind overlay must not render NodePort services: #{names.join(", ")}")
    end

    renderer = find_doc.call(
      "Deployment",
      "eidolon-controlled-reality",
      "shield-controlled-reality"
    )
    fail_with.call("must deploy the controlled-reality renderer") unless renderer

    pod_spec = renderer.dig("spec", "template", "spec")
    container = pod_spec&.dig("containers", 0)
    security = container&.fetch("securityContext", {})
    pod_security = pod_spec&.fetch("securityContext", {})
    resources = container&.fetch("resources", {})
    fail_with.call("renderer must disable service-account token mounting") unless pod_spec&.fetch("automountServiceAccountToken", nil) == false
    fail_with.call("renderer must run as non-root user 65532") unless pod_security["runAsNonRoot"] == true && pod_security["runAsUser"] == 65_532
    fail_with.call("renderer must use RuntimeDefault seccomp") unless pod_security.dig("seccompProfile", "type") == "RuntimeDefault"
    fail_with.call("renderer root filesystem must be read-only") unless security["readOnlyRootFilesystem"] == true
    fail_with.call("renderer privilege escalation must be disabled") unless security["allowPrivilegeEscalation"] == false
    fail_with.call("renderer must drop all capabilities") unless security.dig("capabilities", "drop") == ["ALL"]
    %w[cpu memory ephemeral-storage].each do |resource|
      fail_with.call("renderer must set #{resource} requests and limits") unless resources.dig("requests", resource) && resources.dig("limits", resource)
    end
    volumes = pod_spec.fetch("volumes", [])
    fail_with.call("renderer must mount only its dedicated secret") unless volumes.length == 1 && volumes[0].dig("secret", "secretName") == "eidolon-controlled-reality-auth"

    service = find_doc.call(
      "Service",
      "eidolon-controlled-reality",
      "shield-controlled-reality"
    )
    fail_with.call("must expose the renderer only through ClusterIP port 9103") unless service && service.dig("spec", "type") != "NodePort" && service.dig("spec", "ports", 0, "port") == 9103

    proxy = find_doc.call("Deployment", "eidolon-shield-proxy", "shield-system")
    proxy_container = proxy&.dig("spec", "template", "spec", "containers", 0)
    validate_non_root.call(proxy, "proxy", true)
    proxy_args = proxy_container&.fetch("args", []) || []
    renderer_flag = proxy_args.index("--controlled-reality-backend-addr")
    secret_flag = proxy_args.index("--controlled-reality-backend-auth-secret-file")
    fail_with.call("proxy must use renderer Service DNS") unless renderer_flag && proxy_args[renderer_flag + 1] == "eidolon-controlled-reality.shield-controlled-reality.svc.cluster.local:9103"
    fail_with.call("proxy must use the dedicated renderer secret") unless secret_flag && proxy_args[secret_flag + 1] == "/var/run/secrets/eidolon-controlled-reality/auth-secret.txt"
    proxy_volumes = proxy.dig("spec", "template", "spec", "volumes") || []
    fail_with.call("proxy must mount the renderer auth Secret") unless proxy_volumes.any? { |volume| volume.dig("secret", "secretName") == "eidolon-controlled-reality-auth" }

    demo_target = find_doc.call(
      "Deployment",
      "eidolon-owned-demo-target",
      "shield-targets"
    )
    validate_non_root.call(demo_target, "owned demo target", false)

    default_deny = find_doc.call(
      "NetworkPolicy",
      "controlled-reality-default-deny",
      "shield-controlled-reality"
    )
    fail_with.call("must retain namespace-wide ingress and egress default deny") unless default_deny && default_deny.dig("spec", "podSelector") == {} && default_deny.dig("spec", "policyTypes")&.sort == %w[Egress Ingress]

    ingress = find_doc.call(
      "NetworkPolicy",
      "allow-proxy-to-controlled-reality",
      "shield-controlled-reality"
    )
    from = ingress&.dig("spec", "ingress", 0, "from")
    port = ingress&.dig("spec", "ingress", 0, "ports", 0)
    allowed_peer = from&.first
    fail_with.call("renderer ingress must have exactly one combined namespace and pod selector") unless from&.length == 1 &&
      allowed_peer.dig("namespaceSelector", "matchLabels", "kubernetes.io/metadata.name") == "shield-system" &&
      allowed_peer.dig("podSelector", "matchLabels", "app.kubernetes.io/name") == "eidolon-shield-proxy"
    fail_with.call("renderer ingress must allow only TCP port 9103") unless port == { "protocol" => "TCP", "port" => 9103 }
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
