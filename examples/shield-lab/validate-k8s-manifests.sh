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
kind, and metadata.name. It also enforces the proxy's single-writer deployment
and PVC-backed policy-state invariants, plus the trusted-ingress continuity-key
mount and persistent session-signing key required for restart-safe identity.
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

validate_proxy_single_writer() {
  local manifest_path="$1"
  local rendered_yaml="$2"

  printf '%s' "$rendered_yaml" | "$RUBY_BIN" -e '
    require "yaml"

    manifest_path = ARGV.fetch(0)
    docs = YAML.load_stream(STDIN.read).compact
    fail_with = ->(message) { abort("error: #{manifest_path} proxy #{message}") }
    find_doc = lambda do |kind, name, namespace|
      docs.find do |doc|
        doc.is_a?(Hash) &&
          doc["kind"] == kind &&
          doc.dig("metadata", "name") == name &&
          doc.dig("metadata", "namespace") == namespace
      end
    end

    proxy = find_doc.call("Deployment", "eidolon-shield-proxy", "shield-system")
    fail_with.call("deployment is missing") unless proxy
    fail_with.call("must use exactly one replica") unless proxy.dig("spec", "replicas") == 1

    strategy = proxy.dig("spec", "strategy")
    fail_with.call("must use Recreate strategy") unless strategy.is_a?(Hash) && strategy["type"] == "Recreate"
    fail_with.call("must not configure rollingUpdate") if strategy.key?("rollingUpdate")

    pod_spec = proxy.dig("spec", "template", "spec")
    container = pod_spec&.fetch("containers", [])&.find { |item| item["name"] == "shield-proxy" }
    fail_with.call("container is missing") unless container
    fail_with.call("must disable service-account token mounting") unless
      pod_spec&.fetch("automountServiceAccountToken", nil) == false
    fail_with.call("must retain fsGroup 65532 for repeat state migration") unless
      pod_spec&.dig("securityContext", "fsGroup") == 65_532

    state_init_containers = pod_spec.fetch("initContainers", []).select do |item|
      item["name"] == "normalize-eidolon-state"
    end
    state_init = state_init_containers.first
    fail_with.call("state migration init container is missing or duplicated") unless
      state_init_containers.length == 1
    fail_with.call("state migration init container must use the proxy image") unless
      state_init&.fetch("image", nil) == container["image"] &&
      state_init&.fetch("imagePullPolicy", nil) == container["imagePullPolicy"]

    expected_state_init_command = [
      "state_dir=/var/lib/eidolon",
      "if [ -L \"$state_dir\" ] || [ ! -d \"$state_dir\" ]; then",
      "  echo \"refusing invalid Eidolon state directory: $state_dir\" >&2",
      "  exit 1",
      "fi",
      "normalize_state_file() {",
      "  if [ -L \"$1\" ]; then",
      "    echo \"refusing symlinked Eidolon state path: $1\" >&2",
      "    exit 1",
      "  fi",
      "  if [ -e \"$1\" ]; then",
      "    [ -f \"$1\" ]",
      "    chown 0:0 \"$1\"",
      "    chmod 0600 \"$1\"",
      "    chown 65532:65532 \"$1\"",
      "  fi",
      "}",
      "for state_path in \\",
      "  \"$state_dir/events.jsonl\" \\",
      "  \"$state_dir/events.jsonl.exposures.json\" \\",
      "  \"$state_dir/events.jsonl.exposures.json.tmp\" \\",
      "  \"$state_dir/events.jsonl.consumed-proofs.json\" \\",
      "  \"$state_dir/events.jsonl.consumed-proofs.json.tmp\" \\",
      "  \"$state_dir/debug.jsonl\" \\",
      "  \"$state_dir/policy-state.json\" \\",
      "  \"$state_dir/policy-state.tmp\" \\",
      "  \"$state_dir/policy-state.json.lock\" \\",
      "  \"$state_dir/policy-state.json.continuity.json\" \\",
      "  \"$state_dir/policy-state.json.continuity.json.tmp\" \\",
      "  \"$state_dir/interventions.txt\"; do",
      "  normalize_state_file \"$state_path\"",
      "done",
      "for archive_path in \"$state_dir\"/events.jsonl.* \"$state_dir\"/debug.jsonl.*; do",
      "  archive_name=${archive_path##*/}",
      "  archive_suffix=${archive_name#*.jsonl.}",
      "  case \"$archive_suffix\" in",
      "    \"\"|*[!0123456789]*)",
      "      continue",
      "      ;;",
      "  esac",
      "  normalize_state_file \"$archive_path\"",
      "done",
      "chown 0:0 \"$state_dir\"",
      "chmod 0770 \"$state_dir\"",
      "chown 65532:65532 \"$state_dir\""
    ].join("\n") + "\n"
    fail_with.call("state migration init container must use the exact bounded command") unless
      state_init&.fetch("command", nil) == ["/bin/sh", "-ec"] &&
      state_init&.fetch("args", nil) == [expected_state_init_command]

    expected_state_init_security = {
      "runAsNonRoot" => false,
      "runAsUser" => 0,
      "runAsGroup" => 0,
      "allowPrivilegeEscalation" => false,
      "readOnlyRootFilesystem" => true,
      "capabilities" => {
        "drop" => ["ALL"],
        "add" => ["CHOWN"]
      }
    }
    fail_with.call("state migration init container must use its exact root exception") unless
      state_init&.fetch("securityContext", nil) == expected_state_init_security
    expected_state_init_mounts = [
      { "name" => "eidolon-state", "mountPath" => "/var/lib/eidolon" }
    ]
    fail_with.call("state migration init container must mount only eidolon-state") unless
      state_init&.fetch("volumeMounts", nil) == expected_state_init_mounts &&
      state_init&.fetch("volumeDevices", []) == []
    fail_with.call("state migration init container must not receive environment data") unless
      state_init&.fetch("env", []) == [] &&
      state_init&.fetch("envFrom", []) == []
    fail_with.call("state migration init container must exit before the proxy starts") if
      state_init&.key?("restartPolicy")

    args = container.fetch("args", [])
    policy_flag = args.index("--policy-state")
    fail_with.call("must use EIDOLON_POLICY_STATE_PATH") unless
      policy_flag && args[policy_flag + 1] == "$(EIDOLON_POLICY_STATE_PATH)"
    continuity_key_flag = args.index("--ingress-continuity-key-file")
    fail_with.call("must use the mounted ingress continuity key") unless
      continuity_key_flag &&
      args[continuity_key_flag + 1] ==
        "/var/run/secrets/eidolon-trusted-ingress/continuity-key.txt"
    session_signing_flags = args.each_index.select do |index|
      args[index] == "--session-signing-key-file"
    end
    session_signing_flag = session_signing_flags.first
    fail_with.call("must use exactly one mounted session-signing key") unless
      session_signing_flags.length == 1 &&
      args[session_signing_flag + 1] ==
        "/var/run/secrets/eidolon-session-signing/key-ring.json"

    env = container.fetch("env", [])
    policy_env = env.find { |item| item["name"] == "EIDOLON_POLICY_STATE_PATH" }
    fail_with.call("must load EIDOLON_POLICY_STATE_PATH from the proxy ConfigMap") unless
      policy_env&.dig("valueFrom", "configMapKeyRef", "name") == "eidolon-shield-proxy-config" &&
      policy_env&.dig("valueFrom", "configMapKeyRef", "key") == "EIDOLON_POLICY_STATE_PATH"

    state_mount = container.fetch("volumeMounts", []).find { |item| item["name"] == "eidolon-state" }
    fail_with.call("state volume must mount at /var/lib/eidolon") unless
      state_mount&.fetch("mountPath", nil) == "/var/lib/eidolon"
    trusted_ingress_mount = container.fetch("volumeMounts", []).find do |item|
      item["name"] == "eidolon-trusted-ingress"
    end
    fail_with.call("trusted-ingress Secret must use its read-only mount") unless
      trusted_ingress_mount&.fetch("mountPath", nil) ==
        "/var/run/secrets/eidolon-trusted-ingress" &&
      trusted_ingress_mount&.fetch("readOnly", nil) == true
    session_signing_mounts = container.fetch("volumeMounts", []).select do |item|
      item["name"] == "eidolon-session-signing"
    end
    session_signing_mount = session_signing_mounts.first
    fail_with.call("session-signing Secret must use exactly one read-only mount") unless
      session_signing_mounts.length == 1 &&
      session_signing_mount&.fetch("mountPath", nil) ==
        "/var/run/secrets/eidolon-session-signing" &&
      session_signing_mount&.fetch("readOnly", nil) == true

    state_volume = pod_spec.fetch("volumes", []).find { |item| item["name"] == "eidolon-state" }
    fail_with.call("state volume must use the supported PVC") unless
      state_volume&.dig("persistentVolumeClaim", "claimName") == "eidolon-shield-proxy-state"
    trusted_ingress_volume = pod_spec.fetch("volumes", []).find do |item|
      item["name"] == "eidolon-trusted-ingress"
    end
    fail_with.call("trusted-ingress volume must use the supported Secret") unless
      trusted_ingress_volume&.dig("secret", "secretName") == "eidolon-trusted-ingress"
    trusted_ingress_items = trusted_ingress_volume&.dig("secret", "items")
    expected_trusted_ingress_items = [
      { "key" => "transport-auth.txt", "path" => "transport-auth.txt" },
      { "key" => "continuity-key.txt", "path" => "continuity-key.txt" }
    ]
    fail_with.call("trusted-ingress Secret must project transport and continuity keys") unless
      trusted_ingress_items == expected_trusted_ingress_items
    session_signing_volumes = pod_spec.fetch("volumes", []).select do |item|
      item["name"] == "eidolon-session-signing"
    end
    session_signing_volume = session_signing_volumes.first
    session_signing_secret = session_signing_volume&.fetch("secret", nil)
    fail_with.call("session-signing volume must use exactly one required Secret") unless
      session_signing_volumes.length == 1 &&
      session_signing_secret&.fetch("secretName", nil) == "eidolon-session-signing" &&
      session_signing_secret&.fetch("optional", false) == false
    expected_session_signing_items = [
      { "key" => "key-ring.json", "path" => "key-ring.json" }
    ]
    fail_with.call("session-signing Secret must project key-ring.json") unless
      session_signing_secret&.fetch("items", nil) == expected_session_signing_items

    config = find_doc.call("ConfigMap", "eidolon-shield-proxy-config", "shield-system")
    expected_state_paths = {
      "EIDOLON_EVENT_LOG_PATH" => "/var/lib/eidolon/events.jsonl",
      "EIDOLON_DEBUG_LOG_PATH" => "/var/lib/eidolon/debug.jsonl",
      "EIDOLON_POLICY_STATE_PATH" => "/var/lib/eidolon/policy-state.json",
      "EIDOLON_INTERVENTION_CONTROL_PATH" => "/var/lib/eidolon/interventions.txt"
    }
    expected_state_paths.each do |key, expected|
      fail_with.call("ConfigMap must keep #{key} on the PVC") unless
        config&.dig("data", key) == expected
    end

    pvc = find_doc.call("PersistentVolumeClaim", "eidolon-shield-proxy-state", "shield-system")
    fail_with.call("state PVC is missing") unless pvc
    fail_with.call("state PVC must remain single-node ReadWriteOnce") unless
      pvc.dig("spec", "accessModes") == ["ReadWriteOnce"]
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
  validate_proxy_single_writer "$manifest_path" "$rendered_yaml"
  if [[ "$manifest_path" == "examples/shield-lab/k8s/kind" ]]; then
    validate_kind_overlay_shape "$rendered_yaml"
  fi
  echo "validated ${manifest_path}"
done
