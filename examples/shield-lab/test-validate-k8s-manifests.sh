#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
VALIDATE_SCRIPT="$SCRIPT_DIR/validate-k8s-manifests.sh"
REAL_KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
RUBY_BIN="${RUBY_BIN:-ruby}"

output="$("$VALIDATE_SCRIPT")"

rg -q '^validated examples/shield-lab/k8s/base$' <<<"$output"
rg -q '^validated examples/shield-lab/k8s/orbstack$' <<<"$output"
rg -q '^validated examples/shield-lab/k8s/kind$' <<<"$output"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
fake_kubectl="$tmp_dir/kubectl"

cat >"$fake_kubectl" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

rendered_yaml="$("$REAL_KUBECTL_BIN" "$@")"
mutation="${EIDOLON_MANIFEST_MUTATION:-}"
mutation_target="${EIDOLON_MANIFEST_MUTATION_TARGET:-}"
manifest_path="${2:-}"

if [[ -z "$mutation" || "$manifest_path" != "$mutation_target" ]]; then
  printf '%s' "$rendered_yaml"
  exit 0
fi

printf '%s' "$rendered_yaml" | "$RUBY_BIN" -e '
  require "yaml"

  mutation = ARGV.fetch(0)
  docs = YAML.load_stream(STDIN.read).compact
  proxy = docs.find do |doc|
    doc["kind"] == "Deployment" &&
      doc.dig("metadata", "name") == "eidolon-shield-proxy" &&
      doc.dig("metadata", "namespace") == "shield-system"
  end
  config = docs.find do |doc|
    doc["kind"] == "ConfigMap" &&
      doc.dig("metadata", "name") == "eidolon-shield-proxy-config" &&
      doc.dig("metadata", "namespace") == "shield-system"
  end
  pvc = docs.find do |doc|
    doc["kind"] == "PersistentVolumeClaim" &&
      doc.dig("metadata", "name") == "eidolon-shield-proxy-state" &&
      doc.dig("metadata", "namespace") == "shield-system"
  end
  abort("proxy fixture is missing") unless proxy && config && pvc

  case mutation
  when "replicas"
    proxy["spec"]["replicas"] = 2
  when "strategy"
    proxy["spec"]["strategy"] = { "type" => "RollingUpdate" }
  when "rolling_update"
    proxy["spec"]["strategy"]["rollingUpdate"] = { "maxSurge" => 1 }
  when "policy_path"
    config["data"]["EIDOLON_POLICY_STATE_PATH"] = "/tmp/policy-state.json"
  when "policy_arg"
    args = proxy.dig("spec", "template", "spec", "containers", 0, "args")
    index = args.index("--policy-state")
    args.slice!(index, 2)
  when "continuity_key_arg"
    args = proxy.dig("spec", "template", "spec", "containers", 0, "args")
    index = args.index("--ingress-continuity-key-file")
    args.slice!(index, 2)
  when "continuity_key_path"
    args = proxy.dig("spec", "template", "spec", "containers", 0, "args")
    index = args.index("--ingress-continuity-key-file")
    args[index + 1] = "/tmp/continuity-key.txt"
  when "policy_env"
    env = proxy.dig("spec", "template", "spec", "containers", 0, "env").find do |item|
      item["name"] == "EIDOLON_POLICY_STATE_PATH"
    end
    env["valueFrom"]["configMapKeyRef"]["name"] = "other-config"
  when "event_path"
    config["data"]["EIDOLON_EVENT_LOG_PATH"] = "/tmp/events.jsonl"
  when "mount_path"
    mount = proxy.dig("spec", "template", "spec", "containers", 0, "volumeMounts").find do |item|
      item["name"] == "eidolon-state"
    end
    mount["mountPath"] = "/tmp/eidolon"
  when "trusted_ingress_mount"
    mount = proxy.dig("spec", "template", "spec", "containers", 0, "volumeMounts").find do |item|
      item["name"] == "eidolon-trusted-ingress"
    end
    mount["readOnly"] = false
  when "trusted_ingress_secret"
    volume = proxy.dig("spec", "template", "spec", "volumes").find do |item|
      item["name"] == "eidolon-trusted-ingress"
    end
    volume["secret"]["secretName"] = "other-secret"
  when "continuity_key_projection"
    volume = proxy.dig("spec", "template", "spec", "volumes").find do |item|
      item["name"] == "eidolon-trusted-ingress"
    end
    volume["secret"]["items"].reject! { |item| item["key"] == "continuity-key.txt" }
  when "wrong_pvc"
    volume = proxy.dig("spec", "template", "spec", "volumes").find do |item|
      item["name"] == "eidolon-state"
    end
    volume["persistentVolumeClaim"]["claimName"] = "other-state"
  when "state_volume"
    volume = proxy.dig("spec", "template", "spec", "volumes").find do |item|
      item["name"] == "eidolon-state"
    end
    volume.delete("persistentVolumeClaim")
    volume["emptyDir"] = {}
  when "pvc_access"
    pvc["spec"]["accessModes"] = ["ReadWriteMany"]
  else
    abort("unknown mutation: #{mutation}")
  end

  docs.each { |doc| STDOUT.write(YAML.dump(doc)) }
' "$mutation"
SCRIPT
chmod +x "$fake_kubectl"

assert_rejected() {
  local mutation="$1"
  local expected="$2"
  local target="${3:-examples/shield-lab/k8s/base}"
  local rejected_output

  if rejected_output="$(
    KUBECTL_BIN="$fake_kubectl" \
      REAL_KUBECTL_BIN="$REAL_KUBECTL_BIN" \
      RUBY_BIN="$RUBY_BIN" \
      EIDOLON_MANIFEST_MUTATION="$mutation" \
      EIDOLON_MANIFEST_MUTATION_TARGET="$target" \
      "$VALIDATE_SCRIPT" 2>&1
  )"; then
    echo "expected manifest mutation '$mutation' to be rejected" >&2
    exit 1
  fi

  rg -Fq "$expected" <<<"$rejected_output" || {
    echo "unexpected rejection for '$mutation': $rejected_output" >&2
    exit 1
  }
}

assert_rejected "replicas" "proxy must use exactly one replica"
assert_rejected "strategy" "proxy must use Recreate strategy"
assert_rejected "strategy" "proxy must use Recreate strategy" "examples/shield-lab/k8s/orbstack"
assert_rejected "strategy" "proxy must use Recreate strategy" "examples/shield-lab/k8s/kind"
assert_rejected "rolling_update" "proxy must not configure rollingUpdate"
assert_rejected "policy_path" "proxy ConfigMap must keep EIDOLON_POLICY_STATE_PATH on the PVC"
assert_rejected "policy_arg" "proxy must use EIDOLON_POLICY_STATE_PATH"
assert_rejected "continuity_key_arg" "proxy must use the mounted ingress continuity key"
assert_rejected "continuity_key_path" "proxy must use the mounted ingress continuity key"
assert_rejected "policy_env" "proxy must load EIDOLON_POLICY_STATE_PATH from the proxy ConfigMap"
assert_rejected "event_path" "proxy ConfigMap must keep EIDOLON_EVENT_LOG_PATH on the PVC"
assert_rejected "mount_path" "proxy state volume must mount at /var/lib/eidolon"
assert_rejected "trusted_ingress_mount" "proxy trusted-ingress Secret must use its read-only mount"
assert_rejected "trusted_ingress_secret" "proxy trusted-ingress volume must use the supported Secret"
assert_rejected "continuity_key_projection" "proxy trusted-ingress Secret must project transport and continuity keys"
assert_rejected "wrong_pvc" "proxy state volume must use the supported PVC"
assert_rejected "state_volume" "proxy state volume must use the supported PVC"
assert_rejected "pvc_access" "proxy state PVC must remain single-node ReadWriteOnce"

printf 'shield-lab k8s manifest validation checks passed\n'
