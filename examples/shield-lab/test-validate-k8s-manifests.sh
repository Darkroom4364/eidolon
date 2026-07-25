#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
VALIDATE_SCRIPT="$SCRIPT_DIR/validate-k8s-manifests.sh"
REAL_KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
RUBY_BIN="${RUBY_BIN:-ruby}"
REAL_CHMOD_BIN="$(command -v chmod)"

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
  pod_spec = proxy.dig("spec", "template", "spec")
  state_init_containers = pod_spec.fetch("initContainers", [])
  state_init = state_init_containers.find do |item|
    item["name"] == "normalize-eidolon-state"
  end
  abort("state migration init fixture is missing") unless state_init

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
  when "session_signing_key_arg"
    args = proxy.dig("spec", "template", "spec", "containers", 0, "args")
    index = args.index("--session-signing-key-file")
    args.slice!(index, 2)
  when "session_signing_key_path"
    args = proxy.dig("spec", "template", "spec", "containers", 0, "args")
    index = args.index("--session-signing-key-file")
    args[index + 1] = "/tmp/key-ring.json"
  when "session_signing_key_duplicate"
    args = proxy.dig("spec", "template", "spec", "containers", 0, "args")
    args.push("--session-signing-key-file", "/tmp/key-ring.json")
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
  when "session_signing_mount"
    mounts = proxy.dig("spec", "template", "spec", "containers", 0, "volumeMounts")
    mounts.reject! { |item| item["name"] == "eidolon-session-signing" }
  when "session_signing_mount_path"
    mount = proxy.dig("spec", "template", "spec", "containers", 0, "volumeMounts").find do |item|
      item["name"] == "eidolon-session-signing"
    end
    mount["mountPath"] = "/tmp/session-signing"
  when "session_signing_mount_writable"
    mount = proxy.dig("spec", "template", "spec", "containers", 0, "volumeMounts").find do |item|
      item["name"] == "eidolon-session-signing"
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
  when "session_signing_volume"
    volumes = proxy.dig("spec", "template", "spec", "volumes")
    volumes.reject! { |item| item["name"] == "eidolon-session-signing" }
  when "session_signing_secret"
    volume = proxy.dig("spec", "template", "spec", "volumes").find do |item|
      item["name"] == "eidolon-session-signing"
    end
    volume["secret"]["secretName"] = "other-secret"
  when "session_signing_optional"
    volume = proxy.dig("spec", "template", "spec", "volumes").find do |item|
      item["name"] == "eidolon-session-signing"
    end
    volume["secret"]["optional"] = true
  when "session_signing_projection_key"
    volume = proxy.dig("spec", "template", "spec", "volumes").find do |item|
      item["name"] == "eidolon-session-signing"
    end
    volume["secret"]["items"][0]["key"] = "other.json"
  when "session_signing_projection_path"
    volume = proxy.dig("spec", "template", "spec", "volumes").find do |item|
      item["name"] == "eidolon-session-signing"
    end
    volume["secret"]["items"][0]["path"] = "other.json"
  when "state_init_service_account_token"
    pod_spec["automountServiceAccountToken"] = true
  when "state_init_fs_group"
    pod_spec["securityContext"]["fsGroup"] = 0
  when "state_init_missing"
    state_init_containers.reject! { |item| item["name"] == "normalize-eidolon-state" }
  when "state_init_duplicate"
    state_init_containers << Marshal.load(Marshal.dump(state_init))
  when "state_init_image"
    state_init["image"] = "other-image"
  when "state_init_image_pull_policy"
    state_init["imagePullPolicy"] = "Always"
  when "state_init_command"
    state_init["args"] = ["chown -R 65532:65532 /var/lib/eidolon\n"]
  when "state_init_archive_filter"
    state_init["args"][0] = state_init["args"][0].sub(
      "      continue\n",
      "      normalize_state_file \"$archive_path\"\n"
    )
  when "state_init_restart_policy"
    state_init["restartPolicy"] = "Always"
  when "state_init_user"
    state_init["securityContext"]["runAsUser"] = 65532
  when "state_init_group"
    state_init["securityContext"]["runAsGroup"] = 65532
  when "state_init_non_root"
    state_init["securityContext"]["runAsNonRoot"] = true
  when "state_init_rootfs"
    state_init["securityContext"]["readOnlyRootFilesystem"] = false
  when "state_init_escalation"
    state_init["securityContext"]["allowPrivilegeEscalation"] = true
  when "state_init_capabilities"
    state_init["securityContext"]["capabilities"]["add"] = ["CHOWN", "FOWNER"]
  when "state_init_mount_path"
    state_init["volumeMounts"][0]["mountPath"] = "/tmp/eidolon"
  when "state_init_extra_mount"
    state_init["volumeMounts"] << {
      "name" => "eidolon-session-signing",
      "mountPath" => "/var/run/secrets/eidolon-session-signing",
      "readOnly" => true
    }
  when "state_init_env"
    state_init["env"] = [{ "name" => "UNEXPECTED", "value" => "data" }]
  when "state_init_env_from"
    state_init["envFrom"] = [{ "secretRef" => { "name" => "unexpected" } }]
  when "state_init_volume_device"
    state_init["volumeDevices"] = [
      { "name" => "eidolon-state", "devicePath" => "/dev/eidolon-state" }
    ]
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

render_state_init_command_for() {
  local state_dir="$1"

  "$REAL_KUBECTL_BIN" kustomize "$SCRIPT_DIR/k8s/base" | "$RUBY_BIN" -e '
    require "shellwords"
    require "yaml"

    docs = YAML.load_stream(STDIN.read).compact
    proxy = docs.find do |doc|
      doc["kind"] == "Deployment" &&
        doc.dig("metadata", "name") == "eidolon-shield-proxy"
    end
    state_init = proxy.dig("spec", "template", "spec", "initContainers").find do |item|
      item["name"] == "normalize-eidolon-state"
    end
    command = state_init.dig("args", 0)
    prefix = "state_dir=/var/lib/eidolon\n"
    abort("unexpected state init command") unless command.start_with?(prefix)

    STDOUT.write("state_dir=#{Shellwords.escape(ARGV.fetch(0))}\n")
    STDOUT.write(command.delete_prefix(prefix))
  ' "$state_dir"
}

assert_mode() {
  "$RUBY_BIN" -e '
    expected = Integer(ARGV.fetch(1), 8)
    actual = File.stat(ARGV.fetch(0)).mode & 0o777
    abort("unexpected mode for #{ARGV[0]}: #{actual.to_s(8)}") unless actual == expected
  ' "$1" "$2"
}

state_init_bin="$tmp_dir/state-init-bin"
state_init_chown_log="$tmp_dir/state-init-chown.log"
state_init_chmod_log="$tmp_dir/state-init-chmod.log"
mkdir -p "$state_init_bin"
cat >"$state_init_bin/chown" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\t%s\n' "$1" "$2" >>"${STATE_INIT_CHOWN_LOG:?}"
SCRIPT
cat >"$state_init_bin/chmod" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\t%s\n' "$1" "$2" >>"${STATE_INIT_CHMOD_LOG:?}"
exec "${REAL_CHMOD_BIN:?}" "$@"
SCRIPT
"$REAL_CHMOD_BIN" +x "$state_init_bin/chown" "$state_init_bin/chmod"

run_state_init_command() {
  local command
  command="$(render_state_init_command_for "$1")"
  PATH="$state_init_bin:$PATH" \
    STATE_INIT_CHOWN_LOG="$state_init_chown_log" \
    STATE_INIT_CHMOD_LOG="$state_init_chmod_log" \
    REAL_CHMOD_BIN="$REAL_CHMOD_BIN" \
    /bin/sh -ec "$command"
}

state_dir="$tmp_dir/state-init-success"
fixed_state_names=(
  events.jsonl
  events.jsonl.exposures.json
  events.jsonl.exposures.json.tmp
  events.jsonl.consumed-proofs.json
  events.jsonl.consumed-proofs.json.tmp
  debug.jsonl
  policy-state.json
  policy-state.tmp
  policy-state.json.lock
  policy-state.json.continuity.json
  policy-state.json.continuity.json.tmp
  interventions.txt
)
numeric_archive_names=(events.jsonl.0 events.jsonl.123 debug.jsonl.007)
unknown_archive_names=(events.jsonl.1-secret debug.jsonl.2.tmp)
mkdir -p "$state_dir"
for name in "${fixed_state_names[@]}" "${numeric_archive_names[@]}"; do
  printf 'recognized\n' >"$state_dir/$name"
  "$REAL_CHMOD_BIN" 0644 "$state_dir/$name"
done
for name in "${unknown_archive_names[@]}"; do
  printf 'unknown\n' >"$state_dir/$name"
  "$REAL_CHMOD_BIN" 0640 "$state_dir/$name"
done

run_state_init_command "$state_dir"

for name in "${fixed_state_names[@]}" "${numeric_archive_names[@]}"; do
  assert_mode "$state_dir/$name" 0600
  rg -Fq "0:0	$state_dir/$name" "$state_init_chown_log"
  rg -Fq "65532:65532	$state_dir/$name" "$state_init_chown_log"
done
for name in "${unknown_archive_names[@]}"; do
  assert_mode "$state_dir/$name" 0640
  ! rg -Fq "$state_dir/$name" "$state_init_chown_log"
  ! rg -Fq "$state_dir/$name" "$state_init_chmod_log"
done
assert_mode "$state_dir" 0770

assert_state_init_rejects_symlink() {
  local label="$1"
  local name="$2"
  local output
  local status=0
  local symlink_dir="$tmp_dir/state-init-symlink-$label"

  mkdir -p "$symlink_dir"
  ln -s "$symlink_dir/missing-target" "$symlink_dir/$name"
  output="$(run_state_init_command "$symlink_dir" 2>&1)" || status="$?"
  [[ "$status" -ne 0 ]]
  rg -Fq "refusing symlinked Eidolon state path: $symlink_dir/$name" <<<"$output"
}

assert_state_init_rejects_symlink fixed events.jsonl
assert_state_init_rejects_symlink numeric debug.jsonl.9

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

for target in \
  "examples/shield-lab/k8s/base" \
  "examples/shield-lab/k8s/orbstack" \
  "examples/shield-lab/k8s/kind"; do
  assert_rejected \
    "session_signing_key_arg" \
    "proxy must use exactly one mounted session-signing key" \
    "$target"
  assert_rejected \
    "session_signing_key_path" \
    "proxy must use exactly one mounted session-signing key" \
    "$target"
  assert_rejected \
    "session_signing_key_duplicate" \
    "proxy must use exactly one mounted session-signing key" \
    "$target"
  assert_rejected \
    "session_signing_mount" \
    "proxy session-signing Secret must use exactly one read-only mount" \
    "$target"
  assert_rejected \
    "session_signing_mount_path" \
    "proxy session-signing Secret must use exactly one read-only mount" \
    "$target"
  assert_rejected \
    "session_signing_mount_writable" \
    "proxy session-signing Secret must use exactly one read-only mount" \
    "$target"
  assert_rejected \
    "session_signing_volume" \
    "proxy session-signing volume must use exactly one required Secret" \
    "$target"
  assert_rejected \
    "session_signing_secret" \
    "proxy session-signing volume must use exactly one required Secret" \
    "$target"
  assert_rejected \
    "session_signing_optional" \
    "proxy session-signing volume must use exactly one required Secret" \
    "$target"
  assert_rejected \
    "session_signing_projection_key" \
    "proxy session-signing Secret must project key-ring.json" \
    "$target"
  assert_rejected \
    "session_signing_projection_path" \
    "proxy session-signing Secret must project key-ring.json" \
    "$target"
  assert_rejected \
    "state_init_service_account_token" \
    "proxy must disable service-account token mounting" \
    "$target"
  assert_rejected \
    "state_init_fs_group" \
    "proxy must retain fsGroup 65532 for repeat state migration" \
    "$target"
  assert_rejected \
    "state_init_missing" \
    "proxy state migration init container is missing or duplicated" \
    "$target"
  assert_rejected \
    "state_init_duplicate" \
    "proxy state migration init container is missing or duplicated" \
    "$target"
  assert_rejected \
    "state_init_image" \
    "proxy state migration init container must use the proxy image" \
    "$target"
  assert_rejected \
    "state_init_image_pull_policy" \
    "proxy state migration init container must use the proxy image" \
    "$target"
  assert_rejected \
    "state_init_command" \
    "proxy state migration init container must use the exact bounded command" \
    "$target"
  assert_rejected \
    "state_init_archive_filter" \
    "proxy state migration init container must use the exact bounded command" \
    "$target"
  assert_rejected \
    "state_init_restart_policy" \
    "proxy state migration init container must exit before the proxy starts" \
    "$target"
  assert_rejected \
    "state_init_user" \
    "proxy state migration init container must use its exact root exception" \
    "$target"
  assert_rejected \
    "state_init_group" \
    "proxy state migration init container must use its exact root exception" \
    "$target"
  assert_rejected \
    "state_init_non_root" \
    "proxy state migration init container must use its exact root exception" \
    "$target"
  assert_rejected \
    "state_init_rootfs" \
    "proxy state migration init container must use its exact root exception" \
    "$target"
  assert_rejected \
    "state_init_escalation" \
    "proxy state migration init container must use its exact root exception" \
    "$target"
  assert_rejected \
    "state_init_capabilities" \
    "proxy state migration init container must use its exact root exception" \
    "$target"
  assert_rejected \
    "state_init_mount_path" \
    "proxy state migration init container must mount only eidolon-state" \
    "$target"
  assert_rejected \
    "state_init_extra_mount" \
    "proxy state migration init container must mount only eidolon-state" \
    "$target"
  assert_rejected \
    "state_init_env" \
    "proxy state migration init container must not receive environment data" \
    "$target"
  assert_rejected \
    "state_init_env_from" \
    "proxy state migration init container must not receive environment data" \
    "$target"
  assert_rejected \
    "state_init_volume_device" \
    "proxy state migration init container must mount only eidolon-state" \
    "$target"
done

printf 'shield-lab k8s manifest validation checks passed\n'
