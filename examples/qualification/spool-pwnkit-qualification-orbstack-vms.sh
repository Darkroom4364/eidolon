#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"

SPOOL_PLAN="${1:-${EIDOLON_PWNKIT_VM_SPOOL_PLAN:-}}"
OUTPUT_DIR="${2:-${EIDOLON_PWNKIT_VM_SPOOL_DIR:-/tmp/eidolon-pwnkit-qualification-vm-spool-$(date +%Y%m%d-%H%M%S)}}"
ORBCTL_BIN="${ORBCTL_BIN:-orbctl}"
DRY_RUN="${EIDOLON_PWNKIT_VM_SPOOL_DRY_RUN:-0}"
MACHINE_PREFIX="${EIDOLON_PWNKIT_VM_PREFIX:-eidolon-qual-}"
VM_ARCH="${EIDOLON_PWNKIT_VM_ARCH:-}"
VM_CPUS="${EIDOLON_PWNKIT_VM_CPUS:-2}"
VM_MEMORY="${EIDOLON_PWNKIT_VM_MEMORY:-4G}"
VM_DISK="${EIDOLON_PWNKIT_VM_DISK:-32G}"
HOST_PWNKIT_SOURCE_DIR="${PWNKIT_SOURCE_DIR:-$HOME/Projects/pwnkit}"

usage() {
  cat <<'USAGE'
Usage: examples/qualification/spool-pwnkit-qualification-orbstack-vms.sh <vm-spool-plan.json> [output-dir]

Creates or starts the OrbStack Kali VMs required by a pwnkit qualification
matrix spool plan, then writes host-side helper scripts for running the mapped
qualification wrappers inside each machine.

The input plan should come from:
  examples/qualification/run-pwnkit-qualification-matrix.sh

Outputs:
  <output-dir>/vm-spool-manifest.json
  <output-dir>/README.md
  <output-dir>/cloud-init/<vm-profile>.yaml
  <output-dir>/run-<vm-profile>.sh

Environment:
  ORBCTL_BIN                     orbctl command override. Defaults to orbctl.
  EIDOLON_PWNKIT_VM_SPOOL_DRY_RUN
                                 If true, write manifests and helper scripts
                                 without calling orbctl.
  EIDOLON_PWNKIT_VM_PREFIX       Machine-name prefix. Defaults to eidolon-qual-.
  EIDOLON_PWNKIT_VM_ARCH         Optional OrbStack machine architecture.
  EIDOLON_PWNKIT_VM_CPUS         CPU limit passed to orbctl create. Defaults to 2.
  EIDOLON_PWNKIT_VM_MEMORY       Memory limit passed to orbctl create. Defaults to 4G.
  EIDOLON_PWNKIT_VM_DISK         Disk limit passed to orbctl create. Defaults to 32G.
  PWNKIT_SOURCE_DIR              Host-side pwnkit checkout used in generated
                                 helper scripts. Defaults to ~/Projects/pwnkit.

The generated helper scripts execute the existing Kali wrappers against the
host-mounted Eidolon and pwnkit checkouts through OrbStack:
  - examples/m3/run-pwnkit-kali-vm.sh
  - examples/shield-lab/run-pwnkit-kali-vm.sh
USAGE
}

fail() {
  echo "error: $*" >&2
  exit 2
}

truthy() {
  local value
  value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$value" in
    1|true|yes|on)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    fail "missing required tool: $command_name"
  fi
}

require_nonempty() {
  local name="$1"
  local value="$2"
  [[ -n "$value" ]] || fail "$name must not be empty"
}

host_path_to_linux_mount() {
  local host_path="$1"
  [[ "$host_path" = /* ]] || fail "host path must be absolute: $host_path"
  printf '/mnt/mac%s' "$host_path"
}

validate_spool_plan() {
  [[ -n "$SPOOL_PLAN" ]] || fail "missing vm-spool-plan.json path"
  [[ -f "$SPOOL_PLAN" ]] || fail "vm-spool plan not found: $SPOOL_PLAN"

  jq -e '
    .schema_version == 1
    and .run_kind == "pwnkit_qualification_vm_spool_plan"
    and .boundary == "scanner_qualification"
    and (.vm_profiles | type == "array")
    and (.vm_profiles | all(
      .vm_profile != null
      and (.vm_profile | type == "string")
      and .runner_kinds != null
      and (.runner_kinds | type == "array")
      and .control_kinds != null
      and (.control_kinds | type == "array")
      and .variant_ids != null
      and (.variant_ids | type == "array")
      and .hypothesis_ids != null
      and (.hypothesis_ids | type == "array")
    ))
  ' "$SPOOL_PLAN" >/dev/null || fail "invalid vm-spool plan: $SPOOL_PLAN"
}

vm_profile_machine_suffix() {
  case "$1" in
    kali_vm_same_vm_loopback)
      printf 'kali-loopback'
      ;;
    kali_vm_to_orbstack_nodeport)
      printf 'kali-orbstack'
      ;;
    *)
      fail "unsupported vm_profile: $1"
      ;;
  esac
}

vm_profile_runner_script() {
  case "$1" in
    kali_vm_same_vm_loopback)
      printf 'examples/m3/run-pwnkit-kali-vm.sh'
      ;;
    kali_vm_to_orbstack_nodeport)
      printf 'examples/shield-lab/run-pwnkit-kali-vm.sh'
      ;;
    *)
      fail "unsupported vm_profile: $1"
      ;;
  esac
}

vm_profile_runner_environment() {
  case "$1" in
    kali_vm_same_vm_loopback|kali_vm_to_orbstack_nodeport)
      printf 'kali_vm'
      ;;
    *)
      fail "unsupported vm_profile: $1"
      ;;
  esac
}

vm_profile_network_topology() {
  case "$1" in
    kali_vm_same_vm_loopback)
      printf 'same_vm_loopback'
      ;;
    kali_vm_to_orbstack_nodeport)
      printf 'kali_vm_to_orbstack_nodeport'
      ;;
    *)
      fail "unsupported vm_profile: $1"
      ;;
  esac
}

vm_profile_sample_dir() {
  case "$1" in
    kali_vm_same_vm_loopback)
      printf '/tmp/eidolon-pwnkit-qualification-kali-loopback'
      ;;
    kali_vm_to_orbstack_nodeport)
      printf '/tmp/eidolon-pwnkit-qualification-kali-orbstack'
      ;;
    *)
      fail "unsupported vm_profile: $1"
      ;;
  esac
}

vm_profile_host_prerequisite() {
  case "$1" in
    kali_vm_same_vm_loopback)
      printf 'none'
      ;;
    kali_vm_to_orbstack_nodeport)
      printf 'deploy the Shield lab on the macOS host before running the helper'
      ;;
    *)
      fail "unsupported vm_profile: $1"
      ;;
  esac
}

write_cloud_init() {
  local vm_profile="$1"
  local output_path="$2"

  cat > "$output_path" <<EOF
#cloud-config
package_update: true
packages:
  - git
  - curl
  - jq
  - ripgrep
  - nodejs
  - npm
  - build-essential
runcmd:
  - [ sh, -lc, 'npm install -g pnpm >/var/log/eidolon-pnpm-install.log 2>&1 || true' ]
  - [ sh, -lc, 'mkdir -p ~/Projects' ]
  - [ sh, -lc, 'printf "Eidolon qualification VM profile: ${vm_profile}\n" >/etc/motd' ]
EOF
}

write_run_helper() {
  local vm_profile="$1"
  local machine_name="$2"
  local output_path="$3"
  local runner_script
  local sample_dir
  local linux_repo_root
  local linux_pwnkit_source_dir

  runner_script="$(vm_profile_runner_script "$vm_profile")"
  sample_dir="$(vm_profile_sample_dir "$vm_profile")"
  linux_repo_root="$(host_path_to_linux_mount "$REPO_ROOT")"
  linux_pwnkit_source_dir="$(host_path_to_linux_mount "$HOST_PWNKIT_SOURCE_DIR")"

  cat > "$output_path" <<EOF
#!/usr/bin/env bash
set -euo pipefail

ORBCTL_BIN="\${ORBCTL_BIN:-$ORBCTL_BIN}"
MACHINE_NAME="\${EIDOLON_PWNKIT_VM_MACHINE_NAME:-$machine_name}"
HOST_REPO_ROOT="\${EIDOLON_PWNKIT_VM_HOST_REPO_ROOT:-$REPO_ROOT}"
HOST_PWNKIT_SOURCE_DIR="\${PWNKIT_SOURCE_DIR:-$HOST_PWNKIT_SOURCE_DIR}"
RUN_COUNT="\${1:-1}"
SAMPLE_DIR="\${2:-$sample_dir}"

host_path_to_linux_mount() {
  local host_path="\$1"
  [[ "\$host_path" = /* ]] || {
    echo "error: host path must be absolute: \$host_path" >&2
    exit 2
  }
  printf '/mnt/mac%s' "\$host_path"
}

LINUX_REPO_ROOT="\$(host_path_to_linux_mount "\$HOST_REPO_ROOT")"
LINUX_PWNKIT_SOURCE_DIR="\$(host_path_to_linux_mount "\$HOST_PWNKIT_SOURCE_DIR")"

exec "\$ORBCTL_BIN" run -m "\$MACHINE_NAME" --shell bash -lc \
  "cd \$(printf '%q' \"\$LINUX_REPO_ROOT\") && PWNKIT_SOURCE_DIR=\$(printf '%q' \"\$LINUX_PWNKIT_SOURCE_DIR\") $runner_script \$(printf '%q' \"\$RUN_COUNT\") \$(printf '%q' \"\$SAMPLE_DIR\")"
EOF
  chmod +x "$output_path"
}

machine_exists() {
  local machine_name="$1"
  local name

  if [[ "${EXISTING_MACHINES+set}" != "set" ]]; then
    return 1
  fi
  [[ "${#EXISTING_MACHINES[@]}" -gt 0 ]] || return 1
  for name in "${EXISTING_MACHINES[@]}"; do
    if [[ "$name" == "$machine_name" ]]; then
      return 0
    fi
  done
  return 1
}

load_existing_machines() {
  local machine_name
  EXISTING_MACHINES=()
  while IFS= read -r machine_name; do
    [[ -n "$machine_name" ]] || continue
    EXISTING_MACHINES+=("$machine_name")
  done < <("$ORBCTL_BIN" list -q)
}

create_or_start_machine() {
  local vm_profile="$1"
  local machine_name="$2"
  local cloud_init_path="$3"
  local existed=0
  local created=0

  if machine_exists "$machine_name"; then
    existed=1
  else
    local create_args=(
      create
      --cpus "$VM_CPUS"
      --memory "$VM_MEMORY"
      --disk "$VM_DISK"
      --user-data "$cloud_init_path"
    )
    if [[ -n "$VM_ARCH" ]]; then
      create_args+=(--arch "$VM_ARCH")
    fi
    create_args+=(kali:current "$machine_name")
    "$ORBCTL_BIN" "${create_args[@]}"
    created=1
  fi

  "$ORBCTL_BIN" start "$machine_name"
  printf '%s,%s\n' "$existed" "$created"
}

write_readme() {
  local output_path="$1"
  local manifest_path="$2"
  local host_repo_root="$3"
  local host_pwnkit_source_dir="$4"

  {
    printf '# OrbStack Qualification VM Spool\n\n'
    printf -- '- generated_at_utc: `%s`\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf -- '- spool_plan: `%s`\n' "$SPOOL_PLAN"
    printf -- '- manifest: `%s`\n' "$manifest_path"
    printf -- '- host_repo_root: `%s`\n' "$host_repo_root"
    printf -- '- host_pwnkit_source_dir: `%s`\n\n' "$host_pwnkit_source_dir"
    printf 'This spooler creates or starts the OrbStack Kali machines required by the pwnkit qualification matrix and writes host-side helper scripts for the mapped wrappers.\n\n'
    printf '## Files\n\n'
    printf -- '- `cloud-init/<vm-profile>.yaml`: cloud-init used for first creation.\n'
    printf -- '- `run-<vm-profile>.sh`: host-side helper that runs the mapped qualification wrapper inside the VM through `orbctl run`.\n'
    printf -- '- `vm-spool-manifest.json`: machine mapping, runner commands, and profile metadata.\n'
  } > "$output_path"
}

main() {
  local dry_run_json
  local profile_count
  local profiles_dir
  local manifest_path
  local entry_path
  local readme_path

  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  validate_spool_plan
  require_command jq
  require_command shasum

  mkdir -p "$OUTPUT_DIR/cloud-init" "$OUTPUT_DIR/entries"

  dry_run_json=false
  if truthy "$DRY_RUN"; then
    dry_run_json=true
  else
    require_command "$ORBCTL_BIN"
    load_existing_machines
  fi

  profile_count="$(jq '.vm_profiles | length' "$SPOOL_PLAN")"
  manifest_path="$OUTPUT_DIR/vm-spool-manifest.json"
  readme_path="$OUTPUT_DIR/README.md"
  : > "$manifest_path"

  for ((i = 0; i < profile_count; i += 1)); do
    local vm_profile
    local machine_name
    local cloud_init_path
    local helper_path
    local runner_script
    local runner_environment
    local network_topology
    local sample_dir
    local host_prerequisite
    local existed=0
    local created=0
    local result

    vm_profile="$(jq -r ".vm_profiles[$i].vm_profile" "$SPOOL_PLAN")"
    machine_name="${MACHINE_PREFIX}$(vm_profile_machine_suffix "$vm_profile")"
    cloud_init_path="$OUTPUT_DIR/cloud-init/$vm_profile.yaml"
    helper_path="$OUTPUT_DIR/run-$vm_profile.sh"
    runner_script="$(vm_profile_runner_script "$vm_profile")"
    runner_environment="$(vm_profile_runner_environment "$vm_profile")"
    network_topology="$(vm_profile_network_topology "$vm_profile")"
    sample_dir="$(vm_profile_sample_dir "$vm_profile")"
    host_prerequisite="$(vm_profile_host_prerequisite "$vm_profile")"
    entry_path="$OUTPUT_DIR/entries/$vm_profile.json"

    write_cloud_init "$vm_profile" "$cloud_init_path"
    write_run_helper "$vm_profile" "$machine_name" "$helper_path"

    if ! truthy "$DRY_RUN"; then
      result="$(create_or_start_machine "$vm_profile" "$machine_name" "$cloud_init_path")"
      existed="${result%,*}"
      created="${result#*,}"
    fi

    jq -n \
      --arg vm_profile "$vm_profile" \
      --arg machine_name "$machine_name" \
      --arg distro "kali:current" \
      --arg runner_script "$runner_script" \
      --arg runner_environment "$runner_environment" \
      --arg network_topology "$network_topology" \
      --arg sample_dir "$sample_dir" \
      --arg host_prerequisite "$host_prerequisite" \
      --arg helper_script "$helper_path" \
      --arg cloud_init_path "$cloud_init_path" \
      --arg host_repo_root "$REPO_ROOT" \
      --arg host_pwnkit_source_dir "$HOST_PWNKIT_SOURCE_DIR" \
      --argjson dry_run "$dry_run_json" \
      --argjson existed "$([[ "$existed" == "1" ]] && printf 'true' || printf 'false')" \
      --argjson created "$([[ "$created" == "1" ]] && printf 'true' || printf 'false')" \
      --slurpfile spool "$SPOOL_PLAN" \
      '($spool[0].vm_profiles[] | select(.vm_profile == $vm_profile)) as $profile
      | {
          vm_profile: $vm_profile,
          machine_name: $machine_name,
          distro: $distro,
          dry_run: $dry_run,
          existed: $existed,
          created: $created,
          runner_kinds: $profile.runner_kinds,
          control_kinds: $profile.control_kinds,
          variant_ids: $profile.variant_ids,
          hypothesis_ids: $profile.hypothesis_ids,
          runner_environment: $runner_environment,
          network_topology: $network_topology,
          runner_script: $runner_script,
          sample_dir: $sample_dir,
          host_prerequisite: $host_prerequisite,
          host_repo_root: $host_repo_root,
          host_pwnkit_source_dir: $host_pwnkit_source_dir,
          helper_script: $helper_script,
          cloud_init_path: $cloud_init_path
        }' > "$entry_path"
  done

  jq -s \
    --arg spool_plan "$SPOOL_PLAN" \
    --arg output_dir "$OUTPUT_DIR" \
    --arg host_repo_root "$REPO_ROOT" \
    --arg host_pwnkit_source_dir "$HOST_PWNKIT_SOURCE_DIR" \
    --argjson dry_run "$dry_run_json" \
    '{
      schema_version: 1,
      run_kind: "pwnkit_qualification_orbstack_vm_spool_manifest",
      boundary: "scanner_qualification",
      generated_at: (now | todateiso8601),
      spool_plan: $spool_plan,
      output_dir: $output_dir,
      provider: "orbstack",
      host_repo_root: $host_repo_root,
      host_pwnkit_source_dir: $host_pwnkit_source_dir,
      dry_run: $dry_run,
      profiles: .
    }' "$OUTPUT_DIR"/entries/*.json > "$manifest_path"

  write_readme "$readme_path" "$manifest_path" "$REPO_ROOT" "$HOST_PWNKIT_SOURCE_DIR"

  echo "orbstack qualification VM spool manifest: $manifest_path"
}

main "$@"
