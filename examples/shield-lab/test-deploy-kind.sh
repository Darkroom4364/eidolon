#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RUNNER="$SCRIPT_DIR/deploy-kind.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-shield-kind-deploy-test.XXXXXX"
}

make_stub_bin_dir() {
  local dir="$1"

  mkdir -p "$dir"
  cat > "$dir/kind" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

log_file="${KIND_LOG:?}"
printf '%s\n' "$*" >> "$log_file"

case "$1 ${2:-}" in
  "get clusters")
    if [[ -n "${KIND_FIXTURE_EXISTING_CLUSTER:-}" ]]; then
      printf '%s\n' "$KIND_FIXTURE_EXISTING_CLUSTER"
    fi
    ;;
  "create cluster")
    ;;
  *)
    ;;
esac
SH
  chmod +x "$dir/kind"

  cat > "$dir/kubectl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

log_file="${KUBECTL_LOG:?}"
printf '%s\n' "$*" >> "$log_file"

case "${1:-} ${2:-} ${3:-}" in
  "config current-context ")
    printf 'kind-eidolon-shield\n'
    ;;
  "-n kube-system get")
    if [[ "${KINDNET_PRESENT:-}" == "1" && "${5:-}" == "kindnet" ]]; then
      exit 0
    fi
    exit 1
    ;;
  "get tigerastatus calico")
    if [[ "${CALICO_PRESENT:-}" == "1" ]]; then
      exit 0
    fi
    exit 1
    ;;
  "-n shield-system get")
    exit 1
    ;;
  "-n shield-controlled-reality get")
    exit 1
    ;;
  "-n shield-system create")
    if [[ "$4" == "configmap" ]]; then
      printf 'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: %s\n' "$5"
    elif [[ "$4" == "secret" && "$*" == *"--dry-run=client"* ]]; then
      printf 'apiVersion: v1\nkind: Secret\nmetadata:\n  name: %s\n' "$6"
    fi
    ;;
  "-n shield-controlled-reality create")
    if [[ "$4" == "secret" && "$*" == *"--dry-run=client"* ]]; then
      printf 'apiVersion: v1\nkind: Secret\nmetadata:\n  name: %s\n' "$6"
    fi
    ;;
  "apply -f -")
    cat >/dev/null
    ;;
  "apply -f "*)
    ;;
  "apply -k "*)
    ;;
  "wait --for=condition=Available")
    ;;
  *)
    ;;
esac

if [[ "$1 ${2:-} ${3:-} ${4:-}" == "-n shield-system patch deployment" ]]; then
  exit 0
fi

if [[ "$1 ${2:-} ${3:-} ${4:-}" == "-n shield-system rollout status" ]]; then
  exit 0
fi

if [[ "$1 ${2:-} ${3:-} ${4:-}" == "-n shield-controlled-reality rollout status" ]]; then
  exit 0
fi
SH
  chmod +x "$dir/kubectl"

  cat > "$dir/openssl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "$1 ${2:-} ${3:-}" in
  "rand -hex 24")
    printf 'fixture-secret\n'
    ;;
  "rand -hex 32")
    printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n'
    ;;
  "dgst -sha256 -r")
    printf 'fixture-digest *%s\n' "$4"
    ;;
  *)
    exit 1
    ;;
esac
SH
  chmod +x "$dir/openssl"
}

test_creates_cluster_when_missing_and_applies_kind_overlay() {
  local temp_dir
  local bin_dir
  local profile
  local output

  temp_dir="$(new_temp_dir)"
  bin_dir="$temp_dir/bin"
  profile="$temp_dir/profile.json"
  make_stub_bin_dir "$bin_dir"
  printf '{"schema_version":1,"profile_id":"fixture"}\n' > "$profile"

  output="$(
    PATH="$bin_dir:$PATH" \
      KUBECTL_LOG="$temp_dir/kubectl.log" \
      KIND_LOG="$temp_dir/kind.log" \
      EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET=fixture-secret \
      EIDOLON_SHIELD_BAIT_PROFILE_PATH="$profile" \
      "$RUNNER" 2>&1
  )"

  rg -q 'get clusters' "$temp_dir/kind.log"
  rg -q 'create cluster --name eidolon-shield --config .*/examples/shield-lab/kind-config.yaml' "$temp_dir/kind.log"
  rg -q 'load docker-image eidolon-shield-proxy:local --name eidolon-shield' "$temp_dir/kind.log"
  rg -q 'load docker-image eidolon-owned-demo-target:local --name eidolon-shield' "$temp_dir/kind.log"
  rg -q 'load docker-image eidolon-controlled-reality:local --name eidolon-shield' "$temp_dir/kind.log"
  rg -q 'apply --server-side -f https://raw.githubusercontent.com/projectcalico/calico/v3.32.1/manifests/operator-crds.yaml' "$temp_dir/kubectl.log"
  rg -q -- '-n shield-system create secret generic eidolon-controlled-reality-auth' "$temp_dir/kubectl.log"
  rg -q -- '-n shield-controlled-reality create secret generic eidolon-controlled-reality-auth' "$temp_dir/kubectl.log"
  rg -q 'apply -k .*/examples/shield-lab/k8s/kind' "$temp_dir/kubectl.log"
  rg -q 'Cluster:             eidolon-shield' <<<"$output"
  rg -q 'Context:             kind-eidolon-shield' <<<"$output"
  rg -q 'Renderer:            kubectl -n shield-controlled-reality get deployment eidolon-controlled-reality' <<<"$output"
  rg -q 'Port forward proxy:  kubectl -n shield-system port-forward svc/eidolon-shield-proxy 9102:9102' <<<"$output"
}

test_skips_cluster_creation_when_kind_cluster_already_exists() {
  local temp_dir
  local bin_dir
  local profile

  temp_dir="$(new_temp_dir)"
  bin_dir="$temp_dir/bin"
  profile="$temp_dir/profile.json"
  make_stub_bin_dir "$bin_dir"
  printf '{"schema_version":1,"profile_id":"fixture"}\n' > "$profile"

  PATH="$bin_dir:$PATH" \
    KUBECTL_LOG="$temp_dir/kubectl.log" \
    KIND_LOG="$temp_dir/kind.log" \
    KIND_FIXTURE_EXISTING_CLUSTER="eidolon-shield" \
    CALICO_PRESENT=1 \
    EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET=fixture-secret \
    EIDOLON_SHIELD_CONTROLLED_REALITY_AUTH_SECRET=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
    EIDOLON_SHIELD_BAIT_PROFILE_PATH="$profile" \
    "$RUNNER" >/dev/null 2>&1

  ! rg -q 'create cluster --name eidolon-shield' "$temp_dir/kind.log"
}

test_rejects_missing_kind_config() {
  local temp_dir
  local bin_dir
  local profile
  local output
  local status=0

  temp_dir="$(new_temp_dir)"
  bin_dir="$temp_dir/bin"
  profile="$temp_dir/profile.json"
  make_stub_bin_dir "$bin_dir"
  printf '{"schema_version":1,"profile_id":"fixture"}\n' > "$profile"

  output="$(
    PATH="$bin_dir:$PATH" \
      KUBECTL_LOG="$temp_dir/kubectl.log" \
      KIND_LOG="$temp_dir/kind.log" \
      EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET=fixture-secret \
      EIDOLON_SHIELD_BAIT_PROFILE_PATH="$profile" \
      EIDOLON_SHIELD_KIND_CONFIG_PATH="$temp_dir/missing-kind-config.yaml" \
      "$RUNNER" 2>&1
  )" || status="$?"

  [[ "$status" -eq 1 ]]
  rg -q 'kind config not found:' <<<"$output"
}

test_rejects_existing_kindnet_cluster() {
  local temp_dir
  local bin_dir
  local profile
  local output
  local status=0

  temp_dir="$(new_temp_dir)"
  bin_dir="$temp_dir/bin"
  profile="$temp_dir/profile.json"
  make_stub_bin_dir "$bin_dir"
  printf '{"schema_version":1,"profile_id":"fixture"}\n' > "$profile"

  output="$(
    PATH="$bin_dir:$PATH" \
      KUBECTL_LOG="$temp_dir/kubectl.log" \
      KIND_LOG="$temp_dir/kind.log" \
      KIND_FIXTURE_EXISTING_CLUSTER="eidolon-shield" \
      KINDNET_PRESENT=1 \
      EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET=fixture-secret \
      EIDOLON_SHIELD_BAIT_PROFILE_PATH="$profile" \
      "$RUNNER" 2>&1
  )" || status="$?"

  [[ "$status" -eq 1 ]]
  rg -q 'kindnet, which does not enforce NetworkPolicy' <<<"$output"
}

test_creates_cluster_when_missing_and_applies_kind_overlay
test_skips_cluster_creation_when_kind_cluster_already_exists
test_rejects_missing_kind_config
test_rejects_existing_kindnet_cluster

printf 'shield-lab kind deploy fixture tests passed\n'
