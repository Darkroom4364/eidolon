#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RUNNER="$SCRIPT_DIR/deploy-orbstack.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-shield-deploy-test.XXXXXX"
}

make_stub_bin_dir() {
  local dir="$1"

  mkdir -p "$dir"
  cat > "$dir/kubectl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

log_file="${KUBECTL_LOG:?}"
printf '%s\n' "$*" >> "$log_file"

case "$1 $2 ${3:-}" in
  "config current-context ")
    printf 'orbstack\n'
    ;;
  "-n shield-system get")
    exit 1
    ;;
  "-n shield-system create")
    if [[ "$4" == "configmap" ]]; then
      printf 'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: %s\n' "$5"
    fi
    ;;
  "apply -f -")
    cat >/dev/null
    ;;
  "apply -k "*)
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
SH
  chmod +x "$dir/kubectl"

  cat > "$dir/openssl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "$1 ${2:-} ${3:-}" in
  "rand -hex 24")
    printf 'fixture-secret\n'
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

test_uses_explicit_bait_profile_configmap() {
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
      EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET=fixture-secret \
      EIDOLON_SHIELD_BAIT_PROFILE_PATH="$profile" \
      "$RUNNER" 2>&1
  )"

  rg -q "Bait profile:        $(cd "$temp_dir" && pwd -P)/profile.json" <<<"$output"
  rg -q 'Bait profile digest: fixture-digest' <<<"$output"
  rg -q 'create configmap eidolon-shield-bait-profile' "$temp_dir/kubectl.log"
  rg -q 'create configmap eidolon-shield-ingress-trust-config' "$temp_dir/kubectl.log"
  rg -q 'create secret generic eidolon-bait-signing' "$temp_dir/kubectl.log"
  rg -q -- "--from-file=bait-profile.json=$(cd "$temp_dir" && pwd -P)/profile.json" \
    "$temp_dir/kubectl.log"
  rg -q -- '--from-file=ingress-trust.json=.*/examples/shield-lab/ingress-trust-configs/docs-crawler-soften-docs-only.json' \
    "$temp_dir/kubectl.log"
  rg -q 'apply -k .*/examples/shield-lab/k8s/orbstack' "$temp_dir/kubectl.log"
  rg -q 'patch deployment eidolon-shield-proxy' "$temp_dir/kubectl.log"
  rg -q 'eidolon.dev/bait-profile-sha256' "$temp_dir/kubectl.log"
  rg -q 'eidolon.dev/ingress-trust-sha256' "$temp_dir/kubectl.log"
  rg -q 'fixture-digest' "$temp_dir/kubectl.log"
  rg -q 'rollout status deployment/eidolon-shield-proxy' "$temp_dir/kubectl.log"
  rg -q 'Bait signing:        kubectl -n shield-system get secret eidolon-bait-signing' <<<"$output"
  rg -q 'Ingress trust:       .*/examples/shield-lab/ingress-trust-configs/docs-crawler-soften-docs-only.json' <<<"$output"
  rg -q 'Ingress trust digest:fixture-digest' <<<"$output"
  rg -q 'Ingress trust config:kubectl -n shield-system get configmap eidolon-shield-ingress-trust-config' <<<"$output"
}

test_rejects_missing_bait_profile() {
  local temp_dir
  local bin_dir
  local output
  local status=0

  temp_dir="$(new_temp_dir)"
  bin_dir="$temp_dir/bin"
  make_stub_bin_dir "$bin_dir"

  output="$(
    PATH="$bin_dir:$PATH" \
      KUBECTL_LOG="$temp_dir/kubectl.log" \
      EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET=fixture-secret \
      EIDOLON_SHIELD_BAIT_PROFILE_PATH="$temp_dir/missing-profile.json" \
      "$RUNNER" 2>&1
  )" || status="$?"

  [[ "$status" -eq 1 ]]
  rg -q 'bait profile not found:' <<<"$output"
}

test_rejects_missing_ingress_trust_config() {
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
      EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET=fixture-secret \
      EIDOLON_SHIELD_BAIT_PROFILE_PATH="$profile" \
      EIDOLON_SHIELD_INGRESS_TRUST_CONFIG_PATH="$temp_dir/missing-ingress-trust.json" \
      "$RUNNER" 2>&1
  )" || status="$?"

  [[ "$status" -eq 1 ]]
  rg -q 'ingress trust config not found:' <<<"$output"
}

test_uses_explicit_bait_profile_configmap
test_rejects_missing_bait_profile
test_rejects_missing_ingress_trust_config

printf 'shield-lab deploy fixture tests passed\n'
