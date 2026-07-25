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
    if [[ "$4" != "secret" || "$5" != "eidolon-trusted-ingress" ]]; then
      exit 1
    fi
    if [[ "${TRUSTED_INGRESS_FETCH_FAILURE:-}" == "1" ]]; then
      exit 1
    fi
    if [[ "${TRUSTED_INGRESS_SECRET_EXISTS:-}" != "1" ]]; then
      exit 0
    fi
    printf '%s\n' "${TRUSTED_INGRESS_RESOURCE_VERSION:-7}"
    printf 'transport-auth.txt\t%s\n' "${TRUSTED_INGRESS_TRANSPORT_DATA:-}"
    if [[ "${TRUSTED_INGRESS_CONTINUITY_PRESENT:-}" == "1" ]]; then
      printf 'continuity-key.txt\t%s\n' "${TRUSTED_INGRESS_CONTINUITY_DATA:-}"
    fi
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
  rg -Fq -- '--from-literal=transport-auth.txt=fixture-secret --from-literal=continuity-key.txt=fixture-secret' \
    "$temp_dir/kubectl.log"
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

test_bootstraps_missing_continuity_key_from_existing_transport_data() {
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
    TRUSTED_INGRESS_SECRET_EXISTS=1 \
    TRUSTED_INGRESS_TRANSPORT_DATA=dHJhbnNwb3J0LWtleQ== \
    EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET=replacement-must-not-be-used \
    EIDOLON_SHIELD_BAIT_PROFILE_PATH="$profile" \
    "$RUNNER" >/dev/null 2>&1

  rg -q 'patch secret eidolon-trusted-ingress --type=json' "$temp_dir/kubectl.log"
  rg -Fq '"op":"test","path":"/metadata/resourceVersion","value":"7"' \
    "$temp_dir/kubectl.log"
  rg -Fq '"op":"test","path":"/data/transport-auth.txt","value":"dHJhbnNwb3J0LWtleQ=="' \
    "$temp_dir/kubectl.log"
  rg -Fq '"op":"add","path":"/data/continuity-key.txt","value":"dHJhbnNwb3J0LWtleQ=="' \
    "$temp_dir/kubectl.log"
  [[ "$(rg -c '^-n shield-system get secret eidolon-trusted-ingress ' \
    "$temp_dir/kubectl.log")" -eq 1 ]]
  rg -q -- '--ignore-not-found -o go-template=' "$temp_dir/kubectl.log"
  ! rg -q 'create secret generic eidolon-trusted-ingress' "$temp_dir/kubectl.log"
  ! rg -q 'replacement-must-not-be-used' "$temp_dir/kubectl.log"
}

test_rejects_trusted_ingress_fetch_failure() {
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
      TRUSTED_INGRESS_FETCH_FAILURE=1 \
      EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET=replacement-must-not-be-used \
      EIDOLON_SHIELD_BAIT_PROFILE_PATH="$profile" \
      "$RUNNER" 2>&1
  )" || status="$?"

  [[ "$status" -eq 1 ]]
  rg -q 'could not read trusted-ingress Secret eidolon-trusted-ingress' <<<"$output"
  [[ "$(rg -c '^-n shield-system get secret eidolon-trusted-ingress ' \
    "$temp_dir/kubectl.log")" -eq 1 ]]
  ! rg -q 'patch secret eidolon-trusted-ingress' "$temp_dir/kubectl.log"
  ! rg -q 'create secret generic eidolon-trusted-ingress' "$temp_dir/kubectl.log"
  ! rg -q 'replacement-must-not-be-used' "$temp_dir/kubectl.log"
}

test_preserves_existing_continuity_key() {
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
    TRUSTED_INGRESS_SECRET_EXISTS=1 \
    TRUSTED_INGRESS_TRANSPORT_DATA=dHJhbnNwb3J0LWtleQ== \
    TRUSTED_INGRESS_CONTINUITY_PRESENT=1 \
    TRUSTED_INGRESS_CONTINUITY_DATA=c3RhYmxlLWNvbnRpbnVpdHkta2V5 \
    EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET=replacement-must-not-be-used \
    EIDOLON_SHIELD_BAIT_PROFILE_PATH="$profile" \
    "$RUNNER" >/dev/null 2>&1

  [[ "$(rg -c '^-n shield-system get secret eidolon-trusted-ingress ' \
    "$temp_dir/kubectl.log")" -eq 1 ]]
  ! rg -q 'patch secret eidolon-trusted-ingress' "$temp_dir/kubectl.log"
  ! rg -q 'create secret generic eidolon-trusted-ingress' "$temp_dir/kubectl.log"
  ! rg -q 'replacement-must-not-be-used' "$temp_dir/kubectl.log"
}

test_rejects_empty_existing_continuity_key() {
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
      TRUSTED_INGRESS_SECRET_EXISTS=1 \
      TRUSTED_INGRESS_TRANSPORT_DATA=dHJhbnNwb3J0LWtleQ== \
      TRUSTED_INGRESS_CONTINUITY_PRESENT=1 \
      EIDOLON_SHIELD_BAIT_PROFILE_PATH="$profile" \
      "$RUNNER" 2>&1
  )" || status="$?"

  [[ "$status" -eq 1 ]]
  rg -q 'trusted-ingress Secret has an empty continuity-key.txt' <<<"$output"
  ! rg -q 'patch secret eidolon-trusted-ingress' "$temp_dir/kubectl.log"
}

test_rejects_legacy_secret_without_transport_data() {
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
      TRUSTED_INGRESS_SECRET_EXISTS=1 \
      EIDOLON_SHIELD_BAIT_PROFILE_PATH="$profile" \
      "$RUNNER" 2>&1
  )" || status="$?"

  [[ "$status" -eq 1 ]]
  rg -q 'trusted-ingress Secret is missing non-empty transport-auth.txt' <<<"$output"
  ! rg -q 'patch secret eidolon-trusted-ingress' "$temp_dir/kubectl.log"
  ! rg -q 'create secret generic eidolon-trusted-ingress' "$temp_dir/kubectl.log"
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
test_bootstraps_missing_continuity_key_from_existing_transport_data
test_preserves_existing_continuity_key
test_rejects_empty_existing_continuity_key
test_rejects_legacy_secret_without_transport_data
test_rejects_trusted_ingress_fetch_failure
test_rejects_missing_bait_profile
test_rejects_missing_ingress_trust_config

printf 'shield-lab deploy fixture tests passed\n'
