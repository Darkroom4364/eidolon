#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
python_bin="${PYTHON_BIN:-python3}"
trusted_ingress_secret_name="${EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET_NAME:-eidolon-trusted-ingress}"
trusted_ingress_secret_key="${EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET_KEY:-transport-auth.txt}"
trusted_ingress_continuity_key="continuity-key.txt"
trusted_ingress_secret_literal="${EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET:-}"
bait_signing_secret_name="${EIDOLON_SHIELD_BAIT_SIGNING_SECRET_NAME:-eidolon-bait-signing}"
bait_signing_secret_key="${EIDOLON_SHIELD_BAIT_SIGNING_SECRET_KEY:-signing-secret.txt}"
bait_signing_secret_literal="${EIDOLON_SHIELD_BAIT_SIGNING_SECRET:-}"
session_signing_secret_name="eidolon-session-signing"
session_signing_secret_key="key-ring.json"
session_signing_key_hex="${EIDOLON_SHIELD_SESSION_SIGNING_KEY_HEX:-}"
session_signing_validator="${script_dir}/validate-session-key-file.py"
bait_profile_configmap_name="eidolon-shield-bait-profile"
bait_profile_key="bait-profile.json"
bait_profile_rollout_annotation="eidolon.dev/bait-profile-sha256"
bait_profile_path="${EIDOLON_SHIELD_BAIT_PROFILE_PATH:-${repo_root}/examples/shield-lab/bait-profiles/default-m3-catalog.json}"
bait_profile_sha256=""
ingress_trust_configmap_name="eidolon-shield-ingress-trust-config"
ingress_trust_config_key="ingress-trust.json"
ingress_trust_rollout_annotation="eidolon.dev/ingress-trust-sha256"
ingress_trust_config_path="${EIDOLON_SHIELD_INGRESS_TRUST_CONFIG_PATH:-${repo_root}/examples/shield-lab/ingress-trust-configs/docs-crawler-soften-docs-only.json}"
ingress_trust_config_sha256=""

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "$command_name is required" >&2
    exit 1
  fi
}

canonical_file_path() {
  local path="$1"
  local dir
  local base

  dir="$(dirname "$path")"
  base="$(basename "$path")"
  (
    cd "$dir"
    printf '%s/%s' "$(pwd -P)" "$base"
  )
}

compute_file_sha256() {
  local path="$1"
  local digest

  require_command openssl
  digest="$(openssl dgst -sha256 -r "$path")"
  printf '%s' "${digest%% *}"
}

resolve_bait_profile_path() {
  if [[ ! -f "$bait_profile_path" ]]; then
    echo "bait profile not found: ${bait_profile_path}" >&2
    exit 1
  fi

  bait_profile_path="$(canonical_file_path "$bait_profile_path")"
  bait_profile_sha256="$(compute_file_sha256 "$bait_profile_path")"
}

resolve_ingress_trust_config_path() {
  if [[ ! -f "$ingress_trust_config_path" ]]; then
    echo "ingress trust config not found: ${ingress_trust_config_path}" >&2
    exit 1
  fi

  ingress_trust_config_path="$(canonical_file_path "$ingress_trust_config_path")"
  ingress_trust_config_sha256="$(compute_file_sha256 "$ingress_trust_config_path")"
}

generate_secret_value() {
  local explicit_literal="$1"

  if [[ -n "$explicit_literal" ]]; then
    printf '%s' "$explicit_literal"
    return
  fi

  require_command openssl
  openssl rand -hex 24
}

ensure_secret() {
  local secret_name="$1"
  local secret_key="$2"
  local secret_literal="$3"
  local secret_value

  if kubectl -n shield-system get secret "$secret_name" >/dev/null 2>&1; then
    return
  fi

  secret_value="$(generate_secret_value "$secret_literal")"
  kubectl -n shield-system create secret generic "$secret_name" \
    --from-literal="${secret_key}=${secret_value}" >/dev/null
}

json_pointer_escape() {
  local value="$1"

  value="${value//\~/~0}"
  value="${value//\//~1}"
  printf '%s' "$value"
}

ensure_trusted_ingress_secret() {
  local continuity_data=""
  local continuity_present=0
  local data_key
  local data_line
  local data_value
  local resource_version
  local secret_data=""
  local secret_snapshot
  local secret_value
  local transport_data=""
  local transport_present=0
  local transport_key_pointer

  if ! secret_snapshot="$(
    kubectl -n shield-system get secret "$trusted_ingress_secret_name" \
      --ignore-not-found \
      -o 'go-template={{.metadata.resourceVersion}}{{"\n"}}{{range $key, $value := .data}}{{printf "%s\t%s\n" $key $value}}{{end}}'
  )"; then
    echo "could not read trusted-ingress Secret ${trusted_ingress_secret_name}" >&2
    exit 1
  fi

  if [[ -z "$secret_snapshot" ]]; then
    secret_value="$(generate_secret_value "$trusted_ingress_secret_literal")"
    kubectl -n shield-system create secret generic "$trusted_ingress_secret_name" \
      --from-literal="${trusted_ingress_secret_key}=${secret_value}" \
      --from-literal="${trusted_ingress_continuity_key}=${secret_value}" >/dev/null
    return
  fi

  resource_version="${secret_snapshot%%$'\n'*}"
  if [[ -z "$resource_version" ]]; then
    echo "trusted-ingress Secret has no resourceVersion" >&2
    exit 1
  fi

  if [[ "$secret_snapshot" == *$'\n'* ]]; then
    secret_data="${secret_snapshot#*$'\n'}"
  fi
  while IFS= read -r data_line; do
    [[ -z "$data_line" ]] && continue
    if [[ "$data_line" != *$'\t'* ]]; then
      echo "trusted-ingress Secret returned malformed data" >&2
      exit 1
    fi
    data_key="${data_line%%$'\t'*}"
    data_value="${data_line#*$'\t'}"
    case "$data_key" in
      "$trusted_ingress_secret_key")
        transport_present=1
        transport_data="$data_value"
        ;;
      "$trusted_ingress_continuity_key")
        continuity_present=1
        continuity_data="$data_value"
        ;;
    esac
  done <<<"$secret_data"

  if [[ "$transport_present" != "1" || -z "$transport_data" ]]; then
    echo "trusted-ingress Secret is missing non-empty ${trusted_ingress_secret_key}" >&2
    exit 1
  fi

  if [[ "$continuity_present" == "1" ]]; then
    if [[ -z "$continuity_data" ]]; then
      echo "trusted-ingress Secret has an empty ${trusted_ingress_continuity_key}" >&2
      exit 1
    fi
    return
  fi

  transport_key_pointer="$(json_pointer_escape "$trusted_ingress_secret_key")"
  kubectl -n shield-system patch secret "$trusted_ingress_secret_name" \
    --type=json \
    -p "[{\"op\":\"test\",\"path\":\"/metadata/resourceVersion\",\"value\":\"${resource_version}\"},{\"op\":\"test\",\"path\":\"/data/${transport_key_pointer}\",\"value\":\"${transport_data}\"},{\"op\":\"add\",\"path\":\"/data/${trusted_ingress_continuity_key}\",\"value\":\"${transport_data}\"}]" \
    >/dev/null
}

validate_session_signing_key_hex() {
  local value="$1"

  if [[ ! "$value" =~ ^[[:xdigit:]]{64}$ ]]; then
    echo "session signing key must contain exactly 64 hexadecimal characters" >&2
    exit 1
  fi
}

generate_session_signing_key_hex() {
  local value="$session_signing_key_hex"

  if [[ -z "$value" ]]; then
    require_command openssl
    value="$(openssl rand -hex 32)"
  fi
  validate_session_signing_key_hex "$value"
  printf '%s' "$value"
}

validate_existing_session_signing_key_file() {
  local encoded_key_file="$1"

  require_command "$python_bin"
  if [[ ! -f "$session_signing_validator" ]]; then
    echo "session signing key validator not found: ${session_signing_validator}" >&2
    exit 1
  fi
  if ! printf '%s' "$encoded_key_file" |
    "$python_bin" "$session_signing_validator" >/dev/null 2>&1
  then
    echo "session-signing Secret contains an invalid ${session_signing_secret_key}" >&2
    exit 1
  fi
}

ensure_session_signing_secret() {
  local data_key
  local data_line
  local data_value
  local key_data=""
  local key_file
  local key_hex
  local key_present=0
  local resource_version
  local secret_data=""
  local secret_snapshot

  if ! secret_snapshot="$(
    kubectl -n shield-system get secret "$session_signing_secret_name" \
      --ignore-not-found \
      -o 'go-template={{.metadata.resourceVersion}}{{"\n"}}{{range $key, $value := .data}}{{printf "%s\t%s\n" $key $value}}{{end}}'
  )"; then
    echo "could not read session-signing Secret ${session_signing_secret_name}" >&2
    exit 1
  fi

  if [[ -z "$secret_snapshot" ]]; then
    key_hex="$(generate_session_signing_key_hex)"
    key_file="$(printf '{"active_key_version":1,"keys":[{"version":1,"key_hex":"%s"}]}' "$key_hex")"
    printf '%s' "$key_file" |
      kubectl -n shield-system create secret generic "$session_signing_secret_name" \
        --from-file="${session_signing_secret_key}=/dev/stdin" >/dev/null
    return
  fi

  resource_version="${secret_snapshot%%$'\n'*}"
  if [[ -z "$resource_version" ]]; then
    echo "session-signing Secret has no resourceVersion" >&2
    exit 1
  fi

  if [[ "$secret_snapshot" == *$'\n'* ]]; then
    secret_data="${secret_snapshot#*$'\n'}"
  fi
  while IFS= read -r data_line; do
    [[ -z "$data_line" ]] && continue
    if [[ "$data_line" != *$'\t'* ]]; then
      echo "session-signing Secret returned malformed data" >&2
      exit 1
    fi
    data_key="${data_line%%$'\t'*}"
    data_value="${data_line#*$'\t'}"
    if [[ "$data_key" == "$session_signing_secret_key" ]]; then
      key_present=1
      key_data="$data_value"
    fi
  done <<<"$secret_data"

  if [[ "$key_present" != "1" ]]; then
    echo "session-signing Secret is missing ${session_signing_secret_key}" >&2
    exit 1
  fi
  if [[ -z "$key_data" ]]; then
    echo "session-signing Secret has an empty ${session_signing_secret_key}" >&2
    exit 1
  fi
  validate_existing_session_signing_key_file "$key_data"
}

apply_bait_profile_configmap() {
  kubectl -n shield-system create configmap "$bait_profile_configmap_name" \
    --from-file="${bait_profile_key}=${bait_profile_path}" \
    --dry-run=client -o yaml | kubectl apply -f -
}

apply_ingress_trust_configmap() {
  kubectl -n shield-system create configmap "$ingress_trust_configmap_name" \
    --from-file="${ingress_trust_config_key}=${ingress_trust_config_path}" \
    --dry-run=client -o yaml | kubectl apply -f -
}

rollout_proxy_for_bait_profile() {
  kubectl -n shield-system patch deployment eidolon-shield-proxy \
    --type merge \
    -p "{\"spec\":{\"template\":{\"metadata\":{\"annotations\":{\"${bait_profile_rollout_annotation}\":\"${bait_profile_sha256}\",\"${ingress_trust_rollout_annotation}\":\"${ingress_trust_config_sha256}\"}}}}}" >/dev/null
  kubectl -n shield-system rollout status deployment/eidolon-shield-proxy >/dev/null
}

require_command kubectl

context="$(kubectl config current-context)"

case "${context}" in
  orbstack|orbstack-*)
    ;;
  *)
    echo "expected kubectl current-context to be orbstack, got: ${context}" >&2
    exit 1
    ;;
esac

kubectl apply -f - <<'YAML'
apiVersion: v1
kind: Namespace
metadata:
  name: shield-system
YAML

resolve_bait_profile_path
resolve_ingress_trust_config_path
ensure_trusted_ingress_secret
ensure_session_signing_secret
ensure_secret "$bait_signing_secret_name" "$bait_signing_secret_key" "$bait_signing_secret_literal"
apply_bait_profile_configmap
apply_ingress_trust_configmap
kubectl apply -k "${repo_root}/examples/shield-lab/k8s/orbstack"
rollout_proxy_for_bait_profile

echo "OrbStack Shield lab deployed."
echo "Proxy service:       kubectl -n shield-system get svc eidolon-shield-proxy"
echo "Edge service:        kubectl -n shield-system get svc eidolon-shield-edge"
echo "Demo target service: kubectl -n shield-targets get svc eidolon-owned-demo-target"
echo "Direct edge service: kubectl -n shield-targets get svc eidolon-owned-demo-target-edge"
echo "Trusted ingress:     kubectl -n shield-system get secret ${trusted_ingress_secret_name}"
echo "Session signing:     kubectl -n shield-system get secret ${session_signing_secret_name}"
echo "Bait signing:        kubectl -n shield-system get secret ${bait_signing_secret_name}"
echo "Bait profile:        ${bait_profile_path}"
echo "Bait profile digest: ${bait_profile_sha256}"
echo "Bait profile config: kubectl -n shield-system get configmap ${bait_profile_configmap_name}"
echo "Ingress trust:       ${ingress_trust_config_path}"
echo "Ingress trust digest:${ingress_trust_config_sha256}"
echo "Ingress trust config:kubectl -n shield-system get configmap ${ingress_trust_configmap_name}"
echo "Shield URL:          http://127.0.0.1:31080"
echo "Direct URL:          http://127.0.0.1:31081"
