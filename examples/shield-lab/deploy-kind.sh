#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
kubectl_bin="${KUBECTL_BIN:-kubectl}"
kind_bin="${KIND_BIN:-kind}"
kind_cluster_name="${EIDOLON_SHIELD_KIND_CLUSTER_NAME:-eidolon-shield}"
kind_config_path="${EIDOLON_SHIELD_KIND_CONFIG_PATH:-${repo_root}/examples/shield-lab/kind-config.yaml}"
expected_context="${EIDOLON_SHIELD_KIND_CONTEXT:-kind-${kind_cluster_name}}"
trusted_ingress_secret_name="${EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET_NAME:-eidolon-trusted-ingress}"
trusted_ingress_secret_key="${EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET_KEY:-transport-auth.txt}"
trusted_ingress_continuity_key="continuity-key.txt"
trusted_ingress_secret_literal="${EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET:-}"
bait_signing_secret_name="${EIDOLON_SHIELD_BAIT_SIGNING_SECRET_NAME:-eidolon-bait-signing}"
bait_signing_secret_key="${EIDOLON_SHIELD_BAIT_SIGNING_SECRET_KEY:-signing-secret.txt}"
bait_signing_secret_literal="${EIDOLON_SHIELD_BAIT_SIGNING_SECRET:-}"
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
controlled_reality_auth_secret_name="eidolon-controlled-reality-auth"
controlled_reality_auth_secret_key="auth-secret.txt"
controlled_reality_auth_secret_literal="${EIDOLON_SHIELD_CONTROLLED_REALITY_AUTH_SECRET:-}"
calico_version="v3.32.1"
calico_base_url="https://raw.githubusercontent.com/projectcalico/calico/${calico_version}/manifests"
kind_images=(
  "eidolon-shield-proxy:local"
  "eidolon-owned-demo-target:local"
  "eidolon-controlled-reality:local"
)

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

resolve_kind_config_path() {
  if [[ ! -f "$kind_config_path" ]]; then
    echo "kind config not found: ${kind_config_path}" >&2
    exit 1
  fi

  kind_config_path="$(canonical_file_path "$kind_config_path")"
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

  if "$kubectl_bin" -n shield-system get secret "$secret_name" >/dev/null 2>&1; then
    return
  fi

  secret_value="$(generate_secret_value "$secret_literal")"
  "$kubectl_bin" -n shield-system create secret generic "$secret_name" \
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
    "$kubectl_bin" -n shield-system get secret "$trusted_ingress_secret_name" \
      --ignore-not-found \
      -o 'go-template={{.metadata.resourceVersion}}{{"\n"}}{{range $key, $value := .data}}{{printf "%s\t%s\n" $key $value}}{{end}}'
  )"; then
    echo "could not read trusted-ingress Secret ${trusted_ingress_secret_name}" >&2
    exit 1
  fi

  if [[ -z "$secret_snapshot" ]]; then
    secret_value="$(generate_secret_value "$trusted_ingress_secret_literal")"
    "$kubectl_bin" -n shield-system create secret generic "$trusted_ingress_secret_name" \
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
  "$kubectl_bin" -n shield-system patch secret "$trusted_ingress_secret_name" \
    --type=json \
    -p "[{\"op\":\"test\",\"path\":\"/metadata/resourceVersion\",\"value\":\"${resource_version}\"},{\"op\":\"test\",\"path\":\"/data/${transport_key_pointer}\",\"value\":\"${transport_data}\"},{\"op\":\"add\",\"path\":\"/data/${trusted_ingress_continuity_key}\",\"value\":\"${transport_data}\"}]" \
    >/dev/null
}

validate_controlled_reality_auth_secret() {
  local value="$1"

  if [[ ! "$value" =~ ^[[:xdigit:]]{64}$ ]]; then
    echo "controlled-reality auth secret must contain exactly 64 hexadecimal characters" >&2
    exit 1
  fi
}

apply_controlled_reality_auth_secret() {
  local namespace="$1"
  local value="$2"

  "$kubectl_bin" -n "$namespace" create secret generic "$controlled_reality_auth_secret_name" \
    --from-literal="${controlled_reality_auth_secret_key}=${value}" \
    --dry-run=client -o yaml | "$kubectl_bin" apply -f - >/dev/null
}

ensure_controlled_reality_auth_secrets() {
  local system_secret_data
  local renderer_secret_data
  local secret_value

  if [[ -n "$controlled_reality_auth_secret_literal" ]]; then
    validate_controlled_reality_auth_secret "$controlled_reality_auth_secret_literal"
    apply_controlled_reality_auth_secret shield-system "$controlled_reality_auth_secret_literal"
    apply_controlled_reality_auth_secret \
      shield-controlled-reality \
      "$controlled_reality_auth_secret_literal"
    return
  fi

  system_secret_data="$(
    "$kubectl_bin" -n shield-system get secret "$controlled_reality_auth_secret_name" \
      -o "jsonpath={.data.${controlled_reality_auth_secret_key//./\\.}}" 2>/dev/null || true
  )"
  renderer_secret_data="$(
    "$kubectl_bin" -n shield-controlled-reality get secret "$controlled_reality_auth_secret_name" \
      -o "jsonpath={.data.${controlled_reality_auth_secret_key//./\\.}}" 2>/dev/null || true
  )"

  if [[ -n "$system_secret_data" || -n "$renderer_secret_data" ]]; then
    if [[ -z "$system_secret_data" || "$system_secret_data" != "$renderer_secret_data" ]]; then
      echo "controlled-reality auth secrets must exist in both namespaces with matching values" >&2
      exit 1
    fi
    return
  fi

  require_command openssl
  secret_value="$(openssl rand -hex 32)"
  validate_controlled_reality_auth_secret "$secret_value"
  apply_controlled_reality_auth_secret shield-system "$secret_value"
  apply_controlled_reality_auth_secret shield-controlled-reality "$secret_value"
}

apply_bait_profile_configmap() {
  "$kubectl_bin" -n shield-system create configmap "$bait_profile_configmap_name" \
    --from-file="${bait_profile_key}=${bait_profile_path}" \
    --dry-run=client -o yaml | "$kubectl_bin" apply -f -
}

apply_ingress_trust_configmap() {
  "$kubectl_bin" -n shield-system create configmap "$ingress_trust_configmap_name" \
    --from-file="${ingress_trust_config_key}=${ingress_trust_config_path}" \
    --dry-run=client -o yaml | "$kubectl_bin" apply -f -
}

rollout_proxy_for_bait_profile() {
  "$kubectl_bin" -n shield-system patch deployment eidolon-shield-proxy \
    --type merge \
    -p "{\"spec\":{\"template\":{\"metadata\":{\"annotations\":{\"${bait_profile_rollout_annotation}\":\"${bait_profile_sha256}\",\"${ingress_trust_rollout_annotation}\":\"${ingress_trust_config_sha256}\"}}}}}" >/dev/null
  "$kubectl_bin" -n shield-system rollout status deployment/eidolon-shield-proxy >/dev/null
}

ensure_kind_cluster() {
  if "$kind_bin" get clusters | grep -Fxq "$kind_cluster_name"; then
    return
  fi

  "$kind_bin" create cluster --name "$kind_cluster_name" --config "$kind_config_path"
}

ensure_calico_network_policy() {
  if "$kubectl_bin" -n kube-system get daemonset kindnet >/dev/null 2>&1; then
    echo "existing kind cluster uses kindnet, which does not enforce NetworkPolicy; recreate it with ${kind_config_path}" >&2
    exit 1
  fi

  if ! "$kubectl_bin" get tigerastatus calico >/dev/null 2>&1; then
    "$kubectl_bin" apply --server-side -f "${calico_base_url}/operator-crds.yaml" >/dev/null
    "$kubectl_bin" apply --server-side -f "${calico_base_url}/tigera-operator.yaml" >/dev/null
    "$kubectl_bin" apply --server-side -f "${calico_base_url}/custom-resources.yaml" >/dev/null
  fi

  "$kubectl_bin" wait --for=create tigerastatus/calico --timeout=300s >/dev/null
  "$kubectl_bin" wait --for=condition=Available tigerastatus/calico --timeout=300s >/dev/null
}

load_kind_images() {
  local image

  for image in "${kind_images[@]}"; do
    "$kind_bin" load docker-image "$image" --name "$kind_cluster_name"
  done
}

require_command "$kubectl_bin"
require_command "$kind_bin"

resolve_kind_config_path
resolve_bait_profile_path
resolve_ingress_trust_config_path
ensure_kind_cluster

context="$("$kubectl_bin" config current-context)"
if [[ "$context" != "$expected_context" ]]; then
  echo "expected kubectl current-context to be ${expected_context}, got: ${context}" >&2
  exit 1
fi

ensure_calico_network_policy

"$kubectl_bin" apply -f - <<'YAML'
apiVersion: v1
kind: Namespace
metadata:
  name: shield-system
---
apiVersion: v1
kind: Namespace
metadata:
  name: shield-controlled-reality
YAML

ensure_trusted_ingress_secret
ensure_secret "$bait_signing_secret_name" "$bait_signing_secret_key" "$bait_signing_secret_literal"
ensure_controlled_reality_auth_secrets
apply_bait_profile_configmap
apply_ingress_trust_configmap
load_kind_images
"$kubectl_bin" apply -k "${repo_root}/examples/shield-lab/k8s/kind"
rollout_proxy_for_bait_profile
"$kubectl_bin" -n shield-controlled-reality rollout status \
  deployment/eidolon-controlled-reality >/dev/null

echo "kind Shield lab deployed."
echo "Cluster:             ${kind_cluster_name}"
echo "Context:             ${expected_context}"
echo "Proxy service:       kubectl -n shield-system get svc eidolon-shield-proxy"
echo "Demo target service: kubectl -n shield-targets get svc eidolon-owned-demo-target"
echo "Trusted ingress:     kubectl -n shield-system get secret ${trusted_ingress_secret_name}"
echo "Bait signing:        kubectl -n shield-system get secret ${bait_signing_secret_name}"
echo "Renderer auth:       kubectl -n shield-system get secret ${controlled_reality_auth_secret_name}"
echo "Renderer:            kubectl -n shield-controlled-reality get deployment eidolon-controlled-reality"
echo "Bait profile:        ${bait_profile_path}"
echo "Bait profile digest: ${bait_profile_sha256}"
echo "Bait profile config: kubectl -n shield-system get configmap ${bait_profile_configmap_name}"
echo "Ingress trust:       ${ingress_trust_config_path}"
echo "Ingress trust digest:${ingress_trust_config_sha256}"
echo "Ingress trust config:kubectl -n shield-system get configmap ${ingress_trust_configmap_name}"
echo "Port forward proxy:  kubectl -n shield-system port-forward svc/eidolon-shield-proxy 9102:9102"
