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

"$kubectl_bin" apply -f - <<'YAML'
apiVersion: v1
kind: Namespace
metadata:
  name: shield-system
YAML

ensure_secret "$trusted_ingress_secret_name" "$trusted_ingress_secret_key" "$trusted_ingress_secret_literal"
ensure_secret "$bait_signing_secret_name" "$bait_signing_secret_key" "$bait_signing_secret_literal"
apply_bait_profile_configmap
apply_ingress_trust_configmap
"$kubectl_bin" apply -k "${repo_root}/examples/shield-lab/k8s/kind"
rollout_proxy_for_bait_profile

echo "kind Shield lab deployed."
echo "Cluster:             ${kind_cluster_name}"
echo "Context:             ${expected_context}"
echo "Proxy service:       kubectl -n shield-system get svc eidolon-shield-proxy"
echo "Demo target service: kubectl -n shield-targets get svc eidolon-owned-demo-target"
echo "Trusted ingress:     kubectl -n shield-system get secret ${trusted_ingress_secret_name}"
echo "Bait signing:        kubectl -n shield-system get secret ${bait_signing_secret_name}"
echo "Bait profile:        ${bait_profile_path}"
echo "Bait profile digest: ${bait_profile_sha256}"
echo "Bait profile config: kubectl -n shield-system get configmap ${bait_profile_configmap_name}"
echo "Ingress trust:       ${ingress_trust_config_path}"
echo "Ingress trust digest:${ingress_trust_config_sha256}"
echo "Ingress trust config:kubectl -n shield-system get configmap ${ingress_trust_configmap_name}"
echo "Port forward proxy:  kubectl -n shield-system port-forward svc/eidolon-shield-proxy 9102:9102"
