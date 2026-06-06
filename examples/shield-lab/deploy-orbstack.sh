#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
trusted_ingress_secret_name="${EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET_NAME:-eidolon-trusted-ingress}"
trusted_ingress_secret_key="${EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET_KEY:-transport-auth.txt}"
trusted_ingress_secret_literal="${EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET:-}"

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "$command_name is required" >&2
    exit 1
  fi
}

generate_trusted_ingress_secret() {
  if [[ -n "$trusted_ingress_secret_literal" ]]; then
    printf '%s' "$trusted_ingress_secret_literal"
    return
  fi

  require_command openssl
  openssl rand -hex 24
}

ensure_trusted_ingress_secret() {
  local secret_value

  if kubectl -n shield-system get secret "$trusted_ingress_secret_name" >/dev/null 2>&1; then
    return
  fi

  secret_value="$(generate_trusted_ingress_secret)"
  kubectl -n shield-system create secret generic "$trusted_ingress_secret_name" \
    --from-literal="${trusted_ingress_secret_key}=${secret_value}" >/dev/null
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

ensure_trusted_ingress_secret
kubectl apply -k "${repo_root}/examples/shield-lab/k8s/orbstack"

echo "OrbStack Shield lab deployed."
echo "Proxy service:       kubectl -n shield-system get svc eidolon-shield-proxy"
echo "Edge service:        kubectl -n shield-system get svc eidolon-shield-edge"
echo "Demo target service: kubectl -n shield-targets get svc eidolon-owned-demo-target"
echo "Direct edge service: kubectl -n shield-targets get svc eidolon-owned-demo-target-edge"
echo "Trusted ingress:     kubectl -n shield-system get secret ${trusted_ingress_secret_name}"
echo "Shield URL:          http://127.0.0.1:31080"
echo "Direct URL:          http://127.0.0.1:31081"
