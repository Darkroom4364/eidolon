#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SMOKE_SCRIPT="$SCRIPT_DIR/smoke-trusted-ingress-orbstack.sh"

new_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/eidolon-trusted-ingress-smoke-test.XXXXXX"
}

make_stub_bins() {
  local dir="$1"

  cat > "$dir/kubectl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

case "$*" in
  "config current-context")
    printf 'orbstack\n'
    ;;
  "-n shield-system get svc eidolon-shield-edge -o json")
    cat <<'JSON'
{"metadata":{"name":"eidolon-shield-edge"},"spec":{"ports":[{"name":"http","nodePort":31080}]}}
JSON
    ;;
  "-n shield-system get secret eidolon-trusted-ingress -o json")
    cat <<'JSON'
{"data":{"transport-auth.txt":"c2VjcmV0LXZhbHVl"}}
JSON
    ;;
  *)
    echo "unexpected kubectl invocation: $*" >&2
    exit 1
    ;;
esac
SH

  cat > "$dir/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

has_transport_auth=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -H)
      if [[ "${2:-}" == "X-Eidolon-Ingress-Transport-Auth: secret-value" ]]; then
        has_transport_auth=1
      fi
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

if [[ "$has_transport_auth" -eq 1 ]]; then
  cat <<'JSON'
{"paths":{"/api/v1/imports":{"post":{}}}}
JSON
else
  cat <<'JSON'
{"paths":{"/api/v2/import/reconcile":{"post":{}},"/api/v1/imports":{"post":{}}}}
JSON
fi
SH

  chmod +x "$dir/kubectl" "$dir/curl"
}

test_smoke_script_distinguishes_raw_and_authenticated_ingress() {
  local temp_dir
  local output

  temp_dir="$(new_temp_dir)"
  make_stub_bins "$temp_dir"

  output="$(
    KUBECTL_BIN="$temp_dir/kubectl" \
      CURL_BIN="$temp_dir/curl" \
      "$SMOKE_SCRIPT"
  )"

  rg -q 'trusted-ingress smoke ok' <<<"$output"
}

test_smoke_script_distinguishes_raw_and_authenticated_ingress

printf 'shield-lab trusted ingress smoke checks passed\n'
