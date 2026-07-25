#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RUNNER="$SCRIPT_DIR/deploy-kind.sh"
REAL_OPENSSL_BIN="$(command -v openssl)"
export REAL_OPENSSL_BIN
SESSION_SIGNING_KEY_HEX="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
SESSION_SIGNING_KEY_FILE='{"active_key_version":1,"keys":[{"version":1,"key_hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}'
# Derive the encoded fixture from the canonical JSON to prevent drift.
SESSION_SIGNING_KEY_DATA="$(
  printf '%s' "$SESSION_SIGNING_KEY_FILE" | "$REAL_OPENSSL_BIN" base64 -A
)"

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
    if [[ "$4" != "secret" ]]; then
      exit 1
    fi
    case "$5" in
      eidolon-trusted-ingress)
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
      eidolon-session-signing)
        if [[ "${SESSION_SIGNING_FETCH_FAILURE:-}" == "1" ]]; then
          exit 1
        fi
        if [[ "${SESSION_SIGNING_SECRET_EXISTS:-}" != "1" ]]; then
          exit 0
        fi
        printf '%s\n' "${SESSION_SIGNING_RESOURCE_VERSION:-11}"
        if [[ "${SESSION_SIGNING_KEY_PRESENT:-}" == "1" ]]; then
          printf 'key-ring.json\t%s\n' "${SESSION_SIGNING_KEY_DATA:-}"
        fi
        ;;
      *)
        exit 1
        ;;
    esac
    ;;
  "-n shield-controlled-reality get")
    exit 1
    ;;
  "-n shield-system create")
    if [[ "$4" == "configmap" ]]; then
      printf 'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: %s\n' "$5"
    elif [[ "$4" == "secret" && "$5" == "generic" && "$6" == "eidolon-session-signing" ]]; then
      if [[ -n "${SESSION_SIGNING_STDIN_CAPTURE:-}" ]]; then
        cat >"$SESSION_SIGNING_STDIN_CAPTURE"
      else
        cat >/dev/null
      fi
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

encode_session_key_file() {
  printf '%s' "$1" | "$REAL_OPENSSL_BIN" base64 -A
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
      SESSION_SIGNING_STDIN_CAPTURE="$temp_dir/session-key-ring.json" \
      EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET=fixture-secret \
      EIDOLON_SHIELD_SESSION_SIGNING_KEY_HEX="$SESSION_SIGNING_KEY_HEX" \
      EIDOLON_SHIELD_BAIT_PROFILE_PATH="$profile" \
      "$RUNNER" 2>&1
  )"

  rg -q 'get clusters' "$temp_dir/kind.log"
  rg -q 'create cluster --name eidolon-shield --config .*/examples/shield-lab/kind-config.yaml' "$temp_dir/kind.log"
  rg -q 'load docker-image eidolon-shield-proxy:local --name eidolon-shield' "$temp_dir/kind.log"
  rg -q 'load docker-image eidolon-owned-demo-target:local --name eidolon-shield' "$temp_dir/kind.log"
  rg -q 'load docker-image eidolon-controlled-reality:local --name eidolon-shield' "$temp_dir/kind.log"
  rg -q 'apply --server-side -f https://raw.githubusercontent.com/projectcalico/calico/v3.32.1/manifests/operator-crds.yaml' "$temp_dir/kubectl.log"
  rg -q 'wait --for=create tigerastatus/calico --timeout=300s' "$temp_dir/kubectl.log"
  rg -Fq -- '--from-literal=transport-auth.txt=fixture-secret --from-literal=continuity-key.txt=fixture-secret' \
    "$temp_dir/kubectl.log"
  rg -Fq -- 'create secret generic eidolon-session-signing --from-file=key-ring.json=/dev/stdin' \
    "$temp_dir/kubectl.log"
  [[ "$(<"$temp_dir/session-key-ring.json")" == "$SESSION_SIGNING_KEY_FILE" ]]
  ! rg -Fq "$SESSION_SIGNING_KEY_HEX" "$temp_dir/kubectl.log"
  ! rg -Fq "$SESSION_SIGNING_KEY_FILE" "$temp_dir/kubectl.log"
  rg -q -- '-n shield-system create secret generic eidolon-controlled-reality-auth' "$temp_dir/kubectl.log"
  rg -q -- '-n shield-controlled-reality create secret generic eidolon-controlled-reality-auth' "$temp_dir/kubectl.log"
  rg -q 'apply -k .*/examples/shield-lab/k8s/kind' "$temp_dir/kubectl.log"
  rg -q 'Cluster:             eidolon-shield' <<<"$output"
  rg -q 'Context:             kind-eidolon-shield' <<<"$output"
  rg -q 'Renderer:            kubectl -n shield-controlled-reality get deployment eidolon-controlled-reality' <<<"$output"
  rg -q 'Port forward proxy:  kubectl -n shield-system port-forward svc/eidolon-shield-proxy 9102:9102' <<<"$output"
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
    KIND_LOG="$temp_dir/kind.log" \
    CALICO_PRESENT=1 \
    TRUSTED_INGRESS_SECRET_EXISTS=1 \
    TRUSTED_INGRESS_TRANSPORT_DATA=dHJhbnNwb3J0LWtleQ== \
    EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET=replacement-must-not-be-used \
    EIDOLON_SHIELD_CONTROLLED_REALITY_AUTH_SECRET=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
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
      KIND_LOG="$temp_dir/kind.log" \
      CALICO_PRESENT=1 \
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

test_rejects_invalid_session_signing_key_override() {
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
      CALICO_PRESENT=1 \
      EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET=fixture-secret \
      EIDOLON_SHIELD_SESSION_SIGNING_KEY_HEX=not-a-valid-key \
      EIDOLON_SHIELD_BAIT_PROFILE_PATH="$profile" \
      "$RUNNER" 2>&1
  )" || status="$?"

  [[ "$status" -eq 1 ]]
  rg -Fxq 'session signing key must contain exactly 64 hexadecimal characters' <<<"$output"
  ! rg -q 'create secret generic eidolon-session-signing' "$temp_dir/kubectl.log"
  ! rg -q -- '--from-literal=key-ring.json=' "$temp_dir/kubectl.log"
}

test_preserves_existing_session_signing_secret() {
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
    CALICO_PRESENT=1 \
    SESSION_SIGNING_SECRET_EXISTS=1 \
    SESSION_SIGNING_KEY_PRESENT=1 \
    SESSION_SIGNING_KEY_DATA="$SESSION_SIGNING_KEY_DATA" \
    EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET=fixture-secret \
    EIDOLON_SHIELD_SESSION_SIGNING_KEY_HEX=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
    EIDOLON_SHIELD_CONTROLLED_REALITY_AUTH_SECRET=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
    EIDOLON_SHIELD_BAIT_PROFILE_PATH="$profile" \
    "$RUNNER" >/dev/null 2>&1

  [[ "$(rg -c '^-n shield-system get secret eidolon-session-signing ' \
    "$temp_dir/kubectl.log")" -eq 1 ]]
  ! rg -q 'create secret generic eidolon-session-signing' "$temp_dir/kubectl.log"
  ! rg -q 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' \
    "$temp_dir/kubectl.log"
}

test_rejects_session_signing_secret_without_key() {
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
      CALICO_PRESENT=1 \
      SESSION_SIGNING_SECRET_EXISTS=1 \
      EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET=fixture-secret \
      EIDOLON_SHIELD_CONTROLLED_REALITY_AUTH_SECRET=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
      EIDOLON_SHIELD_BAIT_PROFILE_PATH="$profile" \
      "$RUNNER" 2>&1
  )" || status="$?"

  [[ "$status" -eq 1 ]]
  rg -q 'session-signing Secret is missing key-ring.json' <<<"$output"
  ! rg -q 'create secret generic eidolon-session-signing' "$temp_dir/kubectl.log"
}

test_rejects_empty_session_signing_key() {
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
      CALICO_PRESENT=1 \
      SESSION_SIGNING_SECRET_EXISTS=1 \
      SESSION_SIGNING_KEY_PRESENT=1 \
      EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET=fixture-secret \
      EIDOLON_SHIELD_CONTROLLED_REALITY_AUTH_SECRET=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
      EIDOLON_SHIELD_BAIT_PROFILE_PATH="$profile" \
      "$RUNNER" 2>&1
  )" || status="$?"

  [[ "$status" -eq 1 ]]
  rg -q 'session-signing Secret has an empty key-ring.json' <<<"$output"
  ! rg -q 'create secret generic eidolon-session-signing' "$temp_dir/kubectl.log"
}

test_rejects_session_signing_fetch_failure() {
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
      CALICO_PRESENT=1 \
      SESSION_SIGNING_FETCH_FAILURE=1 \
      EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET=fixture-secret \
      EIDOLON_SHIELD_CONTROLLED_REALITY_AUTH_SECRET=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
      EIDOLON_SHIELD_BAIT_PROFILE_PATH="$profile" \
      "$RUNNER" 2>&1
  )" || status="$?"

  [[ "$status" -eq 1 ]]
  rg -q 'could not read session-signing Secret eidolon-session-signing' <<<"$output"
  [[ "$(rg -c '^-n shield-system get secret eidolon-session-signing ' \
    "$temp_dir/kubectl.log")" -eq 1 ]]
  ! rg -q 'create secret generic eidolon-session-signing' "$temp_dir/kubectl.log"
}

test_rejects_invalid_existing_session_signing_key_files() {
  local bin_dir
  local encoded_key_file
  local fixture
  local fixture_json
  local fixture_name
  local output
  local profile
  local status
  local temp_dir
  local fixtures=(
    'malformed-json|not-json'
    'non-object|[]'
    'active-out-of-range|{"active_key_version":4294967296,"keys":[{"version":1,"key_hex":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}]}'
    'version-not-u32|{"active_key_version":1,"keys":[{"version":1.5,"key_hex":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}]}'
    'empty-keys|{"active_key_version":1,"keys":[]}'
    'malformed-key-hex|{"active_key_version":1,"keys":[{"version":1,"key_hex":"not-hex"}]}'
    'duplicate-version|{"active_key_version":1,"keys":[{"version":1,"key_hex":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},{"version":1,"key_hex":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}]}'
    'missing-active|{"active_key_version":2,"keys":[{"version":1,"key_hex":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}]}'
  )

  for fixture in "${fixtures[@]}"; do
    fixture_name="${fixture%%|*}"
    fixture_json="${fixture#*|}"
    encoded_key_file="$(encode_session_key_file "$fixture_json")"
    temp_dir="$(new_temp_dir)"
    bin_dir="$temp_dir/bin"
    profile="$temp_dir/profile.json"
    status=0
    make_stub_bin_dir "$bin_dir"
    printf '{"schema_version":1,"profile_id":"fixture"}\n' > "$profile"

    output="$(
      PATH="$bin_dir:$PATH" \
        KUBECTL_LOG="$temp_dir/kubectl.log" \
        KIND_LOG="$temp_dir/kind.log" \
        CALICO_PRESENT=1 \
        SESSION_SIGNING_SECRET_EXISTS=1 \
        SESSION_SIGNING_KEY_PRESENT=1 \
        SESSION_SIGNING_KEY_DATA="$encoded_key_file" \
        EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET=fixture-secret \
        EIDOLON_SHIELD_BAIT_PROFILE_PATH="$profile" \
        "$RUNNER" 2>&1
    )" || status="$?"

    [[ "$status" -eq 1 ]] || {
      echo "expected ${fixture_name} session key fixture to fail" >&2
      return 1
    }
    rg -Fxq 'session-signing Secret contains an invalid key-ring.json' <<<"$output"
    ! rg -Fq "$fixture_json" <<<"$output"
    ! rg -Fq "$encoded_key_file" <<<"$output"
    ! rg -q 'create secret generic eidolon-session-signing' "$temp_dir/kubectl.log"
    ! rg -q 'apply -k .*/examples/shield-lab/k8s/kind' "$temp_dir/kubectl.log"
    ! rg -q 'patch deployment eidolon-shield-proxy' "$temp_dir/kubectl.log"
  done
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
    KIND_LOG="$temp_dir/kind.log" \
    CALICO_PRESENT=1 \
    TRUSTED_INGRESS_SECRET_EXISTS=1 \
    TRUSTED_INGRESS_TRANSPORT_DATA=dHJhbnNwb3J0LWtleQ== \
    TRUSTED_INGRESS_CONTINUITY_PRESENT=1 \
    TRUSTED_INGRESS_CONTINUITY_DATA=c3RhYmxlLWNvbnRpbnVpdHkta2V5 \
    EIDOLON_SHIELD_TRUSTED_INGRESS_SECRET=replacement-must-not-be-used \
    EIDOLON_SHIELD_CONTROLLED_REALITY_AUTH_SECRET=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
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
      KIND_LOG="$temp_dir/kind.log" \
      CALICO_PRESENT=1 \
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
      KIND_LOG="$temp_dir/kind.log" \
      CALICO_PRESENT=1 \
      TRUSTED_INGRESS_SECRET_EXISTS=1 \
      EIDOLON_SHIELD_BAIT_PROFILE_PATH="$profile" \
      "$RUNNER" 2>&1
  )" || status="$?"

  [[ "$status" -eq 1 ]]
  rg -q 'trusted-ingress Secret is missing non-empty transport-auth.txt' <<<"$output"
  ! rg -q 'patch secret eidolon-trusted-ingress' "$temp_dir/kubectl.log"
  ! rg -q 'create secret generic eidolon-trusted-ingress' "$temp_dir/kubectl.log"
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
test_bootstraps_missing_continuity_key_from_existing_transport_data
test_preserves_existing_continuity_key
test_rejects_empty_existing_continuity_key
test_rejects_legacy_secret_without_transport_data
test_rejects_trusted_ingress_fetch_failure
test_rejects_invalid_session_signing_key_override
test_preserves_existing_session_signing_secret
test_rejects_session_signing_secret_without_key
test_rejects_empty_session_signing_key
test_rejects_session_signing_fetch_failure
test_rejects_invalid_existing_session_signing_key_files
test_skips_cluster_creation_when_kind_cluster_already_exists
test_rejects_missing_kind_config
test_rejects_existing_kindnet_cluster

printf 'shield-lab kind deploy fixture tests passed\n'
