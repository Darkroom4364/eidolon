#!/usr/bin/env bash

eidolon_lab_fail() {
  echo "error: $*" >&2
  exit 2
}

eidolon_lab_require_command() {
  local command_name="$1"

  if ! command -v "$command_name" >/dev/null 2>&1; then
    eidolon_lab_fail "missing required tool: $command_name"
  fi
}

eidolon_lab_url_authority() {
  local name="$1"
  local url="$2"
  local rest

  if [[ "$url" != http://* ]]; then
    eidolon_lab_fail "$name must be an http loopback URL, got: $url"
  fi

  rest="${url#http://}"
  if [[ "$rest" == */* || "$rest" == *\?* || "$rest" == *#* ]]; then
    eidolon_lab_fail "$name must not include a path, query, or fragment, got: $url"
  fi
  if [[ "$rest" == *@* ]]; then
    eidolon_lab_fail "$name must not include userinfo, got: $url"
  fi

  printf '%s' "$rest"
}

eidolon_lab_loopback_host_for_url() {
  local name="$1"
  local url="$2"
  local authority
  local host

  authority="$(eidolon_lab_url_authority "$name" "$url")"
  if [[ "$authority" == \[*\]* ]]; then
    host="${authority%%]*}"
    host="${host#[}"
  else
    host="${authority%%:*}"
  fi

  printf '%s' "$host"
}

eidolon_lab_require_loopback_url() {
  local name="$1"
  local url="$2"
  local host

  host="$(eidolon_lab_loopback_host_for_url "$name" "$url")"
  if [[ "$host" == "localhost" || "$host" == "::1" || "$host" =~ ^127(\.[0-9]{1,3}){3}$ ]]; then
    return
  fi

  eidolon_lab_fail "$name must be an http loopback URL, got: $url"
}

eidolon_lab_listen_addr_for_url() {
  local name="$1"
  local url="$2"
  local authority
  local host
  local port

  authority="$(eidolon_lab_url_authority "$name" "$url")"
  if [[ "$authority" == \[*\]* ]]; then
    if [[ "$authority" != \[*\]:* ]]; then
      eidolon_lab_fail "$name must include an explicit port, got: $url"
    fi

    host="${authority%%]*}"
    host="${host#[}"
    port="${authority##*:}"
    printf '[%s]:%s' "$host" "$port"
    return
  fi

  if [[ "$authority" != *:* ]]; then
    eidolon_lab_fail "$name must include an explicit port, got: $url"
  fi

  host="${authority%%:*}"
  port="${authority##*:}"
  if [[ "$host" == "localhost" ]]; then
    host="127.0.0.1"
  fi

  printf '%s:%s' "$host" "$port"
}
