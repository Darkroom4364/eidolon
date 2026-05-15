#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export EIDOLON_M3_TRACE_RUN_KIND="${EIDOLON_M3_TRACE_RUN_KIND:-m3_agent_replay_trace}"
export EIDOLON_M3_TRACE_EVIDENCE_SOURCE="${EIDOLON_M3_TRACE_EVIDENCE_SOURCE:-authorized_agent_proxy_trace}"

exec "$SCRIPT_DIR/collect-action-trace.sh" "$@"
