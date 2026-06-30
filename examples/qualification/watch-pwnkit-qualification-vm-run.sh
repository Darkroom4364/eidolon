#!/usr/bin/env bash
set -euo pipefail

ORBCTL_BIN="${ORBCTL_BIN:-orbctl}"
VM_NAME="${EIDOLON_PWNKIT_WATCH_VM_NAME:-kali}"
POLL_INTERVAL_SECONDS="${EIDOLON_PWNKIT_WATCH_INTERVAL_SECONDS:-5}"
TAIL_LINES="${EIDOLON_PWNKIT_WATCH_TAIL_LINES:-10}"
ONCE=0
RUN_PATH=""

usage() {
  cat <<'USAGE'
Usage: examples/qualification/watch-pwnkit-qualification-vm-run.sh [--vm <name>] [--interval <seconds>] [--tail-lines <n>] [--once] <vm-sample-dir-or-run-dir>

Watches the current pwnkit qualification run state for a Kali VM-backed sample.
If the path is a sample root, the script selects the newest run-* directory.
If the path exists on the host, the script reads it locally; otherwise it uses
OrbStack to read the path inside the VM.

Visible outputs:
  - agent-summary.json
  - latest hypotheses.jsonl entries
  - latest actions.jsonl entries
  - available tool-results/*.json
  - tail of pwnkit-eidolon.stderr.log and pwnkit-eidolon.stdout.log

Options:
  --vm <name>          OrbStack VM name. Defaults to `kali`.
  --interval <sec>     Poll interval. Defaults to 5 seconds.
  --tail-lines <n>     Tail count for logs/jsonl files. Defaults to 10.
  --once               Print one snapshot and exit.
  -h, --help           Show this help text.
USAGE
}

fail() {
  echo "error: $*" >&2
  exit 2
}

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    fail "missing required tool: $command_name"
  fi
}

resolve_local_run_dir() {
  local path="$1"

  if [[ -f "$path/agent-summary.json" || -f "$path/pwnkit-summary.json" ]]; then
    printf '%s\n' "$path"
    return
  fi

  find "$path" -maxdepth 1 -type d -name 'run-*' | sort | tail -n 1
}

resolve_remote_run_dir() {
  local path="$1"
  "$ORBCTL_BIN" run -m "$VM_NAME" bash -lc "
set -euo pipefail
path=$(printf '%q' "$path")
if [[ -f \"\$path/agent-summary.json\" || -f \"\$path/pwnkit-summary.json\" ]]; then
  printf '%s\n' \"\$path\"
  exit 0
fi
find \"\$path\" -maxdepth 1 -type d -name 'run-*' | sort | tail -n 1
"
}

print_local_snapshot() {
  local run_dir="$1"

  printf 'run_dir: %s\n' "$run_dir"
  if [[ -f "$run_dir/agent-summary.json" ]]; then
    printf '\n== agent-summary ==\n'
    cat "$run_dir/agent-summary.json"
    printf '\n'
  fi
  if [[ -f "$run_dir/hypotheses.jsonl" ]]; then
    printf '\n== hypotheses (tail) ==\n'
    tail -n "$TAIL_LINES" "$run_dir/hypotheses.jsonl"
  fi
  if [[ -f "$run_dir/actions.jsonl" ]]; then
    printf '\n== actions (tail) ==\n'
    tail -n "$TAIL_LINES" "$run_dir/actions.jsonl"
  fi
  if [[ -d "$run_dir/tool-results" ]]; then
    printf '\n== tool-results ==\n'
    find "$run_dir/tool-results" -maxdepth 1 -type f -name '*.json' | sort | sed "s#^$run_dir/##"
  fi
  if [[ -f "$run_dir/pwnkit-eidolon.stderr.log" ]]; then
    printf '\n== pwnkit-eidolon.stderr.log (tail) ==\n'
    tail -n "$TAIL_LINES" "$run_dir/pwnkit-eidolon.stderr.log"
  fi
  if [[ -f "$run_dir/pwnkit-eidolon.stdout.log" ]]; then
    printf '\n== pwnkit-eidolon.stdout.log (tail) ==\n'
    tail -n "$TAIL_LINES" "$run_dir/pwnkit-eidolon.stdout.log"
  fi
}

print_remote_snapshot() {
  local run_dir="$1"

  "$ORBCTL_BIN" run -m "$VM_NAME" bash -lc "
set -euo pipefail
run_dir=$(printf '%q' "$run_dir")
tail_lines=$(printf '%q' "$TAIL_LINES")
printf 'run_dir: %s\n' \"\$run_dir\"
if [[ -f \"\$run_dir/agent-summary.json\" ]]; then
  printf '\n== agent-summary ==\n'
  cat \"\$run_dir/agent-summary.json\"
  printf '\n'
fi
if [[ -f \"\$run_dir/hypotheses.jsonl\" ]]; then
  printf '\n== hypotheses (tail) ==\n'
  tail -n \"\$tail_lines\" \"\$run_dir/hypotheses.jsonl\"
fi
if [[ -f \"\$run_dir/actions.jsonl\" ]]; then
  printf '\n== actions (tail) ==\n'
  tail -n \"\$tail_lines\" \"\$run_dir/actions.jsonl\"
fi
if [[ -d \"\$run_dir/tool-results\" ]]; then
  printf '\n== tool-results ==\n'
  find \"\$run_dir/tool-results\" -maxdepth 1 -type f -name '*.json' | sort | sed \"s#^\$run_dir/##\"
fi
if [[ -f \"\$run_dir/pwnkit-eidolon.stderr.log\" ]]; then
  printf '\n== pwnkit-eidolon.stderr.log (tail) ==\n'
  tail -n \"\$tail_lines\" \"\$run_dir/pwnkit-eidolon.stderr.log\"
fi
if [[ -f \"\$run_dir/pwnkit-eidolon.stdout.log\" ]]; then
  printf '\n== pwnkit-eidolon.stdout.log (tail) ==\n'
  tail -n \"\$tail_lines\" \"\$run_dir/pwnkit-eidolon.stdout.log\"
fi
"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vm)
      [[ $# -ge 2 ]] || fail "missing value for --vm"
      VM_NAME="$2"
      shift 2
      ;;
    --interval)
      [[ $# -ge 2 ]] || fail "missing value for --interval"
      POLL_INTERVAL_SECONDS="$2"
      shift 2
      ;;
    --tail-lines)
      [[ $# -ge 2 ]] || fail "missing value for --tail-lines"
      TAIL_LINES="$2"
      shift 2
      ;;
    --once)
      ONCE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      fail "unknown option: $1"
      ;;
    *)
      [[ -z "$RUN_PATH" ]] || fail "unexpected positional argument: $1"
      RUN_PATH="$1"
      shift
      ;;
  esac
done

[[ -n "$RUN_PATH" ]] || fail "missing vm-sample-dir-or-run-dir"
require_command "$ORBCTL_BIN"
require_command find
require_command tail

if [[ -e "$RUN_PATH" ]]; then
  RUN_DIR="$(resolve_local_run_dir "$RUN_PATH")"
  [[ -n "$RUN_DIR" ]] || fail "no run-* directory or run artifacts found under: $RUN_PATH"
  if [[ "$ONCE" -eq 1 ]]; then
    print_local_snapshot "$RUN_DIR"
    exit 0
  fi
  while :; do
    clear
    print_local_snapshot "$RUN_DIR"
    sleep "$POLL_INTERVAL_SECONDS"
  done
else
  RUN_DIR="$(resolve_remote_run_dir "$RUN_PATH")"
  [[ -n "$RUN_DIR" ]] || fail "no run-* directory or run artifacts found in VM path: $RUN_PATH"
  if [[ "$ONCE" -eq 1 ]]; then
    print_remote_snapshot "$RUN_DIR"
    exit 0
  fi
  while :; do
    clear
    print_remote_snapshot "$RUN_DIR"
    sleep "$POLL_INTERVAL_SECONDS"
  done
fi
