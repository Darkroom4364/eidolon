#!/usr/bin/env python3
"""Enforce the semantic-canary crate's intentionally tiny capability surface."""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
CRATE = ROOT / "crates" / "eidolon-semantic-canary"

manifest = (CRATE / "Cargo.toml").read_text(encoding="utf-8")
section = re.search(r"(?ms)^\[dependencies\]\n(.*?)(?=^\[|\Z)", manifest)
if section is None:
    sys.exit("semantic-canary manifest has no [dependencies] section")
actual = set()
for raw_line in section.group(1).splitlines():
    line = raw_line.split("#", 1)[0].strip()
    if not line:
        continue
    match = re.match(r'([A-Za-z0-9_-]+)(?:\.workspace)?\s*=', line)
    if match is None:
        sys.exit(f"unrecognized semantic-canary dependency line: {raw_line!r}")
    actual.add(match.group(1))
allowed = {"serde", "serde_json", "sha2"}
if actual != allowed:
    sys.exit(f"semantic-canary dependencies must be exactly {sorted(allowed)}; got {sorted(actual)}")

for forbidden_manifest_key in ("build =", "links ="):
    if forbidden_manifest_key in manifest:
        sys.exit(f"semantic-canary manifest contains forbidden capability: {forbidden_manifest_key}")

for path in sorted((CRATE / "src").rglob("*.rs")):
    text = path.read_text(encoding="utf-8")
    forbidden = {
        "std::fs": "filesystem",
        "std::net": "network",
        "std::process::Command": "subprocess",
        "extern \"C\"": "ffi",
        "unsafe {": "unsafe",
    }
    for needle, capability in forbidden.items():
        if needle in text:
            sys.exit(f"{path.relative_to(ROOT)} contains forbidden {capability} capability: {needle}")
print("semantic-canary capability allowlist passed")
