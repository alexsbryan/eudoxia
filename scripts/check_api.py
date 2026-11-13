#!/usr/bin/env python3
"""Production API retirement is an explicit contract, not an unknown-type refusal."""
from pathlib import Path
import re
import sys
import tomllib

root = Path(__file__).resolve().parent.parent
patterns = [
    r"pub struct (?:Grant|SignedGrant|OwnerPolicy|Terms)\b",
    r"\bChain\(Vec<SignedGrant>\)",
    r"eudoxia-grant-v1|eudoxia/grant/v1",
    r"legacy_observation|legacy_fingerprint|legacy_encoding",
    r"eudoxia/frame/3|mod framing;",
]


def forbidden(text):
    return any(re.search(pattern, text) for pattern in patterns)


assert forbidden("pub struct SignedGrant { signature: Vec<u8> }"), "missed API plant"
assert forbidden('let id = "eudoxia-grant-v1";'), "missed carrier plant"
assert not forbidden("pub struct Scope { interval: Interval }"), "rejected lawful scope"
failed = [str(p.relative_to(root)) for p in sorted((root / "src").rglob("*.rs")) if forbidden(p.read_text())]
manifest = tomllib.loads((root / "Cargo.toml").read_text())
for section in ["dependencies", "dev-dependencies"]:
    for name, value in manifest.get(section, {}).items():
        if isinstance(value, dict) and "path" in value and not (root / value["path"]).resolve().is_relative_to(root):
            failed.append(f"{section}.{name}: sibling checkout dependency")
if failed:
    print("failed: standalone API/checkout boundary:", *failed, sep="\n  ")
    sys.exit(1)
print("passed: prototype API/carriers/runtime frame-3 path retired; standalone checkout boundary; named plants detected")
