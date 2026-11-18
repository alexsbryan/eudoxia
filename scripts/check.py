#!/usr/bin/env python3
"""The reproducible gate; a missing tool or failed command is never skipped."""
from pathlib import Path
import os
import subprocess
import sys

root = Path(__file__).resolve().parent.parent
if os.environ.get("TRYBUILD") == "overwrite":
    raise SystemExit("refusing to run the gate in compiler-contract rewrite mode")
commands = [
    ["cargo", "fmt", "--all", "--check"],
    ["rustfmt", "--edition", "2024", "--check", *[str(p.relative_to(root)) for p in sorted((root / "tests/ui").rglob("*.rs"))]],
    [sys.executable, "scripts/check_contract.py"],
    [sys.executable, "scripts/check_api.py"],
    [sys.executable, "scripts/check_boundary.py", "--self-test"],
    ["cargo", "clippy", "--locked", "--all-targets", "--all-features", "--", "-D", "warnings"],
    ["cargo", "test", "--locked", "--all-features"],
    ["cargo", "test", "--locked", "--no-default-features"],
    ["cargo", "run", "--locked", "--example", "owned_resource"],
    [sys.executable, "scripts/check_extensions.py"],
]
# The community profile is its own package root, so `--all` above never reaches it.
community = ["--manifest-path", "community/Cargo.toml"]
commands += [
    ["cargo", "fmt", *community, "--all", "--check"],
    ["cargo", "clippy", *community, "--locked", "--all-targets", "--", "-D", "warnings"],
    ["cargo", "test", *community, "--locked"],
    ["cargo", "check", *community, "--locked", "--lib", "--target", "wasm32-unknown-unknown"],
]
for target in [[], ["--target", "wasm32-unknown-unknown"]]:
    for features in [["--no-default-features"], ["--all-features"]]:
        commands.append(["cargo", "check", "--locked", "--lib", *features, *target])
for command in commands:
    print("check:", " ".join(command), flush=True)
    subprocess.run(command, cwd=root, check=True)
print("passed: Eudoxia gate", flush=True)
