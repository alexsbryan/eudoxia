#!/usr/bin/env python3
"""Inspect isolated production runtime features; compiler checks still run separately."""
import json
from pathlib import Path
import re
import subprocess
import sys

root = Path(__file__).resolve().parent.parent


def source_errors(text):
    return bool(re.search(r"\bextern\s+crate\s+std\b|\bstd::|\basync\s+(?:fn|move|\{)", text))


def feature_errors(features):
    return sorted(set(features) & {"std", "preserve_order"})


if "--self-test" in sys.argv:
    assert source_errors("extern crate std;"), "missed planted std import"
    assert source_errors("std::fs::read(path)"), "missed planted ambient I/O"
    assert feature_errors(["alloc", "std"]), "missed planted runtime std feature"
    print("passed: boundary instrument rejects planted std import, ambient I/O, std feature")

for path in (root / "src").rglob("*.rs"):
    assert not source_errors(path.read_text()), f"ambient source dependency: {path}"

# Resolve Eudoxia as a dependency: root-package metadata also enables dev tools'
# std features. Those are not the shipped library closure (trybuild exposed this).
probe = root / "target/boundary-probe"
(probe / "src").mkdir(parents=True, exist_ok=True)
(probe / "Cargo.toml").write_text(
    '[package]\nname = "eudoxia-boundary-probe"\nversion = "0.0.0"\nedition = "2024"\n'
    '[workspace]\n[features]\ncanon = ["eudoxia/canon"]\n'
    '[dependencies]\neudoxia = { path = "../..", default-features = false }\n')
(probe / "src/lib.rs").write_text('#![no_std]\npub use eudoxia;\n')
(probe / "Cargo.lock").write_bytes((root / "Cargo.lock").read_bytes())

for platform, flags in [(p, f) for p in [[], ["--filter-platform", "wasm32-unknown-unknown"]]
                        for f in [[], ["--features", "canon"]]]:
    command = ["cargo", "metadata", "--offline", "--manifest-path", str(probe / "Cargo.toml"), "--format-version", "1",
               "--no-default-features", *platform, *flags]
    metadata = json.loads(subprocess.check_output(command, cwd=root))
    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    pending, visited = [metadata["resolve"]["root"]], set()
    while pending:
        package_id = pending.pop()
        if package_id in visited:
            continue
        package, node = packages[package_id], nodes[package_id]
        if any("proc-macro" in t["kind"] for t in package["targets"]):
            continue  # Host code, not the shipped runtime dependency closure.
        visited.add(package_id)
        assert not feature_errors(node["features"]), (package["name"], node["features"])
        pending += [d["pkg"] for d in node["deps"] if any(k["kind"] is None for k in d["dep_kinds"])]
    print(f"passed: {'wasm' if platform else 'native'} {'canon' if flags else 'core'} runtime closure, {len(visited)} packages; no std/preserve_order features")
