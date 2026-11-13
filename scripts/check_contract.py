#!/usr/bin/env python3
"""Freeze original acceptance laws; permit formatting and exact adapter imports."""
import hashlib
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent.parent
paths = ["tests/acceptance.rs", "tests/canon.rs", "tests/common/mod.rs"]


def formatted(text):
    # Only this non-executable test-fixture lint annotation may differ from red.
    text = text.removeprefix("#![allow(clippy::type_complexity)]\n")
    # The executor/carrier/canon adapters translate retired construction syntax.
    # Only their exact imports normalize; every original assertion stays fixed.
    text = text.replace("mod legacy;\n", "").replace("pub use legacy::*;\n", "")
    text = text.replace('#[cfg(feature = "canon")]\npub mod canonical;\n', "").replace('#[cfg(feature="canon")]\npub mod canonical;\n', "")
    canonical_import = 'use common::canonical::{self as canon, Binding, Identity};\n'
    if canonical_import in text:
        text = text.replace(canonical_import, '', 1)
        text = text.replace('use eudoxia::*;', 'use eudoxia::{canon::{self, Binding, Identity}, *};', 1)
    run = subprocess.run(["rustfmt", "--edition", "2024", "--emit", "stdout",
                          "--config", "skip_children=true"], input=text,
                         capture_output=True, text=True, cwd=root, check=True)
    return run.stdout


for name in paths:
    saved = (root / "fixtures/contract" / (name + ".txt")).read_text()
    assert formatted(saved) == formatted((root / name).read_text()), f"acceptance contract changed: {name}"
# A planted changed verdict must be distinguishable after normalization.
saved = (root / "fixtures/contract/tests/acceptance.rs.txt").read_text()
plant = saved.replace("record.decision, Decision::Permitted", "record.decision, Decision::Refused", 1)
assert plant != saved and formatted(saved) != formatted(plant), "contract instrument missed its plant"
print("passed: original assertions/fixtures unchanged; formatting, lint and migration imports checked; changed-verdict plant detected")
