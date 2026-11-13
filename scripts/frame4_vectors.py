#!/usr/bin/env python3
"""Independent docs/ENCODING.md producer; no Rust or serde imports."""
import hashlib
import json


def number(tag, n):
    return bytes([tag]) + n.to_bytes(8, "big")


def text(s):
    b = s.encode()
    return number(5, len(b)) + b


def seq(xs):
    return number(6, len(xs)) + b"".join(xs)


def struct(fields):
    return number(7, len(fields)) + b"".join(text(k) + v for k, v in fields)


raw = b"\x00\xff"
vector = struct([
    ("z", number(3, 42)), ("a", text("λ")),
    ("raw", number(8, len(raw)) + raw),
    ("negatives", seq([number(4, 1), number(4, 2**63)])),
    ("options", seq([b"\x0a", b"\x0b" + number(3, 3)])),
    ("variants", seq([
        b"\x0c" + text("No"), b"\x0d" + text("Item") + number(3, 7),
        b"\x0e" + text("Pair") + seq([number(3, 1), number(3, 2)]),
        b"\x0f" + text("Window") + struct([("from", number(3, 0)), ("until", number(3, 9))]),
    ])),
    ("map", number(9, 2) + text("a") + number(3, 1) + text("z") + number(3, 2)),
])
domain = b"vector/v4"
digest = hashlib.sha256(b"eudoxia/frame/4\0" + len(domain).to_bytes(8, "big") + domain + vector).hexdigest()
context = struct([
    ("request", text("vector")), ("actor", number(8, 32) + bytes(32)),
    ("person", number(8, 32) + bytes(32)), ("application", text("app")),
    ("operation", text("read")), ("resource", text("box/file")),
])
effect_domain = b"eudoxia/effect/v4"
effects = []
for body in [b"", b'{"n":1.00,"s":"\\u0061"}\n\xff', "\u2603".encode()]:
    encoded = seq([context, number(8, len(body)) + body])
    pin = hashlib.sha256(b"eudoxia/frame/4\0" + len(effect_domain).to_bytes(8, "big") + effect_domain + encoded).hexdigest()
    effects.append({"body_hex": body.hex(), "effect_sha256": pin})
print(json.dumps({"vector_bytes": len(vector), "vector_sha256": digest, "effects": effects}, indent=2))
