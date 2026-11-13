#!/usr/bin/env python3
"""Independent frame-3 vectors; no Rust/serde/Eudoxia code is imported."""
import hashlib
import json


def u64(n):
    return n.to_bytes(8, "big")


def frame(v):
    if v is None:
        return b"\x00"
    if isinstance(v, bool):
        return b"\x02" if v else b"\x01"
    if isinstance(v, int):
        return (b"\x03" if v >= 0 else b"\x04") + u64(abs(v))
    if isinstance(v, str):
        b = v.encode("utf-8")
        return b"\x05" + u64(len(b)) + b
    if isinstance(v, list):
        return b"\x06" + u64(len(v)) + b"".join(map(frame, v))
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-8"))
        return b"\x07" + u64(len(keys)) + b"".join(frame(k) + frame(v[k]) for k in keys)
    raise TypeError(type(v))


def digest(domain, value):
    d = domain.encode()
    return hashlib.sha256(b"eudoxia/frame/3\0" + u64(len(d)) + d + frame(value)).hexdigest()


exercise = dict(request="vector", actor=[0] * 32, person=[0] * 32,
                application="app", operation="read", resource="box/file")
vectors = [{"body_hex": b.hex(), "effect_sha256": digest("eudoxia/effect/v3", [exercise, list(b)])}
           for b in [b"", b'{"n":1.00,"s":"\\u0061"}\n\xff', "\u2603".encode()]]
print(json.dumps(vectors, indent=2))
