#!/usr/bin/env python3
"""Independent implementation of docs/IDENTITIES.md; no Rust/serde imports."""
import base64
import hashlib
import json


def field(b):
    return len(b).to_bytes(8, "big") + b


def app(realm_tag, realm, name, class_tag):
    return hashlib.sha256(b"eudoxia/application-identity/v1\0" + bytes([realm_tag]) + realm
                          + field(name.encode()) + bytes([class_tag])).digest()


group = bytes([1]) * 32
other_group = bytes([2]) * 32
record = app(0, group, "notes", 0)
connector = app(0, group, "notes", 1)
other = app(0, other_group, "notes", 0)
record_part = hashlib.sha256(b"eudoxia/resource-identity/v1\0\x00" + group + record).digest()
endpoint = hashlib.sha256(b"eudoxia/resource-identity/v1\0\x02" + record).digest()
# RFC8032 test-vector public key; the identity producer needs no signing library.
computer = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
local = app(1, computer, "café", 0)
lend = hashlib.sha256(b"eudoxia/resource-identity/v1\0\x01" + computer + field("café".encode())).digest()
broker = hashlib.sha256(b"eudoxia/resource-identity/v1\0\x03\x01" + computer + field(b"open-status")).digest()
print(json.dumps({
    "record": record.hex(), "connector": connector.hex(), "other_realm": other.hex(),
    "record_origin": "a" + base64.b32encode(record).decode().lower().rstrip("="),
    "record_part": record_part.hex(), "record_endpoint": endpoint.hex(),
    "computer_app": local.hex(), "lend": lend.hex(), "computer_broker": broker.hex(),
}, indent=2))
