# Streaming frame 4

SHA-256 input:
`"eudoxia/frame/4\0" || domain UTF8 length[u64 BE] || domain || frame(value)`.
Only Eudoxia-owned closed schemas enter; this never reconstructs a native signing
message or interprets original request bytes as JSON.

| Value | Frame |
|---|---|
| null / false / true | 00 / 01 / 02 |
| unsigned/nonnegative integer | 03 || value[u64 BE] |
| negative integer | 04 || magnitude[u64 BE] |
| UTF8 string | 05 || byte length[u64 BE] || bytes |
| sequence/tuple | 06 || count[u64 BE] || each value |
| struct | 07 || field count[u64 BE] || each field name(string), value in declaration order |
| raw bytes | 08 || byte length[u64 BE] || unchanged bytes |
| ordered map | 09 || count[u64 BE] || each key,value in the schema's ordered producer order |
| option none/some | 0a / 0b || value |
| enum unit / newtype / tuple / struct | 0c / 0d / 0e / 0f || variant name(string) || payload (tuple/struct with their own frame) |

Newtype structs are transparent. Unknown collection lengths and floats are errors.
The schemas own field/variant order; BTree maps/sets own key/item order. This is
not a generic map canonicalizer; arbitrary unordered maps are not authority inputs.
Every sequence/map/struct tracks its declared count; under/overproduction fails.
Hashing streams these frames directly into SHA-256, with no serde Value tree,
framed Vec or body copy. Known byte fields use serialize_bytes, including original
body/evidence/signature bytes and full digest/key arrays. JSON transport of those
values remains its declared array/object form, not the hash byte producer.

Every current effect uses domain `eudoxia/effect/v4`, framing a tuple of its
typed context and raw body bytes. Every other Eudoxia-owned fingerprint also uses
frame 4. Identity-v1 dedicated domains (`IDENTITIES.md`) are separate. Reports
use v7 and typed Requests use wire v2. Earlier frame-3 vectors have a test-only
reader in `tests/historical/`, not a production selector.

Evidence is immutable and shared; capture its fingerprint once, not on each
refresh/unit. Fixed effects own their bytes. For streaming transport the real
resource owns the stream/verified handle and admission generation; the effect
binds its owner-generated non-secret stream identity, and preparation consumes
that exact acquired witness. This does not attest unseen future body bytes.
Actual HTTP/blob handle enforcement belongs to the resource, not a fake in-core
I/O trait.

`scripts/frame4_vectors.py` is an independent Python hashlib producer for these
frames; its vectors are pinned in `tests/encoding.rs`. Remaining parse/graph/queue/disk and hashing-total-input
budgets stay with the native protocol/resource owners; streaming is not a quota.
