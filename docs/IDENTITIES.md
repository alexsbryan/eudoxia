# Authority identity v1

These are Eudoxia-owned closed definitions, not a new encoding of a native pass/act.
Their SHA-256 domains and bytes are independent of prototype record/frame 3.
Original native group IDs and public keys enter as their exact 32 bytes.

## Application authority

Descriptor: version 1, realm, validated logical name, immutable Record/Connector
class. Group realm uses the native full BLAKE3 group ID; Computer realm uses the
actual Ed25519 public key. Names use the existing validated Id rules (1–256 UTF-8
bytes, no controls or leading/trailing whitespace); no extra normalization.

```text
"eudoxia/application-identity/v1\0"
|| realm tag [00 Group / 01 Computer] || realm bytes[32]
|| name UTF-8 byte length[u64 BE] || name UTF-8
|| class tag [00 Record / 01 Connector]
```

SHA-256 of those bytes is the full application AuthorityId. The browser origin
label is `a` followed by the full digest in RFC4648 base32, lowercase, unpadded
(53 characters). This carries no recoverable routing key/truncated-name suffix;
routing is a separate authenticated binding. A code version or location is not
part of this stable authority identity. A different class/realm/name is a
different authority identity. A wire-supplied cached digest is never authoritative.

## Resource identity

Hash the following bytes with SHA-256:

```text
"eudoxia/resource-identity/v1\0" || kind tag || fields
00 RecordPart   : group bytes[32] || application AuthorityId[32]
01 Lend         : owner public key[32] || name length[u64 BE] || name UTF-8
02 AppEndpoint  : application AuthorityId[32]
03 NativeBroker : realm tag || realm bytes[32] || name length[u64 BE] || name UTF-8
```

These four resource families are the initial closed set, not all native
operations. Group files/blobs/control/visits and non-key actor forms are not yet
defined here. Own-record and own-endpoint operations must bind the
same application AuthorityId. Group-scoped carried app record operations must
also use that group; Computer-scoped record apps still require the actual target
group's owner authority. An identity/ID alone grants no entitlement.
Native coverage is exact or an explicit set; the retained Tree API covers only
the same native identity, never a legacy string/prefix or implicit child.

## Native operation/context contract

The initial native operations are ReadRecord, AppendRecord, CorrectRecord,
ReadExternal, SendExternal, UseOwnEndpoint and ReadBrokerStatus. Group record
operations require their actual RecordPart; external operations require Lend;
own use requires that application's AppEndpoint; broker status requires Broker.

Record rejects ReadExternal/SendExternal. Connector rejects AppendRecord/
CorrectRecord. These constraints apply on the same owner derivation path even
when all supplied grants/standing policies would independently permit it.
The authenticated resource guard binds the actual operation; a client cannot
rename an append to read or own-endpoint use to defeat the class constraint.

Legacy string Application/Resource/Operation values retain their prototype
encoding and meaning as a distinct representation. Mixing a refined identity
with legacy operation/resource meaning, or a native operation with unclassified
identity, produces an explicit unsupported-context need and no authority. A
legacy string that happens to equal a refined ID is not promoted to it.
The name wrappers do not implement Into<String>: passing a refined Application,
Resource or Operation to a legacy string constructor cannot silently discard its
meaning. `as_str` is presentation; deliberately rebuilding a legacy value from
that string still does not grant native authority.

Wire representations distinguish native objects from legacy strings; descriptor
version is exactly 1; unknown versions/fields and invalid names are rejected on
parse. Derived identity/cache fields are private and recomputed from the parsed
descriptor. This is serialization of an untrusted claim, not authentication.

## Independent vectors and compatibility

`scripts/identity_vectors.py` is an independent Python hashlib/base32 producer,
not a call back into the Rust serializer. Its application/resource/origin
results are frozen in the runtime witness (`tests/identities.rs`).

Reports are v7 and typed Requests v2. This identity grammar does not change
original native signatures, historical frame-3 vectors, or any native wire or
authority policy.
