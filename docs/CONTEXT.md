# Context and ingress v2

`Exercise` is a key-authenticated profile descriptor. `Request` supports explicit
Actor (key, issuer-bound local session, issuer-bound bearer identity, anonymous),
Subject (none, group-bound person, group/host-bound visit) and AuthorityUse
(Personal, Application, Public). These are untrusted claims. A resource supplies
an independently authenticated full actor/subject/use/operation/resource Ingress
at derive and refresh. Parsing never authenticates it. Absence of an application
does not become personal authority, and a session is not its issuer's key.

Session/bearer IDs are non-secret 256-bit commitments/owner-generated identities,
not credentials. Authentication and replay state remain with the admitting owner.
A signature delegation can end only at Actor::Key, not an invented session key.

## Intrinsic app meanings

Known intrinsic operations derive their owner set from exact context/target:

| Operation | Context | Required owners |
|---|---|---|
| Record read/append/correct | Group-bound person; explicit personal/permitted app; key/session | Person + target group |
| External read/send | Person/visit; permitted app; visit on its host | Subject + actual lender |
| Own endpoint, broker status | Explicit personal/permitted app; valid subject | Subject + actual resource |
| Public output | No subject; Public use; explicit actor kind or anonymous | Actual resource |

Record cannot receive external read/send, Connector cannot append/correct. Actual
resource family, own-app ID and group must match. A matching human/display name
is no identity conversion. Missing owner policies yield an explicit need; extra
policies cannot replace them. A compiled profile still proves actual source/owner
legitimacy, eligible-group bindings and real operation classification.

## Profile-owned meanings

`Request::profile` accepts unclassified operation/resource IDs for explicit
personal (person + key/session) or public (no subject) use. The acquired resource's
Basis fixes the nonempty required-owner list; the request's proof subset cannot.
Its independent `Ingress::profile` fixes the full tuple, so caller relabelling
does not authorize another action/target or borrow another session/person.

Classified application use and native resource definitions cannot enter this
path. Unknown app meaning cannot default to an unconstrained personal operation.
Further group/file/control/visitor rules belong to the actual profile and use
the same kernel, rather than a speculative generic platform operation enum or
an unchecked proof constructor.

Both contexts use one generic derivation/scaffold and streaming frame 4. Request
wire version is exactly 2; unknown fields/versions fail. Reports use v7.
Earlier frame-3 vectors have a test-only reader, never a runtime fallback.
Native carrier integration is the embedding's responsibility.
