# Eudoxia — explicit authority, owned execution

The reusable library is pure synchronous Rust, `no_std + alloc`. Explicit
authenticated evidence, configured root meaning and observation time enter;
source-linked judgments and a sealed resource execution path leave. There is no
ambient I/O, clock, identity lookup, private key, authority server or app registry.
`PROOFS.md` states the conditional construction laws; `THREAT_MODEL.md` names the TCB.

Domain policy — a group constitution, a native platform's operation set, its
recovery rules — is a profile contract supplied by the embedding, not a
general-purpose service hidden inside this library.

## One construction path

```text
explicit trusted profile + immutable held sources + explicit observation
  -> Basis (shared immutable policies/facts, checked interpretation deadline)
  -> standing approval OR parsed original statement -> verification -> projection
  -> root/attenuation -> every required owner's Approval -> Agreement
  -> Justification(exact owned Effect)
  -> real resource preparation Witness -> Ready
  -> fresh context check -> Authorized -> resource commit
  -> completed result OR owned linear Lease
```

Only `derivation.rs` constructs authority; only `scaffold.rs` constructs the
operational proof/witness transitions. Reports/traces are observational data and
have no edge back into this graph. A serialized Permitted record is not a permit.
All native carriers, reference fixtures, public/session and key contexts use
that same evaluator. There is no built-in Eudoxia grant format or second chain
evaluator. Earlier prototype types and formats survive only in test migration adapters.

## Ownership

| What | Owner and update law |
|---|---|
| Original statements, native IDs, native signing bytes | The concrete carrier/content store. Eudoxia verifies original bytes; it does not reissue certificates or serialize another system's signed meaning. |
| Root legitimacy, membership/consent/role/source meaning | Eudoxia's compiled installed authority profile; deterministic interpretation of authenticated original meaning. Native adapters own format/authentication correspondence, not a second authority engine. `Basis::interpreted` checks structure, not truth. |
| Policies, source facts, dependency identity | One immutable `Basis` allocation. No mutable global keeper and no union-only permission cache. A fork/cut can retract authority. |
| Observation time and next interpretation boundary | Explicit `Basis::observed_at`; backward time fails, crossing `Recheck::Before` returns Reinterpret. Time is not automatically a new source identity. |
| Original proof bytes and their fingerprint | Immutable shared `Evidence`, captured once. Omission is unknown; only explicit resolved absence is a refusal. |
| Credentials, handles, counters, consumption, sockets and effects | The concrete resource. Its acquired guard supplies current coherent facts, real opaque witnesses, final generation checks and actual commit/continuation. |

An I/O owner does neutral acquisition outside the generative callback, then
derives afresh before protected work. No branded proof survives an await. If
opening a connection itself is protected, authorize that stage before opening.
Resource-specific state machines keep Start/Check/Closed and the original owned
use, not a resent request or second reservation during rechecks.

## Profile and carrier boundary

`Policy`/`Scope` is the one production representation. It binds person/app,
structural resource coverage, operations, interval, onward budget, independent
owner, source dependencies, allowed carrier versions and mandatory conditions.
Factories reject empty/duplicate owners and malformed source structures.

`Rules` are a profile's request rules as data (`src/rules.rs`): each permits or
forbids operations when a closed `Condition` holds over the request's time,
owner, resource and named facts. No free variables, no named escape hatch.
`Rules::basis` decides them into a per-request `Basis`: one exact-scope standing
`Policy` per owner, sourced from that owner's ruling (established on permit,
refused naming the first deciding forbid, `NoGrant` on default deny, Missing
when a rule reads an absent fact). The derivation is unchanged and decides. A
native request's owners are the kernel's `required_owners`, and
`Basis::interpreted` refuses a native-operation policy for such an owner, so
that authority is built only through rules. Laws: `tests/rules.rs`.

`Codec` is installed by the resource profile, never supplied as executable code
in a network request. Parsing returns one owned `ParsedStatement`. Its concrete
`NativeStatement` supplies issuer, signature and native signing message from that
same immutable value. Private verification produces `VerifiedStatement`; only
then is that value consumed to project a Claim under the explicit profile binding
source. This permits source-rooted normalization for formats that do not sign an
Eudoxia-specific source field; the carrier must prove its projection no wider
than the native statement under that binding. A trait cannot prove semantics.

The kernel checks signatures, issuer/holder continuity, source validity,
attenuation, time, final actor and complete ownership. Genuine relevant conflicts
remain Frozen/Missing, not absence or a restored root. The concrete interpreter
defines constitutional/recovery/guest rules; the kernel has no per-domain bypass.

The optional canon adapter calls canon's pinned interpreter. It receives held
original Acts before lossy short-ID Log construction, validates their native IDs,
rejects conflicting content/signature variants and preserves canon-produced full
canonical SHA-256 pins. Explicit operational mappings and authenticated identities
select allowed carriers; canon is not recreated as a second ratifier here.

## Context and identity

`Exercise` is a key-authenticated descriptor for profile-owned operation/resource
IDs. `KeyIngress` binds the actual key and action; the installed profile and real
witness establish represented identity, target and effect meaning.

`Request` adds explicit Actor (key/session/bearer/anonymous), Subject
(none/unscoped-principal/group-person/visit) and AuthorityUse (personal/application/public). Its
resource supplies a complete independent `Ingress` tuple at derive and refresh.
No anonymous request needs an invented key/person, and absence of an app never
becomes personal authority. `Request::profile` supports resource-owned personal
or public operations without inventing generic platform operations. Its owner set
comes from the acquired resource's Basis, never the caller's proof subset.

An unscoped principal is personal authority under an original key before a
group's identity lookup; it is permitted only for profile-owned operations.
Every intrinsic native operation rejects that subject. Policy actor selection
binds the complete credential, including issuer-bound session identity, rather
than reducing a session to a key. `AuthorityId::session` names exact original bytes
under the issuer and profile namespace; it supplies no authentication by itself.

The fixed-observation `atomic`/`PersonalProfile` conveniences use the same sealed
derive/prepare/execute path. They construct no proofs from records, reject every
nonempty obligation set, and invoke an exclusively owned FnOnce commit only after
authorization. Personal source attenuation preserves the parent dependency and
uses the same Scope inclusion relation. The installed interpreter still proves
original authentication and protocol-specific issuer/alias meaning; source truth
is explicit, never defaulted. Mutable observations or I/O require their own owner.
An explicitly empty interval has no live instant and cannot attest a historical
admission window.

Known intrinsic app operations derive required owners and check immutable
Record/Connector class, resource family, own-app binding and group realm.
Profile-defined/unclassified operations cannot be used to erase classification
or reinterpret a native resource as a string. The initial closed intrinsic set
is not a promise to own every future platform operation. Actual new domain
meanings belong to their profile and use these same transitions.

`IDENTITIES.md` freezes Eudoxia-owned app/resource identity-v1 byte domains. Full
256-bit identities/origin labels differ from presentation, hosting/routing and
code selection. Class change makes a distinct identity; an ID alone grants no
entitlement. Class/compartment/issuance enforcement at actual native ingress
remains the embedding's obligation, not a process-sandbox claim.

## Bytes, replay and continuation

Every current effect owns its original byte value. Hashing uses streaming
frame 4 (`ENCODING.md`), including raw byte/key/digest fields, without a JSON
value tree or second framed body buffer. JSON convenience capture is explicit;
opaque bytes are never parsed or normalized for replay. Original external content
IDs keep their producer; resolved streams/verified blob handles stay resource-
owned and are bound by actual preparation, not a fabricated in-core I/O trait.

Report schema is v7 (unpublished); typed request wire is v2. Earlier frame-3
vectors survive only behind a test-only historical reader; production has no old
hashing branch. Replay re-evaluates the original purpose, context, bytes, basis,
evidence and time, returns data only, and rejects changed schema/context/verdicts.

Proofs are scope/guard-invariant, non-Clone and non-Deserialize. Ready owns its
exact Effect and Witness. Commit can hand off one Lease; each protected unit
consumes it, checks the owner's sweep contract and rederives/prepares/commits.
Only the resource output carries a successor. This is not global exactly-once:
durable intent/idempotency and budget consumption belong to the resource.

## Verification and extension

The whole gate is `python3 scripts/check.py`. The original acceptance assertions
are frozen (`fixtures/contract/`); test-only adapters translate retired
construction syntax and original signatures into the real
carrier/profile/scaffold. Compiler controls cover live construction, privacy,
invariance, effect substitution and linear use. Fault plants must compile and
cause the named behavior to fail. Missing/zero-test runs are not evidence.

An extension names its invariant, original producer, legitimate root/owner set,
one state owner and actual effect boundary. It supplies a profile/carrier/witness,
not a callback returning permission or an unchecked proof constructor. Authority
models and interpretation belong to the library; a native platform contributes
small carrier and effect adapters, not a second authority engine. Reference
fixtures do not establish native activation or actual I/O enforcement.

Native acceptance tests have their own package, `integration/`, which depends on
a svrngs checkout. It retains native failures without making another project's
migration the library's default test status; see `integration/README.md`.
