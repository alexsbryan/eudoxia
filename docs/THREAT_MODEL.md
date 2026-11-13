# Threat model

This document covers the library. It is not a security sign-off for any native
embedding: each native embedding (for example svrngs) must discharge its own
carrier, parser and resource-bridge obligations, both analytically and by
implementation correspondence.

`PROOFS.md` is the primary category-level argument. Its constructor invariants,
conservation proofs and indistinguishability results do not depend on observing
attack examples. The experiments here validate implementation correspondence
and expose false premises; they are not prerequisites for deriving those laws.

## 1. What the adversary may control

Assume hostile outsiders, app/worker code, delegated execution keys, ordinary
members and officeholders. They may send arbitrary bytes, sign malicious claims
with keys they actually hold, choose timing/delivery/replay, withhold evidence,
race operations, equivocate, ignore backpressure and attempt resource exhaustion.
Signatures authenticate a signer and bytes; they do not establish entitlement,
honesty, complete history, a trustworthy clock or benign intent.

Protected assets are the exact resource effects and their attribution, native
history/identity integrity, private keys/credentials/private consent, and the
availability/bounded consumption of the node's resources.

Distinguish an adversary at those inputs from compromise of a trusted component.
The library is not an OS/process sandbox and cannot constrain arbitrary code
already owning a resource, a full person key or the node's address space.

## 2. Conditional guarantees with concrete counterexamples

Under legitimate configured roots, correct installed interpretation, authenticated
ingress, truthful current observations and a correct protected resource API:

| Attack | Required outcome / evidence |
|---|---|
| Forge a grant, self-adopt a root, modify a signed field | Strict signature/root checks, zero protected effects; original acceptance/canon cases and native transcript mutations. |
| Widen operations, target, app, represented person, interval or onward depth | Refuse; seven original signed widening dimensions and native narrowing controls. |
| Substitute carrier/host authority for the represented person | No fallback; stable-person/execution-key and eligible-source bindings; native adapter positive and wrong-person/group controls. |
| Supply only one owner's proof or choose a permissive carrier | Required-owner conjunction and per-policy carrier whitelist; sixteen-pair truth table, missing/absence distinction, alternate legacy-carrier rejection. |
| Swap body/action/resource/context after permission | Owned effect plus scoped proof/witness transitions; runtime exact-body/receipt checks and compile-fail action/guard/scope substitutions. |
| Replay an audit result as power | Record has no conversion to executable proof/lease; replay produces data only. Original proof and continuation compiler controls. |
| Backdate new content or reuse another entry's historical receipt | Exact effect/source/authorized-admitter binding; covered instant/window; historical approval cannot authorize a live call. |
| Race the last slot, cancel after preparing, substitute another reservation | Resource owns atomic reservation/consumption; actual threaded last-slot case, RAII release, native-shaped resource identity/generation control. |
| Keep a stream by not reading, repeat a POST during sweeps, change Stop scope | Native owner must schedule/terminate independently of reads. Adapter witnesses keep one slot/one POST and preserve future-only Stop; each native embedding must establish this for its own timers/transport. |
| Feed a known-broken chain an expensive validly signed suffix | Stop parsing/authenticating at the failing prefix; actual red/green work-count witness in `tests/adversarial.rs`. |
| Compose class-forbidden rights or relabel a native target via a legacy path | Refined class/context checks before Approval, exact native coverage, typed missing context and bound guard operation; `tests/identities.rs`. Native compartment/issuance enforcement is the embedding's obligation. |

These are sampled counterexamples and construction protections. Their count is
not an attack-detection rate, an exhaustive proof or a substitute for native
integration/fuzzing/review.

## 3. Hostile authorized actors and incomplete replicas

An officeholder can sign conflicting branches. The selected rule freezes the
affected powers, never restores the forker or seed keeper. A forged sibling must
not trigger that freeze. This deliberately limits authority theft at the cost
of a possible denial of service. Recovery cannot let the forker choose the rule
or eligible voters. Independent data/powers and ordinary exit must remain usable.
Reference profiles model these rules; they do not correct a native
implementation, which must enforce them itself.

A withholding or partitioned peer can make evidence unavailable. Required
missing/contradictory sources must cause WAIT, not permission or authoritative
absence. A source reference proves a dependency, not global freshness or the
absence of unseen changes. The system must declare its verifier/propagation and
revocation bounds; it cannot promise instantaneous distributed revocation or
recall bytes already released.

Native embeddings carry these further construction obligations:

- Immutable Record/Connector identity removes the private-history negative
  query; class/origin/issuance checks must cover every native path before any
  history gate is retired. The library implements the common-kernel refined
  identities and exercise restriction (`IDENTITIES.md`), not native
  activation/origin/issuance or retirement of such a gate. The private-history
  test fixture is not that mechanism.
- Conserved positive guest-slot admissions replace partial-view recounting.
  Pending/offline capacity remains unavailable, and controller equivocation
  freezes its slot; no instant globally consistent physical occupancy is claimed.

Within legitimately granted scope, a malicious member/app may still perform
harmful allowed actions. Narrow rights, resource-local rates/quotas and safe app
business rules matter. Identity correctness is not intent correctness, and an
application label does not attest which code a remote machine executed.

## 4. The trusted computing base is explicit

| Boundary | What it must actually establish |
|---|---|
| Native root interpreter / `Basis::interpreted` | Legitimate roots, entitlement, required-owner set, causal/conflict/cut rules, complete *relevant* evidence or a named need. The constructor checks structure, not truth of facts. |
| Installed carrier parser/projection | One owned native statement supplies original signing bytes and is verified before consuming its projection. The concrete projection must faithfully preserve native meaning and only root-validated normalization. A trait cannot prove this semantic obligation. |
| Ingress / resource `actor` and `operation` | Actual authenticated execution key, stable person under the eligible group, actual target/action. Claimed headers/names/operation strings are not authentication. |
| `current`, clock and source snapshot | Coherent, sufficiently current inputs and explicit cache deadlines; no frozen requester time or mixed versions that never coexisted. |
| Resource `prepare`/`commit` / async owner | Real correctly bound witnesses, every mandatory condition, atomic final checks, exact owned target/body/stream, correct effect/outcome and ongoing termination. |
| Key storage and execution environment | Worker gets only its execution key/scoped evidence; person/approver/backend keys remain confined according to their actual trust model. |

`tests/adversarial.rs::installed_codec_semantics_are_inside_the_trusted_computing_base`
is a **compromise assay**: the honest codec refuses a write; an installed lying
codec adds write to read-only signed meaning and the backend is called. The
original signature stays valid. This is not an untrusted caller selecting code
and not a claimed successful security refusal. It demonstrates the assumption.

The assay also keeps the same logical codec/profile ID: the basis fingerprint
does not hash callback implementation code. Native deployment must use a pinned,
reviewed, versioned registry and preserve semantic/version consistency across
nodes. Network/app inputs cannot install codecs, roots or ready witnesses.
Independent producer vectors and semantic mutation tests are mandatory for each
adapter; avoid multiple handwritten interpretations of the native transcript.
The common API takes an owned parsed/verified/projected statement under the
explicit profile binding, not an independently supplied transcript/claim pair.
The integration package (`integration/tests/`) uses svrngs's own `Pass::message`
producer, not a second transcript; the library crate has no svrngs dependency.
The assay intentionally installs a lying compiled projection; each concrete
native profile still needs its own semantic proof. Requests cannot install one.

A compromised approver can lie about when it admitted new content. A compromised
person key can exercise that person's rights. The kernel does not distinguish
an honest signature from the same key used maliciously. Scope confinement,
revocation/compromise policy and any independent historical anchor must be
explicit; expiry alone cannot prove that a forged historical attestation was
created earlier. No new global authority service is implied as a hidden remedy.

The second compromise assay in `tests/adversarial.rs` actually creates new
content at the simulated post-expiry observation, signs a false earlier
admission with the compromised key, and observes historical execution. It also
checks that this key cannot widen the configured resource scope or use that
receipt for a live call. This establishes the boundary, not a claim to prevent
backdating after the clock witness's key is compromised.

## 5. Availability is not hardened by the current permission tests

Eager verification would decode/verify every real-signed proof in a chain
even after a broken link. `steps` is lazy. A good chain executes; a bad prefix
consumes at most two decodes regardless of the suffix:
`tests/adversarial.rs::invalid_prefix_does_not_force_verification_of_an_attackers_suffix`
supplies 66 real-signed proofs with link two broken.
Validation still checks all relevant narrowing/holder/source/time facts.

This bounds that **cryptographic suffix amplification**, not the whole request.

There is also a universal structural bound: a root's u8 redelegation budget
r allows at most r+1 successful proof steps; the next must fail. Lazy evaluation
therefore performs at most r+2 <= 257 kernel proof-signature checks per delegated
owner/evaluation, plus an optional admission receipt. `PROOFS.md` P8 derives it;
the 66 -> 2 observation only checks correspondence for one case.
Evidence capture fingerprints the supplied bytes once; recording/refresh reuse
that immutable identity. Byte parsing,
hashing, allocations, dependency lookup, graph interpretation, storage and queues
need explicit budgets at their owners, before expensive work where possible.

The earlier frame-3 encoding framed raw bytes as one integer frame per byte,
plus a temporary Value tree; frame 3 survives only as a historical test reader.
Every production context uses streaming frame 4 (`ENCODING.md`) with raw byte
fields and shared cached evidence; a 65,536-byte raw body frames to 65,545
bytes (`encoding::tests::raw_body_has_one_length_frame_not_one_integer_frame_per_byte`).
Streaming alone supplies no parse/graph/queue/disk quota. A native receiver's
message-size limit is not a universal proof of bounded
CPU/heap/queued/cumulative-disk cost. Streaming or
digest-checked owned handles and format-preserving streaming hashing need their
own measurements before treating large inputs as safe.

Native hardening must cover malformed/oversized/deep/repeated inputs, signature
floods, missing-source fan-out, cyclic/long graph handling, cheap rejection,
per-peer/actor work and retained-evidence growth, bounded pending I/O, and
independent users making progress under load. Derive bounds from the actual
protocol/resources; do not invent a permissive fallback or silently raise a cap.
Offline grants are not shared decrementable budgets.

## 6. Confidentiality, replay and security completion

Resource credentials stay out of grants/claims and are injected locally only for
the authorized operation/account. An authority derivation is not a general body
redactor or information-flow system: a malicious backend can echo a credential
in an opaque response.
Use correctly limited backend accounts and actual response/log leak controls.

DecisionRecords include request arguments and source-linked diagnostics. They
are neither tamper-proof audit receipts nor automatically safe public replies.
Render only caller-authorized context and deliberately redact logs; do not expose
another person's private choices, hidden groups or submitted secrets by dumping
Debug/record data. Hashes and metadata can still disclose correlations.

Non-Clone proof/lease types are not exactly-once execution. A fresh lawful
derivation may repeat an allowed request. Durable native IDs, idempotency and
budget consumption belong to the resource's transaction and witnessed state.

Adversarial readiness of a native embedding requires its
interpreter/codec/ingress/resource matrix, independent semantic checks,
bounded-work/fuzz/race tests, and regressions of its real scenarios. Keep all
known-bad controls as positive use cases are enabled. A passing scaffold gate is
evidence for its named checks, not a security sign-off on native boundaries it
does not implement.
