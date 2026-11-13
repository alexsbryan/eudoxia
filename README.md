# Eudoxia

Locks that enforce what a group actually agreed, for software with no landlord.

## The house with no landlord

Picture a big shared house. There's no landlord, no building manager and no
front desk. The people who live there run the place themselves.

They keep a **house book** on the kitchen table, with everything they've agreed
in it. Quiet hours start at ten. Priya's the treasurer this year. Nobody takes
the car out of state. When they change their minds, they don't rip out the old
page; they write the new decision and why. That book is
[**canon**](https://github.com/alexsbryan/canon).

A book doesn't stop anybody, though. Anyone can walk past it and help themselves
to the car keys. So every door, cupboard and drawer gets a lock that **reads the
house book itself**. That's **Eudoxia**.

### How the locks behave

**They check when you turn the handle, not when you were given permission.** Say
Ada wrote you a note on Monday letting you borrow her bike, then changed her mind
this morning. The lock knows. It doesn't care what was true on Monday. It cares
what's true right now.

**A note opens exactly what it says.** "Borrow the ladder" gets you the ladder,
not the drill sitting beside it. If you scribble "and the drill" on the note, the
lock can tell the handwriting isn't Ada's.

**You can pass a note on, but only a smaller one.** Ada lets you use the bike
until Friday. You can let your friend use it until Wednesday. You can't let them
keep it till next month, because you never had that to give.

**Some doors need more than one yes.** The shed belongs to Ada and Bo together, so
the lock wants both their notes. One person saying "it's fine, Bo won't mind"
doesn't count.

**"Not yet" is an honest answer.** Sometimes the lock doesn't say yes or no. It
says it's still waiting on Bo's note. That's better than guessing either way.

**Every time it opens, it leaves a slip in the logbook.** The slip says who opened
it, when, and on whose say-so. But a slip is a receipt, not a key: you can't wave
yesterday's slip at the door to get in again.

**Each lock does its own thinking.** There's no office to phone, because there is
no office. Each lock reads the house book and the notes in front of it and makes
the call right there, even when the internet's down.

### The catch

A lock only protects what's behind it. If someone leaves the cash on the kitchen
table, no lock in the world helps. So the job is to make sure the valuable things
sit behind a door, and that the only way to reach them is to turn a handle and
ask.

Same goes for helpers. Hire an errand runner, a person or an AI, to pick up
groceries with the house card, and you don't hand them the card. You give them a
note, "groceries, under $80, this week," and the card stays in a drawer with a
lock on it. They ask, the lock checks the note and the house book, and the drawer
opens or it doesn't. Tear up the note, and the next time they ask, it doesn't
open.

### Who this is for

Apartment buildings already have this sorted. The landlord hands out key cards
and can switch them off from the office, and there are plenty of good systems for
that.

This is for **houses run by the people who live in them**: apps where there's no
company in the middle and no admin with a master key, just people and the rules
they wrote down together. Canon is the house book. Eudoxia is the lock on every
door, making sure the house actually runs the way the house agreed.

## In technical terms

**Explicit authority, owned execution.** A pure synchronous Rust library
(`no_std + alloc`) for source-rooted permission, attenuated delegation,
independent-owner agreement and resource-scoped execution.

```text
trusted profile + original evidence + explicit time
    -> root / standing or delegated approval -> every required owner
    -> Justification(exact owned effect)
    -> real resource preparation Witness -> Ready
    -> fresh context check -> Authorized -> commit or linear continuation
```

Decision records explain and replay a judgment; they cannot authorize an effect.
Live proof values are invariant to their generative scope and concrete guard,
non-Clone and non-Deserialize. The real resource owns credentials, handles,
reservation/consumption, idempotency and I/O; the kernel has no clock, no
filesystem, no network and no authority server.

## Use

Define the resource's private action/guard/witness, install its legitimate
`Policy`/`Scope`/source interpretation, and supply authenticated ingress and
current coherent observations through `ResourceGuard`. Native carrier code owns
its original message and an audited projection through `NativeStatement`.
There is no built-in Eudoxia certificate format to issue or substitute for it.
A profile can state its request rules as data (`Rules`): closed conditions over
time, owner, resource and named facts, decided into a per-request `Basis`.

The complete compiling example is `examples/owned_resource.rs`:

```sh
cargo run --example owned_resource
```

`Request` explicitly distinguishes key/session/bearer/anonymous actors and
person/visit/no subject. `Request::profile` supports resource-owned personal or
public operations with the owner's fixed policy set. Known intrinsic app
operations additionally enforce immutable Record/Connector identity and exact
app/resource/realm binding. Profile-defined meaning cannot erase classification.
`Exercise` is the smaller key-authenticated descriptor; both use the same kernel.

Effects own exact bytes; fingerprints stream frame 4 (`docs/ENCODING.md`),
without per-byte integer framing or a JSON hashing tree. Evidence and authority
views are immutable and shared; evidence identity is captured once.
Interpretation deadlines and observation time are separate. Historical approval
is a distinct purpose, never a live-service grant.

The optional `canon` feature uses [canon](https://github.com/alexsbryan/canon)'s
pinned institutional interpreter under explicit arrangements and authenticated
identity mappings. It receives original Acts before short-ID deduplication,
preserves full native canonical pins, and rejects ambiguous source variants
rather than selecting authority from them.

## Verify

```sh
python3 scripts/check.py
```

The gate runs fmt and Clippy, the frozen original acceptance assertions
(`fixtures/contract/`), runtime laws, positive and negative compiler programs,
compiled behavioral fault plants (each must make its named witness fail),
independent Python vectors, the production-only example, and isolated native and
`wasm32-unknown-unknown` production builds with and without `canon`. Test-only
migration adapters preserve original assertions and signed fixtures; they are
not production escape hatches. A missing tool or failed command is never skipped.

## Read

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): the API, state owners and extension/trust boundaries.
- [`docs/CONTRACT.md`](docs/CONTRACT.md): implemented laws and their witnesses.
- [`docs/PROOFS.md`](docs/PROOFS.md): analytic invariants and impossibility results.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md): adversaries, semantic TCB and the limits of the guarantees.
- [`docs/IDENTITIES.md`](docs/IDENTITIES.md), [`docs/CONTEXT.md`](docs/CONTEXT.md),
  [`docs/ENCODING.md`](docs/ENCODING.md), [`docs/STATEMENTS.md`](docs/STATEMENTS.md): byte and API contracts.

## Layout

| Path | What |
|---|---|
| `src/` | The library. Only `derivation.rs` constructs authority; only `scaffold.rs` constructs the operational proof/witness transitions. |
| `tests/` | Laws, adversarial cases, reference profiles and compiler (`tests/ui/`) controls. |
| `community/` | `eudoxia-community`, a profile crate: one interpreter of a group's signed history. |
| `integration/` | Separate acceptance package against the [svrngs](https://github.com/alexsbryan/svrngs) native carrier; needs a svrngs checkout. See its README. |
| `fixtures/` | Frozen acceptance contract and independently produced vectors. |
| `scripts/` | The gate and independent vector producers. |

Native integration is the embedding's work: source constitution, recovery,
original-format projections, origins/issuance, real I/O and guest slots belong
to their native owners, using this library's one derivation path.

## License

AGPL-3.0-or-later. See [`LICENSE`](LICENSE). Security reports: [`SECURITY.md`](SECURITY.md).
