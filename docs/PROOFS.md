# Analytic assurance: the laws before the examples

Entire categories can be closed by analysis. Empirical observation is not the
foundation of the architecture. The machine, invariants, assumptions and proof
obligations are stated first; implementation checks test whether the code
realizes that machine. An attack example can refute a claim, but a collection
of examples is not the proof of a universal claim.

These are engineering proofs/arguments, not a claim of mechanized verification.
**Proved in the stated model**, **implementation obligation**, and **impossible
under the stated requirements** are analytic classifications. They are distinct
from passed/failed/could-not-judge/never-ran execution verdicts.

## 1. Model and assumptions

Let a protected exercise be:

```text
E = (realm, resource, operation, authenticated execution key,
     represented person, application, owned arguments/content handle)
```

A profile maps explicit evidence and observations to:

- a nonempty, fixed required-owner set O(E);
- source-derived authority R_o for each required owner;
- temporal requirements and mandatory resource conditions;
- any explicit continuation/recovery rules.

A scope denotes a set of exercises. Exact values, sets and canonical subtree
coverage are predicates; an explicitly configured Any is the universe for that
dimension. Delegation is subset restriction, not reassignment of an identity.

The legitimate root selection is an explicit premise. The native interpreter
must prove that its facts follow from those roots and authenticated native
evidence. The resource must prove that its actual operation, state transaction
and I/O correspond to E. A generic kernel cannot establish these premises by
renaming an input Trusted or Known.

Cryptographic premises are signature unforgeability, adequate collision/preimage
resistance for the actual identities used, domain separation and faithful native
encoding. Memory/type premises are sound safe-Rust privacy, ownership and
lifetimes. Key/clock compromise is analyzed separately, not silently excluded
from the model after a failing example.

The composed safety statement is: every protected Commit(E) has a derivation
for every required owner under the declared authority context/purpose, actual
matching preparation, and the resource's valid commit/continuation conditions.
P1–P4 establish the inference/construction part by induction and ownership;
the native/source/resource obligations in §4 establish that those symbols mean
the real actor, entitlement, target, time and effect. Naming the latter premises
is not their discharge. This distinction prevents both empirical-only assurance
and a proof that hides the entire authorization problem in an assumed true fact.

## 2. Category-level construction results

### P1. Delegation cannot amplify authority

**Proof.** A root begins within its configured R_o. Issuance requires child scope
S_0 subset R_o. Every subsequent delegation requires S_(i+1) subset S_i,
the previous holder as issuer, the same owner/source lineage, and bounded
redelegation. By induction, every reachable chain scope is a subset of R_o.
Exercise requires the actual holder and membership of E in that final scope.
Therefore no sequence of lawful steps can acquire authority outside R_o.

This closes *all lengths/compositions* of lawful delegation, not merely seven
field mutations. It is conditional on faithful native-to-scope interpretation;
a lying interpretation changes the premise, not the subset theorem.

Implementation correspondence: `Scope::covers`, `Root::{establish,issue,narrows}`,
`Chain::{delegate,exercise}`. Stable identities/application constraints and
interval/operation/coverage inclusion are all conjuncts of the subset relation.

### P2. Combining owner approvals cannot manufacture a missing owner

**Proof.** Each Approval binds one owner, the same authority context and E.
Agreement requires exactly the fixed nonempty owner list, one matching Approval
per element. Thus Agreement(E) implies, for every o in O(E), o approved E.
Equivalently, the effective right is inside the intersection of required-owner
rights. Reordering, adding unrelated proofs or omitting a proof cannot remove an
element of O(E). One owner's yes cannot negate another owner's no/unknown.

Implementation correspondence: the resource supplies `Basis::policies`; it is
not inferred from the request's proof subset. `Agreement::all` checks cardinality,
owner ordering, basis and effect equality. The native factory still owes the
proof that O(E) actually names all owners of that operation.

### P3. Reports cannot be laundered into protected execution

Enumerate the complete implemented constructor graph:

```text
Root -> Chain or standing Approval -> Agreement -> Justification
    -> resource preparation witness + Ready -> Authorized -> commit
```

Agreement's constructors are private to derivation. Justification requires that
Agreement; Ready requires its consumed Justification and the real guard's witness;
Authorized is constructed only by execution after refresh. These values are
scope/guard-invariant and not deserializable. Observational records/traces have
no edge into this graph. Therefore arbitrary JSON, a Permitted enum, an old
record, a partial owner report or a marker cannot construct protected authority.

The higher-ranked scope prevents branded values escaping into the callback's
scope-independent result; invariance prevents changing the brand or guard type.
These type rules cover the category rather than one compiler program per forgery.
The protected-I/O perimeter remains an obligation: every native entry point must
use that API, and arbitrary code already owning sockets/files is not sandboxed.

### P4. Exact-operation substitution is excluded at the handoff

**Proof.** Capture E and its owned byte value/handle before derivation. Approval
and Agreement bind its identity. Preparation sees that same E. Ready owns E and
its witness. Execute accepts Ready alone, with no replacement target/body/action.
Commit consumes those owned values. Consequently an external caller has no
parameter through which E' can be substituted after E was authorized.

Collision resistance and faithful canonical target resolution are premises.
A resource witness must bind the actual resource instance, actor/use generation
and E, not merely an integer reservation number. A string that is re-resolved
to a different file/endpoint after authorization violates that premise; an owned
resolved handle closes that alias/TOCTOU category. For streaming transport,
authorize the owned stream-use identity rather than claim all future bytes were
known. Body-sensitive operations must capture/verify their actual body first.

### P5. Evidence arrival order need not be an authority input

**Proof.** Let interpretation be F(profile, authenticated evidence set, explicit
observation). Union/deduplication of that set is associative, commutative and
idempotent. Equal sets therefore give equal answers independent of delivery
order or duplicate count, provided F is deterministic and uses no arrival state.

The evidence set can grow monotonically while authority *decreases*: a discovered
fork or cut can retract a conclusion. Therefore a cache that only unions granted
rights is unsound. Incremental interpretation must equal F of the current held
set and must support invalidation/retraction. It must retain relevant source
objects, not discard colliding/forked objects by a convenient sequence/path key.

This is a design obligation for the actual native interpreter; the RootInterpreter
trait name or an append-only journal does not establish it.

### P6. An authority fork cannot restore the seed by exclusion

Define office state as distinct cases Held, Frozen, Missing and Vacant, with
explicit sources. Genesis establishes the initial holder once. A valid transfer
derives from a uniquely justified predecessor. Genuine competing successors
produce Frozen for dependent powers. Neither Frozen nor Missing is Vacant or a
new Genesis. Resolution must derive from an uncontested authorized procedure.

By case analysis, removing a candidate transfer cannot take the Frozen case
through a missing-holder fallback back to the seed. This eliminates the entire
"filter conflicting changes, then regain old powers" construction. It requires
the native domain representation and every caller to preserve those cases;
a native `keeper: Option` with whole-group unsettled behavior is not that proof.

Only source-valid authority successors participate in this conflict rule.
Otherwise an outsider could freeze powers with arbitrary signed or forged junk.
Unrelated powers/data/ordinary exit do not depend on that office and stay separate.

### P7. One owned lifecycle transition has no implicit resend/revival edge

Model resource state as Pending -> Active -> Closed. Start consumes the one
pending owned request/reservation. Check requires an existing admitted use and
can only produce its next active state. It cannot transition back through Start.
Stop/failure consumes the continuation with no successor. There is no Closed ->
Active edge without fresh admission.

This closes implicit POST resend, slot re-acquisition and stopped-token revival
by state-space design, rather than remembering exceptions in each sweep. The
kernel consumes its Lease and returns only resource output. The native owner
must realize those private Start/Check/Closed transitions and hold the original
socket/slot. An authorization record is not evidence that an active use exists.

This is not global exactly-once execution: a new lawful operation can be admitted.
Exactly-once/idempotency needs a durable consumed-intent state in the resource's
atomic transaction, and no second commit for that intent.

### P8. Kernel signature work has a structural bound

Let root onward budget r be the configured u8 value, so 0 <= r <= 255.
Issuance returns a budget <= r. Each subsequent lawful step strictly decreases
that nonnegative budget. Hence at most r+1 proof steps can succeed. The next
step must fail; lazy evaluation cannot consume the rest of a submitted suffix.

Thus kernel proof-signature checks per delegated owner are at most r+2 <= 257;
an admitted historical receipt adds at most one more kernel signature check.
If the first failure is at position k, at most k proof steps are authenticated.
This follows from the control flow and well-founded budget, for arbitrary input
length; the 66-proof chain rejected after at most 2 proofs are decoded/verified
in `tests/adversarial.rs` is a regression witness, not the proof.

Scope: one evaluation and a fixed trusted owner list. A one-shot attempt performs
at most the derive/prepare/execute evaluations; arbitrary repeated requests need
an ingress quota. Extra work *inside* a codec, message lengths, record hashing,
memory, graph traversal and storage are separate bounds, not covered by counting
kernel signature calls.

### P9. Intrinsic class restrictions survive owner/delegation composition

For classified identity a, define F(a) as the exercises with its permitted class
operations and matching resource family/app/realm. Every native Approval(E)
requires E in F(a) as well as the owner's scope. Agreement requires all such
Approvals. Thus its exercises are in F(a) intersected with every owner's scope;
adding/composing grants cannot introduce E outside F(a). A forbidden untrusted
grant can exist as bytes but cannot construct an Approval. Class/realm/name are
immutable definition inputs; changing them creates another digest/origin under
the cryptographic premises, not new rights for the old identity.

Correspondence: `identity::check_context` is consumed before `derive_owner` can
construct any standing/delegated Approval. Legacy strings are distinct; mixed
contexts return a typed need and native guards compare the structured operation.
`Coverage::contains` preserves that distinction even for the legacy Tree API.
Deserialization reconstructs private identity caches from validated definitions.

This result applies to the refined execution path under authenticated
context and legitimate fixed-owner/profile premises. It does not authenticate
an app merely because its descriptor parsed, turn unclassified profile IDs into
classified native identities, establish native issuance/origin/storage isolation, or make the
native source interpreter complete. Those remain explicit integration obligations.

### P10. A shared app database's sets end alike on every copy

Model: each device signs change sets at `seq` 0, 1, 2, … in a merged app
database. A copy holds a record R and a set Φ of fences, each fence
`(by, d, mark)`. Premise: what the rules read of R is cumulative as R grows.
That is a key's binding to a person and device kind, and a Remove that took a
key. The rules never read standing now. A copy applies a taken set, drops a
refused one for good, and holds one that waits (`community/src/db.rs`).

*Owned rows.* A change to a row whose key's first value is v is taken iff R
binds the signer to the person whose key is v, as TEXT of exactly its bytes,
or the change is a delete and R holds a Remove for every key it binds to that
person. It is refused iff v is not such text, or R binds the signer to
another person and the change is a write. Otherwise it waits. Each input that
decides taken or refused is cumulative under the premise, so every taken or
refused verdict is final as R grows.

*A removed device's sets.* Let C(R, Φ, d) be the fences in Φ for d whose
signer R binds as a computer, where R holds d's Remove. The cut is
m = min{mark(f) : f ∈ C}, with none below every seq. A set (d, s) is taken
iff R holds no Remove of d, or s ≤ m. It is refused iff s > m. It waits while
R binds d to nobody, or C is empty.

1. **Order.** The verdict reads only (R, Φ, s). A minimum over a set does not
   depend on the order its members arrived in.
2. **Refusals are final.** Under the premise, C only grows as R and Φ grow.
   A minimum over a growing set never rises, so s > m stays true. A copy that
   dropped a refused set never needs it again.
3. **Convergence.** Copies that come to hold the same R and Φ have the same m.
   A copy applied too much only if it applied some s > m. That copy rebuilds
   from a source that applied nothing past m, and then it holds exactly the
   sets every copy takes.

Taking a set is not final: a lower fence can arrive later and force a
rebuild. No rule over unbounded fences makes both verdicts final. The
maximum makes taking final, but then a refusal is never final, and any one
fencer could let in sets past the cut. The minimum fails closed: a fencer
can only refuse more of a removed device's sets. Choosing it costs
availability, never integrity. A fence that names a device R holds no Remove
of waits. So no fence reaches a device that stands.

Limit: the record's own disputed cases, such as a fork that takes a binding
or a cut back, fall outside the premise. They are settled by P5/P6, not
here.

## 3. Analytic limits and the choices they force

### I1. Hidden distributed history cannot supply a global negative fact offline

Consider two executions with the same local input at verifier B. In one, nobody
issued a relevant read grant. In the other, partitioned A issued one but B has
not received it. B cannot distinguish the executions. If honest offline writing
must work in the first, B permits it in the second too. This contradicts a rule
requiring global sticky rejection after that hidden read.

Therefore the conjunction of (a) a cross-replica global constraint, (b) private/
unavailable relevant history and (c) unrestricted offline authorization is
impossible in this model. More tests do not resolve it. Choose a scoped serial
authority/epoch, conserved exclusive authority, an immutable permission class,
coordination, fail-closed availability, or a weaker explicitly local/eventual
guarantee. The actual scope/authority choice requires an explicit construction.
The selected native construction in `ARCHITECTURE.md` §3 takes the intrinsic
Record/Connector class option described next; no private-history oracle is part
of that construction. Its implementation obligation is identity/issuance/
compartment preservation, not discovery of a global negative fact.

One constructive alternative is an immutable writer/reader capability class
bound into application authority identity: issuance to a writer cannot produce
external-read authority, and issuance to a reader cannot produce group-write
authority. Class cannot change under the same authority identity on Stop or code
update. Induction over issuance then proves that identity cannot acquire both;
the proof does not query hidden negative history. Credential/process boundaries
must prevent ambient authority from bypassing the class. This proves a scoped
authority property, not arbitrary information-flow security (I5). It changes the
policy from private grant history to an intrinsic class, so it is an explicit
design choice, not a silent reinterpretation of the native contract.

### I2. A shared cap needs conserved allocation or coordination

Independent verifiers each observing spare capacity cannot all spend the same
unallocated global slot while guaranteeing a hard global cap. The same
indistinguishability argument applies. A signature can authenticate a promise;
it does not make that promise consumable only once across independent stores.

A sufficient conservation design is: allocate non-overlapping quotas q_i with
sum(q_i) <= C; each resource owner atomically keeps local active_i <= q_i; transfers
conserve rights and cannot leave both owners able to spend the same allocation.
Then sum(active_i) <= sum(q_i) <= C by arithmetic. This permits local operation
without a universal per-request service. Allocation/transfer authority and
availability still need explicit contracts; offline duplicable bearer tokens
alone are not this construction.

For historical guest admission, persist the admission/denial and its legitimate
allocation source so later capacity does not rewrite the past outcome. This
does not prescribe a new group cap, per-host cap or hidden coordinator.

### I3. Remote instantaneous revocation and partition availability conflict

If the verifier's input has not changed when another replica revokes, it cannot
distinguish revoked from unrevoked operation. Immediate global rejection and
available disconnected use cannot both be promised. A local timer/recheck bound,
short lease, authoritative online verifier or explicit availability restriction
is necessary. Already released information cannot be recalled.

The native resource must define when admission linearizes, which sources/epochs
are rechecked, and whether Stop affects new or active use. For transaction-local
state, atomically compare the relevant generation and consume conditions at
commit; no stale witness crosses that point. An async wait cannot preserve a
freshness claim automatically. These are protocol/state laws, not measurements.
Measurements validate scheduling/I/O meets the declared bound.

### I4. After signing-key compromise, a claimed earlier time is not evidence of creation time

An adversary knowing key k can compute the same signature on (message, sources,
claimed time) that an honest earlier signer could compute. A verifier receiving
only those values has no distinguishing information. A signed claimed timestamp
or expiry check cannot prove the attestation predates compromise.

Historical creation-time assurance requires an independent preexisting anchor,
trusted monotonic source/hardware, a constrained compromise policy, or a weaker
guarantee. Confining the key's permitted subject/target/action remains valuable
and independently provable. The compromised-admitter assay illustrates this
limit; it is not a problem waiting for enough observations.

### I5. A label or per-operation allow decision is not information-flow control

If a process can read value x and can independently send arbitrary payload y,
it can choose y = encode(x). Both operations can satisfy their authorization
predicates while the data flows. Preventing that flow requires structural
separation of authority/processes or an actual data-flow/noninterference model;
renaming the process or checking the two operations separately is insufficient.

Likewise, two programs controlling the same key and producing the same signed
message are indistinguishable to a signature verifier. An app label authenticates
the authority namespace selected by its signer, not which remote code ran.
Code identity requires a separate integrity/attestation premise. A scoped worker
must not possess an ambient full-person key if the design relies on limiting
it to that scope. This is a capability/process-boundary requirement, not a test
that can discover good intent.

### I6. A legacy statement cannot prove a dependency absent from all its evidence

Where neither signed references, causal ancestry nor a trusted admission anchor
establishes which power an old statement used, consider two histories yielding
the same presented statement: it was created legitimately under the relevant
power, or the same key created/backdated it without that power. The verifier has
no distinguishing information. Re-signing/re-encoding the statement now does
not reveal its earlier provenance.

Existing signed ancestry may settle particular legacy cases and should be used.
For the genuinely indistinguishable remainder, select a legitimately authorized
accepted prefix/checkpoint, obtain additional trusted evidence, leave it
unresolved or explicitly choose weaker semantics. This is why migrating legacy
native history needs an explicit rule. It is not an empirical question that more arbitrary old journals
can universally answer.

## 4. Extension obligations: preserve laws rather than accumulate cases

Every extension supplies its changed premise/transition and a preservation
argument. It does not add a new executable permission path.

| Extension | Required analytic obligation | Current generic API alone proves it? |
|---|---|---|
| Native carrier | One immutable parsed statement owns encoding and meaning; valid signature authenticates that statement; projected rights are no greater than its native meaning under the explicit profile binding | The API couples parsed/verified/consumed projection; the concrete carrier still proves semantic correspondence. |
| Native constitution | Root legitimacy, identity, referenced entitlement, conflict/cut/admission rules; deterministic set interpretation and scoped retraction | No. RootInterpreter/Basis are the boundary, not authentication. |
| Resource/profile | Canonical actual target, complete required owners, exact actor/action binding, dependency footprint and observation validity | Only the configured conjunction/construction, not correctness of the factory. |
| Resource condition | Private witness represents actual resource/actor/generation/effect; reserve/consume/release atomic; unknown conditions cannot be skipped | No. Guard transitions enforce possession, resource module proves witness meaning. |
| Continuing I/O | Unique owned-use state; checks cannot restart; all physical I/O gated; idle/non-reading clients cannot suppress rechecks | Kernel lease path is closed; native state/I/O realization remains. |
| Cache | Same output as fresh interpretation for all relevant source/deadline changes, including retraction | Immutable snapshots/deadline checks help; native index equivalence remains. |
| Diagnostics | Observable reasons follow actual derivation; public outputs contain only caller-authorized data | Reports follow derivation; redaction/disclosure policy remains. |

For signed meaning, a pair of arbitrary callbacks named encode/claims is not a
proof. The trusted native module must parse once into a private immutable
statement, compute its canonical native signing message and semantic projection
from that same value, and prove the projection respects the protocol. Contextual
identity normalization must come from separate authenticated bindings, never
unsigned scope widening. New native formats preserve original bytes; no new
universal policy language is implied. The open Codec interface therefore
does not analytically close every possible adapter, even though the normalized
kernel's attenuation theorem is closed.

### Native reach-pass lemma

The projection of a native svrngs reach pass is sound and complete, within
the lemma domain, by the argument sketched below, under canonical authenticated key ingress, explicit
time, legitimate original-issuer/person binding and the cryptographic premises
above. The message is the original native producer's, not an Eudoxia
certificate. Length framing and the distinguished approver tag make that grammar
unambiguous.

The important distinction is **app reach versus the signed read set**. Project
the whole scope to disjoint own-app/read resource names. Then, with unchanged
application, coverage inclusion is equivalent to the native read-subset rule,
including when the child tries to add the app itself as a read. A union of
untagged app/read labels does not preserve that rule. Root/link budgets 1 -> 0,
kernel signer/holder continuity, equal person from the established binding and
exclusive interval inclusion supply the remaining native direct/link conjuncts.
The original person's authority is preserved at the execution key; the link
issuer/worker host never replaces the represented person.

`integration/tests/reach_projection.rs` uses native `Pass::sign`/`message` and the
existing sealed derivation/resource path, and compares the projection with native
`carries` across signed-scope, presentation and time changes. These check
correspondence to the argument; their number is not its proof. Lender/person
consent and HTTP method policy remain independent.

**Not a full public-API equivalence.** Native `check` accepts arbitrary holder
strings and uses literal key spelling; its verifier/error precedence differ from
the kernel. `the_native_public_string_api_is_not_identical_to_canonical_key_ingress`
in the same file records an out-of-domain difference. An embedding that adopts
this projection owes the resolution of those compatibility obligations and must
not leave a competing evaluator in place; native integration is the embedding's
responsibility. Native sources: svrngs `pass.rs::{message,check,carries}`,
`sig.rs::{field,verify_hex}`.

### Source identity obligation

Authority references must preserve actual full-strength identity/domain binding,
not just have a field called hash. svrngs native IDs bind the full BLAKE3 digest
and group namespace (`sig.rs::{act_id,derive_id}`). Canon's short display ActId
keeps 48 bits (`canon-core/id.rs`), while its signed `refs` deliberately pin full
SHA-256 (`canon-core/sign.rs::{canonical,digest,prepare}`). A hash of the short
label does not recover lost entropy. Use the actual verified full pin/anchor
semantics at authority boundaries and preserve distinct objects/conflicts.
The canon adapter (`canon` feature) validates the original set before constructing
Log, rejects conflicting content/signature variants and carries canon-produced
full canonical SHA-256 pins. A caller must supply the held originals; feeding an
already lossy set cannot recover discarded conflicts. These preconditions are
explicit, not inferred from SHA-256's name or a few random IDs.

The legacy svrngs computer Label also appends a truncated name hash to a node
key (`pass.rs::Label::of`). That is not a full 256-bit origin-identity proof for
names chosen under that owner. The selected construction instead encodes a full
authority descriptor digest and obtains routing from an authenticated binding;
capability class and storage isolation do not rest on that short name suffix.

Canon's `Log::from_acts` also deduplicates by the short ID before its consumer
interprets it. A consumer cannot recover a conflicting object already discarded
there. The native/canon boundary must establish the full pin and conflict-
preservation obligations before that lossy construction, or use an appropriate
versioned input representation. Signed full refs are useful existing machinery;
they do not justify assuming every earlier short-ID operation is collision-free.

### Coverage of the behavior families

The acceptance behaviors are listed in `CONTRACT.md`.

| Behavior | Analytic basis / remaining premise |
|---|---|
| Source-linked acts, admission/cut, handover and fork | P5/P6 plus the actual native entitlement, consent, cut and signed-reference rules; no timestamp-derived office authority |
| Exact bodies; native chains preserving person/app/execution identity | P1/P2/P4 plus the native statement/projection and identity-binding lemmas |
| Standing offers/consents and bounded visitor scope | P2/P4; audience/coverage and source ownership; I2 for the separate global/historical visit-cap contract |
| Author corrections | P4 plus stable-person and target-author derivation, never name equality |
| Historical admission receipts | P4 plus an honest scoped historical witness; I4 states the compromise limit |
| Continuations and contended reservations | P7, resource transaction/epoch correspondence, and I2/I3 for distributed capacity/revocation |
| Selected code and acceptance | P4/P5/P6 plus application activation/acceptance ownership and immutable selected content |
| Records and reports | P3/P4 and caller-scoped rendering; a report is not a proof constructor |
| Read-grant history versus delegated writes | I1 first forces the private-authority/scope/availability choice; the selected protocol must then preserve P1–P7 |
| An app database's owned rows and a removed device's sets | P10 plus the carrier's correspondence: it judges every change row and set it applies, it keeps its fences through a rebuild, and it resends only from a copy within the cut |

## 5. Assurance and the next feature

The architectural bar is:

1. State the desired effect/guarantee and attacker knowledge/control.
2. Define authority/state/source scope; check the guarantee is jointly possible.
3. Identify the allowed constructors/transitions and prove invariant preservation.
4. Discharge native interpretation, root, resource and cryptographic premises.
5. Check the implementation realizes those laws; use counterexamples, compiler
   checks, differential/fuzz/race/load tests where they can refute a mismatch.

Tests are instruments for the last step and for discovering a false premise;
they are not the reason P1–P8 or I1–I6 hold. Performance/timing/OS behavior still
need measurement, and proof/analysis still needs review. Neither silently
substitutes for the other. N+1 changes a named premise or transition and owes a
preservation argument, rather than another isolated check that happened to pass.
