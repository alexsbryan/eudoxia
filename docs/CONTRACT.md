# Contract and implementation witnesses

`PROOFS.md` gives the analytic assurance model and extension obligations. The
cases below are implementation/refutation instruments for that model. Their
passing count is not the derivation of its invariants or impossibility results.

This contract covers the library. The reference profiles exercise its laws
through the same sealed evaluator and resource transitions; they do not establish
native journal, pass/link/approval, browser or transport results. Native
integration witnesses live in `integration/` and document their own status in
`integration/README.md`. The library implements the refined identity/context
subset of `ARCHITECTURE.md` described below; the complete native mechanisms are
not implemented by the reference private-history fixture or the carrier API alone.

The same exercise, basis, evidence and explicit time produce the same record.
These are conditional guarantees under `ARCHITECTURE.md`'s trust boundary, not a
claim that user-supplied history or clocks authenticate themselves.

| Law | Acceptance witness |
|---|---|
| Explicit roots | A canon-backed basis comes from explicit initial arrangements and admitted standing, not an empty/open scope or raw Projection. |
| No self-adoption | A proposed grant cannot supply its own voter; an existing authorized person's approval is the positive control. |
| Attenuation | Signed delegation reaches a distinct execution key; changing any signature-covered term or widening target, operation, identity, time or delegation is refused. |
| Complete ownership | Both independently required owners must permit; caller omission cannot remove an owner, and zero owners cannot permit. |
| Explicit outcomes | Refused, NotApplicable, Undetermined and Permitted remain distinct. Needs identify owners, issuers, source references, conflicts, unsupported codecs or missing admission. |
| Mandatory means mandatory | Unknown and understood-but-unenforceable conditions prevent any execution. Advice cannot supply a missing permission. |
| Exact time | Start is inclusive, expiry exclusive; parent limits and later delivery do not extend live rights. |
| Record is not authority | A serialized record replays only against its exact basis/evidence; replay cannot construct Justification, Ready or Authorized and never performs an effect. |
| Stable identities | Equal display names cannot merge keys. This core stores no display names. |
| Canon preservation | Bound effective native sources, arrangements and operational mappings identify authority; unrelated questions and clock ticks do not edit it. |

Owner combination, independent of input order:

- Any explicit refusal or a required owner's NotApplicable makes the final
  result Refused; unresolved other owners remain visible in the record. Known
  absence of applicable authority suffices to block even if another owner is unknown.
- Otherwise any missing/undetermined owner makes it Undetermined.
- All required owners permitting makes it Permitted, with all obligations.
- A policy targeting a different resource/application is NotApplicable. A known
  unsupported operation at the correct target is Refused.
- Empty required-owner sets and duplicate owner policies are invalid inputs.

`tests/laws.rs` exercises all sixteen pairs of Permit, explicit absence, missing
evidence and policy non-applicability. This is our required-owner conjunction,
not a claim to implement XACML's combining algorithms.

Known absence of a grant and failure to obtain evidence are different inputs.
Only the embedding can assert authoritative absence; omission means unknown.
There is no fallback from a delegated actor to its host's personal authority.

## Structural scaffold

| Construction invariant | Witness |
|---|---|
| Proofs are not verdicts | `record_is_not_a_justification`, `partial_owner_is_not_agreement` compiler cases; only derivation.rs constructs Agreement. |
| Conditions cannot be skipped | `conditional_is_not_ready`, `forge_ready`; real opaque reservations in scaffold runtime tests. |
| Exact effect, no substitution | `different_action`, `substitute_arguments`; mutable source arguments are frozen before derivation. |
| Same owner context | `cross_session`, `foreign_guard_authorization`, `escape_scope`; invariant generative scope and guard types. |
| No fabricated execution authority | `clone_ready`, `deserialize_ready`, `historical_is_not_live`; positive lawful path compiles. |
| No legacy bypass | `retired_boolean_execution` must fail to compile; no production Enforcer/perform API remains. |
| Current context at transitions | Ordinary forward ticks re-evaluate successfully; expiry, relevant authority changes or stale interpretations block execution and release reservations. |
| Linear continuation | Only commit can hand off Lease; each protected unit consumes it and rederives, prepares and commits; failure/stop has no successor. Clone, reuse, foreign-guard and record-to-lease compiler controls. |
| Same derivation, two views | Root/delegation/agreement/exercise trace follows private proof construction and binds the full effect, not just its descriptor. |

Runtime owners establish freshness, authenticity and witness truth under their
own mutation boundary. The compiler requires the proof/witness path; it cannot
prove those changing facts or social legitimacy. This is not exactly-once or a
wall-clock lifetime guarantee. Record format v7 binds arguments and observed
derivation. The original acceptance assertions are retained through a test-only
migration adapter (`tests/common/legacy.rs`), not a library compatibility escape
hatch.

## Intrinsic class and exact-resource context

`ApplicationAuthority` owns immutable realm/name/class and a recomputed full
SHA-256 identity; its origin label encodes all 256 bits. `ResourceIdentity` names
an exact record part, lend, own endpoint or native broker. `IDENTITIES.md` freezes
their independent byte domains. These are untrusted definitions, not authority.

The existing owner derivation checks native context before constructing Approval:
Record cannot exercise external read/send, Connector cannot append/correct, and
operation family, own-app identity and group record realm must match. Each required
owner still supplies its independent standing/delegated authority. Correct context
does not choose that owner set or authenticate the actor/target for the embedding.
An ordinary native operation cannot be relabelled at a guard as a permitted read.

Legacy strings remain a separate prototype representation, never promoted by a
matching display label. Mixed native/legacy context reports `Need::context`;
legacy Tree prefixes do not cover native definitions. A native Tree covers only
that exact native identity; it grants no implicit children. Current record v7
roundtrips/replays, while relabelling it v6 fails replay rather than upgrading it.
Original test/native signing bytes remain unchanged. All current effects and owned
fingerprints use streaming frame 4 (`ENCODING.md`). Old frame-3 vectors use only
a historical test reader (`tests/historical/frame3.rs`); no production context
selects the old hashing path.

`tests/identities.rs` observes protected effects for the allowed/forbidden pairs,
two-owner reference-native signed composition, exact-target failures, guarded
operation substitution, typed missing context, legacy alias isolation and cache/
wire/version rejection. Independent Python vectors cover both realm tags, every
resource family, Unicode byte lengths and the full origin. Compiler controls
allow legitimate refined construction and reject mutation of class/digest caches.
They also reject implicit conversion into the legacy string constructor; display
text can only be deliberately copied and remains an unclassified value.
Native source interpretation, issuance and origins/storage are not implemented
by this library.

## Explicit native context and streaming input

`CONTEXT.md` specifies the full-ingress context, `Request`, alongside the key
Exercise. Both use the same generic Effect/Approval/Agreement/scaffold. Native
Actor distinguishes keys, issuer-bound sessions, issuer-bound bearer identities
and anonymous input; Subject distinguishes none, group-bound person and visit.
AuthorityUse explicitly selects personal, application or public authority.
The guard supplies an independent complete Ingress binding at derive and refresh;
same-person sessions, application/personal use and different targets cannot swap.
Operation/target meaning supplies required owner identities, not the proof subset.
Missing owner policy produces an Undetermined owner need; extra policies do not
replace it. Anonymous public output needs no invented person or execution key;
key delegation cannot terminate at an invented session key. Native source and
authentication adapters still have to discharge these premises at actual ingress.

Profile-defined personal/public operations use explicit `Request::profile` and
independent `Ingress::profile`. The acquired resource fixes the owner policies;
supplied proofs cannot omit one. Custom/unclassified meaning cannot erase an
application's classification or mix a native resource into the unclassified path.
`tests/profile_requests.rs` exercises real commit, missing owner source, operation
substitution and classification/resource downgrade controls. Request wire is v2.

Frame 4 streams closed values and raw bytes into SHA-256 without a Value tree or
second framed body buffer. Evidence is immutable/shared and captures its digest
once. Independent Python vectors cover signed integers,
Unicode, raw bytes, options, every enum representation and ordered fields/maps.
Malformed counts, unknown lengths and floats fail instead of producing a hash.
Actual opened stream/blob handles and resource-specific admission budgets belong
to their I/O owners; no in-core I/O abstraction is substituted for them.

There is one production Policy/Scope and original-statement evidence path.
Grant/SignedGrant/Terms/OwnerPolicy, prototype Basis factories and the built-in
Chain/certificate evaluator are retired. Original fixtures use test-only
construction/carrier adapters, then the real verifier, narrowing and scaffold.
`scripts/check_api.py` rejects production resurrection and sibling dependencies.

Canon's production adapter takes the held original Act set before short-ID Log
construction, validates native IDs/versions, refuses ambiguous content/signature
variants and uses canon's full canonical SHA-256 pins. It directly constructs
Policy/Scope with explicitly selected carriers. `tests/canon_sources.rs` and its
compiled plants cover those source boundaries; canon still owns interpretation.

The tests are witnesses, not exhaustive proof. Native and wasm production builds
and isolated consumer manifests test the dependency boundary; dev-tool std
features are not mistaken for the shipped library's features.

## Extension witnesses and state ownership

`tests/extensions.rs` uses a pure set/graph constitutional interpreter, an
independent native evidence codec and a concrete mutex/reservation resource. No
membership, keeper, visit, code-version or reader/writer branch is added to the
kernel for those domain cases. Their source of truth and transitions are in the
reference profile, including an **explicit fixture-only** resolution rule.

| Witness | Observed effect / counterexample |
|---|---|
| `b01_sources_not_display_time_or_carrier_determine_counted_effects` | Authenticated distinct carriers and independent arrival orders commit the same legitimate source-linked acts; superseded power fails; missing handover waits. |
| `b02_opaque_bytes_and_installed_native_evidence_have_one_producer` | Binary/escaped/number-spelling bodies reach commit unchanged; tampered original transcript fails; unknown codec waits. Independent Python frame vectors and native Pass::sign fixture. |
| `b03_join_link_leave_and_cut_are_one_constitutional_interpretation` | Invitation/consent admission, linked device, self-leave and covered cut ancestry succeed; bare Admit and backdated post-cut writes produce no effects. |
| `b04_genuine_forks_freeze_without_restoring_a_keeper` | Duplicate/bad-signature siblings preserve lawful handover; genuine fork waits without restoring a keeper; unrelated data succeeds; resolution needs an explicitly configured rule. |
| `b05_independent_standing_owners_audiences_and_structural_coverage` | Independent standing offers/consents permit with zero per-request grants; either refusal, wrong audience, alias path or missing eligibility blocks; visitor scope/time is bounded. |
| `b06_narrow_native_delegation_cannot_fall_back_or_leak_credentials` | Native chains preserve person/app and distinct execution identity; signed widening, host fallback and unselected legacy carrier fail; backend credential use remains resource-local. |
| `b07_corrections_follow_stable_people_not_labels_or_carriers` | Author's linked device commits the exact correction; a namesake or wrong app cannot; missing target waits. |
| `b08_historical_admission_binds_effect_sources_issuer_and_purpose` | Exact-effect trusted receipts preserve historical admission after expiry; wrong body/issuer/time or live reuse fail. Attested windows work only when wholly covered, without invented timestamps. |
| `b09_continuation_is_linear_and_rechecks_current_rights_not_old_records` | Valid clock ticks advance a linear continuation; expiry, missing authority and missed check bounds stop it while independently authorized uses remain available. |
| `b10_last_slot_is_atomic_and_failures_release_the_owned_reservation` | Two real threads compete for one reservation; one commits. Failure releases capacity; unknown mandatory conditions cause no effect. |
| `b11_activation_executes_accepted_bytes_and_surfaces_first_version_conflict` | Actual selected code bytes reach commit; substitution/conflicting first versions fail; the right person's acceptance selects the original code, unchanged by pending updates. |
| `b12_explanations_replay_without_creating_more_effects` | Records reproduce source-linked judgments without another commit or publishing private fact contents; compiler controls prevent minting executable proofs. |
| `b13_sticky_cross_operation_history_is_not_erased_by_stop_or_code_change` | Read-grant history blocks delegated writes through reordered/duplicate delivery, Stop and code change; direct writing succeeds; unavailable private history waits. |

Derived authority is immutable. Cache observation is a checked transition:
`Recheck::Before` makes reuse at the boundary return Reinterpret; refresh may
produce the same authority identity. The canon adapter accounts for known future
acts and inclusive horizon boundaries. `tests/canon_extensions.rs` and
`cached_authority_must_be_reinterpreted_at_its_declared_transition_boundary` in
`tests/extensions.rs` exercise both successful reuse and necessary invalidation.

`scripts/check_extensions.py` compiles isolated fault plants and requires actual
behavioral failures, never compile errors or zero-test runs. It covers owner
refusal, missing sources, native signatures, attenuation, receipt content/purpose,
expiry, continuation/cache deadlines, interval coverage, actor/effect binding,
last-slot reservation and the reference constitution's freeze/Admit/isolation rules.
The gate runs these controls with the normal tests and production boundary checks.

## Native-shaped adapter witnesses

Adversarial readiness and the trust assumptions behind these witnesses are
specified in `THREAT_MODEL.md`. `tests/adversarial.rs` includes a bounded-verification
attack control and deliberate codec/admitter compromise assays; the latter
observe consequences outside the honest-TCB guarantee, not attack refusals.

`integration/tests/native_bindings.rs` uses the producer-frozen native pass under a root
that binds its issuing device to a different stable person. Internal hints do
not authorize another person/group; original native bytes/signature stay intact.
The root's native membership derivation is assumed here, not implemented by this
test. Its source is the shared test parser, not a second transcript producer.

`tests/svrngs_use_lifecycle.rs` models the existing asynchronous usage acquisition
and retained `InFlight` shape. A non-repeatable POST forwards once while idle
checks keep its original slot. A change during acquisition causes no forward;
withdrawal closes once and leaves independent uses running. A lend cannot use
another lend's reservation. The current future-only Stop behavior is preserved
for an already active use; this is not an unannounced cancellation policy.

These witnesses execute owner state transitions, not native sockets/timers.
No fixture's assertion that private history is known supplies a production proof
of that assertion.

Native cases, such as those against svrngs (github.com/alexsbryan/svrngs), are a
separate acceptance package (`integration/Cargo.toml`), not a dependency of this
crate; `integration/README.md` gives their commands and status. The library gate
runs all library laws and does not skip or claim native integration results.
