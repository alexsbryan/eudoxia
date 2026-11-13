# Eudoxia

Read docs/ARCHITECTURE.md and docs/CONTRACT.md before changing the model. The
core is pure, synchronous, no_std + alloc. Explicit evidence and time enter; a
judgment leaves. No ambient clock, filesystem, network, identity lookup or
global policy.

Work red -> green -> refactor. First name the contract and write an independent
counterexample, run it and keep the red result. Implement the smallest green.
Refactor with those tests fixed. Report the actual commands and outcomes with
the change; never claim a compile error alone proves a behavioral refusal.

Keep policy decisions, execution conditions, and execution outcomes distinct.
Serialization is not authentication. Decision records never mint execution
permits. Canon interpretation stays canon's; do not recreate its ratifier.

The foundation is the sealed derivation and branded resource scaffold, not a
permission boolean. New features outside derivation.rs/scaffold.rs must consume
their lawful transitions, never add unchecked constructors or record-to-proof
conversions. Changes to those two kernel boundaries need compiler counterexamples
and runtime witnesses. Current contexts, authenticated ingress and opaque
preparation witnesses come from the resource owner. Historical data is not live
authority. Update public construction-path tests when deliberately changing APIs;
never bless an unknown-type error as evidence of a protected boundary.

Checks: `python3 scripts/check.py` runs the whole gate — cargo fmt --all --check;
cargo clippy --all-targets --all-features -- -D warnings; cargo test
--all-features; the frozen acceptance contract (fixtures/contract); compiled
fault plants (scripts/check_extensions.py); isolated production builds with no
default features and with canon, also for wasm32-unknown-unknown. Do not weaken
an acceptance test to make a refactor green.
