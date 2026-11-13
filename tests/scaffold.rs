mod common;
use common::*;
use eudoxia::*;
use std::{cell::Cell, collections::BTreeSet, rc::Rc};

struct Read;
#[derive(Debug, PartialEq)]
enum ResourceError {
    UnknownCondition,
    Unenforceable,
    WrongReservation,
}
struct Reservation {
    exact: Fingerprint,
    held: Rc<Cell<usize>>,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.held.set(self.held.get() - 1);
    }
}
#[derive(Default)]
struct State {
    prepares: usize,
    commits: usize,
}
struct Guard<'a> {
    actor: Principal,
    clock: &'a Cell<i64>,
    withdrawn: &'a Cell<bool>,
    state: &'a mut State,
    held: Rc<Cell<usize>>,
    required: BTreeSet<Obligation>,
    operation: Operation,
    enforceable: bool,
}
impl ResourceGuard for Guard<'_> {
    type Action = Read;
    type Witness = Reservation;
    type Output = (Exercise, Vec<u8>, DecisionRecord);
    type Error = ResourceError;
    fn ingress(&self) -> KeyIngress {
        KeyIngress {
            actor: self.actor,
            operation: self.operation.clone(),
        }
    }
    fn current(&mut self) -> Result<Basis, ResourceError> {
        let mut owners = policies();
        owners[0].obligations = self.required.clone();
        if self.withdrawn.get() {
            owners[0].issuers.clear();
        }
        Ok(Basis::trusted(id("guard-v1"), self.clock.get(), owners).unwrap())
    }
    fn prepare(
        &mut self,
        effect: &Effect<Read>,
        obligations: &BTreeSet<Obligation>,
    ) -> Result<Reservation, ResourceError> {
        self.state.prepares += 1;
        for required in obligations {
            if required.kind != id("credential") {
                return Err(ResourceError::UnknownCondition);
            }
            if !self.enforceable {
                return Err(ResourceError::Unenforceable);
            }
        }
        self.held.set(self.held.get() + 1);
        Ok(Reservation {
            exact: effect.fingerprint(),
            held: self.held.clone(),
        })
    }
    fn commit(&mut self, authorized: Authorized<'_, Self>) -> Result<Self::Output, ResourceError> {
        let (effect, reservation, record) = authorized.into_parts();
        if effect.fingerprint() != reservation.exact {
            return Err(ResourceError::WrongReservation);
        }
        self.state.commits += 1;
        Ok((
            effect.exercise().clone(),
            effect.arguments().to_vec(),
            record,
        ))
    }
}
fn guard<'a>(
    clock: &'a Cell<i64>,
    withdrawn: &'a Cell<bool>,
    state: &'a mut State,
    held: &Rc<Cell<usize>>,
) -> Guard<'a> {
    Guard {
        actor: principal(4),
        clock,
        withdrawn,
        state,
        held: held.clone(),
        required: BTreeSet::new(),
        operation: operation("read"),
        enforceable: true,
    }
}

#[test]
fn actor_binding_cannot_be_claimed_by_the_request() {
    let (clock, withdrawn, mut state, held) = (
        Cell::new(30),
        Cell::new(false),
        State::default(),
        Rc::new(Cell::new(0)),
    );
    let mut resource = guard(&clock, &withdrawn, &mut state, &held);
    resource.actor = principal(9);
    with_resource(resource, |live| {
        assert!(matches!(
            live.derive(Effect::<Read>::new(exercise(), &()).unwrap(), &evidence()),
            Err(DeriveError::ActorMismatch)
        ));
    })
    .unwrap();
    assert_eq!((state.prepares, state.commits), (0, 0));
}

#[test]
fn action_binding_cannot_be_claimed_by_the_request() {
    let (clock, withdrawn, mut state, held) = (
        Cell::new(30),
        Cell::new(false),
        State::default(),
        Rc::new(Cell::new(0)),
    );
    let mut resource = guard(&clock, &withdrawn, &mut state, &held);
    resource.operation = operation("write");
    with_resource(resource, |live| {
        assert!(matches!(
            live.derive(Effect::<Read>::new(exercise(), &()).unwrap(), &evidence()),
            Err(DeriveError::ActionMismatch)
        ));
    })
    .unwrap();
    assert_eq!((state.prepares, state.commits), (0, 0));
}

#[test]
fn lawful_derivation_owns_exact_frozen_arguments_and_an_execution_witness() {
    let (clock, withdrawn, mut state, held) = (
        Cell::new(30),
        Cell::new(false),
        State::default(),
        Rc::new(Cell::new(0)),
    );
    let mut arguments = serde_json::json!({"entry": "original", "amount": 42});
    let effect = Effect::<Read>::new(exercise(), &arguments).unwrap();
    arguments["entry"] = "substitution".into();
    let (actual, bytes, record) =
        with_resource(guard(&clock, &withdrawn, &mut state, &held), |live| {
            let proof = live.derive(effect, &evidence()).unwrap();
            let ready = live.prepare(proof).unwrap();
            assert_eq!(held.get(), 1);
            live.execute(ready).unwrap()
        })
        .unwrap();
    assert_eq!(actual, exercise());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["entry"],
        "original"
    );
    assert_eq!(record.arguments, bytes);
    assert_eq!((state.prepares, state.commits, held.get()), (1, 1, 0));
}

#[test]
fn changed_time_blocks_preparation_before_any_reservation() {
    let (clock, withdrawn, mut state, held) = (
        Cell::new(30),
        Cell::new(false),
        State::default(),
        Rc::new(Cell::new(0)),
    );
    with_resource(guard(&clock, &withdrawn, &mut state, &held), |live| {
        let proof = live
            .derive(Effect::<Read>::new(exercise(), &()).unwrap(), &evidence())
            .unwrap();
        clock.set(80);
        assert!(matches!(
            live.prepare(proof),
            Err(TransitionError::ContextChanged)
        ));
    })
    .unwrap();
    assert_eq!((state.prepares, state.commits, held.get()), (0, 0, 0));
}

#[test]
fn expiry_after_preparation_blocks_commit_and_releases_the_witness() {
    let (clock, withdrawn, mut state, held) = (
        Cell::new(30),
        Cell::new(false),
        State::default(),
        Rc::new(Cell::new(0)),
    );
    with_resource(guard(&clock, &withdrawn, &mut state, &held), |live| {
        let proof = live
            .derive(Effect::<Read>::new(exercise(), &()).unwrap(), &evidence())
            .unwrap();
        let ready = live.prepare(proof).unwrap();
        clock.set(80);
        assert!(matches!(
            live.execute(ready),
            Err(TransitionError::ContextChanged)
        ));
    })
    .unwrap();
    assert_eq!((state.prepares, state.commits, held.get()), (1, 0, 0));
}

#[test]
fn withdrawal_after_preparation_blocks_commit_without_changing_the_request() {
    let (clock, withdrawn, mut state, held) = (
        Cell::new(30),
        Cell::new(false),
        State::default(),
        Rc::new(Cell::new(0)),
    );
    with_resource(guard(&clock, &withdrawn, &mut state, &held), |live| {
        let proof = live
            .derive(Effect::<Read>::new(exercise(), &()).unwrap(), &evidence())
            .unwrap();
        let ready = live.prepare(proof).unwrap();
        withdrawn.set(true);
        assert!(matches!(
            live.execute(ready),
            Err(TransitionError::ContextChanged)
        ));
    })
    .unwrap();
    assert_eq!((state.commits, held.get()), (0, 0));
}

#[test]
fn all_required_owners_are_needed_to_construct_a_justification() {
    let (clock, withdrawn, mut state, held) = (
        Cell::new(30),
        Cell::new(false),
        State::default(),
        Rc::new(Cell::new(0)),
    );
    let partial =
        Evidence::new([(owner("person"), OwnerEvidence::Chain(chain("person", 1)))]).unwrap();
    with_resource(guard(&clock, &withdrawn, &mut state, &held), |live| {
        let Err(DeriveError::Judgment(record)) =
            live.derive(Effect::<Read>::new(exercise(), &()).unwrap(), &partial)
        else {
            panic!("partial authority produced a justification");
        };
        assert_eq!(record.decision, Decision::Undetermined);
        assert!(record.derivation.is_none());
    })
    .unwrap();
    assert_eq!((state.prepares, state.commits), (0, 0));
}

#[test]
fn mandatory_conditions_require_real_resource_preparation() {
    for (kind, enforceable, expected) in [
        ("unknown", true, ResourceError::UnknownCondition),
        ("credential", false, ResourceError::Unenforceable),
    ] {
        let (clock, withdrawn, mut state, held) = (
            Cell::new(30),
            Cell::new(false),
            State::default(),
            Rc::new(Cell::new(0)),
        );
        let mut resource = guard(&clock, &withdrawn, &mut state, &held);
        resource.required.insert(Obligation {
            kind: id(kind),
            ..obligation()
        });
        resource.enforceable = enforceable;
        with_resource(resource, |live| {
            let proof = live.derive(Effect::<Read>::new(exercise(), &()).unwrap(), &evidence()).unwrap();
            assert!(matches!(live.prepare(proof), Err(TransitionError::Resource(actual)) if actual == expected));
        }).unwrap();
        assert_eq!((state.commits, held.get()), (0, 0));
    }
}

#[test]
fn the_record_is_an_observation_of_roots_delegations_agreement_and_exercise() {
    let effect = Effect::<Read>::new(exercise(), &42).unwrap();
    let record = inspect(&basis(30), &effect, &evidence());
    let Some(DerivationTrace::Exercise {
        authority,
        effect: exact,
    }) = &record.derivation
    else {
        panic!("no exercise derivation");
    };
    assert_eq!(*exact, effect.fingerprint());
    let DerivationTrace::Agreement {
        required,
        approvals,
    } = authority.as_ref()
    else {
        panic!("no owner agreement");
    };
    assert_eq!(required.len(), 2);
    assert_eq!(approvals.len(), 2);
    for (owner, approval) in required.iter().zip(approvals) {
        let DerivationTrace::Delegation { parent, holder, .. } = approval else {
            panic!("no execution delegation");
        };
        assert_eq!(*holder, principal(4));
        let DerivationTrace::Delegation { parent, holder, .. } = parent.as_ref() else {
            panic!("no first delegation");
        };
        assert_eq!(*holder, principal(3));
        let DerivationTrace::Root {
            owner: source,
            basis: fingerprint,
            ..
        } = parent.as_ref()
        else {
            panic!("not rooted");
        };
        assert_eq!(source, owner);
        assert_eq!(*fingerprint, basis(30).fingerprint());
    }
    assert_eq!(record.replay(&basis(30), &evidence()).unwrap(), record);
}

#[test]
fn a_long_legal_derivation_still_has_a_roundtrippable_record() {
    let count = 64_u8;
    let mut owners = policies();
    for policy in &mut owners {
        policy.terms.redelegations = count;
    }
    let b = Basis::trusted(id("long-proof-v1"), 30, owners).unwrap();
    let supplied = Evidence::new([("person", 1), ("lender", 5)].map(|(name, root)| {
        let chain = (0..count)
            .map(|step| {
                let issuer = if step == 0 { root } else { 3 };
                let mut bounds = terms();
                bounds.interval = Interval::new(20, 80).unwrap();
                bounds.operations = [operation("read")].into();
                bounds.redelegations = count - step - 1;
                sign(
                    Grant {
                        owner: owner(name),
                        issuer: principal(issuer),
                        holder: principal(if step + 1 == count { 4 } else { 3 }),
                        terms: bounds,
                    },
                    issuer,
                )
            })
            .collect();
        (owner(name), OwnerEvidence::Chain(chain))
    }))
    .unwrap();
    let record = judge(&b, &exercise(), &supplied);
    assert_eq!(record.decision, Decision::Permitted);
    let encoded = serde_json::to_string(&record).unwrap();
    let decoded: DecisionRecord = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded.replay(&b, &supplied).unwrap(), record);
}
