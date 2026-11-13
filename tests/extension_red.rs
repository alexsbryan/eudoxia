//! The three behavioral counterexamples captured before extending the scaffold.
mod common;
use common::*;
use eudoxia::*;
use std::{cell::Cell, collections::BTreeSet};

struct Read;
struct Door<'a> {
    clock: &'a Cell<i64>,
    calls: &'a Cell<usize>,
    standing: bool,
}
impl ResourceGuard for Door<'_> {
    type Action = Read;
    type Witness = ();
    type Output = Vec<u8>;
    type Error = &'static str;
    fn ingress(&self) -> KeyIngress {
        KeyIngress {
            actor: principal(4),
            operation: operation("read"),
        }
    }
    fn current(&mut self) -> Result<Basis, Self::Error> {
        if self.standing {
            let old = basis(self.clock.get());
            let mut policies = old.policies().to_vec();
            for p in &mut policies {
                p.approval = ApprovalRule::Standing;
            }
            let facts = policies
                .iter()
                .map(|p| Fact {
                    source: p.source.clone(),
                    state: FactState::Established,
                })
                .collect();
            Ok(Basis::interpreted(
                id("standing-v1"),
                self.clock.get(),
                policies,
                facts,
                vec![],
                Recheck::OnSourceChange,
            )
            .unwrap())
        } else {
            Ok(basis(self.clock.get()))
        }
    }
    fn prepare(&mut self, _: &Effect<Read>, _: &BTreeSet<Obligation>) -> Result<(), Self::Error> {
        Ok(())
    }
    fn commit(&mut self, a: Authorized<'_, Self>) -> Result<Vec<u8>, Self::Error> {
        self.calls.set(self.calls.get() + 1);
        Ok(a.into_parts().0.arguments().to_vec())
    }
}

fn owned_body(bytes: Vec<u8>) -> Effect<Read> {
    Effect::from_bytes(exercise(), bytes)
}

#[test]
fn b02_the_resource_receives_the_owners_original_bytes() {
    let (clock, calls) = (Cell::new(30), Cell::new(0));
    let body = b"{ \"n\":1.00, \"s\":\"\\u0061\" }\n".to_vec();
    let received = with_resource(
        Door {
            clock: &clock,
            calls: &calls,
            standing: false,
        },
        |live| {
            let proof = live.derive(owned_body(body.clone()), &evidence()).unwrap();
            let ready = live.prepare(proof).unwrap();
            live.execute(ready).unwrap()
        },
    )
    .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(received, body);
}

#[test]
fn b05_a_standing_offer_needs_no_per_request_certificate() {
    let (clock, calls) = (Cell::new(30), Cell::new(0));
    with_resource(
        Door {
            clock: &clock,
            calls: &calls,
            standing: true,
        },
        |live| {
            let proof = live
                .derive(owned_body(vec![]), &Evidence::default())
                .unwrap();
            let ready = live.prepare(proof).unwrap();
            live.execute(ready).unwrap();
        },
    )
    .unwrap();
    assert_eq!(calls.get(), 1);
}

#[test]
fn b09_ordinary_clock_ticks_do_not_revoke_a_valid_request() {
    let (clock, calls) = (Cell::new(30), Cell::new(0));
    with_resource(
        Door {
            clock: &clock,
            calls: &calls,
            standing: false,
        },
        |live| {
            let proof = live.derive(owned_body(vec![]), &evidence()).unwrap();
            clock.set(31);
            let ready = live.prepare(proof).unwrap();
            clock.set(32);
            live.execute(ready).unwrap();
        },
    )
    .unwrap();
    assert_eq!(calls.get(), 1);
}
