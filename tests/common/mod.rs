#![allow(dead_code)]
#[cfg(feature = "canon")]
pub mod canonical;
mod legacy;
use ed25519_dalek::{Signer, SigningKey};
use eudoxia::*;
pub use legacy::*;
use std::collections::BTreeSet;

pub fn id(s: &str) -> Id {
    Id::new(s).unwrap()
}
pub fn owner(s: &str) -> Owner {
    Owner::new(s).unwrap()
}
pub fn operation(s: &str) -> Operation {
    Operation::new(s).unwrap()
}
pub fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
pub fn principal(seed: u8) -> Principal {
    Principal::new(key(seed).verifying_key().to_bytes()).unwrap()
}
pub fn terms() -> Terms {
    Terms {
        person: principal(2),
        application: Application::new("movie-night").unwrap(),
        resource: Resource::new("house/library").unwrap(),
        operations: [operation("read"), operation("write")].into(),
        interval: Interval::new(0, 200).unwrap(),
        redelegations: 2,
    }
}
pub fn policies() -> Vec<OwnerPolicy> {
    [("person", 1), ("lender", 5)]
        .into_iter()
        .map(|(name, issuer)| OwnerPolicy {
            owner: owner(name),
            issuers: [principal(issuer)].into(),
            terms: terms(),
            obligations: BTreeSet::new(),
        })
        .collect()
}
pub fn basis(at: i64) -> Basis {
    Basis::trusted(id("fixture-v1"), at, policies()).unwrap()
}
pub fn exercise() -> Exercise {
    Exercise {
        request: id("request-1"),
        actor: principal(4),
        person: principal(2),
        application: terms().application,
        operation: operation("read"),
        resource: terms().resource,
    }
}
pub fn sign(grant: Grant, seed: u8) -> SignedGrant {
    let signature = key(seed).sign(&grant.signing_bytes()).to_bytes().to_vec();
    SignedGrant { grant, signature }
}
pub fn chain(name: &str, issuer: u8) -> Vec<SignedGrant> {
    let mut parent = terms();
    parent.interval = Interval::new(10, 100).unwrap();
    parent.redelegations = 1;
    let mut child = parent.clone();
    child.operations = [operation("read")].into();
    child.interval = Interval::new(20, 80).unwrap();
    child.redelegations = 0;
    vec![
        sign(
            Grant {
                owner: owner(name),
                issuer: principal(issuer),
                holder: principal(3),
                terms: parent,
            },
            issuer,
        ),
        sign(
            Grant {
                owner: owner(name),
                issuer: principal(3),
                holder: principal(4),
                terms: child,
            },
            3,
        ),
    ]
}
pub fn evidence() -> Evidence {
    Evidence::new(
        [("person", 1), ("lender", 5)]
            .map(|(name, issuer)| (owner(name), OwnerEvidence::Chain(chain(name, issuer)))),
    )
    .unwrap()
}
pub fn evidence_with_child(mut change: impl FnMut(&mut Terms)) -> Evidence {
    Evidence::new([("person", 1), ("lender", 5)].map(|(name, issuer)| {
        let mut values = chain(name, issuer);
        change(&mut values[1].grant.terms);
        values[1] = sign(values[1].grant.clone(), 3);
        (owner(name), OwnerEvidence::Chain(values))
    }))
    .unwrap()
}
pub fn obligation() -> Obligation {
    Obligation {
        kind: id("credential"),
        argument: id("readers-only"),
        phase: Phase::Before,
    }
}

pub struct Recorder {
    pub calls: usize,
    pub conditions: usize,
    pub state: ConditionState,
    pub fail: bool,
}
impl Recorder {
    pub fn new(state: ConditionState) -> Self {
        Self {
            calls: 0,
            conditions: 0,
            state,
            fail: false,
        }
    }
}
impl Enforcer for Recorder {
    type Output = Exercise;
    type Error = &'static str;
    fn condition(&mut self, _: &Obligation) -> ConditionState {
        self.conditions += 1;
        self.state
    }
    fn execute(&mut self, permit: Permit<'_>) -> Result<Exercise, Self::Error> {
        self.calls += 1;
        if self.fail {
            return Err("backend unavailable");
        }
        Ok(permit.exercise().clone())
    }
}
