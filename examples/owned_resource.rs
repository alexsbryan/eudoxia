//! A consumer using only the production API, with an actual owned mutation.
use eudoxia::*;
use std::collections::BTreeSet;

fn id(s: &str) -> Id {
    Id::new(s).unwrap()
}
fn operation() -> Operation {
    Operation::new("example/store").unwrap()
}
fn resource() -> Resource {
    Resource::new("example/value").unwrap()
}
struct StoreValue;
struct Ledger {
    actor: Actor,
    subject: Subject,
    basis: Basis,
    value: Vec<u8>,
}
struct Guard<'a>(&'a mut Ledger);
struct Prepared(Fingerprint);
impl ResourceGuard<Request> for Guard<'_> {
    type Action = StoreValue;
    type Witness = Prepared;
    type Output = DecisionRecord<Request>;
    type Error = &'static str;
    fn ingress(&self) -> Ingress {
        Ingress::profile(
            self.0.actor,
            self.0.subject,
            AuthorityUse::Personal,
            operation(),
            resource(),
        )
    }
    fn current(&mut self) -> Result<Basis, Self::Error> {
        Ok(self.0.basis.clone())
    }
    fn prepare(
        &mut self,
        e: &Effect<StoreValue, Request>,
        conditions: &BTreeSet<Obligation>,
    ) -> Result<Prepared, Self::Error> {
        if !conditions.is_empty() {
            return Err("unknown mandatory condition");
        }
        Ok(Prepared(e.fingerprint()))
    }
    fn commit(&mut self, a: Authorized<'_, Self, Request>) -> Result<Self::Output, Self::Error> {
        let (effect, witness, record) = a.into_parts();
        if witness.0 != effect.fingerprint() {
            return Err("different prepared effect");
        }
        self.0.value = effect.arguments().to_vec();
        Ok(record)
    }
}
fn main() {
    let key = Principal::new(
        ed25519_dalek::SigningKey::from_bytes(&[1; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap();
    let actor = Actor::Session {
        issuer: key,
        id: AuthorityId::from_bytes([2; 32]),
    };
    let subject = Subject::Person {
        group: AuthorityId::from_bytes([3; 32]),
        person: key,
    };
    // These installed sources/policies are the resource's explicit trust root,
    // not facts inferred from a client's asserted actor or proof subset.
    let policies: Vec<_> = ["person", "resource"]
        .into_iter()
        .enumerate()
        .map(|(i, name)| Policy {
            owner: Owner::new(name).unwrap(),
            source: SourceRef {
                namespace: id("example-root"),
                algorithm: id("owner-source"),
                digest: vec![i as u8; 32],
            },
            scope: Scope {
                person: Some(key),
                application: None,
                coverage: Coverage::Exact(resource()),
                operations: [operation()].into(),
                interval: Interval::new(0, 60).unwrap(),
                redelegations: 0,
            },
            approval: ApprovalRule::Standing,
            actor: None,
            effect: None,
            requires: Default::default(),
            admitters: Default::default(),
            carriers: Default::default(),
            obligations: Default::default(),
        })
        .collect();
    let facts = policies
        .iter()
        .map(|p| Fact {
            source: p.source.clone(),
            state: FactState::Established,
        })
        .collect();
    let basis = Basis::interpreted(
        id("example-v1"),
        30,
        policies,
        facts,
        vec![],
        Recheck::OnSourceChange,
    )
    .unwrap();
    let mut ledger = Ledger {
        actor,
        subject,
        basis,
        value: vec![],
    };
    let request = Request::profile(
        id("request"),
        actor,
        subject,
        AuthorityUse::Personal,
        operation(),
        resource(),
    )
    .unwrap();
    let original = vec![0, 255, b'{', b'}'];
    let record = with_resource(Guard(&mut ledger), |live| {
        let proof = live
            .derive(
                Effect::from_bytes(request, original.clone()),
                &Evidence::default(),
            )
            .unwrap();
        let ready = live.prepare(proof).unwrap();
        live.execute(ready).unwrap()
    })
    .unwrap();
    assert_eq!(ledger.value, original);
    assert_eq!(record.decision, Decision::Permitted);
    println!(
        "committed {} original bytes through both owners",
        ledger.value.len()
    );
}
