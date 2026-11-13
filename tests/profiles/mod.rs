#![allow(dead_code)]
pub mod constitution;
pub mod native;
pub mod resource;
pub mod transport;
pub use eudoxia::OwnerProof as OwnerEvidence;
use eudoxia::*;
use sha2::{Digest, Sha256};

pub fn id(s: &str) -> Id {
    Id::new(s).unwrap()
}
pub fn key(n: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[n; 32])
}
pub fn person(n: u8) -> Principal {
    Principal::new(key(n).verifying_key().to_bytes()).unwrap()
}
pub fn reference(s: &[u8]) -> SourceRef {
    SourceRef {
        namespace: id("reference-group"),
        algorithm: id("sha256"),
        digest: Sha256::digest(s).to_vec(),
    }
}
pub fn op(s: &str) -> Operation {
    Operation::new(s).unwrap()
}
pub fn request(actor: u8, operation: &str) -> Exercise {
    Exercise {
        request: id("request"),
        actor: person(actor),
        person: person(2),
        application: Application::new("movie").unwrap(),
        operation: op(operation),
        resource: Resource::new("house/library").unwrap(),
    }
}
pub fn policy(name: &str) -> Policy {
    Policy {
        owner: Owner::new(name).unwrap(),
        source: reference(name.as_bytes()),
        scope: Scope {
            person: None,
            application: None,
            coverage: Coverage::Tree(Resource::new("house").unwrap()),
            operations: [op("read"), op("write")].into(),
            interval: Interval::new(0, 80).unwrap(),
            redelegations: 2,
        },
        approval: ApprovalRule::Standing,
        actor: None,
        effect: None,
        requires: Default::default(),
        admitters: [person(7)].into(),
        carriers: [id("reference-native-v1")].into(),
        obligations: Default::default(),
    }
}
pub fn snapshot(at: i64, policies: Vec<Policy>, mut extra: Vec<Fact>) -> Basis {
    for p in &policies {
        if !extra.iter().any(|f| f.source == p.source) {
            extra.push(Fact {
                source: p.source.clone(),
                state: FactState::Established,
            });
        }
    }
    Basis::interpreted(
        id("reference-profile-v1"),
        at,
        policies,
        extra,
        vec![native::codec()],
        Recheck::OnSourceChange,
    )
    .unwrap()
}
