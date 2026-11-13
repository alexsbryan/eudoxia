//! A native pass's issuer/device is not necessarily its stable person. Context
//! is supplied by the resource adapter and checked against the established root;
//! it is not appended to or re-signed into the original native transcript.
mod profiles;
use eudoxia::*;
use profiles::{
    resource::{Door, Read},
    svrngs_pass::{self, Pass},
    *,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Envelope {
    original: Vec<u8>,
    person_hint: Principal,
    source_hint: SourceRef,
}
fn decode(envelope: &[u8]) -> Result<ParsedStatement, DecodeError> {
    let e: Envelope = serde_json::from_slice(envelope).map_err(|_| DecodeError::Malformed)?;
    Ok(ParsedStatement::new(Bound {
        statement: svrngs_pass::decode(&e.original)?,
        person_hint: e.person_hint,
        source_hint: e.source_hint,
    }))
}
struct Bound {
    statement: ParsedStatement,
    person_hint: Principal,
    source_hint: SourceRef,
}
impl NativeStatement for Bound {
    fn issuer(&self) -> Principal {
        self.statement.issuer()
    }
    fn signature(&self) -> &[u8] {
        self.statement.signature()
    }
    fn signing_message(&self) -> std::borrow::Cow<'_, [u8]> {
        self.statement.signing_message()
    }
    fn project(self: Box<Self>, binding: &SourceRef) -> Result<Claim, DecodeError> {
        let mut claim = Box::new(self.statement).project(binding)?;
        if let Claim::Delegation { scope, sources, .. } = &mut claim {
            scope.person = Some(self.person_hint);
            *sources = [self.source_hint].into();
        }
        Ok(claim)
    }
}
#[test]
fn a_linked_issuer_maps_to_its_stable_person_without_reissuing_its_pass() {
    let raw = include_bytes!("../../fixtures/vectors/svrngs-pass.json").to_vec();
    let wire: Pass = serde_json::from_slice(&raw).unwrap();
    let source = SourceRef {
        namespace: id("native-house-id"),
        algorithm: id("svrngs-blake3"),
        digest: vec![42; 32],
    };
    let mut p = policy("person");
    p.source = source.clone();
    p.scope.person = Some(person(1));
    p.approval = ApprovalRule::Delegated([person(2)].into());
    p.scope.application = Some(Application::new(wire.app.clone()).unwrap());
    p.scope.coverage = Coverage::Set(
        core::iter::once(&wire.app)
            .chain(&wire.reads)
            .map(|r| Resource::new(r.clone()).unwrap())
            .collect(),
    );
    p.scope.interval = Interval::new(i64::MIN, 80).unwrap();
    p.carriers = [id("native-bound-pass-v1")].into();
    // The root interpreter establishes device 2 -> stable person 1. Hints alone
    // cannot establish that mapping: issuer authorization and scope must agree.
    let b = Basis::interpreted(
        id("native-binding-profile-v1"),
        30,
        vec![p.clone()],
        vec![Fact {
            source: source.clone(),
            state: FactState::Established,
        }],
        vec![Codec {
            id: id("native-bound-pass-v1"),
            decode,
        }],
        Recheck::OnSourceChange,
    )
    .unwrap();
    let door = Door::new(b, 4, "read");
    let mut e = request(4, "read");
    e.person = person(1);
    e.application = Application::new(wire.app).unwrap();
    e.resource = Resource::new(wire.reads[0].clone()).unwrap();
    let supplied = |person_hint, source_hint| {
        Evidence::new([(
            p.owner.clone(),
            OwnerEvidence::Native(vec![NativeEvidence {
                codec: id("native-bound-pass-v1"),
                bytes: serde_json::to_vec(&Envelope {
                    original: raw.clone(),
                    person_hint,
                    source_hint,
                })
                .unwrap(),
            }]),
        )])
        .unwrap()
    };
    let out = door
        .run(
            Effect::<Read>::from_bytes(e.clone(), vec![1]),
            &supplied(person(1), source.clone()),
        )
        .unwrap();
    assert_eq!(out.record.exercise.person, person(1));
    assert_eq!(out.record.exercise.actor, person(4));
    assert_eq!(door.effects(), 1);
    assert!(
        door.run(
            Effect::from_bytes(e.clone(), vec![1]),
            &supplied(person(6), source.clone())
        )
        .is_err()
    );
    let mut wrong = source;
    wrong.namespace = id("other-group");
    assert!(
        door.run(Effect::from_bytes(e, vec![1]), &supplied(person(1), wrong))
            .is_err()
    );
    assert_eq!(door.effects(), 1);
}
