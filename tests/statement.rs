mod profiles;
use eudoxia::*;
use profiles::{
    resource::{Door, Read},
    *,
};
use std::sync::atomic::{AtomicUsize, Ordering};

static PROJECTED: AtomicUsize = AtomicUsize::new(0);
struct Counted(ParsedStatement);
impl NativeStatement for Counted {
    fn issuer(&self) -> Principal {
        self.0.issuer()
    }
    fn signature(&self) -> &[u8] {
        self.0.signature()
    }
    fn signing_message(&self) -> std::borrow::Cow<'_, [u8]> {
        self.0.signing_message()
    }
    fn project(self: Box<Self>, binding: &SourceRef) -> Result<Claim, DecodeError> {
        PROJECTED.fetch_add(1, Ordering::SeqCst);
        Box::new(self.0).project(binding)
    }
}
fn parse(raw: &[u8]) -> Result<ParsedStatement, DecodeError> {
    Ok(ParsedStatement::new(Counted((native::codec().decode)(
        raw,
    )?)))
}

#[test]
fn invalid_signature_never_reaches_semantic_projection_or_the_resource() {
    let mut p = policy("person");
    p.approval = ApprovalRule::Delegated([person(2)].into());
    let mut scope = p.scope.clone();
    scope.redelegations = 0;
    let proof = native::sign(
        native::Body::Delegation {
            owner: p.owner.clone(),
            holder: person(4),
            scope,
            sources: [p.source.clone()].into(),
        },
        2,
    );
    let b = Basis::interpreted(
        id("statement-stage-v1"),
        30,
        vec![p.clone()],
        vec![Fact {
            source: p.source.clone(),
            state: FactState::Established,
        }],
        vec![Codec {
            id: id("reference-native-v1"),
            decode: parse,
        }],
        Recheck::OnSourceChange,
    )
    .unwrap();
    let d = Door::new(b, 4, "read");
    let effect = || Effect::<Read>::from_bytes(request(4, "read"), vec![]);
    PROJECTED.store(0, Ordering::SeqCst);
    d.run(
        effect(),
        &Evidence::new([(p.owner.clone(), OwnerEvidence::Native(vec![proof.clone()]))]).unwrap(),
    )
    .unwrap();
    assert!(PROJECTED.load(Ordering::SeqCst) > 0);
    assert_eq!(d.effects(), 1);
    let mut env: native::Envelope = serde_json::from_slice(&proof.bytes).unwrap();
    env.signature[0] ^= 1;
    let bad = NativeEvidence {
        bytes: serde_json::to_vec(&env).unwrap(),
        ..proof
    };
    PROJECTED.store(0, Ordering::SeqCst);
    assert!(
        d.run(
            effect(),
            &Evidence::new([(p.owner, OwnerEvidence::Native(vec![bad]))]).unwrap()
        )
        .is_err()
    );
    assert_eq!(PROJECTED.load(Ordering::SeqCst), 0);
    assert_eq!(d.effects(), 1);
}
