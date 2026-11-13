mod profiles;
use eudoxia::*;
use profiles::svrngs_pass::{Pass, decode};
use profiles::{
    resource::{Door, Read},
    *,
};
#[test]
fn original_svrngs_pass_signature_opens_the_backend_without_reissuance() {
    let raw = include_bytes!("../../fixtures/vectors/svrngs-pass.json").to_vec();
    let pass: Pass = serde_json::from_slice(&raw).unwrap();
    let codec = Codec {
        id: id("svrngs-reach-pass-v1"),
        decode,
    };
    let mut p = policy("person");
    p.carriers = [codec.id.clone()].into();
    p.approval = ApprovalRule::Delegated([person(2)].into());
    p.scope.person = Some(person(2));
    p.scope.application = Some(Application::new(pass.app.clone()).unwrap());
    p.scope.coverage = Coverage::Set(
        core::iter::once(&pass.app)
            .chain(&pass.reads)
            .map(|s| Resource::new(s.clone()).unwrap())
            .collect(),
    );
    p.scope.interval = Interval::new(i64::MIN, 80).unwrap();
    let basis = Basis::interpreted(
        id("svrngs-vector-v1"),
        79,
        vec![p.clone()],
        vec![Fact {
            source: p.source.clone(),
            state: FactState::Established,
        }],
        vec![codec],
        Recheck::OnSourceChange,
    )
    .unwrap();
    let proof = Evidence::new([(
        p.owner,
        OwnerEvidence::Native(vec![NativeEvidence {
            codec: id("svrngs-reach-pass-v1"),
            bytes: raw.clone(),
        }]),
    )])
    .unwrap();
    let door = Door::new(basis, 4, "read");
    let mut e = request(4, "read");
    e.application = Application::new(pass.app).unwrap();
    e.resource = Resource::new(pass.reads[0].clone()).unwrap();
    let body = b"{ \"query\":\"\\u0061\" }".to_vec();
    let output = door
        .run(Effect::<Read>::from_bytes(e.clone(), body.clone()), &proof)
        .unwrap();
    assert_eq!(output.body, body);
    assert_eq!(door.effects(), 1);
    door.at(80);
    assert!(door.run(Effect::from_bytes(e, body), &proof).is_err());
    assert_eq!(door.effects(), 1);
}
