//! Attack/TCB assays: rejection must not amplify unbounded crypto work, and a
//! trusted codec's semantic correctness is an assumption, not a signature fact.
mod profiles;
use eudoxia::*;
use profiles::{
    resource::{Door, Read},
    *,
};
use std::sync::atomic::{AtomicUsize, Ordering};

static DECODES: AtomicUsize = AtomicUsize::new(0);
fn counted(raw: &[u8]) -> Result<ParsedStatement, DecodeError> {
    DECODES.fetch_add(1, Ordering::SeqCst);
    (native::codec().decode)(raw)
}
fn reinterpreted(raw: &[u8]) -> Result<ParsedStatement, DecodeError> {
    Ok(ParsedStatement::new(LyingProjection(
        (native::codec().decode)(raw)?
    )))
}
struct LyingProjection(ParsedStatement);
impl NativeStatement for LyingProjection {
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
        let mut claim = Box::new(self.0).project(binding)?;
        if let Claim::Delegation { scope, .. } = &mut claim {
            scope.operations.insert(op("write"));
        }
        Ok(claim)
    }
}
fn setup(decode: fn(&[u8]) -> Result<ParsedStatement, DecodeError>) -> (Door, Policy) {
    let mut p = policy("person");
    p.scope.person = Some(person(2));
    p.approval = ApprovalRule::Delegated([person(2)].into());
    let l = policy("lender");
    let facts = vec![
        Fact {
            source: p.source.clone(),
            state: FactState::Established,
        },
        Fact {
            source: l.source.clone(),
            state: FactState::Established,
        },
    ];
    let b = Basis::interpreted(
        id("reference-profile-v1"),
        30,
        vec![p.clone(), l],
        facts,
        vec![Codec {
            id: id("reference-native-v1"),
            decode,
        }],
        Recheck::OnSourceChange,
    )
    .unwrap();
    (Door::new(b, 4, "read"), p)
}
fn request_effect(operation: &str) -> Effect<Read> {
    Effect::from_bytes(request(4, operation), b"actual request".to_vec())
}

#[test]
fn invalid_prefix_does_not_force_verification_of_an_attackers_suffix() {
    let (door, p) = setup(counted);
    let valid = native::chain(&p);
    let evidence = Evidence::new([(p.owner.clone(), valid.clone())]).unwrap();
    DECODES.store(0, Ordering::SeqCst);
    door.run(request_effect("read"), &evidence).unwrap();
    assert!(DECODES.load(Ordering::SeqCst) >= 2);
    assert_eq!(door.effects(), 1);
    let OwnerEvidence::Native(chain) = valid else {
        unreachable!()
    };
    // These signatures are real. The second issuer is not the first holder,
    // so its entire suffix is irrelevant even though all signatures verify.
    let mut attack = vec![chain[0].clone(), chain[0].clone()];
    attack.extend(std::iter::repeat_n(chain[0].clone(), 64));
    let attack = Evidence::new([(p.owner, OwnerEvidence::Native(attack))]).unwrap();
    DECODES.store(0, Ordering::SeqCst);
    assert!(door.run(request_effect("read"), &attack).is_err());
    let work = DECODES.load(Ordering::SeqCst);
    assert!(
        work <= 2,
        "rejected prefix still decoded/verified {work} proofs"
    );
    assert_eq!(door.effects(), 1);
}

#[test]
fn installed_codec_semantics_are_inside_the_trusted_computing_base() {
    let (honest, p) = setup(native::codec().decode);
    let proof = Evidence::new([(p.owner.clone(), native::chain(&p))]).unwrap();
    let honest = Door {
        operation: op("write"),
        ..honest
    };
    assert!(honest.run(request_effect("write"), &proof).is_err());
    assert_eq!(honest.effects(), 0);
    // A compromised installed codec verifies the *same original signature*
    // while lying about the signed operation. The kernel cannot infer an
    // external protocol's true meaning from arbitrary transcript bytes.
    let (bad, _) = setup(reinterpreted);
    let bad = Door {
        operation: op("write"),
        ..bad
    };
    assert_eq!(
        honest.basis.lock().unwrap().fingerprint(),
        bad.basis.lock().unwrap().fingerprint(),
        "codec implementation changes must get a different installed profile/version"
    );
    bad.run(request_effect("write"), &proof).unwrap();
    assert_eq!(
        bad.effects(),
        1,
        "boundary assay, not a claimed security refusal"
    );
}

#[test]
fn a_compromised_admitter_can_lie_about_history_but_not_widen_its_root_scope() {
    let mut p = policy("person");
    p.actor = Some(person(4).into());
    p.scope.person = Some(person(2));
    p.scope.application = Some(Application::new("movie").unwrap());
    p.scope.coverage = Coverage::Exact(Resource::new("house/library").unwrap());
    let mut historical = Door::new(snapshot(100, vec![p.clone()], vec![]), 4, "write");
    historical.purpose = Purpose::HistoricalAdmission;
    let receipt_for = |effect: &Effect<Read>| {
        // The compromised key signs *now*, after expiry, falsely claiming79.
        let receipt = native::sign(
            native::Body::Admission {
                effect: effect.fingerprint(),
                at: 79,
                sources: [p.source.clone()].into(),
            },
            7,
        );
        Evidence::new([(
            p.owner.clone(),
            OwnerEvidence::Admitted {
                proof: Box::new(OwnerEvidence::Absent),
                receipt,
            },
        )])
        .unwrap()
    };
    let new_content = Effect::from_bytes(request(4, "write"), b"created after expiry".to_vec());
    let receipt = receipt_for(&new_content);
    historical.run(new_content, &receipt).unwrap();
    assert_eq!(
        historical.effects(),
        1,
        "compromise assay: signature cannot prove an honest past clock observation"
    );
    let live = Door::new(snapshot(79, vec![p.clone()], vec![]), 4, "write");
    assert!(
        live.run(
            Effect::from_bytes(request(4, "write"), b"created after expiry".to_vec()),
            &receipt
        )
        .is_err()
    );
    assert_eq!(live.effects(), 0);
    let mut outside = request(4, "write");
    outside.resource = Resource::new("house/admin").unwrap();
    let outside = Effect::from_bytes(outside, vec![1]);
    let receipt = receipt_for(&outside);
    assert!(historical.run(outside, &receipt).is_err());
    assert_eq!(historical.effects(), 1);
}
