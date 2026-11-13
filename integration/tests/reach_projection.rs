//! Native producer/callers are the oracle; this is a profile witness, not cutover.
#[allow(dead_code)]
mod profiles;
use eudoxia::*;
use profiles::{
    resource::{Door, Read},
    svrngs_pass::{Pass, bytes, principal},
    *,
};
use svrngs_core::{actor_of, pass::Label};

// This profile supplies a binding, not a new certificate on the native pass.
fn source() -> SourceRef {
    SourceRef {
        namespace: id("native-reach-person"),
        algorithm: id("ed25519-key"),
        digest: person(1).bytes().to_vec(),
    }
}

struct Reach {
    pass: Pass,
    issuer: Principal,
    signature: Vec<u8>,
    onward: u8,
}
fn parsed(raw: &[u8], onward: u8) -> Result<ParsedStatement, DecodeError> {
    let pass: Pass = serde_json::from_slice(raw).map_err(|_| DecodeError::Malformed)?;
    if pass.op.is_some() || pass.approval.is_some() {
        return Err(DecodeError::Malformed);
    }
    Ok(ParsedStatement::new(Reach {
        issuer: principal(&pass.person)?,
        signature: bytes(&pass.sig)?,
        pass,
        onward,
    }))
}
fn root(raw: &[u8]) -> Result<ParsedStatement, DecodeError> {
    parsed(raw, 1)
}
fn link(raw: &[u8]) -> Result<ParsedStatement, DecodeError> {
    parsed(raw, 0)
}
fn reads(lend: &Label) -> Resource {
    Resource::new(format!("lend/read/{lend}")).unwrap()
}
fn coverage(pass: &Pass) -> Coverage {
    Coverage::Set(
        core::iter::once(target(&pass.app, &pass.app))
            .chain(pass.reads.iter().map(reads))
            .collect(),
    )
}
impl NativeStatement for Reach {
    fn issuer(&self) -> Principal {
        self.issuer
    }
    fn signature(&self) -> &[u8] {
        &self.signature
    }
    fn signing_message(&self) -> std::borrow::Cow<'_, [u8]> {
        self.pass.message().into()
    }
    fn project(self: Box<Self>, binding: &SourceRef) -> Result<Claim, DecodeError> {
        if binding.namespace != id("native-reach-person") || binding.algorithm != id("ed25519-key")
        {
            return Err(DecodeError::Malformed);
        }
        let person = Principal::new(
            binding
                .digest
                .as_slice()
                .try_into()
                .map_err(|_| DecodeError::Malformed)?,
        )
        .map_err(|_| DecodeError::Malformed)?;
        Ok(Claim::Delegation {
            owner: Owner::new("person").unwrap(),
            holder: principal(&self.pass.holder)?,
            scope: Scope {
                person: Some(person),
                application: Some(Application::new(self.pass.app.clone()).unwrap()),
                coverage: coverage(&self.pass),
                operations: [op("read")].into(),
                interval: Interval::new(i64::MIN, self.pass.until)
                    .map_err(|_| DecodeError::Malformed)?,
                redelegations: self.onward,
            },
            sources: [binding.clone()].into(),
        })
    }
}

fn label(n: u8) -> Label {
    Label::of(person(n).bytes(), "app")
}
fn pass(by: u8, holder: u8, app: u8, reads: &[u8], until: i64) -> Pass {
    Pass::sign(
        &key(by),
        &actor_of(&key(holder)),
        (label(app), reads.iter().map(|n| label(*n)).collect()),
        until,
    )
}
fn target(app: &Label, lend: &Label) -> Resource {
    if lend == app {
        Resource::new(format!("lend/own/{lend}")).unwrap()
    } else {
        reads(lend)
    }
}
fn projected(parent: &Pass, link: Option<&Pass>, actor: u8, lend: &Label, at: i64) -> bool {
    let mut p = policy("person");
    p.source = source();
    p.scope = Scope {
        person: Some(person(1)),
        application: None,
        coverage: Coverage::Tree(Resource::new("lend").unwrap()),
        operations: [op("read")].into(),
        interval: Interval::new(i64::MIN, i64::MAX).unwrap(),
        redelegations: 1,
    };
    p.approval = ApprovalRule::Delegated([person(2)].into());
    p.carriers = [id("native-reach-root"), id("native-reach-link")].into();
    let basis = Basis::interpreted(
        id("native-reach-witness"),
        at,
        vec![p.clone()],
        vec![Fact {
            source: p.source.clone(),
            state: FactState::Established,
        }],
        vec![
            Codec {
                id: id("native-reach-root"),
                decode: root,
            },
            Codec {
                id: id("native-reach-link"),
                decode: self::link,
            },
        ],
        Recheck::OnSourceChange,
    )
    .unwrap();
    let evidence = Evidence::new([(
        p.owner,
        OwnerProof::Native(
            core::iter::once(("native-reach-root", parent))
                .chain(link.map(|l| ("native-reach-link", l)))
                .map(|(codec, p)| NativeEvidence {
                    codec: id(codec),
                    bytes: serde_json::to_vec(p).unwrap(),
                })
                .collect(),
        ),
    )])
    .unwrap();
    let mut e = request(actor, "read");
    e.person = person(1);
    e.application = Application::new(parent.app.clone()).unwrap();
    e.resource = target(&parent.app, lend);
    let door = Door::new(basis, actor, "read");
    let body = b"original native request".to_vec();
    let result = door.run(Effect::<Read>::from_bytes(e, body.clone()), &evidence);
    if let Ok(out) = &result {
        assert_eq!(out.body, body);
        assert_eq!(out.record.exercise.person, person(1));
        assert_eq!(out.record.exercise.actor, person(actor));
    }
    assert_eq!(door.effects(), usize::from(result.is_ok()));
    result.is_ok()
}

#[test]
fn a_lawful_holder_link_preserves_the_original_person_and_whole_scope() {
    let parent = pass(2, 4, 7, &[8, 9], 80);
    let link = pass(4, 5, 7, &[8], 60);
    assert_eq!(parent.check(&actor_of(&key(4)), &label(8), 30), Ok(()));
    assert!(projected(&parent, None, 4, &label(8), 30), "direct control");
    assert_eq!(
        parent.carries(&link, &actor_of(&key(5)), &label(8), 30),
        Ok(())
    );
    assert!(projected(&parent, Some(&link), 5, &label(8), 30));
}

#[test]
fn app_reach_does_not_allow_adding_the_app_to_the_signed_read_set() {
    let parent = pass(2, 4, 7, &[8], 80);
    let narrow = pass(4, 5, 7, &[8], 60);
    let wider = pass(4, 5, 7, &[7, 8], 60);
    let actor = actor_of(&key(5));
    assert_eq!(parent.carries(&narrow, &actor, &label(8), 30), Ok(()));
    assert_eq!(
        parent.carries(&wider, &actor, &label(8), 30),
        Err(svrngs_core::pass::PassFault::Wider)
    );
    assert!(projected(&parent, Some(&narrow), 5, &label(8), 30));
    assert!(!projected(&parent, Some(&wider), 5, &label(8), 30));
}

#[test]
fn signed_scope_and_presentation_changes_match_native_reach_in_the_lemma_domain() {
    let parent = pass(2, 4, 7, &[8, 9], 80);
    let link = pass(4, 5, 7, &[8], 60);
    let actor = actor_of(&key(5));
    let compare = |parent: &Pass, link: &Pass, at| {
        assert_eq!(
            projected(parent, Some(link), 5, &label(8), at),
            parent.carries(link, &actor, &label(8), at).is_ok(),
            "native until={}, link until={}, at={at}",
            parent.until,
            link.until
        );
    };
    for at in [i64::MIN, -1, 0, 59, 60, 79, 80, i64::MAX] {
        compare(&parent, &link, at);
    }
    for altered in [
        pass(4, 5, 7, &[8, 9], 60),
        pass(4, 5, 7, &[8, 9, 7], 60),
        pass(4, 5, 7, &[8], 81),
        pass(4, 5, 9, &[8], 60),
        pass(6, 5, 7, &[8], 60),
        pass(4, 6, 7, &[8], 60),
        pass(4, 5, 7, &[], 60),
        pass(4, 5, 7, &[8, 8], 60),
        pass(4, 5, 7, &[8], i64::MIN),
    ] {
        compare(&parent, &altered, 30);
    }
    let mut forged = link.clone();
    forged.reads.push(label(9));
    compare(&parent, &forged, 30);
    let mut entry = parent.clone();
    entry.op = Some(serde_json::from_value(serde_json::json!("00".repeat(32))).unwrap());
    compare(&entry, &link, 30);
    let mut stray_approval = link.clone();
    stray_approval.approval = Some("00".repeat(64));
    compare(&parent, &stray_approval, 30);
    let mut approvable = link;
    approvable.approver = Some(actor_of(&key(6)));
    approvable.sig = svrngs_core::sign_message(&key(4), &approvable.message());
    compare(&parent, &approvable, 30);
}

#[test]
fn the_native_public_string_api_is_not_identical_to_canonical_key_ingress() {
    let p = Pass::sign(&key(2), "not-a-key", (label(7), vec![]), 80);
    assert_eq!(p.check("not-a-key", &label(7), 30), Ok(()));
    let mut p = pass(2, 4, 7, &[], 80);
    p.person = p.person.to_uppercase();
    p.sig = svrngs_core::sign_message(&key(2), &p.message());
    assert_eq!(p.check(&actor_of(&key(4)), &label(7), 30), Ok(()));
    assert!(!projected(&p, None, 4, &label(7), 30));
}
