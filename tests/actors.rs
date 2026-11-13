//! Native context witnesses.
mod profiles;
use eudoxia::*;
use profiles::*;
use std::{cell::Cell, collections::BTreeSet};

struct Read;
struct Door<'a> {
    basis: &'a Basis,
    ingress: &'a Ingress,
    calls: &'a Cell<usize>,
}
impl ResourceGuard<Request> for Door<'_> {
    type Action = Read;
    type Witness = Fingerprint;
    type Output = DecisionRecord<Request>;
    type Error = &'static str;
    fn ingress(&self) -> Ingress {
        self.ingress.clone()
    }
    fn current(&mut self) -> Result<Basis, Self::Error> {
        Ok(self.basis.clone())
    }
    fn prepare(
        &mut self,
        e: &Effect<Read, Request>,
        o: &BTreeSet<Obligation>,
    ) -> Result<Fingerprint, Self::Error> {
        if !o.is_empty() {
            return Err("unknown obligation");
        }
        Ok(e.fingerprint())
    }
    fn commit(&mut self, a: Authorized<'_, Self, Request>) -> Result<Self::Output, Self::Error> {
        let (e, w, r) = a.into_parts();
        assert_eq!(e.fingerprint(), w);
        self.calls.set(self.calls.get() + 1);
        Ok(r)
    }
}
fn group() -> AuthorityId {
    AuthorityId::from_bytes([1; 32])
}
fn subject() -> Subject {
    Subject::Person {
        group: group(),
        person: person(2),
    }
}
fn session(n: u8) -> Actor {
    Actor::Session {
        issuer: person(1),
        id: AuthorityId::from_bytes([n; 32]),
    }
}
fn app() -> Application {
    Application::classified(ApplicationAuthority::new(
        AuthorityRealm::Group([1; 32]),
        id("notes"),
        ApplicationClass::Record,
    ))
}
fn part() -> ResourceIdentity {
    ResourceIdentity::record_part([1; 32], app().authority().unwrap())
}
fn request_(
    actor: Actor,
    subject: Subject,
    authority: AuthorityUse,
    operation: NativeOperation,
    resource: ResourceIdentity,
) -> Result<Request, Invalid> {
    Request::new(
        id("native-request"),
        actor,
        subject,
        authority,
        operation,
        resource,
    )
}
fn write(actor: Actor) -> Request {
    request_(
        actor,
        subject(),
        AuthorityUse::Application(app()),
        NativeOperation::AppendRecord,
        part(),
    )
    .unwrap()
}
fn ingress(actor: Actor) -> Ingress {
    Ingress::new(
        actor,
        subject(),
        AuthorityUse::Application(app()),
        NativeOperation::AppendRecord,
        part(),
    )
}
/// The exact-scope standing policy each required owner gets, as a hand-built
/// basis would say it. Sealed: the kernel refuses it (`Basis::interpreted`).
fn hand_built(r: &Request) -> Result<Basis, Invalid> {
    let ps = r
        .required_owners()
        .unwrap()
        .into_iter()
        .map(|o| {
            let mut p = policy(o.as_str());
            p.scope.application = r.application().cloned();
            p.scope.person = r.person();
            p.scope.coverage = Coverage::Exact(r.resource().clone());
            p.scope.operations = [r.operation().clone()].into();
            p
        })
        .collect();
    let facts = vec![];
    Basis::interpreted(
        id("reference-profile-v1"),
        30,
        ps,
        facts,
        vec![],
        Recheck::OnSourceChange,
    )
}
/// Every required owner permits by rule; with `omit`, the person owner's permit
/// reads a fact the request lacks, so that owner stays undetermined.
fn basis_for(r: &Request, omit: bool) -> Basis {
    let fact = |name: &str| Term::Fact(id(name));
    let person = r
        .required_owners()
        .unwrap()
        .into_iter()
        .find(|o| o.as_str().starts_with("person:"));
    let condition = match omit {
        false => Condition::All(vec![]),
        true => Condition::Any(vec![
            Condition::Not(Box::new(Condition::Same(Term::Owner, fact("person-owner")))),
            Condition::Holds(fact("person-agrees")),
        ]),
    };
    let rules = Rules::new(vec![Rule {
        id: id("test/permit"),
        verdict: Verdict::Permit,
        operations: [r.operation().clone()].into(),
        condition,
    }])
    .unwrap();
    let asked = Asked {
        at: 30,
        operation: r.operation().clone(),
        resource: r.resource().clone(),
        facts: person
            .map(|o| (id("person-owner"), Value::Text(o.as_str().into())))
            .into_iter()
            .collect(),
    };
    let effect = Effect::<Read, Request>::from_bytes(r.clone(), vec![]);
    let (basis, _) = rules
        .basis(id("reference-profile-v1"), &effect, BTreeSet::new(), &asked)
        .unwrap();
    basis
}
fn run(
    r: Result<Request, Invalid>,
    i: &Ingress,
    b: &Basis,
    calls: &Cell<usize>,
) -> Result<DecisionRecord<Request>, String> {
    let r = r.map_err(|e| e.to_string())?;
    with_resource(
        Door {
            basis: b,
            ingress: i,
            calls,
        },
        |live| {
            let p = live
                .derive(
                    Effect::from_bytes(r, vec![0, 255, 42]),
                    &Evidence::default(),
                )
                .map_err(|e| e.to_string())?;
            let p = live.prepare(p).map_err(|e| e.to_string())?;
            live.execute(p).map_err(|e| e.to_string())
        },
    )
    .unwrap()
}

#[test]
fn an_anonymous_request_cannot_borrow_the_hosts_person_or_write_authority() {
    let good = write(session(1));
    let b = basis_for(&good, false);
    let count = Cell::new(0);
    assert!(
        run(
            request_(
                Actor::Anonymous,
                subject(),
                AuthorityUse::Application(app()),
                NativeOperation::AppendRecord,
                part()
            ),
            &ingress(session(1)),
            &b,
            &count
        )
        .is_err()
    );
    assert_eq!(count.get(), 0);
    run(Ok(good), &ingress(session(1)), &b, &count).unwrap();
    assert_eq!(count.get(), 1);
}

#[test]
fn two_same_person_sessions_are_not_the_same_authenticated_ingress() {
    let r = write(session(1));
    let b = basis_for(&r, false);
    let count = Cell::new(0);
    // The other session's own basis permits it, so only ingress can refuse.
    let other = write(session(2));
    let permits_other = basis_for(&other, false);
    assert!(run(Ok(other), &ingress(session(1)), &permits_other, &count).is_err());
    assert_eq!(count.get(), 0);
    run(Ok(r), &ingress(session(1)), &b, &count).unwrap();
    assert_eq!(count.get(), 1);
}

/// A native issuer's personal key scope precedes group-standing resolution.
/// Its holder is an authenticated protocol session, with literal native spelling
/// retained in that session's identity, not an invented key or social group.
#[test]
fn native_key_scope_has_no_invented_group_and_binds_the_exact_session() {
    let mut wire = serde_json::to_value(write(session(1))).unwrap();
    wire["subject"] = serde_json::json!({ "kind": "principal", "principal": person(2) });
    wire["authority"] = serde_json::json!({ "kind": "personal" });
    wire["operation"] = serde_json::json!("native-use");
    wire["resource"] = serde_json::json!("native-part");
    let request: Request = serde_json::from_value(wire).unwrap();
    assert_eq!(request.subject().group(), None);
    assert_eq!(request.person(), Some(person(2)));
    let mut p = policy("native-issuer");
    p.scope.person = request.person();
    p.scope.application = None;
    p.scope.operations = [request.operation().clone()].into();
    p.scope.coverage = Coverage::Exact(request.resource().clone());
    let mut wire = serde_json::to_value(p).unwrap();
    wire["actor"] = serde_json::to_value(session(1)).unwrap();
    let p: Policy = serde_json::from_value(wire).unwrap();
    let b = snapshot(30, vec![p], vec![]);
    let ingress = |actor| {
        Ingress::profile(
            actor,
            request.subject(),
            AuthorityUse::Personal,
            request.operation().clone(),
            request.resource().clone(),
        )
    };
    let count = Cell::new(0);
    run(Ok(request.clone()), &ingress(session(1)), &b, &count).unwrap();
    assert_eq!(count.get(), 1);
    let mut other = serde_json::to_value(&request).unwrap();
    other["actor"] = serde_json::to_value(session(2)).unwrap();
    assert!(
        run(
            serde_json::from_value(other).map_err(|_| Invalid::Context),
            &ingress(session(2)),
            &b,
            &count
        )
        .is_err()
    );
    assert_eq!(
        count.get(),
        1,
        "a genuine second session is not the selected holder"
    );

    let mut native = serde_json::to_value(write(session(1))).unwrap();
    native["subject"] = serde_json::json!({ "kind": "principal", "principal": person(2) });
    assert!(
        serde_json::from_value::<Request>(native).is_err(),
        "key scope cannot erase a native operation's required group"
    );
}

#[test]
fn a_native_operation_cannot_omit_the_person_owner_from_its_policy_set() {
    let r = write(session(1));
    // No caller assembles a native request's owners by hand, omitted or not.
    assert_eq!(hand_built(&r).unwrap_err(), Invalid::Policy);
    let count = Cell::new(0);
    // An owner outside the required form may hold a native policy, but its
    // permit cannot stand in for the required owners it omits.
    let mut stranger = policy("local-admin");
    stranger.scope.application = r.application().cloned();
    stranger.scope.person = r.person();
    stranger.scope.coverage = Coverage::Exact(r.resource().clone());
    stranger.scope.operations = [r.operation().clone()].into();
    let established = Fact {
        source: stranger.source.clone(),
        state: FactState::Established,
    };
    let stranger = Basis::interpreted(
        id("reference-profile-v1"),
        30,
        vec![stranger],
        vec![established],
        vec![],
        Recheck::OnSourceChange,
    )
    .unwrap();
    assert!(run(Ok(r.clone()), &ingress(session(1)), &stranger, &count).is_err());
    assert_eq!(count.get(), 0);
    let missing = basis_for(&r, true);
    let report = inspect(
        &missing,
        &Effect::<Read, Request>::from_bytes(r.clone(), vec![]),
        &Evidence::default(),
    );
    assert_eq!(report.decision, Decision::Undetermined);
    assert_eq!(report.owners.len(), 2);
    assert!(run(Ok(r.clone()), &ingress(session(1)), &missing, &count).is_err());
    assert_eq!(count.get(), 0);
    run(
        Ok(r.clone()),
        &ingress(session(1)),
        &basis_for(&r, false),
        &count,
    )
    .unwrap();
    assert_eq!(count.get(), 1);
}

#[test]
fn an_explicit_public_output_works_without_any_fabricated_person_or_key() {
    let resource = ResourceIdentity::lend(person(6), id("on-air"));
    for actor in [
        Actor::Anonymous,
        session(1),
        Actor::Key { key: person(4) },
        Actor::Bearer {
            issuer: person(6),
            id: AuthorityId::from_bytes([3; 32]),
        },
    ] {
        let r = request_(
            actor,
            Subject::None,
            AuthorityUse::Public,
            NativeOperation::ReadPublicOutput,
            resource.clone(),
        )
        .unwrap();
        let b = basis_for(&r, false);
        assert_eq!(b.policies().len(), 1);
        let i = Ingress::new(
            actor,
            Subject::None,
            AuthorityUse::Public,
            NativeOperation::ReadPublicOutput,
            resource.clone(),
        );
        let count = Cell::new(0);
        let record = run(Ok(r), &i, &b, &count).unwrap();
        assert_eq!(count.get(), 1);
        assert_eq!(record.exercise.subject(), Subject::None);
        let wire = serde_json::to_vec(&record).unwrap();
        let restored: DecisionRecord<Request> = serde_json::from_slice(&wire).unwrap();
        assert_eq!(restored.replay(&b, &Evidence::default()).unwrap(), record);
    }
}

#[test]
fn personal_authority_subject_and_actual_target_are_independent_ingress_bindings() {
    let r = write(session(1));
    let b = basis_for(&r, false);
    let count = Cell::new(0);
    let personal = request_(
        session(1),
        subject(),
        AuthorityUse::Personal,
        NativeOperation::AppendRecord,
        part(),
    )
    .unwrap();
    assert!(run(Ok(personal), &ingress(session(1)), &b, &count).is_err());
    let wrong_subject = Subject::Person {
        group: group(),
        person: person(9),
    };
    let other = request_(
        session(1),
        wrong_subject,
        AuthorityUse::Application(app()),
        NativeOperation::AppendRecord,
        part(),
    )
    .unwrap();
    assert!(run(Ok(other), &ingress(session(1)), &b, &count).is_err());
    assert_eq!(count.get(), 0);
    assert!(
        request_(
            session(1),
            Subject::Person {
                group: AuthorityId::from_bytes([2; 32]),
                person: person(2)
            },
            AuthorityUse::Application(app()),
            NativeOperation::AppendRecord,
            part()
        )
        .is_err()
    );
}

#[test]
fn public_target_substitution_is_stopped_by_ingress_even_under_the_same_lender() {
    let a = ResourceIdentity::lend(person(6), id("on-air"));
    let b = ResourceIdentity::lend(person(6), id("other-output"));
    let r = request_(
        Actor::Anonymous,
        Subject::None,
        AuthorityUse::Public,
        NativeOperation::ReadPublicOutput,
        b,
    )
    .unwrap();
    let basis = basis_for(&r, false);
    let count = Cell::new(0);
    let i = Ingress::new(
        Actor::Anonymous,
        Subject::None,
        AuthorityUse::Public,
        NativeOperation::ReadPublicOutput,
        a,
    );
    assert!(run(Ok(r), &i, &basis, &count).is_err());
    assert_eq!(count.get(), 0);
}

#[test]
fn visits_are_their_own_subject_and_never_reach_another_host_or_group_record() {
    let s = Subject::Visit {
        group: group(),
        visit: AuthorityId::from_bytes([7; 32]),
        host: person(6),
        guest: person(8),
    };
    let authority = AuthorityUse::Personal;
    let actor = Actor::Key { key: person(8) };
    let resource = ResourceIdentity::lend(person(6), id("film"));
    let r = request_(
        actor,
        s,
        authority.clone(),
        NativeOperation::UseLend,
        resource.clone(),
    )
    .unwrap();
    let b = basis_for(&r, false);
    let c = Cell::new(0);
    run(
        Ok(r),
        &Ingress::new(
            actor,
            s,
            authority.clone(),
            NativeOperation::UseLend,
            resource,
        ),
        &b,
        &c,
    )
    .unwrap();
    assert_eq!(c.get(), 1);
    assert!(
        request_(
            actor,
            s,
            authority.clone(),
            NativeOperation::UseLend,
            ResourceIdentity::lend(person(9), id("film"))
        )
        .is_err()
    );
    assert!(request_(actor, s, authority, NativeOperation::AppendRecord, part()).is_err());
}
