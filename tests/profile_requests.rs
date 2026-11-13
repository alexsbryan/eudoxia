use eudoxia::*;
fn key() -> Principal {
    Principal::new(
        ed25519_dalek::SigningKey::from_bytes(&[1; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap()
}
fn descriptor(authority: AuthorityUse) -> serde_json::Value {
    serde_json::json!({"version":2,"request":"profile-request","actor":Actor::Session {issuer:key(),id:AuthorityId::from_bytes([2;32])},"subject":Subject::Person {group:AuthorityId::from_bytes([3;32]),person:key()},"authority":authority,"operation":"profile/record-command","resource":"profile/exact-resource"})
}
#[test]
fn a_profile_defined_operation_retains_explicit_session_subject_and_personal_use() {
    let request: Request = serde_json::from_value(descriptor(AuthorityUse::Personal)).unwrap();
    assert_eq!(
        request.actor(),
        Actor::Session {
            issuer: key(),
            id: AuthorityId::from_bytes([2; 32])
        }
    );
    assert_eq!(request.person(), Some(key()));
    assert_eq!(request.authority(), &AuthorityUse::Personal);
    assert_eq!(request.operation().as_str(), "profile/record-command");
    assert!(request.operation().native_kind().is_none());
}

struct Store<'a> {
    basis: Basis,
    calls: &'a std::cell::Cell<usize>,
}
fn operation() -> Operation {
    Operation::new("profile/record-command").unwrap()
}
fn resource() -> Resource {
    Resource::new("profile/exact-resource").unwrap()
}
fn actor() -> Actor {
    Actor::Session {
        issuer: key(),
        id: AuthorityId::from_bytes([2; 32]),
    }
}
fn subject() -> Subject {
    Subject::Person {
        group: AuthorityId::from_bytes([3; 32]),
        person: key(),
    }
}
impl ResourceGuard<Request> for Store<'_> {
    type Action = ();
    type Witness = Fingerprint;
    type Output = Vec<u8>;
    type Error = &'static str;
    fn ingress(&self) -> Ingress {
        Ingress::profile(
            actor(),
            subject(),
            AuthorityUse::Personal,
            operation(),
            resource(),
        )
    }
    fn current(&mut self) -> Result<Basis, Self::Error> {
        Ok(self.basis.clone())
    }
    fn prepare(
        &mut self,
        e: &Effect<(), Request>,
        o: &std::collections::BTreeSet<Obligation>,
    ) -> Result<Fingerprint, Self::Error> {
        if !o.is_empty() {
            return Err("unknown condition");
        }
        Ok(e.fingerprint())
    }
    fn commit(&mut self, a: Authorized<'_, Self, Request>) -> Result<Vec<u8>, Self::Error> {
        let (e, w, _) = a.into_parts();
        assert_eq!(e.fingerprint(), w);
        self.calls.set(self.calls.get() + 1);
        Ok(e.arguments().to_vec())
    }
}
fn basis(missing: bool) -> Basis {
    let make = |name: &str| {
        let source = SourceRef {
            namespace: Id::new("test-profile").unwrap(),
            algorithm: Id::new("sha256").unwrap(),
            digest: sha2::Sha256::digest(name.as_bytes()).to_vec(),
        };
        Policy {
            owner: Owner::new(name).unwrap(),
            source,
            scope: Scope {
                person: Some(key()),
                application: None,
                coverage: Coverage::Exact(resource()),
                operations: [
                    operation(),
                    Operation::new("profile/another-command").unwrap(),
                ]
                .into(),
                interval: Interval::new(0, 50).unwrap(),
                redelegations: 0,
            },
            approval: ApprovalRule::Standing,
            actor: None,
            effect: None,
            requires: Default::default(),
            admitters: Default::default(),
            carriers: Default::default(),
            obligations: Default::default(),
        }
    };
    use sha2::Digest;
    let ps = vec![make("person"), make("resource")];
    let facts = ps
        .iter()
        .enumerate()
        .map(|(i, p)| Fact {
            source: p.source.clone(),
            state: if missing && i == 1 {
                FactState::Missing
            } else {
                FactState::Established
            },
        })
        .collect();
    Basis::interpreted(
        Id::new("test-profile").unwrap(),
        30,
        ps,
        facts,
        vec![],
        Recheck::OnSourceChange,
    )
    .unwrap()
}
fn execute(request: Request, missing: bool, calls: &std::cell::Cell<usize>) -> bool {
    with_resource(
        Store {
            basis: basis(missing),
            calls,
        },
        |live| {
            let Ok(p) = live.derive(
                Effect::from_bytes(request, b"exact original operation".to_vec()),
                &Evidence::default(),
            ) else {
                return false;
            };
            let Ok(ready) = live.prepare(p) else {
                return false;
            };
            live.execute(ready).is_ok()
        },
    )
    .unwrap()
}
#[test]
fn a_profile_operation_still_requires_both_resource_owned_approvals_and_exact_ingress() {
    let request: Request = serde_json::from_value(descriptor(AuthorityUse::Personal)).unwrap();
    let calls = std::cell::Cell::new(0);
    assert!(!execute(request.clone(), true, &calls));
    assert_eq!(calls.get(), 0);
    assert!(execute(request, false, &calls));
    assert_eq!(calls.get(), 1);
    let mut forged = descriptor(AuthorityUse::Personal);
    forged["operation"] = serde_json::json!("profile/another-command");
    assert!(!execute(
        serde_json::from_value(forged).unwrap(),
        false,
        &calls
    ));
    assert_eq!(calls.get(), 1);
}
#[test]
fn custom_meaning_cannot_erase_classification_or_mix_a_native_resource() {
    let app = Application::classified(ApplicationAuthority::new(
        AuthorityRealm::Group([3; 32]),
        Id::new("app").unwrap(),
        ApplicationClass::Connector,
    ));
    assert!(
        serde_json::from_value::<Request>(descriptor(AuthorityUse::Application(app.clone())))
            .is_err()
    );
    let mut wire = descriptor(AuthorityUse::Personal);
    wire["resource"] = serde_json::to_value(Resource::identified(ResourceIdentity::app_endpoint(
        app.authority().unwrap(),
    )))
    .unwrap();
    assert!(serde_json::from_value::<Request>(wire).is_err());
    let mut wire = descriptor(AuthorityUse::Personal);
    wire["operation"] =
        serde_json::to_value(Operation::native(NativeOperation::AppendRecord)).unwrap();
    assert!(serde_json::from_value::<Request>(wire).is_err());
}
