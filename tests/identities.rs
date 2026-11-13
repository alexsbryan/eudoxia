//! Authority identity v1 contract (docs/IDENTITIES.md).
mod profiles;
use eudoxia::*;
use profiles::{
    resource::{Door, Read},
    *,
};

#[derive(Clone, Copy)]
enum Class {
    Record,
    Connector,
}
#[derive(Clone, Copy)]
enum Use {
    ReadRecord,
    Append,
    Correct,
    ReadExternal,
    SendExternal,
    Own,
    Broker,
}
fn application(group: u8, class: Class) -> Application {
    Application::classified(ApplicationAuthority::new(
        AuthorityRealm::Group([group; 32]),
        id("notes"),
        match class {
            Class::Record => ApplicationClass::Record,
            Class::Connector => ApplicationClass::Connector,
        },
    ))
}
fn operation(use_: Use) -> Operation {
    Operation::native(match use_ {
        Use::ReadRecord => NativeOperation::ReadRecord,
        Use::Append => NativeOperation::AppendRecord,
        Use::Correct => NativeOperation::CorrectRecord,
        Use::ReadExternal => NativeOperation::ReadExternal,
        Use::SendExternal => NativeOperation::SendExternal,
        Use::Own => NativeOperation::UseOwnEndpoint,
        Use::Broker => NativeOperation::ReadBrokerStatus,
    })
}
fn target(group: u8, app: &Application, use_: Use) -> Resource {
    Resource::identified(match use_ {
        Use::ReadRecord | Use::Append | Use::Correct => {
            ResourceIdentity::record_part([group; 32], app.authority().unwrap())
        }
        Use::ReadExternal | Use::SendExternal => ResourceIdentity::lend(person(6), id("library")),
        Use::Own => ResourceIdentity::app_endpoint(app.authority().unwrap()),
        Use::Broker => {
            ResourceIdentity::native_broker(AuthorityRealm::Group([group; 32]), id("open-status"))
        }
    })
}
fn owner_policy(owner: &str, app: &Application, group: u8) -> Policy {
    let mut p = policy(owner);
    p.scope.application = Some(app.clone());
    p.actor = Some(person(4).into());
    p.scope.coverage = Coverage::Set(
        [Use::ReadRecord, Use::ReadExternal, Use::Own, Use::Broker]
            .map(|u| target(group, app, u))
            .into(),
    );
    p.scope.operations = [
        Use::ReadRecord,
        Use::Append,
        Use::Correct,
        Use::ReadExternal,
        Use::SendExternal,
        Use::Own,
        Use::Broker,
    ]
    .map(operation)
    .into();
    p
}
fn door(group: u8, class: Class, use_: Use) -> Door {
    let app = application(group, class);
    Door {
        operation: operation(use_),
        ..Door::new(
            snapshot(
                30,
                vec![
                    owner_policy("person", &app, group),
                    owner_policy("resource", &app, group),
                ],
                vec![],
            ),
            4,
            "unused",
        )
    }
}
fn effect(group: u8, class: Class, use_: Use) -> Effect<Read> {
    let mut e = request(4, "unused");
    e.application = application(group, class);
    e.operation = operation(use_);
    e.resource = target(group, &e.application, use_);
    Effect::from_bytes(e, b"owner's original bytes".to_vec())
}

#[test]
fn class_and_realm_are_part_of_authority_identity_not_display_name() {
    let a = application(1, Class::Record);
    assert_eq!(a, application(1, Class::Record));
    assert_ne!(a, application(1, Class::Connector));
    assert_ne!(a, application(2, Class::Record));
}

#[test]
fn record_authority_can_write_its_part_but_cannot_obtain_external_access() {
    let record = door(1, Class::Record, Use::Append);
    record
        .run(effect(1, Class::Record, Use::Append), &Evidence::default())
        .unwrap();
    assert_eq!(record.effects(), 1);
    let external = Door {
        operation: operation(Use::ReadExternal),
        ..record.clone()
    };
    assert!(
        external
            .run(
                effect(1, Class::Record, Use::ReadExternal),
                &Evidence::default()
            )
            .is_err()
    );
    assert_eq!(record.effects(), 1);
}

#[test]
fn connector_can_read_and_send_but_cannot_compose_record_writing() {
    let connector = door(1, Class::Connector, Use::ReadExternal);
    connector
        .run(
            effect(1, Class::Connector, Use::ReadExternal),
            &Evidence::default(),
        )
        .unwrap();
    let send = Door {
        operation: operation(Use::SendExternal),
        ..connector.clone()
    };
    send.run(
        effect(1, Class::Connector, Use::SendExternal),
        &Evidence::default(),
    )
    .unwrap();
    assert_eq!(connector.effects(), 2);
    let append = Door {
        operation: operation(Use::Append),
        ..connector.clone()
    };
    assert!(
        append
            .run(
                effect(1, Class::Connector, Use::Append),
                &Evidence::default()
            )
            .is_err()
    );
    assert_eq!(connector.effects(), 2);
}

#[test]
fn legacy_tree_labels_cannot_cover_native_resource_identities() {
    let app = application(1, Class::Record);
    let resource = target(1, &app, Use::Append);
    let mut p = owner_policy("person", &app, 1);
    // A display-label collision is not a native resource grant. The previous
    // path-prefix implementation discarded the distinction before comparison.
    p.scope.coverage = Coverage::Tree(Resource::new(resource.as_str()).unwrap());
    let d = Door {
        operation: operation(Use::Append),
        ..Door::new(snapshot(30, vec![p.clone()], vec![]), 4, "unused")
    };
    assert!(
        d.run(effect(1, Class::Record, Use::Append), &Evidence::default())
            .is_err()
    );
    assert_eq!(d.effects(), 0);
    p.scope.coverage = Coverage::Tree(resource);
    d.install(snapshot(30, vec![p], vec![]));
    d.run(effect(1, Class::Record, Use::Append), &Evidence::default())
        .unwrap();
    assert_eq!(d.effects(), 1);
}

#[test]
fn every_allowed_class_operation_reaches_the_real_owner_but_the_other_pair_does_not() {
    for class in [Class::Record, Class::Connector] {
        for use_ in [
            Use::ReadRecord,
            Use::Append,
            Use::Correct,
            Use::ReadExternal,
            Use::SendExternal,
            Use::Own,
            Use::Broker,
        ] {
            let d = door(1, class, use_);
            let allowed = !matches!(
                (class, use_),
                (Class::Record, Use::ReadExternal | Use::SendExternal)
                    | (Class::Connector, Use::Append | Use::Correct)
            );
            let result = d.run(effect(1, class, use_), &Evidence::default());
            assert_eq!(result.is_ok(), allowed);
            assert_eq!(d.effects(), usize::from(allowed));
        }
    }
}

fn with_exercise(e: Exercise) -> Effect<Read> {
    Effect::from_bytes(e, b"owner's original bytes".to_vec())
}

#[test]
fn wrong_family_other_apps_part_and_other_group_fail_even_with_explicit_standing() {
    let app = application(1, Class::Record);
    let mut e = effect(1, Class::Record, Use::Append).exercise().clone();
    for wrong in [
        target(1, &app, Use::ReadExternal),
        target(1, &application(1, Class::Connector), Use::Append),
        target(2, &app, Use::Append),
    ] {
        let mut p = owner_policy("person", &app, 1);
        p.scope.coverage = Coverage::Exact(wrong.clone());
        let d = Door {
            operation: operation(Use::Append),
            ..Door::new(snapshot(30, vec![p], vec![]), 4, "unused")
        };
        e.resource = wrong;
        let f = with_exercise(e.clone());
        let r = inspect(&d.basis.lock().unwrap(), &f, &Evidence::default());
        assert_eq!(
            r.owners[0].decision,
            OwnerDecision::Refused(Reason::ResourceContextMismatch)
        );
        assert!(d.run(f, &Evidence::default()).is_err());
        assert_eq!(d.effects(), 0);
    }
    let mut own = effect(1, Class::Record, Use::Own).exercise().clone();
    own.resource = target(1, &application(1, Class::Connector), Use::Own);
    assert!(
        door(1, Class::Record, Use::Own)
            .run(with_exercise(own), &Evidence::default())
            .is_err()
    );
}

#[test]
fn native_operation_guard_cannot_be_relabelled_as_a_permitted_read() {
    let d = door(1, Class::Connector, Use::Append);
    assert!(
        d.run(
            effect(1, Class::Connector, Use::ReadRecord),
            &Evidence::default()
        )
        .is_err()
    );
    assert_eq!(d.effects(), 0);
}

#[test]
fn partial_legacy_context_is_a_typed_need_not_a_class_or_personal_fallback() {
    for missing in [
        ContextNeed::ApplicationIdentity,
        ContextNeed::ResourceIdentity,
        ContextNeed::OperationMeaning,
    ] {
        let d = door(1, Class::Record, Use::Append);
        let mut e = effect(1, Class::Record, Use::Append).exercise().clone();
        match missing {
            ContextNeed::ApplicationIdentity => {
                e.application = Application::new(e.application.as_str()).unwrap()
            }
            ContextNeed::ResourceIdentity => {
                e.resource = Resource::new(e.resource.as_str()).unwrap()
            }
            ContextNeed::OperationMeaning => {
                e.operation = Operation::new(e.operation.as_str()).unwrap()
            }
            ContextNeed::ExecutionContext => unreachable!(),
        }
        let f = with_exercise(e);
        let r = inspect(&d.basis.lock().unwrap(), &f, &Evidence::default());
        assert_eq!(r.decision, Decision::Undetermined);
        assert!(r.owners.iter().all(
            |o| matches!(&o.decision,OwnerDecision::Undetermined(n) if n.context==[missing].into())
        ));
        assert!(d.run(f, &Evidence::default()).is_err());
        assert_eq!(d.effects(), 0);
    }
}

#[test]
fn two_owner_native_signed_composition_preserves_class_and_original_signatures() {
    use profiles::native::{self, Body};
    for (class, use_, allowed) in [
        (Class::Record, Use::Append, true),
        (Class::Connector, Use::ReadExternal, true),
        (Class::Record, Use::ReadExternal, false),
        (Class::Connector, Use::Append, false),
    ] {
        let app = application(1, class);
        let mut ps = vec![
            owner_policy("person", &app, 1),
            owner_policy("resource", &app, 1),
        ];
        let entries: Vec<_> = ps
            .iter_mut()
            .enumerate()
            .map(|(i, p)| {
                let issuer = if i == 0 { 2 } else { 6 };
                p.approval = ApprovalRule::Delegated([person(issuer)].into());
                let mut first = p.scope.clone();
                first.redelegations = 1;
                let mut last = first.clone();
                last.redelegations = 0;
                last.operations = [operation(use_)].into();
                last.coverage = Coverage::Exact(target(1, &app, use_));
                (
                    p.owner.clone(),
                    OwnerEvidence::Native(vec![
                        native::sign(
                            Body::Delegation {
                                owner: p.owner.clone(),
                                holder: person(3),
                                scope: first,
                                sources: [p.source.clone()].into(),
                            },
                            issuer,
                        ),
                        native::sign(
                            Body::Delegation {
                                owner: p.owner.clone(),
                                holder: person(4),
                                scope: last,
                                sources: [p.source.clone()].into(),
                            },
                            3,
                        ),
                    ]),
                )
            })
            .collect();
        let evidence = Evidence::new(entries.clone()).unwrap();
        let d = Door {
            operation: operation(use_),
            ..Door::new(snapshot(30, ps, vec![]), 4, "unused")
        };
        assert_eq!(d.run(effect(1, class, use_), &evidence).is_ok(), allowed);
        assert_eq!(d.effects(), usize::from(allowed));
        // A wire edit to immutable class cannot keep the previous signature.
        if allowed {
            // The envelope signs original body bytes. Mutate the parsed body,
            // retaining the original signature and every other authority source.
            let OwnerEvidence::Native(proofs) = &entries[0].1 else {
                unreachable!()
            };
            let mut proof = proofs[0].clone();
            let mut env: native::Envelope = serde_json::from_slice(&proof.bytes).unwrap();
            let mut body: serde_json::Value = serde_json::from_slice(&env.body).unwrap();
            body["Delegation"]["scope"]["application"]["class"] = serde_json::json!("connector");
            if matches!(class, Class::Connector) {
                body["Delegation"]["scope"]["application"]["class"] = serde_json::json!("record");
            }
            env.body = serde_json::to_vec(&body).unwrap();
            proof.bytes = serde_json::to_vec(&env).unwrap();
            let mut entries = entries.clone();
            let OwnerEvidence::Native(chain) = &mut entries[0].1 else {
                unreachable!()
            };
            chain[0] = proof;
            let tampered = Evidence::new(entries).unwrap();
            let report = inspect(&d.basis.lock().unwrap(), &effect(1, class, use_), &tampered);
            assert_eq!(
                report.owners[0].decision,
                OwnerDecision::Refused(Reason::InvalidSignature)
            );
            assert!(d.run(effect(1, class, use_), &tampered).is_err());
            assert_eq!(d.effects(), 1);
        }
    }
}

#[test]
fn independent_identity_and_full_origin_vectors_are_not_json_hashes() {
    let a = application(1, Class::Record);
    let a = a.authority().unwrap();
    assert_eq!(
        a.identity().hex(),
        "130e65aef001d4529f0e1257f3cc94c12d03ed3edbb47fcdae196deea084b64c"
    );
    assert_eq!(
        a.origin_label(),
        "acmhgllxqahkffhyocjl7hteuyewqh3j63o2h7tnodfw65ieewzga"
    );
    assert_eq!(
        application(1, Class::Connector)
            .authority()
            .unwrap()
            .identity()
            .hex(),
        "e5a605adf54f9d4f0d2ad33683cd0fabc485cd8134626c1e8fc3f26988adbe4c"
    );
    assert_eq!(
        application(2, Class::Record)
            .authority()
            .unwrap()
            .identity()
            .hex(),
        "2c8343939bfcc438ff2243c6dcf6aab0eb456a256b9e2188934f5d491e7352cd"
    );
    assert_eq!(
        ResourceIdentity::record_part([1; 32], a).identity().hex(),
        "5c141d85e069a30ddd3046fc1241efeef069632c67ec76eb2afb29bfb5ac27c3"
    );
    assert_eq!(
        ResourceIdentity::app_endpoint(a).identity().hex(),
        "7098e1c647edb1397b8fdef91c53260a05054298d4f1ff7bdbeffe50a5e8bf6a"
    );
    assert_ne!(
        AuthorityId::from_bytes([0; 32]).origin_label(),
        AuthorityId::from_bytes([255; 32]).origin_label()
    );
    let computer = Principal::new([
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ])
    .unwrap();
    let app = ApplicationAuthority::new(
        AuthorityRealm::Computer(computer),
        id("café"),
        ApplicationClass::Record,
    );
    assert_eq!(
        app.identity().hex(),
        "7e2713b61b46933559f132fa247d7fe7d8408ccf53383a2afce7ddd5c5173087"
    );
    assert_eq!(
        ResourceIdentity::lend(computer, id("café"))
            .identity()
            .hex(),
        "f30d3b1df033aab9d8ce5b08033e5c1402756fd60e4c9389267461a904e38954"
    );
    assert_eq!(
        ResourceIdentity::native_broker(AuthorityRealm::Computer(computer), id("open-status"))
            .identity()
            .hex(),
        "79b4134a8b92368d205cd97ef826dee31b22ba92283a83fc9a2ed2865ce413e3"
    );
}

#[test]
fn computer_scoped_record_still_needs_each_targets_actual_owner_policy() {
    let app = Application::classified(ApplicationAuthority::new(
        AuthorityRealm::Computer(person(1)),
        id("notes"),
        ApplicationClass::Record,
    ));
    let mut p = owner_policy("actual-group", &app, 1);
    p.scope.coverage = Coverage::Exact(target(1, &app, Use::Append));
    let d = Door {
        operation: operation(Use::Append),
        ..Door::new(snapshot(30, vec![p.clone()], vec![]), 4, "unused")
    };
    let mut e = effect(1, Class::Record, Use::Append).exercise().clone();
    e.application = app.clone();
    e.resource = target(1, &app, Use::Append);
    d.run(with_exercise(e.clone()), &Evidence::default())
        .unwrap();
    e.resource = target(2, &app, Use::Append);
    assert!(
        d.run(with_exercise(e.clone()), &Evidence::default())
            .is_err()
    );
    assert_eq!(d.effects(), 1);
    p.scope.coverage = Coverage::Exact(e.resource.clone());
    d.install(snapshot(30, vec![p], vec![]));
    d.run(with_exercise(e), &Evidence::default()).unwrap();
    assert_eq!(d.effects(), 2);
}

#[test]
fn definitions_recompute_identity_reject_cache_version_and_unknown_fields() {
    let original = application(1, Class::Record);
    let wire = serde_json::to_value(&original).unwrap();
    let decoded: Application = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(decoded, original);
    let mut changed = wire.clone();
    changed["class"] = serde_json::json!("connector");
    let changed: Application = serde_json::from_value(changed).unwrap();
    assert_ne!(changed, original);
    assert_ne!(
        changed.authority().unwrap().origin_label(),
        original.authority().unwrap().origin_label()
    );
    for (field, value) in [
        ("identity", serde_json::json!(vec![0; 32])),
        ("unknown", serde_json::json!(true)),
        ("version", serde_json::json!(2)),
        ("name", serde_json::json!(" notes")),
    ] {
        let mut wrong = wire.clone();
        wrong[field] = value;
        assert!(serde_json::from_value::<Application>(wrong).is_err());
    }
    let resource = target(1, &original, Use::Own);
    let wire = serde_json::to_value(&resource).unwrap();
    assert_eq!(
        serde_json::from_value::<Resource>(wire.clone()).unwrap(),
        resource
    );
    for field in ["identity", "unknown"] {
        let mut wrong = wire.clone();
        wrong[field] = serde_json::json!("forged");
        assert!(serde_json::from_value::<Resource>(wrong).is_err());
    }
    let mut wrong = wire;
    wrong["definition"]["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Resource>(wrong).is_err());
    assert!(
        serde_json::from_str::<Operation>(r#"{"native":"append-record","unknown":true}"#).is_err()
    );
    assert!(serde_json::from_str::<Operation>(r#"{"native":"unknown-operation"}"#).is_err());
}

#[test]
fn legacy_strings_remain_distinct_and_old_records_cannot_replay_as_new() {
    let d = door(1, Class::Record, Use::Own);
    let e = effect(1, Class::Record, Use::Own);
    let evidence = Evidence::default();
    let r = inspect(&d.basis.lock().unwrap(), &e, &evidence);
    assert_eq!(r.version, 7);
    let copy: DecisionRecord = serde_json::from_slice(&serde_json::to_vec(&r).unwrap()).unwrap();
    assert_eq!(copy.replay(&d.basis.lock().unwrap(), &evidence).unwrap(), r);
    let mut old = r;
    old.version = 6;
    assert_eq!(
        old.replay(&d.basis.lock().unwrap(), &evidence),
        Err(ReplayError::JudgmentChanged)
    );
    for value in [
        "notes",
        "app:130e65aef001d4529f0e1257f3cc94c12d03ed3edbb47fcdae196deea084b64c",
    ] {
        let legacy: Application = serde_json::from_value(serde_json::json!(value)).unwrap();
        assert!(legacy.authority().is_none());
        assert_eq!(
            serde_json::to_value(legacy).unwrap(),
            serde_json::json!(value)
        );
    }
}
