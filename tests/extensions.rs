#[path = "common/legacy.rs"]
mod legacy_carrier;
mod profiles;
use eudoxia::*;
use legacy_carrier::{Grant, SignedGrant, Terms};
use profiles::{
    constitution::{self as c, Act, Constitution, History},
    native::{self, Body},
    resource::{Door, Read},
    *,
};
use std::{
    collections::BTreeSet,
    sync::{Arc, Barrier},
};

fn effect(actor: u8, operation: &str) -> Effect<Read> {
    Effect::from_bytes(request(actor, operation), b"original\0body".to_vec())
}
fn exercise_line(
    profile: &Constitution,
    entries: &[NativeEvidence],
) -> (Door, Result<resource::Output, String>) {
    let effect = profile.effect(entries);
    let mut door = Door::new(
        profile
            .establish(&History::known(entries.to_vec()), 30)
            .unwrap(),
        2,
        "write",
    );
    door.actor = effect.exercise().actor;
    let output = door.run(effect, &Evidence::default());
    (door, output)
}
fn require_wait(profile: &Constitution, entries: &[NativeEvidence], reference: &SourceRef) {
    let effect = profile.effect(entries);
    let basis = profile
        .establish(&History::known(entries.to_vec()), 30)
        .unwrap();
    let record = inspect(&basis, &effect, &Evidence::default());
    assert_eq!(record.decision, Decision::Undetermined);
    assert!(record.owners.iter().any(
        |o| matches!(&o.decision,OwnerDecision::Undetermined(n) if n.sources.contains(reference))
    ));
    let (d, r) = exercise_line(profile, entries);
    assert!(r.is_err());
    assert_eq!(d.effects(), 0);
}

#[test]
fn b01_sources_not_display_time_or_carrier_determine_counted_effects() {
    let (old, old_line) = c::line(
        1,
        None,
        900,
        Act::Invite {
            power: c::root(),
            key: person(8),
            person: person(8),
        },
    );
    let (handover, h) = c::line(
        1,
        Some(old.clone()),
        -900,
        Act::HandOn {
            power: c::root(),
            to: person(2),
        },
    );
    let (jo, jo_line) = c::line(
        2,
        None,
        -999,
        Act::Invite {
            power: handover.clone(),
            key: person(9),
            person: person(9),
        },
    );
    let (bad, bad_line) = c::line(
        1,
        Some(handover.clone()),
        -9999,
        Act::Invite {
            power: c::root(),
            key: person(10),
            person: person(10),
        },
    );
    let entries = vec![
        old_line.clone(),
        h.clone(),
        jo_line.clone(),
        bad_line.clone(),
    ];
    let mut reordered = entries.clone();
    reordered.reverse();
    reordered.push(h.clone());
    for target in [&old, &jo] {
        let p = Constitution::new(target.clone());
        let a = p.establish(&History::known(entries.clone()), 30).unwrap();
        let b = p.establish(&History::known(reordered.clone()), 30).unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint());
        for carrier in [6, 10] {
            let received = transport::receive(transport::send(carrier, &reordered)).unwrap();
            let (door, r) = exercise_line(&p, &received);
            assert!(r.is_ok());
            assert_eq!(door.effects(), 1);
        }
    }
    let mut forged_packet = transport::send(6, &reordered);
    forged_packet.carrier = person(10);
    assert!(transport::receive(forged_packet).is_err());
    let (door, r) = exercise_line(&Constitution::new(bad), &entries);
    assert!(r.is_err());
    assert_eq!(door.effects(), 0);
    require_wait(&Constitution::new(jo), &[jo_line], &handover);
}

#[test]
fn b02_opaque_bytes_and_installed_native_evidence_have_one_producer() {
    let mut p = policy("person");
    p.approval = ApprovalRule::Delegated([person(2)].into());
    let proof = Evidence::new([(p.owner.clone(), native::chain(&p))]).unwrap();
    let door = Door::new(snapshot(30, vec![p.clone()], vec![]), 4, "read");
    let bytes = b"{\"n\":1.00,\"s\":\"\\u0061\"}\n\xff".to_vec();
    let out = door
        .run(
            Effect::from_bytes(request(4, "read"), bytes.clone()),
            &proof,
        )
        .unwrap();
    assert_eq!(out.body, bytes);
    assert_eq!(door.effects(), 1);
    assert_eq!(
        out.record
            .replay(&snapshot(30, vec![p.clone()], vec![]), &proof)
            .unwrap(),
        out.record
    );
    let OwnerEvidence::Native(mut chain) = native::chain(&p) else {
        unreachable!()
    };
    let mut env: native::Envelope = serde_json::from_slice(&chain[1].bytes).unwrap();
    env.body.push(b' ');
    chain[1].bytes = serde_json::to_vec(&env).unwrap();
    let forged = Evidence::new([(p.owner.clone(), OwnerEvidence::Native(chain))]).unwrap();
    assert!(door.run(effect(4, "read"), &forged).is_err());
    assert_eq!(door.effects(), 1);
    let unknown = Evidence::new([(
        p.owner.clone(),
        OwnerEvidence::Native(vec![NativeEvidence {
            codec: id("unknown-v1"),
            bytes: vec![],
        }]),
    )])
    .unwrap();
    let record = inspect(&snapshot(30, vec![p], vec![]), &effect(4, "read"), &unknown);
    assert_eq!(record.decision, Decision::Undetermined);
    assert!(
        matches!(&record.owners[0].decision,OwnerDecision::Undetermined(n) if n.codecs.contains(&id("unknown-v1")))
    );
}

#[test]
fn b03_join_link_leave_and_cut_are_one_constitutional_interpretation() {
    let (inv, i) = c::line(
        1,
        None,
        999,
        Act::Invite {
            power: c::root(),
            key: person(8),
            person: person(8),
        },
    );
    let (admit, a) = c::line(
        1,
        Some(inv.clone()),
        -999,
        Act::Admit {
            invite: Some(inv.clone()),
            key: person(8),
            person: person(8),
            consent: c::consent(8, &inv),
        },
    );
    let (bare, b) = c::line(
        1,
        Some(admit.clone()),
        0,
        Act::Admit {
            invite: None,
            key: person(9),
            person: person(2),
            consent: vec![],
        },
    );
    let (link, l) = c::line(
        2,
        None,
        0,
        Act::Link {
            key: person(9),
            consent: c::consent(9, &reference(person(2).bytes())),
        },
    );
    let (written, w) = c::line(
        9,
        None,
        0,
        Act::Record {
            app: c::app(),
            as_app: false,
            value: 42,
        },
    );
    let (cut, cut_line) = c::line(
        1,
        Some(bare.clone()),
        0,
        Act::Remove {
            power: c::root(),
            key: person(9),
            through: written.clone(),
        },
    );
    let (replay, r) = c::line(
        9,
        Some(written.clone()),
        -99999,
        Act::Record {
            app: c::app(),
            as_app: false,
            value: 99,
        },
    );
    let (leave, exit) = c::line(8, None, 0, Act::Leave);
    let entries = vec![i, a, b, l, w, cut_line, r, exit];
    for target in [admit, link, written, cut, leave] {
        let (d, r) = exercise_line(&Constitution::new(target), &entries);
        assert!(r.is_ok());
        assert_eq!(d.effects(), 1);
    }
    for target in [bare, replay] {
        let (d, r) = exercise_line(&Constitution::new(target), &entries);
        assert!(r.is_err());
        assert_eq!(d.effects(), 0);
    }
}

#[test]
fn b04_genuine_forks_freeze_without_restoring_a_keeper() {
    let (h, hand) = c::line(
        1,
        None,
        1,
        Act::HandOn {
            power: c::root(),
            to: person(2),
        },
    );
    let (fork, other) = c::line(
        1,
        None,
        -999,
        Act::Invite {
            power: c::root(),
            key: person(8),
            person: person(8),
        },
    );
    let (data, d) = c::line(
        6,
        None,
        0,
        Act::Record {
            app: c::app(),
            as_app: false,
            value: 1,
        },
    );
    let p = Constitution::new(h.clone());
    let mut forged = other.clone();
    let mut env: native::Envelope = serde_json::from_slice(&forged.bytes).unwrap();
    env.signature[0] ^= 1;
    forged.bytes = serde_json::to_vec(&env).unwrap();
    for control in [vec![hand.clone(), hand.clone()], vec![hand.clone(), forged]] {
        let (d, r) = exercise_line(&p, &control);
        assert!(r.is_ok());
        assert_eq!(d.effects(), 1);
    }
    let entries = vec![hand, other, d];
    let b = p.establish(&History::known(entries.clone()), 30).unwrap();
    let record = inspect(&b, &p.effect(&entries), &Evidence::default());
    assert_eq!(record.decision, Decision::Undetermined);
    assert!(
        matches!(&record.owners[0].decision,OwnerDecision::Undetermined(n) if n.conflicts==[h.clone(),fork.clone()].into())
    );
    let (d, r) = exercise_line(&p, &entries);
    assert!(r.is_err());
    assert_eq!(d.effects(), 0);
    let (d, r) = exercise_line(&Constitution::new(data), &entries);
    assert!(r.is_ok());
    assert_eq!(d.effects(), 1);
    let branches: BTreeSet<_> = [h, fork].into();
    let msg = c::resolution_message(&c::root(), person(2), &branches);
    use ed25519_dalek::Signer;
    let approvals = [2, 6]
        .map(|n| (person(n), key(n).sign(&msg).to_bytes().to_vec()))
        .into();
    let (resolution, line) = c::line(
        2,
        None,
        0,
        Act::Resolve {
            power: c::root(),
            to: person(2),
            branches,
            approvals,
        },
    );
    let mut resolved = entries;
    resolved.push(line);
    let mut p = Constitution::new(resolution.clone());
    assert!(exercise_line(&p, &resolved).1.is_err());
    p.resolution = Some([person(2), person(6)].into());
    assert!(exercise_line(&p, &resolved).1.is_ok());
    let (use_id, use_line) = c::line(
        2,
        Some(resolution.clone()),
        0,
        Act::Invite {
            power: resolution,
            key: person(8),
            person: person(8),
        },
    );
    resolved.push(use_line);
    p.target = use_id;
    assert!(exercise_line(&p, &resolved).1.is_ok());
}

#[test]
fn b05_independent_standing_owners_audiences_and_structural_coverage() {
    let mut lender = policy("lender");
    lender.scope.person = None;
    lender.scope.application = None;
    let consent = policy("person");
    let door = Door::new(
        snapshot(30, vec![lender.clone(), consent.clone()], vec![]),
        4,
        "read",
    );
    assert_eq!(
        door.run(effect(4, "read"), &Evidence::default())
            .unwrap()
            .account,
        "readers-account"
    );
    for source in [&lender.source, &consent.source] {
        door.install(snapshot(
            30,
            vec![lender.clone(), consent.clone()],
            vec![Fact {
                source: source.clone(),
                state: FactState::Refused(Reason::SourceRejected),
            }],
        ));
        assert!(door.run(effect(4, "read"), &Evidence::default()).is_err());
    }
    door.install(snapshot(30, vec![lender.clone(), consent.clone()], vec![]));
    for target in [
        "household/library",
        "house/../other",
        "house/%2e%2e/other",
        "house//library",
        "house\\library",
    ] {
        let mut e = request(4, "read");
        e.resource = Resource::new(target).unwrap();
        assert!(
            door.run(Effect::from_bytes(e, vec![]), &Evidence::default())
                .is_err()
        );
    }
    let membership = reference(b"membership:house:ana");
    lender.requires.insert(membership.clone());
    door.install(snapshot(
        30,
        vec![lender, consent],
        vec![Fact {
            source: membership.clone(),
            state: FactState::Missing,
        }],
    ));
    let record = inspect(
        &door.basis.lock().unwrap(),
        &effect(4, "read"),
        &Evidence::default(),
    );
    assert_eq!(record.decision, Decision::Undetermined);
    assert!(
        matches!(&record.owners[0].decision,OwnerDecision::Undetermined(n) if n.sources.contains(&membership))
    );
    assert_eq!(door.effects(), 1);
}

#[test]
fn b06_narrow_native_delegation_cannot_fall_back_or_leak_credentials() {
    let mut p = policy("person");
    p.scope.person = Some(person(2));
    p.approval = ApprovalRule::Delegated([person(2)].into());
    let mut lender = policy("lender");
    lender.obligations.insert(Obligation {
        kind: id("credential"),
        argument: id("readers-only"),
        phase: Phase::Before,
    });
    let proof = Evidence::new([(p.owner.clone(), native::chain(&p))]).unwrap();
    let door = Door::new(snapshot(30, vec![p.clone(), lender], vec![]), 4, "read");
    let out = door.run(effect(4, "read"), &proof).unwrap();
    assert_eq!(out.record.exercise.person, person(2));
    assert_eq!(out.record.exercise.actor, person(4));
    assert_eq!(out.account, "readers-account");
    assert_eq!(
        door.state.lock().unwrap().backend_auth,
        vec!["lender-held-readers-secret"]
    );
    assert!(
        !serde_json::to_string(&out.record)
            .unwrap()
            .contains("lender-held-readers-secret")
    );
    assert!(!out.body.windows(6).any(|b| b == b"secret"));
    let wrong = Door {
        actor: person(2),
        ..door.clone()
    };
    assert!(wrong.run(effect(2, "read"), &proof).is_err());
    assert_eq!(door.effects(), 1);
    let mut child = p.scope.clone();
    child.operations.insert(op("admin"));
    child.redelegations = 0;
    let wider = native::sign(
        Body::Delegation {
            owner: p.owner.clone(),
            holder: person(4),
            scope: child,
            sources: [p.source.clone()].into(),
        },
        2,
    );
    let invalid = Evidence::new([(p.owner.clone(), OwnerEvidence::Native(vec![wider]))]).unwrap();
    assert!(door.run(effect(4, "read"), &invalid).is_err());
    assert_eq!(door.effects(), 1);
    // The same root does not implicitly install the prototype grant format.
    use ed25519_dalek::Signer;
    let grant = Grant {
        owner: p.owner.clone(),
        issuer: person(2),
        holder: person(4),
        terms: Terms {
            person: person(2),
            application: Application::new("movie").unwrap(),
            resource: Resource::new("house/library").unwrap(),
            operations: [op("read")].into(),
            interval: Interval::new(0, 80).unwrap(),
            redelegations: 0,
        },
    };
    let signature = key(2).sign(&grant.signing_bytes()).to_bytes().to_vec();
    let legacy: OwnerProof =
        legacy_carrier::OwnerEvidence::Chain(vec![SignedGrant { grant, signature }]).into();
    let wrong_format = Evidence::new([(p.owner, legacy)]).unwrap();
    assert!(door.run(effect(4, "read"), &wrong_format).is_err());
}

#[test]
fn b07_corrections_follow_stable_people_not_labels_or_carriers() {
    let (link, l) = c::line(
        2,
        None,
        0,
        Act::Link {
            key: person(9),
            consent: c::consent(9, &reference(person(2).bytes())),
        },
    );
    let (entry, e) = c::line(
        2,
        Some(link),
        0,
        Act::Record {
            app: c::app(),
            as_app: false,
            value: 42,
        },
    );
    let (good, g) = c::line(
        9,
        None,
        0,
        Act::Correct {
            target: entry.clone(),
            app: c::app(),
            value: 40,
        },
    );
    let (namesake, n) = c::line(
        6,
        None,
        0,
        Act::Correct {
            target: entry.clone(),
            app: c::app(),
            value: 0,
        },
    );
    let (other_app, a) = c::line(
        9,
        Some(good.clone()),
        0,
        Act::Correct {
            target: entry.clone(),
            app: Application::new("other").unwrap(),
            value: 0,
        },
    );
    let entries = vec![l, e, g.clone(), n, a];
    let (d, r) = exercise_line(&Constitution::new(good.clone()), &entries);
    assert!(r.is_ok());
    assert_eq!(d.effects(), 1);
    for bad in [namesake, other_app] {
        let (d, r) = exercise_line(&Constitution::new(bad), &entries);
        assert!(r.is_err());
        assert_eq!(d.effects(), 0);
    }
    require_wait(&Constitution::new(good), &[entries[0].clone(), g], &entry);
}

#[test]
fn b08_historical_admission_binds_effect_sources_issuer_and_purpose() {
    let p = policy("person");
    let e = effect(4, "write");
    let receipt = native::sign(
        Body::Admission {
            effect: e.fingerprint(),
            at: 79,
            sources: [p.source.clone()].into(),
        },
        7,
    );
    let evidence = Evidence::new([(
        p.owner.clone(),
        OwnerEvidence::Admitted {
            proof: Box::new(OwnerEvidence::Absent),
            receipt: receipt.clone(),
        },
    )])
    .unwrap();
    let mut door = Door::new(snapshot(100, vec![p.clone()], vec![]), 4, "write");
    door.purpose = Purpose::HistoricalAdmission;
    let out = door.run(e, &evidence).unwrap();
    assert_eq!(out.record.purpose, Purpose::HistoricalAdmission);
    assert_eq!(door.effects(), 1);
    assert!(
        door.run(
            Effect::from_bytes(request(4, "write"), b"substitute".to_vec()),
            &evidence
        )
        .is_err()
    );
    let live = Door::new(snapshot(79, vec![p.clone()], vec![]), 4, "write");
    assert!(live.run(effect(4, "write"), &evidence).is_err());
    assert_eq!(live.effects(), 0);
    assert_eq!(door.effects(), 1);
    door.at(100);
    for (issuer, at) in [(6, 79), (7, 80), (7, 101)] {
        let receipt = native::sign(
            Body::Admission {
                effect: effect(4, "write").fingerprint(),
                at,
                sources: [p.source.clone()].into(),
            },
            issuer,
        );
        let bad = Evidence::new([(
            p.owner.clone(),
            OwnerEvidence::Admitted {
                proof: Box::new(OwnerEvidence::Absent),
                receipt,
            },
        )])
        .unwrap();
        assert!(door.run(effect(4, "write"), &bad).is_err());
    }
    let record = inspect_admission(
        &snapshot(100, vec![p], vec![]),
        &effect(4, "write"),
        &Evidence::default(),
    );
    assert_eq!(record.decision, Decision::Undetermined);
    assert!(matches!(&record.owners[0].decision,OwnerDecision::Undetermined(n) if n.admission));
}

#[test]
fn historical_native_witness_can_attest_a_window_without_inventing_an_instant() {
    let mut p = policy("person");
    p.scope.interval = Interval::new(20, 80).unwrap();
    let mut door = Door::new(snapshot(100, vec![p.clone()], vec![]), 4, "write");
    door.purpose = Purpose::HistoricalAdmission;
    for (from, until, allowed) in [
        (20, 80, true),
        (19, 80, false),
        (20, 81, false),
        (200, 300, false),
    ] {
        let receipt = native::sign(
            Body::AdmissionWindow {
                effect: effect(4, "write").fingerprint(),
                window: Interval::new(from, until).unwrap(),
                sources: [p.source.clone()].into(),
            },
            7,
        );
        let proof = Evidence::new([(
            p.owner.clone(),
            OwnerEvidence::Admitted {
                proof: Box::new(OwnerEvidence::Absent),
                receipt,
            },
        )])
        .unwrap();
        assert_eq!(door.run(effect(4, "write"), &proof).is_ok(), allowed);
    }
    assert_eq!(door.effects(), 1);
}

#[test]
fn an_empty_native_interval_supplies_no_live_or_historical_admission_instant() {
    let mut p = policy("person");
    p.scope.interval = Interval::empty(i64::MIN);
    let door = Door::new(snapshot(i64::MIN, vec![p.clone()], vec![]), 4, "write");
    assert!(!p.scope.interval.contains(i64::MIN));
    assert!(door.run(effect(4, "write"), &Evidence::default()).is_err());
    assert_eq!(door.effects(), 0);

    p.scope.interval = Interval::new(20, 80).unwrap();
    let mut history = Door::new(snapshot(100, vec![p.clone()], vec![]), 4, "write");
    history.purpose = Purpose::HistoricalAdmission;
    let window = Interval::empty(30);
    assert_eq!(
        serde_json::from_value::<Interval>(serde_json::json!([30, 30])).unwrap(),
        window
    );
    let receipt = native::sign(
        Body::AdmissionWindow {
            effect: effect(4, "write").fingerprint(),
            window,
            sources: [p.source.clone()].into(),
        },
        7,
    );
    let proof = Evidence::new([(
        p.owner,
        OwnerEvidence::Admitted {
            proof: Box::new(OwnerEvidence::Absent),
            receipt,
        },
    )])
    .unwrap();
    assert!(history.run(effect(4, "write"), &proof).is_err());
    assert_eq!(history.effects(), 0);
}

#[test]
fn b09_continuation_is_linear_and_rechecks_current_rights_not_old_records() {
    let p = policy("lender");
    let door = Door::new(snapshot(77, vec![p.clone()], vec![]), 4, "read");
    let initial = door.run(effect(4, "read"), &Evidence::default()).unwrap();
    assert_eq!(initial.lease.contract().scope(), &id("lend:library"));
    door.at(78);
    let next = initial.lease.execute_unit(door.clone()).unwrap();
    door.at(79);
    let next = next.lease.execute_unit(door.clone()).unwrap();
    door.at(80);
    assert!(next.lease.execute_unit(door.clone()).is_err());
    assert_eq!(door.effects(), 3);
    let door = Door::new(snapshot(30, vec![p.clone()], vec![]), 4, "read");
    let initial = door.run(effect(4, "read"), &Evidence::default()).unwrap();
    door.install(snapshot(
        30,
        vec![p.clone()],
        vec![Fact {
            source: p.source.clone(),
            state: FactState::Missing,
        }],
    ));
    door.at(31);
    assert!(initial.lease.execute_unit(door.clone()).is_err());
    assert_eq!(door.effects(), 1);
    let other = Door::new(snapshot(30, vec![p], vec![]), 4, "read");
    let lease = other
        .run(effect(4, "read"), &Evidence::default())
        .unwrap()
        .lease;
    other.at(33);
    assert!(matches!(
        lease.execute_unit(other.clone()),
        Err(LeaseError::CheckBoundary)
    ));
    assert_eq!(other.effects(), 1);
}

fn continuation_successors(lease: Lease<Door>, door: Door) -> Vec<Lease<Door>> {
    let output = lease.execute_unit(door).unwrap();
    vec![output.lease]
}
#[test]
fn one_continuation_transition_returns_one_owned_successor() {
    let door = Door::new(snapshot(30, vec![policy("lender")], vec![]), 4, "read");
    let lease = door
        .run(effect(4, "read"), &Evidence::default())
        .unwrap()
        .lease;
    door.at(31);
    let successors = continuation_successors(lease, door.clone());
    assert_eq!(door.effects(), 2);
    assert_eq!(successors.len(), 1);
}

#[test]
fn cached_authority_must_be_reinterpreted_at_its_declared_transition_boundary() {
    let p = policy("lender");
    let facts = vec![Fact {
        source: p.source.clone(),
        state: FactState::Established,
    }];
    let b = Basis::interpreted(
        id("cached-v1"),
        30,
        vec![p.clone()],
        facts.clone(),
        vec![],
        Recheck::Before(31),
    )
    .unwrap();
    assert!(matches!(
        b.observed_at(29),
        Err(ObservationError::ClockReversed)
    ));
    assert!(matches!(
        b.observed_at(31),
        Err(ObservationError::Reinterpret { at: 31 })
    ));
    let identity = b.fingerprint();
    let door = Door::new(b, 4, "read");
    with_resource(door.clone(), |live| {
        let proof = live
            .derive(effect(4, "read"), &Evidence::default())
            .unwrap();
        door.at(31);
        assert!(matches!(
            live.prepare(proof),
            Err(TransitionError::Resource(
                "authority needs reinterpretation"
            ))
        ));
    })
    .unwrap();
    assert_eq!(door.effects(), 0);
    let refreshed = Basis::interpreted(
        id("cached-v1"),
        31,
        vec![p],
        facts,
        vec![],
        Recheck::OnSourceChange,
    )
    .unwrap();
    assert_eq!(refreshed.fingerprint(), identity);
    door.install(refreshed);
    door.run(effect(4, "read"), &Evidence::default()).unwrap();
    assert_eq!(door.effects(), 1);
}

#[test]
fn b10_last_slot_is_atomic_and_failures_release_the_owned_reservation() {
    let p = policy("lender");
    let door = Door::new(snapshot(30, vec![p.clone()], vec![]), 4, "read");
    let barrier = Arc::new(Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let (d, b) = (door.clone(), barrier.clone());
            std::thread::spawn(move || {
                with_resource(d, |live| {
                    let p = live
                        .derive(effect(4, "read"), &Evidence::default())
                        .unwrap();
                    let ready = live.prepare(p);
                    b.wait();
                    if let Ok(r) = ready {
                        live.execute(r).unwrap();
                    }
                })
                .unwrap()
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    assert_eq!(door.effects(), 1);
    assert_eq!(door.state.lock().unwrap().held, 0);
    door.state.lock().unwrap().fail = true;
    assert!(door.run(effect(4, "read"), &Evidence::default()).is_err());
    assert_eq!(door.effects(), 1);
    assert_eq!(door.state.lock().unwrap().held, 0);
    door.state.lock().unwrap().fail = false;
    door.run(effect(4, "read"), &Evidence::default()).unwrap();
    assert_eq!(door.effects(), 2);
    let mut unknown = p;
    unknown.obligations.insert(Obligation {
        kind: id("unknown"),
        argument: id("must"),
        phase: Phase::During,
    });
    door.install(snapshot(30, vec![unknown], vec![]));
    assert!(door.run(effect(4, "read"), &Evidence::default()).is_err());
    assert_eq!(door.effects(), 2);
}

#[test]
fn b11_activation_executes_accepted_bytes_and_surfaces_first_version_conflict() {
    let (first, a) = c::line(
        2,
        None,
        999,
        Act::Place {
            app: c::app(),
            code: b"code A".to_vec(),
            parent: None,
        },
    );
    let (second, b) = c::line(
        6,
        None,
        -999,
        Act::Place {
            app: c::app(),
            code: b"code B".to_vec(),
            parent: None,
        },
    );
    let (run, r) = c::line(
        2,
        Some(first.clone()),
        0,
        Act::Run {
            candidate: first.clone(),
        },
    );
    let p = Constitution::new(run.clone());
    let (d, out) = exercise_line(&p, &[a.clone(), r.clone()]);
    assert_eq!(out.unwrap().body, b"code A");
    assert_eq!(d.effects(), 1);
    let current = p.effect(&[a.clone(), r.clone()]);
    assert!(
        d.run(
            Effect::from_bytes(current.exercise().clone(), b"substituted code".to_vec()),
            &Evidence::default()
        )
        .is_err()
    );
    assert_eq!(d.effects(), 1);
    let conflict = vec![a.clone(), b.clone(), r.clone()];
    let (d, out) = exercise_line(&p, &conflict);
    assert!(out.is_err());
    assert_eq!(d.effects(), 0);
    let (_, wrong) = c::line(
        6,
        Some(second),
        0,
        Act::Accept {
            candidate: first.clone(),
        },
    );
    let mut entries = conflict;
    entries.push(wrong);
    assert!(exercise_line(&p, &entries).1.is_err());
    let (_, yes) = c::line(2, Some(run), 0, Act::Accept { candidate: first });
    entries.push(yes);
    let (d, out) = exercise_line(&p, &entries);
    assert_eq!(out.unwrap().body, b"code A");
    assert_eq!(d.effects(), 1);
    let (_, update) = c::line(
        6,
        None,
        0,
        Act::Place {
            app: c::app(),
            code: b"unaccepted update".to_vec(),
            parent: Some(p.target.clone()),
        },
    );
    entries.push(update);
    assert_eq!(exercise_line(&p, &entries).1.unwrap().body, b"code A");
}

#[test]
fn visitor_scope_and_profile_specific_refusals_need_no_new_kernel_branch() {
    let mut p = policy("host-visit");
    p.actor = Some(person(8).into());
    p.scope.person = Some(person(8));
    p.scope.coverage = Coverage::Exact(Resource::new("house/host").unwrap());
    p.scope.operations = [op("read")].into();
    p.scope.interval = Interval::new(30, 32).unwrap();
    let door = Door::new(snapshot(30, vec![p.clone()], vec![]), 8, "read");
    let mut e = request(8, "read");
    e.person = person(8);
    e.resource = Resource::new("house/host").unwrap();
    door.run(Effect::from_bytes(e.clone(), vec![]), &Evidence::default())
        .unwrap();
    assert_eq!(door.effects(), 1);
    let wrong = Door {
        actor: person(9),
        ..door.clone()
    };
    let mut claimed = e.clone();
    claimed.actor = person(9);
    assert!(
        wrong
            .run(Effect::from_bytes(claimed, vec![]), &Evidence::default())
            .is_err()
    );
    for target in ["house/other-host", "house/library"] {
        let mut other = e.clone();
        other.resource = Resource::new(target).unwrap();
        assert!(
            door.run(Effect::from_bytes(other, vec![]), &Evidence::default())
                .is_err()
        );
    }
    door.at(32);
    assert!(
        door.run(Effect::from_bytes(e.clone(), vec![]), &Evidence::default())
            .is_err()
    );
    assert_eq!(door.effects(), 1);
    door.at(30);
    door.install(snapshot(
        30,
        vec![p.clone()],
        vec![Fact {
            source: p.source,
            state: FactState::Refused(Reason::Profile(id("visit-stopped"))),
        }],
    ));
    let record = inspect(
        &door.basis.lock().unwrap(),
        &Effect::<Read>::from_bytes(e.clone(), vec![]),
        &Evidence::default(),
    );
    assert_eq!(
        record.owners[0].decision,
        OwnerDecision::Refused(Reason::Profile(id("visit-stopped")))
    );
    assert!(
        door.run(Effect::from_bytes(e, vec![]), &Evidence::default())
            .is_err()
    );
    assert_eq!(door.effects(), 1);
}

#[test]
fn b12_explanations_replay_without_creating_more_effects() {
    let dependency = reference(b"private consent, not published bytes");
    let mut p = policy("person");
    p.requires.insert(dependency.clone());
    let basis = snapshot(
        30,
        vec![p],
        vec![Fact {
            source: dependency.clone(),
            state: FactState::Established,
        }],
    );
    let door = Door::new(basis.clone(), 4, "read");
    let out = door.run(effect(4, "read"), &Evidence::default()).unwrap();
    let serialized = serde_json::to_vec(&out.record).unwrap();
    let record: DecisionRecord = serde_json::from_slice(&serialized).unwrap();
    assert_eq!(record.replay(&basis, &Evidence::default()).unwrap(), record);
    assert_eq!(door.effects(), 1);
    assert!(
        !String::from_utf8(serialized)
            .unwrap()
            .contains("private consent")
    );
    let DerivationTrace::Exercise { authority, .. } = record.derivation.unwrap() else {
        panic!()
    };
    let DerivationTrace::Agreement { approvals, .. } = *authority else {
        panic!()
    };
    assert!(
        matches!(&approvals[0],DerivationTrace::Standing {dependencies,..} if dependencies.contains(&dependency))
    );
}

#[test]
fn b13_sticky_cross_operation_history_is_not_erased_by_stop_or_code_change() {
    let (read, g) = c::line(2, None, 0, Act::ReadOther { app: c::app() });
    let (write, w) = c::line(
        2,
        Some(read),
        0,
        Act::Record {
            app: c::app(),
            as_app: true,
            value: 1,
        },
    );
    let (stop, s) = c::line(2, Some(write.clone()), 0, Act::Stop { app: c::app() });
    let (changed, update) = c::line(
        2,
        Some(stop),
        0,
        Act::Place {
            app: c::app(),
            code: b"new code".to_vec(),
            parent: Some(write.clone()),
        },
    );
    let (later, l) = c::line(
        2,
        Some(changed),
        0,
        Act::Record {
            app: c::app(),
            as_app: true,
            value: 2,
        },
    );
    let (direct, d) = c::line(
        2,
        Some(later.clone()),
        0,
        Act::Record {
            app: c::app(),
            as_app: false,
            value: 3,
        },
    );
    let entries = vec![g, w, s, update, l, d];
    for target in [write, later] {
        let p = Constitution::new(target);
        for mut route in [entries.clone(), entries.iter().cloned().rev().collect()] {
            route.push(entries[0].clone());
            let (d, r) = exercise_line(&p, &route);
            assert!(r.is_err());
            assert_eq!(d.effects(), 0);
        }
    }
    let (d, r) = exercise_line(&Constitution::new(direct), &entries);
    assert!(r.is_ok());
    assert_eq!(d.effects(), 1);
    let (target, entry) = c::line(
        2,
        None,
        0,
        Act::Record {
            app: c::app(),
            as_app: true,
            value: 4,
        },
    );
    let p = Constitution::new(target);
    let source = reference(b"authoritative private grant history");
    let history = History {
        entries: vec![entry],
        private: c::PrivateHistory::Unavailable(source.clone()),
    };
    let b = p.establish(&history, 30).unwrap();
    let e = p.effect(&history.entries);
    let record = inspect(&b, &e, &Evidence::default());
    assert_eq!(record.decision, Decision::Undetermined);
    assert!(
        matches!(&record.owners[0].decision,OwnerDecision::Undetermined(n) if n.sources.contains(&source))
    );
    let door = Door::new(b, 2, "write");
    assert!(door.run(e, &Evidence::default()).is_err());
    assert_eq!(door.effects(), 0);
}

#[test]
fn scale_cached_interpretations_and_native_source_names_are_not_clock_identity() {
    let b = snapshot(30, vec![policy("lender")], vec![]);
    let original = b.fingerprint();
    for time in 31..10000 {
        assert_eq!(b.observed_at(time).unwrap().fingerprint(), original);
    }
    let a = reference(b"same bytes");
    let mut other = a.clone();
    other.algorithm = id("blake3");
    assert_ne!(a, other);
    other = a.clone();
    other.namespace = id("other-group");
    assert_ne!(a, other);
    let mut other_algorithm = a.clone();
    other_algorithm.algorithm = id("blake3");
    for needed in [other, other_algorithm] {
        let mut required = policy("lender");
        required.requires.insert(needed.clone());
        let cross_system = Door::new(
            snapshot(
                30,
                vec![required.clone()],
                vec![Fact {
                    source: a.clone(),
                    state: FactState::Established,
                }],
            ),
            4,
            "read",
        );
        assert!(
            cross_system
                .run(effect(4, "read"), &Evidence::default())
                .is_err()
        );
        assert_eq!(cross_system.effects(), 0);
        cross_system.install(snapshot(
            30,
            vec![required],
            vec![Fact {
                source: needed,
                state: FactState::Established,
            }],
        ));
        cross_system
            .run(effect(4, "read"), &Evidence::default())
            .unwrap();
        assert_eq!(cross_system.effects(), 1);
    }
    let mut p = policy("lender");
    p.scope.person = None;
    let mut second = policy("person");
    second.scope.person = Some(person(2));
    second.scope.application = Some(Application::new("movie").unwrap());
    assert!(
        Door::new(snapshot(30, vec![p, second], vec![]), 4, "read")
            .run(effect(4, "read"), &Evidence::default())
            .is_ok()
    );
}
