//! Whole replacement correspondence against the frozen pre-swap oracle. The
//! production module is exercised directly, not a separately compiled copy.
extern crate alloc;
use svrngs_core::pass::{Label, Pass};
pub use svrngs_core::*;
#[path = "profiles/r1_before.rs"]
mod before;
use svrngs_core::authority as candidate;

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn label(n: u8, name: &str) -> Label {
    Label::of(&key(n).verifying_key().to_bytes(), name)
}
fn sign(mut p: Pass, n: u8) -> Pass {
    p.sig = sign_message(&key(n), &p.message());
    p
}
fn pass(holder: &str, until: i64) -> Pass {
    Pass::approvable(
        &key(1),
        holder,
        (label(8, "money"), vec![label(8, "other")]),
        until,
        Some(actor_of(&key(7))),
    )
}
fn act(kind: &str) -> RailAct {
    RailAct::Record {
        payload: Payload::new(serde_json::json!({"kind": kind})).unwrap(),
    }
}
fn line(p: &Pass, ts: i64, act: RailAct) -> Op<SignedOp> {
    sign_act(
        &key(4),
        "group",
        ts,
        0,
        None,
        act,
        None,
        None,
        Some(p.clone()),
    )
}

#[test]
fn complete_direct_api_keeps_literal_names_form_time_and_refusal_order() {
    for raw in [
        actor_of(&key(4)),
        actor_of(&key(4)).to_uppercase(),
        String::new(),
        "not a signing key / %".into(),
        "x".repeat(1024),
    ] {
        for until in [i64::MIN, -1, 0, 100, i64::MAX] {
            let original = pass(&raw, until);
            let mut invalid = original.clone();
            invalid.sig.replace_range(..2, "ff");
            let mut attached = original.clone();
            attached.op = Some(line(&original, 0, act("money/item")).id);
            // The native public API uses ordinary Dalek verification. This
            // small-order compatibility control must not silently become the
            // library codec's strict-verification contract during the swap.
            let mut weak = original.clone();
            weak.person = format!("01{}", "00".repeat(31));
            weak.sig = format!("01{}", "00".repeat(63));
            assert!(before::signed(&weak));
            for p in [original, invalid, attached, weak] {
                for presented in [&raw, "other"] {
                    for at in [i64::MIN, -1, 0, 99, 100, i64::MAX] {
                        for target in [&p.app, &p.reads[0], &label(8, "outside")] {
                            assert_eq!(
                                candidate::check(&p, presented, target, at),
                                before::check(&p, presented, target, at),
                                "holder={presented:?}, at={at}, until={until}"
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn carrier_authentication_is_shared_without_inventing_write_or_standing_rights() {
    for holder in [actor_of(&key(4)), "literal / holder".into(), String::new()] {
        for until in [i64::MIN, 0, 100] {
            let p = pass(&holder, until);
            let mut invalid = p.clone();
            invalid.sig.replace_range(..2, "ff");
            for source in [p, invalid] {
                for actual in [&holder, "another"] {
                    let got = candidate::held(&source, actual);
                    assert_eq!(got, before::signed(&source) && source.holder == actual);
                }
            }
        }
    }
}

#[test]
fn phone_open_uses_the_same_original_scope_and_exact_approval_request() {
    let approver = actor_of(&key(7));
    let holder = actor_of(&key(4));
    for carried in [false, true] {
        let mut issued = pass(&holder, 1000);
        issued.app = if carried {
            Label::carried("money", "group")
        } else {
            label(8, "money-group")
        };
        issued = sign(issued, 1);
        let reach = issued.clone();
        let mut wrong = issued.clone();
        wrong.reads.clear();
        wrong = sign(wrong, 1);
        let mut foreign = reach.clone();
        foreign.app = label(9, "elsewhere");
        foreign = sign(foreign, 1);
        for ts in [i64::MIN, 0, 299, 300, 301, 999, 1000, i64::MAX] {
            for action in [act("money/item"), act("events/item"), RailAct::Seal] {
                let draft = line(&issued, ts, action);
                let mut unsigned = draft.clone();
                unsigned.kind.sig.clear();
                let mut missing = draft.clone();
                missing.kind.grant = None;
                for line in [&draft, &unsigned, &missing] {
                    for presented in [&approver, "another"] {
                        for opener in [&reach, &foreign] {
                            for grant in [&issued, &wrong] {
                                for now in [0, 300, 999, 1000] {
                                    let got = candidate::approve_in_open(
                                        presented, "group", opener, grant, line, now,
                                    )
                                    .map_err(|e| e.to_string());
                                    let expected = before::approve_in_open(
                                        presented, "group", opener, grant, line, now,
                                    )
                                    .map_err(str::to_string);
                                    assert_eq!(got, expected);
                                    if let Ok(pass) = got {
                                        assert_eq!(
                                            pass.approval_message(),
                                            expected.unwrap().approval_message()
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn approved_original_content_is_not_replaced_by_a_record_or_a_different_body() {
    let mut broad = pass(&actor_of(&key(4)), 100);
    broad.app = Label::carried("money", "group");
    broad = sign(broad, 1);
    let draft = line(&broad, 99, act("money/item"));
    let mut exact = before::approving(&broad, &draft, "group", 99).unwrap();
    exact.approval = Some(sign_message(&key(7), &exact.approval_message()));
    assert!(before::signed(&exact));
    for (ts, action) in [
        (99, act("money/item")),
        (99, act("money/changed")),
        (100, act("money/item")),
    ] {
        let line = line(&exact, ts, action);
        let held = candidate::Lines::new();
        let mut selected = candidate::Lines::new();
        let got = candidate::select(
            &candidate::read(&exact),
            &line.id,
            &line,
            "group",
            &held,
            &mut selected,
        );
        let expected = before::entry(&exact, &line, "group", &held);
        assert_eq!(got, expected);
        assert_eq!(selected.len(), usize::from(expected.is_ok()));
    }
}

#[test]
fn complete_link_api_preserves_child_first_errors_whole_scope_and_original_person() {
    let p = pass(&actor_of(&key(4)), 100);
    let endpoint = actor_of(&key(5));
    let base = sign(p.link(&endpoint), 4);
    let mut other_app = base.clone();
    other_app.app = p.reads[0].clone();
    other_app = sign(other_app, 4);
    let mut wider_reads = base.clone();
    wider_reads.reads.push(p.app.clone());
    wider_reads = sign(wider_reads, 4);
    let mut later = base.clone();
    later.until = 101;
    later = sign(later, 4);
    let mut alias = base.clone();
    alias.person = alias.person.to_uppercase();
    alias = sign(alias, 4);
    let mut invalid = base.clone();
    invalid.sig.replace_range(..2, "ff");
    for link in [base, other_app, wider_reads, later, alias, invalid] {
        for raw in [&endpoint, "other"] {
            for at in [i64::MIN, 0, 99, 100, i64::MAX] {
                for target in [&p.app, &p.reads[0], &label(8, "outside")] {
                    let mut committed = 0;
                    let got =
                        candidate::resolve(&p, Some(&link), raw, target, at, || committed += 1);
                    let expected = before::carries(&p, &link, raw, target, at);
                    assert_eq!(got, expected);
                    assert_eq!(committed, usize::from(expected.is_ok()));
                }
            }
        }
    }
}

#[test]
fn original_record_approval_and_correction_sources_commit_or_refuse_identically() {
    for app in [Label::carried("money", "group"), label(8, "money-group")] {
        for until in [i64::MIN, 0, 100, i64::MAX] {
            let mut broad = pass(&actor_of(&key(4)), until);
            broad.app = app.clone();
            broad = sign(broad, 1);
            let target = line(&broad, -1, act("money/item"));
            let missing = line(&broad, -1, act("money/missing"));
            let held = [(target.id.clone(), &target)].into_iter().collect();
            for at in [i64::MIN, -1, 0, 99, 100, i64::MAX] {
                for action in [
                    act("money/item"),
                    act("events/item"),
                    RailAct::Seal,
                    RailAct::Correct {
                        corrects: target.id.clone(),
                        replacement: None,
                    },
                    RailAct::Correct {
                        corrects: missing.id.clone(),
                        replacement: None,
                    },
                    RailAct::Correct {
                        corrects: target.id.clone(),
                        replacement: Some(
                            Payload::new(serde_json::json!({"kind":"events/item"})).unwrap(),
                        ),
                    },
                ] {
                    let draft = line(&broad, at, action);
                    let mut forged = broad.clone();
                    forged.sig.replace_range(..2, "ff");
                    for p in [&broad, &forged] {
                        let mut selected = candidate::Lines::new();
                        let read = candidate::read(p);
                        let got = candidate::select(
                            &read,
                            &draft.id,
                            &draft,
                            "group",
                            &held,
                            &mut selected,
                        );
                        let expected = before::entry(p, &draft, "group", &held);
                        assert_eq!(got, expected);
                        assert_eq!(selected.len(), usize::from(expected.is_ok()));
                        if let Some(original) = selected.get(&draft.id) {
                            assert!(std::ptr::eq(*original, &draft));
                        }
                        for now in [0, 99, 100] {
                            let got = candidate::approving(p, &draft, "group", now);
                            assert_eq!(got, before::approving(p, &draft, "group", now));
                        }
                    }
                }
            }
        }
    }
}
