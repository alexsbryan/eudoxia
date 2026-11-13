mod common;
use common::*;
use eudoxia::*;

fn evidence_state(name: &str, state: usize, issuer: u8) -> Option<(Owner, OwnerEvidence)> {
    match state {
        0 | 3 => Some((owner(name), OwnerEvidence::Chain(chain(name, issuer)))),
        1 => Some((owner(name), OwnerEvidence::Absent)),
        2 => None,
        _ => unreachable!(),
    }
}

#[test]
fn required_owner_truth_table_is_conjunctive_and_keeps_unknowns_visible() {
    for person in 0..4 {
        for lender in 0..4 {
            let mut owners = policies();
            if person == 3 {
                owners[0].terms.operations = [operation("write")].into();
            }
            if lender == 3 {
                owners[1].terms.operations = [operation("write")].into();
            }
            let b = Basis::trusted(id("truth-table-v1"), 30, owners).unwrap();
            let proof = Evidence::new(
                [
                    evidence_state("person", person, 1),
                    evidence_state("lender", lender, 5),
                ]
                .into_iter()
                .flatten(),
            )
            .unwrap();
            let expected = if person == 1 || lender == 1 || person == 3 || lender == 3 {
                Decision::Refused
            } else if person == 2 || lender == 2 {
                Decision::Undetermined
            } else {
                Decision::Permitted
            };
            let record = judge(&b, &exercise(), &proof);
            assert_eq!(
                record.decision, expected,
                "person {person}, lender {lender}"
            );
            assert_eq!(record.owners.len(), 2);
            assert_eq!(
                record
                    .owners
                    .iter()
                    .filter(|o| matches!(o.decision, OwnerDecision::Undetermined(_)))
                    .count(),
                usize::from(person == 2) + usize::from(lender == 2)
            );
        }
    }
}

#[test]
fn bounded_interval_law_matches_definition_not_arrival_order() {
    for start in [0, 9, 10, 19, 20, 30, 79] {
        for end in [20, 30, 31, 80, 100, 101, 200] {
            if start >= end {
                continue;
            }
            let proof =
                evidence_with_child(|terms| terms.interval = Interval::new(start, end).unwrap());
            let expected = if start >= 10 && end <= 100 && start <= 30 && 30 < end {
                Decision::Permitted
            } else {
                Decision::Refused
            };
            assert_eq!(
                judge(&basis(30), &exercise(), &proof).decision,
                expected,
                "[{start}, {end})"
            );
        }
    }
}

#[test]
fn duplicate_evidence_and_invalid_intervals_are_rejected_before_evaluation() {
    assert_eq!(Interval::new(10, 10), Err(Invalid::Interval));
    assert_eq!(Interval::new(11, 10), Err(Invalid::Interval));
    assert!(matches!(
        Evidence::new([
            (owner("person"), OwnerEvidence::Absent),
            (owner("person"), OwnerEvidence::Absent)
        ]),
        Err(Invalid::DuplicateEvidence)
    ));
}

#[test]
fn both_owners_mandatory_conditions_survive_composition() {
    let mut owners = policies();
    owners[0].obligations.insert(obligation());
    owners[1].obligations.insert(Obligation {
        kind: id("end-at-expiry"),
        argument: id("actor-link"),
        phase: Phase::During,
    });
    let b = Basis::trusted(id("condition-law-v1"), 30, owners).unwrap();
    let record = judge(&b, &exercise(), &evidence());
    assert_eq!(record.obligations.len(), 2);
    let mut enforcer = Recorder::new(ConditionState::Ready);
    perform(&b, &exercise(), &evidence(), &mut enforcer).unwrap();
    assert_eq!((enforcer.conditions, enforcer.calls), (2, 1));
}

#[test]
fn a_broken_delegation_link_is_not_replaced_by_another_holder() {
    let mut grants = chain("person", 1);
    grants[1].grant.issuer = principal(8);
    grants[1] = sign(grants[1].grant.clone(), 8);
    let proof = Evidence::new([
        (owner("person"), OwnerEvidence::Chain(grants)),
        (owner("lender"), OwnerEvidence::Chain(chain("lender", 5))),
    ])
    .unwrap();
    let record = judge(&basis(30), &exercise(), &proof);
    assert_eq!(record.decision, Decision::Refused);
    assert!(
        record
            .owners
            .iter()
            .any(|o| o.decision == OwnerDecision::Refused(Reason::BrokenChain))
    );
}

#[test]
fn a_required_non_applicable_policy_stays_in_the_report() {
    let mut owners = policies();
    owners[0].terms.operations = [operation("write")].into();
    let b = Basis::trusted(id("applicability-law-v1"), 30, owners).unwrap();
    let record = judge(&b, &exercise(), &evidence());
    assert_eq!(record.decision, Decision::Refused);
    assert!(
        record
            .owners
            .iter()
            .any(|o| o.owner == owner("person") && o.decision == OwnerDecision::NotApplicable)
    );
    assert_eq!(record.owners.len(), 2);
}
