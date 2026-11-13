#![allow(clippy::type_complexity)]
mod common;
use common::*;
use eudoxia::*;

#[test]
fn a_narrowed_delegation_reaches_a_distinct_execution_key() {
    let request = exercise();
    assert_ne!(request.actor, request.person);
    assert_ne!(request.actor, principal(3));
    let record = judge(&basis(30), &request, &evidence());
    assert_eq!(record.decision, Decision::Permitted);
    assert_eq!(record.owners.len(), 2);
    assert!(
        record.owners.iter().all(
            |o| matches!(&o.decision, OwnerDecision::Permitted { grants } if grants.len() == 2)
        )
    );
}

#[test]
fn both_required_owners_must_permit_and_omission_is_not_absence() {
    let missing =
        Evidence::new([(owner("person"), OwnerEvidence::Chain(chain("person", 1)))]).unwrap();
    let record = judge(&basis(30), &exercise(), &missing);
    assert_eq!(record.decision, Decision::Undetermined);
    assert!(record.owners.iter().any(|o| matches!(&o.decision, OwnerDecision::Undetermined(n) if n.owner == owner("lender") && n.issuers.contains(&principal(5)))));
    let absent = Evidence::new([
        (owner("person"), OwnerEvidence::Chain(chain("person", 1))),
        (owner("lender"), OwnerEvidence::Absent),
    ])
    .unwrap();
    assert_eq!(
        judge(&basis(30), &exercise(), &absent).decision,
        Decision::Refused
    );
    assert_eq!(
        judge(&basis(30), &exercise(), &evidence()).decision,
        Decision::Permitted
    );
}

#[test]
fn refusal_non_applicability_and_missing_evidence_remain_distinct() {
    let b = basis(30);
    let mut unrelated = exercise();
    unrelated.resource = Resource::new("household/library").unwrap();
    assert_eq!(
        judge(&b, &unrelated, &evidence()).decision,
        Decision::NotApplicable
    );
    let mut forbidden = exercise();
    forbidden.operation = operation("delete");
    assert_eq!(
        judge(&b, &forbidden, &evidence()).decision,
        Decision::Refused
    );
    assert_eq!(
        judge(&b, &exercise(), &Evidence::default()).decision,
        Decision::Undetermined
    );
}

#[test]
fn a_required_owners_non_applicable_grant_is_not_dropped() {
    let supplied = evidence_with_child(|t| t.resource = Resource::new("another-library").unwrap());
    let record = judge(&basis(30), &exercise(), &supplied);
    assert_eq!(record.decision, Decision::Refused);
    assert_eq!(record.owners.len(), 2);
}

#[test]
fn signed_widening_of_each_authority_dimension_is_refused() {
    let changes: Vec<Box<dyn Fn(&mut Terms)>> = vec![
        Box::new(|t| {
            t.operations.insert(operation("delete"));
        }),
        Box::new(|t| t.resource = Resource::new("other").unwrap()),
        Box::new(|t| t.person = principal(7)),
        Box::new(|t| t.application = Application::new("another-app").unwrap()),
        Box::new(|t| t.interval = Interval::new(9, 80).unwrap()),
        Box::new(|t| t.interval = Interval::new(20, 101).unwrap()),
        Box::new(|t| t.redelegations = 1),
    ];
    for (i, change) in changes.iter().enumerate() {
        let proof = evidence_with_child(change);
        assert_eq!(
            judge(&basis(30), &exercise(), &proof).decision,
            Decision::Refused,
            "dimension {i}"
        );
    }
}

#[test]
fn a_modified_signature_and_a_self_signed_substitute_are_refused() {
    for substitute in [false, true] {
        let mut values = chain("person", 1);
        if substitute {
            values[0].grant.issuer = principal(9);
            values[0] = sign(values[0].grant.clone(), 9);
        } else {
            values[1].signature[0] ^= 1;
        }
        let proof = Evidence::new([
            (owner("person"), OwnerEvidence::Chain(values)),
            (owner("lender"), OwnerEvidence::Chain(chain("lender", 5))),
        ])
        .unwrap();
        assert_eq!(
            judge(&basis(30), &exercise(), &proof).decision,
            Decision::Refused
        );
    }
}

#[test]
fn holding_another_execution_key_does_not_fall_back_to_the_person() {
    let mut request = exercise();
    request.actor = request.person;
    assert_eq!(
        judge(&basis(30), &request, &evidence()).decision,
        Decision::Refused
    );
}

#[test]
fn operational_start_is_inclusive_and_expiry_is_exclusive() {
    for (at, expected) in [
        (19, Decision::Refused),
        (20, Decision::Permitted),
        (79, Decision::Permitted),
        (80, Decision::Refused),
        (100, Decision::Refused),
    ] {
        assert_eq!(
            judge(&basis(at), &exercise(), &evidence()).decision,
            expected,
            "at {at}"
        );
    }
}

#[test]
fn unknown_and_unenforceable_mandatory_conditions_block_the_effect() {
    let mut owners = policies();
    owners[0].obligations.insert(obligation());
    let b = Basis::trusted(id("fixture-v1"), 30, owners).unwrap();
    for state in [ConditionState::Unknown, ConditionState::Unenforceable] {
        let mut enforcer = Recorder::new(state);
        assert_eq!(
            perform(&b, &exercise(), &evidence(), &mut enforcer),
            Err(ExecutionError::Condition {
                obligation: obligation(),
                state
            })
        );
        assert_eq!(
            enforcer.calls, 0,
            "no effect can precede condition enforcement"
        );
    }
    let mut enforcer = Recorder::new(ConditionState::Ready);
    assert_eq!(
        perform(&b, &exercise(), &evidence(), &mut enforcer).unwrap(),
        exercise()
    );
    assert_eq!((enforcer.conditions, enforcer.calls), (1, 1));
}

#[test]
fn no_execution_occurs_on_a_non_permit_judgment() {
    let mut enforcer = Recorder::new(ConditionState::Ready);
    assert_eq!(
        perform(&basis(80), &exercise(), &evidence(), &mut enforcer),
        Err(ExecutionError::NotPermitted(Decision::Refused))
    );
    assert_eq!(enforcer.calls, 0);
}

#[test]
fn successful_authorization_is_not_reported_as_successful_execution() {
    let mut enforcer = Recorder::new(ConditionState::Ready);
    enforcer.fail = true;
    assert_eq!(
        perform(&basis(30), &exercise(), &evidence(), &mut enforcer),
        Err(ExecutionError::Effect("backend unavailable"))
    );
    assert_eq!(enforcer.calls, 1);
}

#[test]
fn a_decision_record_replays_but_does_not_extend_live_authority() {
    let (b, proof, request) = (basis(30), evidence(), exercise());
    let record = judge(&b, &request, &proof);
    assert_eq!(record.decision, Decision::Permitted);
    let json = serde_json::to_string(&record).unwrap();
    let restored: DecisionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.replay(&b, &proof).unwrap(), record);
    assert_eq!(
        restored.replay(&basis(80), &proof),
        Err(ReplayError::ContextChanged)
    );
    let mut enforcer = Recorder::new(ConditionState::Ready);
    assert!(perform(&basis(80), &request, &proof, &mut enforcer).is_err());
    assert_eq!(enforcer.calls, 0);
}

#[test]
fn replay_rejects_changed_exercise_verdict_and_evidence() {
    let (b, proof) = (basis(30), evidence());
    let record = judge(&b, &exercise(), &proof);
    let mut forged = record.clone();
    forged.exercise.request = id("request-2");
    assert_eq!(forged.replay(&b, &proof), Err(ReplayError::JudgmentChanged));
    forged = record.clone();
    forged.decision = Decision::Refused;
    assert_eq!(forged.replay(&b, &proof), Err(ReplayError::JudgmentChanged));
    assert_eq!(
        record.replay(&b, &Evidence::default()),
        Err(ReplayError::ContextChanged)
    );
}

#[test]
fn owner_and_evidence_order_does_not_change_a_decision_record() {
    let mut owners = policies();
    owners.reverse();
    let b = Basis::trusted(id("fixture-v1"), 30, owners).unwrap();
    let proof = Evidence::new([
        (owner("lender"), OwnerEvidence::Chain(chain("lender", 5))),
        (owner("person"), OwnerEvidence::Chain(chain("person", 1))),
    ])
    .unwrap();
    assert_eq!(
        judge(&b, &exercise(), &proof),
        judge(&basis(30), &exercise(), &evidence())
    );
    assert_eq!(judge(&b, &exercise(), &proof).decision, Decision::Permitted);
}

#[test]
fn empty_and_duplicate_owners_cannot_create_vacuous_permission() {
    assert!(matches!(
        Basis::trusted(id("v1"), 30, vec![]),
        Err(Invalid::Owners)
    ));
    let policy = policies().remove(0);
    assert!(matches!(
        Basis::trusted(id("v1"), 30, vec![policy.clone(), policy]),
        Err(Invalid::Owners)
    ));
}
