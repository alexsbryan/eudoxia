//! Kernel laws of rules as data: they hold for every rule set. Each is decided
//! end to end, through the per-request Basis and the one derivation, not by
//! reading a ruling alone. Each law was watched failing on a planted evaluator.
mod profiles;
use eudoxia::*;
use profiles::*;
use std::collections::{BTreeMap, BTreeSet};

fn fact(name: &str) -> Term {
    Term::Fact(id(name))
}
fn rule(name: &str, verdict: Verdict, condition: Condition) -> Rule {
    Rule {
        id: id(name),
        verdict,
        operations: [op("use")].into(),
        condition,
    }
}
fn permit(name: &str, condition: Condition) -> Rule {
    rule(name, Verdict::Permit, condition)
}
fn forbid(name: &str, condition: Condition) -> Rule {
    rule(name, Verdict::Forbid, condition)
}
fn always() -> Condition {
    Condition::All(vec![])
}
fn not(c: Condition) -> Condition {
    Condition::Not(Box::new(c))
}
/// One request, its owners and its facts, decided through the derivation.
fn decided(
    rules: Vec<Rule>,
    owners: &[&str],
    facts: &[(&str, Value)],
) -> (DecisionRecord<Request>, Vec<Ruling>) {
    let request = Request::profile(
        id("ask"),
        Actor::Key { key: person(4) },
        Subject::Principal {
            principal: person(2),
        },
        AuthorityUse::Personal,
        op("use"),
        Resource::new("thing").unwrap(),
    )
    .unwrap();
    let asked = Asked {
        at: 30,
        operation: op("use"),
        resource: Resource::new("thing").unwrap(),
        facts: facts
            .iter()
            .map(|(name, value)| (id(name), value.clone()))
            .collect::<BTreeMap<_, _>>(),
    };
    let effect = Effect::<(), Request>::from_bytes(request, vec![]);
    let owners: BTreeSet<_> = owners.iter().map(|o| Owner::new(*o).unwrap()).collect();
    let (basis, rulings) = Rules::new(rules)
        .unwrap()
        .basis(id("laws-v1"), &effect, owners, &asked)
        .unwrap();
    (inspect(&basis, &effect, &Evidence::default()), rulings)
}
fn one(rules: Vec<Rule>, facts: &[(&str, Value)]) -> (Decision, Ruled) {
    let (record, rulings) = decided(rules, &["owner"], facts);
    (record.decision, rulings[0].ruled.clone())
}

#[test]
fn default_deny() {
    for rules in [
        vec![],
        vec![permit("never", not(always()))],
        vec![Rule {
            operations: [op("other")].into(),
            ..permit("elsewhere", always())
        }],
    ] {
        let (record, rulings) = decided(rules, &["owner"], &[]);
        assert_eq!(record.decision, Decision::Refused);
        assert_eq!(rulings[0].ruled, Ruled::Deny);
        assert_eq!(
            record.owners[0].decision,
            OwnerDecision::Refused(Reason::NoGrant)
        );
    }
    assert_eq!(
        one(vec![permit("yes", always())], &[]),
        (Decision::Permitted, Ruled::Permit(vec![id("yes")]))
    );
}

#[test]
fn forbid_beats_permit_and_the_record_names_the_first_deciding_rule() {
    let rules = vec![
        permit("open", always()),
        forbid("first", always()),
        permit("again", always()),
        forbid("second", Condition::Holds(fact("set"))),
    ];
    let (record, rulings) = decided(rules, &["owner"], &[("set", Value::Flag(true))]);
    assert_eq!(record.decision, Decision::Refused);
    assert_eq!(
        rulings[0].ruled,
        Ruled::Forbid(vec![id("first"), id("second")])
    );
    assert_eq!(
        record.owners[0].decision,
        OwnerDecision::Refused(Reason::Profile(id("first")))
    );
}

/// Every condition over one fact in each of its states: set, unset, missing.
fn family() -> Vec<Condition> {
    let leaves = vec![
        always(),
        not(always()),
        Condition::Holds(fact("a")),
        Condition::Holds(fact("absent")),
        Condition::Before(Term::Time, fact("until")),
        Condition::In(Term::Resource, fact("named")),
    ];
    let mut all = leaves.clone();
    for c in &leaves {
        all.push(not(c.clone()));
        for d in &leaves {
            all.push(Condition::Any(vec![c.clone(), d.clone()]));
        }
    }
    all
}

#[test]
fn narrowing_never_enables() {
    let worlds: [&[(&str, Value)]; 2] = [
        &[
            ("a", Value::Flag(true)),
            ("until", Value::Time(31)),
            ("named", Value::Texts(["thing".into()].into())),
        ],
        &[
            ("a", Value::Flag(false)),
            ("until", Value::Time(30)),
            ("named", Value::Texts(BTreeSet::new())),
        ],
    ];
    let permitted = |rules: Vec<Rule>, facts| one(rules, facts).0 == Decision::Permitted;
    for facts in worlds {
        for c in family() {
            let wide = permitted(vec![permit("p", c.clone())], facts);
            for d in family() {
                // A narrower permit, or a forbid added, never permits more.
                let narrow = vec![permit("p", Condition::All(vec![c.clone(), d.clone()]))];
                assert!(wide || !permitted(narrow, facts), "{c:?} narrowed by {d:?}");
                let guarded = vec![permit("p", c.clone()), forbid("f", d.clone())];
                assert!(wide || !permitted(guarded, facts), "{c:?} guarded by {d:?}");
            }
        }
    }
}

#[test]
fn every_owner_must_permit() {
    let rules = vec![permit("mine", Condition::Same(Term::Owner, fact("agrees")))];
    let agrees = [("agrees", Value::Text("alex".into()))];
    let (record, rulings) = decided(rules.clone(), &["alex", "bo"], &agrees);
    assert_eq!(record.decision, Decision::Refused);
    assert_eq!(record.owners.len(), 2);
    assert_eq!(rulings[0].ruled, Ruled::Permit(vec![id("mine")]));
    assert_eq!(rulings[1].ruled, Ruled::Deny);
    let (record, _) = decided(rules, &["alex"], &agrees);
    assert_eq!(record.decision, Decision::Permitted);
}

#[test]
fn a_missing_fact_never_decides() {
    // Missing, or of the wrong kind: neither a permit nor a forbid it reads decides.
    for absent in [vec![], vec![("a", Value::Text("yes".into()))]] {
        let (decision, ruled) = one(vec![permit("p", Condition::Holds(fact("a")))], &absent);
        assert_eq!(decision, Decision::Undetermined);
        assert_eq!(ruled, Ruled::Missing(vec![id("p")]));
        let rules = vec![
            permit("p", always()),
            forbid("f", not(Condition::Holds(fact("a")))),
        ];
        let (decision, ruled) = one(rules, &absent);
        assert_eq!(decision, Decision::Undetermined);
        assert_eq!(ruled, Ruled::Missing(vec![id("f")]));
    }
    // A known forbid still refuses beside a missing one; a known false
    // conjunct still decides an All whose other conjunct is missing.
    let rules = vec![
        permit("p", always()),
        forbid("unknown", Condition::Holds(fact("absent"))),
        forbid("known", always()),
    ];
    assert_eq!(
        one(rules, &[]),
        (Decision::Refused, Ruled::Forbid(vec![id("known")]))
    );
    let rules = vec![
        permit("p", always()),
        forbid(
            "f",
            Condition::All(vec![not(always()), Condition::Holds(fact("absent"))]),
        ),
    ];
    assert_eq!(one(rules, &[]).0, Decision::Permitted);
}

#[test]
fn a_request_basis_is_exactly_its_effect() {
    let request = Request::profile(
        id("ask"),
        Actor::Key { key: person(4) },
        Subject::Principal {
            principal: person(2),
        },
        AuthorityUse::Personal,
        op("use"),
        Resource::new("thing").unwrap(),
    )
    .unwrap();
    let effect = Effect::<(), Request>::from_bytes(request, vec![]);
    let rules = Rules::new(vec![permit("yes", always())]).unwrap();
    let elsewhere = Asked {
        at: 30,
        operation: op("use"),
        resource: Resource::new("other").unwrap(),
        facts: BTreeMap::new(),
    };
    let owners: BTreeSet<_> = [Owner::new("owner").unwrap()].into();
    assert_eq!(
        rules
            .basis(id("laws-v1"), &effect, owners, &elsewhere)
            .unwrap_err(),
        Invalid::Context
    );
    assert_eq!(
        Rules::new(vec![permit("twice", always()), permit("twice", always())]).unwrap_err(),
        Invalid::Policy
    );
}
