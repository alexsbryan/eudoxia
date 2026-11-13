//! Selected-constitution counterexamples against the actual pre-adoption fold.
//! These inputs do not retroactively change the meaning of retained legacy history.
use svrngs_core as n;
fn key(seed: u8) -> n::SigningKey {
    n::SigningKey::from_bytes(&[seed; 32])
}
fn actor(seed: u8) -> String {
    n::actor_of(&key(seed))
}
fn person(s: &str) -> n::Person {
    n::Person::parse(s).unwrap()
}
fn roster() -> n::Roster {
    n::Roster::new(
        [
            (person("ana"), vec![actor(1)]),
            (person("bo"), vec![actor(2)]),
            (person("cy"), vec![actor(3)]),
        ]
        .into(),
    )
}
const GROUP: &str = "native-constitution-counterexample";
fn sign(by: u8, ts: i64, seq: u64, prev: Option<n::OpId>, act: n::RailAct) -> n::Op<n::SignedOp> {
    n::sign_act(&key(by), GROUP, ts, seq, prev, act, None, None, None)
}
fn admit(ops: &[n::Op<n::SignedOp>]) -> n::Admission {
    n::admit(
        &n::ActSet::of(ops),
        &[],
        &roster(),
        GROUP,
        &n::Ed25519Verifier,
    )
}

#[test]
fn an_office_fork_cannot_choose_a_branch_to_cut_an_unrelated_member() {
    let hand = sign(1, 10, 0, None, n::RailAct::HandOn { key: actor(2) });
    let fork = sign(1, 11, 0, None, n::RailAct::HandOn { key: actor(3) });
    let cut = sign(
        2,
        12,
        0,
        None,
        n::RailAct::Remove {
            key: actor(3),
            through: vec![],
        },
    );
    let data = sign(
        3,
        13,
        0,
        None,
        n::RailAct::Record {
            payload: n::Payload::new(
                serde_json::json!({"kind":"ordinary","value":"independent data"}),
            )
            .unwrap(),
        },
    );
    let normal = admit(&[hand.clone(), cut.clone()]);
    assert!(
        !normal.membership().standing.contains(&actor(3)),
        "the uncontested holder's cut is the positive control"
    );
    let conflicted = admit(&[hand, fork, cut, data.clone()]);
    assert!(
        conflicted.membership().standing.contains(&actor(3)),
        "neither disputed successor can cut"
    );
    assert!(
        conflicted.membership().counts(&data.id),
        "independent membership/data is not frozen with the office"
    );
}

#[test]
fn a_bare_admit_cannot_supply_the_new_profiles_invitation_and_joining_consent() {
    let bare = sign(
        1,
        10,
        0,
        None,
        n::RailAct::Admit {
            person: person("dee"),
            key: actor(9),
            invite: None,
        },
    );
    let result = admit(&[bare]);
    assert!(!result.membership().standing.contains(&actor(9)));
}
