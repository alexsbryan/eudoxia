mod profiles;
use eudoxia::*;
use profiles::*;

fn run(
    policy: Policy,
    state: FactState,
    bytes: &mut Vec<Vec<u8>>,
) -> Result<DecisionRecord, AtomicError> {
    let basis = Basis::single(id("fixed-native-profile"), 30, policy, state).unwrap();
    let effect = Effect::<()>::from_bytes(request(4, "read"), vec![0, 255, b'{', b'0']);
    atomic(
        basis,
        KeyIngress {
            actor: person(4),
            operation: op("read"),
        },
        Purpose::Live,
        bytes,
        effect,
        &Evidence::default(),
        |effect, store, record| {
            store.push(effect.arguments().to_vec());
            record
        },
    )
}

#[test]
fn fixed_owner_commits_exact_bytes_and_cannot_substitute_missing_source_truth() {
    let mut bytes = Vec::new();
    let p = policy("issuer");
    let record = run(p.clone(), FactState::Established, &mut bytes).unwrap();
    assert_eq!(bytes, [vec![0, 255, b'{', b'0']]);
    assert_eq!(record.decision, Decision::Permitted);
    for state in [
        FactState::Missing,
        FactState::Refused(Reason::SourceRejected),
        FactState::Frozen([p.source.clone()].into()),
    ] {
        assert!(run(p.clone(), state, &mut bytes).is_err());
        assert_eq!(bytes.len(), 1);
    }
}

#[test]
fn fixed_owner_rejects_every_unimplemented_condition_before_commit() {
    let mut bytes = Vec::new();
    for phase in [Phase::Before, Phase::During, Phase::After] {
        let mut p = policy("issuer");
        p.obligations.insert(Obligation {
            kind: id("unknown"),
            argument: id("required"),
            phase,
        });
        assert!(matches!(
            run(p, FactState::Established, &mut bytes),
            Err(AtomicError::Transition(TransitionError::Resource(
                Invalid::Policy
            )))
        ));
        assert!(bytes.is_empty());
    }
}
