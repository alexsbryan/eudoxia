#![cfg(feature = "canon")]
use canon_core::{Act, ActKind, Effect as CanonEffect, Scope as CanonScope};
use canon_institution::Arrangements;
use eudoxia::canon::{self, Binding, CanonError, Identity};
use eudoxia::*;

fn root() -> Act {
    Act::new(
        ActKind::Grant {
            holder: "stable:ada".into(),
            scope: CanonScope::new("house").unwrap(),
            horizon: None,
            rationale: "root".into(),
        },
        10,
        "stable:founder",
    )
}
fn establish(acts: &[Act]) -> Result<Basis, CanonError> {
    let key = Principal::new(
        ed25519_dalek::SigningKey::from_bytes(&[1; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap();
    let roots = Arrangements {
        boundary: 10,
        effects: vec![CanonEffect {
            source: acts[0].id.clone(),
            effective_at: 10,
        }],
        pending: vec![],
    };
    let binding = Binding {
        owner: Owner::new("owner").unwrap(),
        scope: CanonScope::new("house.library").unwrap(),
        authority: Scope {
            person: Some(key),
            application: None,
            coverage: Coverage::Exact(Resource::new("library").unwrap()),
            operations: [Operation::new("read").unwrap()].into(),
            interval: Interval::new(0, 100).unwrap(),
            redelegations: 0,
        },
        carriers: Default::default(),
        obligations: Default::default(),
    };
    canon::establish(
        acts,
        &roots,
        30,
        Id::new("full-sources-v1").unwrap(),
        vec![binding],
        &[Identity {
            actor: "stable:ada".into(),
            key,
        }],
        vec![],
    )
}
#[test]
fn canonical_full_pins_and_exact_duplicates_survive_before_short_id_log_construction() {
    let act = root();
    let basis = establish(std::slice::from_ref(&act)).unwrap();
    assert_eq!(
        basis.fingerprint(),
        establish(&[act.clone(), act.clone()])
            .unwrap()
            .fingerprint()
    );
    let sources = &basis.policies()[0].requires;
    assert_eq!(sources.len(), 1);
    let source = sources.first().unwrap();
    assert_eq!(source.algorithm.as_str(), "canon-canonical-sha256-hex");
    assert_eq!(source.digest, canon_core::sign::digest(&act).into_bytes());
    assert_eq!(source.digest.len(), 64);
}
#[test]
fn rewritten_content_id_is_not_an_authenticated_source() {
    let mut act = root();
    act.actor = "another:actor".into();
    assert!(matches!(establish(&[act]), Err(CanonError::Source(_))));
}
#[test]
fn conflicting_signature_variants_cannot_be_lost_by_short_id_deduplication() {
    let mut a = root();
    a.v = canon_core::act::SIGNED_VERSION;
    let mut b = a.clone();
    b.sig = Some("different signature witness".into());
    assert_eq!(canon_core::sign::digest(&a), canon_core::sign::digest(&b));
    for acts in [vec![a.clone(), b.clone()], vec![b, a]] {
        assert!(matches!(establish(&acts), Err(CanonError::Ambiguous(_))));
    }
}
