#![cfg(feature = "canon")]
mod common;
use canon_core::{Act, ActKind, Effect, Log, Scope};
use canon_institution::Arrangements;
use common::canonical::{self as canon, Binding, Identity};
use common::*;
use eudoxia::ObservationError;

#[test]
fn canon_observation_ticks_and_unrelated_records_do_not_edit_authority() {
    let a = Act::new(
        ActKind::Grant {
            holder: "stable:ada".into(),
            scope: Scope::new("house").unwrap(),
            horizon: None,
            rationale: "root".into(),
        },
        10,
        "stable:founder",
    );
    let roots = Arrangements {
        boundary: 10,
        effects: vec![Effect {
            source: a.id.clone(),
            effective_at: 10,
        }],
        pending: vec![],
    };
    let bindings = || {
        policies()
            .into_iter()
            .map(|p| Binding {
                owner: p.owner,
                scope: Scope::new("house.library").unwrap(),
                terms: p.terms,
                obligations: p.obligations,
            })
            .collect()
    };
    let ids = vec![Identity {
        actor: "stable:ada".into(),
        key: principal(1),
    }];
    let before = canon::establish(
        &Log::from_acts(vec![a.clone()]),
        &roots,
        30,
        id("canon-stable-v1"),
        bindings(),
        &ids,
    )
    .unwrap();
    let tick = canon::establish(
        &Log::from_acts(vec![a.clone()]),
        &roots,
        31,
        id("canon-stable-v1"),
        bindings(),
        &ids,
    )
    .unwrap();
    assert_eq!(before.fingerprint(), tick.fingerprint());
    let question = Act::new(
        ActKind::Question {
            text: "An unrelated question".into(),
            proposal: None,
        },
        20,
        "stable:ada",
    );
    let appended = canon::establish(
        &Log::from_acts(vec![a, question]),
        &roots,
        31,
        id("canon-stable-v1"),
        bindings(),
        &ids,
    )
    .unwrap();
    assert_eq!(before.fingerprint(), appended.fingerprint());
}

#[test]
fn canon_cache_cannot_cross_a_known_inclusive_horizon_without_reinterpretation() {
    let a = Act::new(
        ActKind::Grant {
            holder: "stable:ada".into(),
            scope: Scope::new("house").unwrap(),
            horizon: Some(31),
            rationale: "root".into(),
        },
        10,
        "stable:founder",
    );
    let roots = Arrangements {
        boundary: 10,
        effects: vec![Effect {
            source: a.id.clone(),
            effective_at: 10,
        }],
        pending: vec![],
    };
    let log = Log::from_acts(vec![a]);
    let bindings = || {
        policies()
            .into_iter()
            .map(|p| Binding {
                owner: p.owner,
                scope: Scope::new("house.library").unwrap(),
                terms: p.terms,
                obligations: p.obligations,
            })
            .collect()
    };
    let ids = vec![Identity {
        actor: "stable:ada".into(),
        key: principal(1),
    }];
    let b = canon::establish(&log, &roots, 30, id("canon-deadline-v1"), bindings(), &ids).unwrap();
    assert!(b.observed_at(31).is_ok());
    assert!(matches!(
        b.observed_at(32),
        Err(ObservationError::Reinterpret { at: 32 })
    ));
    let after =
        canon::establish(&log, &roots, 32, id("canon-deadline-v1"), bindings(), &ids).unwrap();
    assert_ne!(b.fingerprint(), after.fingerprint());
    assert!(after.owners().iter().all(|o| o.issuers.is_empty()));
}
