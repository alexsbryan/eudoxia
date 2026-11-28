//! What one request costs through these rules, as a carrier pays it: each
//! decision builds its rule table and a Basis and commits through the
//! sealed path. An instrument, not a check: `#[ignore]`d. Each line is the
//! median of five runs.
//!
//! Run: `cargo test --release --test cost -- --ignored --nocapture`.
use eudoxia_community::{app, lend};
use std::hint::black_box;
use std::time::Instant;

/// The Ed25519 base point: a key that reads as one.
const KEY: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];
const PERSON: &str = "5866666666666666666666666666666666666666666666666666666666666666";
const CALLS: u32 = 20_000;

fn timed<T>(name: &str, mut call: impl FnMut() -> T) {
    let mut runs: Vec<f64> = (0..5)
        .map(|_| {
            let began = Instant::now();
            for _ in 0..CALLS {
                black_box(call());
            }
            began.elapsed().as_secs_f64() * 1e6 / f64::from(CALLS)
        })
        .collect();
    runs.sort_by(f64::total_cmp);
    println!(
        "{{\"request\": {name:?}, \"median_us\": {:.1}, \"min_us\": {:.1}, \"max_us\": {:.1}}}",
        runs[2], runs[0], runs[4]
    );
}

#[test]
#[ignore = "an instrument: run with --ignored --nocapture"]
fn one_request_through_the_rules() {
    let (own, other) = ("own-shelf", "other-picks");
    let yes = Some(lend::Said::Yes);
    let reads = (true, false, false);
    timed("door: the person's choice", || {
        lend::choose(&KEY, true, own, Some(other), yes)
    });
    timed("door: the credential", || {
        lend::admit(&KEY, own, Some(other), lend::Asked::Read, reads)
    });
    timed("door: a request (choice and credential)", || {
        let chosen = lend::choose(&KEY, true, own, Some(other), yes);
        (
            chosen,
            lend::admit(&KEY, own, Some(other), lend::Asked::Read, reads),
        )
    });
    timed("a page's reach of a lend", || {
        lend::reach(
            &KEY,
            other,
            (true, false),
            Some((true, false)),
            (false, false),
        )
    });
    timed("a stream's recheck", || {
        lend::recheck(&KEY, own, true, Some(200), Some(100))
    });
    let vouched = lend::Vouch {
        listed: true,
        app: own,
        linked: false,
        until: 200,
        longest: 120,
        asked: lend::Asked::Read,
        removed: (false, false),
    };
    timed("door: a listed key's pass", || {
        lend::vouch(&KEY, own, 100, vouched)
    });
    let write = app::Write {
        node: &KEY,
        group: "the-group",
        person: PERSON,
        app: "money",
        class: app::Class::Record,
        act: Some(app::Act::Record),
        through: app::Through::Route {
            here: true,
            sized: true,
        },
    };
    timed("an app's write", || app::write(&write, || ()));
    let who = ("the-group", PERSON);
    timed("a reading app's class, refused", || {
        app::writes(&KEY, who, "money", app::Class::Connector)
    });
}

/// An id that counts every comparison made of it, so the interpreter's work
/// is measured without a clock.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Counted(u32);
thread_local! {
    static COMPARED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}
impl PartialOrd for Counted {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Counted {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        COMPARED.with(|c| c.set(c.get() + 1));
        self.0.cmp(&other.0)
    }
}
#[derive(Debug, Clone)]
struct Counting;
impl eudoxia_community::Vocabulary for Counting {
    type Id = Counted;
    type Person = &'static str;
    type Device = bool;
    fn computer(device: &bool) -> bool {
        *device
    }
}

/// The comparisons one fold makes of a host chain of `n` visits, each over
/// before the next.
fn fold_of(n: u32) -> u64 {
    use eudoxia_community::{Act, Community, Evidence, Roots, SourceMember, Statement};
    let member = |key: &'static str| (key.to_string(), SourceMember::root(key.into(), key, true));
    let roots =
        Roots::<Counting>::genesis([member("keeper"), member("host")].into(), "keeper".into())
            .unwrap();
    let held = (1..=n)
        .map(|i| {
            let at = i64::from(i) * 10;
            let act = Act::Fill {
                key: format!("guest-{i}"),
                until: at + 5,
                under: None,
                consent: true,
            };
            let line = Statement {
                author: "host".into(),
                stands_as: "host".into(),
                prev: (i > 1).then(|| Counted(i - 1)),
                at,
                readable: true,
                delegated: false,
                act,
            };
            (Counted(i), line)
        })
        .collect();
    let evidence = Evidence {
        held,
        forged: Default::default(),
    };
    COMPARED.with(|c| c.set(0));
    let facts = Community::new(&roots, &evidence).facts();
    assert!(facts.verdicts().values().all(Result::is_ok));
    COMPARED.with(std::cell::Cell::get)
}

/// Judging a host's visits is linear in its chain, up to the
/// lookups' logarithm: twice the chain costs well under three times the
/// work. Plant: the chain walked again for each visit (quadratic, about
/// four times).
#[test]
fn a_host_s_visits_cost_linear_work_in_its_chain() {
    let (small, large) = (fold_of(400), fold_of(800));
    let ratio = large as f64 / small as f64;
    assert!(ratio < 3.0, "{small} then {large}: {ratio:.2}");
}
