//! Guests: each visit a fill on its host computer's own chain, judged by the
//! chain behind it. Each law names the plant it went red on.
use eudoxia_community::{
    Act, Community, Evidence, GUESTS_MOST, Roots, SourceFailure, SourceFault, SourceMember,
    Statement, VISIT_LONGEST, Vocabulary,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
struct V;
impl Vocabulary for V {
    type Id = u32;
    type Person = &'static str;
    /// Whether the device is a computer.
    type Device = bool;
    fn computer(device: &bool) -> bool {
        *device
    }
}

const HOUR: i64 = 3_600;
const KEEPER: &str = "keeper";
const HOST: &str = "host";
const OTHER: &str = "other";
const PHONE: &str = "phone";

/// A house: its keeper's computer, two more computers, and a phone.
fn roots() -> Roots<V> {
    let members = [(KEEPER, true), (HOST, true), (OTHER, true), (PHONE, false)]
        .into_iter()
        .map(|(key, computer)| {
            let member = SourceMember::root(key.into(), key, computer);
            (key.to_string(), member)
        })
        .collect();
    Roots::genesis(members, KEEPER.into()).unwrap()
}

/// Lines by id, each appended to its author's chain.
#[derive(Clone, Default)]
struct History {
    held: BTreeMap<u32, Statement<V>>,
    tips: BTreeMap<String, u32>,
}
impl History {
    fn add(&mut self, author: &str, at: i64, act: Act<V>) -> u32 {
        let id = self.held.len() as u32 + 1;
        let prev = self.tips.insert(author.into(), id);
        self.held.insert(id, statement(author, prev, at, act));
        id
    }
    /// A visit by `author` at `at` of `key`, `hours` long, under `under`.
    fn fill(&mut self, author: &str, at: i64, key: &str, hours: i64, under: Option<u32>) -> u32 {
        let (key, until) = (key.into(), at + hours * HOUR);
        self.add(
            author,
            at,
            Act::Fill {
                key,
                until,
                under,
                consent: true,
            },
        )
    }
    fn stop(&mut self, author: &str, at: i64, fill: u32) -> u32 {
        let (corrects, replacement) = (fill, None);
        self.add(
            author,
            at,
            Act::Correct {
                corrects,
                replacement,
            },
        )
    }
    fn verdicts(&self) -> BTreeMap<u32, Result<(), SourceFailure<u32>>> {
        let roots = roots();
        let evidence = Evidence {
            held: self.held.clone(),
            forged: BTreeSet::new(),
        };
        Community::new(&roots, &evidence).facts().verdicts().clone()
    }
    fn counts(&self, id: u32) -> bool {
        self.verdicts()[&id].is_ok()
    }
    fn why(&self, id: u32) -> Option<SourceFault> {
        match &self.verdicts()[&id] {
            Err(SourceFailure::Refused { why }) => Some(*why),
            _ => None,
        }
    }
}

fn statement(author: &str, prev: Option<u32>, at: i64, act: Act<V>) -> Statement<V> {
    Statement {
        author: author.into(),
        stands_as: author.into(),
        prev,
        at,
        readable: true,
        delegated: false,
        act,
    }
}

/// Plant: freeness judged over the visible fills (the chain's lines
/// walked by time, holes not marked): the third fill counted.
#[test]
fn a_slot_is_never_free_for_lack_of_a_visible_fill() {
    let mut h = History::default();
    h.fill(HOST, 0, "sam", 48, None);
    let second = h.fill(HOST, 10, "tia", 48, None);
    let third = h.fill(HOST, 20, "uma", 48, None);
    assert_eq!(h.why(third), Some(SourceFault::Full));
    h.held.remove(&second);
    assert!(
        matches!(h.verdicts()[&third], Err(SourceFailure::Missing { .. })),
        "a hole before the fill: {:?}",
        h.verdicts()[&third]
    );
}

/// Plant: at a fork, the earlier branch by its signed time walked on.
#[test]
fn a_fork_of_the_host_s_chain_freezes_its_fills() {
    let mut h = History::default();
    let first = h.fill(HOST, 0, "sam", 1, None);
    let one = h.fill(HOST, 10, "tia", 48, None);
    h.tips.insert(HOST.into(), first);
    let two = h.fill(HOST, 20, "uma", 48, None);
    assert!(h.counts(first), "before the fork");
    for fill in [one, two] {
        assert!(
            matches!(h.verdicts()[&fill], Err(SourceFailure::Frozen { .. })),
            "{fill}: {:?}",
            h.verdicts()[&fill]
        );
    }
}

/// Plant: the fills on judged against every Stop the chain holds,
/// later ones included: the refused third counted after the first's Stop.
#[test]
fn a_refusal_never_becomes_a_grant() {
    let mut h = History::default();
    let first = h.fill(HOST, 0, "sam", 48, None);
    h.fill(HOST, 10, "tia", 48, None);
    let third = h.fill(HOST, 20, "uma", 48, None);
    h.stop(HOST, 30, first);
    let fourth = h.fill(HOST, 40, "val", 48, None);
    assert_eq!(
        h.why(third),
        Some(SourceFault::Full),
        "refused at its place"
    );
    assert!(h.counts(fourth), "the Stop freed a slot for the next fill");
}

/// Plant: any standing key fills (the computer check gone).
#[test]
fn only_the_host_computer_consumes_its_own_slots() {
    let mut h = History::default();
    let phone = h.fill(PHONE, 0, "sam", 48, None);
    let stranger = h.fill("stranger", 0, "tia", 48, None);
    let mut delegated = statement(OTHER, None, 0, Act::Data { part: "x".into() });
    delegated.delegated = true;
    delegated.act = Act::Fill {
        key: "uma".into(),
        until: 48 * HOUR,
        under: None,
        consent: true,
    };
    h.held.insert(99, delegated);
    assert_eq!(h.why(phone), Some(SourceFault::Computer));
    assert_eq!(h.why(stranger), Some(SourceFault::Binding));
    assert_eq!(h.why(99), Some(SourceFault::Use));
}

/// Plant: fills walked in signed-time order.
/// Times here disagree with the chain, and ids are dealt in two orders.
#[test]
fn fold_equals_refold_in_any_delivery_order() {
    let build = |order: [u32; 4]| {
        let mut h = History::default();
        let lines = [
            (
                100,
                Act::Fill {
                    key: "sam".into(),
                    until: 1_000,
                    under: None,
                    consent: true,
                },
            ),
            (
                110,
                Act::Fill {
                    key: "tia".into(),
                    until: 1_000,
                    under: None,
                    consent: true,
                },
            ),
            (
                120,
                Act::Correct {
                    corrects: order[0],
                    replacement: None,
                },
            ),
            (
                90,
                Act::Fill {
                    key: "uma".into(),
                    until: 1_000,
                    under: None,
                    consent: true,
                },
            ),
        ];
        let mut prev = None;
        for (n, (at, act)) in lines.into_iter().enumerate() {
            h.held.insert(order[n], statement(HOST, prev, at, act));
            prev = Some(order[n]);
        }
        let v = h.verdicts();
        order.map(|id| v[&id].is_ok())
    };
    let one = build([1, 2, 3, 4]);
    let other = build([40, 30, 20, 10]);
    assert_eq!(one, other, "the same facts in any order");
    assert_eq!(one, [true, true, true, true], "by the chain, not the clock");
}

/// Plants, each in turn: the length unread, a member's key let
/// through, a key used earlier on the chain let through, the slot count gone.
#[test]
fn the_bounds_hold() {
    let mut h = History::default();
    let long = h.fill(HOST, 0, "sam", VISIT_LONGEST / HOUR, None);
    let longer = h.fill(OTHER, 0, "tia", 49, None);
    assert!(h.counts(long), "48 hours is a visit");
    assert_eq!(h.why(longer), Some(SourceFault::Guest), "49 is not");

    let mut h = History::default();
    let member = h.fill(HOST, 0, OTHER, 1, None);
    let first = h.fill(HOST, 10, "sam", 1, None);
    let again = h.fill(HOST, 2 * HOUR, "sam", 1, None);
    assert_eq!(h.why(member), Some(SourceFault::Guest), "a member's key");
    assert!(h.counts(first));
    assert_eq!(h.why(again), Some(SourceFault::Guest), "a key used before");

    let mut h = History::default();
    let mine = h.fill(HOST, 0, "sam", 48, None);
    let theirs = h.fill(OTHER, 0, "sam", 48, None);
    assert_eq!(h.why(mine), Some(SourceFault::Guest), "two hosts, one key");
    assert_eq!(h.why(theirs), Some(SourceFault::Guest), "neither picked");

    let mut h = History::default();
    h.fill(HOST, 0, "sam", 48, None);
    h.fill(HOST, 10, "tia", 48, None);
    let third = h.fill(HOST, 20, "uma", 48, None);
    assert_eq!(h.why(third), Some(SourceFault::Full), "a third at once");

    let mut h = History::default();
    let most = h.add(
        KEEPER,
        0,
        Act::Slots {
            per_computer: GUESTS_MOST,
        },
    );
    let past = h.add(
        KEEPER,
        1,
        Act::Slots {
            per_computer: GUESTS_MOST + 1,
        },
    );
    assert!(h.counts(most));
    assert!(!h.counts(past), "a setting past the most");
}

/// Plant: a fill that binds its key.
#[test]
fn no_guest_key_reaches_the_record() {
    let mut h = History::default();
    let fill = h.fill(HOST, 0, "sam", 48, None);
    let roots = roots();
    let evidence = Evidence {
        held: h.held.clone(),
        forged: BTreeSet::new(),
    };
    let facts = Community::new(&roots, &evidence).facts();
    assert!(facts.verdicts()[&fill].is_ok());
    assert!(!facts.bound().contains_key("sam"), "bound");
    assert!(!facts.standing().contains("sam"), "standing");
}

/// Plant: any standing key's setting counts.
#[test]
fn a_non_keeper_s_setting_does_not_count() {
    let mut h = History::default();
    let own = h.add(HOST, 0, Act::Slots { per_computer: 8 });
    for (n, guest) in ["sam", "tia", "uma"].into_iter().enumerate() {
        h.fill(HOST, 10 + n as i64, guest, 48, Some(own));
    }
    assert!(!h.counts(own), "the setting");
    let third = *h.held.keys().last().unwrap();
    assert!(!h.counts(third), "a fill under it");
}

/// Plant: each fill judged under the newest setting held.
#[test]
fn lowering_the_setting_voids_no_admitted_guest() {
    let mut h = History::default();
    let three = h.add(KEEPER, 0, Act::Slots { per_computer: 3 });
    let fills: Vec<u32> = ["sam", "tia", "uma"]
        .into_iter()
        .enumerate()
        .map(|(n, guest)| h.fill(HOST, 10 + n as i64, guest, 48, Some(three)))
        .collect();
    let one = h.add(KEEPER, 20, Act::Slots { per_computer: 1 });
    let next = h.fill(HOST, 30, "val", 48, Some(one));
    for fill in fills {
        assert!(h.counts(fill), "{fill} stays a guest");
    }
    assert_eq!(h.why(next), Some(SourceFault::Full), "the new number holds");
    let roots = roots();
    let evidence = Evidence {
        held: h.held.clone(),
        forged: BTreeSet::new(),
    };
    let facts = Community::new(&roots, &evidence).facts();
    assert_eq!(facts.setting(), Some((&one, 1)), "the setting that stands");
}

/// Plant: a default of none.
#[test]
fn the_default_is_two() {
    let mut h = History::default();
    let first = h.fill(HOST, 0, "sam", 48, None);
    let second = h.fill(HOST, 10, "tia", 48, None);
    let third = h.fill(HOST, 20, "uma", 48, None);
    assert!(h.counts(first) && h.counts(second));
    assert_eq!(h.why(third), Some(SourceFault::Full));
}

/// Plant: the consent unread, so a fill counts without its guest's consent
/// to its own host.
#[test]
fn another_member_s_copy_of_a_guest_s_key_takes_nothing() {
    let mut h = History::default();
    let tia = h.fill(HOST, 0, "tia", 48, None);
    let key = "tia".to_string();
    let copy = Act::Fill {
        key,
        until: 48 * HOUR,
        under: None,
        consent: false,
    };
    let mallory = h.add(OTHER, 10, copy);
    assert!(h.counts(tia), "Tia's visit with the host she chose");
    assert_eq!(h.why(mallory), Some(SourceFault::Consent), "the copy");
}
