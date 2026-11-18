//! Laws of an app's shared database: a set counts once the record binds its
//! signer, removed or not; an owned row changes only by its person's
//! devices; a removed person's rows take deletes from any member; and no
//! verdict a copy acted on ever turns, so every order of arrival ends alike.
//! Each law names the plant it went red on.
use eudoxia_community::db::{self, Change, Key, Lacks, Type, Verdict, Why};
use eudoxia_community::{
    Act, Community, Evidence, Facts, Roots, SourceMember, Statement, Vocabulary,
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

const KEEPER: &str = "keeper";
const PRIYA: &str = "priya";
const PRIYA_PHONE: &str = "priya-phone";
const SAM: &str = "sam";
const SAM_PHONE: &str = "sam-phone";
const TIA: &str = "tia";
const UMA: &str = "uma";

/// A house: the keeper's computer; Priya and Sam each with a computer and
/// a phone; Tia with a computer. Each person's key is their computer's.
fn roots() -> Roots<V> {
    let keys = [
        (KEEPER, KEEPER, true),
        (PRIYA, PRIYA, true),
        (PRIYA_PHONE, PRIYA, false),
        (SAM, SAM, true),
        (SAM_PHONE, SAM, false),
        (TIA, TIA, true),
    ];
    let member = |(key, first, computer): (&str, &'static str, bool)| {
        (
            key.to_string(),
            SourceMember::root(first.into(), first, computer),
        )
    };
    Roots::genesis(keys.map(member).into_iter().collect(), KEEPER.into()).unwrap()
}

/// The record's facts once these Removes are held, each `(by, key)` on its
/// signer's own chain.
fn record(removes: &[(&str, &str)]) -> Facts<V> {
    let (mut held, mut tips) = (BTreeMap::new(), BTreeMap::new());
    for (i, (by, key)) in removes.iter().enumerate() {
        let id = i as u32 + 1;
        let statement = Statement {
            author: by.to_string(),
            stands_as: by.to_string(),
            prev: tips.insert(*by, id),
            at: i64::from(id),
            readable: true,
            delegated: false,
            act: Act::Remove {
                key: key.to_string(),
                through: Vec::new(),
            },
        };
        held.insert(id, statement);
    }
    let roots = roots();
    let forged = BTreeSet::new();
    let facts = Community::new(&roots, &Evidence { held, forged }).facts();
    for (_, key) in removes {
        assert!(
            facts.out().contains_key(*key),
            "the record holds {key}'s Remove"
        );
    }
    facts
}

/// The keeper's Removes of these keys.
fn removed(keys: &[&'static str]) -> Facts<V> {
    let removes: Vec<_> = keys.iter().map(|key| (KEEPER, *key)).collect();
    record(&removes)
}

/// Every subset of `keys`, the one at index `mask` holding each key whose
/// bit is set.
fn subsets(keys: &[&'static str]) -> Vec<Vec<&'static str>> {
    let held = |mask: usize| (0..keys.len()).filter(move |i| mask & (1 << i) != 0);
    let named = |mask| held(mask).map(|i| keys[i]).collect();
    (0..1 << keys.len()).map(named).collect()
}

fn text(key: &str) -> Key<'_> {
    Key {
        kind: Type::Text,
        bytes: key.as_bytes(),
    }
}

/// One change set as the carrier reads it: its signer and the owned rows
/// it changes, each `(person_key, change)`; its shared rows ask nothing.
#[derive(Debug, Clone, Copy)]
struct Set {
    signer: &'static str,
    owned: &'static [(&'static str, Change)],
}

impl Set {
    /// Its verdict: its signer's, joined with each owned row's.
    fn verdict(&self, record: &Facts<V>) -> Verdict {
        let row = |(key, change): &(&str, Change)| db::row(record, self.signer, text(key), *change);
        (self.owned.iter().map(row)).fold(db::set(record, self.signer), Verdict::and)
    }
}

/// Plant: a write to another person's row taken (Sam's set changing
/// Priya's vote).
#[test]
fn an_owned_row_changes_only_by_its_person_s_devices() {
    let r = record(&[]);
    assert_eq!(
        db::row(&r, PRIYA, text(PRIYA), Change::Write),
        Verdict::Taken
    );
    assert_eq!(
        db::row(&r, PRIYA_PHONE, text(PRIYA), Change::Write),
        Verdict::Taken
    );
    assert_eq!(
        db::row(&r, PRIYA, text(PRIYA), Change::Delete),
        Verdict::Taken
    );
    let not_theirs = Verdict::Refused(Why::NotTheirs);
    assert_eq!(
        db::row(&r, SAM, text(PRIYA), Change::Write),
        not_theirs,
        "Sam's set changing Priya's vote"
    );
    assert_eq!(
        db::row(&r, SAM_PHONE, text(PRIYA), Change::Write),
        not_theirs
    );
    // A key-moving update carries a row under the new key: refused whoever signs.
    assert_eq!(db::row(&r, PRIYA, text(SAM), Change::Write), not_theirs);
    // A device the record binds to nobody waits for it.
    let unknown = Verdict::Waits(Lacks::Device);
    assert_eq!(db::row(&r, UMA, text(UMA), Change::Write), unknown);
}

/// Plant: the key compared by its bytes whatever its type (Priya's key's
/// bytes as a BLOB taken as Priya's).
#[test]
fn a_key_is_its_person_s_only_as_text_of_exactly_its_bytes() {
    let r = record(&[]);
    let not_theirs = Verdict::Refused(Why::NotTheirs);
    for kind in [Type::Blob, Type::Integer, Type::Real, Type::Null] {
        let key = Key {
            kind,
            bytes: PRIYA.as_bytes(),
        };
        assert_eq!(
            db::row(&r, PRIYA, key, Change::Write),
            not_theirs,
            "{kind:?}"
        );
        assert_eq!(
            db::row(&r, SAM, key, Change::Delete),
            not_theirs,
            "{kind:?}"
        );
    }
    for other in ["PRIYA", "priya ", "priy"] {
        assert_eq!(
            db::row(&r, PRIYA, text(other), Change::Write),
            not_theirs,
            "{other:?}"
        );
    }
    let unread = Key {
        kind: Type::Text,
        bytes: b"priya\xff",
    };
    assert_eq!(
        db::row(&r, SAM, unread, Change::Delete),
        not_theirs,
        "nobody's key"
    );
}

/// Plant: a delete of another person's row taken while they stand.
#[test]
fn a_removed_person_s_rows_take_deletes_from_any_member() {
    let removal = Verdict::Waits(Lacks::Removal);
    let standing = record(&[]);
    assert_eq!(
        db::row(&standing, SAM, text(PRIYA), Change::Delete),
        removal
    );
    let one_key = record(&[(PRIYA, PRIYA_PHONE)]);
    assert_eq!(
        db::row(&one_key, SAM, text(PRIYA), Change::Delete),
        removal,
        "her computer stands"
    );
    let gone = removed(&[PRIYA, PRIYA_PHONE]);
    assert_eq!(
        db::row(&gone, SAM, text(PRIYA), Change::Delete),
        Verdict::Taken
    );
    assert_eq!(
        db::row(&gone, SAM_PHONE, text(PRIYA), Change::Delete),
        Verdict::Taken
    );
    let not_theirs = Verdict::Refused(Why::NotTheirs);
    assert_eq!(
        db::row(&gone, SAM, text(PRIYA), Change::Write),
        not_theirs,
        "deletes only"
    );
    // Her own devices' sets stay hers, removed or not.
    assert_eq!(
        db::row(&gone, PRIYA, text(PRIYA), Change::Write),
        Verdict::Taken
    );
    // A key the record binds to nobody may be a person not yet held.
    assert_eq!(db::row(&gone, SAM, text(UMA), Change::Delete), removal);
}

/// Plants: a set the record binds no signer of taken; a removed device's
/// set refused.
#[test]
fn a_removed_device_s_sets_are_taken_like_any_device_s() {
    let before = record(&[]);
    let after = record(&[(PRIYA, PRIYA_PHONE)]);
    let gone = removed(&[PRIYA, PRIYA_PHONE]);
    for r in [&before, &after, &gone] {
        for signer in [PRIYA, PRIYA_PHONE, SAM, TIA] {
            assert_eq!(db::set(r, signer), Verdict::Taken, "{signer}");
        }
        assert_eq!(db::set(r, UMA), Verdict::Waits(Lacks::Device));
    }
    assert_eq!(
        db::row(&after, PRIYA_PHONE, text(PRIYA), Change::Write),
        Verdict::Taken,
        "a removed device's write to its own person's row"
    );
}

/// A set is taken only if its signer and every owned row it changes take
/// it, and refused if any refuses.
#[test]
fn a_set_s_verdicts_join_refusal_first() {
    let taken = Verdict::Taken;
    let (device, removal) = (
        Verdict::Waits(Lacks::Device),
        Verdict::Waits(Lacks::Removal),
    );
    let theirs = Verdict::Refused(Why::NotTheirs);
    assert_eq!(taken.and(taken), taken);
    assert_eq!((taken.and(removal), removal.and(taken)), (removal, removal));
    assert_eq!(
        (removal.and(device), device.and(removal)),
        (removal, device)
    );
    assert_eq!((removal.and(theirs), theirs.and(removal)), (theirs, theirs));
    assert_eq!(taken.and(theirs), theirs);
}

/// Every key, signer and change in the house, and one the record binds to
/// nobody, judged under each of `records`; and each set's own verdict.
fn verdicts(records: &[Facts<V>]) -> Vec<Vec<Verdict>> {
    let keys = [KEEPER, PRIYA, PRIYA_PHONE, SAM, SAM_PHONE, TIA, UMA];
    let judged = |r: &Facts<V>| {
        let mut all: Vec<_> = keys.iter().map(|signer| db::set(r, signer)).collect();
        for signer in keys {
            for key in keys {
                for change in [Change::Write, Change::Delete] {
                    all.push(db::row(r, signer, text(key), change));
                }
            }
        }
        all
    };
    records.iter().map(judged).collect()
}

/// The module has no way to refuse a set it once took: as the record grows
/// by Removes, in any order, a taken or refused verdict never turns. A Remove
/// arriving after a removed device's set was taken leaves it taken.
/// Plants: a removed device's set refused; a removed device's write to its
/// own person's row refused.
#[test]
fn no_verdict_turns_as_removes_arrive() {
    let subsets = subsets(&[PRIYA_PHONE, PRIYA, SAM_PHONE, TIA]);
    let records: Vec<_> = subsets.iter().map(|held| removed(held)).collect();
    let judged = verdicts(&records);
    for (a, fewer) in subsets.iter().enumerate() {
        for (b, more) in subsets.iter().enumerate() {
            if !fewer.iter().all(|key| more.contains(key)) {
                continue;
            }
            for (i, (then, now)) in judged[a].iter().zip(&judged[b]).enumerate() {
                if !matches!(then, Verdict::Waits(_)) {
                    assert_eq!(then, now, "verdict {i} under {fewer:?}, then {more:?}");
                }
            }
        }
    }
    let phone = Set {
        signer: PRIYA_PHONE,
        owned: &[(PRIYA, Change::Write)],
    };
    let (first, last) = (&records[0], records.last().unwrap());
    assert_eq!(phone.verdict(first), Verdict::Taken);
    assert_eq!(
        phone.verdict(last),
        Verdict::Taken,
        "its Remove came after it was taken"
    );
}

#[derive(Debug, Clone, Copy)]
enum Event {
    Remove(usize),
    Set(usize),
}

/// One copy of an app's database, as a carrier keeps it: a set taken is
/// applied and never judged again, one refused is dropped for good, one
/// that waits is held, never applied; each Remove judges again what it
/// holds. `removes` is a mask of the Removes held, indexing `records`.
#[derive(Default)]
struct Copy {
    removes: usize,
    held: BTreeSet<usize>,
    applied: BTreeSet<usize>,
    refused: BTreeSet<usize>,
}
impl Copy {
    fn take(&mut self, event: Event, records: &[Facts<V>], sets: &[Set]) {
        match event {
            Event::Remove(i) => self.removes |= 1 << i,
            Event::Set(i) => drop(self.held.insert(i)),
        }
        let record = &records[self.removes];
        for i in std::mem::take(&mut self.held) {
            let _ = match sets[i].verdict(record) {
                Verdict::Taken => self.applied.insert(i),
                Verdict::Refused(_) => self.refused.insert(i),
                Verdict::Waits(_) => self.held.insert(i),
            };
        }
        for i in &self.applied {
            let now = sets[*i].verdict(record);
            assert_eq!(now, Verdict::Taken, "set {i}, applied, never turns");
        }
    }
}

fn orders(events: &[Event]) -> Vec<Vec<Event>> {
    if events.is_empty() {
        return vec![Vec::new()];
    }
    let mut all = Vec::new();
    for i in 0..events.len() {
        let mut rest = events.to_vec();
        let first = rest.remove(i);
        for mut order in orders(&rest) {
            order.insert(0, first);
            all.push(order);
        }
    }
    all
}

/// Every order of Priya's two Removes and five sets ends with the same copy:
/// her phone's sets applied, whether they came before its Remove or after;
/// Sam's delete of her row held until both Removes, then applied; Sam's
/// phone's write to it refused; a stranger's set held. At every arrival, no
/// set a copy applied has turned, and what every copy applied is what the
/// whole record takes.
/// Plants: a removed device's set refused; a removed device's write to its
/// own person's row refused.
#[test]
fn every_order_of_the_removes_and_sets_ends_alike() {
    let removes = [PRIYA, PRIYA_PHONE];
    let records: Vec<_> = subsets(&removes).iter().map(|h| removed(h)).collect();
    let sets = [
        Set {
            signer: PRIYA_PHONE,
            owned: &[(PRIYA, Change::Write)],
        },
        Set {
            signer: PRIYA_PHONE,
            owned: &[],
        },
        Set {
            signer: SAM,
            owned: &[(PRIYA, Change::Delete), (SAM, Change::Write)],
        },
        Set {
            signer: SAM_PHONE,
            owned: &[(PRIYA, Change::Write)],
        },
        Set {
            signer: UMA,
            owned: &[],
        },
    ];
    let mut events: Vec<_> = (0..removes.len()).map(Event::Remove).collect();
    events.extend((0..sets.len()).map(Event::Set));
    let all = orders(&events);
    assert_eq!(all.len(), 5040);
    let ended = |order: &[Event]| {
        let mut copy = Copy::default();
        for event in order {
            copy.take(*event, &records, &sets);
        }
        (copy.applied, copy.refused, copy.held)
    };
    let first = ended(&all[0]);
    for order in &all {
        assert_eq!(ended(order), first, "{:?} against {:?}", order, all[0]);
    }
    let expected = (
        BTreeSet::from([0, 1, 2]),
        BTreeSet::from([3]),
        BTreeSet::from([4]),
    );
    assert_eq!(first, expected);
    let whole = records.last().unwrap();
    let taken: BTreeSet<_> = (0..sets.len())
        .filter(|i| sets[*i].verdict(whole) == Verdict::Taken)
        .collect();
    assert_eq!(first.0, taken, "what every copy applied, the record takes");
    let mut early = Copy::default();
    for event in [Event::Set(2), Event::Remove(0)] {
        early.take(event, &records, &sets);
    }
    assert_eq!(early.held, BTreeSet::from([2]), "held, not applied");
    early.take(Event::Remove(1), &records, &sets);
    assert_eq!(early.applied, BTreeSet::from([2]), "then applied once");
}
