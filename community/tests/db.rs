//! Laws of an app's shared database: an owned row changes only by its
//! person's devices; a removed person's rows take deletes from any member;
//! a removed device's sets count up to its lowest fence, the same on every
//! copy in any order of arrival. Each law names the plant it went red on.
use eudoxia_community::db::{self, Change, Cut, Fence, Key, Lacks, Type, Verdict, Why};
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

/// A fence of Priya's phone, by `by`, at `mark`.
fn phone_fence(by: &'static str, mark: Option<u64>) -> Fence<'static> {
    let device = PRIYA_PHONE;
    Fence { by, device, mark }
}

fn text(key: &str) -> Key<'_> {
    Key {
        kind: Type::Text,
        bytes: key.as_bytes(),
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
    assert_eq!(db::row(&r, "uma", text("uma"), Change::Write), unknown);
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
    let gone = record(&[(KEEPER, PRIYA), (KEEPER, PRIYA_PHONE)]);
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
    // Her own devices' sets are hers; where they stop is their fence's.
    assert_eq!(
        db::row(&gone, PRIYA, text(PRIYA), Change::Write),
        Verdict::Taken
    );
    // A key the record binds to nobody may be a person not yet held.
    assert_eq!(db::row(&gone, SAM, text("uma"), Change::Delete), removal);
}

/// Plant: a set past its device's fence taken.
#[test]
fn a_removed_device_s_sets_count_up_to_its_lowest_fence() {
    let (before, after) = (record(&[]), record(&[(PRIYA, PRIYA_PHONE)]));
    let fences = [phone_fence(SAM, Some(2)), phone_fence(PRIYA, Some(4))];
    assert_eq!(
        Cut::of(&before, PRIYA_PHONE, &fences),
        Cut::Stands,
        "no Remove, no cut"
    );
    assert_eq!(Cut::Stands.set(9), Verdict::Taken);
    assert_eq!(Cut::of(&after, PRIYA_PHONE, &[]), Cut::Unfenced);
    assert_eq!(Cut::Unfenced.set(0), Verdict::Waits(Lacks::Fence));
    let cut = Cut::of(&after, PRIYA_PHONE, &fences);
    assert_eq!(cut, Cut::At(Some(2)));
    for seq in 0..=2 {
        assert_eq!(cut.set(seq), Verdict::Taken, "{seq}");
    }
    for seq in 3..=5 {
        assert_eq!(cut.set(seq), Verdict::Refused(Why::PastCut), "{seq}");
    }
    let none = phone_fence(TIA, None);
    let all = [fences[0], fences[1], none];
    assert_eq!(
        Cut::of(&after, PRIYA_PHONE, &all),
        Cut::At(None),
        "a copy holding none"
    );
    assert_eq!(Cut::At(None).set(0), Verdict::Refused(Why::PastCut));
    assert_eq!(Cut::of(&after, "uma", &fences), Cut::Unknown);
    assert_eq!(Cut::Unknown.set(0), Verdict::Waits(Lacks::Device));
}

/// A fence counts by its signer's binding as a computer and its device's
/// Remove, and never stops counting: not when its signer is cut after.
#[test]
fn a_computer_s_fence_of_a_removed_device_counts_for_good() {
    let (before, after) = (record(&[]), record(&[(PRIYA, PRIYA_PHONE)]));
    let sam = phone_fence(SAM, Some(2));
    assert_eq!(db::fence(&after, &sam), Verdict::Taken);
    assert_eq!(db::fence(&before, &sam), Verdict::Waits(Lacks::Removal));
    let phone = Fence {
        by: SAM_PHONE,
        ..sam
    };
    assert_eq!(db::fence(&after, &phone), Verdict::Refused(Why::NoCopy));
    assert_eq!(Cut::of(&after, PRIYA_PHONE, &[phone]), Cut::Unfenced);
    let stranger = Fence { by: "uma", ..sam };
    assert_eq!(db::fence(&after, &stranger), Verdict::Waits(Lacks::Device));
    let elsewhere = Fence {
        device: TIA,
        mark: Some(0),
        ..sam
    };
    assert_eq!(Cut::of(&after, PRIYA_PHONE, &[elsewhere]), Cut::Unfenced);
    let sam_cut = record(&[(PRIYA, PRIYA_PHONE), (KEEPER, SAM)]);
    assert_eq!(db::fence(&sam_cut, &sam), Verdict::Taken);
    assert_eq!(Cut::of(&sam_cut, PRIYA_PHONE, &[sam]), Cut::At(Some(2)));
}

/// A copy rebuilds only where it applied a set its device's cut refuses.
#[test]
fn a_copy_rebuilds_only_past_the_cut() {
    let cut = Cut::At(Some(2));
    assert!(!cut.undoes(None) && !cut.undoes(Some(2)));
    assert!(cut.undoes(Some(3)));
    assert!(Cut::At(None).undoes(Some(0)));
    for open in [Cut::Unknown, Cut::Stands, Cut::Unfenced] {
        assert!(!open.undoes(Some(9)), "{open:?}");
    }
}

/// A set is taken only if its cut and every owned row it changes take it,
/// and refused if any refuses.
#[test]
fn a_set_s_verdicts_join_refusal_first() {
    let (taken, waits) = (Verdict::Taken, Verdict::Waits(Lacks::Fence));
    let (past, theirs) = (
        Verdict::Refused(Why::PastCut),
        Verdict::Refused(Why::NotTheirs),
    );
    assert_eq!(taken.and(taken), taken);
    assert_eq!((taken.and(waits), waits.and(taken)), (waits, waits));
    assert_eq!((waits.and(past), past.and(waits)), (past, past));
    assert_eq!((taken.and(past), past.and(theirs)), (past, past));
}

#[derive(Debug, Clone, Copy)]
enum Event {
    Remove,
    Fence(usize),
    Set(u64),
}

/// One copy of an app's database, as a carrier keeps it: a set taken is
/// applied, one refused is dropped for good, one that waits is held; each
/// arrival judges again what it holds, and a cut that refuses something
/// applied rebuilds.
#[derive(Default)]
struct Copy {
    removed: bool,
    fences: Vec<Fence<'static>>,
    held: BTreeSet<u64>,
    applied: BTreeSet<u64>,
    refused: BTreeSet<u64>,
}
impl Copy {
    fn take(&mut self, event: Event, records: &[Facts<V>; 2], fences: &[Fence<'static>]) {
        match event {
            Event::Remove => self.removed = true,
            Event::Fence(i) => self.fences.push(fences[i]),
            Event::Set(seq) => drop(self.held.insert(seq)),
        }
        let record = &records[usize::from(self.removed)];
        let cut = Cut::of(record, PRIYA_PHONE, &self.fences);
        if cut.undoes(self.applied.last().copied()) {
            let undone: Vec<_> = (self.applied.iter().copied())
                .filter(|s| cut.set(*s) != Verdict::Taken)
                .collect();
            for seq in undone {
                self.applied.remove(&seq);
                self.refused.insert(seq);
            }
        }
        for seq in std::mem::take(&mut self.held) {
            let _ = match cut.set(seq) {
                Verdict::Taken => self.applied.insert(seq),
                Verdict::Refused(_) => self.refused.insert(seq),
                Verdict::Waits(_) => self.held.insert(seq),
            };
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

/// Every order of the Remove, two fences that disagree and the device's
/// sets ends with the same copy: what the lowest fence takes, applied,
/// the rest refused, nothing held. A copy that took a set past the cut
/// before the Remove came ends equal to one that never saw it.
/// Plants: the first fence held decides; the highest fence decides, so a
/// set one copy refused for good another later takes.
#[test]
fn every_order_of_the_remove_fences_and_sets_ends_alike() {
    let records = [record(&[]), record(&[(PRIYA, PRIYA_PHONE)])];
    let fences = [phone_fence(PRIYA, Some(2)), phone_fence(SAM, Some(0))];
    let mut events = vec![Event::Remove, Event::Fence(0), Event::Fence(1)];
    events.extend((0..4).map(Event::Set));
    let all = orders(&events);
    assert_eq!(all.len(), 5040);
    let ended = |order: &[Event]| {
        let mut copy = Copy::default();
        for event in order {
            copy.take(*event, &records, &fences);
        }
        (copy.applied, copy.refused, copy.held)
    };
    let first = ended(&all[0]);
    for order in &all {
        assert_eq!(ended(order), first, "{:?} against {:?}", order, all[0]);
    }
    let cut = Cut::of(&records[1], PRIYA_PHONE, &fences);
    let taken: BTreeSet<u64> = (0..4).filter(|s| cut.set(*s) == Verdict::Taken).collect();
    let refused = BTreeSet::from([1, 2, 3]);
    assert_eq!(first, (BTreeSet::from([0]), refused, BTreeSet::new()));
    assert_eq!(
        first.0, taken,
        "what every copy applied is what the cut takes"
    );
    let mut unseen = Copy::default();
    let never = [
        Event::Set(0),
        Event::Remove,
        Event::Fence(0),
        Event::Fence(1),
    ];
    for event in never {
        unseen.take(event, &records, &fences);
    }
    let mut early = Copy::default();
    for event in [Event::Set(0), Event::Set(3)]
        .into_iter()
        .chain(never.into_iter().skip(1))
    {
        early.take(event, &records, &fences);
    }
    assert_eq!(early.applied, unseen.applied);
}
