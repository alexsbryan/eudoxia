//! Laws of a person's Removes of their own keys: no one of them voids
//! another, so a key one took out stays out as more of the record arrives.
//! Only the office's cut of the key that signed one takes it back, by the
//! cut's own rule. Each law names the plant it went red on.
use eudoxia_community::{
    Act, Community, Evidence, Facts, Redemption, Roots, SourceFailure, SourceFault, SourceMember,
    SourceOffice, Statement, Vocabulary,
};
use std::collections::BTreeSet;

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
const PRIYA_LAPTOP: &str = "priya-laptop";
const PRIYA_PHONE: &str = "priya-phone";
const PRIYA_TABLET: &str = "priya-tablet";
const SAM: &str = "sam";

/// A house: the keeper's computer; Priya with two computers, her desktop
/// (her first key) and her laptop; Sam with a computer.
fn roots() -> Roots<V> {
    let keys = [
        (KEEPER, KEEPER),
        (PRIYA, PRIYA),
        (PRIYA_LAPTOP, PRIYA),
        (SAM, SAM),
    ];
    let member = |(key, first): (&str, &'static str)| {
        (
            key.to_string(),
            SourceMember::root(first.into(), first, true),
        )
    };
    Roots::genesis(keys.map(member).into_iter().collect(), KEEPER.into()).unwrap()
}

/// A line `by` signs at `at` after `prev` on its own chain.
fn line(by: &str, prev: Option<u32>, at: i64, act: Act<V>) -> Statement<V> {
    Statement {
        author: by.to_string(),
        stands_as: by.to_string(),
        prev,
        at,
        readable: true,
        delegated: false,
        act,
    }
}

/// `by`'s Remove of `key`, covering the lines of it `through` names.
fn remove(by: &str, prev: Option<u32>, at: i64, key: &str, through: &[u32]) -> Statement<V> {
    let key = key.to_string();
    let through = through.to_vec();
    line(by, prev, at, Act::Remove { key, through })
}

/// Lines of a history, each under its id.
type Lines = Vec<(u32, Statement<V>)>;

/// The record's facts once these lines are held, each under its id.
fn holding(lines: &[(u32, Statement<V>)]) -> Facts<V> {
    let roots = roots();
    let held = lines.iter().cloned().collect();
    let forged = BTreeSet::new();
    Community::new(&roots, &Evidence { held, forged }).facts()
}

fn stands(record: &Facts<V>, key: &str) -> bool {
    record.standing().contains(key)
}

/// A line past every coverage that names its key: refused for good.
fn past_reach() -> Result<(), SourceFailure<u32>> {
    Err(SourceFailure::Refused {
        why: SourceFault::Binding,
    })
}

/// Priya leaves from her desktop, as an embedding's Leave writes it: a
/// Remove of her laptop (1), then of her desktop (2). Her laptop, which
/// never saw them, signs a Remove of her desktop dated before both (3), then
/// a line of an app's after it (4).
fn own_removal_then_a_back_dated_remove() -> Lines {
    let data = Act::Data {
        part: "notes".into(),
    };
    vec![
        (1, remove(PRIYA, None, 10, PRIYA_LAPTOP, &[])),
        (2, remove(PRIYA, Some(1), 11, PRIYA, &[])),
        (3, remove(PRIYA_LAPTOP, None, 5, PRIYA, &[])),
        (4, line(PRIYA_LAPTOP, Some(3), 6, data)),
    ]
}

/// Priya leaves from both computers at once, each by an embedding's Leave:
/// a Remove of the other computer, then of itself. No line is crafted.
fn two_leaves() -> Lines {
    vec![
        (1, remove(PRIYA, None, 10, PRIYA_LAPTOP, &[])),
        (2, remove(PRIYA, Some(1), 11, PRIYA, &[])),
        (3, remove(PRIYA_LAPTOP, None, 10, PRIYA, &[])),
        (4, remove(PRIYA_LAPTOP, Some(3), 11, PRIYA_LAPTOP, &[])),
    ]
}

/// The keeper cuts Priya's laptop (1), then her desktop (2), as an
/// embedding's removal writes it: every key of hers, naming no line. The
/// laptop then signs Removes of the keeper (3) and of her desktop (4), dated
/// before the cuts.
fn keeper_cut_then_back_dated_removes() -> Lines {
    vec![
        (1, remove(KEEPER, None, 10, PRIYA_LAPTOP, &[])),
        (2, remove(KEEPER, Some(1), 11, PRIYA, &[])),
        (3, remove(PRIYA_LAPTOP, None, 5, KEEPER, &[])),
        (4, remove(PRIYA_LAPTOP, Some(3), 6, PRIYA, &[])),
    ]
}

/// Priya's desktop removes her laptop (1); the keeper then cuts the desktop,
/// naming that Remove (2). The laptop signs a Remove of the desktop dated
/// before both (3).
fn remover_cut_then_a_back_dated_remove() -> Lines {
    vec![
        (1, remove(PRIYA, None, 10, PRIYA_LAPTOP, &[])),
        (2, remove(KEEPER, None, 11, PRIYA, &[1])),
        (3, remove(PRIYA_LAPTOP, None, 5, PRIYA, &[])),
    ]
}

/// Priya's desktop binds her phone (1, 2) and her laptop binds her tablet
/// (3, 4), each by its own Invite and Admit. The phone removes the laptop
/// (5); the tablet removes the desktop (6). Each Remove's signer is bound by
/// a line of the key the other Remove takes out.
fn removes_by_keys_bound_by_each_other_s_target() -> Lines {
    let invite = || Act::Invite {
        until: 100,
        device_of: Some(PRIYA.into()),
    };
    let admit = |key: &str, invite| Act::Admit {
        person: PRIYA,
        key: key.into(),
        sound: true,
        redemption: Some(Redemption {
            invite,
            device: false,
            consent: true,
        }),
    };
    vec![
        (1, line(PRIYA, None, 1, invite())),
        (2, line(PRIYA, Some(1), 2, admit(PRIYA_PHONE, 1))),
        (3, line(PRIYA_LAPTOP, None, 1, invite())),
        (4, line(PRIYA_LAPTOP, Some(3), 2, admit(PRIYA_TABLET, 3))),
        (5, remove(PRIYA_PHONE, None, 3, PRIYA_LAPTOP, &[])),
        (6, remove(PRIYA_TABLET, None, 3, PRIYA, &[])),
    ]
}

/// Priya's laptop, removed by her desktop, stays out after it signs a
/// Remove of the desktop dated before its removal. That Remove counts too:
/// two devices that remove each other are both out. Each of her Removes is
/// established, and the laptop's lines past its removal's reach stay
/// refused.
/// Plants: one of a person's Removes voids another; an exit's verdict
/// judged against another exit.
#[test]
fn a_device_its_person_removed_stays_out_after_a_back_dated_remove_of_its_remover() {
    let lines = own_removal_then_a_back_dated_remove();
    let left = holding(&lines[..2]);
    assert!(!stands(&left, PRIYA) && !stands(&left, PRIYA_LAPTOP));
    let all = holding(&lines);
    assert_eq!(
        all.out().get(PRIYA_LAPTOP),
        Some(&(1, true)),
        "her desktop's Remove took it"
    );
    assert!(!stands(&all, PRIYA_LAPTOP), "the laptop stands again");
    assert!(!stands(&all, PRIYA));
    for id in [1, 2, 3] {
        assert_eq!(all.verdicts()[&id], Ok(()), "Remove {id} counts");
    }
    assert_eq!(all.verdicts()[&4], past_reach(), "the laptop's line");
    let mutual = holding(&[lines[0].clone(), lines[2].clone()]);
    assert!(!stands(&mutual, PRIYA) && !stands(&mutual, PRIYA_LAPTOP));
    assert_eq!(mutual.out().get(PRIYA), Some(&(3, true)));
}

/// Two Leaves of one person at once leave every key of theirs out.
/// Plant: one of a person's Removes voids another.
#[test]
fn two_concurrent_leaves_leave_every_key_of_their_person_out() {
    let all = holding(&two_leaves());
    for key in [PRIYA, PRIYA_LAPTOP] {
        assert!(!stands(&all, key), "{key} stands after two leaves");
        assert!(all.out()[key].1, "her own Remove took {key}");
    }
    assert!(stands(&all, KEEPER) && stands(&all, SAM));
}

/// A keeper's cut holds against the cut device's back-dated Removes: the
/// keeper stands and holds the office, both of Priya's keys are out by the
/// cuts, and the laptop's Removes are refused. Before the keeper cuts her
/// desktop, the laptop's Remove of it counts for nothing: the cut of the
/// laptop names no line of it, so it retracts every one.
/// Plant: an exit counted past the office's cut of the key that signed it.
#[test]
fn a_keeper_s_cut_holds_against_the_cut_device_s_back_dated_removes() {
    let lines = keeper_cut_then_back_dated_removes();
    let all = holding(&lines);
    assert!(stands(&all, KEEPER), "the keeper stands");
    assert!(matches!(all.office(), SourceOffice::Held { key, .. } if key == KEEPER));
    assert_eq!(all.out().get(PRIYA_LAPTOP), Some(&(1, false)));
    assert_eq!(all.out().get(PRIYA), Some(&(2, false)));
    for id in [3, 4] {
        assert_eq!(
            all.verdicts()[&id],
            past_reach(),
            "the laptop's Remove {id}"
        );
    }
    let one_cut = holding(&[lines[0].clone(), lines[2].clone(), lines[3].clone()]);
    assert!(
        stands(&one_cut, PRIYA),
        "the cut laptop removed her desktop"
    );
}

/// A device removed by its person's other device stays out after the
/// keeper cuts that device, naming the Remove, and it signs a back-dated
/// Remove of it.
/// Plant: one of a person's Removes voids another.
#[test]
fn a_device_removed_by_a_device_the_keeper_cut_stays_out_after_removing_it() {
    let lines = remover_cut_then_a_back_dated_remove();
    let before = holding(&lines[..2]);
    assert!(!stands(&before, PRIYA) && !stands(&before, PRIYA_LAPTOP));
    let all = holding(&lines);
    assert_eq!(
        all.out().get(PRIYA_LAPTOP),
        Some(&(1, true)),
        "her desktop's Remove took it"
    );
    assert!(!stands(&all, PRIYA_LAPTOP), "the laptop stands again");
    assert_eq!(all.out().get(PRIYA), Some(&(2, false)), "the keeper cut it");
}

/// Histories in which a line arriving later could put back a key one of a
/// person's own Removes took out.
fn histories() -> Vec<(&'static str, Lines)> {
    vec![
        (
            "her own removal, then a back-dated Remove of her remover",
            own_removal_then_a_back_dated_remove(),
        ),
        ("two concurrent leaves", two_leaves()),
        (
            "a keeper's cut, then the cut device's back-dated Removes",
            keeper_cut_then_back_dated_removes(),
        ),
        (
            "her remover cut, then a back-dated Remove of it",
            remover_cut_then_a_back_dated_remove(),
        ),
        (
            "Removes by keys bound by each other's target",
            removes_by_keys_bound_by_each_other_s_target(),
        ),
    ]
}

/// As more of a history arrives, whatever of it a copy held first, a key a
/// person's own Remove took out never stands again, short of the office's
/// cut of the key that signed that Remove, which refuses it by the cut's
/// own rule: for each history, every subset of its lines held against every
/// larger one.
/// Plant: one of a person's Removes voids another.
#[test]
fn no_key_a_person_s_own_remove_took_out_stands_again_as_more_arrives() {
    for (history, lines) in histories() {
        let held = |mask: usize| {
            let lines = lines.iter().enumerate();
            let kept = lines.filter(|(i, _)| mask & (1 << i) != 0);
            kept.map(|(_, line)| line.clone()).collect::<Vec<_>>()
        };
        let all = 1usize << lines.len();
        let records: Vec<_> = (0..all).map(|mask| holding(&held(mask))).collect();
        for fewer in 0..all {
            for (key, (by, own)) in records[fewer].out() {
                if !own {
                    continue;
                }
                let signer = &lines.iter().find(|(id, _)| id == by).unwrap().1.author;
                for more in (0..all).filter(|more| fewer & !more == 0) {
                    let now = &records[more];
                    let signer_cut = now.out().get(signer).is_some_and(|(_, own)| !own);
                    let cut = signer_cut && now.verdicts()[by].is_err();
                    let held = format!("{fewer:b}, then {more:b}");
                    assert!(
                        !stands(now, key) || cut,
                        "{history}: {key}, out by Remove {by}, stands holding {held}"
                    );
                }
            }
        }
    }
}
