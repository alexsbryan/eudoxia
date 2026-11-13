//! Laws of who may use a lend: two owners, the lender and the person, each
//! must permit; a person's stop and a missing yes refuse; a recheck
//! revokes a use once what let it in stops.
use eudoxia_community::lend::{self, Admit, Asked, Refusal, Said};

/// The Ed25519 base point: a key that reads as one.
const NODE: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];
const OWN: &str = "own-shelf";
const OTHER: &str = "other-picks";

/// The person's stop refuses an app the lender lets read: each owner
/// decides its own rules, and every owner must permit.
#[test]
fn a_person_s_stop_refuses_what_the_lender_lets_through() {
    let read = lend::admit(&NODE, OWN, Some(OTHER), Asked::Read, (false, false, false));
    assert_eq!(read, Ok(Admit::Bare), "the lender lets another app read");
    let stopped = lend::choose(&NODE, true, OWN, Some(OTHER), Some(Said::Stop));
    assert_eq!(
        stopped,
        Err(Refusal::Stopped),
        "the person's stop refuses it"
    );
    let yes = lend::choose(&NODE, true, OWN, Some(OTHER), Some(Said::Yes));
    assert_eq!(yes, Ok(()), "the person's yes lets it");
    let write = lend::admit(&NODE, OWN, Some(OTHER), Asked::Write, (true, false, true));
    assert_eq!(
        write,
        Err(Refusal::ReadOnly),
        "the lender lets another app only read"
    );
}

/// A yes counts only for an app named: a request naming none is unasked.
#[test]
fn no_app_named_is_unasked_even_with_a_yes() {
    let none = lend::choose(&NODE, true, OWN, None, Some(Said::Yes));
    assert_eq!(none, Err(Refusal::Unasked));
    assert_eq!(lend::choose(&NODE, true, OWN, Some(OWN), None), Ok(()));
    assert_eq!(lend::choose(&NODE, false, OWN, None, None), Ok(()));
}

/// A use let in is cut once what let it in no longer stands, its pass has
/// lapsed, or no clock can judge its pass.
#[test]
fn a_recheck_revokes_once_what_let_it_in_stops() {
    let (until, before, after) = (Some(100), Some(99), Some(100));
    assert!(lend::recheck(&NODE, OWN, true, until, before), "live");
    assert!(
        lend::recheck(&NODE, OWN, true, None, before),
        "no pass to lapse"
    );
    assert!(
        !lend::recheck(&NODE, OWN, false, until, before),
        "standing stopped"
    );
    assert!(
        !lend::recheck(&NODE, OWN, true, until, after),
        "the pass lapsed"
    );
    assert!(
        !lend::recheck(&NODE, OWN, true, until, None),
        "no clock to judge the pass by"
    );
    assert!(
        lend::recheck(&NODE, OWN, true, None, None),
        "no pass, so no clock needed"
    );
}

/// A page reaches only what it reads; another computer's app only on its
/// person's yes naming the lend, and a carried app sends only where that
/// yes names it to.
#[test]
fn a_page_reaches_what_it_reads_on_its_person_s_yes() {
    let reach = |reads, yes, send| lend::reach(&NODE, OTHER, reads, yes, (send, true));
    assert_eq!(reach((false, true), None, false), Err(Refusal::Silent));
    assert_eq!(reach((false, false), None, false), Err(Refusal::NotRead));
    assert_eq!(
        reach((true, false), None, false),
        Ok(()),
        "this computer's own app"
    );
    assert_eq!(
        reach((true, false), Some((false, false)), false),
        Err(Refusal::Unopened)
    );
    assert_eq!(reach((true, false), Some((true, false)), false), Ok(()));
    assert_eq!(
        reach((true, false), Some((true, false)), true),
        Err(Refusal::Unsent)
    );
    assert_eq!(reach((true, false), Some((true, true)), true), Ok(()));
}

/// A node key that reads as no key decides nothing: never a permit.
#[test]
fn no_key_permits_nothing() {
    // y = 2 is on no point of the curve.
    let mut none = [0; 32];
    none[0] = 2;
    assert!(lend::choose(&none, false, OWN, None, None).is_err());
    assert!(!lend::recheck(&none, OWN, true, None, Some(1)));
}
