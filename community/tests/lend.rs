//! Laws of who may use a lend: two owners, the lender and the person, each
//! must permit; a person's stop and a missing yes refuse; a recheck
//! revokes a use once what let it in stops; a pass a key the lend lists
//! signed opens it only as its own app, to read and send, for no longer
//! than its entry accepts.
use eudoxia_community::lend::{self, Admit, Asked, Refusal, Said, Vouch};

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
    assert!(lend::vouch(&none, OWN, NOW, vouched()).is_err());
}

const NOW: i64 = 1_000;

/// A pass a listed key signed for `OWN`, ending 120 s from now, its
/// entry accepting 120 s, asked to read: what every case below varies.
fn vouched() -> Vouch<'static> {
    Vouch {
        listed: true,
        app: OWN,
        linked: false,
        until: NOW + 120,
        longest: 120,
        asked: Asked::Read,
        removed: (false, false),
    }
}

fn vouch(v: Vouch<'_>) -> Result<i64, Refusal> {
    lend::vouch(&NODE, OWN, NOW, v)
}

/// A listed key's pass opens the lend to read and to send where its
/// lender said, until the pass's own end, and no later.
#[test]
fn a_listed_key_s_pass_opens_its_lend_to_read_and_send_until_it_ends() {
    assert_eq!(
        vouch(vouched()),
        Ok(NOW + 120),
        "a read, its end exactly the longest"
    );
    let send = Vouch {
        asked: Asked::Send,
        until: NOW + 1,
        ..vouched()
    };
    assert_eq!(vouch(send), Ok(NOW + 1), "a declared send, a shorter pass");
}

/// The entry judging the request is the signer's own: a signer the lend
/// does not list opens nothing.
#[test]
fn a_pass_no_listed_key_signed_is_refused() {
    let unlisted = Vouch {
        listed: false,
        ..vouched()
    };
    assert_eq!(vouch(unlisted), Err(Refusal::Unlisted));
}

/// A pass for another app that lists this lend among its reads does not
/// open it: the pass must name this lend as its own app.
#[test]
fn a_pass_naming_another_app_is_refused_though_it_reads_this_one() {
    let sideways = Vouch {
        app: OTHER,
        ..vouched()
    };
    assert_eq!(vouch(sideways), Err(Refusal::Elsewhere));
}

/// A holder cannot hand a listed key's pass on to another key.
#[test]
fn a_pass_a_link_hands_on_is_refused() {
    let linked = Vouch {
        linked: true,
        ..vouched()
    };
    assert_eq!(vouch(linked), Err(Refusal::Linked));
}

/// Removal wins: a key a group held here removed, as the pass's signer
/// or its holder, is refused on this path too.
#[test]
fn a_removed_signer_or_holder_is_refused() {
    for removed in [(true, false), (false, true), (true, true)] {
        let out = Vouch {
            removed,
            ..vouched()
        };
        assert_eq!(vouch(out), Err(Refusal::Removed), "{removed:?}");
    }
}

/// The lender, not the signer, bounds how long: a pass ending even a
/// second past the entry's longest from now is refused.
#[test]
fn a_pass_ending_past_the_longest_its_entry_accepts_is_refused() {
    let hour = Vouch {
        until: NOW + 3_600,
        ..vouched()
    };
    assert_eq!(vouch(hour), Err(Refusal::Outlasts), "an hour against 120 s");
    let second = Vouch {
        until: NOW + 121,
        ..vouched()
    };
    assert_eq!(vouch(second), Err(Refusal::Outlasts), "one second over");
    let far = Vouch {
        until: i64::MAX,
        longest: u32::MAX,
        ..vouched()
    };
    assert_eq!(
        vouch(far),
        Err(Refusal::Outlasts),
        "the longest accepted bounds the farthest pass"
    );
}

/// A pass that has lapsed opens nothing, whatever its entry accepts.
#[test]
fn a_lapsed_pass_is_refused() {
    let lapsed = Vouch {
        until: NOW,
        ..vouched()
    };
    assert_eq!(vouch(lapsed), Err(Refusal::Lapsed));
}

/// Nothing but a read or a declared send: a write is refused.
#[test]
fn a_listed_key_s_pass_never_writes() {
    let write = Vouch {
        asked: Asked::Write,
        ..vouched()
    };
    assert_eq!(vouch(write), Err(Refusal::ReadsAndSends));
}
