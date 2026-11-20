//! Laws of which program may receive a lend's traffic: an approval is the
//! sockets read that take what the carrier sends, or why none is; a
//! connection is carried only to what was approved; and missing, stale or
//! mismatched evidence is refused. Each law names the plants it went red on.
use eudoxia_community::binding::{
    Chosen, Held, Process, Read, Refused, Socket, Took, approve, check,
};
use std::net::{IpAddr, Ipv4Addr};

/// A socket of `id` on 127.0.0.1, made in `cgroup`, held by `holders`.
fn socket(id: u64, cgroup: Option<u64>, holders: &[Process]) -> Socket {
    let holders = holders.iter().copied().collect();
    Socket {
        id,
        cgroup,
        holders,
        at: IpAddr::V4(Ipv4Addr::LOCALHOST),
        dual: false,
    }
}

/// A socket of `id` bound to `at`.
fn bound(id: u64, at: &str) -> Socket {
    Socket {
        at: at.parse().unwrap(),
        ..socket(id, Some(4), &[(100, 1)])
    }
}

/// Linux's read: lasting cookies, in boot 7.
fn linux(sockets: Vec<Socket>) -> Read {
    Read {
        boot: Some(7),
        lasting: true,
        sockets,
        unlisted: false,
    }
}

/// A Mac's read: handles of this read alone, no boot.
fn mac(sockets: Vec<Socket>, unlisted: bool) -> Read {
    Read {
        boot: None,
        lasting: false,
        sockets,
        unlisted,
    }
}

fn chosen(pid: u32, start: u64, now: Option<u64>, parents: &[(u32, u32)]) -> Chosen {
    Chosen {
        pid,
        start,
        now,
        parents: parents.iter().copied().collect(),
    }
}

/// **An approval is the sockets read, or why none is**: Linux's by cookie
/// and cgroup, a Mac's by the processes holding them; nothing on the port,
/// or on a Mac only another account's, refused; with a process chosen, one
/// that stopped refused, and a socket on the port held by neither it nor a
/// child of it refused, a prefork's worker under its master approved.
/// Plants: the holder check skipped (another program's socket approved
/// with the chosen one); the start not compared (a stopped selection
/// approved).
#[test]
fn an_approval_is_the_sockets_read_or_why_none_is() {
    let two = linux(vec![
        socket(10, Some(4), &[(100, 1)]),
        socket(11, Some(4), &[(100, 1)]),
    ]);
    let approved = approve(&two, None).unwrap();
    assert_eq!(approved.sockets, [10, 11].into());
    assert_eq!(approved.cgroups, [4].into());
    assert!(approved.processes.is_empty(), "Linux approves by cookie");
    assert_eq!(approved.boot, Some(7));
    let on_mac = approve(
        &mac(vec![socket(9, None, &[(100, 1), (101, 2)])], false),
        None,
    );
    let on_mac = on_mac.unwrap();
    assert!(
        on_mac.sockets.is_empty(),
        "a Mac's handle names a socket in one read only"
    );
    assert_eq!(on_mac.processes, [(100, 1), (101, 2)].into());
    assert_eq!(approve(&linux(vec![]), None), Err(Refused::Nothing));
    assert_eq!(approve(&mac(vec![], true), None), Err(Refused::NotYours));
    // The master 100 chosen; its worker 101 holds the listener too.
    let prefork = linux(vec![socket(10, Some(4), &[(101, 5)])]);
    let master = chosen(100, 1, Some(1), &[(101, 100), (100, 1)]);
    assert!(
        approve(&prefork, Some(&master)).is_ok(),
        "a worker under its master"
    );
    let beside = linux(vec![
        socket(10, Some(4), &[(100, 1)]),
        socket(12, Some(9), &[(300, 3)]),
    ]);
    assert_eq!(approve(&beside, Some(&master)), Err(Refused::Another));
    let unread = linux(vec![
        socket(10, Some(4), &[(100, 1)]),
        socket(12, Some(9), &[]),
    ]);
    assert_eq!(
        approve(&unread, Some(&master)),
        Err(Refused::Another),
        "a socket no holder of which is read"
    );
    let restarted = chosen(100, 1, Some(2), &[]);
    assert_eq!(approve(&two, Some(&restarted)), Err(Refused::Stopped));
    assert_eq!(
        approve(&two, Some(&chosen(100, 1, None, &[]))),
        Err(Refused::Stopped)
    );
    let looped = chosen(100, 1, Some(1), &[(300, 301), (301, 300)]);
    let elsewhere = linux(vec![socket(12, Some(9), &[(300, 3)])]);
    assert_eq!(
        approve(&elsewhere, Some(&looped)),
        Err(Refused::Another),
        "a loop of parents ends"
    );
}

/// **A connection is carried only to what was approved**: Linux's, every
/// listener's cookie approved and the server end's cgroup; a Mac's, every
/// listener held by an approved process and the acceptor an approved
/// process or started by one (a prefork's worker, or Node cluster's, handed
/// the connection by its primary); a datagram by the sockets alone. Each
/// other case is held: none approved, another boot, a socket not approved
/// beside the approved one, an accept in another cgroup (the listener that
/// took it closed since), an acceptor neither approved nor started by one,
/// and nothing on the port; a Mac's socket beside it whose last user has
/// exited is unjudged, not another's. Plants: the cookie compare skipped
/// (another listener carried); the cgroup check skipped (an accept in
/// another cgroup carried); the acceptor alone compared, not its parents
/// (the worker held); a socket with no holder read taken as another's.
#[test]
fn a_connection_is_carried_only_to_what_was_approved() {
    let read = linux(vec![socket(10, Some(4), &[])]);
    let approved = approve(&read, None).unwrap();
    let ok = |now: &Read, took: &Took| check(Some(&approved), now, took);
    assert_eq!(ok(&read, &Took::Cgroup(4)), Ok(()));
    assert_eq!(ok(&read, &Took::Datagram), Ok(()));
    assert_eq!(check(None, &read, &Took::Datagram), Err(Held::Unapproved));
    let rebooted = Read {
        boot: Some(8),
        ..read.clone()
    };
    assert_eq!(
        ok(&rebooted, &Took::Datagram),
        Err(Held::Another),
        "another boot"
    );
    let restarted = linux(vec![socket(13, Some(4), &[])]);
    assert_eq!(
        ok(&restarted, &Took::Cgroup(4)),
        Err(Held::Another),
        "a restart"
    );
    let joined = linux(vec![socket(10, Some(4), &[]), socket(14, Some(9), &[])]);
    assert_eq!(
        ok(&joined, &Took::Cgroup(4)),
        Err(Held::Another),
        "a listener beside"
    );
    assert_eq!(
        ok(&joined, &Took::Datagram),
        Err(Held::Another),
        "a socket beside"
    );
    assert_eq!(
        ok(&read, &Took::Cgroup(9)),
        Err(Held::Another),
        "accepted in another cgroup"
    );
    assert_eq!(ok(&linux(vec![]), &Took::Cgroup(4)), Err(Held::Empty));

    let listener = mac(vec![socket(9, None, &[(100, 1)])], false);
    let approved = approve(&listener, None).unwrap();
    let ok = |now: &Read, took: &Took| check(Some(&approved), now, took);
    let worker = mac(vec![socket(77, None, &[(100, 1), (101, 2)])], false);
    let up = |lineage: &[Process]| Took::Lineage(lineage.to_vec());
    assert_eq!(
        ok(&worker, &up(&[(101, 2), (100, 1)])),
        Ok(()),
        "a prefork's worker"
    );
    assert_eq!(
        ok(&listener, &up(&[(5, 5), (1, 1)])),
        Err(Held::Another),
        "an acceptor neither approved nor started by one"
    );
    let over = mac(
        vec![socket(9, None, &[(100, 1)]), socket(8, None, &[(200, 3)])],
        false,
    );
    assert_eq!(
        ok(&over, &up(&[(100, 1)])),
        Err(Held::Another),
        "a more specific bind beside"
    );
    assert_eq!(ok(&over, &Took::Datagram), Err(Held::Another));
    let exited = mac(
        vec![socket(9, None, &[(100, 1)]), socket(8, None, &[])],
        false,
    );
    assert_eq!(
        ok(&exited, &Took::Datagram),
        Err(Held::Unjudged),
        "a socket beside whose last user has exited"
    );
    let again = mac(vec![socket(9, None, &[(100, 4)])], false);
    assert_eq!(
        ok(&again, &Took::Datagram),
        Err(Held::Another),
        "the same pid started again"
    );
}

/// **The carrier reaches a lend at an address an approved socket listens
/// on**: 127.0.0.1 for one on it or on every IPv4 address, ::1 for one on
/// it or on every IPv6 address, 127.0.0.1 when both are; one on another
/// address alone refused, saying which. A check finds that address still
/// listened on by an approved socket, else nothing is there. Plant: `on`
/// taking every socket on the port (a LAN address alone approved; an
/// approved LAN socket alone carried).
#[test]
fn the_carrier_reaches_a_lend_at_an_address_an_approved_socket_listens_on() {
    let at = |sockets: Vec<Socket>| approve(&linux(sockets), None).map(|a| a.at.to_string());
    assert_eq!(at(vec![bound(1, "127.0.0.1")]), Ok("127.0.0.1".into()));
    assert_eq!(at(vec![bound(1, "0.0.0.0")]), Ok("127.0.0.1".into()));
    assert_eq!(at(vec![bound(1, "::1")]), Ok("::1".into()));
    assert_eq!(at(vec![bound(1, "::")]), Ok("::1".into()));
    assert_eq!(
        at(vec![bound(1, "::ffff:127.0.0.1")]),
        Ok("127.0.0.1".into())
    );
    let both = vec![bound(1, "::"), bound(2, "0.0.0.0")];
    assert_eq!(at(both), Ok("127.0.0.1".into()), "both families: IPv4's");
    let lan: IpAddr = "192.168.1.5".parse().unwrap();
    assert_eq!(
        at(vec![bound(1, "192.168.1.5")]),
        Err(Refused::Elsewhere(lan))
    );
    let other: IpAddr = "127.0.0.2".parse().unwrap();
    assert_eq!(
        at(vec![bound(1, "127.0.0.2")]),
        Err(Refused::Elsewhere(other))
    );
    let beside = linux(vec![bound(1, "::1"), bound(2, "192.168.1.5")]);
    let approved = approve(&beside, None).unwrap();
    let lan_alone = linux(vec![bound(2, "192.168.1.5")]);
    let checked = check(Some(&approved), &lan_alone, &Took::Datagram);
    assert_eq!(checked, Err(Held::Empty), "nothing approved at ::1 now");
    assert_eq!(check(Some(&approved), &beside, &Took::Datagram), Ok(()));
}

/// **Something not approved, once seen, holds a lend until it is approved
/// again**: an approval marked held carries nothing, whatever is on the
/// port; one made again carries. Plant: `held` not read by `check` (the
/// approved socket back alone carried).
#[test]
fn something_not_approved_once_seen_holds_until_approved_again() {
    let read = linux(vec![socket(10, Some(4), &[])]);
    let mut approved = approve(&read, None).unwrap();
    approved.held = true;
    let held = check(Some(&approved), &read, &Took::Cgroup(4));
    assert_eq!(held, Err(Held::Another), "the approved socket back alone");
    let again = approve(&read, None).unwrap();
    assert!(!again.held);
    assert_eq!(check(Some(&again), &read, &Took::Cgroup(4)), Ok(()));
}

/// **A server end that waits on the carrier's first bytes is carried while
/// every socket on the port is approved**: Linux's request is made a socket
/// only by the listener its handshake reached, which is among those read,
/// listening or bound, so all approved carries; one not approved beside,
/// listening or bound and not listening, holds it. Plant: a waiting server
/// end held while all is approved. That the listener is among those read
/// is the carrier's to hold: it reads bound sockets as well as listening
/// ones.
#[test]
fn a_server_end_waiting_on_the_first_bytes_is_carried_while_all_is_approved() {
    let read = linux(vec![socket(10, Some(4), &[])]);
    let approved = approve(&read, None).unwrap();
    assert_eq!(check(Some(&approved), &read, &Took::Waiting), Ok(()));
    let beside = linux(vec![socket(10, Some(4), &[]), socket(14, Some(9), &[])]);
    let waiting = check(Some(&approved), &beside, &Took::Waiting);
    assert_eq!(waiting, Err(Held::Another));
}

/// **Only a socket that takes what the carrier sends holds a lend or is
/// approved with it**: beside a socket on 127.0.0.1, one on 127.0.0.2, on a
/// LAN address or on ::1 is neither approved with it nor holds it; one on
/// every IPv4 address holds it. Plant: `on` taking every socket on the port
/// (the one on 127.0.0.2 approved with it, and another there holding it).
#[test]
fn only_a_socket_that_takes_what_the_carrier_sends_holds_a_lend() {
    let game = bound(1, "127.0.0.1");
    for at in ["127.0.0.2", "192.168.1.5", "::1"] {
        let read = linux(vec![game.clone(), bound(2, at)]);
        let approved = approve(&read, None).unwrap();
        assert_eq!(approved.sockets, [1].into(), "{at} approved with it");
        let since = linux(vec![game.clone(), bound(3, at)]);
        let checked = check(Some(&approved), &since, &Took::Datagram);
        assert_eq!(checked, Ok(()), "another on {at}");
    }
    let approved = approve(&linux(vec![game.clone()]), None).unwrap();
    let every = linux(vec![game, bound(3, "0.0.0.0")]);
    let checked = check(Some(&approved), &every, &Took::Datagram);
    assert_eq!(checked, Err(Held::Another), "another on every address");
}

/// **A socket on every IPv6 address that takes IPv4's too takes what is
/// sent to 127.0.0.1**: a dual `[::]` alone is reached at 127.0.0.1, an
/// IPv6-only one at ::1; beside an approved socket on 127.0.0.1, a dual one
/// holds it and an IPv6-only one doesn't. Plant: `dual` not read by `on` (a
/// dual `[::]` reached at ::1).
#[test]
fn a_dual_socket_takes_what_is_sent_to_127_0_0_1() {
    let dual = Socket {
        dual: true,
        ..bound(1, "::")
    };
    let at = |s: Socket| approve(&linux(vec![s]), None).map(|a| a.at.to_string());
    assert_eq!(at(dual.clone()), Ok("127.0.0.1".into()));
    assert_eq!(at(bound(1, "::")), Ok("::1".into()));
    let game = bound(2, "127.0.0.1");
    let approved = approve(&linux(vec![game.clone()]), None).unwrap();
    let beside = |s: Socket| {
        let now = linux(vec![game.clone(), s]);
        check(Some(&approved), &now, &Took::Datagram)
    };
    assert_eq!(beside(dual), Err(Held::Another), "a dual one");
    assert_eq!(beside(bound(1, "::")), Ok(()), "an IPv6-only one");
}

/// **Missing evidence is refused**: with no approval, every connection is
/// held, whatever took it; a socket there whose holder can't be read is
/// unjudged, never carried; and with nothing there, or only what the read
/// can't list, the connection is held. Approving, nothing on the port, or
/// only what the read can't list, is refused. Plants: no approval carried;
/// an unread holder carried; nothing there carried.
#[test]
fn missing_evidence_is_refused() {
    let read = linux(vec![socket(10, Some(4), &[])]);
    let tooks = [
        Took::Datagram,
        Took::Waiting,
        Took::Cgroup(4),
        Took::Lineage(vec![(100, 1)]),
    ];
    for took in tooks {
        let unapproved = check(None, &read, &took);
        assert_eq!(unapproved, Err(Held::Unapproved), "{took:?}, none approved");
    }
    let listener = mac(vec![socket(9, None, &[(100, 1)])], false);
    let approved = approve(&listener, None).unwrap();
    let ok = |now: &Read| check(Some(&approved), now, &Took::Lineage(vec![(100, 1)]));
    let unread = mac(
        vec![socket(9, None, &[(100, 1)]), socket(8, None, &[])],
        false,
    );
    assert_eq!(ok(&unread), Err(Held::Unjudged), "a holder not read");
    assert_eq!(ok(&mac(vec![], false)), Err(Held::Empty), "nothing there");
    assert_eq!(
        ok(&mac(vec![], true)),
        Err(Held::Empty),
        "only what the read can't list"
    );
    assert_eq!(approve(&linux(vec![]), None), Err(Refused::Nothing));
    assert_eq!(approve(&mac(vec![], true), None), Err(Refused::NotYours));
}

/// **Stale evidence is refused**: a process chosen that started again since
/// it was shown, or stopped, is not approved; an approval from another boot
/// holds every connection, its cookies another boot's; and on a Mac, a
/// process with the approved id but another start holds it, as another
/// program. Plants: the boot not compared; the chosen start not compared;
/// a holder's start not compared.
#[test]
fn stale_evidence_is_refused() {
    let read = linux(vec![socket(10, Some(4), &[(100, 1)])]);
    let shown = |now| chosen(100, 1, now, &[]);
    assert!(approve(&read, Some(&shown(Some(1)))).is_ok());
    let again = approve(&read, Some(&shown(Some(2))));
    assert_eq!(again, Err(Refused::Stopped), "started again since shown");
    let gone = approve(&read, Some(&shown(None)));
    assert_eq!(gone, Err(Refused::Stopped), "stopped since shown");

    let approved = approve(&read, None).unwrap();
    assert_eq!(check(Some(&approved), &read, &Took::Cgroup(4)), Ok(()));
    let rebooted = Read {
        boot: Some(8),
        ..read.clone()
    };
    let held = check(Some(&approved), &rebooted, &Took::Cgroup(4));
    assert_eq!(held, Err(Held::Another), "another boot");

    let listener = mac(vec![socket(9, None, &[(100, 1)])], false);
    let approved = approve(&listener, None).unwrap();
    let acceptor = Took::Lineage(vec![(100, 1)]);
    assert_eq!(check(Some(&approved), &listener, &acceptor), Ok(()));
    let restarted = mac(vec![socket(9, None, &[(100, 4)])], false);
    for took in [Took::Datagram, Took::Lineage(vec![(100, 4)])] {
        let held = check(Some(&approved), &restarted, &took);
        assert_eq!(held, Err(Held::Another), "the same pid started again");
    }
}

/// **Evidence that doesn't match is refused**: a socket there by another
/// cookie than the approved one, a socket held by a process not approved, a
/// connection accepted in a cgroup not approved, or by a process neither
/// approved nor started by one, each holds the connection; and a process
/// chosen that holds no socket there is not approved. Plants: the cookie
/// not compared; the cgroup not compared; a holder not compared; the
/// acceptor not compared; the chosen process's holding not compared.
#[test]
fn mismatched_evidence_is_refused() {
    let read = linux(vec![socket(10, Some(4), &[])]);
    let approved = approve(&read, None).unwrap();
    let other = linux(vec![socket(11, Some(4), &[])]);
    let held = check(Some(&approved), &other, &Took::Cgroup(4));
    assert_eq!(held, Err(Held::Another), "another cookie");
    let held = check(Some(&approved), &read, &Took::Cgroup(5));
    assert_eq!(held, Err(Held::Another), "another cgroup");

    let listener = mac(vec![socket(9, None, &[(100, 1)])], false);
    let approved = approve(&listener, None).unwrap();
    let another = mac(vec![socket(9, None, &[(200, 3)])], false);
    let held = check(Some(&approved), &another, &Took::Datagram);
    assert_eq!(held, Err(Held::Another), "another holder");
    let up = Took::Lineage(vec![(300, 5), (1, 1)]);
    let held = check(Some(&approved), &listener, &up);
    assert_eq!(held, Err(Held::Another), "another acceptor");

    let elsewhere = chosen(200, 3, Some(3), &[(100, 1)]);
    let refused = approve(&listener, Some(&elsewhere));
    assert_eq!(refused, Err(Refused::Another), "chosen, holding none of it");
}

/// **A dial address no approved socket still covers is refused**: approved
/// at 127.0.0.1, a program that now listens only on a LAN address, on
/// 127.0.0.2, or on IPv6 alone holds every connection as nothing there,
/// though it is the approved process; on every IPv4 address it still covers
/// 127.0.0.1. A port where no socket covers this computer's own addresses
/// is not approved, saying where its socket is. Plants: the check reading
/// every socket on the port, not those covering the approved address; an
/// approval made where no socket covers 127.0.0.1 or ::1.
#[test]
fn a_dial_address_no_approved_socket_covers_is_refused() {
    let held_at = |at: &str| Socket {
        at: at.parse().unwrap(),
        ..socket(9, None, &[(100, 1)])
    };
    let approved = approve(&mac(vec![held_at("127.0.0.1")], false), None).unwrap();
    assert_eq!(approved.at, IpAddr::V4(Ipv4Addr::LOCALHOST));
    let acceptor = Took::Lineage(vec![(100, 1)]);
    for at in ["192.168.1.5", "127.0.0.2", "::1", "::"] {
        let moved = mac(vec![held_at(at)], false);
        let held = check(Some(&approved), &moved, &acceptor);
        assert_eq!(held, Err(Held::Empty), "only on {at}");
    }
    let every = mac(vec![held_at("0.0.0.0")], false);
    let carried = check(Some(&approved), &every, &acceptor);
    assert_eq!(carried, Ok(()), "on every IPv4 address");
    let lan: IpAddr = "192.168.1.5".parse().unwrap();
    let refused = approve(&mac(vec![held_at("192.168.1.5")], false), None);
    assert_eq!(refused, Err(Refused::Elsewhere(lan)));
}
