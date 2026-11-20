//! Laws of which program may receive a lend's traffic: an approval is the
//! sockets read that take what the carrier sends, or why none is; a
//! connection is carried only to what was approved; and missing, stale or
//! mismatched evidence is refused. Each law names the plants it went red on.
use eudoxia_community::binding::{
    Approved, Chosen, Held, Process, Read, Refused, Socket, Took, approve, check,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// A socket of `id` on 127.0.0.1, made in `cgroup`, held by `holders`,
/// connected to nothing.
fn socket(id: u64, cgroup: Option<u64>, holders: &[Process]) -> Socket {
    let holders = holders.iter().copied().collect();
    Socket {
        id,
        cgroup,
        holders,
        at: IpAddr::V4(Ipv4Addr::LOCALHOST),
        dual: false,
        peer: None,
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

/// A Mac's TCP read: generation counts, which last, in boot 9, and no
/// cgroup.
fn counted(sockets: Vec<Socket>) -> Read {
    Read {
        boot: Some(9),
        lasting: true,
        sockets,
        unlisted: false,
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

/// **A socket whose id lasts and that carries no cgroup is approved by its
/// id, with the processes holding it, by which what took a connection is
/// judged**: a Mac's TCP read with lasting ids keeps both; that socket,
/// taken by an approved process, by a prefork's worker started since, or by
/// a Node cluster's worker its primary handed the connection, carries; a new
/// socket from the same process, alone or beside it, a restart, another
/// account's acceptor and another boot are held. Plants: the holders not
/// kept where ids last; a socket judged by its holders where ids last;
/// another socket's id carried; the boot not compared; the acceptor alone
/// compared, not its parents; the acceptor not compared.
#[test]
fn a_lasting_socket_with_no_cgroup_is_approved_by_its_id_and_its_acceptor_by_its_holders() {
    // The primary 100 holds the listener, counted 40, and so does its worker.
    let listener = counted(vec![socket(40, None, &[(100, 1), (101, 2)])]);
    let primary = chosen(100, 1, Some(1), &[(101, 100), (100, 1)]);
    let approved = approve(&listener, Some(&primary)).unwrap();
    assert_eq!(approved.sockets, [40].into(), "by its id");
    let holders = [(100, 1), (101, 2)].into();
    assert_eq!(approved.processes, holders, "with its holders");
    assert_eq!(approved.boot, Some(9));
    let took = |now: &Read, up: &[Process]| {
        let took = Took::Lineage(up.to_vec());
        check(Some(&approved), now, &took)
    };
    let worker = [(101, 2), (100, 1)];
    assert_eq!(took(&listener, &worker), Ok(()), "a worker approved");
    let since = counted(vec![socket(40, None, &[(100, 1), (102, 5)])]);
    let worker = [(102, 5), (100, 1)];
    assert_eq!(took(&since, &worker), Ok(()), "a worker started since");
    let handed = [(103, 6), (100, 1), (1, 1)];
    assert_eq!(took(&listener, &handed), Ok(()), "a cluster's worker");
    let next = counted(vec![socket(41, None, &[(100, 1)])]);
    let same = [(100, 1)];
    assert_eq!(
        took(&next, &same),
        Err(Held::Another),
        "a new socket, the same process"
    );
    let beside = counted(vec![
        socket(40, None, &[(100, 1)]),
        socket(41, None, &[(100, 1)]),
    ]);
    assert_eq!(
        took(&beside, &same),
        Err(Held::Another),
        "a new socket beside it, the same process"
    );
    let restarted = counted(vec![socket(42, None, &[(100, 7)])]);
    let again = [(100, 7), (1, 1)];
    assert_eq!(took(&restarted, &again), Err(Held::Another), "a restart");
    let theirs = [(500, 8), (1, 1)];
    assert_eq!(
        took(&listener, &theirs),
        Err(Held::Another),
        "another account's acceptor"
    );
    let rebooted = Read {
        boot: Some(10),
        ..listener.clone()
    };
    assert_eq!(took(&rebooted, &same), Err(Held::Another), "another boot");
}

/// **A datagram socket connected to the carrier's own socket for a flow
/// alone, made in an approved cgroup, is admitted for the flows the carrier
/// names**: beside the approved socket, one a server makes for a flow on
/// the same address (pasta's, for rootless Podman), connected to the
/// carrier's socket for it, in the approved cgroup, is carried, and one for
/// each flow named; one not connected or whose peer is unread, one
/// connected elsewhere, one connected to the flow in another cgroup or in
/// none read, one beside a datagram whose flows aren't named, and one for a
/// flow not named are held; a Mac's, with no cgroup, is held as before.
/// Plants: the socket for this flow held; an unconnected socket admitted;
/// one connected elsewhere admitted; one in another cgroup admitted; one
/// with no cgroup read admitted; one admitted for a datagram whose flows
/// aren't named.
#[test]
fn a_socket_connected_to_the_carrier_s_flow_in_an_approved_cgroup_is_admitted_for_it() {
    // pasta's socket on the port, cookie 1 in cgroup 10601; one it makes
    // for a flow is on the same address, held by the same process.
    let pasta = |id, cgroup, peer: Option<&str>| Socket {
        peer: peer.map(|p| p.parse().unwrap()),
        ..socket(id, cgroup, &[(300, 3)])
    };
    let listener = pasta(1, Some(10601), None);
    let approved = approve(&linux(vec![listener.clone()]), None).unwrap();
    let one: SocketAddr = "127.0.0.1:45588".parse().unwrap();
    let two: SocketAddr = "127.0.0.1:45590".parse().unwrap();
    let flows = |named: &[SocketAddr]| Took::Flow(named.iter().copied().collect());
    let this = flows(&[one]);
    let beside = |s: Socket, took: &Took| {
        let now = linux(vec![listener.clone(), s]);
        check(Some(&approved), &now, took)
    };
    let answering = pasta(4099, Some(10601), Some("127.0.0.1:45588"));
    assert_eq!(
        beside(answering.clone(), &this),
        Ok(()),
        "its socket for the flow"
    );
    let held = |s| beside(s, &this);
    assert_eq!(
        held(pasta(4099, Some(10601), None)),
        Err(Held::Another),
        "not connected, or its peer unread"
    );
    assert_eq!(
        held(pasta(4099, Some(10601), Some("127.0.0.1:45589"))),
        Err(Held::Another),
        "connected elsewhere"
    );
    assert_eq!(
        held(pasta(4099, Some(9), Some("127.0.0.1:45588"))),
        Err(Held::Another),
        "connected to the flow, in another cgroup"
    );
    assert_eq!(
        held(pasta(4099, None, Some("127.0.0.1:45588"))),
        Err(Held::Another),
        "connected to the flow, no cgroup read"
    );
    assert_eq!(
        beside(answering.clone(), &Took::Datagram),
        Err(Held::Another),
        "a datagram whose flows aren't named"
    );
    let second = pasta(4100, Some(10601), Some("127.0.0.1:45590"));
    let both = linux(vec![listener.clone(), answering, second]);
    let each = check(Some(&approved), &both, &flows(&[one, two]));
    assert_eq!(each, Ok(()), "a socket for each flow named");
    let unnamed = check(Some(&approved), &both, &this);
    assert_eq!(unnamed, Err(Held::Another), "a socket for a flow not named");

    let game = socket(9, None, &[(100, 1)]);
    let approved = approve(&mac(vec![game.clone()], false), None).unwrap();
    let connected = Socket {
        peer: Some(one),
        ..socket(8, None, &[(200, 3)])
    };
    let now = mac(vec![game, connected], false);
    let mac = check(Some(&approved), &now, &this);
    assert_eq!(mac, Err(Held::Another), "a Mac's, connected to the flow");
}

/// Ten sockets, each read a way the others aren't, made in cgroup 4 or 5
/// where `cgroups` are read.
fn ten(cgroups: bool) -> Vec<Socket> {
    let rows: [(u64, u64, &[Process], &str, bool); 10] = [
        (1, 4, &[(100, 1)], "127.0.0.1", false),
        (2, 4, &[(101, 2)], "0.0.0.0", false),
        (3, 5, &[(200, 3)], "127.0.0.1", false),
        (4, 4, &[], "127.0.0.1", false),
        (5, 4, &[(100, 1)], "::", true),
        (6, 5, &[(100, 1)], "::", false),
        (7, 4, &[(100, 4)], "192.168.1.5", false),
        (1, 5, &[(200, 3)], "127.0.0.1", false),
        (8, 4, &[(100, 1), (101, 2)], "::1", false),
        (9, 4, &[(100, 1)], "127.0.0.2", false),
    ];
    let socket = |&(id, cgroup, holders, at, dual): &(u64, u64, &[Process], &str, bool)| Socket {
        id,
        cgroup: cgroups.then_some(cgroup),
        holders: holders.iter().copied().collect(),
        at: at.parse().unwrap(),
        dual,
        peer: None,
    };
    rows.iter().map(socket).collect()
}

/// Every read of none, one or two of `sockets`, in `boot`.
fn every(sockets: &[Socket], boot: Option<u64>, lasting: bool) -> Vec<Read> {
    let mut each = vec![vec![]];
    each.extend(sockets.iter().map(|s| vec![s.clone()]));
    for one in sockets {
        each.extend(sockets.iter().map(|other| vec![one.clone(), other.clone()]));
    }
    let read = |sockets| Read {
        boot,
        lasting,
        sockets,
        unlisted: false,
    };
    each.into_iter().map(read).collect()
}

/// **A read judged as before decides as before**: on every read of up to
/// two of ten sockets, with their cgroups and lasting ids in a boot (Linux's)
/// or with ids of one read alone and no boot (a Mac's UDP), listed or not,
/// approve decides as [`before`] did for each process chosen, and check
/// decides as it did on each approval it made, held or not, in that boot or
/// another, whatever took the connection. On a read whose ids last with no
/// cgroup read, check decides as it did on what Linux says took a
/// connection, over the approval each makes. Each read is judged again
/// with every socket connected to the carrier's flow: approve, and check on
/// whatever took the connection but a flow, decide as before; a datagram
/// on the carrier's flows decides as a datagram did where no socket is
/// connected, or none carries a cgroup (a Mac's, or lasting ids with none).
/// Plants: the holders kept of a socket with its cgroup; a socket whose id
/// names it in one read not judged by its holders; a socket with no cgroup
/// connected to a flow admitted; a datagram on a flow held where a datagram
/// was carried.
#[test]
fn a_read_judged_as_before_decides_as_before() {
    let chosens = [
        None,
        Some(chosen(100, 1, Some(1), &[(101, 100), (100, 1)])),
        Some(chosen(100, 1, Some(2), &[])),
        Some(chosen(200, 3, Some(3), &[])),
    ];
    // What took a connection, each beside the same as it was stated before.
    let tooks = [
        (Took::Datagram, before::Took::Datagram),
        (Took::Waiting, before::Took::Waiting),
        (Took::Cgroup(4), before::Took::Cgroup(4)),
        (Took::Cgroup(5), before::Took::Cgroup(5)),
        (
            Took::Lineage(vec![(101, 2), (100, 1)]),
            before::Took::Lineage(vec![(101, 2), (100, 1)]),
        ),
        (
            Took::Lineage(vec![(100, 1)]),
            before::Took::Lineage(vec![(100, 1)]),
        ),
        (
            Took::Lineage(vec![(200, 3), (1, 1)]),
            before::Took::Lineage(vec![(200, 3), (1, 1)]),
        ),
        (
            Took::Lineage(vec![(100, 4)]),
            before::Took::Lineage(vec![(100, 4)]),
        ),
        (Took::Lineage(vec![]), before::Took::Lineage(vec![])),
    ];
    let flow: SocketAddr = "127.0.0.1:45588".parse().unwrap();
    let flows = Took::Flow([flow].into());
    let datagram = before::Took::Datagram;
    // `read`, and `read` with every socket connected to the carrier's flow.
    let ways = |read: &Read| {
        let connected = |s: &Socket| Socket {
            peer: Some(flow),
            ..s.clone()
        };
        let sockets = read.sockets.iter().map(connected).collect();
        let joined = Read {
            sockets,
            ..read.clone()
        };
        [read.clone(), joined]
    };
    let shapes = [
        (
            every(&ten(true), Some(7), true),
            vec![Some(7), Some(8)],
            true,
        ),
        (every(&ten(false), None, false), vec![None], false),
    ];
    for (reads, boots, cgroups) in &shapes {
        let mut approvals = vec![None];
        for unlisted in [false, true] {
            for read in reads.iter().flat_map(ways) {
                let read = Read { unlisted, ..read };
                for chosen in &chosens {
                    let was = before::approve(&read, chosen.as_ref());
                    let is = approve(&read, chosen.as_ref());
                    assert_eq!(is, was, "approving {read:?}, {chosen:?} chosen");
                    for held in [false, true] {
                        let approved = was.clone().ok().map(|a| Approved { held, ..a });
                        if approved.is_some() && !approvals.contains(&approved) {
                            approvals.push(approved);
                        }
                    }
                }
            }
        }
        for approved in &approvals {
            let approved = approved.as_ref();
            for (read, boot) in reads.iter().flat_map(|r| boots.iter().map(move |b| (r, b))) {
                let now = Read {
                    boot: *boot,
                    ..read.clone()
                };
                let [alone, joined] = ways(&now);
                for now in [&alone, &joined] {
                    for (took, was) in &tooks {
                        let had = before::check(approved, now, was);
                        let is = check(approved, now, took);
                        assert_eq!(is, had, "{approved:?} checked on {now:?}, {took:?}");
                    }
                }
                let had = before::check(approved, &alone, &datagram);
                let is = check(approved, &alone, &flows);
                assert_eq!(is, had, "{approved:?} on {alone:?}, a flow, none connected");
                if !cgroups {
                    let had = before::check(approved, &joined, &datagram);
                    let is = check(approved, &joined, &flows);
                    assert_eq!(is, had, "{approved:?} on {joined:?}, a flow, no cgroup");
                }
            }
        }
    }
    let no_cgroup = every(&ten(false), Some(7), true);
    let linux = [
        (Took::Datagram, before::Took::Datagram),
        (Took::Waiting, before::Took::Waiting),
        (Took::Cgroup(4), before::Took::Cgroup(4)),
        (flows, before::Took::Datagram),
    ];
    for read in &no_cgroup {
        for chosen in &chosens {
            let was = before::approve(read, chosen.as_ref());
            let is = approve(read, chosen.as_ref());
            assert_eq!(is.as_ref().err(), was.as_ref().err(), "approving {read:?}");
            let (Ok(is), Ok(was)) = (is, was) else {
                continue;
            };
            for now in no_cgroup.iter().flat_map(ways) {
                for (took, then) in &linux {
                    let checked = check(Some(&is), &now, took);
                    let had = before::check(Some(&was), &now, then);
                    assert_eq!(checked, had, "{was:?} checked on {now:?}, {took:?}");
                }
            }
        }
    }
}

/// `approve` and `check` as they stood before a socket whose id lasts was
/// kept with its holders where it carries no cgroup, word for word, over
/// what took a connection as it was stated then (`Took`, four kinds): what
/// [`a_read_judged_as_before_decides_as_before`] holds them to.
mod before {
    use eudoxia_community::binding::{Approved, Chosen, Held, Process, Read, Refused, Socket};
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// What took a connection, as the carrier stated it then.
    #[derive(Debug)]
    pub enum Took {
        Datagram,
        Cgroup(u64),
        Lineage(Vec<Process>),
        Waiting,
    }

    pub fn approve(read: &Read, chosen: Option<&Chosen>) -> Result<Approved, Refused> {
        let Some(first) = read.sockets.first() else {
            return Err(if read.unlisted {
                Refused::NotYours
            } else {
                Refused::Nothing
            });
        };
        let mine = [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ];
        let at = mine
            .into_iter()
            .find(|to| !on(read, *to).is_empty())
            .ok_or(Refused::Elsewhere(first.at))?;
        let on = on(read, at);
        if let Some(chosen) = chosen {
            if chosen.now != Some(chosen.start) {
                return Err(Refused::Stopped);
            }
            let within = |&(pid, _): &Process| descends(pid, chosen.pid, &chosen.parents);
            if !on.iter().all(|s| s.holders.iter().any(within)) {
                return Err(Refused::Another);
            }
        }
        let lasting = on.iter().filter(|_| read.lasting);
        let named = on.iter().filter(|_| !read.lasting);
        Ok(Approved {
            boot: read.boot,
            sockets: lasting.map(|s| s.id).collect(),
            cgroups: on.iter().filter_map(|s| s.cgroup).collect(),
            processes: named.flat_map(|s| s.holders.iter().copied()).collect(),
            at,
            held: false,
        })
    }

    fn on(read: &Read, to: IpAddr) -> Vec<&Socket> {
        let takes = |s: &&Socket| {
            let at = s.at.to_canonical();
            let every = at.is_ipv4() == to.is_ipv4() || s.dual && to.is_ipv4();
            at == to || at.is_unspecified() && every
        };
        read.sockets.iter().filter(takes).collect()
    }

    fn descends(pid: u32, from: u32, parents: &BTreeMap<u32, u32>) -> bool {
        let up = |at: &u32| parents.get(at).copied().filter(|parent| parent != at);
        core::iter::successors(Some(pid), up)
            .take(parents.len() + 1)
            .any(|at| at == from)
    }

    pub fn check(approved: Option<&Approved>, now: &Read, took: &Took) -> Result<(), Held> {
        let approved = approved.ok_or(Held::Unapproved)?;
        if approved.held || approved.boot != now.boot {
            return Err(Held::Another);
        }
        let on = on(now, approved.at);
        let by_id = |s: &Socket| now.lasting && approved.sockets.contains(&s.id);
        let ok = |s: &&Socket| by_id(s) || !s.holders.is_disjoint(&approved.processes);
        let unapproved = on.iter().filter(|s| !ok(s));
        let seen = unapproved.map(|s| now.lasting || !s.holders.is_empty());
        match seen.max() {
            _ if on.is_empty() => Err(Held::Empty),
            Some(true) => Err(Held::Another),
            Some(false) => Err(Held::Unjudged),
            None => match took {
                Took::Datagram | Took::Waiting => Ok(()),
                Took::Cgroup(cgroup) if approved.cgroups.contains(cgroup) => Ok(()),
                Took::Lineage(up) if up.iter().any(|p| approved.processes.contains(p)) => Ok(()),
                Took::Cgroup(_) | Took::Lineage(_) => Err(Held::Another),
            },
        }
    }
}
