//! Laws of which program may receive a lend's traffic: an approval is the
//! sockets read, or why none is; a connection is carried only to what was
//! approved. Each law names the plants it went red on.
use eudoxia_community::binding::{
    Chosen, Held, Process, Read, Refused, Socket, Took, approve, check,
};

/// A socket of `id`, made in `cgroup`, held by `holders`.
fn socket(id: u64, cgroup: Option<u64>, holders: &[Process]) -> Socket {
    let holders = holders.iter().copied().collect();
    Socket {
        id,
        cgroup,
        holders,
    }
}

/// Linux's read: lasting cookies, in boot 7.
fn linux(sockets: Vec<Socket>) -> Read {
    Read {
        boot: Some(7),
        lasting: true,
        sockets,
        unlisted: false,
        shared: false,
    }
}

/// A Mac's read: handles of this read alone, no boot.
fn mac(sockets: Vec<Socket>, unlisted: bool) -> Read {
    Read {
        boot: None,
        lasting: false,
        sockets,
        unlisted,
        shared: false,
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
/// listener held by an approved process and the acceptor holding one; a
/// datagram by the sockets alone. Each other case is held: none approved,
/// another boot, a socket not approved beside the approved one, an accept
/// in another cgroup (the listener that took it closed since), an acceptor
/// holding no listener of the port, and nothing on the port. Plants: the
/// cookie compare skipped (another listener carried); the cgroup check
/// skipped (an accept in another cgroup carried).
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
    assert_eq!(
        ok(&worker, &Took::Holding([77, 78].into())),
        Ok(()),
        "a prefork's worker"
    );
    assert_eq!(
        ok(&listener, &Took::Holding([5].into())),
        Err(Held::Another),
        "an acceptor holding no listener"
    );
    let over = mac(
        vec![socket(9, None, &[(100, 1)]), socket(8, None, &[(200, 3)])],
        false,
    );
    assert_eq!(
        ok(&over, &Took::Holding([9].into())),
        Err(Held::Another),
        "a more specific bind beside"
    );
    assert_eq!(ok(&over, &Took::Datagram), Err(Held::Another));
    let again = mac(vec![socket(9, None, &[(100, 4)])], false);
    assert_eq!(
        ok(&again, &Took::Datagram),
        Err(Held::Another),
        "the same pid started again"
    );
}

/// **A port others may bind beside is declined**: a read that says a
/// socket could bind beside those on the port refuses the approval,
/// whatever else it holds. Plant: the `shared` check skipped (approved).
#[test]
fn a_port_others_may_bind_beside_is_declined() {
    let mut read = linux(vec![socket(10, Some(4), &[(100, 1)])]);
    read.shared = true;
    assert_eq!(approve(&read, None), Err(Refused::Shared));
}
