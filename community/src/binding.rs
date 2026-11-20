// SPDX-License-Identifier: AGPL-3.0-or-later
//! Which program may receive a lend's traffic: the lender's two decisions,
//! over what the carrier read of the lend's port. No I/O, no clock and no
//! system's types, only ids in sets. The carrier reads the port, states
//! what it read here, and acts on what these decide.
//!
//! - [`approve`]: the sockets on the port, each with the processes holding
//!   it, and the process the person chose, if any: what is approved, or
//!   why nothing is.
//! - [`check`]: what was approved, the sockets on the port now, and what
//!   took this connection: carry it, or why it is held.
//!
//! A socket is approved by its id where the system gives it one that no
//! later socket gets while it runs (Linux's cookie), else by the processes
//! holding it, each named by its id and start, which no later process
//! shares (a Mac's).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// A process: its id and its start, which no later process shares.
pub type Process = (u32, u64);

/// One socket on a lend's port, as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socket {
    /// Linux's cookie; a Mac's handle, which names it in this read alone.
    pub id: u64,
    /// The cgroup it was made in, where one is read (Linux).
    pub cgroup: Option<u64>,
    /// The processes holding it, where they were read.
    pub holders: BTreeSet<Process>,
}

/// A lend's port as read once: the sockets on it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Read {
    /// The boot the ids belong to, where they last for one (Linux): the
    /// first 64 bits of its id.
    pub boot: Option<u64>,
    /// Whether a socket's id is never another's while the system runs.
    pub lasting: bool,
    pub sockets: Vec<Socket>,
    /// Something answers on the port that the read can't list: another
    /// account's program, on a Mac.
    pub unlisted: bool,
    /// Another socket could bind beside those on the port and take its
    /// datagrams, as a bind beside them, closed at once, showed (Linux UDP).
    pub shared: bool,
}

/// What a person approved for a lend: the sockets, or the processes
/// holding them, and the cgroups they were made in. Kept as its fields,
/// each set only where it holds any; a field it doesn't know is refused.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approved {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot: Option<u64>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub sockets: BTreeSet<u64>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub cgroups: BTreeSet<u64>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub processes: BTreeSet<Process>,
}

/// The process a person chose on the port, and what runs now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chosen {
    pub pid: u32,
    /// Its start when it was shown to the person.
    pub start: u64,
    /// The start of the process with that id now; none when none runs.
    pub now: Option<u64>,
    /// Each process's parent, read with the sockets.
    pub parents: BTreeMap<u32, u32>,
}

/// Why nothing is approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// Nothing answers on the port.
    Nothing,
    /// What answers isn't a program of the account the carrier runs as,
    /// and only that account's can be read here.
    NotYours,
    /// The process chosen stopped: another has its id, or none does.
    Stopped,
    /// A socket on the port isn't held by the process chosen or a child.
    Another,
    /// What answers lets other programs bind beside it on the port.
    Shared,
}

/// What took the connection the carrier made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Took {
    /// A datagram, which the sockets read alone may receive.
    Datagram,
    /// The cgroup its server end carries (Linux).
    Cgroup(u64),
    /// The sockets the process holding its server end holds, by their ids
    /// in this read (a Mac).
    Holding(BTreeSet<u64>),
}

/// Why a connection is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Held {
    /// Nothing is approved for the lend.
    Unapproved,
    /// Something not approved is on the port, or took the connection.
    Another,
    /// Nothing is on the port now.
    Empty,
}

/// What `read` approves, with `chosen` when the person chose a process:
/// every socket on the port, each held by it or a child of it.
pub fn approve(read: &Read, chosen: Option<&Chosen>) -> Result<Approved, Refused> {
    if read.sockets.is_empty() {
        return Err(if read.unlisted {
            Refused::NotYours
        } else {
            Refused::Nothing
        });
    }
    if read.shared {
        return Err(Refused::Shared);
    }
    if let Some(chosen) = chosen {
        if chosen.now != Some(chosen.start) {
            return Err(Refused::Stopped);
        }
        let within = |&(pid, _): &Process| descends(pid, chosen.pid, &chosen.parents);
        if !read.sockets.iter().all(|s| s.holders.iter().any(within)) {
            return Err(Refused::Another);
        }
    }
    let lasting = read.sockets.iter().filter(|_| read.lasting);
    let named = read.sockets.iter().filter(|_| !read.lasting);
    Ok(Approved {
        boot: read.boot,
        sockets: lasting.map(|s| s.id).collect(),
        cgroups: read.sockets.iter().filter_map(|s| s.cgroup).collect(),
        processes: named.flat_map(|s| s.holders.iter().copied()).collect(),
    })
}

/// Whether `pid` is `from` or descends from it, by `parents`, each step a
/// parent that isn't itself, as many as there are parents.
fn descends(pid: u32, from: u32, parents: &BTreeMap<u32, u32>) -> bool {
    let up = |at: &u32| parents.get(at).copied().filter(|parent| parent != at);
    core::iter::successors(Some(pid), up)
        .take(parents.len() + 1)
        .any(|at| at == from)
}

/// Whether a connection `took` may be carried, by what is `approved` and
/// what is on the port `now`: the same boot; at least one socket, every
/// one approved, by its id or a process holding it; and what took it the
/// approved cgroup, or a process holding a socket on the port.
pub fn check(approved: Option<&Approved>, now: &Read, took: &Took) -> Result<(), Held> {
    let approved = approved.ok_or(Held::Unapproved)?;
    if approved.boot != now.boot {
        return Err(Held::Another);
    }
    if now.sockets.is_empty() {
        return Err(Held::Empty);
    }
    let by_id = |s: &Socket| now.lasting && approved.sockets.contains(&s.id);
    let ok = |s: &Socket| by_id(s) || !s.holders.is_disjoint(&approved.processes);
    if !now.sockets.iter().all(ok) {
        return Err(Held::Another);
    }
    match took {
        Took::Datagram => Ok(()),
        Took::Cgroup(cgroup) if approved.cgroups.contains(cgroup) => Ok(()),
        Took::Holding(held) if now.sockets.iter().any(|s| held.contains(&s.id)) => Ok(()),
        Took::Cgroup(_) | Took::Holding(_) => Err(Held::Another),
    }
}
