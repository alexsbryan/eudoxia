// SPDX-License-Identifier: AGPL-3.0-or-later
//! What counts in an app's shared database: whose sets count, and who may
//! change an owned row. The carrier keeps each copy of the database, signs
//! and verifies its change sets and merges them; it states here a set's
//! signer and what it read of the set, and the record answers through
//! [`Record`]. Each verdict is a pure function of those, so copies holding
//! the same decide alike whenever they sync, in any order of arrival.
//!
//! A verdict is closed ([`Verdict`]): taken; refused for good, which no
//! later record undoes, so a copy may drop the set; or waits, held and never
//! applied until the record brings what it lacks. Every answer read from
//! the record is one it never takes back as it grows: a key's binding; a
//! Remove that took a key; and, once it holds the Remove of every key of a
//! person, that person's keys. Who stands now is never read, since a member
//! cut later would turn a verdict already acted on. The record's own
//! disputed cases, a fork that takes a binding or a cut back, are its own
//! to settle.
//!
//! **No rule undoes a set a copy took.** A taken verdict is final, so a
//! copy's state is the join of every set it has taken, whatever order they
//! came in. A carrier may prune a set once every value it wrote is
//! overwritten: the sets that overwrote it already dominate it, and no rule
//! ever takes them out of the join. A rule that refused a set some copy had
//! taken would make copies undo it, and an undo is unsound once a copy
//! prunes: a write overwritten and then pruned, whose replacement a later
//! cut of its device undoes, is gone from every copy alike.
//!
//! **A device's sets** ([`set`]). A set counts once the record binds its
//! signer, and waits while it binds it to nobody. A removed device's sets
//! are taken like any device's, so its Remove stops only what it writes from
//! then on: the carrier stops the device reaching the group at its
//! transport. The cost, said plainly: a removed device's sets still count if
//! they reach any copy, in the window before its removal arrives or from a
//! member who relays them on purpose, and their values stand until someone
//! writes over them.
//!
//! **Owned rows.** A table whose primary key's first column is `person_key`
//! is owned, row by row. A change to such a row counts only from a device
//! the record binds to that row's person: the value is compared by its
//! type and bytes, so only TEXT spelling exactly the person's key is
//! theirs. Each change row is judged by [`row`]: a key-moving update
//! carries a row under each key, so moving a row to another person is
//! refused whoever signs.
//!
//! **A removed person's rows.** Once the record holds the Remove of every
//! key it binds to a row's person, any member's device may delete that row,
//! and do nothing else to it, so the group can clear a removed person's
//! rows. Until a copy's record holds that, the delete waits, held and never
//! applied: no copy can tell a removal on its way from none, and a refusal
//! would part it for good from a copy that already holds the removal.
use crate::{Facts, Vocabulary};

/// What the rules read of the record: the community interpreter's
/// [`Facts`], or an embedding's one projection of them. Each answer is
/// cumulative: a binding and a Remove, once held, are never taken back.
pub trait Record {
    /// The person's key the record binds `device`'s key to: its person's
    /// first key, which a cut key keeps. None while it binds it to none.
    fn person_of(&self, device: &str) -> Option<&str>;
    /// Whether the record holds a Remove that took `device`'s key: a cut,
    /// or its person's own.
    fn removed(&self, device: &str) -> bool;
    /// Every key the record binds to the person whose key is `person`. Once
    /// the record holds the Remove of every key this gives, it gives no other.
    fn keys_of(&self, person: &str) -> impl Iterator<Item = &str>;
}

impl<C: Vocabulary> Record for Facts<C> {
    fn person_of(&self, device: &str) -> Option<&str> {
        self.bound().get(device).map(|m| m.first.as_str())
    }
    fn removed(&self, device: &str) -> bool {
        self.out().contains_key(device)
    }
    fn keys_of(&self, person: &str) -> impl Iterator<Item = &str> {
        let of = move |(_, m): &(_, &crate::SourceMember<_, _, _>)| m.first == person;
        self.bound().iter().filter(of).map(|(key, _)| key.as_str())
    }
}

/// What a copy does with a change set, or with one row of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Applied, and never undone: no later record turns it.
    Taken,
    /// Never applied, on any copy, whatever reaches it later.
    Refused(Why),
    /// Held, never applied, until the record brings what it lacks.
    Waits(Lacks),
}

impl Verdict {
    /// The verdict of a set judged by both: a refusal before a wait, a wait
    /// before taken, the first of two alike. A set is taken only if its
    /// signer's binding and every owned row it changes take it.
    pub fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::Refused(_), _) | (Self::Waits(_), Self::Taken | Self::Waits(_)) => self,
            _ => other,
        }
    }
}

/// Why a set is refused for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// It changes an owned row that is not its signer's person's.
    NotTheirs,
}

impl core::fmt::Display for Why {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NotTheirs => "only its own person’s devices change this row",
        })
    }
}
impl core::error::Error for Why {}

/// What a held set waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lacks {
    /// The record's binding of its signer.
    Device,
    /// The Remove of every key of the row's person, for a delete of their
    /// row by another person's device.
    Removal,
}

/// SQLite's storage classes: the type a value has in a change set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    Null,
    Integer,
    Real,
    Text,
    Blob,
}

/// The first value of a changed row's primary key, as its change carries
/// it: its type and its bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key<'a> {
    pub kind: Type,
    pub bytes: &'a [u8],
}

/// What one change does to its row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// Makes it, sets a column of it, or makes it again after a delete.
    Write,
    /// Deletes it.
    Delete,
}

/// Whether a set `signer` signed counts: taken once the record binds its
/// signer, whether or not it holds a Remove of it; until then it waits. A
/// set's verdict joins this with [`row`]'s for each owned row it changes.
pub fn set(record: &impl Record, signer: &str) -> Verdict {
    if record.person_of(signer).is_some() {
        Verdict::Taken
    } else {
        Verdict::Waits(Lacks::Device)
    }
}

/// Whether `signer`'s set may make `change` to the owned row whose key's
/// first value is `key`. A value that is not TEXT, or not UTF-8, is nobody's
/// key, so it is refused whoever signs.
pub fn row(record: &impl Record, signer: &str, key: Key<'_>, change: Change) -> Verdict {
    let owner = (key.kind == Type::Text).then(|| core::str::from_utf8(key.bytes).ok());
    let Some(Some(owner)) = owner else {
        return Verdict::Refused(Why::NotTheirs);
    };
    let Some(person) = record.person_of(signer) else {
        return Verdict::Waits(Lacks::Device);
    };
    match change {
        _ if owner == person => Verdict::Taken,
        Change::Write => Verdict::Refused(Why::NotTheirs),
        Change::Delete if gone(record, owner) => Verdict::Taken,
        Change::Delete => Verdict::Waits(Lacks::Removal),
    }
}

/// Whether the record holds the Remove of every key it binds to `person`,
/// and binds one.
fn gone(record: &impl Record, person: &str) -> bool {
    let mut keys = record.keys_of(person).peekable();
    keys.peek().is_some() && keys.all(|k| record.removed(k))
}
