// SPDX-License-Identifier: AGPL-3.0-or-later
//! What counts in an app's shared database: who may change an owned row,
//! and where a removed device's change sets stop. The carrier keeps each
//! copy of the database, signs and verifies its change sets and applies
//! them; it states here a set's signer, what it read of the set, and the
//! fences it holds, and the record answers through [`Record`]. Each verdict
//! is a pure function of those, so copies holding the same decide alike
//! whenever they sync, in any order of arrival.
//!
//! A change set is one device's, at its own `seq`, counted from 0. A
//! verdict is closed ([`Verdict`]): taken; refused for good, which no later
//! record or fence undoes, so a copy may drop the set; or waits, held until
//! the record or the fences bring what it lacks. Every answer read from the
//! record is one it never takes back as it grows: a key's binding, and a
//! Remove that took a key. Who stands now is never read, since a member cut
//! later would turn a verdict already acted on. The record's own disputed
//! cases, a fork that takes a binding or a cut back, are its own to settle.
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
//! and do nothing else to it. Until a copy's record holds that, the delete
//! waits: no copy can tell a removal on its way from none, and a refusal
//! would part it for good from a copy that already holds the removal.
//!
//! **A removed device's sets: the fence.** A Remove names record lines,
//! not change sets, so it cannot say where a device's sets end, and the
//! record's format stays as it is. The cut lands in each app's database by
//! [`Fence`]s: control sets in that database's own sync, each signed by a
//! computer and naming a removed device and the computer's mark for it, the
//! highest `seq` up to which its copy holds every one of that device's sets.
//!
//! - *Who may fence.* Any computer the record binds. A fence states what a
//!   copy holds, so a device that keeps none says nothing by one. The
//!   remover may be such a device, of a person with no computer, so no
//!   narrower set of fencers is always there; and which Remove took a key
//!   can change as the record grows (a second Remove of it), so a rule
//!   naming the remover would not be cumulative. Whether a fence counts
//!   reads only its signer's binding and the Remove of the device it names,
//!   never whether its signer stands: a fence that stopped counting would
//!   let in sets it had refused for good, which copies no longer hold.
//! - *Two fences that disagree: the lowest counts.* More fences can only
//!   lower a cut, so a set past it stays refused whatever arrives after,
//!   and every copy holding the same fences is at the same cut. Under the
//!   highest, no refusal would ever be final, and any one fencer, careless
//!   or one that took the device's sets after its Remove, could let in what
//!   it wrote past its cut. The lowest costs three things, said plainly:
//!   - the stalest fencer decides: sets the device made before its Remove
//!     that the lowest fencer had not seen are refused on every copy;
//!   - taking is not final while a fence may still arrive: each lower one
//!     makes the copies that applied past it rebuild ([`Cut::undoes`]);
//!   - any member's computer can lower a removed device's cut, as far as
//!     refusing every set the device made. Its fence is signed, so the act
//!     is its signer's, and no fence lets a set in or reaches a device the
//!     record holds no Remove of.
//!
//!   So a carrier fences from the remover's side: the computer that signs
//!   a Remove fences in the same step; for a remover holding no copy, a
//!   computer of the remover's person, once it holds the Remove; any other
//!   computer only where a Remove has stood with no fence counting.
//! - *The verdict for a set* ([`Cut::set`]). A device the record binds to
//!   nobody: waits. One it holds no Remove of: taken. Removed, with no
//!   fence counting: waits, as taking it could need undoing. Cut at a mark:
//!   taken at or below it, refused for good past it.
//! - *Values that stand are kept.* A removed device's taken sets stand as
//!   any set does, and later writes overwrite them as usual. Clearing them
//!   would be someone's write, which no rule can make on every copy at
//!   once; a removed person's owned rows go by the rule above, and any
//!   member may change a shared row.
//!
//! **When a copy rebuilds.** A copy can take a device's sets before it holds
//! the device's Remove, or under a cut a later fence lowers, and a merged
//! value cannot be un-merged. So a copy rebuilds an app's database when it
//! has applied a set of a device past that device's cut ([`Cut::undoes`]),
//! which only a newly counting fence or a newly held Remove can bring. It
//! keeps the fences it holds, takes a full resend from a copy that applied
//! none of that device's sets past the cut, and applies its own device's
//! sets again. Another member's later write to a row the refused set had
//! touched still stands.
use crate::{Facts, Vocabulary};

/// What the rules read of the record: the community interpreter's
/// [`Facts`], or an embedding's one projection of them. Each answer is
/// cumulative: a binding and a Remove, once held, are never taken back.
pub trait Record {
    /// The person's key the record binds `device`'s key to: its person's
    /// first key, which a cut key keeps. None while it binds it to none.
    fn person_of(&self, device: &str) -> Option<&str>;
    /// Whether the record binds `device`'s key as a computer's.
    fn computer(&self, device: &str) -> bool;
    /// Whether the record holds a Remove that took `device`'s key: a cut,
    /// or its person's own.
    fn removed(&self, device: &str) -> bool;
    /// Every key the record binds to the person whose key is `person`.
    fn keys_of(&self, person: &str) -> impl Iterator<Item = &str>;
}

impl<C: Vocabulary> Record for Facts<C> {
    fn person_of(&self, device: &str) -> Option<&str> {
        self.bound().get(device).map(|m| m.first.as_str())
    }
    fn computer(&self, device: &str) -> bool {
        (self.bound().get(device)).is_some_and(|m| C::computer(&m.device))
    }
    fn removed(&self, device: &str) -> bool {
        self.out().contains_key(device)
    }
    fn keys_of(&self, person: &str) -> impl Iterator<Item = &str> {
        let of = move |(_, m): &(_, &crate::SourceMember<_, _, _>)| m.first == person;
        self.bound().iter().filter(of).map(|(key, _)| key.as_str())
    }
}

/// What a copy does with a change set, or with one row or fence of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Applied.
    Taken,
    /// Never applied, on any copy, whatever reaches it later.
    Refused(Why),
    /// Held until the record or the fences bring what it lacks.
    Waits(Lacks),
}

impl Verdict {
    /// The verdict of a set judged by both: a refusal before a wait, a wait
    /// before taken, the first of two alike. A set is taken only if its cut
    /// and every owned row it changes take it.
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
    /// It is a removed device's, past the device's cut.
    PastCut,
    /// A fence signed by a device that keeps no copy.
    NoCopy,
}

impl core::fmt::Display for Why {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NotTheirs => "only its own person’s devices change this row",
            Self::PastCut => "written past where its device was removed",
            Self::NoCopy => "only a computer, which keeps a copy, can say where a cut lands",
        })
    }
}
impl core::error::Error for Why {}

/// What a held set waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lacks {
    /// The record's binding of its signer.
    Device,
    /// A fence of its device, which the record holds a Remove of.
    Fence,
    /// A removal the record does not hold yet: of the row's person, for a
    /// delete of their row; of the fenced device, for a fence.
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

/// A fence: the computer `by`'s word, as a control set in one app
/// database's own sync, that its copy holds every set of `device` up to
/// `mark` (none: it holds none of them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fence<'a> {
    pub by: &'a str,
    pub device: &'a str,
    pub mark: Option<u64>,
}

/// Whether `fence` counts: signed by a computer the record binds, for a
/// device it holds a Remove of. A carrier counts a fence in its signer's
/// mark like any set, and judges it here, never by its signer's own cut.
pub fn fence(record: &impl Record, fence: &Fence<'_>) -> Verdict {
    if record.person_of(fence.by).is_none() {
        Verdict::Waits(Lacks::Device)
    } else if !record.computer(fence.by) {
        Verdict::Refused(Why::NoCopy)
    } else if !record.removed(fence.device) {
        Verdict::Waits(Lacks::Removal)
    } else {
        Verdict::Taken
    }
}

/// Where a device's change sets stop counting in one app's database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cut {
    /// The record binds the device to nobody.
    Unknown,
    /// The record holds no Remove of it.
    Stands,
    /// The record holds its Remove, and no fence of it counts.
    Unfenced,
    /// At the lowest mark of the fences of it that count.
    At(Option<u64>),
}

impl Cut {
    /// `device`'s cut, given the record and the fences this database holds.
    pub fn of<'a, 'b: 'a>(
        record: &impl Record,
        device: &str,
        fences: impl IntoIterator<Item = &'a Fence<'b>>,
    ) -> Self {
        if record.person_of(device).is_none() {
            return Self::Unknown;
        }
        if !record.removed(device) {
            return Self::Stands;
        }
        let counts = |f: &&Fence| f.device == device && fence(record, f) == Verdict::Taken;
        let lowest = fences.into_iter().filter(counts).map(|f| f.mark).min();
        lowest.map_or(Self::Unfenced, Self::At)
    }

    /// The verdict for the device's set `seq`.
    pub fn set(self, seq: u64) -> Verdict {
        match self {
            Self::Unknown => Verdict::Waits(Lacks::Device),
            Self::Stands => Verdict::Taken,
            Self::Unfenced => Verdict::Waits(Lacks::Fence),
            Self::At(mark) if Some(seq) <= mark => Verdict::Taken,
            Self::At(_) => Verdict::Refused(Why::PastCut),
        }
    }

    /// Whether a copy whose highest applied set of the device is `applied`
    /// (none: it applied none) must rebuild the app's database: it applied
    /// a set this cut refuses.
    pub fn undoes(self, applied: Option<u64>) -> bool {
        matches!(self, Self::At(mark) if applied > mark)
    }
}
