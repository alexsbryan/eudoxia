// SPDX-License-Identifier: AGPL-3.0-or-later
//! What an app may write in a group's record as its person: only its own
//! part, never as a reader. An app's class is no fact a rule reads: it is
//! part of the app's identity (`eudoxia::ApplicationAuthority`), and the
//! kernel refuses a reading app's write before any owner is asked. The
//! record part written is the app's own by construction, so a correction
//! counts only where the entry it voids was of that part too.
//!
//! The carrier states what it read of the request, whichever way the write
//! came: through an app's own route on this computer, or in a lent app's
//! answer. The rules decide each required owner, the person and the group,
//! into one Basis; a refusal is the first rule in [`Check`]'s order that
//! forbade. No rule here reads time, so a write is decided at the epoch.
use crate::rule::{Check as _, Facts, all, decide, flag, holds, not, put, text};
use alloc::vec::Vec;
use eudoxia::{
    Actor, Application, ApplicationAuthority, AuthorityId, AuthorityRealm, AuthorityUse, Condition,
    Id, Ingress, NativeOperation, Operation, Principal, Purpose, Resource, ResourceIdentity, Rule,
    Subject, Verdict,
};

/// An app's class: whether it writes the record, or reads what others lend.
pub use eudoxia::ApplicationClass as Class;

/// What a write asks, as the carrier read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Act<'a> {
    /// An entry in the app's part, or a body that is none, so whose it is
    /// cannot be told.
    Record,
    /// A correction, and the part of the entry it voids, when held.
    Correct { target: Option<&'a str> },
}

/// The way a write came, and what the carrier read of it there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Through {
    /// The app's own route on a computer carrying it: written only by that
    /// computer, `here`, its body within the size a write may be.
    Route { here: bool, sized: bool },
    /// A lent app's answer, naming the group it writes in (`read`, with the
    /// app's kind), where the lender and the person `both` stand, which the
    /// lend reaches (`lent`), in a part no folder of the group claims
    /// (`theirs`).
    Answer {
        read: bool,
        both: bool,
        lent: bool,
        theirs: bool,
    },
}

/// One write of an app's act as its person.
#[derive(Debug, Clone, Copy)]
pub struct Write<'a> {
    /// The computer that would sign it.
    pub node: &'a [u8; 32],
    pub group: &'a str,
    /// The person's key.
    pub person: &'a str,
    /// The app's kind: its part of the record is `<app>/…`.
    pub app: &'a str,
    pub class: Class,
    /// The act, when its body reads as one.
    pub act: Option<Act<'a>>,
    pub through: Through,
}

/// Why an app's act is not written as its person.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unwritten {
    /// The app reads others' lends, so it writes nothing in the record.
    Reads,
    /// Written from a device other than the computer carrying the app.
    Elsewhere,
    TooLarge,
    /// A lent app's answer named an act that cannot be read.
    Unread,
    NotBoth,
    NotLent,
    /// Its act is not one, or voids an entry outside the app's own part.
    NotAnAct,
    OtherPart,
}

impl core::fmt::Display for Unwritten {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Reads => {
                "An app that reads your friends’ apps can’t write in the group’s record."
            }
            Self::Elsewhere => "it is written only from the computer carrying it",
            Self::TooLarge => "too large",
            Self::Unread | Self::NotAnAct => "answered with an entry that cannot be read",
            Self::NotBoth => "wrote in a group you and its lender are not both in",
            Self::NotLent => "wrote in a group it is not lent to",
            Self::OtherPart => "writes only its own part of the group’s record",
        })
    }
}
impl core::error::Error for Unwritten {}

macro_rules! checks {
    ($($check:ident),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Check { $($check),+ }
        impl crate::rule::Check for Check {
            const PROFILE: &'static str = "community-app";
            const ALL: &'static [Self] = &[$(Check::$check),+];
            fn rule(self) -> Rule {
                self.rule()
            }
        }
    };
}
checks!(
    Elsewhere, TooLarge, Unread, NotBoth, NotLent, Theirs, Unshaped, OtherPart, Writes
);

impl Check {
    fn rule(self) -> Rule {
        use Check::*;
        let route = || holds("route");
        let answer = |fact| all([not(route()), not(holds(fact))]);
        let (verdict, condition) = match self {
            Elsewhere => (Verdict::Forbid, all([route(), not(holds("here"))])),
            TooLarge => (Verdict::Forbid, all([route(), not(holds("sized"))])),
            Unread => (Verdict::Forbid, answer("read")),
            NotBoth => (Verdict::Forbid, answer("both")),
            NotLent => (Verdict::Forbid, answer("lent")),
            Theirs => (Verdict::Forbid, answer("theirs")),
            Unshaped => (Verdict::Forbid, not(holds("shaped"))),
            OtherPart => (Verdict::Forbid, not(holds("own"))),
            Writes => (Verdict::Permit, Condition::All(Vec::new())),
        };
        let writes = [
            NativeOperation::AppendRecord,
            NativeOperation::CorrectRecord,
        ];
        Rule {
            id: self.id(),
            verdict,
            operations: writes.into_iter().map(Operation::native).collect(),
            condition,
        }
    }
}

/// Whether `write` counts as its person's; `apply` runs only if it does.
pub fn write<T>(write: &Write, apply: impl FnOnce() -> T) -> Result<T, Unwritten> {
    let mut facts = Facts::new();
    match write.through {
        Through::Route { here, sized } => {
            flag(&mut facts, "route", true);
            flag(&mut facts, "here", here);
            flag(&mut facts, "sized", sized);
        }
        Through::Answer {
            read,
            both,
            lent,
            theirs,
        } => {
            flag(&mut facts, "route", false);
            flag(&mut facts, "read", read);
            flag(&mut facts, "both", both);
            flag(&mut facts, "lent", lent);
            flag(&mut facts, "theirs", theirs);
        }
    }
    flag(&mut facts, "shaped", write.act.is_some());
    let target = match write.act {
        Some(Act::Correct { target }) => Some(target),
        _ => None,
    };
    flag(
        &mut facts,
        "own",
        target.is_none_or(|t| t == Some(write.app)),
    );
    put(&mut facts, "app", text(write.app));
    let refused = |check| match check {
        Some(Check::Elsewhere) => Unwritten::Elsewhere,
        Some(Check::TooLarge) => Unwritten::TooLarge,
        Some(Check::Unread) => Unwritten::Unread,
        Some(Check::NotBoth) => Unwritten::NotBoth,
        Some(Check::NotLent) => Unwritten::NotLent,
        Some(Check::Unshaped) if write.through.answer() => Unwritten::Unread,
        Some(Check::Unshaped) => Unwritten::NotAnAct,
        _ => Unwritten::OtherPart,
    };
    let operation = match target {
        Some(_) => NativeOperation::CorrectRecord,
        None => NativeOperation::AppendRecord,
    };
    let who = (write.group, write.person);
    let (ingress, resource) = request(write.node, who, write.app, write.class, operation);
    let asked = eudoxia::Asked {
        at: 0,
        operation: Operation::native(operation),
        resource,
        facts,
    };
    // A native request's owners are its context's: the person and the group.
    let owners: &[&str] = if ingress.is_some() { &[] } else { &["writer"] };
    let decided = decide(ingress, asked, owners, Purpose::Live, apply);
    decided.map_err(|r| match r {
        // The kernel refuses a reading app's write before any owner rules.
        crate::rule::Refused::Invalid if write.class == Class::Connector => Unwritten::Reads,
        r => refused(r.rule()),
    })
}

impl Through {
    fn answer(self) -> bool {
        matches!(self, Self::Answer { .. })
    }
}

/// Whether an app of `class` may write its own part of `group`'s record as
/// `person` at all, before anything of the write is read: the kernel's
/// check of the app's identity, which no owner's rule can change.
pub fn writes(
    node: &[u8; 32],
    (group, person): (&str, &str),
    app: &str,
    class: Class,
) -> Result<(), Unwritten> {
    let operation = NativeOperation::AppendRecord;
    let (ingress, _) = request(node, (group, person), app, class, operation);
    let effect =
        ingress.map(|i| i.effect::<()>(Id::new("community-app").expect("fixed"), Vec::new()));
    match effect {
        Some(Err(_)) if class == Class::Connector => Err(Unwritten::Reads),
        _ => Ok(()),
    }
}

/// A write as the kernel's request: the person's in the group, by the app
/// of its kind and class there, to the app's own part, by the computer
/// that would sign it. No ingress when a key or the kind does not read as
/// one: the rules then decide without a Basis, so the write never counts.
fn request(
    node: &[u8; 32],
    (group, person): (&str, &str),
    app: &str,
    class: Class,
    operation: NativeOperation,
) -> (Option<Ingress>, Resource) {
    let unread = || Resource::new("community-app").expect("fixed");
    let Some(node) = Principal::new(*node).ok() else {
        return (None, unread());
    };
    let named = Id::new("community-app/group").expect("fixed");
    let group = AuthorityId::session(node, &named, group.as_bytes());
    let realm = AuthorityRealm::Group(*group.bytes());
    let Ok(kind) = Id::new(app) else {
        return (None, unread());
    };
    let app = ApplicationAuthority::new(realm, kind, class);
    let resource = ResourceIdentity::record_part(*group.bytes(), &app);
    let mut key = [0; 32];
    let person = hex(person, &mut key).and_then(|()| Principal::new(key).ok());
    let ingress = person.map(|person| {
        let subject = Subject::Person { group, person };
        let authority = AuthorityUse::Application(Application::classified(app));
        let actor = Actor::Key { key: node };
        Ingress::new(actor, subject, authority, operation, resource.clone())
    });
    (ingress, Resource::identified(resource))
}

/// `text`, 64 lowercase hex, into `out`.
fn hex(text: &str, out: &mut [u8; 32]) -> Option<()> {
    let digit = |b: u8| (b as char).to_digit(16).filter(|_| !b.is_ascii_uppercase());
    (text.len() == 64).then_some(())?;
    for (i, pair) in text.as_bytes().chunks(2).enumerate() {
        out[i] = (digit(pair[0])? * 16 + digit(pair[1])?) as u8;
    }
    Some(())
}
