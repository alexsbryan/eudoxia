// SPDX-License-Identifier: AGPL-3.0-or-later
//! What a person's pass lets its holder do, decided by rules as data
//! (`eudoxia::Rules`). A pass is a person's signed word that a holder key may act as them for
//! an app until a time: reach the app and the lends it reads, write the app's
//! own part of the record, or have one exact entry approved. A link carries a
//! pass on to another key, never wider.
//!
//! The carrier reads its original pass into [`Pass`], verifying its
//! signatures, and an entry into [`Entry`] with the parts its own labels name;
//! this module decides, through [`eudoxia::Rules`] into a per-request Basis,
//! and commits only through the sealed path. The refusal is the first
//! deciding rule's, in the order the rules are listed.
use crate::rule::{Check as _, Facts, decide, holds, not, put, same, term, text, texts, within};
use alloc::{format, string::String, vec, vec::Vec};
use eudoxia::{
    Actor, Asked, AuthorityId, AuthorityUse, Condition, Ingress, Operation, Principal, Purpose,
    Resource, Rule, Subject, Term, Value, Verdict,
};
use serde::{Deserialize, Serialize};

/// A pass as its carrier read it. `signed` is the carrier's verification of
/// the person's signature, and of the approver's where it names an entry.
#[derive(Debug, Clone)]
pub struct Pass<'a> {
    pub person: &'a str,
    /// The person's key, when `person` spells one.
    pub key: Option<[u8; 32]>,
    pub holder: &'a str,
    pub app: &'a str,
    pub reads: Vec<&'a str>,
    pub until: i64,
    pub approver: Option<&'a str>,
    /// The one entry it approves.
    pub approves: Option<String>,
    pub signed: bool,
    /// The computer whose app it opens; none for an app a group carries.
    pub lender: Option<[u8; 32]>,
}

/// The part of the record an app kind writes, as the carrier labels it.
#[derive(Debug, Clone)]
pub struct Part {
    pub kind: String,
    pub label: String,
}

#[derive(Debug, Clone)]
pub enum Act {
    Write(Part),
    /// The corrected entry's part, when it is held, and its replacement's.
    Correct {
        target: Option<Part>,
        replacement: Option<Part>,
    },
    /// Any other act: a decision.
    Decide,
}

/// A line a holder wrote under a pass.
#[derive(Debug, Clone)]
pub struct Entry<'a> {
    pub actor: &'a str,
    pub written: i64,
    /// Its id without its grant: what an approval names.
    pub content: &'a str,
    pub act: Act,
}

/// Why a pass opens nothing here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassFault {
    NotReach,
    Unsigned,
    NotTheHolder,
    Lapsed,
    NotNamed,
    Wider,
}

/// Why a holder may not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Why {
    Unapproved,
    Unsigned,
    NotTheHolder,
    Lapsed,
    OtherKind,
    Decides,
    /// The act it corrects is not held, so whose part it is cannot be told
    /// yet: it may be real data, and counts once its target arrives.
    Unheld,
}

/// Why an open's signer approves no entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalFault {
    Missing,
    Open,
    Entry,
}

macro_rules! words {
    ($($ty:ty { $($variant:ident => $said:literal),+ $(,)? })+) => {$(
        impl core::fmt::Display for $ty {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(match self { $(Self::$variant => $said),+ })
            }
        }
        impl core::error::Error for $ty {}
    )+};
}
words! {
    PassFault {
        NotReach => "an entry approval is not a reach pass",
        Unsigned => "not signed by the person it names",
        NotTheHolder => "held by another key than the one presenting it",
        Lapsed => "lapsed",
        NotNamed => "it does not name this lend",
        Wider => "its link names more than the pass it carries",
    }
    Why {
        Unapproved => "its person did not approve this exact entry",
        Unsigned => "its pass is not signed by the person it names",
        NotTheHolder => "its pass is another key's",
        Lapsed => "its pass had lapsed",
        OtherKind => "an app writes only its own part of the record",
        Decides => "an app decides nothing for its person",
        Unheld => "what it corrects is not held here yet",
    }
    ApprovalFault {
        Missing => "no write grant",
        Open => "this app has no live authority here",
        Entry => "this entry was not approved",
    }
}

/// What a request asks of a pass: the profile's closed operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Use {
    Reach,
    Record,
    Decide,
    Approve,
    Open,
    Hold,
}
impl Use {
    fn operation(self) -> Operation {
        Operation::new(format!("community-pass/{self:?}")).expect("fixed")
    }
}

/// The rules, in the order their refusals are named.
macro_rules! checks {
    ($($check:ident),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Check { $($check),+ }
        impl crate::rule::Check for Check {
            const PROFILE: &'static str = "community-pass";
            const ALL: &'static [Self] = &[$(Check::$check),+];
            fn rule(self) -> Rule {
                self.rule()
            }
        }
    };
}
checks!(
    LinkApproval,
    LinkUnsigned,
    LinkHolder,
    LinkLapsed,
    LinkNamed,
    NoGrant,
    NotOurs,
    Approval,
    NoApprover,
    Unsigned,
    Unapproved,
    Unheld,
    Replaced,
    Holder,
    Lapsed,
    Stale,
    Decides,
    Named,
    Wider,
    Reaches,
    Writes,
    Opened,
    Held,
);

fn named(lends: &str) -> Condition {
    Condition::In(Term::Resource, term(lends))
}
fn lapsed(time: Term, until: &str) -> Condition {
    not(Condition::Before(time, term(until)))
}
fn linked(c: Condition) -> Condition {
    Condition::All(vec![holds("linked"), c])
}

impl Check {
    fn rule(self) -> Rule {
        use {Check::*, Use::*};
        let forbid = |uses: &'static [Use], c| (Verdict::Forbid, uses, c);
        let (verdict, uses, condition): (_, &[Use], _) = match self {
            LinkApproval => forbid(&[Reach], linked(holds("link/approval"))),
            LinkUnsigned => forbid(&[Reach], linked(not(holds("link/signed")))),
            LinkHolder => forbid(&[Reach], linked(not(same("link/holding", "link/holder")))),
            LinkLapsed => forbid(&[Reach], linked(lapsed(Term::Time, "link/until"))),
            LinkNamed => forbid(&[Reach], linked(not(named("link/lends")))),
            NoGrant => forbid(&[Open], not(holds("granted"))),
            NotOurs => forbid(
                &[Open],
                not(Condition::All(vec![
                    Condition::In(term("asking"), term("reach/approver")),
                    Condition::In(term("asking"), term("approver")),
                    holds("issued"),
                    same("reach/lender", "lender"),
                    Condition::Near(Term::Time, term("written"), 300),
                ])),
            ),
            Approval => forbid(&[Reach, Approve], holds("approval")),
            NoApprover => forbid(&[Approve], not(holds("approvable"))),
            Unsigned => forbid(
                &[Reach, Record, Decide, Approve, Hold],
                not(holds("signed")),
            ),
            Unapproved => forbid(&[Record, Decide], not(within("approves", "content"))),
            Unheld => forbid(&[Record], not(holds("held"))),
            Replaced => forbid(&[Record], not(within("replaced", "target"))),
            Holder => forbid(
                &[Reach, Record, Decide, Approve, Hold],
                not(same("holding", "holder")),
            ),
            Lapsed => forbid(
                &[Reach, Record, Decide, Approve],
                lapsed(Term::Time, "until"),
            ),
            Stale => forbid(&[Approve], lapsed(term("written"), "until")),
            Decides => forbid(&[Approve], not(holds("writes"))),
            Named => forbid(&[Reach], linked(not(named("lends")))),
            Wider => forbid(
                &[Reach],
                linked(not(Condition::All(vec![
                    same("link/app", "app"),
                    within("link/reads", "reads"),
                    not(Condition::Before(term("until"), term("link/until"))),
                ]))),
            ),
            // A pass reaches the lends it names, and writes its app's own part.
            Reaches => (Verdict::Permit, &[Reach], named("lends")),
            Writes => (
                Verdict::Permit,
                &[Record, Approve],
                Condition::Same(Term::Resource, term("app")),
            ),
            Opened => (Verdict::Permit, &[Open], Condition::All(vec![])),
            Held => (Verdict::Permit, &[Hold], Condition::All(vec![])),
        };
        Rule {
            id: self.id(),
            verdict,
            operations: uses.iter().map(|u| u.operation()).collect(),
            condition,
        }
    }
}

fn principal(pass: &Pass) -> Option<Principal> {
    pass.key.and_then(|key| Principal::new(key).ok())
}

/// The facts a pass states, under `prefix`.
fn stated(facts: &mut Facts, pass: &Pass, prefix: &str) {
    let mut fact = |name: &str, value| put(facts, &format!("{prefix}{name}"), value);
    fact("approval", Value::Flag(pass.approves.is_some()));
    fact("approvable", Value::Flag(pass.approver.is_some()));
    fact(
        "signed",
        Value::Flag(pass.signed && principal(pass).is_some()),
    );
    fact("holder", text(pass.holder));
    fact("until", Value::Time(pass.until));
    fact("app", text(pass.app));
    fact("reads", texts(pass.reads.iter().copied()));
    let lends = core::iter::once(pass.app).chain(pass.reads.iter().copied());
    fact("lends", texts(lends));
    fact("approves", texts(pass.approves.as_deref()));
    fact("approver", texts(pass.approver));
    let lender = pass.lender.map(|key| AuthorityId::from_bytes(key).hex());
    fact(
        "lender",
        Value::Text(lender.unwrap_or_else(|| "carried".into())),
    );
}

/// One request of `pass`'s person, presented by `presented`, its `facts`
/// complete, decided by the rules into a Basis and committed through the
/// sealed path. The refusal is the first deciding rule; `None` when none
/// forbade (default deny, or a fact the request lacks).
#[allow(clippy::too_many_arguments)]
fn judged<T>(
    pass: &Pass,
    use_: Use,
    presented: &str,
    resource: &str,
    at: i64,
    facts: Facts,
    purpose: Purpose,
    apply: impl FnOnce() -> T,
) -> Result<T, Option<Check>> {
    let resource = Resource::new(resource).map_err(|_| None)?;
    let operation = use_.operation();
    let asked = Asked {
        at,
        operation: operation.clone(),
        resource: resource.clone(),
        facts,
    };
    // A person named by no key signed nothing: the rules refuse it unsigned.
    let ingress = principal(pass).filter(|_| pass.signed).map(|principal| {
        let profile = eudoxia::Id::new("community-pass-v1").expect("fixed");
        let id = AuthorityId::session(principal, &profile, presented.as_bytes());
        let actor = Actor::Session {
            issuer: principal,
            id,
        };
        let subject = Subject::Principal { principal };
        Ingress::profile(actor, subject, AuthorityUse::Personal, operation, resource)
    });
    decide(ingress, asked, &["pass-issuer"], purpose, apply).map_err(|r| r.rule())
}

/// Whether `pass`, or `link` carrying it, presented by `presented` at `at`
/// opens `lend`; `apply` runs only if it does.
pub fn reach<T>(
    pass: &Pass,
    link: Option<&Pass>,
    presented: &str,
    lend: &str,
    at: i64,
    apply: impl FnOnce() -> T,
) -> Result<T, PassFault> {
    let mut facts = Facts::new();
    stated(&mut facts, pass, "");
    put(&mut facts, "linked", Value::Flag(link.is_some()));
    let holding = link.map_or(presented, |link| link.person);
    put(&mut facts, "holding", text(holding));
    if let Some(link) = link {
        stated(&mut facts, link, "link/");
        put(&mut facts, "link/holding", text(presented));
    }
    let resolved = judged(
        pass,
        Use::Reach,
        presented,
        lend,
        at,
        facts,
        Purpose::Live,
        apply,
    );
    resolved.map_err(|check| match check {
        Some(Check::LinkApproval | Check::Approval) => PassFault::NotReach,
        Some(Check::LinkUnsigned | Check::Unsigned) => PassFault::Unsigned,
        Some(Check::LinkHolder | Check::Holder) => PassFault::NotTheHolder,
        Some(Check::LinkLapsed | Check::Lapsed) => PassFault::Lapsed,
        Some(Check::Wider) => PassFault::Wider,
        _ => PassFault::NotNamed,
    })
}

/// The facts an entry states, and the part its act writes (or corrects).
fn entered(entry: &Entry, pass: &Pass) -> Facts {
    let mut facts = Facts::new();
    stated(&mut facts, pass, "");
    put(&mut facts, "holding", text(entry.actor));
    put(&mut facts, "written", Value::Time(entry.written));
    put(&mut facts, "content", texts([entry.content]));
    let (held, target, replaced) = match &entry.act {
        Act::Correct {
            target,
            replacement,
        } => (target.is_some(), target.as_ref(), replacement.as_ref()),
        _ => (true, None, None),
    };
    put(&mut facts, "held", Value::Flag(held));
    put(&mut facts, "target", texts(target.map(|p| p.kind.as_str())));
    put(
        &mut facts,
        "replaced",
        texts(replaced.map(|p| p.kind.as_str())),
    );
    let writes = !matches!(entry.act, Act::Decide);
    put(&mut facts, "writes", Value::Flag(writes));
    facts
}

/// Whether a holder's `entry` under `pass` counts in its person's place,
/// judged at the time it was written; `apply` runs only if it does.
pub fn entry<T>(pass: &Pass, entry: &Entry, apply: impl FnOnce() -> T) -> Result<T, Why> {
    let (use_, part) = match &entry.act {
        Act::Write(part) => (Use::Record, Some(part)),
        Act::Correct { target, .. } => (Use::Record, target.as_ref()),
        Act::Decide => (Use::Decide, None),
    };
    let resource = part.map_or(pass.app, |p| p.label.as_str());
    let facts = entered(entry, pass);
    let purpose = Purpose::HistoricalAdmission;
    let judged = judged(
        pass,
        use_,
        entry.actor,
        resource,
        entry.written,
        facts,
        purpose,
        apply,
    );
    judged.map_err(|check| match check {
        Some(Check::Unsigned) => Why::Unsigned,
        Some(Check::Unapproved) => Why::Unapproved,
        Some(Check::Unheld) => Why::Unheld,
        Some(Check::Holder) => Why::NotTheHolder,
        Some(Check::Lapsed) => Why::Lapsed,
        _ if use_ == Use::Decide => Why::Decides,
        _ => Why::OtherKind,
    })
}

/// Whether the approver `pass` names may approve `entry` at `at`, its own
/// clock: before the pass lapses, by its holder, writing only its app's part.
pub fn approving(pass: &Pass, entry: &Entry, at: i64) -> bool {
    let part = match &entry.act {
        Act::Write(part) => Some(part),
        Act::Correct { replacement, .. } => replacement.as_ref(),
        Act::Decide => None,
    };
    let resource = part.map_or(pass.app, |p| p.label.as_str());
    let facts = entered(entry, pass);
    judged(
        pass,
        Use::Approve,
        entry.actor,
        resource,
        at,
        facts,
        Purpose::Live,
        || (),
    )
    .is_ok()
}

/// Whether the signer of the open `reach`, whose approver is `asking`,
/// approves `entry` under `grant` (the line's, and whether the open issued
/// it) at `at`: both name `asking`, of one lender's app, the line stamped
/// within five minutes, the open's pass live for the line's holder.
pub fn open(
    asking: &str,
    reach_pass: &Pass,
    grant: Option<(&Pass, bool)>,
    entry: &Entry,
    at: i64,
) -> Result<(), ApprovalFault> {
    let mut facts = Facts::new();
    put(&mut facts, "asking", text(asking));
    put(&mut facts, "written", Value::Time(entry.written));
    put(&mut facts, "granted", Value::Flag(grant.is_some()));
    stated(&mut facts, reach_pass, "reach/");
    if let Some((pass, issued)) = grant {
        stated(&mut facts, pass, "");
        put(&mut facts, "issued", Value::Flag(issued));
    }
    let app = reach_pass.app;
    let open = judged(
        reach_pass,
        Use::Open,
        entry.actor,
        app,
        at,
        facts,
        Purpose::Live,
        || (),
    );
    open.map_err(|check| match check {
        Some(Check::NoGrant) => ApprovalFault::Missing,
        _ => ApprovalFault::Open,
    })?;
    reach(reach_pass, None, entry.actor, app, at, || ()).map_err(|_| ApprovalFault::Open)?;
    let (pass, _) = grant.ok_or(ApprovalFault::Missing)?;
    approving(pass, entry, at)
        .then_some(())
        .ok_or(ApprovalFault::Entry)
}

/// Whether `holder` holds `pass`, signed: a carrier's authentication of a
/// line's source, not a write permission.
pub fn held(pass: &Pass, holder: &str) -> bool {
    let mut facts = Facts::new();
    stated(&mut facts, pass, "");
    put(&mut facts, "holding", text(holder));
    judged(
        pass,
        Use::Hold,
        holder,
        pass.app,
        i64::MIN,
        facts,
        Purpose::Live,
        || (),
    )
    .is_ok()
}
