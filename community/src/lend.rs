// SPDX-License-Identifier: AGPL-3.0-or-later
//! Who may use a lend, decided by rules as data (`eudoxia::Rules`) on the
//! computer that decides, under its own key. Two owners must each permit:
//! the lender says whether a page reaches its lend, what an app other than
//! the lend's own may do with it, and whether a use let in still stands; the
//! person says which apps may use it as them, by their yes or stop. No rule
//! here reads time but the recheck's, so the others are decided at the
//! epoch; the recheck and a key's vouch at the deciding computer's clock.
//!
//! A lend's lender may also list keys it trusts: a pass one of them signed,
//! naming the lend as its app, opens it to the pass's holder as nobody, a
//! read or a declared send, until the pass lapses ([`vouch`]).
//!
//! The person's word is kept beside the lend on the lender's computer, never
//! in the record: the carrier reads it there and states it as a fact of the
//! request, as it states every other. A rule reads only what one request
//! binds, so a refusal is the first rule in [`Check`]'s order that forbade.
use crate::rule::{Check as _, Facts, all, any, decide, flag, holds, not, put, term, text};
use alloc::{format, vec::Vec};
use eudoxia::{
    Actor, Asked as Request, AuthorityId, AuthorityUse, Condition, Ingress, Operation, Principal,
    Purpose, Resource, Rule, Subject, Term, Value, Verdict,
};
use serde::{Deserialize, Serialize};

/// What a person says of an app using a lend as them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Said {
    Yes,
    Stop,
}

/// What a request asks of a lend's service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asked {
    /// A read, which changes nothing.
    Read,
    /// One of the sends the lend's lender named, exactly.
    Send,
    /// Anything else.
    Write,
}

/// The lender's credential that goes with a request let in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    /// The lender's own: the person opening their lend, or its own page.
    Own,
    /// The account the lender keeps for apps that read it.
    Readers,
    /// None: the service answers as it would anyone.
    Bare,
}

/// Why a lend lets a request through for none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The person stopped this app using the lend.
    Stopped,
    /// The lend asks its person, and they said no yes to this app.
    Unasked,
    /// An app other than the lend's own only reads it, and sends only
    /// where its lender said, from a member's computer.
    ReadOnly,
    /// The lend's lender did not say what it lends, so whether a page
    /// reads it cannot be judged.
    Silent,
    NotRead,
    /// The page's person has not said yes to it reaching this lend.
    Unopened,
    /// The page's person has not said it may send to this lend.
    Unsent,
    /// What let the use in has lapsed or no longer stands.
    Lapsed,
    /// No key the lend lists signed the pass.
    Unlisted,
    /// The pass names another app, and this lend only among what that reads.
    Elsewhere,
    /// A link hands the pass on to another key.
    Linked,
    /// A group held here removed the pass's signer or its holder.
    Removed,
    /// The pass ends later than the longest its listed key's entry accepts.
    Outlasts,
    /// A listed key's pass reads the lend and sends where its lender said,
    /// nothing else.
    ReadsAndSends,
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NotRead => "this page does not read that; only what its lender declared it reads",
            Self::Unopened => "Open it from your home page first.",
            Self::Unsent => {
                "This app sends here only once you say so: open it from your home page, and tick where it sends."
            }
            Self::Stopped => "its person stopped this app using it",
            Self::Unasked => "only an app its person said yes to uses it",
            Self::ReadOnly => "an app only reads it",
            Self::Silent => "its lender did not say what it lends",
            Self::Lapsed => "what let it in has lapsed or no longer stands",
            Self::Unlisted => "no key this lend lists signed its pass",
            Self::Elsewhere => "its pass names another app, and this lend only among what that reads",
            Self::Linked => "a pass a listed key signed is not handed on by a link",
            Self::Removed => "a group this computer holds removed its key or its pass's signer",
            Self::Outlasts => "its pass lasts longer than this lend's lender accepts",
            Self::ReadsAndSends => "it is lent by key to read and to send to, nothing else",
        })
    }
}
impl core::error::Error for Refusal {}

/// What a request asks of the lend's owners: the profile's closed operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Use {
    Choose,
    Admit,
    Reach,
    Recheck,
    Vouch,
}

/// Who says each rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum By {
    Lender,
    Person,
}
const OWNERS: [&str; 2] = ["lender", "person"];

macro_rules! checks {
    ($($check:ident),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Check { $($check),+ }
        impl crate::rule::Check for Check {
            const PROFILE: &'static str = "community-lend";
            const ALL: &'static [Self] = &[$(Check::$check),+];
            fn rule(self) -> Rule {
                self.rule()
            }
        }
    };
}
checks!(
    Stopped,
    Unasked,
    ReadOnly,
    Silent,
    NotRead,
    Unopened,
    Unsent,
    Lapsed,
    Unstood,
    Unlisted,
    Elsewhere,
    Linked,
    Removed,
    Outlasts,
    ReadsAndSends,
    Lent,
    Agrees,
);

impl Check {
    fn rule(self) -> Rule {
        use {By::*, Check::*, Use::*};
        const EVERY: &[Use] = &[Choose, Admit, Reach, Recheck, Vouch];
        let (by, verdict, uses, condition): (_, _, &[Use], _) = match self {
            Stopped => (
                Person,
                Verdict::Forbid,
                &[Choose],
                all([
                    holds("asks"),
                    holds("other"),
                    not(holds("yes")),
                    holds("stop"),
                ]),
            ),
            Unasked => (
                Person,
                Verdict::Forbid,
                &[Choose],
                all([
                    holds("asks"),
                    any([
                        not(holds("named")),
                        all([holds("other"), not(holds("yes"))]),
                    ]),
                ]),
            ),
            // An app other than the lend's own reads it; it sends only where
            // the lend's rows say, as an app its group carries, never for a
            // pass's holder.
            ReadOnly => (
                Lender,
                Verdict::Forbid,
                &[Admit],
                all([
                    holds("other"),
                    any([
                        holds("write"),
                        all([holds("send"), any([holds("holder"), not(holds("carried"))])]),
                    ]),
                ]),
            ),
            Silent => (
                Lender,
                Verdict::Forbid,
                &[Reach],
                all([not(holds("reads")), holds("silent")]),
            ),
            NotRead => (Lender, Verdict::Forbid, &[Reach], not(holds("reads"))),
            Unopened => (
                Person,
                Verdict::Forbid,
                &[Reach],
                all([not(holds("own")), not(holds("named"))]),
            ),
            Unsent => (
                Person,
                Verdict::Forbid,
                &[Reach],
                all([holds("send"), holds("carried"), not(holds("sends"))]),
            ),
            Lapsed => (
                Lender,
                Verdict::Forbid,
                &[Recheck, Vouch],
                all([
                    holds("lapses"),
                    not(Condition::Before(Term::Time, term("until"))),
                ]),
            ),
            Unstood => (Lender, Verdict::Forbid, &[Recheck], not(holds("stands"))),
            // A pass a key the lend lists signed: its own app, not handed
            // on, its signer and holder removed by no group held here, no
            // longer than the entry accepts, and a read or a declared send.
            Unlisted => (Lender, Verdict::Forbid, &[Vouch], not(holds("listed"))),
            Elsewhere => (Lender, Verdict::Forbid, &[Vouch], not(holds("its-app"))),
            Linked => (Lender, Verdict::Forbid, &[Vouch], holds("linked")),
            Removed => (
                Lender,
                Verdict::Forbid,
                &[Vouch],
                any([holds("signer-removed"), holds("holder-removed")]),
            ),
            Outlasts => (
                Lender,
                Verdict::Forbid,
                &[Vouch],
                Condition::Before(term("latest"), term("until")),
            ),
            ReadsAndSends => (Lender, Verdict::Forbid, &[Vouch], holds("write")),
            Lent => (Lender, Verdict::Permit, EVERY, Condition::All(Vec::new())),
            Agrees => (Person, Verdict::Permit, EVERY, Condition::All(Vec::new())),
        };
        let owner = Condition::Same(Term::Owner, term(&format!("by/{by:?}")));
        Rule {
            id: self.id(),
            verdict,
            operations: uses.iter().map(|u| u.operation()).collect(),
            condition: all([owner, condition]),
        }
    }
}

impl Use {
    fn operation(self) -> Operation {
        Operation::new(format!("community-lend/{self:?}")).expect("fixed")
    }
}

/// One request of `use_` about `resource`, decided on the computer whose
/// key is `node` at `at`, its time, by every owner's rules.
fn judged<T>(
    node: &[u8; 32],
    use_: Use,
    resource: &str,
    at: i64,
    mut facts: Facts,
    apply: impl FnOnce() -> T,
) -> Result<T, Refusal> {
    put(&mut facts, "by/Lender", text(OWNERS[0]));
    put(&mut facts, "by/Person", text(OWNERS[1]));
    let refused = |check| match check {
        Some(Check::Stopped) => Refusal::Stopped,
        Some(Check::ReadOnly) => Refusal::ReadOnly,
        Some(Check::Silent) => Refusal::Silent,
        Some(Check::NotRead) => Refusal::NotRead,
        Some(Check::Unopened) => Refusal::Unopened,
        Some(Check::Unsent) => Refusal::Unsent,
        Some(Check::Lapsed | Check::Unstood) => Refusal::Lapsed,
        Some(Check::Unlisted) => Refusal::Unlisted,
        Some(Check::Elsewhere) => Refusal::Elsewhere,
        Some(Check::Linked) => Refusal::Linked,
        Some(Check::Removed) => Refusal::Removed,
        Some(Check::Outlasts) => Refusal::Outlasts,
        Some(Check::ReadsAndSends) => Refusal::ReadsAndSends,
        _ if use_ == Use::Recheck => Refusal::Lapsed,
        _ => Refusal::Unasked,
    };
    let resource = Resource::new(resource).map_err(|_| refused(None))?;
    let operation = use_.operation();
    let asked = Request {
        at,
        operation: operation.clone(),
        resource: resource.clone(),
        facts,
    };
    // The deciding computer acts under its own key, for its own resource.
    let ingress = Principal::new(*node).ok().map(|principal| {
        let profile = eudoxia::Id::new("community-lend-v1").expect("fixed");
        let id = AuthorityId::session(principal, &profile, resource.as_str().as_bytes());
        let actor = Actor::Session {
            issuer: principal,
            id,
        };
        let subject = Subject::Principal { principal };
        Ingress::profile(actor, subject, AuthorityUse::Personal, operation, resource)
    });
    decide(ingress, asked, &OWNERS, Purpose::Live, apply).map_err(|r| refused(r.rule()))
}

/// Whether `app` (none: the person's own open) may use the lend `own` as
/// its person, who `said` this of it, where the lend `asks` them: one that
/// asks nobody, or asked by its own pages, lets it; else only on their yes.
pub fn choose(
    node: &[u8; 32],
    asks: bool,
    own: &str,
    app: Option<&str>,
    said: Option<Said>,
) -> Result<(), Refusal> {
    let mut facts = Facts::new();
    flag(&mut facts, "asks", asks);
    flag(&mut facts, "named", app.is_some());
    flag(&mut facts, "other", app.is_some_and(|a| a != own));
    flag(&mut facts, "yes", said == Some(Said::Yes));
    flag(&mut facts, "stop", said == Some(Said::Stop));
    judged(node, Use::Choose, own, 0, facts, || ())
}

/// The credential that goes with a request `asked` of the lend `own` by
/// `app` (none: the person's own open), where the lender keeps an account
/// for readers (`readers`), from a pass's `holder` or not, the app one its
/// group `carried`.
pub fn admit(
    node: &[u8; 32],
    own: &str,
    app: Option<&str>,
    asked: Asked,
    (readers, holder, carried): (bool, bool, bool),
) -> Result<Admit, Refusal> {
    let other = app.is_some_and(|a| a != own);
    let mut facts = Facts::new();
    flag(&mut facts, "other", other);
    flag(&mut facts, "write", asked == Asked::Write);
    flag(&mut facts, "send", asked == Asked::Send);
    flag(&mut facts, "holder", holder);
    flag(&mut facts, "carried", carried);
    judged(node, Use::Admit, own, 0, facts, || match (other, readers) {
        (false, _) => Admit::Own,
        (true, true) => Admit::Readers,
        (true, false) => Admit::Bare,
    })
}

/// Whether a page reaches the lend `label` as its person: `reads`, the lend
/// among what it reads, else refused, `away` where the lend's lender did not
/// say what it lends (`silent`); then its person's yes, naming the lend and
/// naming it to send to (none needed for this computer's own app); and, for
/// a request that sends from an app its group `carried`, the second.
pub fn reach(
    node: &[u8; 32],
    label: &str,
    (reads, silent): (bool, bool),
    yes: Option<(bool, bool)>,
    (send, carried): (bool, bool),
) -> Result<(), Refusal> {
    let (named, sends) = yes.unwrap_or_default();
    let mut facts = Facts::new();
    let stated = [
        ("reads", reads),
        ("silent", silent),
        ("own", yes.is_none()),
        ("named", named),
        ("sends", sends),
        ("send", send),
        ("carried", carried),
    ];
    for (name, value) in stated {
        flag(&mut facts, name, value);
    }
    judged(node, Use::Reach, label, 0, facts, || ())
}

/// Whether a use let in at the lend `label` still is at `now`, the deciding
/// computer's clock (none: unread, so no pass is judged live): what let it in
/// still `stands`, and the pass carrying it, which lapses at `until` if it
/// does, has not.
pub fn recheck(
    node: &[u8; 32],
    label: &str,
    stands: bool,
    until: Option<i64>,
    now: Option<i64>,
) -> bool {
    let mut facts = Facts::new();
    flag(&mut facts, "stands", stands);
    flag(&mut facts, "lapses", until.is_some());
    if let Some(until) = until {
        put(&mut facts, "until", Value::Time(until));
    }
    // The clock is read only where a pass can lapse.
    let at = match (until, now) {
        (_, Some(now)) => now,
        (None, None) => 0,
        (Some(_), None) => return false,
    };
    judged(node, Use::Recheck, label, at, facts, || ()).is_ok()
}

/// What the carrier states of a pass presented for a lend whose signer it
/// looked up among the keys the lend's lender lists: each a fact the pass
/// or the lend's declaration holds, or what this computer's groups say.
/// The pass's own rules (signed by its signer, held by the key presenting
/// it, for this lend, not lapsed) are judged apart, as every pass's are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vouch<'a> {
    /// The pass's signer is a key the lend's declaration lists.
    pub listed: bool,
    /// The app the pass names.
    pub app: &'a str,
    /// A link hands the pass on to another key.
    pub linked: bool,
    /// When the pass lapses.
    pub until: i64,
    /// The longest, in seconds from now, its listed key's entry accepts.
    pub longest: u32,
    /// What the request asks of the lend's service.
    pub asked: Asked,
    /// Whether a group this computer holds removed the pass's signer, and
    /// its holder.
    pub removed: (bool, bool),
}

/// Whether the pass `vouch` states opens the lend `label` to its holder,
/// at `now`, the deciding computer's clock: when that admission lapses,
/// the pass's own end. What it opens carries none of the lender's
/// credential, so there is no [`Admit`] to answer.
pub fn vouch(node: &[u8; 32], label: &str, now: i64, vouch: Vouch<'_>) -> Result<i64, Refusal> {
    let latest = now.saturating_add(i64::from(vouch.longest));
    let mut facts = Facts::new();
    let (signer, holder) = vouch.removed;
    let stated = [
        ("listed", vouch.listed),
        ("its-app", vouch.app == label),
        ("linked", vouch.linked),
        ("signer-removed", signer),
        ("holder-removed", holder),
        ("write", vouch.asked == Asked::Write),
        ("lapses", true),
    ];
    for (name, value) in stated {
        flag(&mut facts, name, value);
    }
    put(&mut facts, "until", Value::Time(vouch.until));
    put(&mut facts, "latest", Value::Time(latest));
    judged(node, Use::Vouch, label, now, facts, || vouch.until)
}
