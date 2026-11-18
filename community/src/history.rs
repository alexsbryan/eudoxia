//! One interpreter of group history, from what lines already carry: each
//! author's `prev` chain, the office holder's chain, and full-ID references.
//! Two strata: each act is lawful in its own causal past (binding, invitation,
//! redemption, correction chain); then the whole held set resolves the office
//! along its holder's chain, the cuts and exits that chain empowers, and
//! membership. Results are facts and reasons, never execution permits. The
//! carrier verifies its own signatures and states the results here; a signed
//! time is read only against a signed bound (an invite's `until`, a visit's
//! `until`). A visit is judged along its host computer's own chain (`guest`).
use crate::schema::{
    AuthorityChange, AuthorityRef, OfficeDispute, PeopleSnapshot, RecoveryChoice, SourceMember,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
    string::String,
    vec,
    vec::Vec,
};
use core::cell::{OnceCell, RefCell};
use core::fmt::Debug;
use serde::Serialize;

#[path = "guest.rs"]
mod guest;
pub use guest::{GUESTS_DEFAULT, GUESTS_MOST, VISIT_LONGEST};

/// The carrier's own types. Interpretation never inspects them beyond order,
/// equality and whether a device is a computer.
pub trait Vocabulary: Clone + Debug {
    type Id: Ord + Clone + Debug;
    type Person: Clone + Eq + Debug;
    type Device: Copy + Eq + Debug;
    fn computer(device: &Self::Device) -> bool;
}
type Id<C> = <C as Vocabulary>::Id;
type Ref<C> = AuthorityRef<Id<C>>;
type Member<C> = SourceMember<Id<C>, <C as Vocabulary>::Person, <C as Vocabulary>::Device>;
type Snapshot<C> = PeopleSnapshot<Id<C>, <C as Vocabulary>::Person>;
type Change<C> = AuthorityChange<Id<C>, <C as Vocabulary>::Person>;
type Judged<C, T> = Result<T, SourceFailure<Id<C>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceFault {
    Root,
    Signature,
    /// A line version this build does not read.
    Version,
    Use,
    Binding,
    Rebound,
    BareAdmit,
    Invitation,
    Consent,
    Expired,
    Office,
    Computer,
    Snapshot,
    Stale,
    Cycle,
    Recovery,
    Correction,
    Closure,
    /// A visit past a bound: too long, or its guest's key bound or used.
    Guest,
    /// A visit with none of its host's slots free.
    Full,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceFailure<I: Ord> {
    Refused {
        why: SourceFault,
    },
    Missing {
        sources: BTreeSet<AuthorityRef<I>>,
    },
    Frozen {
        source: AuthorityRef<I>,
        branches: BTreeSet<I>,
    },
    MissingApprovals {
        proposal: I,
        people: BTreeSet<String>,
    },
}
fn refused<I: Ord, T>(why: SourceFault) -> Result<T, SourceFailure<I>> {
    Err(SourceFailure::Refused { why })
}
fn missing<I: Ord, T>(source: AuthorityRef<I>) -> Result<T, SourceFailure<I>> {
    Err(SourceFailure::Missing {
        sources: [source].into(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceOffice<I: Ord> {
    Held {
        source: AuthorityRef<I>,
        key: String,
    },
    Frozen {
        source: AuthorityRef<I>,
        conflict: OfficeConflict<I>,
    },
    Missing {
        sources: BTreeSet<AuthorityRef<I>>,
    },
    Vacant {
        source: AuthorityRef<I>,
        exits: BTreeSet<I>,
    },
    /// Handed on, with neither the recipient's Accept nor the holder's
    /// withdrawal held. Nobody holds it; it is not vacant.
    Pending {
        source: AuthorityRef<I>,
        hand_on: I,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OfficeConflict<I: Ord> {
    Claims {
        branches: BTreeSet<I>,
        holder: String,
    },
    Dependency {
        statement: I,
        cause: SourceFailure<I>,
    },
    Recoveries {
        commits: BTreeSet<I>,
        holder: String,
    },
}

/// What an original statement says, in this profile's terms. Signature
/// results (`sound`, `consent`) are the carrier's own checks.
#[derive(Debug, Clone)]
pub enum Act<C: Vocabulary> {
    Invite {
        until: i64,
        device_of: Option<String>,
    },
    Admit {
        person: C::Person,
        key: String,
        /// The admitted key is a well-formed, usable public key.
        sound: bool,
        redemption: Option<Redemption<C>>,
    },
    /// To another key: a hand-on. To the holder's own key: its withdrawal.
    HandOn {
        key: String,
    },
    /// The hand-on recipient's consent, on its own chain.
    Accept {
        hand_on: C::Id,
    },
    Remove {
        key: String,
        through: Vec<C::Id>,
    },
    Meets,
    /// The keeper's setting: how many guests each computer may have at once.
    Slots {
        per_computer: u8,
    },
    /// A visit, on its host computer's chain: the guest's fresh key, until
    /// when, the keeper's setting it is judged under (none: the default), and
    /// whether the guest's key consented to this host (the carrier's check).
    Fill {
        key: String,
        until: i64,
        under: Option<C::Id>,
        consent: bool,
    },
    Correct {
        corrects: C::Id,
        replacement: Option<String>,
    },
    /// An app's statement in its part.
    Data {
        part: String,
    },
    Change(Change<C>),
    /// Not interpreted here; what it names still orders history.
    Other {
        through: Vec<C::Id>,
    },
}
#[derive(Debug, Clone)]
pub struct Redemption<C: Vocabulary> {
    pub invite: C::Id,
    pub device: C::Device,
    /// The admitted key consented to this invitation, person and device.
    pub consent: bool,
}
impl<C: Vocabulary> Act<C> {
    fn part(&self) -> Option<&String> {
        match self {
            Self::Data { part } => Some(part),
            Self::Correct { replacement, .. } => replacement.as_ref(),
            _ => None,
        }
    }
}

/// One verified original line.
#[derive(Debug, Clone)]
pub struct Statement<C: Vocabulary> {
    pub author: String,
    /// The key whose standing the line counts under: its author's, or for
    /// a line under a grant, the grant's person's (its scope is the pass's).
    pub stands_as: String,
    pub prev: Option<C::Id>,
    /// The line's own signed time; read only against a signed bound.
    pub at: i64,
    /// This build reads the line's version.
    pub readable: bool,
    /// Signed on another person's behalf.
    pub delegated: bool,
    pub act: Act<C>,
}
/// Verified originals by id, and ids whose every copy failed verification.
#[derive(Debug, Clone)]
pub struct Evidence<C: Vocabulary> {
    pub held: BTreeMap<C::Id, Statement<C>>,
    pub forged: BTreeSet<C::Id>,
}

/// Explicit trusted initial arrangement, normally verified from native genesis.
/// A request never supplies this value to an owner.
#[derive(Debug, Clone)]
pub struct Roots<C: Vocabulary> {
    members: BTreeMap<String, Member<C>>,
    office: String,
}
impl<C: Vocabulary> Roots<C> {
    pub fn genesis(members: BTreeMap<String, Member<C>>, office: String) -> Judged<C, Self> {
        match members.get(&office) {
            None => refused(SourceFault::Root),
            Some(holder) if !C::computer(&holder.device) => refused(SourceFault::Computer),
            Some(_) => Ok(Self { members, office }),
        }
    }
    pub fn members(&self) -> &BTreeMap<String, Member<C>> {
        &self.members
    }
    pub fn office(&self) -> &str {
        &self.office
    }
    pub fn snapshot(&self) -> Snapshot<C> {
        PeopleSnapshot {
            through: BTreeSet::new(),
            people: people::<C>(&self.members),
        }
    }
}
fn people<C: Vocabulary>(members: &BTreeMap<String, Member<C>>) -> BTreeMap<String, C::Person> {
    members
        .values()
        .map(|m| (m.first.clone(), m.person.clone()))
        .collect()
}

/// An office position: who holds it, from where on their chain, and what
/// supports its power.
#[derive(Clone)]
struct OfficeNode<C: Vocabulary> {
    source: Ref<C>,
    key: String,
    person: String,
    /// The holder's office acts count only after this line (its Accept or
    /// recovery commit); `None` for the genesis holder.
    after: Option<Id<C>>,
    support: BTreeSet<Id<C>>,
    cuts: Vec<SourceCut<C>>,
    /// The newest guest setting the office walk counted, to here.
    setting: Option<Id<C>>,
}
#[derive(Clone)]
struct SourceCut<C: Vocabulary> {
    by: Id<C>,
    key: String,
    through: Vec<Id<C>>,
    support: BTreeSet<Id<C>>,
}
/// One Remove of a key of the signer's own person.
struct SourceExit<C: Vocabulary> {
    by: Id<C>,
    person: String,
    actor: String,
    key: String,
    through: Vec<Id<C>>,
}
struct DataCoverage<C: Vocabulary> {
    known: BTreeSet<Id<C>>,
    missing: BTreeSet<Ref<C>>,
}
struct RecoveryPlan<'a, C: Vocabulary> {
    choice: &'a RecoveryChoice<Id<C>, C::Person>,
    eligible: BTreeSet<String>,
}
struct OfficeResult<C: Vocabulary> {
    state: SourceOffice<Id<C>>,
    cuts: Vec<SourceCut<C>>,
    selected: BTreeSet<Id<C>>,
    support: BTreeSet<Id<C>>,
    nodes: BTreeMap<Ref<C>, OfficeNode<C>>,
    setting: Option<Id<C>>,
}
/// What one lawful office act does at its position.
enum Step<C: Vocabulary> {
    Meets,
    Cut(SourceCut<C>),
    Exit,
    HandOn(String),
}
/// Where the walk from one office position ends.
enum Reached<C: Vocabulary> {
    Next(OfficeNode<C>),
    Settled(SourceOffice<Id<C>>),
    Claims(BTreeSet<Id<C>>),
    Vacated(BTreeSet<Id<C>>),
    Pending(Id<C>),
}

/// The interpreter over roots and evidence, or over a recovery's closed frame
/// of that evidence.
pub struct Community<'a, C: Vocabulary> {
    roots: &'a Roots<C>,
    evidence: &'a Evidence<C>,
    within: Option<BTreeSet<Id<C>>>,
    memo: Memo<C>,
}
/// What one interpreter has resolved over its fixed held set, so a fold of
/// every statement resolves the office, the exits, each key's binding and
/// support, and each chain's coverage once (P8). Each is a pure function of
/// the roots and the held set; only top-level calls (no cycle marks) keep.
struct Memo<C: Vocabulary> {
    office: OnceCell<OfficeResult<C>>,
    exits: OnceCell<Vec<SourceExit<C>>>,
    fills: OnceCell<guest::Fills<C>>,
    bound: Kept<String, Judged<C, Member<C>>>,
    support: Kept<String, Judged<C, BTreeSet<Id<C>>>>,
    coverage: Kept<Heads<C>, Rc<DataCoverage<C>>>,
}
type Kept<K, T> = RefCell<BTreeMap<K, T>>;
/// A chain's key and the heads its coverage is read from.
type Heads<C> = (String, Vec<Id<C>>);
impl<C: Vocabulary> Default for Memo<C> {
    fn default() -> Self {
        Self {
            office: OnceCell::new(),
            exits: OnceCell::new(),
            fills: OnceCell::new(),
            bound: RefCell::default(),
            support: RefCell::default(),
            coverage: RefCell::default(),
        }
    }
}
fn kept<K: Ord, T: Clone>(memo: &Kept<K, T>, key: K, f: impl FnOnce() -> T) -> T {
    if let Some(hit) = memo.borrow().get(&key) {
        return hit.clone();
    }
    let found = f();
    memo.borrow_mut().insert(key, found.clone());
    found
}

/// Everything one fold of the held set establishes, made once per journal
/// change: the office, every key ever bound (G1) and those standing, each
/// key out with the Remove that took it and whether that was its own exit,
/// and every held statement's verdict, each as [`Community::assess`] gives.
/// Standing and out can turn as lines arrive (P5); two answers never do,
/// short of the office's own disputes: each key cut by a cut whose reach
/// the record holds whole, and each key bound by a line such a cut retracts.
pub struct Facts<C: Vocabulary> {
    office: SourceOffice<Id<C>>,
    bound: BTreeMap<String, Member<C>>,
    standing: BTreeSet<String>,
    out: BTreeMap<String, (Id<C>, bool)>,
    cuts: BTreeMap<String, Id<C>>,
    retracted: BTreeSet<String>,
    verdicts: BTreeMap<Id<C>, Judged<C, ()>>,
    stops: BTreeMap<Id<C>, Id<C>>,
    setting: Option<(Id<C>, u8)>,
}
impl<C: Vocabulary> Facts<C> {
    pub fn office(&self) -> &SourceOffice<Id<C>> {
        &self.office
    }
    pub fn bound(&self) -> &BTreeMap<String, Member<C>> {
        &self.bound
    }
    pub fn standing(&self) -> &BTreeSet<String> {
        &self.standing
    }
    pub fn out(&self) -> &BTreeMap<String, (Id<C>, bool)> {
        &self.out
    }
    /// Each key the office has cut by a cut whose reach the record holds
    /// whole, with the first such cut: every line of the key the cut names,
    /// back to the key's first. A person's own Remove is not a cut.
    pub fn cuts(&self) -> &BTreeMap<String, Id<C>> {
        &self.cuts
    }
    /// Each key [`Facts::bound`] holds whose binding rests on a line a cut
    /// of [`Facts::cuts`] retracts: its key's, past that cut's reach. The
    /// reach is fixed once held whole, so no later line restores it.
    pub fn retracted(&self) -> &BTreeSet<String> {
        &self.retracted
    }
    pub fn verdicts(&self) -> &BTreeMap<Id<C>, Judged<C, ()>> {
        &self.verdicts
    }
    /// Each visit that counts and was stopped, with its host's Stop.
    pub fn stops(&self) -> &BTreeMap<Id<C>, Id<C>> {
        &self.stops
    }
    /// The keeper's guest setting that stands, which a new visit names; none
    /// while the keeper has set none ([`GUESTS_DEFAULT`]).
    pub fn setting(&self) -> Option<(&Id<C>, u8)> {
        self.setting.as_ref().map(|(id, n)| (id, *n))
    }
}

impl<'a, C: Vocabulary> Community<'a, C> {
    pub fn new(roots: &'a Roots<C>, evidence: &'a Evidence<C>) -> Self {
        Self {
            roots,
            evidence,
            within: None,
            memo: Memo::default(),
        }
    }
    fn resolution(&self) -> &OfficeResult<C> {
        self.memo.office.get_or_init(|| self.resolve_office())
    }
    fn final_exits(&self) -> &[SourceExit<C>] {
        let resolution = self.resolution();
        self.memo
            .exits
            .get_or_init(|| self.exits(&resolution.cuts, &resolution.support))
    }
    fn lookup(&self, id: &Id<C>) -> Option<&'a Statement<C>> {
        let inside = self.within.as_ref().is_none_or(|w| w.contains(id));
        self.evidence.held.get(id).filter(|_| inside)
    }
    fn held(&self) -> impl Iterator<Item = (&'a Id<C>, &'a Statement<C>)> + '_ {
        let evidence: &'a Evidence<C> = self.evidence;
        evidence
            .held
            .iter()
            .filter(|(id, _)| self.within.as_ref().is_none_or(|w| w.contains(*id)))
    }
    fn get(&self, id: &Id<C>) -> Judged<C, &'a Statement<C>> {
        if let Some(op) = self.lookup(id) {
            return Ok(op);
        }
        if self.evidence.forged.contains(id) {
            return refused(SourceFault::Signature);
        }
        missing(AuthorityRef::Act(id.clone()))
    }
    /// G2: an authority act counts only with its author's chain held from
    /// the first line to it.
    fn chained(&self, op: &Statement<C>) -> Judged<C, ()> {
        let mut at = op.prev.clone();
        let mut seen = BTreeSet::new();
        while let Some(id) = at {
            if !seen.insert(id.clone()) {
                return refused(SourceFault::Cycle);
            }
            at = self.get(&id)?.prev.clone();
        }
        Ok(())
    }
    /// Whether `ancestor` is on `op`'s own chain before it.
    fn descends(&self, ancestor: &Id<C>, op: &Statement<C>) -> bool {
        let mut at = op.prev.clone();
        let mut seen = BTreeSet::new();
        while let Some(id) = at.filter(|id| seen.insert(id.clone())) {
            if id == *ancestor {
                return true;
            }
            at = self.lookup(&id).and_then(|p| p.prev.clone());
        }
        false
    }
    fn person(
        &self,
        op: &'a Statement<C>,
        seen: &mut BTreeSet<(String, Ref<C>)>,
    ) -> Judged<C, Member<C>> {
        if op.delegated {
            return refused(SourceFault::Use);
        }
        if !op.readable {
            return refused(SourceFault::Version);
        }
        self.bound(&op.stands_as, seen)
    }
    /// G1: a key's binding is the roots' or its counting Admits', never cited.
    fn bound(&self, key: &str, seen: &mut BTreeSet<(String, Ref<C>)>) -> Judged<C, Member<C>> {
        if !seen.is_empty() {
            return self.binding_of(key, seen);
        }
        kept(&self.memo.bound, key.into(), || self.binding_of(key, seen))
    }
    fn binding_of(&self, key: &str, seen: &mut BTreeSet<(String, Ref<C>)>) -> Judged<C, Member<C>> {
        if let Some(member) = self.roots.members.get(key) {
            return Ok(member.clone());
        }
        let mut first = None;
        for (id, op) in self.held() {
            if !matches!(&op.act, Act::Admit { key: target, .. } if target == key) {
                continue;
            }
            match self.checked_binding(key, &AuthorityRef::Act(id.clone()), seen) {
                Ok(member) => return Ok(member),
                Err(failure) => {
                    first.get_or_insert(failure);
                }
            }
        }
        Err(first.unwrap_or(SourceFailure::Refused {
            why: SourceFault::Binding,
        }))
    }
    fn binding(
        &self,
        key: &str,
        source: &Ref<C>,
        seen: &mut BTreeSet<(String, Ref<C>)>,
    ) -> Judged<C, Member<C>> {
        if *source == AuthorityRef::Genesis {
            return self
                .roots
                .members
                .get(key)
                .cloned()
                .ok_or(SourceFailure::Refused {
                    why: SourceFault::Binding,
                });
        }
        let AuthorityRef::Act(id) = source else {
            return refused(SourceFault::Binding);
        };
        if self.roots.members.contains_key(key) {
            return refused(SourceFault::Rebound);
        }
        let mark = (key.into(), source.clone());
        if !seen.insert(mark.clone()) {
            return refused(SourceFault::Cycle);
        }
        let result = self.admitted_binding(key, id, seen);
        seen.remove(&mark);
        result
    }
    fn admitted_binding(
        &self,
        key: &str,
        id: &Id<C>,
        seen: &mut BTreeSet<(String, Ref<C>)>,
    ) -> Judged<C, Member<C>> {
        let op = self.get(id)?;
        let Act::Admit {
            person,
            key: target,
            sound,
            redemption,
        } = &op.act
        else {
            return refused(SourceFault::Binding);
        };
        if target != key || !sound {
            return refused(SourceFault::Binding);
        }
        self.chained(op)?;
        let issuer = self.person(op, seen)?;
        let Some(redemption) = redemption else {
            return refused(SourceFault::BareAdmit);
        };
        let offered = self.get(&redemption.invite)?;
        let Act::Invite { until, device_of } = &offered.act else {
            return refused(SourceFault::Invitation);
        };
        if offered.author != op.author {
            return refused(SourceFault::Invitation);
        }
        self.invitation(&redemption.invite, seen)?;
        self.open_link(id, op, &redemption.invite)?;
        if op.at >= *until {
            return refused(SourceFault::Expired);
        }
        if !redemption.consent {
            return refused(SourceFault::Consent);
        }
        let (first, person) = match device_of {
            Some(first) if *first == issuer.first => (first.clone(), issuer.person),
            Some(_) => return refused(SourceFault::Binding),
            None => (key.into(), person.clone()),
        };
        Ok(SourceMember {
            first,
            person,
            device: redemption.device,
            source: AuthorityRef::Act(id.clone()),
        })
    }
    fn invitation(&self, id: &Id<C>, seen: &mut BTreeSet<(String, Ref<C>)>) -> Judged<C, ()> {
        let op = self.get(id)?;
        if !matches!(op.act, Act::Invite { .. }) {
            return refused(SourceFault::Invitation);
        }
        self.chained(op)?;
        self.person(op, seen)?;
        Ok(())
    }
    /// The open link at an Admit's position is its issuer's newest Invite
    /// before it on the issuer's chain. Both are the issuer's lines, so only a
    /// fork of that chain makes a redemption concurrent with its close.
    fn open_link(&self, id: &Id<C>, admit: &Statement<C>, invite: &Id<C>) -> Judged<C, ()> {
        if !self.descends(invite, admit) {
            return refused(SourceFault::Invitation);
        }
        for (newer, candidate) in self.held() {
            if newer == invite
                || candidate.author != admit.author
                || !matches!(candidate.act, Act::Invite { .. })
                || !self.descends(invite, candidate)
                || self.invitation(newer, &mut BTreeSet::new()).is_err()
            {
                continue;
            }
            if self.descends(newer, admit) {
                return refused(SourceFault::Invitation);
            }
            if !self.descends(id, candidate) {
                return Err(SourceFailure::Frozen {
                    source: AuthorityRef::Act(invite.clone()),
                    branches: [id.clone(), newer.clone()].into(),
                });
            }
        }
        Ok(())
    }
    /// The binding `source` establishes for `key`, or why it does not.
    pub fn identity(&self, key: &str, source: &Ref<C>) -> Judged<C, Member<C>> {
        self.checked_binding(key, source, &mut BTreeSet::new())
    }
    fn checked_binding(
        &self,
        key: &str,
        source: &Ref<C>,
        seen: &mut BTreeSet<(String, Ref<C>)>,
    ) -> Judged<C, Member<C>> {
        let member = self.binding(key, source, seen)?;
        let AuthorityRef::Act(id) = source else {
            return Ok(member);
        };
        let mut conflicts = BTreeSet::from([id.clone()]);
        for (other_id, op) in self.held() {
            if other_id == id || !matches!(&op.act, Act::Admit { key: target, .. } if target == key)
            {
                continue;
            }
            // A later attempt cannot invalidate the source it acknowledges.
            if self.known_dependency(id, other_id) {
                continue;
            }
            let other_source = AuthorityRef::Act(other_id.clone());
            let Ok(other) = self.binding(key, &other_source, seen) else {
                continue;
            };
            if self.known_dependency(other_id, id) {
                return refused(SourceFault::Rebound);
            }
            if (member.first.as_str(), &member.person, member.device)
                != (other.first.as_str(), &other.person, other.device)
            {
                conflicts.insert(other_id.clone());
            }
        }
        if conflicts.len() > 1 {
            return Err(SourceFailure::Frozen {
                source: source.clone(),
                branches: conflicts,
            });
        }
        Ok(member)
    }
    fn raw_members(&self) -> BTreeMap<String, Member<C>> {
        let mut members = self.roots.members.clone();
        let mut conflicts = BTreeSet::new();
        for (id, op) in self.held() {
            let Act::Admit { key, .. } = &op.act else {
                continue;
            };
            let Ok(member) = self.identity(key, &AuthorityRef::Act(id.clone())) else {
                continue;
            };
            if let Some(old) = members.get(key) {
                if (old.first.as_str(), &old.person, old.device)
                    != (member.first.as_str(), &member.person, member.device)
                {
                    conflicts.insert(key.clone());
                }
            } else {
                members.insert(key.clone(), member);
            }
        }
        members.retain(|key, _| !conflicts.contains(key));
        members
    }
    fn root_office(&self) -> OfficeNode<C> {
        OfficeNode {
            source: AuthorityRef::Genesis,
            key: self.roots.office.clone(),
            person: self.roots.members[&self.roots.office].first.clone(),
            after: None,
            support: BTreeSet::new(),
            cuts: Vec::new(),
            setting: None,
        }
    }
    /// The lines a key's binding rests on: its Admit, that Admit's invite, and
    /// their issuer's own binding, recursively.
    fn key_support(&self, key: &str, seen: &mut BTreeSet<Ref<C>>) -> Judged<C, BTreeSet<Id<C>>> {
        if self.roots.members.contains_key(key) {
            return Ok(BTreeSet::new());
        }
        let support = |seen: &mut BTreeSet<Ref<C>>| {
            let source = self.bound(key, &mut BTreeSet::new())?.source;
            self.identity_support(&source, seen)
        };
        if !seen.is_empty() {
            return support(seen);
        }
        kept(&self.memo.support, key.into(), || support(seen))
    }
    fn identity_support(
        &self,
        source: &Ref<C>,
        seen: &mut BTreeSet<Ref<C>>,
    ) -> Judged<C, BTreeSet<Id<C>>> {
        let AuthorityRef::Act(id) = source else {
            return Ok(BTreeSet::new());
        };
        if !seen.insert(source.clone()) {
            return refused(SourceFault::Cycle);
        }
        let op = self.get(id)?;
        let mut support = BTreeSet::from([id.clone()]);
        support.extend(self.key_support(&op.author, seen)?);
        if let Act::Admit {
            redemption: Some(r),
            ..
        } = &op.act
        {
            support.extend(self.identity_support(&AuthorityRef::Act(r.invite.clone()), seen)?);
        }
        seen.remove(source);
        Ok(support)
    }
    /// Every id a statement names: its previous line, then what its act names.
    /// The order fixes which missing source a closure reports first.
    fn references(op: &Statement<C>) -> Vec<Id<C>> {
        fn act<I: Clone + Ord>(source: &AuthorityRef<I>) -> Option<I> {
            match source {
                AuthorityRef::Act(id) => Some(id.clone()),
                _ => None,
            }
        }
        let mut refs: Vec<_> = op.prev.iter().cloned().collect();
        match &op.act {
            Act::Correct { corrects, .. } => refs.push(corrects.clone()),
            Act::Admit {
                redemption: Some(r),
                ..
            } => refs.push(r.invite.clone()),
            Act::Accept { hand_on } => refs.push(hand_on.clone()),
            Act::Fill { under, .. } => refs.extend(under.iter().cloned()),
            Act::Remove { through, .. } | Act::Other { through } => {
                refs.extend(through.iter().cloned())
            }
            Act::Change(AuthorityChange::RecoveryProposal { choice }) => {
                refs.extend(act(choice.dispute.source()));
                refs.extend(choice.dispute.evidence().into_iter().cloned());
                refs.extend(choice.departed.iter().cloned());
                refs.extend(choice.snapshot.through.iter().cloned());
            }
            Act::Change(AuthorityChange::RecoveryVote { proposal }) => refs.push(proposal.clone()),
            Act::Change(AuthorityChange::RecoveryCommit {
                proposal,
                votes,
                snapshot,
            }) => {
                refs.push(proposal.clone());
                refs.extend(votes.values().cloned());
                refs.extend(snapshot.through.iter().cloned());
            }
            _ => {}
        }
        refs
    }
    fn closure(&self, heads: impl IntoIterator<Item = Id<C>>) -> Judged<C, BTreeSet<Id<C>>> {
        let mut pending: Vec<_> = heads.into_iter().collect();
        let mut closed = BTreeSet::new();
        while let Some(id) = pending.pop() {
            if closed.insert(id.clone()) {
                pending.extend(Self::references(self.get(&id)?));
            }
        }
        Ok(closed)
    }
    fn data_coverage(
        &self,
        key: &str,
        heads: impl IntoIterator<Item = Id<C>>,
    ) -> Rc<DataCoverage<C>> {
        let heads: Vec<_> = heads.into_iter().collect();
        kept(&self.memo.coverage, (key.into(), heads.clone()), || {
            Rc::new(self.covered(key, heads))
        })
    }
    fn covered(&self, key: &str, mut pending: Vec<Id<C>>) -> DataCoverage<C> {
        let mut known = BTreeSet::new();
        let mut missing = BTreeSet::new();
        while let Some(id) = pending.pop() {
            if known.contains(&id) {
                continue;
            }
            match self.get(&id) {
                Ok(op) if op.stands_as == key => {
                    known.insert(id);
                    pending.extend(op.prev.clone());
                }
                Ok(_) => {}
                Err(_) => {
                    missing.insert(AuthorityRef::Act(id));
                }
            }
        }
        DataCoverage { known, missing }
    }
    fn checked(&self, id: &Id<C>) -> Judged<C, BTreeSet<Id<C>>> {
        let op = self.get(id)?;
        let mut checked = BTreeSet::from([id.clone()]);
        checked.extend(self.key_support(&op.stands_as, &mut BTreeSet::new())?);
        Ok(checked)
    }
    /// A cut retracts its key's lines outside its `through` coverage, except a
    /// line that supports the cut's own power: without that exemption a cut
    /// removing its own support has no fixpoint.
    fn allowed_by_cuts(
        &self,
        id: &Id<C>,
        cuts: &[SourceCut<C>],
        power: &BTreeSet<Id<C>>,
    ) -> Judged<C, ()> {
        if power.contains(id) {
            return Ok(());
        }
        let checked = self.checked(id)?;
        for cut in cuts {
            let coverage = self.data_coverage(&cut.key, cut.through.clone());
            for source in &checked {
                let entry = self.get(source)?;
                if entry.stands_as != cut.key
                    || coverage.known.contains(source)
                    || cut.support.contains(source)
                    || power.contains(source)
                {
                    continue;
                }
                if !coverage.missing.is_empty() {
                    return Err(SourceFailure::Missing {
                        sources: coverage.missing.clone(),
                    });
                }
                return refused(SourceFault::Binding);
            }
        }
        Ok(())
    }
    /// An exit retracts its key's lines past its coverage: the Remove's own
    /// ancestry when the key signed it, and the lines `through` names. It
    /// never retracts another exit (`exits`).
    fn allowed_by_exits(
        &self,
        id: &Id<C>,
        exits: &[SourceExit<C>],
        power: &BTreeSet<Id<C>>,
    ) -> Judged<C, ()> {
        if power.contains(id) {
            return Ok(());
        }
        for source in self.checked(id)?.difference(power) {
            let op = self.get(source)?;
            for exit in exits {
                if exit.by == *source || exit.key != op.stands_as {
                    continue;
                }
                let own = (exit.actor == exit.key).then(|| exit.by.clone());
                let heads = exit.through.iter().cloned().chain(own);
                let coverage = self.data_coverage(&op.stands_as, heads);
                if !coverage.known.contains(source) {
                    if !coverage.missing.is_empty() {
                        return Err(SourceFailure::Missing {
                            sources: coverage.missing.clone(),
                        });
                    }
                    return refused(SourceFault::Binding);
                }
            }
        }
        Ok(())
    }
    /// A Remove of a key of the signer's own person: always lawful.
    fn exit(&self, id: &Id<C>) -> Judged<C, SourceExit<C>> {
        let op = self.get(id)?;
        let person = self.person(op, &mut BTreeSet::new())?;
        let Act::Remove { key, through } = &op.act else {
            return refused(SourceFault::Use);
        };
        let members = self.raw_members();
        if members
            .get(key)
            .is_none_or(|member| member.first != person.first)
        {
            return refused(SourceFault::Use);
        }
        Ok(SourceExit {
            by: id.clone(),
            person: person.first,
            actor: op.author.clone(),
            key: key.clone(),
            through: through.clone(),
        })
    }
    /// Every exit no cut retracts. Exits never void each other: each takes its
    /// key out, whatever another Remove of that person says or retracts, so
    /// what they take out only grows with the held set, short of the office's
    /// cut of the key that signed one, or a fork of a binding it rests on.
    fn exits(&self, cuts: &[SourceCut<C>], power: &BTreeSet<Id<C>>) -> Vec<SourceExit<C>> {
        self.held()
            .filter(|(_, op)| matches!(op.act, Act::Remove { .. }))
            .filter_map(|(id, _)| {
                self.exit(id)
                    .ok()
                    .filter(|_| self.allowed_by_cuts(id, cuts, power).is_ok())
            })
            .collect()
    }
    /// Positive causal evidence only. An unheld edge proves no ordering and is
    /// not allowed to poison an existing binding before its own proof succeeds.
    fn known_dependency(&self, ancestor: &Id<C>, head: &Id<C>) -> bool {
        let mut pending = vec![head.clone()];
        let mut seen = BTreeSet::new();
        while let Some(id) = pending.pop() {
            if id == *ancestor {
                return true;
            }
            if seen.insert(id.clone())
                && let Some(op) = self.lookup(&id)
            {
                pending.extend(Self::references(op));
            }
        }
        false
    }
    fn snapshot_frame(&self, snapshot: &Snapshot<C>, op: &Statement<C>) -> Judged<C, Self> {
        let heads = snapshot.through.iter().cloned().chain(Self::references(op));
        Ok(Self {
            roots: self.roots,
            evidence: self.evidence,
            within: Some(self.closure(heads)?),
            memo: Memo::default(),
        })
    }
    /// Whether this line is an office act at all (G5).
    fn office_kind(op: &Statement<C>) -> bool {
        matches!(
            op.act,
            Act::HandOn { .. } | Act::Meets | Act::Slots { .. } | Act::Remove { .. }
        )
    }
    /// What a lawful office act by `holder` does; its refusal otherwise.
    fn step(&self, holder: &str, id: &Id<C>, op: &'a Statement<C>) -> Judged<C, Step<C>> {
        if let Act::Remove { key, .. } = &op.act
            && key == holder
            && self.exit(id).is_ok()
        {
            return Ok(Step::Exit);
        }
        self.chained(op)?;
        if op.author != holder {
            return refused(SourceFault::Office);
        }
        let actor = self.person(op, &mut BTreeSet::new())?;
        if !C::computer(&actor.device) {
            return refused(SourceFault::Computer);
        }
        match &op.act {
            Act::HandOn { key } => {
                let recipient = self.bound(key, &mut BTreeSet::new())?;
                if !C::computer(&recipient.device) {
                    return refused(SourceFault::Computer);
                }
                if *key == op.author {
                    return refused(SourceFault::Office);
                }
                Ok(Step::HandOn(key.clone()))
            }
            Act::Remove { key, through } => {
                let removed = self.bound(key, &mut BTreeSet::new())?;
                if removed.first == actor.first {
                    return refused(SourceFault::Use);
                }
                Ok(Step::Cut(SourceCut {
                    by: id.clone(),
                    key: key.clone(),
                    through: through.clone(),
                    support: BTreeSet::new(),
                }))
            }
            Act::Meets => Ok(Step::Meets),
            Act::Slots { per_computer } if *per_computer <= GUESTS_MOST => Ok(Step::Meets),
            _ => refused(SourceFault::Office),
        }
    }
    /// The holder's office acts after `from`, plus Removes of its key by
    /// another of its person's keys, which no chain orders against them.
    fn office_acts(
        &self,
        node: &OfficeNode<C>,
        from: Option<&Id<C>>,
    ) -> Vec<(&'a Id<C>, &'a Statement<C>)> {
        self.held()
            .filter(|(_, op)| {
                let own = op.author == node.key
                    && Self::office_kind(op)
                    && from.is_none_or(|f| self.descends(f, op));
                let other_exit = op.author != node.key
                    && matches!(&op.act, Act::Remove { key, .. } if *key == node.key);
                own || other_exit
            })
            .collect()
    }
    /// The office along its holder's chain. Office acts on two branches of the
    /// chain freeze it (never a pick); a hand-on passes it with the
    /// recipient's Accept, lapses with the holder's withdrawal, and freezes
    /// with both; a holder's exit vacates it; a unique recovery resumes it.
    fn resolve_office(&self) -> OfficeResult<C> {
        let mut node = self.root_office();
        let mut selected = BTreeSet::new();
        let mut nodes = BTreeMap::new();
        loop {
            if nodes.contains_key(&node.source) {
                let state = SourceOffice::Missing {
                    sources: [node.source.clone()].into(),
                };
                return finish(node, state, selected, nodes);
            }
            nodes.insert(node.source.clone(), node.clone());
            let mut from = node.after.clone();
            let reached = loop {
                let mut lawful = Vec::new();
                let mut needs = BTreeSet::new();
                let mut blocked = None;
                for (id, op) in self.office_acts(&node, from.as_ref()) {
                    match self.step(&node.key, id, op) {
                        Ok(step) => lawful.push((id, op, step)),
                        Err(SourceFailure::Missing { sources }) => needs.extend(sources),
                        Err(cause @ SourceFailure::Frozen { .. }) => {
                            blocked = Some(OfficeConflict::Dependency {
                                statement: id.clone(),
                                cause,
                            });
                        }
                        Err(_) => {}
                    }
                }
                let earliest: BTreeSet<_> = lawful
                    .iter()
                    .filter(|(id, op, _)| {
                        !lawful
                            .iter()
                            .any(|(other, _, _)| other != id && self.descends(other, op))
                    })
                    .map(|(id, _, _)| (*id).clone())
                    .collect();
                if earliest.len() > 1 {
                    break Reached::Claims(earliest);
                }
                let Some((id, op, step)) =
                    lawful.into_iter().find(|(id, ..)| earliest.contains(*id))
                else {
                    let source = node.source.clone();
                    break Reached::Settled(match (blocked, needs.is_empty()) {
                        (Some(conflict), _) => SourceOffice::Frozen { source, conflict },
                        (None, false) => SourceOffice::Missing { sources: needs },
                        (None, true) => SourceOffice::Held {
                            source,
                            key: node.key.clone(),
                        },
                    });
                };
                match step {
                    Step::Meets if matches!(op.act, Act::Slots { .. }) => {
                        node.setting = Some(id.clone())
                    }
                    Step::Meets => {}
                    Step::Cut(mut cut) => {
                        node.support.insert(id.clone());
                        cut.support = node.support.clone();
                        node.cuts.push(cut);
                    }
                    Step::Exit => break Reached::Vacated([id.clone()].into()),
                    Step::HandOn(key) => {
                        let unaccepted = |d: &OfficeDispute<Id<C>>| matches!(d, OfficeDispute::Unaccepted { hand_on, .. } if hand_on == id);
                        let recovered = || self.recoveries(&node, unaccepted).into_keys();
                        match (self.accepted(id, &key, &node), self.withdrawn(id, op)) {
                            // An Accept beside a recovery of its hand-on
                            // never accepted: both held, neither picked (P6).
                            (Some(accept), None) if recovered().next().is_some() => {
                                break Reached::Claims(recovered().chain([accept]).collect());
                            }
                            (Some(accept), None) => {
                                selected.insert(id.clone());
                                let mut support = node.support.clone();
                                support.extend([id.clone(), accept.clone()]);
                                let recipient = self.key_support(&key, &mut BTreeSet::new());
                                support.extend(recipient.unwrap_or_default());
                                let person =
                                    self.bound(&key, &mut BTreeSet::new()).map(|m| m.first);
                                break Reached::Next(OfficeNode {
                                    source: AuthorityRef::Act(id.clone()),
                                    person: person.unwrap_or_else(|_| key.clone()),
                                    key,
                                    after: Some(accept),
                                    support,
                                    cuts: node.cuts.clone(),
                                    setting: node.setting.clone(),
                                });
                            }
                            (None, Some(withdrawal)) => {
                                selected.insert(withdrawal.clone());
                                from = Some(withdrawal);
                                continue;
                            }
                            (Some(accept), Some(withdrawal)) => {
                                break Reached::Claims([accept, withdrawal].into());
                            }
                            (None, None) => break Reached::Pending(id.clone()),
                        }
                    }
                }
                selected.insert(id.clone());
                node.support.insert(id.clone());
                from = Some(id.clone());
            };
            let (claims, vacated, pending) = match reached {
                Reached::Next(child) => {
                    node = child;
                    continue;
                }
                Reached::Settled(state) => return finish(node, state, selected, nodes),
                Reached::Claims(branches) => (Some(branches), None, None),
                Reached::Vacated(exits) => (None, Some(exits), None),
                // The hand-on counts; the office waits on its recipient, or
                // on a recovery when it never comes (`Unaccepted`).
                Reached::Pending(hand_on) => {
                    selected.insert(hand_on.clone());
                    (None, None, Some(hand_on))
                }
            };
            // A recovery resolves only the dispute this position reached.
            let reached = |d: &OfficeDispute<Id<C>>| match d {
                OfficeDispute::Claims { .. } => claims.is_some(),
                OfficeDispute::Vacancy { .. } => vacated.is_some(),
                OfficeDispute::Unaccepted { .. } => pending.is_some(),
            };
            let recovered = self.recoveries(&node, reached);
            if let Some((id, recovered)) = recovered.iter().next().filter(|_| recovered.len() == 1)
            {
                selected.insert(id.clone());
                node = recovered.clone();
                continue;
            }
            let source = node.source.clone();
            let holder = node.key.clone();
            let state = match (claims, vacated, pending) {
                _ if recovered.len() > 1 => SourceOffice::Frozen {
                    source,
                    conflict: OfficeConflict::Recoveries {
                        commits: recovered.into_keys().collect(),
                        holder,
                    },
                },
                (Some(branches), ..) => SourceOffice::Frozen {
                    source,
                    conflict: OfficeConflict::Claims { branches, holder },
                },
                (_, _, Some(hand_on)) => SourceOffice::Pending { source, hand_on },
                (_, exits, _) => SourceOffice::Vacant {
                    source,
                    exits: exits.unwrap_or_default(),
                },
            };
            return finish(node, state, selected, nodes);
        }
    }
    /// The recipient's Accept naming this hand-on, lawful on its own chain.
    fn accepted(&self, hand_on: &Id<C>, key: &str, node: &OfficeNode<C>) -> Option<Id<C>> {
        self.held()
            .find(|(id, op)| {
                op.author == key
                    && matches!(&op.act, Act::Accept { hand_on: named } if named == hand_on)
                    && self.chained(op).is_ok()
                    && self.allowed_by_cuts(id, &node.cuts, &node.support).is_ok()
            })
            .map(|(id, _)| id.clone())
    }
    /// The holder's earliest later HandOn to its own key: the hand-on withdrawn.
    fn withdrawn(&self, hand_on: &Id<C>, op: &Statement<C>) -> Option<Id<C>> {
        let withdrawals: Vec<_> = self
            .held()
            .filter(|(_, line)| {
                line.author == op.author
                    && matches!(&line.act, Act::HandOn { key } if *key == op.author)
                    && self.descends(hand_on, line)
                    && self.chained(line).is_ok()
            })
            .collect();
        withdrawals
            .iter()
            .find(|(_, line)| {
                !withdrawals
                    .iter()
                    .any(|(other, _)| self.descends(other, line))
            })
            .map(|(id, _)| (*id).clone())
    }
    fn recovery_plan(
        &self,
        proposal: &Id<C>,
        base: &OfficeNode<C>,
    ) -> Judged<C, RecoveryPlan<'a, C>> {
        let op = self.get(proposal)?;
        self.chained(op)?;
        let actor = self.person(op, &mut BTreeSet::new())?;
        let Act::Change(AuthorityChange::RecoveryProposal { choice }) = &op.act else {
            return refused(SourceFault::Recovery);
        };
        if op.author != choice.target || !C::computer(&actor.device) {
            return refused(SourceFault::Consent);
        }
        if choice.target == base.key {
            return refused(SourceFault::Recovery);
        }
        let frame = self.snapshot_frame(&choice.snapshot, op)?;
        let office = frame.office();
        if !dispute_matches(&choice.dispute, &office) {
            return refused(SourceFault::Recovery);
        }
        let members = frame.members();
        if people::<C>(&members) != choice.snapshot.people {
            return refused(SourceFault::Snapshot);
        }
        let target = self.bound(&choice.target, &mut BTreeSet::new())?;
        if !C::computer(&target.device) || !members.contains_key(&choice.target) {
            return refused(SourceFault::Computer);
        }
        let mut eligible: BTreeSet<_> = choice
            .snapshot
            .people
            .keys()
            .filter(|key| **key != base.person)
            .cloned()
            .collect();
        let mut departed = BTreeSet::new();
        for exit in &choice.departed {
            let exit_line = self.exit(exit)?;
            self.allowed_by_cuts(exit, &base.cuts, &base.support)?;
            eligible.remove(&exit_line.person);
            departed.insert(exit_line.person);
        }
        if eligible.is_empty() {
            return refused(SourceFault::Recovery);
        }
        self.uncontested(proposal, choice, &departed, base)?;
        Ok(RecoveryPlan { choice, eligible })
    }
    /// A person missing from the snapshot, admitted under an invite at or
    /// before its inviter's snapshot position, contests the recovery. Admits
    /// under later invites came after it and contest nothing.
    fn uncontested(
        &self,
        proposal: &Id<C>,
        choice: &RecoveryChoice<Id<C>, C::Person>,
        departed: &BTreeSet<String>,
        base: &OfficeNode<C>,
    ) -> Judged<C, ()> {
        for (key, member) in self.raw_members() {
            let AuthorityRef::Act(admit) = &member.source else {
                continue;
            };
            if choice.snapshot.people.contains_key(&member.first)
                || departed.contains(&member.first)
                || base.cuts.iter().any(|cut| cut.key == key)
            {
                continue;
            }
            let Some(Act::Admit {
                redemption: Some(r),
                ..
            }) = self.lookup(admit).map(|op| &op.act)
            else {
                continue;
            };
            let Some(invite) = self.lookup(&r.invite) else {
                continue;
            };
            let seen = choice.snapshot.through.iter().any(|position| {
                *position == r.invite
                    || self.lookup(position).is_some_and(|line| {
                        line.author == invite.author && self.descends(&r.invite, line)
                    })
            });
            if seen {
                return Err(SourceFailure::Frozen {
                    source: choice.dispute.source().clone(),
                    branches: [proposal.clone(), admit.clone()].into(),
                });
            }
        }
        Ok(())
    }
    fn recovery_vote(
        &self,
        vote: &Id<C>,
        proposal: &Id<C>,
        plan: &RecoveryPlan<'_, C>,
        base: &OfficeNode<C>,
    ) -> Judged<C, Member<C>> {
        let op = self.get(vote)?;
        if !matches!(&op.act, Act::Change(AuthorityChange::RecoveryVote { proposal: target }) if target == proposal)
        {
            return refused(SourceFault::Recovery);
        }
        self.chained(op)?;
        let actor = self.person(op, &mut BTreeSet::new())?;
        self.allowed_by_cuts(vote, &base.cuts, &base.support)?;
        if !plan.eligible.contains(&actor.first) {
            return refused(SourceFault::Recovery);
        }
        Ok(actor)
    }
    fn recovery_node(&self, id: &Id<C>, base: &OfficeNode<C>) -> Judged<C, OfficeNode<C>> {
        let op = self.get(id)?;
        self.chained(op)?;
        let actor = self.person(op, &mut BTreeSet::new())?;
        let Act::Change(AuthorityChange::RecoveryCommit {
            proposal,
            votes,
            snapshot,
        }) = &op.act
        else {
            return refused(SourceFault::Recovery);
        };
        let plan = self.recovery_plan(proposal, base)?;
        if op.author != plan.choice.target || !C::computer(&actor.device) {
            return refused(SourceFault::Consent);
        }
        let frame = self.snapshot_frame(snapshot, op)?;
        if !dispute_matches(&plan.choice.dispute, &frame.office()) {
            return refused(SourceFault::Stale);
        }
        let members = frame.members();
        if people::<C>(&members) != snapshot.people || !members.contains_key(&op.author) {
            return refused(SourceFault::Snapshot);
        }
        let mut support = base.support.clone();
        support.insert(proposal.clone());
        let mut missing = BTreeSet::new();
        for person in &plan.eligible {
            let Some(vote) = votes.get(person) else {
                missing.insert(person.clone());
                continue;
            };
            let voter = self.recovery_vote(vote, proposal, &plan, base)?;
            if voter.first != *person {
                return refused(SourceFault::Recovery);
            }
            support.insert(vote.clone());
            support.extend(self.key_support(&self.get(vote)?.author, &mut BTreeSet::new())?);
        }
        if !missing.is_empty() {
            return Err(SourceFailure::MissingApprovals {
                proposal: proposal.clone(),
                people: missing,
            });
        }
        if votes.keys().any(|person| !plan.eligible.contains(person)) {
            return refused(SourceFault::Recovery);
        }
        support.extend(plan.choice.departed.iter().cloned());
        support.extend(self.key_support(&op.author, &mut BTreeSet::new())?);
        support.insert(id.clone());
        Ok(OfficeNode {
            source: AuthorityRef::Act(id.clone()),
            key: op.author.clone(),
            person: actor.first,
            after: Some(id.clone()),
            support,
            cuts: base.cuts.clone(),
            setting: base.setting.clone(),
        })
    }
    fn recoveries(
        &self,
        base: &OfficeNode<C>,
        disputes: impl Fn(&OfficeDispute<Id<C>>) -> bool,
    ) -> BTreeMap<Id<C>, OfficeNode<C>> {
        let mut candidates = BTreeMap::new();
        for (id, op) in self.held() {
            let Act::Change(AuthorityChange::RecoveryCommit { proposal, .. }) = &op.act else {
                continue;
            };
            let Ok(proposed) = self.get(proposal) else {
                continue;
            };
            let Act::Change(AuthorityChange::RecoveryProposal { choice }) = &proposed.act else {
                continue;
            };
            if *choice.dispute.source() != base.source || !disputes(&choice.dispute) {
                continue;
            }
            if let Ok(node) = self.recovery_node(id, base) {
                candidates.insert(id.clone(), node);
            }
        }
        candidates
    }
    pub fn office(&self) -> SourceOffice<Id<C>> {
        self.resolution().state.clone()
    }
    pub fn members(&self) -> BTreeMap<String, Member<C>> {
        let mut members = self.raw_members();
        let resolution = self.resolution();
        let exits = self.final_exits();
        members.retain(|_, member| match &member.source {
            AuthorityRef::Act(id) => {
                self.allowed_by_cuts(id, &resolution.cuts, &resolution.support)
                    .is_ok()
                    && self
                        .allowed_by_exits(id, exits, &resolution.support)
                        .is_ok()
            }
            _ => true,
        });
        for cut in &resolution.cuts {
            members.remove(&cut.key);
        }
        for exit in exits {
            members.remove(&exit.key);
        }
        members
    }
    /// One fold of every held statement: [`Facts`].
    pub fn facts(&self) -> Facts<C> {
        let resolution = self.resolution();
        let mut out = BTreeMap::new();
        for cut in &resolution.cuts {
            out.entry(cut.key.clone())
                .or_insert((cut.by.clone(), false));
        }
        for exit in self.final_exits() {
            out.entry(exit.key.clone())
                .or_insert((exit.by.clone(), true));
        }
        let whole: Vec<_> = (resolution.cuts.iter())
            .filter(|cut| self.reached(cut))
            .cloned()
            .collect();
        let mut cuts = BTreeMap::new();
        for cut in &whole {
            cuts.entry(cut.key.clone()).or_insert(cut.by.clone());
        }
        let bound = self.raw_members();
        let retracted = (bound.iter())
            .filter(|(_, member)| self.retracted(member, &whole, &resolution.support))
            .map(|(key, _)| key.clone())
            .collect();
        Facts {
            office: resolution.state.clone(),
            bound,
            standing: self.members().into_keys().collect(),
            out,
            cuts,
            retracted,
            verdicts: self
                .held()
                .map(|(id, _)| (id.clone(), self.assess(id)))
                .collect(),
            stops: self.fills().stops.clone(),
            setting: (resolution.setting.clone())
                .and_then(|id| Some((id.clone(), self.setting(&id).ok()?))),
        }
    }
    /// Whether the record holds `cut`'s reach whole: every line of its key it
    /// names, back to the key's first. Until then it counts for no delete: a
    /// line it lacks may bind the key's person a key the cut leaves standing.
    fn reached(&self, cut: &SourceCut<C>) -> bool {
        let reach = self.data_coverage(&cut.key, cut.through.clone());
        reach.missing.is_empty()
    }
    /// Whether `whole`, cuts whose reach the record holds, retract `member`'s
    /// binding: the rule [`Community::members`] reads cuts by, where it can
    /// only refuse for good. Exits are not read: a later cut can take one back.
    fn retracted(
        &self,
        member: &Member<C>,
        whole: &[SourceCut<C>],
        power: &BTreeSet<Id<C>>,
    ) -> bool {
        let AuthorityRef::Act(admit) = &member.source else {
            return false;
        };
        let past_reach = SourceFailure::Refused {
            why: SourceFault::Binding,
        };
        self.allowed_by_cuts(admit, whole, power) == Err(past_reach)
    }
    /// Whether one held statement is established: lawful in its own past and
    /// standing after the whole held set's office, cuts and exits.
    pub fn assess(&self, id: &Id<C>) -> Judged<C, ()> {
        let op = self.get(id)?;
        let actor = self.person(op, &mut BTreeSet::new())?;
        let resolution = self.resolution();
        self.allowed_by_cuts(id, &resolution.cuts, &resolution.support)?;
        // An exit counts whatever another exit says (`exits`).
        if matches!(op.act, Act::Remove { .. }) && self.exit(id).is_ok() {
            return Ok(());
        }
        self.allowed_by_exits(id, self.final_exits(), &resolution.support)?;
        let base = |dispute: &OfficeDispute<Id<C>>| {
            resolution
                .nodes
                .get(dispute.source())
                .ok_or(SourceFailure::Refused {
                    why: SourceFault::Recovery,
                })
        };
        let proposed = |proposal: &Id<C>| match &self.get(proposal)?.act {
            Act::Change(AuthorityChange::RecoveryProposal { choice }) => Ok(choice),
            _ => refused(SourceFault::Recovery),
        };
        match &op.act {
            Act::Correct {
                corrects,
                replacement,
            } => {
                let target = self.get(corrects)?;
                let author = self.person(target, &mut BTreeSet::new())?;
                if author.first != actor.first {
                    return refused(SourceFault::Correction);
                }
                // A person's word against their own line no app states (a
                // visit's Stop): it counts, and moves no app's part.
                if matches!(target.act, Act::Other { .. } | Act::Fill { .. })
                    && replacement.is_none()
                {
                    return Ok(());
                }
                let mut at = target;
                let mut visited = BTreeSet::new();
                let part = loop {
                    if let Some(part) = at.act.part() {
                        break part;
                    }
                    let Act::Correct { corrects, .. } = &at.act else {
                        return refused(SourceFault::Correction);
                    };
                    if !visited.insert(corrects.clone()) {
                        return refused(SourceFault::Cycle);
                    }
                    at = self.get(corrects)?;
                };
                if replacement.as_ref().is_some_and(|p| p != part) {
                    return refused(SourceFault::Correction);
                }
                Ok(())
            }
            Act::Invite { .. } => self.invitation(id, &mut BTreeSet::new()),
            Act::Admit { key, .. } => self.identity(key, &AuthorityRef::Act(id.clone())).map(drop),
            Act::Accept { .. } => self.chained(op),
            Act::Fill { .. } if !C::computer(&actor.device) => refused(SourceFault::Computer),
            Act::Fill { .. } => {
                self.fills()
                    .verdicts
                    .get(id)
                    .cloned()
                    .unwrap_or(Err(SourceFailure::Refused {
                        why: SourceFault::Cycle,
                    }))
            }
            Act::HandOn { .. } | Act::Meets | Act::Slots { .. } | Act::Remove { .. } => {
                if resolution.selected.contains(id) {
                    return Ok(());
                }
                self.chained(op)?;
                if let Act::HandOn { key } | Act::Remove { key, .. } = &op.act
                    && *key != op.author
                {
                    self.bound(key, &mut BTreeSet::new())?;
                }
                if let Some(failure) = office_failure(&resolution.state) {
                    return Err(failure);
                }
                if resolution.nodes.values().any(|node| node.key == op.author) {
                    return refused(SourceFault::Stale);
                }
                // A non-holder's Remove of another is an ask: it cuts nobody.
                match &op.act {
                    Act::Remove { .. } => Ok(()),
                    _ => refused(SourceFault::Office),
                }
            }
            Act::Change(AuthorityChange::RecoveryProposal { choice }) => {
                self.recovery_plan(id, base(&choice.dispute)?).map(drop)
            }
            Act::Change(AuthorityChange::RecoveryVote { proposal }) => {
                let choice = proposed(proposal)?;
                let base = base(&choice.dispute)?;
                let plan = self.recovery_plan(proposal, base)?;
                self.recovery_vote(id, proposal, &plan, base).map(drop)
            }
            Act::Change(AuthorityChange::RecoveryCommit { proposal, .. }) => {
                let choice = proposed(proposal)?;
                self.recovery_node(id, base(&choice.dispute)?)?;
                if resolution.selected.contains(id) {
                    return Ok(());
                }
                Err(
                    office_failure(&resolution.state).unwrap_or(SourceFailure::Refused {
                        why: SourceFault::Stale,
                    }),
                )
            }
            _ => Ok(()),
        }
    }
}

fn finish<C: Vocabulary>(
    node: OfficeNode<C>,
    state: SourceOffice<Id<C>>,
    selected: BTreeSet<Id<C>>,
    nodes: BTreeMap<Ref<C>, OfficeNode<C>>,
) -> OfficeResult<C> {
    OfficeResult {
        state,
        cuts: node.cuts,
        selected,
        support: node.support,
        nodes,
        setting: node.setting,
    }
}

fn office_failure<I: Ord + Clone>(office: &SourceOffice<I>) -> Option<SourceFailure<I>> {
    match office {
        SourceOffice::Frozen {
            source,
            conflict:
                OfficeConflict::Claims {
                    branches: evidence, ..
                }
                | OfficeConflict::Recoveries {
                    commits: evidence, ..
                },
        } => Some(SourceFailure::Frozen {
            source: source.clone(),
            branches: evidence.clone(),
        }),
        SourceOffice::Frozen {
            conflict: OfficeConflict::Dependency { cause, .. },
            ..
        } => Some(cause.clone()),
        SourceOffice::Missing { sources } => Some(SourceFailure::Missing {
            sources: sources.clone(),
        }),
        _ => None,
    }
}

fn dispute_matches<I: Ord>(dispute: &OfficeDispute<I>, office: &SourceOffice<I>) -> bool {
    match (dispute, office) {
        (
            OfficeDispute::Claims {
                source: expected,
                branches,
            },
            SourceOffice::Frozen {
                source,
                conflict:
                    OfficeConflict::Claims {
                        branches: actual, ..
                    },
            },
        ) => expected == source && branches.len() >= 2 && branches.is_subset(actual),
        (
            OfficeDispute::Vacancy {
                source: expected,
                exits,
            },
            SourceOffice::Vacant {
                source,
                exits: actual,
                ..
            },
        ) => expected == source && !exits.is_empty() && exits.is_subset(actual),
        (
            OfficeDispute::Unaccepted {
                source: expected,
                hand_on: named,
            },
            SourceOffice::Pending { source, hand_on },
        ) => expected == source && named == hand_on,
        _ => false,
    }
}
