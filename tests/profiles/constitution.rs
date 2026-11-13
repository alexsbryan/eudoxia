//! Reference constitutional profile, not the svrngs constitution. All policy
//! decisions below are one pure interpretation of an authenticated evidence set.
//! Fixture-specific roots/resolution rules are explicit, never platform defaults.
use super::*;
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Act {
    HandOn {
        power: SourceRef,
        to: Principal,
    },
    Remove {
        power: SourceRef,
        key: Principal,
        through: SourceRef,
    },
    Invite {
        power: SourceRef,
        key: Principal,
        person: Principal,
    },
    Admit {
        invite: Option<SourceRef>,
        key: Principal,
        person: Principal,
        consent: Vec<u8>,
    },
    Link {
        key: Principal,
        consent: Vec<u8>,
    },
    Leave,
    Record {
        app: Application,
        as_app: bool,
        value: i64,
    },
    Correct {
        target: SourceRef,
        app: Application,
        value: i64,
    },
    Place {
        app: Application,
        code: Vec<u8>,
        parent: Option<SourceRef>,
    },
    Accept {
        candidate: SourceRef,
    },
    Run {
        candidate: SourceRef,
    },
    ReadOther {
        app: Application,
    },
    Stop {
        app: Application,
    },
    Resolve {
        power: SourceRef,
        to: Principal,
        branches: BTreeSet<SourceRef>,
        approvals: Vec<(Principal, Vec<u8>)>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Body {
    pub prev: Option<SourceRef>,
    pub display_at: i64,
    pub act: Act,
}
#[derive(Clone)]
struct Entry {
    by: Principal,
    body: Body,
    bytes: Vec<u8>,
}
fn message(body: &[u8]) -> Vec<u8> {
    let mut v = b"reference-constitution/v1\0".to_vec();
    v.extend_from_slice(body);
    v
}
pub fn root() -> SourceRef {
    reference(b"explicit reference roots: office=1; people=1,2,6")
}
pub fn app() -> Application {
    Application::new("movie").unwrap()
}
pub fn consent(by: u8, about: &SourceRef) -> Vec<u8> {
    key(by)
        .sign(&serde_json::to_vec(&("reference-consent/v1", about, person(by))).unwrap())
        .to_bytes()
        .to_vec()
}
fn consent_ok(by: Principal, about: &SourceRef, sig: &[u8]) -> bool {
    signed(
        by,
        &serde_json::to_vec(&("reference-consent/v1", about, by)).unwrap(),
        sig,
    )
}
pub fn resolution_message(
    power: &SourceRef,
    to: Principal,
    branches: &BTreeSet<SourceRef>,
) -> Vec<u8> {
    serde_json::to_vec(&("reference-resolution/v1", power, to, branches)).unwrap()
}
fn signed(by: Principal, body: &[u8], sig: &[u8]) -> bool {
    ed25519_dalek::VerifyingKey::from_bytes(by.bytes())
        .unwrap()
        .verify_strict(
            body,
            &ed25519_dalek::Signature::from_slice(sig)
                .unwrap_or_else(|_| ed25519_dalek::Signature::from_bytes(&[0; 64])),
        )
        .is_ok()
}
fn entry_id(env: &native::Envelope) -> SourceRef {
    let mut bytes = env.issuer.bytes().to_vec();
    bytes.extend(message(&env.body));
    reference(&bytes)
}
pub fn line(
    by: u8,
    prev: Option<SourceRef>,
    display_at: i64,
    act: Act,
) -> (SourceRef, NativeEvidence) {
    let body = serde_json::to_vec(&Body {
        prev,
        display_at,
        act,
    })
    .unwrap();
    let env = native::Envelope {
        issuer: person(by),
        signature: key(by).sign(&message(&body)).to_bytes().to_vec(),
        body,
    };
    (
        entry_id(&env),
        NativeEvidence {
            codec: id("reference-constitution-v1"),
            bytes: serde_json::to_vec(&env).unwrap(),
        },
    )
}
#[derive(Clone, Debug)]
enum Outcome {
    Established,
    Refused,
    Missing(BTreeSet<SourceRef>),
    Frozen(BTreeSet<SourceRef>),
}
impl Outcome {
    fn missing(r: &SourceRef) -> Self {
        Self::Missing([r.clone()].into())
    }
}
struct View {
    entries: BTreeMap<SourceRef, Entry>,
    invalid: BTreeSet<SourceRef>,
    resolution: Option<BTreeSet<Principal>>,
}
impl View {
    fn new(evidence: &[NativeEvidence], resolution: Option<BTreeSet<Principal>>) -> Self {
        let (mut entries, mut invalid) = (BTreeMap::new(), BTreeSet::new());
        for e in evidence {
            if e.codec != id("reference-constitution-v1") {
                continue;
            }
            let Ok(env) = serde_json::from_slice::<native::Envelope>(&e.bytes) else {
                continue;
            };
            let r = entry_id(&env);
            if !signed(env.issuer, &message(&env.body), &env.signature) {
                invalid.insert(r);
                continue;
            }
            if let Ok(body) = serde_json::from_slice::<Body>(&env.body) {
                entries.insert(
                    r,
                    Entry {
                        by: env.issuer,
                        body,
                        bytes: env.body,
                    },
                );
            }
        }
        Self {
            entries,
            invalid,
            resolution,
        }
    }
    fn get(&self, r: &SourceRef) -> Result<&Entry, Outcome> {
        self.entries.get(r).ok_or_else(|| {
            if self.invalid.contains(r) {
                Outcome::Refused
            } else {
                Outcome::missing(r)
            }
        })
    }
    fn ancestor(&self, ancestor: &SourceRef, tip: &SourceRef) -> bool {
        let mut seen = BTreeSet::new();
        let mut tip = Some(tip);
        while let Some(r) = tip {
            if r == ancestor {
                return true;
            }
            if !seen.insert(r) {
                return false;
            }
            tip = self.entries.get(r).and_then(|e| e.body.prev.as_ref());
        }
        false
    }
    fn authority_source(act: &Act) -> Option<&SourceRef> {
        match act {
            Act::HandOn { power, .. } | Act::Remove { power, .. } | Act::Invite { power, .. } => {
                Some(power)
            }
            _ => None,
        }
    }
    fn raw_holder(
        &self,
        r: &SourceRef,
        seen: &mut BTreeSet<SourceRef>,
    ) -> Result<Principal, Outcome> {
        if *r == root() {
            return Ok(person(1));
        }
        if !seen.insert(r.clone()) {
            return Err(Outcome::Refused);
        }
        let e = self.get(r)?;
        match &e.body.act {
            Act::HandOn { power, to } if self.raw_holder(power, seen)? == e.by => Ok(*to),
            Act::Resolve {
                power,
                to,
                branches,
                approvals,
            } => {
                let conflicts = self.conflicts(power);
                let Some(eligible) = &self.resolution else {
                    return Err(Outcome::Frozen(conflicts));
                };
                let msg = resolution_message(power, *to, branches);
                if conflicts.len() < 2
                    || *branches != conflicts
                    || eligible.is_empty()
                    || !eligible.iter().all(|p| {
                        approvals
                            .iter()
                            .any(|(by, sig)| by == p && signed(*p, &msg, sig))
                    })
                {
                    return Err(Outcome::Frozen(conflicts));
                }
                Ok(*to)
            }
            _ => Err(Outcome::Refused),
        }
    }
    fn conflicts(&self, power: &SourceRef) -> BTreeSet<SourceRef> {
        let mut groups: BTreeMap<(Principal, Option<SourceRef>), Vec<SourceRef>> = BTreeMap::new();
        for (r, e) in &self.entries {
            if Self::authority_source(&e.body.act) == Some(power)
                && self.raw_holder(power, &mut BTreeSet::new()).ok() == Some(e.by)
            {
                groups
                    .entry((e.by, e.body.prev.clone()))
                    .or_default()
                    .push(r.clone());
            }
        }
        groups
            .values()
            .filter(|g| g.len() > 1)
            .flatten()
            .cloned()
            .collect()
    }
    fn holder(&self, r: &SourceRef) -> Result<Principal, Outcome> {
        let holder = self.raw_holder(r, &mut BTreeSet::new())?;
        let conflicts = self.conflicts(r);
        if !conflicts.is_empty() {
            return Err(Outcome::Frozen(conflicts));
        }
        if *r != root()
            && let Act::HandOn { power, .. } = &self.get(r)?.body.act
        {
            self.holder(power)?;
        }
        Ok(holder)
    }
    fn controls(&self, r: &SourceRef, e: &Entry, power: &SourceRef) -> Result<(), Outcome> {
        if self.holder(power)? != e.by {
            return Err(Outcome::Refused);
        }
        for (h, next) in &self.entries {
            if let Act::HandOn { power: p, .. } = &next.body.act
                && p == power
                && *h != *r
                && self.raw_holder(power, &mut BTreeSet::new()).ok() == Some(next.by)
                && !next
                    .body
                    .prev
                    .as_ref()
                    .is_some_and(|prev| self.ancestor(r, prev))
            {
                return Err(Outcome::Refused);
            }
        }
        Ok(())
    }
    fn identity(&self, key: Principal) -> Result<Principal, Outcome> {
        if [person(1), person(2), person(6)].contains(&key) {
            return Ok(key);
        }
        for (r, e) in &self.entries {
            match &e.body.act {
                Act::Link { key: k, consent }
                    if *k == key
                        && [person(1), person(2), person(6)].contains(&e.by)
                        && consent_ok(key, &reference(e.by.bytes()), consent) =>
                {
                    return Ok(e.by);
                }
                Act::Admit {
                    invite: Some(invite),
                    key: k,
                    person: p,
                    consent,
                } if *k == key => {
                    let invitation = self.get(invite)?;
                    if let Act::Invite {
                        power,
                        key: ik,
                        person: ip,
                    } = &invitation.body.act
                    {
                        self.controls(invite, invitation, power)?;
                        if *ik == key
                            && *ip == *p
                            && ![person(1), person(2), person(6)].contains(p)
                            && consent_ok(key, invite, consent)
                            && e.by == invitation.by
                        {
                            return Ok(*p);
                        }
                    }
                    return Err(Outcome::Refused);
                }
                _ => (),
            }
            let _ = r;
        }
        Err(Outcome::Refused)
    }
    fn assess(&self, r: &SourceRef) -> Outcome {
        self.check(r).map_or_else(|o| o, |()| Outcome::Established)
    }
    fn check(&self, r: &SourceRef) -> Result<(), Outcome> {
        let e = self.get(r)?;
        if let Some(prev) = &e.body.prev
            && self.get(prev)?.by != e.by
        {
            return Err(Outcome::Refused);
        }
        let actor = match &e.body.act {
            Act::Admit { .. } => e.by,
            _ => self.identity(e.by)?,
        };
        for (cut, c) in &self.entries {
            if let Act::Remove {
                power,
                key,
                through,
            } = &c.body.act
                && *key == e.by
                && cut != r
                && self.controls(cut, c, power).is_ok()
                && !self.ancestor(r, through)
            {
                return Err(Outcome::Refused);
            }
            if matches!(c.body.act, Act::Leave)
                && c.by == actor
                && cut != r
                && !c.body.prev.as_ref().is_some_and(|p| self.ancestor(r, p))
            {
                return Err(Outcome::Refused);
            }
        }
        match &e.body.act {
            Act::HandOn { power, .. } | Act::Invite { power, .. } => self.controls(r, e, power),
            Act::Remove { power, through, .. } => {
                self.controls(r, e, power)?;
                self.get(through)?;
                Ok(())
            }
            Act::Admit { invite, key, .. } => {
                let Some(invite) = invite else {
                    return Err(Outcome::Refused);
                };
                self.get(invite)?;
                self.identity(*key).map(|_| ())
            }
            Act::Link { key, .. } => {
                if self.identity(*key)? == e.by {
                    Ok(())
                } else {
                    Err(Outcome::Refused)
                }
            }
            Act::Leave => {
                let held =
                    self.entries
                        .keys()
                        .chain(core::iter::once(&root()))
                        .any(|p| {
                            self.holder(p).ok() == Some(actor)
                                && !self.entries.values().any(
                                    |e| matches!(&e.body.act,Act::HandOn {power,..} if power==p),
                                )
                        });
                if held { Err(Outcome::Refused) } else { Ok(()) }
            }
            Act::Correct { target, app, .. } => {
                let original = self.get(target)?;
                let owner = self.identity(original.by)?;
                if let Act::Record { app: a, .. } = &original.body.act
                    && owner == actor
                    && app == a
                {
                    return Ok(());
                }
                Err(Outcome::Refused)
            }
            Act::Record { app, as_app, .. } => {
                if *as_app
                    && self.entries.values().any(|entry| {
                        entry.by == actor
                            && matches!(&entry.body.act,Act::ReadOther {app:a} if a==app)
                    })
                {
                    Err(Outcome::Refused)
                } else {
                    Ok(())
                }
            }
            Act::Run { candidate } => {
                let selected = self.get(candidate)?;
                let Act::Place { app, .. } = &selected.body.act else {
                    return Err(Outcome::Refused);
                };
                let accepted = self.entries.values().any(|a| {
                    self.identity(a.by).ok() == Some(actor)
                        && matches!(&a.body.act,Act::Accept {candidate:c} if c==candidate)
                });
                if accepted {
                    return Ok(());
                }
                let initial: BTreeSet<_> = self
                    .entries
                    .iter()
                    .filter(|(_, e)| {
                        self.identity(e.by).is_ok()
                            && matches!(&e.body.act,Act::Place {app:a,parent:None,..} if a==app)
                    })
                    .map(|(r, _)| r.clone())
                    .collect();
                if initial.len() > 1 {
                    Err(Outcome::Frozen(initial))
                } else if initial.contains(candidate) {
                    Ok(())
                } else {
                    Err(Outcome::Refused)
                }
            }
            Act::Accept { candidate } => {
                self.get(candidate)?;
                Ok(())
            }
            Act::Resolve { .. } => self.raw_holder(r, &mut BTreeSet::new()).map(|_| ()),
            _ => Ok(()),
        }
    }
}

pub struct Constitution {
    pub target: SourceRef,
    pub resolution: Option<BTreeSet<Principal>>,
}
pub enum PrivateHistory {
    Known,
    Unavailable(SourceRef),
}
pub struct History {
    pub entries: Vec<NativeEvidence>,
    pub private: PrivateHistory,
}
impl History {
    pub fn known(entries: Vec<NativeEvidence>) -> Self {
        Self {
            entries,
            private: PrivateHistory::Known,
        }
    }
}
impl Constitution {
    pub fn new(target: SourceRef) -> Self {
        Self {
            target,
            resolution: None,
        }
    }
    pub fn effect(&self, evidence: &[NativeEvidence]) -> Effect<resource::Read> {
        let view = View::new(evidence, self.resolution.clone());
        let e = view.entries.get(&self.target).unwrap();
        let mut request = request(2, "write");
        request.actor = e.by;
        request.person = view.identity(e.by).unwrap_or(e.by);
        let bytes = if let Act::Run { candidate } = &e.body.act {
            match &view.get(candidate).unwrap().body.act {
                Act::Place { code, .. } => code.clone(),
                _ => vec![],
            }
        } else {
            e.bytes.clone()
        };
        Effect::from_bytes(request, bytes)
    }
}
impl RootInterpreter for Constitution {
    type Evidence = History;
    type Error = Invalid;
    fn establish(&self, history: &Self::Evidence, at: i64) -> Result<Basis, Invalid> {
        let evidence = &history.entries;
        let view = View::new(evidence, self.resolution.clone());
        let outcome = view.assess(&self.target);
        let mut p = policy("constitution");
        p.source = reference(&serde_json::to_vec(&(root(), &self.resolution)).unwrap());
        p.scope.interval = Interval::new(i64::MIN, i64::MAX).unwrap();
        p.scope.operations = [op("write")].into();
        p.requires.insert(self.target.clone());
        if view.entries.contains_key(&self.target) {
            let e = self.effect(evidence);
            p.actor = Some(e.exercise().actor.into());
            p.effect = Some(e.fingerprint());
        }
        let mut facts = vec![Fact {
            source: p.source.clone(),
            state: FactState::Established,
        }];
        match outcome {
            Outcome::Established => facts.push(Fact {
                source: self.target.clone(),
                state: FactState::Established,
            }),
            Outcome::Refused => facts.push(Fact {
                source: self.target.clone(),
                state: FactState::Refused(Reason::SourceRejected),
            }),
            Outcome::Frozen(branches) => facts.push(Fact {
                source: self.target.clone(),
                state: FactState::Frozen(branches),
            }),
            Outcome::Missing(refs) => {
                for r in refs {
                    p.requires.insert(r.clone());
                    facts.push(Fact {
                        source: r,
                        state: FactState::Missing,
                    });
                }
                if !facts.iter().any(|f| f.source == self.target) {
                    facts.push(Fact {
                        source: self.target.clone(),
                        state: FactState::Missing,
                    });
                }
            }
        }
        if let PrivateHistory::Unavailable(source) = &history.private
            && view
                .entries
                .get(&self.target)
                .is_some_and(|e| matches!(e.body.act, Act::Record { as_app: true, .. }))
        {
            p.requires.insert(source.clone());
            facts.push(Fact {
                source: source.clone(),
                state: FactState::Missing,
            });
        }
        Basis::interpreted(
            id("reference-constitution-v1"),
            at,
            vec![p],
            facts,
            vec![],
            Recheck::OnSourceChange,
        )
    }
}
