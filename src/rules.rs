//! Rules as data. A rule permits
//! or forbids operations when a closed condition holds over the terms one
//! request binds: its time, the owner asked, its resource and its named facts.
//! There are no free variables, so a rule costs its condition's size in fact
//! lookups (P8). The rules decide into a per-request [`Basis`]: one exact-scope
//! standing [`Policy`] per required owner, its source the owner's ruling, so
//! the one derivation decides (P3: no second constructor of approvals).
//!
//! Default deny; forbid beats permit; every required owner must permit
//! (`Agreement::all`); a missing fact never decides (it leaves the owner
//! Undetermined). A refused owner's record names its first deciding rule.
use crate::*;
use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Permit,
    Forbid,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: Id,
    pub verdict: Verdict,
    pub operations: BTreeSet<Operation>,
    pub condition: Condition,
}

/// What a condition reads: only what the request binds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Term {
    Time,
    Owner,
    Resource,
    Fact(Id),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Value {
    Flag(bool),
    Time(i64),
    Text(String),
    Texts(BTreeSet<String>),
}

/// Closed: a new kind of test is a kernel change with its law, never a name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Condition {
    /// The flag is set.
    Holds(Term),
    Same(Term, Term),
    /// One time strictly before another.
    Before(Term, Term),
    /// Two times at most this many seconds apart.
    Near(Term, Term, u64),
    /// A text among a set.
    In(Term, Term),
    /// A set inside another.
    Within(Term, Term),
    Not(alloc::boxed::Box<Self>),
    All(Vec<Self>),
    Any(Vec<Self>),
}

/// One request's terms. Its operation and resource must be its effect's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Asked {
    pub at: i64,
    pub operation: Operation,
    pub resource: Resource,
    pub facts: BTreeMap<Id, Value>,
}

/// One owner's ruling, its deciding rules in rule order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum Ruled {
    Permit(Vec<Id>),
    Forbid(Vec<Id>),
    /// No rule permits: default deny.
    Deny,
    /// These rules read a fact the request lacks, and could have decided.
    Missing(Vec<Id>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Ruling {
    pub owner: Owner,
    pub ruled: Ruled,
}

/// Kleene's three values: a missing fact is neither true nor false.
type Known = Option<bool>;

/// An installed profile's rules, ids unique.
#[derive(Clone, Debug)]
pub struct Rules(Vec<Rule>);

impl Rules {
    pub fn new(rules: Vec<Rule>) -> Result<Self, Invalid> {
        let ids: BTreeSet<_> = rules.iter().map(|r| &r.id).collect();
        if ids.len() != rules.len() || rules.iter().any(|r| r.operations.is_empty()) {
            return Err(Invalid::Policy);
        }
        Ok(Self(rules))
    }

    /// The ruling for `owner`, without a basis: inspection only.
    pub fn decide(&self, asked: &Asked, owner: &Owner) -> Ruled {
        let (mut forbid, mut forbid_unknown) = (Vec::new(), Vec::new());
        let (mut permit, mut permit_unknown) = (Vec::new(), Vec::new());
        for rule in self.0.iter() {
            if !rule.operations.contains(&asked.operation) {
                continue;
            }
            let (held, unknown) = match rule.verdict {
                Verdict::Forbid => (&mut forbid, &mut forbid_unknown),
                Verdict::Permit => (&mut permit, &mut permit_unknown),
            };
            match holds(&rule.condition, asked, owner) {
                Some(true) => held.push(rule.id.clone()),
                Some(false) => (),
                None => unknown.push(rule.id.clone()),
            }
        }
        if !forbid.is_empty() {
            Ruled::Forbid(forbid)
        } else if !forbid_unknown.is_empty() {
            Ruled::Missing(forbid_unknown)
        } else if !permit.is_empty() {
            Ruled::Permit(permit)
        } else if !permit_unknown.is_empty() {
            Ruled::Missing(permit_unknown)
        } else {
            Ruled::Deny
        }
    }

    /// The per-request Basis: for each owner, a standing policy of exactly this
    /// request's scope, established only where the rules permit. A context that
    /// names its required owners (a native request) uses those, never `owners`.
    pub fn basis<A, C: AuthorityContext>(
        &self,
        profile: Id,
        effect: &Effect<A, C>,
        owners: BTreeSet<Owner>,
        asked: &Asked,
    ) -> Result<(Basis, Vec<Ruling>), Invalid> {
        let context = effect.exercise();
        if context.operation() != &asked.operation || context.resource() != &asked.resource {
            return Err(Invalid::Context);
        }
        let owners = match context.required_owners() {
            Some(required) if owners.is_empty() || owners == required => required,
            Some(_) => return Err(Invalid::Owners),
            None => owners,
        };
        let scope = Scope {
            person: context.person(),
            application: context.application().cloned(),
            coverage: Coverage::Exact(asked.resource.clone()),
            operations: [asked.operation.clone()].into(),
            interval: asked
                .at
                .checked_add(1)
                .map_or(Interval::empty(asked.at), |until| {
                    Interval::new(asked.at, until).expect("one instant")
                }),
            redelegations: 0,
        };
        let (mut policies, mut facts, mut rulings) = (Vec::new(), Vec::new(), Vec::new());
        for owner in owners {
            let ruled = self.decide(asked, &owner);
            let source = SourceRef {
                namespace: Id::new("eudoxia/rules/v1").expect("fixed"),
                algorithm: Id::new("ruling").expect("fixed"),
                digest: crate::model::fingerprint(
                    b"eudoxia/ruling/v1",
                    &(&profile, &owner, asked, &ruled),
                )
                .0
                .to_vec(),
            };
            let state = match &ruled {
                Ruled::Permit(_) => FactState::Established,
                Ruled::Forbid(ids) => FactState::Refused(Reason::Profile(ids[0].clone())),
                Ruled::Deny => FactState::Refused(Reason::NoGrant),
                Ruled::Missing(_) => FactState::Missing,
            };
            let policy = Policy::standing(
                owner.clone(),
                source.clone(),
                scope.clone(),
                Some(context.credential()),
            );
            policies.push(policy);
            facts.push(Fact { source, state });
            rulings.push(Ruling { owner, ruled });
        }
        let basis = Basis::build(
            profile,
            asked.at,
            policies,
            facts,
            Vec::new(),
            Recheck::OnSourceChange,
        )?;
        Ok((basis, rulings))
    }
}

fn holds(condition: &Condition, asked: &Asked, owner: &Owner) -> Known {
    let value = |term: &Term| -> Option<Value> {
        match term {
            Term::Time => Some(Value::Time(asked.at)),
            Term::Owner => Some(Value::Text(owner.as_str().into())),
            Term::Resource => Some(Value::Text(asked.resource.as_str().into())),
            Term::Fact(id) => asked.facts.get(id).cloned(),
        }
    };
    let pair = |a: &Term, b: &Term| Some((value(a)?, value(b)?));
    match condition {
        Condition::Holds(t) => match value(t)? {
            Value::Flag(f) => Some(f),
            _ => None,
        },
        Condition::Same(a, b) => pair(a, b).map(|(a, b)| a == b),
        Condition::Before(a, b) => match pair(a, b)? {
            (Value::Time(a), Value::Time(b)) => Some(a < b),
            _ => None,
        },
        Condition::Near(a, b, most) => match pair(a, b)? {
            (Value::Time(a), Value::Time(b)) => Some(a.abs_diff(b) <= *most),
            _ => None,
        },
        Condition::In(a, b) => match pair(a, b)? {
            (Value::Text(a), Value::Texts(b)) => Some(b.contains(&a)),
            _ => None,
        },
        Condition::Within(a, b) => match pair(a, b)? {
            (Value::Texts(a), Value::Texts(b)) => Some(a.is_subset(&b)),
            _ => None,
        },
        Condition::Not(c) => holds(c, asked, owner).map(|held| !held),
        Condition::All(cs) => cs
            .iter()
            .try_fold(Some(true), |all, c| match holds(c, asked, owner) {
                Some(false) => Err(()),
                Some(true) => Ok(all),
                None => Ok(None),
            })
            .unwrap_or(Some(false)),
        Condition::Any(cs) => cs
            .iter()
            .try_fold(Some(false), |any, c| match holds(c, asked, owner) {
                Some(true) => Err(()),
                Some(false) => Ok(any),
                None => Ok(None),
            })
            .unwrap_or(Some(true)),
    }
}
