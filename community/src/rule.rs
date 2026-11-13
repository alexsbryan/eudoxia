// SPDX-License-Identifier: AGPL-3.0-or-later
//! What every request module of this profile shares: its facts, the few
//! condition shapes its rules are written in, and the one path a request
//! takes. The rules decide each owner's ruling into a per-request Basis
//! ([`eudoxia::Rules::basis`]); only the sealed path commits; a refusal is the
//! first rule in the module's table that forbade for any owner.
use alloc::{boxed::Box, collections::BTreeMap, format, string::String, vec::Vec};
use eudoxia::{
    Asked, Condition, Evidence, Id, Ingress, Owner, Purpose, Rule, Ruled, Rules, Term, Value,
    atomic,
};

pub(crate) type Facts = BTreeMap<Id, Value>;

/// One module's closed set of rules, listed in the order their refusals
/// are named.
pub(crate) trait Check: Copy + core::fmt::Debug + 'static {
    /// The module's name: its rules', operations' and profile's prefix.
    const PROFILE: &'static str;
    const ALL: &'static [Self];
    fn rule(self) -> Rule;
    fn id(self) -> Id {
        Id::new(format!("{}/{self:?}", Self::PROFILE)).expect("fixed rule name")
    }
}

/// Why a request was not let through.
pub(crate) enum Refused<C> {
    /// The first rule, in table order, that forbade.
    Rule(C),
    /// No rule forbade: default deny, or a fact the request lacks.
    Undecided,
    /// The request could not be built: its context is not lawful.
    Invalid,
}

impl<C> Refused<C> {
    pub(crate) fn rule(self) -> Option<C> {
        match self {
            Self::Rule(c) => Some(c),
            _ => None,
        }
    }
}

pub(crate) fn put(facts: &mut Facts, name: &str, value: Value) {
    facts.insert(Id::new(name).expect("fixed fact name"), value);
}
pub(crate) fn flag(facts: &mut Facts, name: &str, value: bool) {
    put(facts, name, Value::Flag(value));
}
pub(crate) fn text(s: &str) -> Value {
    Value::Text(s.into())
}
pub(crate) fn texts<'s>(all: impl IntoIterator<Item = &'s str>) -> Value {
    Value::Texts(all.into_iter().map(String::from).collect())
}
pub(crate) fn term(name: &str) -> Term {
    Term::Fact(Id::new(name).expect("fixed fact name"))
}
pub(crate) fn holds(name: &str) -> Condition {
    Condition::Holds(term(name))
}
pub(crate) fn not(c: Condition) -> Condition {
    Condition::Not(Box::new(c))
}
pub(crate) fn same(a: &str, b: &str) -> Condition {
    Condition::Same(term(a), term(b))
}
pub(crate) fn within(a: &str, b: &str) -> Condition {
    Condition::Within(term(a), term(b))
}
pub(crate) fn all<const N: usize>(cs: [Condition; N]) -> Condition {
    Condition::All(cs.into())
}
pub(crate) fn any<const N: usize>(cs: [Condition; N]) -> Condition {
    Condition::Any(cs.into())
}

/// `asked`, decided by `C`'s rules for each of `owners` (none: the
/// context's required owners) into a Basis and committed through the
/// sealed path under `ingress`; `apply` runs only if every owner permits.
/// With no ingress (no key to act under) the rules are decided without a
/// Basis, so a request never permits.
pub(crate) fn decide<C: Check, T>(
    ingress: Option<Ingress>,
    asked: Asked,
    owners: &[&str],
    purpose: Purpose,
    apply: impl FnOnce() -> T,
) -> Result<T, Refused<C>> {
    let rules = Rules::new(C::ALL.iter().map(|c| c.rule()).collect()).expect("unique rule names");
    let owners = owners.iter().map(|o| Owner::new(*o).expect("fixed owner"));
    let first = |ruled: &[Ruled]| {
        let forbade = |c: &C| {
            let id = c.id();
            ruled
                .iter()
                .any(|r| matches!(r, Ruled::Forbid(ids) if ids.contains(&id)))
        };
        C::ALL
            .iter()
            .copied()
            .find(forbade)
            .map_or(Refused::Undecided, Refused::Rule)
    };
    let Some(ingress) = ingress else {
        let ruled: Vec<_> = owners.map(|o| rules.decide(&asked, &o)).collect();
        return Err(first(&ruled));
    };
    let bytes = asked.resource.as_str().as_bytes().to_vec();
    let effect = ingress
        .effect::<()>(Id::new(C::PROFILE).expect("fixed"), bytes)
        .map_err(|_| Refused::Invalid)?;
    let profile = Id::new(format!("{}-v1", C::PROFILE)).expect("fixed");
    let (basis, rulings) = rules
        .basis(profile, &effect, owners.collect(), &asked)
        .map_err(|_| Refused::Invalid)?;
    let ruled: Vec<_> = rulings.into_iter().map(|r| r.ruled).collect();
    let evidence = Evidence::default();
    atomic(basis, ingress, purpose, (), effect, &evidence, |_, _, _| {
        apply()
    })
    .map_err(|_| first(&ruled))
}
