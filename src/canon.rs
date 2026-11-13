//! Canon owns institutional interpretation and canonical source pins. Profiles
//! bind its admitted standing to operational scopes and installed native carriers.
use crate::*;
use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    vec::Vec,
};
use canon_core::{Act, Log};
use canon_institution::Arrangements;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct Binding {
    pub owner: Owner,
    pub scope: canon_core::Scope,
    pub authority: Scope,
    pub carriers: BTreeSet<Id>,
    pub obligations: BTreeSet<Obligation>,
}
/// Explicit authenticated mapping, never a display-name lookup.
#[derive(Clone, Debug, Serialize)]
pub struct Identity {
    pub actor: String,
    pub key: Principal,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanonError {
    Interpretation(String),
    Identity(String),
    Source(String),
    Ambiguous(String),
    Structure(Invalid),
}
impl core::fmt::Display for CanonError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "canon authority basis: {self:?}")
    }
}
impl core::error::Error for CanonError {}

/// Supply the held original set, BEFORE any lossy short-ID Log construction.
/// Conflicting content/signature variants cannot be discarded into authority.
pub fn establish(
    acts: &[Act],
    arrangements: &Arrangements,
    at: i64,
    profile: Id,
    mut bindings: Vec<Binding>,
    identities: &[Identity],
    codecs: Vec<Codec>,
) -> Result<Basis, CanonError> {
    let mut sources = BTreeMap::new();
    for act in acts {
        if act.v > canon_core::act::FORMAT_VERSION
            || act.v < act.kind.min_version()
            || ((act.sig.is_some() || !act.refs.is_empty())
                && act.v < canon_core::act::SIGNED_VERSION)
            || Act::new(act.kind.clone(), act.ts_unix, act.actor.clone()).id != act.id
        {
            return Err(CanonError::Source(act.id.to_string()));
        }
        let value = (canon_core::sign::digest(act), act.sig.clone());
        if sources.get(&act.id).is_some_and(|old| *old != value) {
            return Err(CanonError::Ambiguous(act.id.to_string()));
        }
        sources.insert(act.id.clone(), value);
    }
    let log = Log::from_acts(acts.to_vec());
    let institution =
        canon_institution::interpret(&log, arrangements, at).map_err(CanonError::Interpretation)?;
    let mut identities = identities.to_vec();
    identities.sort_by(|a, b| a.actor.cmp(&b.actor));
    let mut keys = BTreeSet::new();
    for (index, identity) in identities.iter().enumerate() {
        if identity.actor.is_empty()
            || !keys.insert(identity.key)
            || identities
                .get(index + 1)
                .is_some_and(|n| n.actor == identity.actor)
        {
            return Err(CanonError::Identity(identity.actor.clone()));
        }
    }
    bindings.sort_by(|a, b| a.owner.cmp(&b.owner));
    let certificate = institution.to_json();
    let arrangements_id = certificate
        .get("arrangements_sha256")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CanonError::Interpretation("missing canon arrangements identity".into()))?;
    let mut policies = Vec::new();
    let mut facts = BTreeSet::new();
    for binding in bindings {
        let source = SourceRef {
            namespace: profile.clone(),
            algorithm: Id::new("eudoxia-frame4-sha256").expect("constant"),
            digest: crate::model::fingerprint(
                b"canon-mapping/v1",
                &(arrangements_id, &binding, &identities),
            )
            .0
            .to_vec(),
        };
        facts.insert(source.clone());
        let mut issuers = BTreeSet::new();
        let mut requires = BTreeSet::new();
        for grant in institution
            .projection()
            .grants()
            .iter()
            .filter(|g| g.held_at(at) && g.scope.covers(&binding.scope))
        {
            let identity = identities
                .iter()
                .find(|i| i.actor == grant.actor)
                .ok_or_else(|| CanonError::Identity(grant.actor.clone()))?;
            issuers.insert(identity.key);
            let (pin, _) = sources
                .get(&grant.act)
                .ok_or_else(|| CanonError::Source(grant.act.to_string()))?;
            let reference = SourceRef {
                namespace: profile.clone(),
                algorithm: Id::new("canon-canonical-sha256-hex").expect("constant"),
                digest: pin.as_bytes().to_vec(),
            };
            facts.insert(reference.clone());
            requires.insert(reference);
        }
        policies.push(Policy {
            owner: binding.owner,
            source,
            scope: binding.authority,
            approval: ApprovalRule::Delegated(issuers),
            actor: None,
            effect: None,
            requires,
            admitters: BTreeSet::new(),
            carriers: binding.carriers,
            obligations: binding.obligations,
        });
    }
    let next = acts
        .iter()
        .map(|a| a.ts_unix)
        .chain(
            institution
                .projection()
                .grants()
                .iter()
                .filter_map(|g| g.horizon.and_then(|h| h.checked_add(1))),
        )
        .filter(|t| *t > at)
        .min();
    Basis::interpreted(
        profile,
        at,
        policies,
        facts
            .into_iter()
            .map(|source| Fact {
                source,
                state: FactState::Established,
            })
            .collect(),
        codecs,
        next.map_or(Recheck::OnSourceChange, Recheck::Before),
    )
    .map_err(CanonError::Structure)
}
