//! Inputs owned by an installed authority profile, never execution proofs.
use crate::*;
use alloc::{collections::BTreeSet, vec::Vec};
use serde::{Deserialize, Serialize};

/// Native identity: equal digest bytes in different namespaces/algorithms differ.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRef {
    pub namespace: Id,
    pub algorithm: Id,
    #[serde(serialize_with = "crate::encoding::raw")]
    pub digest: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactState {
    Established,
    Refused(Reason),
    Missing,
    Frozen(BTreeSet<SourceRef>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fact {
    pub source: SourceRef,
    pub state: FactState,
}

/// Coverage is structural. Paths are already decoded by their resource owner;
/// ambiguous spellings are rejected, never normalized by the authority kernel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Coverage {
    Exact(Resource),
    Set(BTreeSet<Resource>),
    Tree(Resource),
}
fn path(value: &str) -> bool {
    !value.is_empty()
        && !value.contains(['%', '\\', '?', '#'])
        && value
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != "..")
}
impl Coverage {
    pub fn contains(&self, resource: &Resource) -> bool {
        match self {
            Self::Exact(r) => r == resource,
            Self::Set(rs) => rs.contains(resource),
            Self::Tree(root) => {
                // Native definitions have no path-prefix authority. In
                // particular, a legacy display label cannot cover their ID.
                if root.identity().is_some() || resource.identity().is_some() {
                    return root == resource;
                }
                let (root, child) = (root.as_str(), resource.as_str());
                path(root)
                    && path(child)
                    && (root == child
                        || child.strip_prefix(root).is_some_and(|s| s.starts_with('/')))
            }
        }
    }
    pub fn covers(&self, child: &Self) -> bool {
        match child {
            Self::Exact(r) => self.contains(r),
            Self::Set(rs) => !rs.is_empty() && rs.iter().all(|r| self.contains(r)),
            Self::Tree(r) => matches!(self, Self::Tree(_)) && self.contains(r),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    /// None is an owner policy applicable to independently established people.
    /// Delegation cannot widen Some into None.
    pub person: Option<Principal>,
    pub application: Option<Application>,
    pub coverage: Coverage,
    pub operations: BTreeSet<Operation>,
    pub interval: Interval,
    pub redelegations: u8,
}
impl Scope {
    /// A relation between scope data, not a proof of authority. The derivation
    /// boundary additionally authenticates issuers, sources and execution context.
    pub fn covers(&self, child: &Self, delegated: bool) -> bool {
        self.person.is_none_or(|p| child.person == Some(p))
            && self
                .application
                .as_ref()
                .is_none_or(|a| child.application.as_ref() == Some(a))
            && self.coverage.covers(&child.coverage)
            && !child.operations.is_empty()
            && child.operations.is_subset(&self.operations)
            && self.interval.covers(child.interval)
            && if delegated {
                child.redelegations < self.redelegations
            } else {
                child.redelegations <= self.redelegations
            }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalRule {
    Standing,
    Delegated(BTreeSet<Principal>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub owner: Owner,
    pub source: SourceRef,
    pub scope: Scope,
    pub approval: ApprovalRule,
    pub actor: Option<Actor>,
    pub effect: Option<Fingerprint>,
    /// Every dependency must be established, including cross-operation history.
    pub requires: BTreeSet<SourceRef>,
    pub admitters: BTreeSet<Principal>,
    pub carriers: BTreeSet<Id>,
    pub obligations: BTreeSet<Obligation>,
}

impl Policy {
    pub fn actor_matches(&self, actual: Actor) -> bool {
        self.actor.is_none_or(|selected| selected == actual)
    }
    /// Assemble an interpreted standing policy. Truth/legitimacy still belong to
    /// the installed interpreter; this value constructs no execution authority.
    pub fn standing(owner: Owner, source: SourceRef, scope: Scope, actor: Option<Actor>) -> Self {
        Self {
            owner,
            source,
            scope,
            actor,
            approval: ApprovalRule::Standing,
            effect: None,
            requires: BTreeSet::new(),
            admitters: BTreeSet::new(),
            carriers: BTreeSet::new(),
            obligations: BTreeSet::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeEvidence {
    pub codec: Id,
    #[serde(serialize_with = "crate::encoding::raw")]
    pub bytes: Vec<u8>,
}

/// A carrier's semantic projection, consumed only after original-byte verification.
/// It remains untrusted authority input: roots, narrowing and exact effect still apply.
#[derive(Clone, Debug)]
pub enum Claim {
    Delegation {
        owner: Owner,
        holder: Principal,
        scope: Scope,
        sources: BTreeSet<SourceRef>,
    },
    Admission {
        effect: Fingerprint,
        when: AdmissionTime,
        sources: BTreeSet<SourceRef>,
    },
}

/// A native approver need not sign a fabricated exact timestamp. Within means
/// every possible admission instant in this attested interval is authorized.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionTime {
    At(i64),
    Within(Interval),
}
impl AdmissionTime {
    pub(crate) fn covered_by(self, interval: Interval) -> bool {
        match self {
            Self::At(at) => interval.contains(at),
            Self::Within(window) => !window.is_empty() && interval.covers(window),
        }
    }
    pub(crate) fn earliest(self) -> i64 {
        match self {
            Self::At(at) => at,
            Self::Within(window) => window.from(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Malformed,
    Unsupported,
    InvalidSignature,
}

/// Installed by the resource profile. Parsing returns one owned native statement;
/// its projection is consumed only after verification. Version names semantic code.
#[derive(Clone, Debug)]
pub struct Codec {
    pub id: Id,
    pub decode: fn(&[u8]) -> Result<crate::ParsedStatement, DecodeError>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Purpose {
    Live,
    HistoricalAdmission,
}

/// Interpretation freshness, separate from rights' temporal conditions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Recheck {
    OnSourceChange,
    Before(i64),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationError {
    ClockReversed,
    Reinterpret { at: i64 },
}
impl core::fmt::Display for ObservationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "authority observation: {self:?}")
    }
}
impl core::error::Error for ObservationError {}

/// One reviewed root interpreter per installed profile. Its laws (including
/// consent, conflict and causal semantics) belong to that profile's tests. A raw
/// projection or caller assertion is not an implementation of those laws.
pub trait RootInterpreter {
    type Evidence;
    type Error;
    fn establish(&self, evidence: &Self::Evidence, at: i64) -> Result<Basis, Self::Error>;
}

impl Basis {
    /// A one-source installed profile, with source state supplied explicitly.
    /// Missing/refused/frozen are never replaced by established standing.
    pub fn single(profile: Id, at: i64, policy: Policy, state: FactState) -> Result<Self, Invalid> {
        let fact = Fact {
            source: policy.source.clone(),
            state,
        };
        Self::interpreted(
            profile,
            at,
            alloc::vec![policy],
            alloc::vec![fact],
            Vec::new(),
            Recheck::OnSourceChange,
        )
    }

    /// Trusted profile boundary, like acquiring a ResourceGuard. This checks
    /// structure, not the interpreter's social legitimacy or completeness.
    ///
    /// Sealed for native requests: a policy naming a native operation for an
    /// owner the kernel requires of one (`group:`, `person:` ...) comes only
    /// from [`crate::Rules::basis`], so no caller hand-builds that authority.
    pub fn interpreted(
        profile: Id,
        at: i64,
        policies: Vec<Policy>,
        facts: Vec<Fact>,
        codecs: Vec<Codec>,
        recheck: Recheck,
    ) -> Result<Self, Invalid> {
        let native = |p: &Policy| p.scope.operations.iter().any(|o| o.native_kind().is_some());
        if policies
            .iter()
            .any(|p| native(p) && crate::context::required_form(&p.owner))
        {
            return Err(Invalid::Policy);
        }
        Self::build(profile, at, policies, facts, codecs, recheck)
    }

    pub(crate) fn build(
        profile: Id,
        at: i64,
        mut policies: Vec<Policy>,
        mut facts: Vec<Fact>,
        mut codecs: Vec<Codec>,
        recheck: Recheck,
    ) -> Result<Self, Invalid> {
        policies.sort_by(|a, b| a.owner.cmp(&b.owner));
        facts.sort_by(|a, b| a.source.cmp(&b.source));
        codecs.sort_by(|a, b| a.id.cmp(&b.id));
        if policies.is_empty() || policies.windows(2).any(|p| p[0].owner == p[1].owner) {
            return Err(Invalid::Owners);
        }
        if matches!(recheck,Recheck::Before(deadline) if deadline<=at) {
            return Err(Invalid::Interval);
        }
        if facts.windows(2).any(|p| p[0].source == p[1].source)
            || codecs.windows(2).any(|p| p[0].id == p[1].id)
            || policies.iter().any(|p| p.scope.operations.is_empty())
            || facts
                .iter()
                .map(|f| &f.source)
                .chain(
                    policies
                        .iter()
                        .flat_map(|p| core::iter::once(&p.source).chain(&p.requires)),
                )
                .any(|r| r.digest.is_empty() || r.digest.len() > 128)
        {
            return Err(Invalid::Policy);
        }
        let fingerprint = crate::model::fingerprint(
            b"eudoxia/authority/v3",
            &(
                &profile,
                &policies,
                &facts,
                codecs.iter().map(|c| &c.id).collect::<Vec<_>>(),
            ),
        );
        Ok(Self {
            at,
            data: alloc::sync::Arc::new(crate::model::AuthorityData {
                profile,
                policies,
                facts,
                codecs,
                fingerprint,
                recheck,
            }),
        })
    }
    pub fn policies(&self) -> &[Policy] {
        &self.data.policies
    }
    pub fn observed_at(&self, at: i64) -> Result<Self, ObservationError> {
        if at < self.at {
            return Err(ObservationError::ClockReversed);
        }
        if let Recheck::Before(deadline) = self.data.recheck
            && at >= deadline
        {
            return Err(ObservationError::Reinterpret { at: deadline });
        }
        let mut b = self.clone();
        b.at = at;
        Ok(b)
    }
}
