//! The only constructors of operational authority. Profiles supply facts, not proofs.
use crate::*;
use alloc::{boxed::Box, collections::BTreeSet, vec::Vec};
use serde::{Deserialize, Serialize};
mod chain_trace;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DerivationTrace {
    Root {
        basis: Fingerprint,
        owner: Owner,
        issuer: Principal,
        source: SourceRef,
        dependencies: BTreeSet<SourceRef>,
    },
    Standing {
        basis: Fingerprint,
        owner: Owner,
        source: SourceRef,
        dependencies: BTreeSet<SourceRef>,
    },
    Delegation {
        #[serde(with = "chain_trace")]
        parent: Box<Self>,
        grant: Fingerprint,
        holder: Principal,
        sources: BTreeSet<SourceRef>,
    },
    Admission {
        authority: Box<Self>,
        receipt: Fingerprint,
        when: AdmissionTime,
    },
    Agreement {
        required: Vec<Owner>,
        approvals: Vec<Self>,
    },
    Exercise {
        authority: Box<Self>,
        effect: Fingerprint,
    },
}
struct Root {
    basis: Fingerprint,
    owner: Owner,
    source: SourceRef,
    scope: Scope,
    trace: DerivationTrace,
}
struct Chain {
    root: Root,
    holder: Principal,
    scope: Scope,
    trace: DerivationTrace,
    grants: Vec<Fingerprint>,
}
struct Approval {
    basis: Fingerprint,
    effect: Fingerprint,
    owner: Owner,
    trace: DerivationTrace,
    grants: Vec<Fingerprint>,
}
pub(crate) struct Agreement {
    trace: DerivationTrace,
}
pub(crate) struct Evaluated<C = Exercise> {
    pub record: DecisionRecord<C>,
    pub agreement: Option<Agreement>,
}
enum Failure {
    Refused(Reason),
    NotApplicable,
    Missing(Box<Need>),
}
impl Failure {
    fn report(self) -> OwnerDecision {
        match self {
            Self::Refused(r) => OwnerDecision::Refused(r),
            Self::NotApplicable => OwnerDecision::NotApplicable,
            Self::Missing(n) => OwnerDecision::Undetermined(*n),
        }
    }
}
fn need(policy: &Policy) -> Need {
    Need {
        owner: policy.owner.clone(),
        issuers: match &policy.approval {
            ApprovalRule::Standing => BTreeSet::new(),
            ApprovalRule::Delegated(is) => is.clone(),
        },
        sources: BTreeSet::new(),
        codecs: BTreeSet::new(),
        conflicts: BTreeSet::new(),
        admission: false,
        context: BTreeSet::new(),
    }
}
fn sources(basis: &Basis, policy: &Policy, refs: &BTreeSet<SourceRef>) -> Result<(), Failure> {
    let mut missing = need(policy);
    let mut refused = None;
    for reference in refs {
        match basis
            .data
            .facts
            .iter()
            .find(|f| f.source == *reference)
            .map(|f| &f.state)
        {
            Some(FactState::Established) => (),
            Some(FactState::Refused(r)) => refused = Some(r.clone()),
            Some(FactState::Frozen(conflicts)) => {
                missing.sources.insert(reference.clone());
                missing.conflicts.extend(conflicts.iter().cloned());
            }
            _ => {
                missing.sources.insert(reference.clone());
            }
        }
    }
    if let Some(r) = refused {
        Err(Failure::Refused(r))
    } else if !missing.sources.is_empty() {
        Err(Failure::Missing(Box::new(missing)))
    } else {
        Ok(())
    }
}
fn outside(interval: Interval, when: AdmissionTime) -> Result<(), Failure> {
    if when.covered_by(interval) {
        Ok(())
    } else {
        Err(Failure::Refused(if when.earliest() < interval.from() {
            Reason::NotYetValid
        } else {
            Reason::Expired
        }))
    }
}
fn decode(
    basis: &Basis,
    policy: &Policy,
    evidence: &NativeEvidence,
) -> Result<(Principal, Claim), Failure> {
    let missing = || {
        let mut n = need(policy);
        n.codecs.insert(evidence.codec.clone());
        Failure::Missing(Box::new(n))
    };
    let codec = basis
        .data
        .codecs
        .iter()
        .find(|c| c.id == evidence.codec)
        .ok_or_else(missing)?;
    if !policy.carriers.contains(&evidence.codec) {
        return Err(Failure::Refused(Reason::WrongEvidenceProfile));
    }
    let failure = |e| match e {
        DecodeError::Malformed | DecodeError::InvalidSignature => {
            Failure::Refused(Reason::InvalidSignature)
        }
        DecodeError::Unsupported => missing(),
    };
    let verified = (codec.decode)(&evidence.bytes)
        .map_err(&failure)?
        .verify()
        .map_err(&failure)?;
    let issuer = verified.issuer();
    let claim = verified.project(&policy.source).map_err(failure)?;
    Ok((issuer, claim))
}
struct Step {
    issuer: Principal,
    owner: Owner,
    holder: Principal,
    scope: Scope,
    sources: BTreeSet<SourceRef>,
    id: Fingerprint,
}
fn steps<'a>(
    basis: &'a Basis,
    policy: &'a Policy,
    evidence: Option<&'a OwnerProof>,
) -> Result<impl Iterator<Item = Result<Step, Failure>> + 'a, Failure> {
    let native = match evidence {
        None => return Err(Failure::Missing(Box::new(need(policy)))),
        Some(OwnerProof::Absent) => return Err(Failure::Refused(Reason::NoGrant)),
        Some(OwnerProof::Admitted { .. }) => {
            return Err(Failure::Refused(Reason::WrongAdmission));
        }
        Some(OwnerProof::Native(chain)) => chain.as_slice(),
    };
    // Parsing/authentication is lazy: a broken prefix cannot buy verification
    // of an arbitrary suffix. Record hashing/ingress byte budgets are separate.
    Ok(native.iter().map(move |p| {
        let (issuer, claim) = decode(basis, policy, p)?;
        match claim {
            Claim::Delegation {
                owner,
                holder,
                scope,
                sources,
            } => Ok(Step {
                issuer,
                owner,
                holder,
                scope,
                sources,
                id: crate::model::fingerprint(b"native-evidence/v3", p),
            }),
            _ => Err(Failure::Refused(Reason::WrongAdmission)),
        }
    }))
}
impl Root {
    fn establish(
        basis: &Basis,
        policy: &Policy,
        issuer: Option<Principal>,
        at: AdmissionTime,
    ) -> Result<Self, Failure> {
        let refs = policy
            .requires
            .iter()
            .cloned()
            .chain(core::iter::once(policy.source.clone()))
            .collect();
        sources(basis, policy, &refs)?;
        outside(policy.scope.interval, at)?;
        if let ApprovalRule::Delegated(issuers) = &policy.approval
            && !issuer.is_some_and(|key| issuers.contains(&key))
        {
            return Err(Failure::Refused(Reason::NoIssuer));
        }
        Ok(Self {
            basis: basis.fingerprint(),
            owner: policy.owner.clone(),
            source: policy.source.clone(),
            scope: policy.scope.clone(),
            trace: if let Some(issuer) = issuer {
                DerivationTrace::Root {
                    basis: basis.fingerprint(),
                    owner: policy.owner.clone(),
                    issuer,
                    source: policy.source.clone(),
                    dependencies: policy.requires.clone(),
                }
            } else {
                DerivationTrace::Standing {
                    basis: basis.fingerprint(),
                    owner: policy.owner.clone(),
                    source: policy.source.clone(),
                    dependencies: policy.requires.clone(),
                }
            },
        })
    }
    fn issue(self, step: Step, at: AdmissionTime) -> Result<Chain, Failure> {
        self.narrows(&self.scope, &step, at, false)?;
        let trace = DerivationTrace::Delegation {
            parent: Box::new(self.trace.clone()),
            grant: step.id,
            holder: step.holder,
            sources: step.sources,
        };
        Ok(Chain {
            root: self,
            holder: step.holder,
            scope: step.scope,
            trace,
            grants: alloc::vec![step.id],
        })
    }
    fn narrows(
        &self,
        parent: &Scope,
        step: &Step,
        at: AdmissionTime,
        delegated: bool,
    ) -> Result<(), Failure> {
        if step.owner != self.owner || !step.sources.contains(&self.source) {
            return Err(Failure::Refused(Reason::BrokenChain));
        }
        if !parent.covers(&step.scope, delegated) {
            return Err(Failure::Refused(Reason::WiderGrant));
        }
        outside(step.scope.interval, at)
    }
    fn approve<A, C: AuthorityContext>(
        self,
        scope: &Scope,
        effect: &Effect<A, C>,
        trace: DerivationTrace,
        grants: Vec<Fingerprint>,
    ) -> Result<Approval, Failure> {
        let e = effect.exercise();
        if scope.person.is_some_and(|p| Some(p) != e.person()) {
            return Err(Failure::Refused(Reason::WrongPerson));
        }
        if scope
            .application
            .as_ref()
            .is_some_and(|a| Some(a) != e.application())
            || !scope.coverage.contains(e.resource())
        {
            return Err(Failure::Refused(Reason::WiderGrant));
        }
        if !scope.operations.contains(e.operation()) {
            return Err(Failure::NotApplicable);
        }
        Ok(Approval {
            basis: self.basis,
            effect: effect.fingerprint(),
            owner: self.owner,
            trace,
            grants,
        })
    }
}
impl Chain {
    fn delegate(mut self, step: Step, at: AdmissionTime) -> Result<Self, Failure> {
        if step.issuer != self.holder {
            return Err(Failure::Refused(Reason::BrokenChain));
        }
        self.root.narrows(&self.scope, &step, at, true)?;
        self.grants.push(step.id);
        self.holder = step.holder;
        self.scope = step.scope;
        self.trace = DerivationTrace::Delegation {
            parent: Box::new(self.trace),
            grant: step.id,
            holder: self.holder,
            sources: step.sources,
        };
        Ok(self)
    }
    fn exercise<A, C: AuthorityContext>(self, effect: &Effect<A, C>) -> Result<Approval, Failure> {
        if Some(self.holder) != effect.exercise().key() {
            return Err(Failure::Refused(Reason::WrongHolder));
        }
        self.root
            .approve(&self.scope, effect, self.trace, self.grants)
    }
}
impl Agreement {
    fn all(basis: &Basis, effect: Fingerprint, approvals: Vec<Approval>) -> Option<Self> {
        if approvals.is_empty()
            || approvals.len() != basis.policies().len()
            || !approvals.iter().zip(basis.policies()).all(|(a, p)| {
                a.owner == p.owner && a.basis == basis.fingerprint() && a.effect == effect
            })
        {
            return None;
        }
        Some(Self {
            trace: DerivationTrace::Exercise {
                authority: Box::new(DerivationTrace::Agreement {
                    required: basis.policies().iter().map(|p| p.owner.clone()).collect(),
                    approvals: approvals.into_iter().map(|a| a.trace).collect(),
                }),
                effect,
            },
        })
    }
}
fn owner<A, C: AuthorityContext>(
    basis: &Basis,
    policy: &Policy,
    effect: &Effect<A, C>,
    supplied: Option<&OwnerProof>,
    purpose: Purpose,
) -> Result<Approval, Failure> {
    let result = derive_owner(basis, policy, effect, supplied, purpose);
    if purpose == Purpose::HistoricalAdmission
        && !matches!(supplied, Some(OwnerProof::Admitted { .. }))
        && matches!(
            &result,
            Err(Failure::Refused(Reason::Expired | Reason::NotYetValid))
        )
    {
        let mut n = need(policy);
        n.admission = true;
        return Err(Failure::Missing(Box::new(n)));
    }
    result
}
fn derive_owner<A, C: AuthorityContext>(
    basis: &Basis,
    policy: &Policy,
    effect: &Effect<A, C>,
    supplied: Option<&OwnerProof>,
    purpose: Purpose,
) -> Result<Approval, Failure> {
    // Intrinsic native meaning constrains standing and delegated roots alike.
    // A legacy name never supplies a missing classified execution context.
    if let Err(failure) = effect.exercise().check() {
        return Err(match failure {
            crate::identity::ContextFailure::Missing(context) => {
                let mut n = need(policy);
                n.context.insert(context);
                Failure::Missing(Box::new(n))
            }
            crate::identity::ContextFailure::ClassDenied => {
                Failure::Refused(Reason::ApplicationClassDenied)
            }
            crate::identity::ContextFailure::ResourceMismatch => {
                Failure::Refused(Reason::ResourceContextMismatch)
            }
        });
    }
    if !policy.actor_matches(effect.exercise().credential()) {
        return Err(Failure::Refused(Reason::WrongHolder));
    }
    if policy.effect.is_some_and(|f| f != effect.fingerprint()) {
        return Err(Failure::Refused(Reason::WrongEffect));
    }
    if policy
        .scope
        .person
        .is_some_and(|p| Some(p) != effect.exercise().person())
    {
        return Err(Failure::Refused(Reason::WrongPerson));
    }
    if !policy
        .scope
        .operations
        .contains(effect.exercise().operation())
    {
        return Err(Failure::NotApplicable);
    }
    let refs = policy
        .requires
        .iter()
        .cloned()
        .chain(core::iter::once(policy.source.clone()))
        .collect();
    sources(basis, policy, &refs)?;
    let (supplied, at, receipt) = if let Some(OwnerProof::Admitted { proof, receipt }) = supplied {
        if purpose != Purpose::HistoricalAdmission {
            return Err(Failure::Refused(Reason::HistoricalOnly));
        }
        let (issuer, claim) = decode(basis, policy, receipt)?;
        let Claim::Admission {
            effect: exact,
            when: at,
            sources: refs,
        } = claim
        else {
            return Err(Failure::Refused(Reason::WrongAdmission));
        };
        if exact != effect.fingerprint()
            || !policy.admitters.contains(&issuer)
            || !refs.contains(&policy.source)
            || at.earliest() > basis.at()
        {
            return Err(Failure::Refused(Reason::WrongAdmission));
        }
        sources(basis, policy, &refs)?;
        (Some(proof.as_ref()), at, Some(receipt))
    } else {
        (supplied, AdmissionTime::At(basis.at()), None)
    };
    if purpose == Purpose::HistoricalAdmission
        && receipt.is_none()
        && !at.covered_by(policy.scope.interval)
    {
        let mut n = need(policy);
        n.admission = true;
        return Err(Failure::Missing(Box::new(n)));
    }
    let mut approval = match &policy.approval {
        ApprovalRule::Standing => {
            let root = Root::establish(basis, policy, effect.exercise().key(), at)?;
            let trace = DerivationTrace::Standing {
                basis: root.basis,
                owner: root.owner.clone(),
                source: root.source.clone(),
                dependencies: policy.requires.clone(),
            };
            root.approve(&policy.scope, effect, trace, Vec::new())?
        }
        ApprovalRule::Delegated(issuers) => {
            if issuers.is_empty() {
                return Err(Failure::Refused(Reason::NoIssuer));
            }
            let mut proofs = steps(basis, policy, supplied)?;
            let first = proofs.next().ok_or(Failure::Refused(Reason::NoGrant))??;
            let root = Root::establish(basis, policy, Some(first.issuer), at)?;
            sources(basis, policy, &first.sources)?;
            let mut chain = root.issue(first, at)?;
            for step in proofs {
                let step = step?;
                sources(basis, policy, &step.sources)?;
                chain = chain.delegate(step, at)?;
            }
            chain.exercise(effect)?
        }
    };
    if let Some(receipt) = receipt {
        approval.trace = DerivationTrace::Admission {
            authority: Box::new(approval.trace),
            receipt: crate::model::fingerprint(b"admission/v3", receipt),
            when: at,
        };
    }
    Ok(approval)
}
pub(crate) fn evaluate<A, C: AuthorityContext>(
    basis: &Basis,
    effect: &Effect<A, C>,
    evidence: &Evidence,
) -> Evaluated<C> {
    evaluate_for(basis, effect, evidence, Purpose::Live)
}
pub(crate) fn evaluate_for<A, C: AuthorityContext>(
    basis: &Basis,
    effect: &Effect<A, C>,
    evidence: &Evidence,
    purpose: Purpose,
) -> Evaluated<C> {
    let (mut reports, mut approvals) = (Vec::new(), Vec::new());
    let target = effect.exercise();
    let required = target.required_owners();
    let applicable = required.is_some()
        || target.check().is_err()
        || basis.policies().iter().any(|p| {
            p.scope.coverage.contains(target.resource())
                && p.scope
                    .application
                    .as_ref()
                    .is_none_or(|a| Some(a) == target.application())
        });
    if applicable {
        for policy in basis.policies() {
            let decision = match owner(basis, policy, effect, evidence.get(&policy.owner), purpose)
            {
                Ok(a) => {
                    let decision = OwnerDecision::Permitted {
                        grants: a.grants.clone(),
                    };
                    approvals.push(a);
                    decision
                }
                Err(f) => f.report(),
            };
            reports.push(OwnerJudgment {
                owner: policy.owner.clone(),
                decision,
            });
        }
    }
    let mut owners_complete = true;
    if let Some(required) = required {
        let configured: BTreeSet<_> = basis.policies().iter().map(|p| p.owner.clone()).collect();
        for owner in required.difference(&configured) {
            owners_complete = false;
            reports.push(OwnerJudgment {
                owner: owner.clone(),
                decision: OwnerDecision::Undetermined(Need {
                    owner: owner.clone(),
                    issuers: BTreeSet::new(),
                    sources: BTreeSet::new(),
                    codecs: BTreeSet::new(),
                    conflicts: BTreeSet::new(),
                    admission: false,
                    context: BTreeSet::new(),
                }),
            });
        }
        for report in &mut reports {
            if !required.contains(&report.owner) {
                owners_complete = false;
                report.decision = OwnerDecision::Refused(Reason::UnexpectedOwner);
            }
        }
    }
    let agreement = owners_complete
        .then(|| Agreement::all(basis, effect.fingerprint(), approvals))
        .flatten();
    let decision = if !applicable {
        Decision::NotApplicable
    } else if agreement.is_some() {
        Decision::Permitted
    } else if reports.iter().any(|r| {
        matches!(
            r.decision,
            OwnerDecision::Refused(_) | OwnerDecision::NotApplicable
        )
    }) {
        Decision::Refused
    } else {
        Decision::Undetermined
    };
    let obligations = if agreement.is_some() {
        basis
            .policies()
            .iter()
            .flat_map(|p| p.obligations.iter().cloned())
            .collect()
    } else {
        BTreeSet::new()
    };
    let trace = agreement.as_ref().map(|a| a.trace.clone());
    let report = crate::record::Report {
        decision,
        owners: reports,
        obligations,
        trace,
    };
    Evaluated {
        record: DecisionRecord::new(basis, effect, evidence, purpose, report),
        agreement,
    }
}
