use crate::*;
use alloc::{collections::BTreeSet, vec::Vec};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Permitted,
    Refused,
    NotApplicable,
    Undetermined,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reason {
    NoGrant,
    NoIssuer,
    InvalidSignature,
    BrokenChain,
    WiderGrant,
    WrongHolder,
    WrongPerson,
    OperationNotGranted,
    NotYetValid,
    Expired,
    SourceRejected,
    WrongAdmission,
    HistoricalOnly,
    WrongEvidenceProfile,
    WrongEffect,
    ApplicationClassDenied,
    ResourceContextMismatch,
    UnexpectedOwner,
    Profile(Id),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Need {
    pub owner: Owner,
    pub issuers: BTreeSet<Principal>,
    pub sources: BTreeSet<SourceRef>,
    pub codecs: BTreeSet<Id>,
    pub conflicts: BTreeSet<SourceRef>,
    pub admission: bool,
    pub context: BTreeSet<ContextNeed>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OwnerDecision {
    Permitted { grants: Vec<Fingerprint> },
    Refused(Reason),
    NotApplicable,
    Undetermined(Need),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerJudgment {
    pub owner: Owner,
    pub decision: OwnerDecision,
}

/// Historical inspection of a descriptor, with null arguments. Never live authority.
pub fn judge(basis: &Basis, exercise: &Exercise, evidence: &Evidence) -> DecisionRecord {
    let effect = Effect::<()>::new(exercise.clone(), &()).expect("null arguments serialize");
    crate::derivation::evaluate(basis, &effect, evidence).record
}

/// Historical inspection including the exact frozen arguments.
pub fn inspect<A, C: AuthorityContext>(
    basis: &Basis,
    effect: &Effect<A, C>,
    evidence: &Evidence,
) -> DecisionRecord<C> {
    crate::derivation::evaluate(basis, effect, evidence).record
}

pub fn inspect_admission<A, C: AuthorityContext>(
    basis: &Basis,
    effect: &Effect<A, C>,
    evidence: &Evidence,
) -> DecisionRecord<C> {
    crate::derivation::evaluate_for(basis, effect, evidence, Purpose::HistoricalAdmission).record
}
