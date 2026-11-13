use crate::*;
use alloc::{collections::BTreeSet, vec::Vec};
use serde::{Deserialize, Serialize};

/// Serializable evidence of a past judgment, never an execution credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionRecord<C = Exercise> {
    pub version: u32,
    pub exercise: C,
    pub arguments: Vec<u8>,
    pub exercise_fingerprint: Fingerprint,
    pub at: i64,
    pub purpose: Purpose,
    pub profile: Id,
    pub basis: Fingerprint,
    pub evidence: Fingerprint,
    pub decision: Decision,
    pub owners: Vec<OwnerJudgment>,
    pub obligations: BTreeSet<Obligation>,
    pub derivation: Option<DerivationTrace>,
}

pub(crate) struct Report {
    pub decision: Decision,
    pub owners: Vec<OwnerJudgment>,
    pub obligations: BTreeSet<Obligation>,
    pub trace: Option<DerivationTrace>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayError {
    ContextChanged,
    JudgmentChanged,
}

impl core::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "authority replay: {self:?}")
    }
}
impl core::error::Error for ReplayError {}

impl<C: AuthorityContext> DecisionRecord<C> {
    pub(crate) fn new<A>(
        basis: &Basis,
        effect: &Effect<A, C>,
        evidence: &Evidence,
        purpose: Purpose,
        report: Report,
    ) -> Self {
        Self {
            version: 7,
            exercise: effect.exercise().clone(),
            arguments: effect.arguments().to_vec(),
            exercise_fingerprint: effect.fingerprint(),
            at: basis.at(),
            purpose,
            profile: basis.profile().clone(),
            basis: basis.fingerprint(),
            evidence: evidence.fingerprint(),
            decision: report.decision,
            owners: report.owners,
            obligations: report.obligations,
            derivation: report.trace,
        }
    }
    pub fn replay(&self, basis: &Basis, evidence: &Evidence) -> Result<Self, ReplayError> {
        if self.basis != basis.fingerprint()
            || self.evidence != evidence.fingerprint()
            || self.at != basis.at()
            || self.profile != *basis.profile()
        {
            return Err(ReplayError::ContextChanged);
        }
        let effect = Effect::<(), C>::recorded(self.exercise.clone(), &self.arguments)
            .map_err(|_| ReplayError::JudgmentChanged)?;
        let replayed =
            crate::derivation::evaluate_for(basis, &effect, evidence, self.purpose).record;
        if replayed != *self {
            return Err(ReplayError::JudgmentChanged);
        }
        Ok(replayed)
    }
}
