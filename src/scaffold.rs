//! Resource-scoped construction: derivation -> preparation witness -> exact effect.
use crate::{
    derivation::{Agreement, evaluate_for},
    *,
};
use alloc::{boxed::Box, collections::BTreeSet};
use core::marker::PhantomData;

/// A trusted acquired resource boundary, normally holding a lock/reservation.
/// `current` supplies authoritative policy, generation and time. `prepare` must
/// obtain real witnesses, reject unknown obligations, and perform no target effect.
/// `commit` consumes those witnesses and honors continuing conditions. An adapter
/// cannot pass an authorization minted for a different guard implementation.
pub trait ResourceGuard<C: AuthorityContext = Exercise>: Sized {
    type Action;
    type Witness;
    type Output;
    type Error;
    fn ingress(&self) -> C::Ingress;
    fn current(&mut self) -> Result<Basis, Self::Error>;
    fn purpose(&self) -> Purpose {
        Purpose::Live
    }
    fn prepare(
        &mut self,
        effect: &Effect<Self::Action, C>,
        obligations: &BTreeSet<Obligation>,
    ) -> Result<Self::Witness, Self::Error>;
    fn commit(&mut self, authorized: Authorized<'_, Self, C>) -> Result<Self::Output, Self::Error>;
}

// Invariance plus the higher-ranked scope makes two live sessions incompatible.
type Brand<'scope, G> = PhantomData<fn(&'scope mut (), G) -> (&'scope mut (), G)>;

pub struct Live<'scope, G: ResourceGuard<C>, C: AuthorityContext = Exercise> {
    guard: G,
    basis: Basis,
    brand: Brand<'scope, (G, C)>,
}
pub struct Justification<'scope, G: ResourceGuard<C>, C: AuthorityContext = Exercise> {
    effect: Effect<G::Action, C>,
    agreement: Agreement,
    record: DecisionRecord<C>,
    evidence: Evidence,
    brand: Brand<'scope, G>,
}
pub struct Ready<'scope, G: ResourceGuard<C>, C: AuthorityContext = Exercise> {
    proof: Justification<'scope, G, C>,
    witness: G::Witness,
}
pub struct Authorized<'scope, G: ResourceGuard<C>, C: AuthorityContext = Exercise> {
    ready: Ready<'scope, G, C>,
}
pub type LeaseHandoff<G, C = Exercise> = (
    Effect<<G as ResourceGuard<C>>::Action, C>,
    <G as ResourceGuard<C>>::Witness,
    DecisionRecord<C>,
    Lease<G, C>,
);

impl<G: ResourceGuard<C>, C: AuthorityContext> core::fmt::Debug for Justification<'_, G, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Justification")
            .field("record", &self.record)
            .finish_non_exhaustive()
    }
}
impl<G: ResourceGuard<C>, C: AuthorityContext> core::fmt::Debug for Ready<'_, G, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ready")
            .field("record", &self.proof.record)
            .finish_non_exhaustive()
    }
}
impl<G: ResourceGuard<C>, C: AuthorityContext> Justification<'_, G, C> {
    pub fn record(&self) -> &DecisionRecord<C> {
        &self.record
    }
}
impl<G: ResourceGuard<C>, C: AuthorityContext> Authorized<'_, G, C> {
    pub fn record(&self) -> &DecisionRecord<C> {
        &self.ready.proof.record
    }
    pub fn into_parts(self) -> (Effect<G::Action, C>, G::Witness, DecisionRecord<C>) {
        let _agreement = self.ready.proof.agreement;
        (
            self.ready.proof.effect,
            self.ready.witness,
            self.ready.proof.record,
        )
    }
    /// Deliberate handover of continuing use. It carries no reusable proof: every
    /// unit must derive, prepare and commit again at the resource boundary.
    pub fn into_lease(self, contract: LeaseContract) -> LeaseHandoff<G, C> {
        let proof = self.ready.proof;
        let lease = Lease {
            exercise: proof.effect.exercise().clone(),
            arguments: proof.effect.arguments().to_vec(),
            evidence: proof.evidence,
            profile: proof.record.profile.clone(),
            last_check: proof.record.at,
            contract,
            guard: PhantomData,
        };
        (proof.effect, self.ready.witness, proof.record, lease)
    }
}

#[derive(Debug)]
pub enum DeriveError<C = Exercise> {
    ActorMismatch,
    ActionMismatch,
    ContextMismatch,
    Judgment(Box<DecisionRecord<C>>),
}
#[derive(Debug)]
pub enum TransitionError<E> {
    ContextChanged,
    Resource(E),
}

impl<C: core::fmt::Debug> core::fmt::Display for DeriveError<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ActorMismatch => {
                f.write_str("request actor does not match authenticated ingress")
            }
            Self::ActionMismatch => f.write_str("request operation does not match resource action"),
            Self::ContextMismatch => f.write_str(
                "request subject, authority or resource does not match authenticated ingress",
            ),
            Self::Judgment(record) => write!(f, "derivation: {:?}", record.decision),
        }
    }
}
impl<C: core::fmt::Debug> core::error::Error for DeriveError<C> {}
impl<E: core::fmt::Display> core::fmt::Display for TransitionError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ContextChanged => {
                f.write_str("authority context changed; reacquire the resource scope")
            }
            Self::Resource(error) => write!(f, "resource: {error}"),
        }
    }
}
impl<E: core::error::Error + 'static> core::error::Error for TransitionError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::ContextChanged => None,
            Self::Resource(error) => Some(error),
        }
    }
}

/// The caller does not supply a basis to the live evaluator. The acquired owner
/// does. No value branded by this scope can escape through the result type.
pub fn with_resource<G: ResourceGuard<C>, C: AuthorityContext, T>(
    mut guard: G,
    use_live: impl for<'scope> FnOnce(&mut Live<'scope, G, C>) -> T,
) -> Result<T, G::Error> {
    let basis = guard.current()?;
    Ok(use_live(&mut Live {
        guard,
        basis,
        brand: PhantomData,
    }))
}

impl<'scope, G: ResourceGuard<C>, C: AuthorityContext> Live<'scope, G, C> {
    pub fn derive(
        &self,
        effect: Effect<G::Action, C>,
        evidence: &Evidence,
    ) -> Result<Justification<'scope, G, C>, DeriveError<C>> {
        effect
            .exercise()
            .matches_ingress(&self.guard.ingress())
            .map_err(|e| match e {
                IngressMismatch::Actor => DeriveError::ActorMismatch,
                IngressMismatch::Action => DeriveError::ActionMismatch,
                IngressMismatch::Context => DeriveError::ContextMismatch,
            })?;
        let evaluated = evaluate_for(&self.basis, &effect, evidence, self.guard.purpose());
        match evaluated.agreement {
            Some(agreement) => Ok(Justification {
                effect,
                agreement,
                record: evaluated.record,
                evidence: evidence.clone(),
                brand: PhantomData,
            }),
            None => Err(DeriveError::Judgment(Box::new(evaluated.record))),
        }
    }
    pub fn prepare(
        &mut self,
        mut proof: Justification<'scope, G, C>,
    ) -> Result<Ready<'scope, G, C>, TransitionError<G::Error>> {
        self.refresh(&mut proof)?;
        let witness = self
            .guard
            .prepare(&proof.effect, &proof.record.obligations)
            .map_err(TransitionError::Resource)?;
        Ok(Ready { proof, witness })
    }
    pub fn execute(
        &mut self,
        mut ready: Ready<'scope, G, C>,
    ) -> Result<G::Output, TransitionError<G::Error>> {
        self.refresh(&mut ready.proof)?;
        self.guard
            .commit(Authorized { ready })
            .map_err(TransitionError::Resource)
    }
    fn refresh(
        &mut self,
        proof: &mut Justification<'scope, G, C>,
    ) -> Result<(), TransitionError<G::Error>> {
        let record = &proof.record;
        let current = self.guard.current().map_err(TransitionError::Resource)?;
        if record
            .exercise
            .matches_ingress(&self.guard.ingress())
            .is_err()
            || self.guard.purpose() != record.purpose
            || current.fingerprint() != record.basis
            || current.at() < record.at
        {
            return Err(TransitionError::ContextChanged);
        }
        let evaluated = evaluate_for(&current, &proof.effect, &proof.evidence, record.purpose);
        let Some(agreement) = evaluated.agreement else {
            return Err(TransitionError::ContextChanged);
        };
        proof.agreement = agreement;
        proof.record = evaluated.record;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseContract {
    scope: Id,
    recheck_within: u32,
}
impl LeaseContract {
    pub fn new(scope: Id, recheck_within: u32) -> Result<Self, Invalid> {
        if recheck_within == 0 {
            return Err(Invalid::Interval);
        }
        Ok(Self {
            scope,
            recheck_within,
        })
    }
    pub fn scope(&self) -> &Id {
        &self.scope
    }
    pub fn recheck_within(&self) -> u32 {
        self.recheck_within
    }
}
pub struct Lease<G: ResourceGuard<C>, C: AuthorityContext = Exercise> {
    exercise: C,
    arguments: alloc::vec::Vec<u8>,
    evidence: Evidence,
    profile: Id,
    last_check: i64,
    contract: LeaseContract,
    guard: PhantomData<fn(G) -> G>,
}
#[derive(Debug)]
pub enum LeaseError<E, C = Exercise> {
    CheckBoundary,
    Resource(E),
    Derivation(DeriveError<C>),
    Transition(TransitionError<E>),
}
impl<G: ResourceGuard<C>, C: AuthorityContext> Lease<G, C> {
    pub fn contract(&self) -> &LeaseContract {
        &self.contract
    }
    pub fn stop(self) {}
    /// The owner calls this for each protected unit, under its named sweep bound.
    /// I/O adapters own timers/termination; the pure kernel has no background task.
    pub fn execute_unit(self, mut guard: G) -> Result<G::Output, LeaseError<G::Error, C>> {
        let current = guard.current().map_err(LeaseError::Resource)?;
        if *current.profile() != self.profile
            || current.at() < self.last_check
            || current.at().saturating_sub(self.last_check)
                > i64::from(self.contract.recheck_within)
            || guard.purpose() != Purpose::Live
        {
            return Err(LeaseError::CheckBoundary);
        }
        let effect = Effect::from_bytes(self.exercise, self.arguments);
        with_resource(guard, |live| {
            let proof = live
                .derive(effect, &self.evidence)
                .map_err(LeaseError::Derivation)?;
            let ready = live.prepare(proof).map_err(LeaseError::Transition)?;
            live.execute(ready).map_err(LeaseError::Transition)
        })
        .map_err(LeaseError::Resource)?
    }
}
