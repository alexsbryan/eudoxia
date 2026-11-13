//! A fixed, synchronous owner uses the ordinary sealed resource transitions.
use crate::*;
use alloc::collections::BTreeSet;
use core::marker::PhantomData;

#[derive(Debug)]
pub enum AtomicError<C = Exercise> {
    Derive(DeriveError<C>),
    Transition(TransitionError<Invalid>),
}
impl<C: core::fmt::Debug> core::fmt::Display for AtomicError<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Derive(error) => error.fmt(f),
            Self::Transition(error) => error.fmt(f),
        }
    }
}
impl<C: core::fmt::Debug> core::error::Error for AtomicError<C> {}

struct Atomic<S, A, F, C: AuthorityContext> {
    basis: Basis,
    ingress: C::Ingress,
    purpose: Purpose,
    state: Option<S>,
    apply: Option<F>,
    action: PhantomData<A>,
}
impl<S, A, F, C, T> ResourceGuard<C> for Atomic<S, A, F, C>
where
    C: AuthorityContext,
    C::Ingress: Clone,
    F: FnOnce(Effect<A, C>, S, DecisionRecord<C>) -> T,
{
    type Action = A;
    type Witness = S;
    type Output = T;
    type Error = Invalid;
    fn ingress(&self) -> C::Ingress {
        self.ingress.clone()
    }
    fn current(&mut self) -> Result<Basis, Invalid> {
        Ok(self.basis.clone())
    }
    fn purpose(&self) -> Purpose {
        self.purpose
    }
    fn prepare(
        &mut self,
        _: &Effect<A, C>,
        obligations: &BTreeSet<Obligation>,
    ) -> Result<S, Invalid> {
        if !obligations.is_empty() {
            return Err(Invalid::Policy);
        }
        self.state.take().ok_or(Invalid::Policy)
    }
    fn commit(&mut self, authorized: Authorized<'_, Self, C>) -> Result<T, Invalid> {
        let (effect, state, record) = authorized.into_parts();
        Ok(self.apply.take().ok_or(Invalid::Policy)?(
            effect, state, record,
        ))
    }
}

/// One infallible owned-state transition under a fixed observation. The real
/// owner binds authoritative inputs and state before calling. Every nonempty
/// obligation set is rejected; mutable observations and I/O need a custom guard.
/// The callback receives the exact effect/state only through authorized commit.
pub fn atomic<S, A, F, C, T>(
    basis: Basis,
    ingress: C::Ingress,
    purpose: Purpose,
    state: S,
    effect: Effect<A, C>,
    evidence: &Evidence,
    apply: F,
) -> Result<T, AtomicError<C>>
where
    C: AuthorityContext,
    C::Ingress: Clone,
    F: FnOnce(Effect<A, C>, S, DecisionRecord<C>) -> T,
{
    with_resource(
        Atomic {
            basis,
            ingress,
            purpose,
            state: Some(state),
            apply: Some(apply),
            action: PhantomData,
        },
        |live| {
            let proof = live.derive(effect, evidence).map_err(AtomicError::Derive)?;
            let ready = live.prepare(proof).map_err(AtomicError::Transition)?;
            live.execute(ready).map_err(AtomicError::Transition)
        },
    )
    .map_err(|error| AtomicError::Transition(TransitionError::Resource(error)))?
}
