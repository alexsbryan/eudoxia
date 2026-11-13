#![allow(dead_code)]
use eudoxia::*;
use std::collections::BTreeSet;

pub struct Read;
pub struct Write;
pub struct Reservation {
    _held: (),
}
pub struct Store<A> {
    pub basis: Basis,
    operation: Operation,
    _action: std::marker::PhantomData<A>,
}
impl<A> Store<A> {
    pub fn new(basis: Basis, operation: Operation) -> Self {
        Self {
            basis,
            operation,
            _action: std::marker::PhantomData,
        }
    }
}
impl<A> ResourceGuard for Store<A> {
    type Action = A;
    type Witness = Reservation;
    type Output = (Exercise, Vec<u8>);
    type Error = &'static str;
    fn ingress(&self) -> KeyIngress {
        KeyIngress {
            actor: self.basis.policies()[0].scope.person.unwrap(),
            operation: self.operation.clone(),
        }
    }
    fn current(&mut self) -> Result<Basis, Self::Error> {
        Ok(self.basis.clone())
    }
    fn prepare(
        &mut self,
        _: &Effect<A>,
        obligations: &BTreeSet<Obligation>,
    ) -> Result<Reservation, Self::Error> {
        if !obligations.is_empty() {
            return Err("unsupported obligation");
        }
        Ok(Reservation { _held: () })
    }
    fn commit(&mut self, authorized: Authorized<'_, Self>) -> Result<Self::Output, Self::Error> {
        let (effect, _reservation, _record) = authorized.into_parts();
        Ok((effect.exercise().clone(), effect.arguments().to_vec()))
    }
}
