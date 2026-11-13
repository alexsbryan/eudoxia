//! Fixed single-owner personal profiles. These are interpreted input data, never
//! execution proofs: installed interpreters remain responsible for authentic
//! source meaning, and every effect uses the ordinary resource scaffold.
use crate::*;
use alloc::vec::Vec;

pub struct PersonalProfile {
    basis: Basis,
    principal: Principal,
}
pub struct PersonalOperation<'a> {
    profile: &'a PersonalProfile,
    at: i64,
    ingress: Ingress,
}
#[derive(Debug)]
pub enum PersonalError {
    Observation(ObservationError),
    Input(Invalid),
    Execution(AtomicError<Request>),
}
impl core::fmt::Display for PersonalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "personal resource: {self:?}")
    }
}
impl core::error::Error for PersonalError {}

impl PersonalProfile {
    /// One installed profile owns one named source interpretation. The source
    /// state is explicit; this does not infer truth from a signature or an ID.
    /// Unscoped principal subjects cannot stand in for intrinsic app operations.
    pub fn interpreted(
        profile: Id,
        at: i64,
        source: Fact,
        scope: Scope,
        actor: Actor,
    ) -> Result<Self, Invalid> {
        let principal = scope.person.ok_or(Invalid::Context)?;
        if scope.application.is_some() {
            return Err(Invalid::Context);
        }
        let owner = Owner::new(profile.as_str())?;
        let policy = Policy::standing(owner, source.source, scope, Some(actor));
        Ok(Self {
            basis: Basis::single(profile, at, policy, source.state)?,
            principal,
        })
    }
    pub fn principal(&self) -> Principal {
        self.principal
    }
    pub fn scope(&self) -> &Scope {
        &self.basis.policies()[0].scope
    }
    pub fn actor(&self) -> Actor {
        self.basis.policies()[0]
            .actor
            .expect("personal profile binds its actor")
    }
    pub fn actor_matches(&self, actor: Actor) -> bool {
        self.basis.policies()[0].actor_matches(actor)
    }
    /// Interpret an authenticated descendant source under the same personal
    /// binding. It cannot widen the generic scope, drop parent dependencies or
    /// turn a missing descendant source into established authority. The actual
    /// protocol's issuer/alias binding is still the interpreter's obligation.
    pub fn attenuated(&self, source: Fact, scope: Scope, actor: Actor) -> Result<Self, Invalid> {
        if !self.scope().covers(&scope, true) {
            return Err(Invalid::Policy);
        }
        let mut policy = self.basis.policies()[0].clone();
        policy.requires.insert(policy.source.clone());
        policy.source = source.source.clone();
        policy.scope = scope;
        policy.actor = Some(actor);
        let mut facts = self.basis.data.facts.clone();
        facts.push(source);
        Ok(Self {
            basis: Basis::interpreted(
                self.basis.profile().clone(),
                self.basis.at(),
                alloc::vec![policy],
                facts,
                Vec::new(),
                Recheck::OnSourceChange,
            )?,
            principal: self.principal,
        })
    }
    pub fn operation(
        &self,
        at: i64,
        actor: Actor,
        operation: Operation,
        resource: Resource,
    ) -> PersonalOperation<'_> {
        PersonalOperation {
            profile: self,
            at,
            ingress: Ingress::profile(
                actor,
                Subject::Principal {
                    principal: self.principal,
                },
                AuthorityUse::Personal,
                operation,
                resource,
            ),
        }
    }
}
impl PersonalOperation<'_> {
    /// The owner's FnOnce captures exclusive state; fixed original bytes enter
    /// separately. Missing sources, rejected scopes and obligations run no commit.
    pub fn commit<T>(
        self,
        purpose: Purpose,
        bytes: Vec<u8>,
        apply: impl FnOnce() -> T,
    ) -> Result<T, PersonalError> {
        let basis = self
            .profile
            .basis
            .observed_at(self.at)
            .map_err(PersonalError::Observation)?;
        let effect = self
            .ingress
            .effect::<()>(Id::new("personal-operation").unwrap(), bytes)
            .map_err(PersonalError::Input)?;
        atomic(
            basis,
            self.ingress,
            purpose,
            apply,
            effect,
            &Evidence::default(),
            |_, apply, _| apply(),
        )
        .map_err(PersonalError::Execution)
    }
}
