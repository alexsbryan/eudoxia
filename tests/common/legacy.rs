//! Test-only migration adapter: preserve the original acceptance assertions while
//! running every effect through the new sealed construction path. Not a public API.
#![allow(dead_code)]
use eudoxia::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Terms {
    pub person: Principal,
    pub application: Application,
    pub resource: Resource,
    pub operations: BTreeSet<Operation>,
    pub interval: Interval,
    pub redelegations: u8,
}
impl From<Terms> for Scope {
    fn from(t: Terms) -> Self {
        Self {
            person: Some(t.person),
            application: Some(t.application),
            coverage: Coverage::Exact(t.resource),
            operations: t.operations,
            interval: t.interval,
            redelegations: t.redelegations,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub owner: Owner,
    pub issuer: Principal,
    pub holder: Principal,
    pub terms: Terms,
}
impl Grant {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = b"eudoxia/grant/v1\0".to_vec();
        bytes.extend(serde_json::to_vec(self).unwrap());
        bytes
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedGrant {
    pub grant: Grant,
    pub signature: Vec<u8>,
}
impl NativeStatement for SignedGrant {
    fn issuer(&self) -> Principal {
        self.grant.issuer
    }
    fn signature(&self) -> &[u8] {
        &self.signature
    }
    fn signing_message(&self) -> std::borrow::Cow<'_, [u8]> {
        self.grant.signing_bytes().into()
    }
    fn project(self: Box<Self>, binding: &SourceRef) -> Result<Claim, DecodeError> {
        Ok(Claim::Delegation {
            owner: self.grant.owner,
            holder: self.grant.holder,
            scope: self.grant.terms.into(),
            sources: [binding.clone()].into(),
        })
    }
}
pub fn codec() -> Codec {
    fn decode(bytes: &[u8]) -> Result<ParsedStatement, DecodeError> {
        let grant: SignedGrant =
            serde_json::from_slice(bytes).map_err(|_| DecodeError::Malformed)?;
        Ok(ParsedStatement::new(grant))
    }
    Codec {
        id: Id::new("eudoxia-grant-v1").unwrap(),
        decode,
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnerEvidence {
    Chain(Vec<SignedGrant>),
    Absent,
}
impl From<OwnerEvidence> for OwnerProof {
    fn from(e: OwnerEvidence) -> Self {
        match e {
            OwnerEvidence::Absent => Self::Absent,
            OwnerEvidence::Chain(chain) => Self::Native(
                chain
                    .into_iter()
                    .map(|grant| NativeEvidence {
                        codec: codec().id,
                        bytes: serde_json::to_vec(&grant).unwrap(),
                    })
                    .collect(),
            ),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OwnerPolicy {
    pub owner: Owner,
    pub issuers: BTreeSet<Principal>,
    pub terms: Terms,
    pub obligations: BTreeSet<Obligation>,
}

// Compatibility exists only in this test module. Both constructors and owner
// observations translate the one production Policy representation, never judge it.
pub trait LegacyBasis {
    fn trusted(profile: Id, at: i64, owners: Vec<OwnerPolicy>) -> Result<Basis, Invalid>;
    fn owners(&self) -> Vec<OwnerPolicy>;
}
impl LegacyBasis for Basis {
    fn trusted(profile: Id, at: i64, owners: Vec<OwnerPolicy>) -> Result<Basis, Invalid> {
        let policies: Vec<_> = owners
            .into_iter()
            .map(|p| {
                let source = SourceRef {
                    namespace: profile.clone(),
                    algorithm: Id::new("test-owner-sha256").unwrap(),
                    digest: Sha256::digest(serde_json::to_vec(&p).unwrap()).to_vec(),
                };
                Policy {
                    owner: p.owner,
                    source,
                    scope: p.terms.into(),
                    approval: ApprovalRule::Delegated(p.issuers),
                    actor: None,
                    effect: None,
                    requires: BTreeSet::new(),
                    admitters: BTreeSet::new(),
                    carriers: [codec().id].into(),
                    obligations: p.obligations,
                }
            })
            .collect();
        let facts = policies
            .iter()
            .map(|p| Fact {
                source: p.source.clone(),
                state: FactState::Established,
            })
            .collect();
        Basis::interpreted(
            profile,
            at,
            policies,
            facts,
            vec![codec()],
            Recheck::OnSourceChange,
        )
    }
    fn owners(&self) -> Vec<OwnerPolicy> {
        self.policies()
            .iter()
            .map(|p| OwnerPolicy {
                owner: p.owner.clone(),
                issuers: match &p.approval {
                    ApprovalRule::Delegated(issuers) => issuers.clone(),
                    ApprovalRule::Standing => BTreeSet::new(),
                },
                terms: Terms {
                    person: p.scope.person.unwrap(),
                    application: p.scope.application.clone().unwrap(),
                    resource: match &p.scope.coverage {
                        Coverage::Exact(r) => r.clone(),
                        _ => panic!("legacy fixture has exact coverage"),
                    },
                    operations: p.scope.operations.clone(),
                    interval: p.scope.interval,
                    redelegations: p.scope.redelegations,
                },
                obligations: p.obligations.clone(),
            })
            .collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditionState {
    Ready,
    Unknown,
    Unenforceable,
}
pub trait Enforcer {
    type Output;
    type Error;
    fn condition(&mut self, obligation: &Obligation) -> ConditionState;
    fn execute(&mut self, permit: Permit<'_>) -> Result<Self::Output, Self::Error>;
}
pub struct Permit<'a> {
    record: &'a DecisionRecord,
}
impl Permit<'_> {
    pub fn exercise(&self) -> &Exercise {
        &self.record.exercise
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum ExecutionError<E> {
    NotPermitted(Decision),
    Condition {
        obligation: Obligation,
        state: ConditionState,
    },
    Effect(E),
    ContextChanged,
}
struct Action;
struct Witness;
struct Guard<'a, E> {
    basis: &'a Basis,
    request: &'a Exercise,
    enforcer: &'a mut E,
}
impl<E: Enforcer> ResourceGuard for Guard<'_, E> {
    type Action = Action;
    type Witness = Witness;
    type Output = E::Output;
    type Error = ExecutionError<E::Error>;
    fn ingress(&self) -> KeyIngress {
        KeyIngress {
            actor: self.request.actor,
            operation: self.request.operation.clone(),
        }
    }
    fn current(&mut self) -> Result<Basis, Self::Error> {
        Ok(self.basis.clone())
    }
    fn prepare(
        &mut self,
        _: &Effect<Action>,
        obligations: &BTreeSet<Obligation>,
    ) -> Result<Witness, Self::Error> {
        for obligation in obligations {
            let state = self.enforcer.condition(obligation);
            if state != ConditionState::Ready {
                return Err(ExecutionError::Condition {
                    obligation: obligation.clone(),
                    state,
                });
            }
        }
        Ok(Witness)
    }
    fn commit(&mut self, authorized: Authorized<'_, Self>) -> Result<Self::Output, Self::Error> {
        let (_effect, _witness, record) = authorized.into_parts();
        self.enforcer
            .execute(Permit { record: &record })
            .map_err(ExecutionError::Effect)
    }
}
fn transition<E>(error: TransitionError<ExecutionError<E>>) -> ExecutionError<E> {
    match error {
        TransitionError::ContextChanged => ExecutionError::ContextChanged,
        TransitionError::Resource(error) => error,
    }
}
pub fn perform<E: Enforcer>(
    basis: &Basis,
    request: &Exercise,
    evidence: &Evidence,
    enforcer: &mut E,
) -> Result<E::Output, ExecutionError<E::Error>> {
    with_resource(
        Guard {
            basis,
            request,
            enforcer,
        },
        |live| {
            let effect = Effect::<Action>::new(request.clone(), &())
                .expect("null fixture arguments serialize");
            let proof = live.derive(effect, evidence).map_err(|error| match error {
                DeriveError::Judgment(record) => ExecutionError::NotPermitted(record.decision),
                DeriveError::ActorMismatch
                | DeriveError::ActionMismatch
                | DeriveError::ContextMismatch => ExecutionError::NotPermitted(Decision::Refused),
            })?;
            let ready = live.prepare(proof).map_err(transition)?;
            live.execute(ready).map_err(transition)
        },
    )?
}
