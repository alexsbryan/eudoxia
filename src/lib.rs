//! Explicit authority. See docs/ARCHITECTURE.md for the trust and execution boundaries.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod atomic;
pub use atomic::{AtomicError, atomic};
mod personal;
pub use personal::{PersonalError, PersonalOperation, PersonalProfile};

mod context;
mod derivation;
mod effect;
mod encoding;
mod identity;
mod judge;
mod model;
mod profile;
mod record;
mod rules;
mod scaffold;
mod statement;

#[cfg(feature = "canon")]
pub mod canon;

pub use context::{
    Actor, AuthorityContext, AuthorityUse, Ingress, IngressMismatch, KeyIngress, Request, Subject,
};
pub use derivation::DerivationTrace;
pub use effect::Effect;
pub use identity::ContextFailure;
pub use identity::{
    Application, ApplicationAuthority, ApplicationClass, AuthorityId, AuthorityRealm, ContextNeed,
    NativeOperation, Operation, Resource, ResourceIdentity, ResourceKind,
};
pub use judge::{
    Decision, Need, OwnerDecision, OwnerJudgment, Reason, inspect, inspect_admission, judge,
};
pub use model::{
    Basis, Evidence, Exercise, Fingerprint, Id, Interval, Invalid, Obligation, Owner, OwnerProof,
    Phase, Principal,
};
pub use profile::{
    AdmissionTime, ApprovalRule, Claim, Codec, Coverage, DecodeError, Fact, FactState,
    NativeEvidence, ObservationError, Policy, Purpose, Recheck, RootInterpreter, Scope, SourceRef,
};
pub use record::{DecisionRecord, ReplayError};
pub use rules::{Asked, Condition, Rule, Ruled, Rules, Ruling, Term, Value, Verdict};
pub use scaffold::{
    Authorized, DeriveError, Justification, Lease, LeaseContract, LeaseError, LeaseHandoff, Live,
    Ready, ResourceGuard, TransitionError, with_resource,
};
pub use statement::{NativeStatement, ParsedStatement, VerifiedStatement};
