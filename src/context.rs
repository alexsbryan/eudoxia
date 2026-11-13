//! Sealed request meanings; authentication is supplied independently by the owner.
use crate::*;
use alloc::{collections::BTreeSet, format};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

mod sealed {
    pub trait Sealed {}
}

/// A closed kernel context, not an extension point for permission callbacks.
pub trait AuthorityContext:
    sealed::Sealed + Clone + core::fmt::Debug + Eq + Serialize + DeserializeOwned
{
    type Actor: Copy + Eq;
    type Ingress;
    fn actor(&self) -> Self::Actor;
    fn key(&self) -> Option<Principal>;
    fn credential(&self) -> Actor;
    fn person(&self) -> Option<Principal>;
    fn application(&self) -> Option<&Application>;
    fn operation(&self) -> &Operation;
    fn resource(&self) -> &Resource;
    fn check(&self) -> Result<(), ContextFailure>;
    fn matches_ingress(&self, ingress: &Self::Ingress) -> Result<(), IngressMismatch>;
    fn required_owners(&self) -> Option<BTreeSet<Owner>>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngressMismatch {
    Actor,
    Action,
    Context,
}
#[derive(Clone)]
pub struct KeyIngress {
    pub actor: Principal,
    pub operation: Operation,
}
impl sealed::Sealed for Exercise {}
impl AuthorityContext for Exercise {
    type Actor = Principal;
    type Ingress = KeyIngress;
    fn actor(&self) -> Principal {
        self.actor
    }
    fn key(&self) -> Option<Principal> {
        Some(self.actor)
    }
    fn credential(&self) -> Actor {
        Actor::Key { key: self.actor }
    }
    fn person(&self) -> Option<Principal> {
        Some(self.person)
    }
    fn application(&self) -> Option<&Application> {
        Some(&self.application)
    }
    fn operation(&self) -> &Operation {
        &self.operation
    }
    fn resource(&self) -> &Resource {
        &self.resource
    }
    fn check(&self) -> Result<(), ContextFailure> {
        crate::identity::check_context(self)
    }
    fn matches_ingress(&self, i: &KeyIngress) -> Result<(), IngressMismatch> {
        if self.actor != i.actor {
            Err(IngressMismatch::Actor)
        } else if self.operation != i.operation {
            Err(IngressMismatch::Action)
        } else {
            Ok(())
        }
    }
    fn required_owners(&self) -> Option<BTreeSet<Owner>> {
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Actor {
    Key { key: Principal },
    Session { issuer: Principal, id: AuthorityId },
    Bearer { issuer: Principal, id: AuthorityId },
    Anonymous,
}
impl Actor {
    pub fn key(self) -> Option<Principal> {
        match self {
            Self::Key { key } => Some(key),
            _ => None,
        }
    }
}
impl From<Principal> for Actor {
    fn from(key: Principal) -> Self {
        Self::Key { key }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Subject {
    None,
    /// Personal authority under this key, before any group's identity lookup.
    /// Profile-owned operations only; never native group/resource authority.
    Principal {
        principal: Principal,
    },
    Person {
        group: AuthorityId,
        person: Principal,
    },
    Visit {
        group: AuthorityId,
        visit: AuthorityId,
        host: Principal,
        guest: Principal,
    },
}
impl Subject {
    pub fn group(self) -> Option<AuthorityId> {
        match self {
            Self::Person { group, .. } | Self::Visit { group, .. } => Some(group),
            Self::None | Self::Principal { .. } => None,
        }
    }
    pub fn person(self) -> Option<Principal> {
        match self {
            Self::Person { person, .. } => Some(person),
            Self::Principal { principal } => Some(principal),
            _ => None,
        }
    }
    fn owner(self) -> Option<Owner> {
        match self {
            Self::Person { group, person } => Some(owner(format!(
                "person:{}:{}",
                group.hex(),
                AuthorityId::from_bytes(*person.bytes()).hex()
            ))),
            Self::Visit { group, visit, .. } => {
                Some(owner(format!("visit:{}:{}", group.hex(), visit.hex())))
            }
            Self::Principal { principal } => Some(owner(format!(
                "principal:{}",
                AuthorityId::from_bytes(*principal.bytes()).hex()
            ))),
            Self::None => None,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "application",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum AuthorityUse {
    Personal,
    Application(Application),
    Public,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestWire {
    version: u8,
    request: Id,
    actor: Actor,
    subject: Subject,
    authority: AuthorityUse,
    operation: Operation,
    resource: Resource,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RequestWire", into = "RequestWire")]
pub struct Request {
    request: Id,
    actor: Actor,
    subject: Subject,
    authority: AuthorityUse,
    operation: Operation,
    resource: Resource,
}
impl Request {
    /// A profile-owned operation/resource with an explicit personal or public
    /// ingress. The acquired resource supplies the fixed owner set in Basis.
    /// Classified apps require a known intrinsic operation, never this escape.
    pub fn profile(
        request: Id,
        actor: Actor,
        subject: Subject,
        authority: AuthorityUse,
        operation: Operation,
        resource: Resource,
    ) -> Result<Self, Invalid> {
        if operation.native_kind().is_some() || resource.identity().is_some() {
            return Err(Invalid::Context);
        }
        let value = Self {
            request,
            actor,
            subject,
            authority,
            operation,
            resource,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn new(
        request: Id,
        actor: Actor,
        subject: Subject,
        authority: AuthorityUse,
        operation: NativeOperation,
        resource: ResourceIdentity,
    ) -> Result<Self, Invalid> {
        let value = Self {
            request,
            actor,
            subject,
            authority,
            operation: Operation::native(operation),
            resource: Resource::identified(resource),
        };
        value.validate()?;
        Ok(value)
    }
    pub fn request(&self) -> &Id {
        &self.request
    }
    pub fn subject(&self) -> Subject {
        self.subject
    }
    pub fn authority(&self) -> &AuthorityUse {
        &self.authority
    }
    fn validate(&self) -> Result<(), Invalid> {
        let Some(operation) = self.operation.native_kind() else {
            if self.resource.identity().is_some() {
                return Err(Invalid::Context);
            }
            return match (&self.authority, self.subject, self.actor) {
                (
                    AuthorityUse::Personal,
                    Subject::Person { .. } | Subject::Principal { .. },
                    Actor::Key { .. } | Actor::Session { .. },
                ) => Ok(()),
                (AuthorityUse::Public, Subject::None, _) => Ok(()),
                _ => Err(Invalid::Context),
            };
        };
        let resource = self.resource.identity().ok_or(Invalid::Context)?;
        if resource.kind() != operation.target_kind() {
            return Err(Invalid::Context);
        }
        if operation == NativeOperation::ReadPublicOutput {
            return if self.subject == Subject::None && self.authority == AuthorityUse::Public {
                Ok(())
            } else {
                Err(Invalid::Context)
            };
        }
        if matches!(self.actor, Actor::Anonymous)
            || matches!(self.subject, Subject::None | Subject::Principal { .. })
            || self.authority == AuthorityUse::Public
        {
            return Err(Invalid::Context);
        }
        if resource
            .group()
            .is_some_and(|group| Some(AuthorityId::from_bytes(group)) != self.subject.group())
        {
            return Err(Invalid::Context);
        }
        if let Subject::Visit { host, .. } = self.subject
            && (resource.lender() != Some(host)
                || !matches!(
                    operation,
                    NativeOperation::ReadExternal
                        | NativeOperation::SendExternal
                        | NativeOperation::UseLend
                ))
        {
            return Err(Invalid::Context);
        }
        match &self.authority {
            AuthorityUse::Personal => {
                if matches!(self.actor, Actor::Bearer { .. })
                    || matches!(
                        operation,
                        NativeOperation::ReadExternal | NativeOperation::SendExternal
                    )
                {
                    return Err(Invalid::Context);
                }
            }
            AuthorityUse::Application(app) => {
                let authority = app.authority().ok_or(Invalid::Context)?;
                if operation == NativeOperation::UseLend
                    || !operation.class_allows(authority.class())
                {
                    return Err(Invalid::Context);
                }
                if resource
                    .application()
                    .is_some_and(|id| id != authority.identity())
                {
                    return Err(Invalid::Context);
                }
                if let AuthorityRealm::Group(group) = authority.realm()
                    && self.subject.group() != Some(AuthorityId::from_bytes(group))
                {
                    return Err(Invalid::Context);
                }
            }
            AuthorityUse::Public => return Err(Invalid::Context),
        }
        if matches!(
            operation,
            NativeOperation::ReadRecord
                | NativeOperation::AppendRecord
                | NativeOperation::CorrectRecord
        ) && (!matches!(self.subject, Subject::Person { .. })
            || matches!(self.actor, Actor::Bearer { .. }))
        {
            return Err(Invalid::Context);
        }
        Ok(())
    }
}
impl TryFrom<RequestWire> for Request {
    type Error = Invalid;
    fn try_from(w: RequestWire) -> Result<Self, Invalid> {
        if w.version != 2 {
            return Err(Invalid::Version);
        }
        let value = Self {
            request: w.request,
            actor: w.actor,
            subject: w.subject,
            authority: w.authority,
            operation: w.operation,
            resource: w.resource,
        };
        value.validate()?;
        Ok(value)
    }
}
impl From<Request> for RequestWire {
    fn from(r: Request) -> Self {
        Self {
            version: 2,
            request: r.request,
            actor: r.actor,
            subject: r.subject,
            authority: r.authority,
            operation: r.operation,
            resource: r.resource,
        }
    }
}

/// Constructed by the resource after authentication/resolution, never decoded
/// from a client's descriptor. Comparing only stable person loses session scope.
#[derive(Clone)]
pub struct Ingress {
    actor: Actor,
    subject: Subject,
    authority: AuthorityUse,
    operation: Operation,
    resource: Resource,
}
impl Ingress {
    /// An owned effect described by this already acquired profile operation.
    /// It constructs data only; source derivation and preparation still follow.
    pub fn effect<A>(
        &self,
        request: Id,
        bytes: alloc::vec::Vec<u8>,
    ) -> Result<Effect<A, Request>, Invalid> {
        let value = Request {
            request,
            actor: self.actor,
            subject: self.subject,
            authority: self.authority.clone(),
            operation: self.operation.clone(),
            resource: self.resource.clone(),
        };
        value.validate()?;
        Ok(Effect::from_bytes(value, bytes))
    }
    pub fn profile(
        actor: Actor,
        subject: Subject,
        authority: AuthorityUse,
        operation: Operation,
        resource: Resource,
    ) -> Self {
        Self {
            actor,
            subject,
            authority,
            operation,
            resource,
        }
    }
    pub fn new(
        actor: Actor,
        subject: Subject,
        authority: AuthorityUse,
        operation: NativeOperation,
        resource: ResourceIdentity,
    ) -> Self {
        Self {
            actor,
            subject,
            authority,
            operation: Operation::native(operation),
            resource: Resource::identified(resource),
        }
    }
}
fn owner(s: alloc::string::String) -> Owner {
    Owner::new(s).expect("bounded full native identity")
}
/// The prefixes of the owner names `Subject::owner` and `required_owners` build.
const REQUIRED: [&str; 6] = [
    "person:",
    "visit:",
    "principal:",
    "group:",
    "lender:",
    "resource:",
];
pub(crate) fn required_form(owner: &Owner) -> bool {
    REQUIRED.iter().any(|p| owner.as_str().starts_with(p))
}
impl sealed::Sealed for Request {}
impl AuthorityContext for Request {
    type Actor = Actor;
    type Ingress = Ingress;
    fn actor(&self) -> Actor {
        self.actor
    }
    fn key(&self) -> Option<Principal> {
        self.actor.key()
    }
    fn credential(&self) -> Actor {
        self.actor
    }
    fn person(&self) -> Option<Principal> {
        self.subject.person()
    }
    fn application(&self) -> Option<&Application> {
        match &self.authority {
            AuthorityUse::Application(app) => Some(app),
            _ => None,
        }
    }
    fn operation(&self) -> &Operation {
        &self.operation
    }
    fn resource(&self) -> &Resource {
        &self.resource
    }
    fn check(&self) -> Result<(), ContextFailure> {
        Ok(())
    }
    fn matches_ingress(&self, i: &Ingress) -> Result<(), IngressMismatch> {
        if self.actor != i.actor {
            return Err(IngressMismatch::Actor);
        }
        if self.operation != i.operation {
            return Err(IngressMismatch::Action);
        }
        if self.subject != i.subject || self.authority != i.authority || self.resource != i.resource
        {
            return Err(IngressMismatch::Context);
        }
        Ok(())
    }
    fn required_owners(&self) -> Option<BTreeSet<Owner>> {
        self.operation.native_kind()?;
        let mut required = BTreeSet::new();
        if let Some(subject) = self.subject.owner() {
            required.insert(subject);
        }
        let resource = self.resource.identity().expect("native resource");
        if let Some(group) = resource.group() {
            required.insert(owner(format!(
                "group:{}",
                AuthorityId::from_bytes(group).hex()
            )));
        } else if let Some(lender) = resource.lender() {
            required.insert(owner(format!(
                "lender:{}",
                AuthorityId::from_bytes(*lender.bytes()).hex()
            )));
        } else {
            required.insert(owner(format!("resource:{}", resource.identity().hex())));
        }
        Some(required)
    }
}
