//! Class/realm identities are immutable untrusted definitions, not permissions.
//! docs/IDENTITIES.md is their byte contract, independent of report encoding.
use crate::{Exercise, Id, Invalid, Principal};
use alloc::{boxed::Box, string::String};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuthorityId(#[serde(serialize_with = "crate::encoding::raw")] [u8; 32]);
impl AuthorityId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    /// An issuer/profile-bound session name. This identifies original bytes; it
    /// does not authenticate possession or promote a label into a signing key.
    pub fn session(issuer: Principal, namespace: &Id, original: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(b"eudoxia/session/v1\0");
        h.update(issuer.bytes());
        name(&mut h, namespace);
        h.update((original.len() as u64).to_be_bytes());
        h.update(original);
        finished(h)
    }
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn hex(&self) -> String {
        self.0
            .iter()
            .flat_map(|b| {
                [
                    char::from(b"0123456789abcdef"[(b >> 4) as usize]),
                    char::from(b"0123456789abcdef"[(b & 15) as usize]),
                ]
            })
            .collect()
    }
    pub fn origin_label(&self) -> String {
        const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
        let mut out = String::from("a");
        let (mut bits, mut acc) = (0_u32, 0_u32);
        for b in self.0 {
            acc = (acc << 8) | u32::from(b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(char::from(ALPHABET[((acc >> bits) & 31) as usize]));
            }
        }
        if bits > 0 {
            out.push(char::from(ALPHABET[((acc << (5 - bits)) & 31) as usize]));
        }
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "id",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum AuthorityRealm {
    Group(#[serde(serialize_with = "crate::encoding::raw")] [u8; 32]),
    Computer(Principal),
}
impl AuthorityRealm {
    fn encode(self, h: &mut Sha256) {
        match self {
            Self::Group(id) => {
                h.update([0]);
                h.update(id);
            }
            Self::Computer(key) => {
                h.update([1]);
                h.update(key.bytes());
            }
        }
    }
}
fn name(h: &mut Sha256, value: &Id) {
    h.update((value.as_str().len() as u64).to_be_bytes());
    h.update(value.as_str().as_bytes());
}
fn finished(h: Sha256) -> AuthorityId {
    AuthorityId(h.finalize().into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApplicationClass {
    Record,
    Connector,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "ApplicationDefinition", into = "ApplicationDefinition")]
pub struct ApplicationAuthority {
    realm: AuthorityRealm,
    name: Id,
    class: ApplicationClass,
    identity: AuthorityId,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplicationDefinition {
    version: u8,
    realm: AuthorityRealm,
    name: Id,
    class: ApplicationClass,
}
impl ApplicationAuthority {
    pub fn new(realm: AuthorityRealm, name_: Id, class: ApplicationClass) -> Self {
        let mut h = Sha256::new();
        h.update(b"eudoxia/application-identity/v1\0");
        realm.encode(&mut h);
        name(&mut h, &name_);
        h.update([match class {
            ApplicationClass::Record => 0,
            ApplicationClass::Connector => 1,
        }]);
        Self {
            realm,
            name: name_,
            class,
            identity: finished(h),
        }
    }
    pub fn realm(&self) -> AuthorityRealm {
        self.realm
    }
    pub fn name(&self) -> &Id {
        &self.name
    }
    pub fn class(&self) -> ApplicationClass {
        self.class
    }
    pub fn identity(&self) -> AuthorityId {
        self.identity
    }
    pub fn origin_label(&self) -> String {
        self.identity.origin_label()
    }
}
impl TryFrom<ApplicationDefinition> for ApplicationAuthority {
    type Error = Invalid;
    fn try_from(d: ApplicationDefinition) -> Result<Self, Invalid> {
        if d.version != 1 {
            return Err(Invalid::Version);
        }
        Ok(Self::new(d.realm, d.name, d.class))
    }
}
impl From<ApplicationAuthority> for ApplicationDefinition {
    fn from(a: ApplicationAuthority) -> Self {
        Self {
            version: 1,
            realm: a.realm,
            name: a.name,
            class: a.class,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceKind {
    RecordPart,
    Lend,
    AppEndpoint,
    NativeBroker,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum ResourceDefinition {
    RecordPart {
        #[serde(serialize_with = "crate::encoding::raw")]
        group: [u8; 32],
        application: AuthorityId,
    },
    Lend {
        owner: Principal,
        name: Id,
    },
    AppEndpoint {
        application: AuthorityId,
    },
    NativeBroker {
        realm: AuthorityRealm,
        name: Id,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceWire {
    version: u8,
    definition: ResourceDefinition,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "ResourceWire", into = "ResourceWire")]
pub struct ResourceIdentity {
    definition: ResourceDefinition,
    identity: AuthorityId,
}
impl ResourceIdentity {
    fn new(definition: ResourceDefinition) -> Self {
        let mut h = Sha256::new();
        h.update(b"eudoxia/resource-identity/v1\0");
        match &definition {
            ResourceDefinition::RecordPart { group, application } => {
                h.update([0]);
                h.update(group);
                h.update(application.bytes());
            }
            ResourceDefinition::Lend { owner, name: n } => {
                h.update([1]);
                h.update(owner.bytes());
                name(&mut h, n);
            }
            ResourceDefinition::AppEndpoint { application } => {
                h.update([2]);
                h.update(application.bytes());
            }
            ResourceDefinition::NativeBroker { realm, name: n } => {
                h.update([3]);
                realm.encode(&mut h);
                name(&mut h, n);
            }
        }
        Self {
            definition,
            identity: finished(h),
        }
    }
    pub fn record_part(group: [u8; 32], application: &ApplicationAuthority) -> Self {
        Self::new(ResourceDefinition::RecordPart {
            group,
            application: application.identity(),
        })
    }
    pub fn lend(owner: Principal, name: Id) -> Self {
        Self::new(ResourceDefinition::Lend { owner, name })
    }
    pub fn app_endpoint(application: &ApplicationAuthority) -> Self {
        Self::new(ResourceDefinition::AppEndpoint {
            application: application.identity(),
        })
    }
    pub fn native_broker(realm: AuthorityRealm, name: Id) -> Self {
        Self::new(ResourceDefinition::NativeBroker { realm, name })
    }
    pub fn identity(&self) -> AuthorityId {
        self.identity
    }
    pub fn kind(&self) -> ResourceKind {
        match self.definition {
            ResourceDefinition::RecordPart { .. } => ResourceKind::RecordPart,
            ResourceDefinition::Lend { .. } => ResourceKind::Lend,
            ResourceDefinition::AppEndpoint { .. } => ResourceKind::AppEndpoint,
            ResourceDefinition::NativeBroker { .. } => ResourceKind::NativeBroker,
        }
    }
    pub(crate) fn application(&self) -> Option<AuthorityId> {
        match self.definition {
            ResourceDefinition::RecordPart { application, .. }
            | ResourceDefinition::AppEndpoint { application } => Some(application),
            _ => None,
        }
    }
    pub(crate) fn group(&self) -> Option<[u8; 32]> {
        match self.definition {
            ResourceDefinition::RecordPart { group, .. } => Some(group),
            _ => None,
        }
    }
    pub(crate) fn lender(&self) -> Option<Principal> {
        match self.definition {
            ResourceDefinition::Lend { owner, .. } => Some(owner),
            _ => None,
        }
    }
}
impl TryFrom<ResourceWire> for ResourceIdentity {
    type Error = Invalid;
    fn try_from(w: ResourceWire) -> Result<Self, Invalid> {
        if w.version != 1 {
            return Err(Invalid::Version);
        }
        Ok(Self::new(w.definition))
    }
}
impl From<ResourceIdentity> for ResourceWire {
    fn from(r: ResourceIdentity) -> Self {
        Self {
            version: 1,
            definition: r.definition,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeOperation {
    ReadRecord,
    AppendRecord,
    CorrectRecord,
    ReadExternal,
    SendExternal,
    UseOwnEndpoint,
    ReadBrokerStatus,
    ReadPublicOutput,
    UseLend,
}
impl NativeOperation {
    pub(crate) fn class_allows(self, class: ApplicationClass) -> bool {
        !matches!(
            (class, self),
            (
                ApplicationClass::Record,
                Self::ReadExternal | Self::SendExternal
            ) | (
                ApplicationClass::Connector,
                Self::AppendRecord | Self::CorrectRecord
            )
        )
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadRecord => "native/read-record",
            Self::AppendRecord => "native/append-record",
            Self::CorrectRecord => "native/correct-record",
            Self::ReadExternal => "native/read-external",
            Self::SendExternal => "native/send-external",
            Self::UseOwnEndpoint => "native/use-own-endpoint",
            Self::ReadBrokerStatus => "native/read-broker-status",
            Self::ReadPublicOutput => "native/read-public-output",
            Self::UseLend => "native/use-lend",
        }
    }
    pub(crate) fn target_kind(self) -> ResourceKind {
        match self {
            Self::ReadRecord | Self::AppendRecord | Self::CorrectRecord => ResourceKind::RecordPart,
            Self::ReadExternal | Self::SendExternal | Self::ReadPublicOutput | Self::UseLend => {
                ResourceKind::Lend
            }
            Self::UseOwnEndpoint => ResourceKind::AppEndpoint,
            Self::ReadBrokerStatus => ResourceKind::NativeBroker,
        }
    }
}

// Legacy string is an explicitly different wire form, never a shorthand for a
// classified identity. Derived labels are cached presentation, not equality.
// Keep the larger native descriptor/cache behind one owned pointer, rather than
// increasing every legacy Scope/Claim by the largest descriptor's inline size.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Named<N> {
    Legacy(Id),
    Native(Box<(N, String)>),
}
macro_rules! refined_name {
    ($ty:ident,$wire:ident,$wire_name:literal,$native:ty,$ctor:ident,$getter:ident,$label:expr) => {
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(from=$wire_name,into=$wire_name)]
        pub struct $ty {
            value: Named<$native>,
        }
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(untagged)]
        enum $wire {
            Legacy(Id),
            Native($native),
        }
        impl $ty {
            pub fn new(value: impl Into<String>) -> Result<Self, Invalid> {
                Ok(Self::from($wire::Legacy(Id::new(value)?)))
            }
            pub fn $ctor(value: $native) -> Self {
                Self::from($wire::Native(value))
            }
            pub fn $getter(&self) -> Option<&$native> {
                match &self.value {
                    Named::Native(n) => Some(&n.0),
                    _ => None,
                }
            }
            pub fn as_str(&self) -> &str {
                match &self.value {
                    Named::Legacy(n) => n.as_str(),
                    Named::Native(n) => &n.1,
                }
            }
        }
        impl From<$wire> for $ty {
            fn from(value: $wire) -> Self {
                let value = match value {
                    $wire::Legacy(n) => Named::Legacy(n),
                    $wire::Native(n) => {
                        let label = ($label)(&n);
                        Named::Native(Box::new((n, label)))
                    }
                };
                Self { value }
            }
        }
        impl From<$ty> for $wire {
            fn from(value: $ty) -> Self {
                match value.value {
                    Named::Legacy(n) => Self::Legacy(n),
                    Named::Native(n) => Self::Native(n.0),
                }
            }
        }
        impl TryFrom<String> for $ty {
            type Error = Invalid;
            fn try_from(s: String) -> Result<Self, Invalid> {
                Self::new(s)
            }
        }
    };
}
// serde conversion attributes require type-name literals rather than macro ids.
refined_name!(
    Application,
    ApplicationValue,
    "ApplicationValue",
    ApplicationAuthority,
    classified,
    authority,
    |a: &ApplicationAuthority| alloc::format!("app:{}", a.identity().hex())
);
refined_name!(
    Resource,
    ResourceValue,
    "ResourceValue",
    ResourceIdentity,
    identified,
    identity,
    |r: &ResourceIdentity| alloc::format!("resource:{}", r.identity().hex())
);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(from = "OperationValue", into = "OperationValue")]
pub struct Operation {
    value: OperationValue,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum OperationValue {
    Legacy(Id),
    Native { native: NativeOperation },
}
impl Operation {
    pub fn new(value: impl Into<String>) -> Result<Self, Invalid> {
        Ok(Self::from(OperationValue::Legacy(Id::new(value)?)))
    }
    pub fn native(value: NativeOperation) -> Self {
        Self::from(OperationValue::Native { native: value })
    }
    pub fn native_kind(&self) -> Option<NativeOperation> {
        match self.value {
            OperationValue::Native { native } => Some(native),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &str {
        match &self.value {
            OperationValue::Legacy(id) => id.as_str(),
            OperationValue::Native { native } => native.as_str(),
        }
    }
}
impl From<OperationValue> for Operation {
    fn from(value: OperationValue) -> Self {
        Self { value }
    }
}
impl From<Operation> for OperationValue {
    fn from(o: Operation) -> Self {
        o.value
    }
}
impl TryFrom<String> for Operation {
    type Error = Invalid;
    fn try_from(s: String) -> Result<Self, Invalid> {
        Self::new(s)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ContextNeed {
    ApplicationIdentity,
    ResourceIdentity,
    OperationMeaning,
    ExecutionContext,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextFailure {
    Missing(ContextNeed),
    ClassDenied,
    ResourceMismatch,
}
pub(crate) fn check_context(e: &Exercise) -> Result<(), ContextFailure> {
    let (app, resource, operation) = (
        e.application.authority(),
        e.resource.identity(),
        e.operation.native_kind(),
    );
    if app.is_none() && resource.is_none() && operation.is_none() {
        return Ok(());
    }
    let app = app.ok_or(ContextFailure::Missing(ContextNeed::ApplicationIdentity))?;
    let resource = resource.ok_or(ContextFailure::Missing(ContextNeed::ResourceIdentity))?;
    let operation = operation.ok_or(ContextFailure::Missing(ContextNeed::OperationMeaning))?;
    if matches!(
        operation,
        NativeOperation::ReadPublicOutput | NativeOperation::UseLend
    ) {
        return Err(ContextFailure::Missing(ContextNeed::ExecutionContext));
    }
    if !operation.class_allows(app.class()) {
        return Err(ContextFailure::ClassDenied);
    }
    if resource.kind() != operation.target_kind()
        || resource
            .application()
            .is_some_and(|id| id != app.identity())
    {
        return Err(ContextFailure::ResourceMismatch);
    }
    if let (AuthorityRealm::Group(expected), ResourceDefinition::RecordPart { group, .. }) =
        (app.realm(), &resource.definition)
        && expected != *group
    {
        return Err(ContextFailure::ResourceMismatch);
    }
    Ok(())
}
