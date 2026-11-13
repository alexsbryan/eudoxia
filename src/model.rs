use crate::{Application, Operation, Resource};
use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Invalid {
    Identifier,
    Interval,
    Owners,
    Policy,
    DuplicateEvidence,
    Key,
    Version,
    Context,
}

impl core::fmt::Display for Invalid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid authority input: {self:?}")
    }
}
impl core::error::Error for Invalid {}

macro_rules! identifier {
    ($($name:ident),+) => {$(
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);
        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, Invalid> {
                let value = value.into();
                if value.is_empty() || value.len() > 256 || value.trim() != value || value.chars().any(char::is_control) {
                    return Err(Invalid::Identifier);
                }
                Ok(Self(value))
            }
            pub fn as_str(&self) -> &str { &self.0 }
        }
        impl TryFrom<String> for $name {
            type Error = Invalid;
            fn try_from(value: String) -> Result<Self, Invalid> { Self::new(value) }
        }
        impl From<$name> for String { fn from(value: $name) -> Self { value.0 } }
    )+};
}
identifier!(Id, Owner);

/// A stable public-key identity. Authentication of the actor is the caller's boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(try_from = "[u8; 32]", into = "[u8; 32]")]
pub struct Principal([u8; 32]);
impl Principal {
    pub fn new(bytes: [u8; 32]) -> Result<Self, Invalid> {
        ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| Invalid::Key)?;
        Ok(Self(bytes))
    }
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl Serialize for Principal {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}
impl TryFrom<[u8; 32]> for Principal {
    type Error = Invalid;
    fn try_from(value: [u8; 32]) -> Result<Self, Invalid> {
        Self::new(value)
    }
}
impl From<Principal> for [u8; 32] {
    fn from(value: Principal) -> Self {
        value.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint(#[serde(serialize_with = "crate::encoding::raw")] pub [u8; 32]);

pub(crate) fn fingerprint<T: Serialize>(domain: &[u8], value: &T) -> Fingerprint {
    crate::encoding::fingerprint(domain, value).expect("closed authority schema")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "(i64, i64)", into = "(i64, i64)")]
pub struct Interval {
    from: i64,
    until: i64,
}
impl Interval {
    /// A known empty set of instants, not missing temporal evidence.
    pub fn empty(at: i64) -> Self {
        Self {
            from: at,
            until: at,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.from == self.until
    }
    pub fn new(from: i64, until: i64) -> Result<Self, Invalid> {
        (from < until)
            .then_some(Self { from, until })
            .ok_or(Invalid::Interval)
    }
    pub fn from(&self) -> i64 {
        self.from
    }
    pub fn until(&self) -> i64 {
        self.until
    }
    pub fn contains(&self, at: i64) -> bool {
        self.from <= at && at < self.until
    }
    pub(crate) fn covers(&self, child: Self) -> bool {
        child.is_empty() || (self.from <= child.from && child.until <= self.until)
    }
}
impl TryFrom<(i64, i64)> for Interval {
    type Error = Invalid;
    fn try_from((from, until): (i64, i64)) -> Result<Self, Invalid> {
        if from == until {
            Ok(Self::empty(from))
        } else {
            Self::new(from, until)
        }
    }
}
impl From<Interval> for (i64, i64) {
    fn from(value: Interval) -> Self {
        (value.from, value.until)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Phase {
    Before,
    During,
    After,
}

/// Opaque, mandatory resource-owned behavior. The enforcer must understand its argument.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Obligation {
    pub kind: Id,
    pub argument: Id,
    pub phase: Phase,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exercise {
    pub request: Id,
    pub actor: Principal,
    pub person: Principal,
    pub application: Application,
    pub operation: Operation,
    pub resource: Resource,
}

#[derive(Debug)]
pub(crate) struct AuthorityData {
    pub profile: Id,
    pub policies: Vec<crate::Policy>,
    pub facts: Vec<crate::Fact>,
    pub codecs: Vec<crate::Codec>,
    pub fingerprint: Fingerprint,
    pub recheck: crate::Recheck,
}
/// An immutable, explicitly timed authority snapshot. It cannot be deserialized.
///
/// ```compile_fail
/// let basis: eudoxia::Basis = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct Basis {
    pub(crate) at: i64,
    pub(crate) data: Arc<AuthorityData>,
}
impl Serialize for Basis {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("Basis", 5)?;
        s.serialize_field("profile", self.profile())?;
        s.serialize_field("at", &self.at)?;
        s.serialize_field("policies", self.policies())?;
        s.serialize_field("facts", &self.data.facts)?;
        s.serialize_field("recheck", &self.data.recheck)?;
        s.end()
    }
}
impl Basis {
    pub fn at(&self) -> i64 {
        self.at
    }
    pub fn fingerprint(&self) -> Fingerprint {
        self.data.fingerprint
    }
    pub fn profile(&self) -> &Id {
        &self.data.profile
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OwnerProof {
    Native(Vec<crate::NativeEvidence>),
    Admitted {
        proof: alloc::boxed::Box<Self>,
        receipt: crate::NativeEvidence,
    },
    /// The trusted evidence resolver establishes absence. Omission alone never does.
    Absent,
}

#[derive(Clone, Debug)]
pub struct Evidence {
    entries: Arc<BTreeMap<Owner, OwnerProof>>,
    fingerprint: Fingerprint,
}
impl Serialize for Evidence {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.entries.as_ref().serialize(s)
    }
}
impl Default for Evidence {
    fn default() -> Self {
        Self::new(core::iter::empty::<(Owner, OwnerProof)>()).expect("empty evidence map is valid")
    }
}
impl Evidence {
    pub fn new<P: Into<OwnerProof>>(
        entries: impl IntoIterator<Item = (Owner, P)>,
    ) -> Result<Self, Invalid> {
        let mut values = BTreeMap::new();
        for (owner, evidence) in entries {
            if values.insert(owner, evidence.into()).is_some() {
                return Err(Invalid::DuplicateEvidence);
            }
        }
        let fingerprint = fingerprint(b"evidence/v1", &values);
        Ok(Self {
            entries: Arc::new(values),
            fingerprint,
        })
    }
    pub(crate) fn get(&self, owner: &Owner) -> Option<&OwnerProof> {
        self.entries.get(owner)
    }
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }
}
