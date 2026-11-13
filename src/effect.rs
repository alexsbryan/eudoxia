use crate::{AuthorityContext, Exercise, Fingerprint, model::fingerprint};
use alloc::vec::Vec;
use core::marker::PhantomData;
use serde::Serialize;

/// An untrusted claim, owning its exact descriptor and frozen arguments.
/// The action marker distinguishes resource APIs; it grants no authority.
pub struct Effect<A, C: AuthorityContext = Exercise> {
    exercise: C,
    arguments: Vec<u8>,
    fingerprint: Fingerprint,
    action: PhantomData<fn() -> A>,
}

impl<A, C: AuthorityContext> Effect<A, C> {
    /// The value owner supplies its bytes. No parsing or normalization occurs.
    pub fn from_bytes(exercise: C, arguments: Vec<u8>) -> Self {
        let fingerprint = fingerprint(
            b"eudoxia/effect/v4",
            &(&exercise, crate::encoding::Raw(&arguments)),
        );
        Self {
            exercise,
            arguments,
            fingerprint,
            action: PhantomData,
        }
    }
    pub fn new(exercise: C, arguments: &impl Serialize) -> Result<Self, serde_json::Error> {
        let mut value = serde_json::to_value(arguments)?;
        canonical(&mut value);
        Ok(Self::from_bytes(exercise, serde_json::to_vec(&value)?))
    }
    pub fn exercise(&self) -> &C {
        &self.exercise
    }
    pub fn arguments(&self) -> &[u8] {
        &self.arguments
    }
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }
    pub(crate) fn recorded(exercise: C, arguments: &[u8]) -> Result<Self, serde_json::Error> {
        Ok(Self::from_bytes(exercise, arguments.to_vec()))
    }
}

fn canonical(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(values) => {
            values.sort_keys();
            for value in values.values_mut() {
                canonical(value);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                canonical(value);
            }
        }
        _ => {}
    }
}
