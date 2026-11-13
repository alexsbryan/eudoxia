//! Installed carrier boundary; original message and projection share one value.
use crate::{Claim, DecodeError, Principal, SourceRef};
use alloc::{borrow::Cow, boxed::Box};

/// Implemented by a compiled native carrier over private immutable parsed data.
/// Its projection must be proved no wider than its original signed meaning.
pub trait NativeStatement: Send + Sync {
    fn issuer(&self) -> Principal;
    fn signature(&self) -> &[u8];
    fn signing_message(&self) -> Cow<'_, [u8]>;
    fn project(self: Box<Self>, binding: &SourceRef) -> Result<Claim, DecodeError>;
}
pub struct ParsedStatement(Box<dyn NativeStatement>);
pub struct VerifiedStatement {
    statement: ParsedStatement,
}
impl ParsedStatement {
    pub fn new<S: NativeStatement + 'static>(statement: S) -> Self {
        Self(Box::new(statement))
    }
    pub(crate) fn verify(self) -> Result<VerifiedStatement, DecodeError> {
        verify(self.issuer(), &self.signing_message(), self.signature())?;
        Ok(VerifiedStatement { statement: self })
    }
}
impl NativeStatement for ParsedStatement {
    fn issuer(&self) -> Principal {
        self.0.issuer()
    }
    fn signature(&self) -> &[u8] {
        self.0.signature()
    }
    fn signing_message(&self) -> Cow<'_, [u8]> {
        self.0.signing_message()
    }
    fn project(self: Box<Self>, binding: &SourceRef) -> Result<Claim, DecodeError> {
        self.0.project(binding)
    }
}
impl VerifiedStatement {
    pub fn issuer(&self) -> Principal {
        self.statement.issuer()
    }
    pub fn project(self, binding: &SourceRef) -> Result<Claim, DecodeError> {
        self.statement.0.project(binding)
    }
}
pub(crate) fn verify(
    issuer: Principal,
    message: &[u8],
    signature: &[u8],
) -> Result<(), DecodeError> {
    let signature = ed25519_dalek::Signature::from_slice(signature);
    let key = ed25519_dalek::VerifyingKey::from_bytes(issuer.bytes());
    if key
        .ok()
        .zip(signature.ok())
        .is_none_or(|(k, s)| k.verify_strict(message, &s).is_err())
    {
        Err(DecodeError::InvalidSignature)
    } else {
        Ok(())
    }
}
