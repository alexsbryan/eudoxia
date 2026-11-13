//! Producer-frozen native reach-pass parser shared by the adapter witnesses.
use super::*;
use eudoxia::*;
pub use svrngs_core::pass::Pass;
pub(crate) fn bytes(s: &str) -> Result<Vec<u8>, DecodeError> {
    if !s.len().is_multiple_of(2)
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(DecodeError::Malformed);
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| DecodeError::Malformed))
        .collect()
}
pub(crate) fn principal(s: &str) -> Result<Principal, DecodeError> {
    Principal::new(bytes(s)?.try_into().map_err(|_| DecodeError::Malformed)?)
        .map_err(|_| DecodeError::Malformed)
}
// The actual native producer owns transcript and Label parsing, not this adapter.
pub fn decode(raw: &[u8]) -> Result<ParsedStatement, DecodeError> {
    let p: Pass = serde_json::from_slice(raw).map_err(|_| DecodeError::Unsupported)?;
    if p.op.is_some() || p.approval.is_some() {
        return Err(DecodeError::Unsupported);
    }
    let issuer = principal(&p.person)?;
    let signature = bytes(&p.sig)?;
    Ok(ParsedStatement::new(Statement {
        pass: p,
        issuer,
        signature,
    }))
}
struct Statement {
    pass: Pass,
    issuer: Principal,
    signature: Vec<u8>,
}
impl NativeStatement for Statement {
    fn issuer(&self) -> Principal {
        self.issuer
    }
    fn signature(&self) -> &[u8] {
        &self.signature
    }
    fn signing_message(&self) -> std::borrow::Cow<'_, [u8]> {
        self.pass.message().into()
    }
    fn project(self: Box<Self>, _binding: &SourceRef) -> Result<Claim, DecodeError> {
        let p = self.pass;
        let targets = core::iter::once(&p.app)
            .chain(&p.reads)
            .map(|r| Resource::new(r.clone()).map_err(|_| DecodeError::Malformed))
            .collect::<Result<_, _>>()?;
        Ok(Claim::Delegation {
            owner: Owner::new("person").unwrap(),
            holder: principal(&p.holder)?,
            scope: Scope {
                person: Some(principal(&p.person)?),
                application: Some(Application::new(p.app).map_err(|_| DecodeError::Malformed)?),
                coverage: Coverage::Set(targets),
                operations: [op("read")].into(),
                interval: Interval::new(i64::MIN, p.until).map_err(|_| DecodeError::Malformed)?,
                redelegations: 0,
            },
            sources: [reference(b"person")].into(),
        })
    }
}
