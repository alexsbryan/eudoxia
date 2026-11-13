//! A deliberately separate carrier. Its owner signs its original body, not a
//! SignedGrant or an Eudoxia re-encoding. This is a reference, not a svrngs codec.
use super::*;
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Body {
    Delegation {
        owner: Owner,
        holder: Principal,
        scope: Scope,
        sources: BTreeSet<SourceRef>,
    },
    Admission {
        effect: Fingerprint,
        at: i64,
        sources: BTreeSet<SourceRef>,
    },
    AdmissionWindow {
        effect: Fingerprint,
        window: Interval,
        sources: BTreeSet<SourceRef>,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub issuer: Principal,
    pub body: Vec<u8>,
    pub signature: Vec<u8>,
}
pub fn transcript(body: &[u8]) -> Vec<u8> {
    let mut t = b"reference-native/v1\0".to_vec();
    t.extend_from_slice(&(body.len() as u64).to_be_bytes());
    t.extend_from_slice(body);
    t
}
pub fn sign(body: Body, by: u8) -> NativeEvidence {
    let body = serde_json::to_vec(&body).unwrap();
    let signature = key(by).sign(&transcript(&body)).to_bytes().to_vec();
    NativeEvidence {
        codec: id("reference-native-v1"),
        bytes: serde_json::to_vec(&Envelope {
            issuer: person(by),
            body,
            signature,
        })
        .unwrap(),
    }
}
pub fn codec() -> Codec {
    Codec {
        id: id("reference-native-v1"),
        decode,
    }
}
fn decode(bytes: &[u8]) -> Result<ParsedStatement, DecodeError> {
    let env: Envelope = serde_json::from_slice(bytes).map_err(|_| DecodeError::Malformed)?;
    let body: Body = serde_json::from_slice(&env.body).map_err(|_| DecodeError::Malformed)?;
    Ok(ParsedStatement::new(Statement { env, body }))
}
struct Statement {
    env: Envelope,
    body: Body,
}
impl NativeStatement for Statement {
    fn issuer(&self) -> Principal {
        self.env.issuer
    }
    fn signature(&self) -> &[u8] {
        &self.env.signature
    }
    fn signing_message(&self) -> std::borrow::Cow<'_, [u8]> {
        transcript(&self.env.body).into()
    }
    fn project(self: Box<Self>, _binding: &SourceRef) -> Result<Claim, DecodeError> {
        Ok(match self.body {
            Body::Delegation {
                owner,
                holder,
                scope,
                sources,
            } => Claim::Delegation {
                owner,
                holder,
                scope,
                sources,
            },
            Body::Admission {
                effect,
                at,
                sources,
            } => Claim::Admission {
                effect,
                when: AdmissionTime::At(at),
                sources,
            },
            Body::AdmissionWindow {
                effect,
                window,
                sources,
            } => Claim::Admission {
                effect,
                when: AdmissionTime::Within(window),
                sources,
            },
        })
    }
}
pub fn chain(p: &Policy) -> OwnerEvidence {
    let mut first = p.scope.clone();
    first.person = Some(person(2));
    first.application = Some(Application::new("movie").unwrap());
    first.redelegations = 1;
    let mut last = first.clone();
    last.coverage = Coverage::Exact(Resource::new("house/library").unwrap());
    last.operations = [op("read")].into();
    last.redelegations = 0;
    OwnerEvidence::Native(vec![
        sign(
            Body::Delegation {
                owner: p.owner.clone(),
                holder: person(3),
                scope: first,
                sources: [p.source.clone()].into(),
            },
            2,
        ),
        sign(
            Body::Delegation {
                owner: p.owner.clone(),
                holder: person(4),
                scope: last,
                sources: [p.source.clone()].into(),
            },
            3,
        ),
    ])
}
