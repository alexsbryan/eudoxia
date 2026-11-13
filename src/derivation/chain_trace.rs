//! Delegation is a sequence. Its wire observation must not acquire a recursive
//! JSON depth limit smaller than the signed u8 delegation bound.
use super::DerivationTrace;
use crate::{Fingerprint, Owner, Principal, SourceRef};
use alloc::{boxed::Box, collections::BTreeSet, vec::Vec};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _, ser::Error as _};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Root {
    basis: Fingerprint,
    owner: Owner,
    issuer: Principal,
    source: SourceRef,
    dependencies: BTreeSet<SourceRef>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    grant: Fingerprint,
    holder: Principal,
    sources: BTreeSet<SourceRef>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Chain {
    root: Root,
    steps: Vec<Step>,
}

pub(super) fn serialize<S: Serializer>(
    parent: &DerivationTrace,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut cursor = parent;
    let mut steps = Vec::new();
    loop {
        match cursor {
            DerivationTrace::Root {
                basis,
                owner,
                issuer,
                source,
                dependencies,
            } => {
                steps.reverse();
                return Chain {
                    root: Root {
                        basis: *basis,
                        owner: owner.clone(),
                        issuer: *issuer,
                        source: source.clone(),
                        dependencies: dependencies.clone(),
                    },
                    steps,
                }
                .serialize(serializer);
            }
            DerivationTrace::Delegation {
                parent,
                grant,
                holder,
                sources,
            } => {
                if steps.len() == usize::from(u8::MAX) {
                    return Err(S::Error::custom(
                        "delegation parent exceeds the signed depth bound",
                    ));
                }
                steps.push(Step {
                    grant: *grant,
                    holder: *holder,
                    sources: sources.clone(),
                });
                cursor = parent;
            }
            DerivationTrace::Agreement { .. }
            | DerivationTrace::Exercise { .. }
            | DerivationTrace::Standing { .. }
            | DerivationTrace::Admission { .. } => {
                return Err(S::Error::custom(
                    "a delegation parent must be a root or delegation",
                ));
            }
        }
    }
}

pub(super) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Box<DerivationTrace>, D::Error> {
    let chain = Chain::deserialize(deserializer)?;
    if chain.steps.len() > usize::from(u8::MAX) {
        return Err(D::Error::custom(
            "delegation parent exceeds the signed depth bound",
        ));
    }
    let mut parent = DerivationTrace::Root {
        basis: chain.root.basis,
        owner: chain.root.owner,
        issuer: chain.root.issuer,
        source: chain.root.source,
        dependencies: chain.root.dependencies,
    };
    for step in chain.steps {
        parent = DerivationTrace::Delegation {
            parent: Box::new(parent),
            grant: step.grant,
            holder: step.holder,
            sources: step.sources,
        };
    }
    Ok(Box::new(parent))
}
