// SPDX-License-Identifier: AGPL-3.0-or-later
//! Community-profile source meaning. Source handles retain the original carrier's
//! identity type; names and device descriptions are data supplied by that carrier.
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupPolicy {
    SourcesV1,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "id",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum AuthorityRef<I: Ord> {
    Genesis,
    Act(I),
}

/// A recovery's own view: the people it counts, and the position (`through`)
/// it read on every chain it counted. A person admitted under an invite at or
/// before its inviter's position, and missing here, contests the recovery.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeopleSnapshot<I: Ord, N> {
    pub through: BTreeSet<I>,
    pub people: BTreeMap<String, N>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceMember<I: Ord, N, D> {
    pub first: String,
    pub person: N,
    pub device: D,
    pub source: AuthorityRef<I>,
}

impl<I: Ord, N, D> SourceMember<I, N, D> {
    /// A member the roots name at genesis.
    pub fn root(first: String, person: N, device: D) -> Self {
        let source = AuthorityRef::Genesis;
        Self {
            first,
            person,
            device,
            source,
        }
    }
}

/// Carriers include these control meanings in their original signed statements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorityChange<I: Ord, N> {
    RecoveryProposal {
        choice: RecoveryChoice<I, N>,
    },
    RecoveryVote {
        proposal: I,
    },
    RecoveryCommit {
        proposal: I,
        votes: BTreeMap<String, I>,
        snapshot: PeopleSnapshot<I, N>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OfficeDispute<I: Ord> {
    Claims {
        source: AuthorityRef<I>,
        branches: BTreeSet<I>,
    },
    Vacancy {
        source: AuthorityRef<I>,
        exits: BTreeSet<I>,
    },
    /// A hand-on neither accepted nor withdrawn: the office is Pending, and
    /// its holder's device may be gone.
    Unaccepted { source: AuthorityRef<I>, hand_on: I },
}
impl<I: Ord> OfficeDispute<I> {
    pub fn source(&self) -> &AuthorityRef<I> {
        match self {
            Self::Claims { source, .. }
            | Self::Vacancy { source, .. }
            | Self::Unaccepted { source, .. } => source,
        }
    }
    pub fn evidence(&self) -> Vec<&I> {
        match self {
            Self::Claims { branches, .. } => branches.iter().collect(),
            Self::Vacancy { exits, .. } => exits.iter().collect(),
            Self::Unaccepted { hand_on, .. } => alloc::vec![hand_on],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryChoice<I: Ord, N> {
    pub dispute: OfficeDispute<I>,
    pub target: String,
    /// Only these original, source-proven voluntary exits narrow the frozen
    /// constituency. An old denied proposal is not promoted by a later exit.
    pub departed: BTreeSet<I>,
    pub snapshot: PeopleSnapshot<I, N>,
}
