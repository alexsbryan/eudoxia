//! Legacy construction syntax only; Canon's actual interpreter and the single
//! production profile/derivation still make every institutional decision.
use super::*;
pub use eudoxia::canon::Identity;
pub struct Binding {
    pub owner: Owner,
    pub scope: canon_core::Scope,
    pub terms: Terms,
    pub obligations: BTreeSet<Obligation>,
}
pub fn establish(
    log: &canon_core::Log,
    arrangements: &canon_institution::Arrangements,
    at: i64,
    profile: Id,
    bindings: Vec<Binding>,
    identities: &[Identity],
) -> Result<Basis, eudoxia::canon::CanonError> {
    let bindings = bindings
        .into_iter()
        .map(|b| eudoxia::canon::Binding {
            owner: b.owner,
            scope: b.scope,
            authority: b.terms.into(),
            carriers: [legacy::codec().id].into(),
            obligations: b.obligations,
        })
        .collect();
    eudoxia::canon::establish(
        log.acts(),
        arrangements,
        at,
        profile,
        bindings,
        identities,
        vec![legacy::codec()],
    )
}
