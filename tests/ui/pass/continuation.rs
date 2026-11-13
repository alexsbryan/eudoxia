#![allow(dead_code)]
use eudoxia::*;
fn lawful_handover<G: ResourceGuard>(authorized: Authorized<'_, G>) {
    let contract = LeaseContract::new(Id::new("execution").unwrap(), 2).unwrap();
    let (_effect, _witness, _record, lease) = authorized.into_lease(contract);
    lease.stop();
}
fn main() {}
