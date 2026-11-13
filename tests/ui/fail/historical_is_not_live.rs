#[path = "../support.rs"]
mod support;
use eudoxia::*;
use support::*;

fn replay(store: Store<Read>, record: DecisionRecord, basis: &Basis, evidence: &Evidence) {
    let historical = record.replay(basis, evidence).unwrap();
    with_resource(store, |live| {
        live.prepare(historical).unwrap();
    })
    .unwrap();
}
fn main() {}
