#[path = "../support.rs"]
mod support;
use eudoxia::*;
use support::*;

fn forge<'scope>(record: DecisionRecord) -> Justification<'scope, Store<Read>> {
    record.into()
}
fn main() {}
