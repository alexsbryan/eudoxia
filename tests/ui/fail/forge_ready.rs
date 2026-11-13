#[path = "../support.rs"]
mod support;
use eudoxia::*;
use support::*;

fn forge<'scope>(
    proof: Justification<'scope, Store<Read>>,
    witness: Reservation,
) -> Ready<'scope, Store<Read>> {
    Ready { proof, witness }
}
fn main() {}
