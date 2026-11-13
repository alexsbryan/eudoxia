#[path = "../support.rs"]
mod support;
use eudoxia::*;
use support::*;

fn substitute<G: ResourceGuard<Action = Read, Witness = Reservation>>(
    real: &mut Store<Read>,
    another_guard: Authorized<'_, G>,
) {
    real.commit(another_guard).unwrap();
}
fn main() {}
