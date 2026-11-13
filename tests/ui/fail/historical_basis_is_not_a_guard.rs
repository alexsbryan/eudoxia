use eudoxia::*;

fn old_snapshot(basis: Basis) {
    with_resource(basis, |_live| ()).unwrap();
}
fn main() {}
