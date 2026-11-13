use eudoxia::*;

fn forge(basis: Basis, ingress: KeyIngress, record: DecisionRecord) {
    atomic(
        basis,
        ingress,
        Purpose::Live,
        (),
        record,
        &Evidence::default(),
        |_: Effect<()>, (), _: DecisionRecord| (),
    );
}
fn main() {}
