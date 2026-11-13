use eudoxia::*;

fn commit(basis: Basis, ingress: KeyIngress, effect: Effect<()>) -> Result<Vec<u8>, AtomicError> {
    atomic(
        basis,
        ingress,
        Purpose::Live,
        (),
        effect,
        &Evidence::default(),
        |effect, (), _| effect.arguments().to_vec(),
    )
}
fn main() {}
