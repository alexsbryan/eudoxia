#[path = "../support.rs"]
mod support;
use eudoxia::*;
use support::*;

fn escape(
    store: Store<Read>,
    request: Exercise,
    evidence: &Evidence,
) -> Ready<'static, Store<Read>> {
    with_resource(store, |live| {
        let proof = live
            .derive(Effect::<Read>::new(request, &()).unwrap(), evidence)
            .unwrap();
        live.prepare(proof).unwrap()
    })
    .unwrap()
}
fn main() {}
