#[path = "../support.rs"]
mod support;
use eudoxia::*;
use support::*;

fn skip(store: Store<Read>, request: Exercise, evidence: &Evidence) {
    with_resource(store, |live| {
        let proof = live
            .derive(Effect::<Read>::new(request, &()).unwrap(), evidence)
            .unwrap();
        live.execute(proof).unwrap();
    })
    .unwrap();
}
fn main() {}
