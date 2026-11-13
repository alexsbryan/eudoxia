#[path = "../support.rs"]
mod support;
use eudoxia::*;
use support::*;

fn cross(first: Store<Read>, second: Store<Read>, request: Exercise, evidence: &Evidence) {
    with_resource(first, |live| {
        let proof = live
            .derive(Effect::<Read>::new(request, &()).unwrap(), evidence)
            .unwrap();
        with_resource(second, |other| {
            other.prepare(proof).unwrap();
        })
        .unwrap();
    })
    .unwrap();
}
fn main() {}
