#[path = "../support.rs"]
mod support;
use eudoxia::*;
use support::*;

fn lawful(store: Store<Read>, request: Exercise, evidence: &Evidence) {
    with_resource(store, |live| {
        let effect = Effect::<Read>::new(request, &42_u32).unwrap();
        let proof = live.derive(effect, evidence).unwrap();
        let _record = proof.record();
        let ready = live.prepare(proof).unwrap();
        let _output = live.execute(ready).unwrap();
    })
    .unwrap();
}
fn main() {
    let _ = lawful;
}
