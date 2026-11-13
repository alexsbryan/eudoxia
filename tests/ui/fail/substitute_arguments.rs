#[path = "../support.rs"]
mod support;
use eudoxia::*;
use support::*;

fn substitute<'scope>(
    live: &mut Live<'scope, Store<Read>>,
    ready: Ready<'scope, Store<Read>>,
    another: Effect<Read>,
) {
    live.execute(ready, another).unwrap();
}
fn main() {}
