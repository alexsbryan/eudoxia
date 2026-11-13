#[path = "../support.rs"]
mod support;
use eudoxia::*;
use support::*;

fn substitute<'scope>(live: &mut Live<'scope, Store<Write>>, ready: Ready<'scope, Store<Read>>) {
    live.execute(ready).unwrap();
}
fn main() {}
