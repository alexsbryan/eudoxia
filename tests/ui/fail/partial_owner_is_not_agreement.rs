#[path = "../support.rs"]
mod support;
use eudoxia::*;
use support::*;

fn partial<'scope>(one_owner: OwnerJudgment) -> Justification<'scope, Store<Read>> {
    one_owner.into()
}
fn main() {}
