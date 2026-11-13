#[path = "../support.rs"]
mod support;
use eudoxia::*;
use support::*;
fn substitute(lease: Lease<Store<Read>>, guard: Store<Write>) {
    let _ = lease.execute_unit(guard);
}
fn main() {}
