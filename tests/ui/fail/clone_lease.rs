#[path = "../support.rs"]
mod support;
use eudoxia::*;
use support::*;
fn duplicate(lease: Lease<Store<Read>>) {
    let _ = lease.clone();
}
fn main() {}
