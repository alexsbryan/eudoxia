#[path = "../support.rs"]
mod support;
use eudoxia::*;
use support::*;
fn reuse(lease: Lease<Store<Read>>) {
    lease.stop();
    lease.stop();
}
fn main() {}
