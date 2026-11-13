use eudoxia::*;

fn downgrade<'scope, G: ResourceGuard<Request> + ResourceGuard>(
    proof: Justification<'scope, G, Request>,
) -> Justification<'scope, G> {
    proof
}
fn main() {}
