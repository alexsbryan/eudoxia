use eudoxia::*;

fn duplicate<G>(ready: Ready<'_, G>)
where
    G: ResourceGuard + Clone,
    G::Action: Clone,
    G::Witness: Clone,
{
    let _another = ready.clone();
}
fn main() {}
