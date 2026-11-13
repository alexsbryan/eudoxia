use eudoxia::*;

fn lawful<G: ResourceGuard<Request>>(guard: G, request: Request, evidence: &Evidence) {
    let _ = with_resource(guard, |live| {
        if let Ok(proof) = live.derive(Effect::from_bytes(request, vec![]), evidence) {
            if let Ok(ready) = live.prepare(proof) {
                let _ = live.execute(ready);
            }
        }
    });
}

fn main() {
    let _ = Request::new;
}
