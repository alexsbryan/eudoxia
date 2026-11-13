use eudoxia::*;

struct AlwaysReady;
impl Enforcer for AlwaysReady {
    type Output = ();
    type Error = ();
    fn condition(&mut self, _: &Obligation) -> ConditionState {
        ConditionState::Ready
    }
    fn execute(&mut self, _: Permit<'_>) -> Result<(), ()> {
        Ok(())
    }
}
fn bypass(basis: &Basis, exercise: &Exercise, evidence: &Evidence) {
    let _ = perform(basis, exercise, evidence, &mut AlwaysReady);
}
fn main() {
    let _ = bypass;
}
