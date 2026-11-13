use eudoxia::*;

// Exercise the constructor's input bound through a method so diagnostics name
// the failed bound, not a feature-dependent list of every String conversion.
trait LegacyInput: Sized {
    fn through_legacy_constructor(self) -> Result<Application, Invalid>;
}
impl<T: Into<String>> LegacyInput for T {
    fn through_legacy_constructor(self) -> Result<Application, Invalid> {
        Application::new(self)
    }
}

fn main() {
    let app = Application::classified(ApplicationAuthority::new(
        AuthorityRealm::Group([1; 32]),
        Id::new("notes").unwrap(),
        ApplicationClass::Record,
    ));
    let _ = app.through_legacy_constructor();
}
