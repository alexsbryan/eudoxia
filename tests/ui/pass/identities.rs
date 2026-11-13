use eudoxia::*;

fn main() {
    let app = ApplicationAuthority::new(
        AuthorityRealm::Group([1; 32]),
        Id::new("notes").unwrap(),
        ApplicationClass::Record,
    );
    let part = Resource::identified(ResourceIdentity::record_part([1; 32], &app));
    let application = Application::classified(app);
    let operation = Operation::native(NativeOperation::AppendRecord);
    let wire = serde_json::to_vec(&(application.clone(), part, operation)).unwrap();
    let decoded: (Application, Resource, Operation) = serde_json::from_slice(&wire).unwrap();
    assert_eq!(decoded.0, application);
}
