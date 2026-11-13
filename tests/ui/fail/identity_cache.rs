use eudoxia::*;

fn main() {
    let mut app = ApplicationAuthority::new(
        AuthorityRealm::Group([1; 32]),
        Id::new("notes").unwrap(),
        ApplicationClass::Record,
    );
    app.identity = AuthorityId::from_bytes([0; 32]);
}
