use eudoxia::*;
#[path = "historical/frame3.rs"]
mod historical;
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
#[test]
fn every_current_context_uses_independent_streaming_effect_vectors() {
    let e = Exercise {
        request: Id::new("vector").unwrap(),
        actor: Principal::new([0; 32]).unwrap(),
        person: Principal::new([0; 32]).unwrap(),
        application: Application::new("app").unwrap(),
        operation: Operation::new("read").unwrap(),
        resource: Resource::new("box/file").unwrap(),
    };
    for (body, expected) in [
        (
            b"".as_slice(),
            "91909bb5a6fe451813ce72b03e8babe5c5b515c63e89efe803220132943888c3",
        ),
        (
            b"{\"n\":1.00,\"s\":\"\\u0061\"}\n\xff".as_slice(),
            "efcf2a03fc50e57d98ef629f7cbe03f1924f45926955ff283baf400f673d3eed",
        ),
        (
            "\u{2603}".as_bytes(),
            "3641ba0e4ed151ee6b07e68be7ce2159f1d85ae56b3328679e5959c1c489a7e4",
        ),
    ] {
        assert_eq!(
            hex(&Effect::<()>::from_bytes(e.clone(), body.to_vec())
                .fingerprint()
                .0),
            expected
        );
    }
}
#[test]
fn independently_produced_frame3_effect_vectors() {
    let e = Exercise {
        request: Id::new("vector").unwrap(),
        actor: Principal::new([0; 32]).unwrap(),
        person: Principal::new([0; 32]).unwrap(),
        application: Application::new("app").unwrap(),
        operation: Operation::new("read").unwrap(),
        resource: Resource::new("box/file").unwrap(),
    };
    for (body, expected) in [
        (
            b"".as_slice(),
            "f01e4b6c8bd2563c52f856e963b45313aae538c59853103c362f208f826fb907",
        ),
        (
            b"{\"n\":1.00,\"s\":\"\\u0061\"}\n\xff".as_slice(),
            "200427a079ee32763815e8acbad75ca4dcc6e0811fa96eef4800b52e740231eb",
        ),
        (
            "\u{2603}".as_bytes(),
            "210d01fc2f981f0289f327a106cb5ae28ad2701bddf13e5a6de386002cd3c05a",
        ),
    ] {
        assert_eq!(
            {
                let domain = b"eudoxia/effect/v3";
                let mut h = Sha256::new();
                h.update(b"eudoxia/frame/3\0");
                h.update((domain.len() as u64).to_be_bytes());
                h.update(domain);
                h.update(historical::bytes(&(&e, body.to_vec())));
                hex(&h.finalize())
            },
            expected
        );
    }
}
