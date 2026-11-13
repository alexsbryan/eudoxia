fn main() {
    let signer = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
    let holder = ed25519_dalek::SigningKey::from_bytes(&[4; 32]);
    let pass = svrngs_core::pass::Pass::sign(
        &signer,
        &svrngs_core::actor_of(&holder),
        (
            svrngs_core::pass::Label::of(&[5; 32], "movie"),
            vec![svrngs_core::pass::Label::of(&[5; 32], "library")],
        ),
        80,
    );
    println!("{}", serde_json::to_string_pretty(&pass).unwrap());
    println!("{:02x?}", pass.message());
    assert!(pass.signed());
}
