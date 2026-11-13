# Native acceptance (svrngs)

This separate package tests Eudoxia against a real native carrier,
[svrngs](https://github.com/alexsbryan/svrngs). It is not part of the library's
default build, tests or gate, and it needs a svrngs checkout beside this
repository (`../svrngs`, see `Cargo.toml`).

From the Eudoxia root:

```sh
# Real-producer pass and identity-binding witnesses.
cargo test --manifest-path integration/Cargo.toml --test native_pass --test native_bindings

# Direct/link reach-pass projection correspondence, plus an explicit public-API limit.
cargo test --manifest-path integration/Cargo.toml --test reach_projection

# Identity and reach-projection controls must detect their compiled fault plants.
python3 scripts/check_extensions.py --integration

# Native source-constitution targets.
cargo test --manifest-path integration/Cargo.toml --test native_constitution

# Everything.
cargo test --manifest-path integration/Cargo.toml
```

The pass and identity witnesses call svrngs's own `Pass::message` producer and
the library's one derivation/resource scaffold; they do not use a handwritten
transcript or reissue certificates.

`native_constitution` holds counterexamples against svrngs's existing group
fold (a bare Admit grants standing; a disputed office successor can cut an
unrelated member). They are expected to fail until svrngs adopts a constitution
that refuses them. Their assertions describe the required behavior and are not
skipped or relabelled as library results. A green library gate or projection
witness is not a native security sign-off.
