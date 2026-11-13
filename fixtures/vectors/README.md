# Independent producers

`frame3` expected results in `tests/encoding.rs` come from the independent
`python3 scripts/frame_vectors.py` specification implementation.

`svrngs-pass.json` was produced by **svrngs-core's own Pass::sign**, not the test
decoder, and confirmed by its Pass::signed. Producer source is beside this file
(`svrngs-pass-generator.rs`). Fixture signing keys are `[2;32]` and `[4;32]`,
lender bytes `[5;32]`, names `movie`/`library`, until 80.

Producer checkout HEAD: `e1634a329644f83be6425259b86d488fe877d703`.
`git hash-object` of the actual read files:

- `crates/svrngs-core/src/pass.rs`: `417c049e8393e37001b0f800e543c766e6b6218b`
- `crates/svrngs-core/src/sig.rs`: `469db10315c60e4aeea02f4b3c3ec03b5c06d679`

The temporary producer manifest used path dependency `svrngs-core` from that
checkout plus ed25519-dalek 2 and serde_json 1. No svrngs dependency is added to
Eudoxia. The test adapter handles this reach-pass profile only, refusing unknown
forms. This vector does not certify a complete production pass/link/entry-approval
adapter, browser transport or journal integration.
