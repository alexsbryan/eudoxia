# Native statement boundary

The installed
carrier parser returns one owned parsed statement. It supplies its original
signing message, issuer and signature from that same value; the kernel verifies
before consuming that value's semantic projection under the explicit profile's
binding SourceRef. A carrier normalizes only under root-proven bindings, never
adds unsigned authority merely because a field was absent. ParsedStatement is not proof;
VerifiedStatement's constructor is private. Neither is an authority constructor.

The carrier's concrete parsed fields are private, immutable and owned; no request
installs a parser or chooses a root. Native formats own their signing-byte producer.
A native adapter projects only what its original statement authorizes, under
explicit root-proven normalization. The projection proof remains an obligation
of each concrete native adapter, not a theorem implied by a trait name. A
compromised compiled adapter can still lie: the existing deliberate TCB assay
must keep distinguishing that case from an untrusted input attack.

The low-level Ed25519 verifier has one implementation shared by reference/test
and native carriers. A native carrier uses its format's own signing-message
producer (for svrngs, `Pass::message`), not another handwritten transcript. Historical entry approvals must retain all
their native signatures/content/source bindings; a reach pass is not an approval.
Legacy class-less native evidence cannot silently gain a classified meaning.

The original signature, attenuation, missing-format, device-binding and
compromise-assay witnesses stay fixed in meaning. Compiler controls reject
constructing VerifiedStatement or treating ParsedStatement as verified; lawful
carrier controls compile and execute. The earlier Eudoxia Grant/SignedGrant format
is test-only, installed as a concrete test carrier rather than a production Chain
branch. Native graph/root and concrete adapter projection proofs remain obligations
of each native integration; native passes are not replaced with new grants.
