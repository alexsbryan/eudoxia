# Security policy

Please report suspected vulnerabilities privately through GitHub's
**Report a vulnerability** button (Security → Advisories) on this repository,
not in a public issue. Include the affected version or commit, a minimal
reproduction, and the guarantee you believe is broken.

What the library does and does not promise — adversary capabilities, the
trusted computing base, and the obligations left to each embedding — is in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). A report that a guarantee in
[`docs/PROOFS.md`](docs/PROOFS.md) or [`docs/CONTRACT.md`](docs/CONTRACT.md)
fails under that model is in scope; a compromised installed profile, carrier or
resource adapter is part of the stated TCB.
