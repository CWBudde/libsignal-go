# zkgroup attribute primitives

This package ports the UID/profile-key attribute, encryption, profile-key
commitment and timestamp portion of `rust/zkgroup/src/crypto` at **v0.102.2**.
It is the first step of go-signal PLAN.md Phase 8.2. It does not implement
credential issuance/proofs, zkcredential, the versioned group/profile API, or
the mautrix-signal shim.

The byte encodings match Rust's fixed-width, little-endian bincode fields.
Ciphertexts here are two compressed Ristretto points (64 bytes); higher-level
API ciphertexts add a reserved byte. Parsers reject incorrect lengths,
noncanonical points/scalars and trailing data. As in upstream serde, stored
attributes, key pairs and commitments are parsed structurally; parsing alone
does not authenticate their redundant fields. Keep secret encodings private.

Use constructors or parsers; zero values are not initialized. Values can be
shared for concurrent reads. Accessors return independent bytes and points.
Key derivation consumes the caller's SHO state, preserving ratchet boundaries
when integrated into group-secret derivation. No randomness is generated
implicitly. UID encryption binds the ACI/PNI kind; profile encryption and
commitments bind the profile key to its UUID.

`internal/ristrettolizard` supplies the reversible mapping absent from gtank's
public API, using `filippo.io/edwards25519/field`. Its inverse is ported from
curve25519-dalek 5.0.0's Lizard module, with the original license retained.
`MAP(0)` is the identity, so gtank's 64-byte uniform map with a zero second half
implements the single map exactly. Inversion uses a canonical representative
recovered by the RFC 9496 decode formulas; it does not access private Go fields.

Compatibility evidence lives in `compat/vectors/zkgroup-crypto.json`, the
`TestZKGroup*` vector/live tests and the package tests. In particular, eight
degenerate profile keys (masked to zero) are encryptable but **not decryptable**
in the pinned upstream: duplicate valid inverse candidates make its
exactly-one-match check fail. This behavior is preserved rather than silently
changing upstream acceptance rules. Normal randomly generated profile keys
round-trip and decrypt in both languages.

See [CONSTANT_TIME.md](CONSTANT_TIME.md) for the source-level review.
