# zkgroup crypto primitives

This package ports the UID/profile-key attribute, encryption, profile-key
commitment and timestamp portion of `rust/zkgroup/src/crypto` at **v0.102.2**.
It also ports the legacy KVAC credentials, profile and receipt blinding requests,
server signatures, and all active request/issuance/presentation proofs. Generic
zkcredential, the versioned group/profile API and the mautrix-signal shim remain
separate steps of go-signal PLAN.md Phases 8.2–8.4.

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

Credential key kinds retain all six historical layouts, including unused scalars
consumed from SHO. Only expiring profile and receipt issuance is active, as in
upstream. V1/V2 profile presentation types support deserialization only. Proof
serialization includes the little-endian u64 length prefix around poksho bytes;
parsing does not authenticate proofs. Verify request proofs before issuance and
issuance proofs before unblinding. Receipt clients must check expected expiration
and level, and higher-level APIs must enforce expiration and redemption policy.

`compat/vectors/zkgroup-credentials.json` records 24 complete flows, including
zero/max timestamps and receipt levels. Live tests cover fresh inputs, both
verification directions, changed metadata, keys, ciphertexts and malformed proofs.
The final SHO squeeze is also checked, detecting incorrect consumption boundaries.

**Parsing boundary:** Go deliberately rejects trailing data. The pinned Rust
`deserialize_in_place` accepts it despite configuring `reject_trailing_bytes`;
`TestZKGroupCredentialTrailingDataPolicy` records this difference against the
unmodified upstream decoder. Canonical serialized values match byte for byte.
