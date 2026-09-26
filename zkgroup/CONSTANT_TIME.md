# Source-level timing review

Reviewed against libsignal v0.102.2. This is a source review, not an independent
cryptographic audit or a machine-code timing proof.

- Group derivation, profile versions, and request/presentation randomness use
  the existing poksho HMAC-SHA256 SHO. Ratchet boundaries and squeeze sizes
  match the Rust API, as confirmed by complete serialized API vectors.
- UID/profile encryption, commitments, blinding, signatures, and presentations
  delegate to the reviewed `zkcrypto` and `zkcredential` implementations. The
  API introduces no new scalar arithmetic, variable-time multiscalar operation,
  secret-indexed table, or big-integer implementation.
- Auth attributes use the upstream UID domain generators and identifier, with
  generic credentials explicitly in LegacyMode. Reusing the same encryption
  domain for ACI and PNI preserves the shared-key presentation statement.
- Access-key derivation uses standard-library AES on the fixed block ending in
  02. Blob encryption uses the existing AES-256-GCM-SIV implementation. Hardware
  AES availability and platform timing properties retain those dependencies'
  existing qualifications; this layer does not strengthen their guarantees.
- Version, length, canonical encoding, and timestamp branches depend on public
  metadata. Issuance verification precedes profile unblinding. Authenticated
  blob padding is inspected only after the AEAD succeeds; failed operations
  return no partial plaintext or unblinded credential.
- Group-send receipt uses the existing UID encryption and generic endorsement
  batch-proof verification. Sorting compares compressed doubled ciphertext points,
  which are visible to the group server; it does not compare secret scalars or
  plaintext IDs. Member counts, ordering and expiration checks are public metadata.
  No endorsement is returned until the complete batch proof verifies.
- Token creation uses ristretto255's scalar inversion and scalar multiplication
  through `zkcredential.ClientDecryptionKey` and `Endorsement.Token`. The UID scalar
  is secret; these operations retain the underlying library's constant-time
  posture. SHA-256 hashes the unblinded point to the 16-byte bearer token. This
  layer adds no variable-time scalar arithmetic. Tokens and group secrets are
  copied during serialization; neither temporary scalar copies nor token buffers
  have guaranteed erasure. Callers must not log or disclose token encodings.
- Serialization copies secrets and does not guarantee heap erasure. Stored
  secret objects must come from trusted local storage; structural parsers do
  not verify consistency of redundant secret/public fields, matching Rust.

Constant-time behavior of underlying primitives is documented separately in
`zkcrypto/CONSTANT_TIME.md`, `../zkcredential/CONSTANT_TIME.md`, and
`../poksho/CONSTANT_TIME.md`. No independent audit has been performed.
