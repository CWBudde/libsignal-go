# Source-level timing review

Reviewed: new attribute/encryption/commitment code, the reversible mapping,
gtank/ristretto255 v0.2.0, edwards25519/field v1.2.0, and upstream
curve25519-dalek 5.0.0 Lizard and zkgroup crypto code. This is a source review,
not an independent cryptographic audit or a machine-code timing proof.

- Secret scalar operations use gtank's constant-time scalar reduction,
  inversion and ScalarMult. There are no variable-time multiscalar calls,
  `math/big`, or secret-indexed lookup tables in this implementation.
- SHO uses the already-reviewed HMAC-SHA256 implementation in `poksho`.
  All secret inputs here have fixed lengths; separate squeeze/ratchet calls
  match upstream. Public timestamp integers use a big-endian hash transcript
  and a little-endian stored representation.
- The single map uses gtank's constant-time uniform mapping, with a fixed zero
  second half. Inverse mapping uses field Add, Subtract, Multiply, Square,
  Invert, SqrtRatio, Absolute, Equal and Select. All candidate slots are visited,
  including the identity special case. No operation branches on a field value.
- Inverse coordinates are reconstructed from an already-valid point's
  constant-time canonical encoding. The field decoder receives exactly 32
  bytes and has no content-dependent rejection path. Canonical decoding of
  untrusted serialized inputs is separate and may branch on public encodings.
- Lizard checks all eight positive candidates with SHA-256 and constant-time
  comparison/copy. UID decryption calculates and compares both ACI and PNI M1
  candidates before selecting the final service ID. It branches only on
  decryption success/failure; as upstream, the final two-element array access
  reveals which kind was returned but does not branch on that kind.
- Profile-key decryption visits all 8 inverse candidates times 8 bit patterns.
  It gates every match on candidate validity, copies with ConstantTimeCopy,
  counts matches, and tests exactly-one only at the end. Invalid slots cannot
  impersonate an all-zero key. Public loop counters determine restored bits.
- The E1 = basepoint check depends on a public ciphertext. Secret-dependent
  success/failure is returned only after authentication. No partial plaintext
  is returned on failure. Duplicate candidates retain upstream rejection
  semantics, including masked-zero profile keys.

Returned encodings may contain secrets; Go cannot promise secure erasure of
all heap copies. Callers must not log secret key pairs or commitment nonces.
