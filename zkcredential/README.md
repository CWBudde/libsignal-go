# Generic anonymous credentials

This package ports `rust/zkcredential` at libsignal **v0.102.2**, using the
existing constant-time Ristretto and `poksho` implementations. It includes:

- Domain-separated two-point attributes, homomorphic encryption and inverse keys.
- Credential keys for **standard** and **legacy** modes, with up to six private
  attribute points plus the aggregate public attribute slot.
- Clear and blinded issuance, including single-point attributes revealed later.
- Presentations with multiple encryption domains, repeated domains, verified or
  unspecified encryption keys, public attributes and revealed attributes.
- Tag-derived batch endorsements, combination/subtraction and 16-byte tokens.

`IssuanceBuilder` and the presentation builders preserve attribute order. Invalid
additions record an error reported by the terminal operation. Builders can be
reused with fresh randomness; they must not be mutated concurrently. Returned
keys, credentials and proofs are immutable through the public API. Point/scalar
accessors return copies.

`StandardMode` is the default zero mode. It separates the public-slot coefficient
by total credential arity (except the upstream two-point migration case), and
binds encryption public keys, second ciphertext points and corresponding
commitments into the presentation's authenticated message. **Never reuse a
server key in different modes.** The mode and encryption domain are out-of-band
context, not serialized wire fields. Use legacy mode only for an existing
protocol that requires it.

Issuance and presentation require **fresh 32-byte cryptographic randomness for
every operation**. Blinding keys should be fresh for each request. Public
attributes must use the same encoding and ratchet boundaries on both sides;
`PublicBytes`, `PublicUint32` and `PublicUint64` implement the upstream defaults.
Custom `PublicAttribute` implementations can absorb structured transcripts.

Application-specific request proofs, expiry checks and redemption rules belong
in callers. Blind issuance does not itself establish that the client blinded an
authorized value. `DecryptToSecondPoint` is deliberately unauthenticated: decode,
re-encode and verify the first ciphertext point before accepting plaintext.
`Verify`/`VerifyBlinded` authenticate issuance before returning a credential;
parsing a stored credential or endorsement does not authenticate it.

Endorsement tag transcripts must include a domain separator and all public
attributes. Endorsements combined or removed must share both server and client
keys. Combination preserves multiplicity, like the upstream point sum. Tokens
are bearer credentials. A derived endorsement private key and its tag information
are sufficient to recover its root key; derivation does not isolate that secret.

Serialization follows upstream bincode fixed integers and little-endian vector
lengths, with canonical scalar/point encodings. Parsers reject trailing bytes,
bound vectors by input length before allocation, and cap presentation commitments
at seven. Proof byte vectors and endorsement-response compressed points remain
opaque until verification. Empty endorsement batches return errors instead of
upstream's indexing panic. Redundant key fields retain upstream parse semantics;
proof creation self-verifies and catches inconsistent fields used by its statement.

`compat/vectors/zkcredential.json` contains 52 complete upstream flows covering
all supported arities, both modes, blind/clear/mixed issuance and both presentation
key policies. Live interop adds fresh randomness and public attributes, mutual
verification, altered inputs, malformed encodings and two exact regenerations.
These primitives do not yet provide Signal group API wrappers or service parity.
See [CONSTANT_TIME.md](CONSTANT_TIME.md) for the source review boundary.
