# Source-level constant-time review

Reviewed 2026-09-26 for go-signal Phase 8.1 against libsignal v0.102.2,
`github.com/gtank/ristretto255` v0.2.0, `filippo.io/edwards25519` v1.2.0, and
Go 1.26's standard SHA256/HMAC implementations.

## Secret-dependent paths

- Witnesses, synthetic nonces, caller randomness, and potentially point values
  are secret. Statement structure, argument names/counts, and message lengths
  are treated as public. Index selection and loop lengths depend only on that
  public structure, never on scalar or point values.
- Witnesses and points are copied before arithmetic. Scalar reduction,
  multiplication, addition, negation and equality use ristretto255 methods.
  Its implementation delegates to edwards25519 scalar arithmetic; no
  `math/big`, decimal conversion, secret-indexed lookup or variable-time scalar
  arithmetic is introduced here. Uniform reduction always consumes 64 bytes.
- Both proving and verification use `Element.MultiScalarMult`, including when
  reconstructing commitments. Its dependency uses fixed radix-16 rounds and
  constant-time table selection (`edwards25519/extra.go`,
  `tables.go:projLookupTable.SelectInto`). No `VarTime*` method is used: upstream
  explicitly notes that points, as well as scalars, may be secret.
- Transcript bytes match upstream: label, ordered statement description,
  points including G, and ratchets. Nonces absorb 32-byte randomness, canonical
  witnesses and the message before one combined squeeze. HMAC/SHA256 use
  standard-library implementations with fixed-size keys and chaining values;
  output loops depend on requested length only. Clones copy hash state rather
  than retaining/replaying a secret transcript buffer.
- Challenge comparison uses `Scalar.Equal` (field subtraction and branch-free
  reduction of the nonzero flag in the dependency). Proof creation verifies the output before returning it,
  preserving upstream's faulty-computation check. No witness or nonce is
  included in an error or log.

## Public parsing and limitations

Canonical proof parsing and argument validation may return early on malformed
public inputs, matching upstream's non-constant-time parser. Exposed canonical
scalar/point decoding helpers are parsers, not APIs that promise hidden-input
validity. Hash execution time reveals input lengths; API users must not encode
secrets in statement structure or argument names if those must be concealed.

The temporary nonce byte buffer is cleared, but Go's runtime and hash/scalar
objects do not provide guaranteed erasure of all copies. This review does not
claim memory zeroization, compiler/assembly verification, timing measurements,
resistance to physical fault injection, or an independent cryptographic audit.
Functional vectors, fuzzing, and cross-language tests establish compatibility;
they are not evidence of constant-time execution by themselves. Revisit the
review when these dependencies or arithmetic paths change.
