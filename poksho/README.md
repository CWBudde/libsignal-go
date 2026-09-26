# poksho

Pure-Go port of `rust/poksho` at libsignal **v0.102.2** (go-signal Phase 8.1).
The package provides both SHO constructions, Ristretto scalar/point helpers,
linear-relation Schnorr proofs, and Schnorr signatures. It does not implement
zkgroup credentials, group endorsements, or username-specific proofs.

Use `NewShoHmacSha256` or `NewShoSha256` for SHO. Absorb chunks, call `Ratchet`,
then call `SqueezeAndRatchet` or `SqueezeAndRatchetInto`. Empty absorbs and
empty squeezes change the state; a repeated ratchet without absorption does
not. `Clone` copies partially absorbed as well as ratcheted states. Squeezing
before ratcheting is programmer misuse and panics, matching upstream. Do not
copy SHO structs by value or share them concurrently. Cloning uses Go 1.26's
standard SHA256/HMAC `hash.Cloner` implementations.

`Statement.Add(lhs, []Term{...})` builds ordered equations. `ScalarArgs` and
`PointArgs` assign Ristretto values by name; the generator `G` is implicit.
`Prove` and `Sign` take explicit `[32]byte` randomness, normally filled with
`crypto/rand.Read`. Identical inputs produce identical bytes. Proving checks
the generated proof before returning it. Verification accepts only canonical
scalar encodings and the exact response count required by the statement.
Arguments are not mutated; concurrent caller mutation is unsupported.

`Add` returns an error without changing the statement for invalid names or
limits. It permits at most 255 equations, terms per equation, scalars, and
points including `G`. Upstream's builder can assign index 255, but its
serializer panics when the corresponding count reaches 256; this Go API
rejects that unusable state. `ParseProof` independently accepts 1–256 response
scalars, matching Rust's parser. Empty statements cannot produce proofs.
Errors can be inspected with `errors.Is`; malformed proofs become
`ErrVerification` at verification entry points. These signatures are poksho
Schnorr signatures, not Signal protocol XEdDSA signatures.

Tests: `CGO_ENABLED=0 go test ./poksho ./compat`; Rust fixtures and interop are
documented in [compat](../compat/README.md#poksho-go-signal-phase-81).
The [constant-time review](CONSTANT_TIME.md) records source-level evidence and
its limits.
