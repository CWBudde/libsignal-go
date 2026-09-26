# Compatibility Vectors

This directory contains committed fixtures used to keep the pure-Go
implementation pinned to upstream `signalapp/libsignal` behavior.

Vector-backed rows in `compat/coverage_manifest.json` and
`internal/upstream/manifest.json` must cite one of these files and record the
fixture SHA-256 digest. Structural-only rows must not cite a checksum; they must
explain which upstream package boundary or fixture is still missing before this
fork can claim parity.

The current upstream pin is `v0.96.4`. These vectors prove local package
behavior only. They do not claim login, send/receive, linked-device, backup
import/export, or interoperability with the official Signal app.

## zkgroup attribute crypto (Phase 8.2)

`gen-vectors zkgroup-crypto` calls the pinned upstream zkgroup crypto APIs.
`zkgroup.crypto`, `zkgroup.decrypt_uid`, `zkgroup.decrypt_profile` and
`zkgroup.inverse` provide live compatibility checks. Hex inputs include `seed`
(group master key), `uuid` (16 bytes), `profile_key` (32 bytes); `pni` is boolean
and `timestamp` is an unsigned 64-bit integer. Decrypt calls take raw 64-byte
`ciphertext`, plus `seed` and (for profiles) `uuid`. The inverse call takes a
32-byte `point` encoding.

The fixture has 40 cases, including all eight combinations of profile-key bits
omitted by the reversible encoding, all-zero/all-ones keys, ACI/PNI, and boundary
timestamps. It compares serialized attributes, key pairs, ciphertexts,
commitments, secret nonces, timestamps, single Elligator maps and inverse
candidates, plus all three upstream hardcoded system-parameter sets.
`TestZKGroupCryptoInterop` includes fresh random inputs and mutual decryption;
negative tests check malformed points, lengths, basepoint E1, wrong UUIDs and
wrong group keys. Two regenerations must be byte-identical.

This fixture covers attribute crypto only. Generic zkcredential,
API wrappers and the Signal group-service shim are still pending. The pinned
Rust implementation rejects profile keys whose masked map is the identity
(including all-zero): duplicate inverse candidates violate its exactly-one
match requirement. Go preserves that behavior.

## Legacy zkgroup credentials (Phase 8.2)

`gen-vectors zkgroup-credentials` emits 24 complete upstream crypto flows.
`zkgroup.credentials` accepts hex `seed` (32 bytes), `uuid`/`serial` (16 bytes),
`profile_key` (32 bytes), `message` (arbitrary), and u64 `timestamp`/`level`.
It returns serialized key layouts, blinded requests and credentials, signatures,
all active proofs, and the final SHO squeeze. `zkgroup.credentials.verify` takes
those same metadata fields plus an `artifacts` object and verifies the supplied
signature, request, two issuance proofs and two presentation proofs using the
actual upstream APIs. No credential or proof equations are reproduced in Rust.
The two private legacy auth markers are represented by public AttrScalars
adapters with the original counts; upstream KeyPair performs the derivation.

Live tests compare fresh inputs and reject changed metadata/keys/ciphertexts.
Go's exact-length parsers are intentionally stricter than the pinned upstream
in-place decoder on trailing bytes; a dedicated differential test records this
exception without modifying the Rust oracle. Generic zkcredential and the
higher-level API/shim are still outside this milestone.
