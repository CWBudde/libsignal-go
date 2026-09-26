<!--
Copyright 2026 libsignal-go contributors.
SPDX-License-Identifier: AGPL-3.0-only
-->

# rust-harness

Compatibility harness that wraps upstream
[`libsignal-protocol`](https://github.com/signalapp/libsignal) and serves as the
behavioral reference oracle for the pure-Go port. It is a **dev/CI-only** crate:
nothing in the Go module depends on it, and it is not published.

The upstream dependency is pinned to a fixed tag, **`v0.102.2`** — the Stage-2
mainline-compat target (T29 advanced it from the Stage-1 pin `v0.91.0`; see ADR
0001). It lives in its own isolated Cargo workspace (`[workspace] members =
["."]`) so it is never pulled into a parent workspace, mirroring
`rust/protocol/cross-version-testing/Cargo.toml` upstream.

## Build-time system dependency: `protoc`

**`protoc` (the Protocol Buffers compiler) must be installed to build this
crate.** The upstream `libsignal-protocol` and `spqr` build scripts compile
their `.proto` files via `prost-build` 0.14, which does **not** vendor a
`protoc` binary — a system `protoc` is required. Without it the build fails at
`libsignal-protocol`'s `build.rs` with "Could not find `protoc`".

- macOS (local): `brew install protobuf`
- Debian/Ubuntu (CI): `apt-get install -y protobuf-compiler`
- GitHub Actions: `arduino/setup-protoc` (or the `apt` package above)

If `protoc` is installed somewhere off `PATH`, point the build at it with the
`PROTOC` environment variable.

> CI note for the workflow task (T13): add a `protoc` setup step before
> `cargo build`. This was a non-obvious blocker discovered during T11.

## Toolchain

`rust-toolchain.toml` pins stable `1.98.1`, matching the toolchain upstream
`v0.102.2` itself pins (up to v0.96.4 upstream pinned `nightly-2026-03-23`).
`rustup` fetches it on demand. A re-pin must update it by hand.

## Usage

Build (release):

```sh
cargo build --release
```

### gen-vectors

Prints a deterministic JSON batch of test vectors to stdout. The batch header
records the `seed`; output is byte-identical across runs (seeded ChaCha20).

```sh
rust-harness gen-vectors <domain>
```

Domains:

- `curve` — XEdDSA sign/verify (deterministic 64-byte signing nonce) and
  X25519 ECDH agreement.
- `kem-decaps` — Kyber1024 `(public_key, secret_key, ciphertext, shared_secret)`
  quadruples with an encapsulate/decapsulate round-trip.
- `hkdf` — the Double Ratchet key derivations, one case per required
  sub-domain: `chain-key`, `message-keys`, `root-key`, `pqxdh-secret`.
- `messages` — golden serialized bytes for `SignalMessage`,
  `PreKeySignalMessage`, `SenderKeyMessage`, and
  `SenderKeyDistributionMessage`, built with fixed keys.
- `fingerprint` — display + scannable fingerprints (v1 and v2) for a fixed
  identity-key pair.
- `username-links` — username-link entropy, deterministic IV, encrypted username
  bytes (`IV || ciphertext || HMAC`), username reservation hash, and
  upstream-decrypted username from `rust/usernames`.
- `mlkem-incremental` — byte-exact KATs for libcrux 0.0.10's incremental
  ML-KEM-768 (the KEM SPQR uses): the keygen split (`pk1`/`pk2`/`dk`), two-phase
  encapsulation (`ct1`, `encaps_state`, `ct2`, `shared_secret`), and
  decapsulation. `encaps_state` is the raw libcrux state for this host's backend;
  `encaps_state_fixed` is the cryspen/libcrux#1275-normalized state (equal to
  `encaps_state` on the portable backend, which is what builds here use). Oracle 3
  for the pure-Go `internal/mlkem768incr` incremental layer; the generated batch
  is committed at
  `internal/mlkem768incr/testdata/libcrux_incremental_mlkem768.json`.
- `spqr-chunks` — golden byte vectors for SPQR v1.5.3's GF(2^16) chunked-transport
  erasure code (the `test-utils` feature exposes its `encoding` module): a set of
  `chunk_at(i)` outputs (`cases`) pinning the BIG-endian u16 point/coefficient
  wire, plus GF16 `mul`/`div` triples (`gf_triples`) pinning the field
  (POLY=0x1100b). Oracle leg (c) for the pure-Go `internal/spqr/chunked` package —
  the erasure property test alone is blind to a uniformly-wrong endianness, so the
  golden bytes are required. Committed at
  `internal/spqr/chunked/testdata/spqr_chunks.json`.

Example:

```sh
rust-harness gen-vectors curve | jq '.seed, (.cases | length)'
```

### interop

A line-delimited JSON-RPC loop over stdin/stdout. Each input line is one request
`{"id": <any>, "method": "<name>", "params": {...}}`; each output line is one
response `{"id": <echoed>, "ok": <bool>, "result"|"error": ...}`. Unknown
methods, malformed JSON, and bad params all produce an error response — the loop
never crashes.

```sh
echo '{"method":"ping"}' | rust-harness interop
```

Methods (extended in later tasks — session/group/sealed-sender ops arrive then):

- `ping`
- `curve.sign` `{ private_key, message }` → `{ signature, public_key }`
- `curve.verify` `{ public_key, message, signature }` → `{ verified }`
- `curve.agree` `{ private_key, public_key }` → `{ shared }`
- `kem.decapsulate` `{ secret_key, ciphertext }` → `{ shared_secret }`
- `username_link.create` `{ username, entropy, iv }` →
  `{ entropy, encrypted_username }`
- `username_link.decrypt` `{ entropy, encrypted_username }` → `{ username }`
- `message.parse_sender_key` `{ serialized }` →
  `{ distribution_id, chain_id, iteration }`

All byte-string params and results are hex-encoded.

## Notes on the `hkdf` domain

The chain-key / root-key / message-keys / pqxdh-secret derivations are
`pub(crate)` upstream, so the harness reproduces them with the same pinned
crate versions (`hkdf`, `hmac`, `sha2` — matching upstream's pins). The formulas
are taken verbatim from `rust/protocol/src/ratchet/keys.rs` and `ratchet.rs` at
the v0.102.2 tag, which remain the contract (these version-stable formulas are
unchanged from v0.91.0 — the hkdf vectors are byte-identical across the re-pin).
Every other domain calls the genuine public API.

## poksho

`gen-vectors poksho` emits deterministic v0.102.2 SHO, conversion, signature,
and linear-relation proof vectors by calling the pinned upstream crate.
`src/poksho_compat.rs` contains this test-only adapter.

RPC methods are `poksho.sho`, `poksho.prove`, `poksho.verify`, `poksho.sign`,
and `poksho.verify_signature`. Byte fields are hex strings, including empty
strings. SHO requests carry `variant` (`hmac` or `sha`), `label`, and ordered
`ops` (`absorb`, `ratchet`, `absorb_and_ratchet`, `squeeze`, `clone`), returning
`outputs`. Proof requests carry ordered `equations` (`lhs`, ordered `terms`
with `scalar`/`point` names), `scalars` and `points` maps, `message`, and 32-byte
`randomness`; verification uses `proof` instead of witnesses/randomness.
Signature requests use singular `scalar` and `point`. Creation returns
`proof`; verification returns `verified`. The committed fixture demonstrates
the request shapes. Invalid builder inputs and SHO transitions produce errors
before calling upstream APIs that would panic.

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
