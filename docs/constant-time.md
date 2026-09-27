# Constant time and zeroization

This page records the review of the module's secret-dependent code paths, and states
what the module does, and does not do, about wiping key material. It covers the
module's own non-test code. The dependencies are covered by their own stated
guarantees (see [Dependencies](#dependencies)). go-signal's
`docs/constant-time-review.md` is the fuller review of the whole pure-Go backend,
including this module at `v0.7.1-cw.4`, the shim's `Destroy` methods, and the
build-tag interaction. Its finding IDs (CT-01 to CT-03) are used here.

A side channel counts as a finding when timing or the memory access pattern depends on
a secret that an attacker doesn't already have: key material, MAC tags that are still
being checked, plaintexts, padding, PINs and entropy pools, proof witnesses and nonces.
Branching on the *result* of a check (reject or accept) is fine, as long as the
comparison itself is constant time. Lengths, versions, counters, public keys,
ciphertexts, attestation evidence and anything else sent in the clear are public.

## Method

1. **Type-aware scan.** `scripts/ctscan` (its own module, so the library doesn't
   depend on `golang.org/x/tools`) reports every `==`/`!=` on a byte array or on a
   string converted from bytes, and every `bytes.Equal`, `bytes.Compare` and
   `bytes.HasPrefix`, in non-test code outside `proto/`:

   ```sh
   go run -C scripts/ctscan . "$PWD"
   ```

   It reports 19 sites. All of them are classified [below](#comparisons-that-are-not-constant-time).

2. **`crypto/subtle` call sites.** These are the comparisons that are meant to be
   constant time. Each was checked for its operands and for the code around it:

   ```sh
   grep -rn --include='*.go' 'subtle\.' . | grep -v _test.go | grep -v '^./proto'
   ```

3. **Hand-written arithmetic.** Every package that does field, scalar, point or
   polynomial arithmetic itself, rather than calling a dependency, was read for
   secret-dependent branches, secret indices, variable-time multiplication and
   `math/big`: `internal/crypto/gcmsiv` (POLYVAL), `internal/mlkem768incr`,
   `internal/ristrettolizard`, `curve` (XEdDSA), `zkgroup/zkcrypto`, `zkcredential`,
   `poksho` and `spqr`.

4. **Decrypt paths.** Every decryption was checked for authenticate-then-decrypt
   ordering, so that padding and decoding errors after decryption can't be used as an
   oracle.

## Result

Three findings: one fixed, two open. The open ones are go-signal's CT-01 and CT-02
(go-signal `docs/constant-time-review.md`, PLAN.md §10.2), and they block the pure-Go
backend from becoming go-signal's default. The package-level reviews in
`poksho/CONSTANT_TIME.md`, `zkcredential/CONSTANT_TIME.md`, `zkgroup/CONSTANT_TIME.md`
and `zkgroup/zkcrypto/CONSTANT_TIME.md` still apply to those packages.

| Site | Finding | Resolution |
| --- | --- | --- |
| `internal/mlkem768incr/incremental.go` `FixEncapsStateEndianness` | **Open (CT-01).** It scans the secret e₂ noise coefficients up to the first decisive value, then branches and allocates depending on it. `toBalanced`/`fromBalanced` also branch on secret coefficients and use a signed `% q`. `Encapsulate2` runs it on every SPQR completion. | To fix: scan all 256 coefficients, select the classification and the swap with masks, and make the balanced conversions branch-free and division-free. Then check the amd64 and arm64 output. |
| `crypto/aes`, used by the CBC, CTR, GCM and GCM-SIV paths | **Open (CT-02).** Go's generic AES indexes tables with secret values. The `purego` build tag, which go-signal uses to select its backend, also removes the standard library's assembly (`aes_asm.go` is `!purego`), so AES is table-driven even on CPUs with AES-NI or ARMv8 AES. | To fix in go-signal and the mautrix fork: select the backend with a tag other than `purego`, and require AES hardware or a reviewed constant-time fallback. This module can't fix it by itself. |
| `internal/crypto/aescbc.go` `pkcs7Unpad` | **Fixed (CT-03).** The padding bytes were checked in constant time, but the pad value's range (`pad == 0 \|\| pad > 16`) returned early, which branched on the last plaintext byte. | Fixed: the range check is folded into the same constant-time mask, and only the length is branched on. `TestPKCS7UnpadMatchesReference` checks all 256 final byte values, each correct and with each padding byte corrupted, against a plain reference. Optimized Go 1.26 output (amd64 `GOAMD64=v1`, arm64) uses only `SETcc`/`CMOV`/`CSEL` on the pad byte; it branches on the length, the fixed 16-step loop counter and once on the overall result. `DecryptCBC` clears the decrypted buffer when the padding is rejected. |

The early return was not reachable as an oracle: all three callers (`session/cipher.go`,
`groups/cipher.go`, `usernames` link decryption) verify a MAC or signature before
decrypting, as upstream does. It was fixed because the function claims to be constant
time and the fix is cheap.

## Constant-time comparisons

All secret comparisons use `crypto/subtle`:

| Package | Site | What is compared |
| --- | --- | --- |
| `protocol` | `signal_message.go` `VerifyMAC` | message MAC |
| `protocol` | `addresses.go` | the serialized address binding |
| `sealedsender` | `internal.go` | the static/ephemeral key MAC |
| `sealedsender` | `v1.go` | the sender's static key against the certificate |
| `sealedsender` | `v2.go` | the rederived ephemeral key, and the authentication tag |
| `internal/crypto` | `aescbc.go` | PKCS#7 padding (see the fix above) |
| `internal/crypto` | `aesctr.go` | keystream length selection |
| `internal/crypto/gcmsiv` | `gcmsiv.go` | the tag; the plaintext is zeroed on failure |
| `spqr` | `authenticator.go` `ctEqual` | the SPQR MACs, mirroring upstream's `util::compare` |
| `internal/mlkem768incr` | `mlkem.go` | FIPS 203 implicit rejection (`ConstantTimeCopy` of the shared secret) |
| `internal/mlkem768incr` | `incremental.go` | `H(ek)` checks on the header and the expanded decapsulation key |
| `internal/ristrettolizard` | `Decode` | all eight Elligator candidates, no early exit |
| `zkgroup/zkcrypto` | `encryption.go` | UID and profile-key decryption over every candidate |
| `zkcredential` | `endorsements.go` | endorsement tokens |
| `usernames` | `usernames.go` | the username-link MAC |
| `accountkeys` | `VerifyLocalPINHash` | the Argon2 PIN hash |
| `curve` | `curve.go`, `xeddsa.go` | public keys, and the signature's `R` |
| `kem` | `kem.go` | public keys |
| `fingerprint` | `fingerprint.go` | scanned fingerprints |
| `session` | `record.go` | Alice's base key |

Some of these operands are public (keys, fingerprints). Comparing them in constant time
costs nothing and matches upstream.

## Comparisons that are not constant time

These are the 19 sites `scripts/ctscan` reports. None of them handles a secret.

| Site | Operands | Why it is fine |
| --- | --- | --- |
| `address/serviceid.go` `Compare` | service IDs | Public identifiers, used to order recipients |
| `attest/dcap/attest.go` (7 sites) | MRENCLAVE, MRSIGNER, QE vendor ID, FMSPC, PCEID, report-data hash and zero padding | Public attestation evidence and policy |
| `attest/dcap/certchain.go` (3) | certificate subject/issuer names and key IDs | Public certificates and CRLs |
| `attest/dcap/json.go` | a JSON `null` literal | Public collateral |
| `attest/dcap/quote.go` (2) | the QE report-data hash and zero padding | Public quote |
| `attest/hsmenclave/hsmenclave.go` | the enclave code hash | Public, compared against the pinned list |
| `internal/zkgroupserver/endorsements.go` | ciphertext encodings, when sorting | Test-only server |
| `zkgroup/endorsements.go` | doubled ciphertext points, when sorting | Public UUID ciphertexts, sorted in the order the protocol prescribes |
| `spqr/chain.go` `keyHistory.get` | the stored key's index | A public message counter; the key itself isn't compared |

## Hand-written arithmetic

- **POLYVAL** (`internal/crypto/gcmsiv/polyval.go`): the carry-less multiply and the
  reduction are masks, shifts and XORs. There are no tables, and the only branch is on
  the public loop index. AES itself comes from `crypto/aes`, so it carries CT-02.
- **ML-KEM-768** (`internal/mlkem768incr`): re-derived from the standard library's FIPS
  203 code. Barrett reduction, `fieldReduceOnce`, `compress` and `decompress` are
  branch-free. `fieldCheckReduced` branches only on public encapsulation-key
  coefficients, and rejection sampling on the public matrix seed. Decapsulation uses
  implicit rejection with `ConstantTimeCopy`. The SPQR state codec around it is not
  constant time (CT-01).
- **Ristretto and Lizard** (`internal/ristrettolizard`): the field operations are from
  `filippo.io/edwards25519/field`. `Inverse` evaluates all four Jacobi quartic points,
  and `Decode` checks all eight candidates with `subtle` and no early exit.
- **XEdDSA** (`curve/xeddsa.go`): signing uses the constant-time `ScalarBaseMult` and
  `MultiplyAdd`. Only verification, where every input is public, uses
  `VarTimeDoubleScalarBaseMult`.
- **zkgroup, zkcredential and poksho**: scalars and points are `gtank/ristretto255`,
  and `Scalar.Invert` is constant time. `poksho`'s prover never uses a variable-time
  multi-scalar multiplication on its witness; `statement.go` says so where it matters.
  Nonce bytes are cleared after use. The only branch in UID decryption (`E1 == G`) is
  on the public ciphertext.
- **SPQR** (`spqr`, `internal/spqr/chunked`): the erasure code works on public key and
  ciphertext chunks, and MACs go through `ctEqual`.
- **`math/big`**: it is not constant time. It appears only in `usernames`, as an upper
  bound for `crypto/rand.Int` when choosing discriminators, and in `attest/dcap`, on
  public ECDSA values.

## Dependencies

These are trusted for constant-time behaviour on secrets, as their documentation
states:

- **Standard library:** `crypto/aes` only when hardware AES is in use: the generic
  fallback indexes tables with secret values, and the `purego` build tag forces it
  (CT-02). Also `crypto/cipher` (GCM, CBC, CTR), `crypto/hmac`, `crypto/hkdf`,
  `crypto/sha256`, `crypto/sha512`, `crypto/ecdh`, `crypto/mlkem`, `crypto/ecdsa` and
  `crypto/rsa`.
- **`golang.org/x/crypto`:** `curve25519` and `chacha20poly1305`.
- **`filippo.io/edwards25519`:** the constant-time API, and the explicit `VarTime`
  functions, which are used only on public inputs.
- **`github.com/gtank/ristretto255`:** built on edwards25519.
- **`github.com/cloudflare/circl`:** Kyber1024.

## Accepted residuals

These match upstream's behaviour, and changing them would buy little:

- **Argon2id** in the SVR PIN derivation uses data-dependent memory access by design.
- **Usernames:** parsing, formatting and candidate deduplication are variable time on
  the name.
- **Parsing the account entropy pool** (`ParseAccountEntropyPool`) branches per
  character when it validates the alphabet. Generating one rejection-samples bytes of
  252 or more, then indexes the 36-character alphabet with the accepted value. Upstream Rust does the same. Parsing leaks at most which character
  class an invalid input fell into.
- **Hex and base64:** the PHC string of the local PIN hash (`LocalPINHash`) and the
  profile key version (`zkgroup/profiles.go`) use the standard library's table-driven
  encoders. The PIN hash is a stored verifier. The version is derived from the profile
  key and sent to the server. Upstream uses non-constant-time encoders as well.
- **Stored state** (session, sender key, pre-key and SPQR records) is protobuf-decoded
  without constant-time guarantees. The records are local, and an attacker who can
  time their decoding can read them anyway.
- **The Go runtime:** the garbage collector, the scheduler and bounds checks add
  timing noise that isn't secret-dependent. This review does not cover Spectre-class
  speculation.

## Zeroization posture

Go does not let a library guarantee that key material is erased:

- The garbage collector moves nothing on the heap, but it frees memory without wiping
  it, and a value copied by assignment, by `append` or by a conversion leaves copies
  the library can't reach.
- Goroutine stacks grow by copying, which leaves the old stack behind unwiped.
- Strings are immutable. A secret that is ever a string (for example
  `AccountEntropyPool.String`) cannot be wiped.
- Register spills and compiler temporaries are beyond the library's reach.
- `runtime/secret` (`secret.Do`) erases registers, stacks and heap allocations, but in
  Go 1.26 it is behind `GOEXPERIMENT=runtimesecret` and supported only on linux/amd64
  and linux/arm64. The module doesn't depend on it. Callers who build with the
  experiment can wrap their own calls in it.

What the module does:

- **Best-effort clearing**, where it is cheap and the buffer is local: `poksho`
  clears the nonce bytes it squeezed, and AES-GCM-SIV zeroes the recovered plaintext
  when the tag doesn't match.
- **Redaction:** key types implement `String` and `Format` so that no `fmt` verb
  prints them. This covers `curve.PrivateKey`, `kem.SecretKey`, the `ratchet` chain,
  root and message keys, and `mlkem768incr.DecapsulationKey768`, each with a
  redaction test.
- **Key types hold arrays or slices**, not strings. The exceptions are the textual
  forms that the API requires: `AccountEntropyPool.String` and the PHC PIN hash
  string.

What it deliberately doesn't do:

- **Promise erasure.** A `Destroy` or `Wipe` method would suggest a guarantee that Go
  can't give, so the module has none. This matches the README's scope note ("FIPS
  certification and key-material zeroization guarantees beyond the documented Go
  posture are out of scope").
- **Wipe what it drops.** Removing old keys (for example `spqr/chain.go`
  `keyHistory.clear`, which shortens a slice) deletes them logically, not physically.
  In the same way, the `Destroy` methods of go-signal's mautrix shim release
  references and don't wipe anything.

What callers should do instead:

- **Treat the process as the boundary.** Keep secrets out of logs and crash reports,
  disable core dumps (`RLIMIT_CORE=0`, `prctl(PR_SET_DUMPABLE, 0)`), and use encrypted
  swap or none.
- **Protect stored state at rest.** The session and key stores hold the long-term
  secrets, and the library doesn't encrypt them.

## Keeping this current

Re-run `scripts/ctscan` when you add code that compares bytes. Add any new site to the
tables above, or move it to `crypto/subtle`. New hand-written arithmetic needs the same
read-through as the packages listed under [Hand-written
arithmetic](#hand-written-arithmetic).
