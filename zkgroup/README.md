# Group and profile API

This package implements the client group/profile API at libsignal **v0.102.2**,
on the existing `zkcrypto` and `zkcredential` primitives. It includes server
public parameters and notary signatures, group key derivation, ACI/PNI and
profile-key encryption, padded group blobs, profile-key commitments/versions,
expiring profile credentials, authentication credentials with PNI, and group-send
endorsements and bearer tokens.

Use constructors or parsers: zero values are not initialized. Returned encodings
are independent copies, and initialized objects support concurrent reads.
Master keys, group secret parameters, profile keys, request contexts, and
received credentials contain secrets and must not be logged. Parsing validates
structure only; use the receive operations to authenticate issuance before
accepting a credential. Presentation parsing and ciphertext extraction do not
verify a presentation. Issuance and server verification for tests are isolated
in `internal/zkgroupserver`.

Every randomized operation accepts explicit 32-byte randomness. Callers must
provide fresh cryptographically random bytes. The shim supplies `crypto/rand`
for APIs without an explicit randomness argument. Nothing in the API package
implicitly reads a clock or generates randomness.

The API encodings include their upstream reserved/version bytes. Profile
presentation V1–V4 uses wire bytes **0–3**; new presentations use V4 (byte 3).
Authentication credentials/responses use byte 3, and their V4 presentations
also use byte 3. Historical profile presentations can be structurally parsed
for ciphertext extraction, but are not issued or verified by the test server.

Expiring profile credentials require day-aligned expiration and 1–7 remaining
**whole** days (upstream integer truncation). Auth receipt requires day-aligned
redemption. The server's auth presentation verification window is inclusive,
from one day before redemption through two days after. These are Unix seconds.

Go parsers reject trailing data and bound vector reads before allocating. The
pinned Rust `deserialize_in_place` may accept trailing bytes; canonical outputs
remain identical. Padded blob decryption follows Rust: it ignores the final
reserved byte and removes the authenticated padding count without requiring
zero-valued padding. Blob authentication failures never return plaintext.

`compat/vectors/zkgroup-api.json` contains 16 complete deterministic Rust API
flows. The interop tests add 16 fresh randomized flows, mutual verification,
tampering/metadata rejection, time boundaries, and two exact regenerations.
The shim runs a selected fixture against both CGO and purego builds. See
`CONSTANT_TIME.md` for the source-level review.

Group-send response receipt verifies a batch proof using the server's endorsement
root public key and a day-aligned expiry **2 hours–7 days** in the future, inclusive.
Ciphertexts sort by their compressed doubled first point; receipt restores the
caller's member order. Include all group members, including the local user, when
receiving; combine only the intended recipients when sending. Combine/remove
preserve multiplicity, so repeated inputs do not deduplicate. Stored endorsements
must originate from verified receipt under the same issuance. Tokens must use the
original expiry; merely attaching an expiry does not authenticate it. The test
server accepts a valid token at the exact expiry instant and rejects later times.
Token parsers accept arbitrary opaque lengths as Rust does; authentic tokens are
16 bytes. Bearer tokens, including full-token serializations, must not be logged.

`compat/vectors/group-send.json` contains 16 complete Rust endorsement flows with
1–31 members, mixed ACI/PNI identities and empty recipient combinations. Live Rust
interop adds fresh randomized flows, mutual verification, ordering/membership
checks, altered-input rejection, expiry boundaries and exact regeneration checks.
