# Source-level timing review

Reviewed the generic credential port against `rust/zkcredential` at v0.102.2,
`poksho`, and gtank/ristretto255 v0.2.0. This is a source-level review, not an
independent cryptographic audit or a machine-code timing proof.

Secret scalars and potentially secret points use constant-time scalar reduction,
inversion, multiplication, addition, subtraction, negation and uniform mapping.
Proof generation and verification use poksho's constant-time MultiScalarMult.
Batch endorsement weighting uses constant-time point multiplication even in the
receive path where Rust permits variable-time multiplication. There are no
VarTime calls, math/big operations or secret-indexed tables here.

Branches and iteration counts depend on public modes, attribute counts, domain
IDs, public key consistency, input lengths and canonical decoding. The arity
separation hash consumes fixed-size secret/public inputs in the exact upstream
ratchet order. Presentation authenticated-data construction follows upstream
standard/legacy behavior, including the empty revealed-only migration case.

Endorsement weights bind the public key, doubled hidden points and all compressed
endorsements before a single squeeze of 127-bit weights. The first weight is one.
Token hashing uses SHA-256 of the compressed unblinded endorsement, truncated to
16 bytes; token comparison uses crypto/subtle.ConstantTimeCompare.

Parsing may branch on public encoding validity. Vector lengths are checked
against available input before allocation, and presentation commitments are
bounded to seven. Invalid compressed endorsements fail verification explicitly.
No unauthenticated credential is returned by issuance verification. The generic
encryption decryption helper returns only an unauthenticated second point, with
its required caller-side first-point authentication documented in the API.

Go cannot guarantee erasure of all secret heap copies. Secret scalar accessors
exist only to support higher-level blinding request proofs; callers must not log
key encodings, nonces or credentials. Fresh randomness, consistent mode selection
and application authorization policy remain caller responsibilities.
