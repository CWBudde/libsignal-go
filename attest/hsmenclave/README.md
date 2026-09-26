# attest/hsmenclave

Pure-Go port of libsignal **v0.102.2** `rust/attest/src/hsm_enclave.rs` and
the bridge's `HsmEnclaveClient` (`bridge/shared/types/src/hsm_enclave.rs`),
go-signal PLAN.md Phase 9.4. It opens a Noise channel to trusted code in an
HSM on `noise`.

- `NewClient(trustedPublicKey, trustedCodeHashes)` requires a 32-byte key
  (`ErrInvalidPublicKey`) and one or more concatenated 32-byte code hashes
  (`ErrInvalidCodeHash`). It starts a `Noise_NK_25519_ChaChaPoly_SHA256`
  handshake whose initial message carries the hashes (48 + 32·n bytes).
- `CompleteHandshake` reads the HSM's reply. Its payload must be one of the
  trusted hashes: a shorter or untrusted payload gives `ErrTrustedCode`. A
  longer one gives `ErrHandshake` wrapping `noise.ErrDecrypt`, because
  upstream reads the payload into a 32-byte buffer that snow refuses to
  overflow.
- `EstablishedSend` / `EstablishedRecv` use the channel and wrap failures in
  `ErrCommunication`. A call in the wrong state returns `ErrInvalidState`,
  and a failed `CompleteHandshake` leaves the client unusable.

The tests run a Go `noise` responder. They were checked once against
upstream, with the upstream side taken from the libsignal v0.102.2 sources
and snow 0.10:

- a snow NK responder read the Go client's initial request, found the code
  hashes, and answered with a trusted hash. The client completed the
  handshake, and one message went each way;
- upstream's `ClientConnectionEstablishment::complete` gave the errors the
  Go client gives for replies with an untrusted, empty, 31-byte, 33-byte or
  64-byte payload, and for empty, truncated, tampered and garbage replies.
