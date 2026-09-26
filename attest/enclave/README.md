# attest/enclave

Pure-Go port of libsignal **v0.102.2** `rust/attest/src/enclave.rs`,
`sgx_session.rs`, `cds2.rs` and the bridge's `SgxClientState`
(`bridge/shared/types/src/sgx_session.rs`), go-signal PLAN.md Phase 9.3. It
opens the Noise channel to an attested SGX enclave on `attest/dcap` and
`noise`.

- `NewSGXHandshake` (`Handshake::for_sgx`): rejects empty evidence or
  endorsements and an MRENCLAVE that is not 32 bytes, verifies the attestation
  at the current time plus `SkewAdjustment` (one day), takes the `pk` claim
  and writes the empty initial Noise message. `PreQuantum` is NK,
  `PostQuantum` NKhfs.
- `NewCDS2Handshake` / `NewCDS2HandshakeWithAdvisories` (`cds2.rs`): decode
  the `ClientHandshakeStart` message as prost does (last value wins, unknown
  fields and groups skipped, a known field with another wire type rejected)
  and start a post-quantum handshake, accepting the enclave's advisories from
  `dcap.SWAdvisories`. `ExtractCDS2Metrics` is `extract_metrics`.
- `Handshake.Complete` reads the enclave's reply. Like upstream, which reads
  it into an empty buffer, a reply with a payload fails.
- `SGXClientState` is the state machine the apps call (`Cds2ClientState_New`,
  `InitialRequest`, `CompleteHandshake`, `EstablishedSend`,
  `EstablishedRecv`). A call in the wrong state returns `ErrInvalidState`,
  and a failed `CompleteHandshake` leaves the state unusable.

Errors follow `enclave.rs` `Error`: `ErrAttestation` (wrapping the `dcap`
error), `ErrAttestationData`, `ErrNoiseHandshake`, `ErrNoise` (wrapping the
`noise` error) and `ErrInvalidState`.

Not ported: SVR2 (`svr2.rs`, the raft config and minimum-limit validation of
`UnvalidatedHandshake::validate`). `Claims` therefore keeps SVR2's `config`
and `minimum_limits` claims undecoded, where upstream would reject malformed
ones; the CDSI enclave attests only `pk`.

Tests port `sgx_session.rs` `test_clock_skew`, `test_happy_path`,
`test_mismatched_keys` and `test_invalid_private_key` on the recorded
`cds2_test` blob, with a Go `noise` responder in place of snow, and `cds2.rs`
`attest_cds2` on the recorded CDSI handshake. Further cases cover the input
checks, the `ClientHandshakeStart` decoding, metrics and the state machine.
The expected outcomes of the decoding cases and of replies that are
truncated, garbage or carry a payload were checked once against upstream's
`cds2::new_handshake_with_advisories` and `Handshake::complete`. The
recorded blobs are read from `../dcap/testdata`. The `cds2_test` blob needs
upstream's test-only acceptance of TCB evaluation data number 12, which
`export_test.go` turns on through `attest/internal/testhook`.
