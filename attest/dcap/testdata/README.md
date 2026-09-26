<!--
Copyright 2026 libsignal-go contributors.
SPDX-License-Identifier: AGPL-3.0-only
-->

# testdata

Recorded attestation data copied unchanged from upstream libsignal
**v0.102.2**, `rust/attest/tests/data/` (AGPL-3.0-only, © Signal Messenger):

- `dcap.evidence`: Open Enclave evidence (SGX v3 quote + custom claims)
- `dcap.pubkey`: hex of the evidence's `pk` claim
- `dcap.endorsements`: its collateral (TCB info, QE identity, CRLs, chains)
- `sgx_x509_extension.der`: an SGX PCK certificate extension
- `tcb_info_v2.json`, `tcb_info_v3.json`: Intel TCB info in both layouts
- `cdsi.handshakestart`: a recorded CDSI `ClientHandshakeStart` (evidence in
  field 2, endorsements in field 3), with `cdsi.timestamp` (big-endian Unix
  seconds), `cdsi.mrenclave`, `cdsi.pubkey` (the raw `pk` claim) and
  `cdsi.advisories` (newline-separated)
- `cds2_test.evidence`, `cds2_test.endorsements`: a 2022 CDS2 test
  attestation (TCB evaluation data number 12), with `cds2_test.mrenclave` and
  `cds2_test.privatekey` (hex; the enclave's Noise static key, whose X25519
  public key is the `pk` claim)
- `dcap_v3.evidence`, `dcap_v3.endorsements`, `dcap_v3.pubkey`: a 2022
  attestation (evaluation data number 12) no upstream test uses
- `dcap-expired.evidence`, `dcap-expired.endorsements`, `dcap-expired.pubkey`:
  a 2021 attestation no upstream test uses; its PCK CRL field is not DER
- `svr2.handshakestart`: a recorded SVR2 `ClientHandshakeStart`, with
  `svr2.timestamp`, `svr2.mrenclave`, `svr2.pubkey` and `svr2.advisories` as
  for CDSI

The expected outcomes in `vectors_test.go` are those of upstream's
`dcap::verify_remote_attestation` (v0.102.2, `test-util` feature for the
evaluation data number 12 exception) run once on the same inputs and times;
this matters most for `dcap_v3` and `dcap-expired`, which upstream never
tests.
