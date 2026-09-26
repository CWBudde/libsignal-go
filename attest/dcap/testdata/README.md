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
