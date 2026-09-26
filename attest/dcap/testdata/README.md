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
