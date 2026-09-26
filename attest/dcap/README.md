# attest/dcap

Pure-Go port of libsignal **v0.102.2** `rust/attest/src/dcap` and
`cert_chain.rs` (go-signal PLAN.md Phase 9.2), on the standard library's
`crypto/x509` and `crypto/ecdsa`.

So far this covers the evidence and the certificate layer:

- `ParseEvidence` / `ParseQuote` / `ParseQuoteSupport`: the SGX v3 ECDSA
  quote (header, report bodies as wire bytes, raw r‖s signatures, QE report,
  auth data, PCK chain) and Open Enclave custom claims. `Quote.VerifySignature`
  checks the ISV signature with the attestation key,
  `QuoteSupport.VerifySignature` the QE report signature with the PCK leaf key,
  `VerifyQEReport` the attestation-key hash and zero padding.
- `ParsePCKExtension`: the SGX PCK certificate extension. Unknown, duplicate or
  missing entries are rejected, as upstream.
- `CertChain`, `RevocationList`, `TrustStore`, `RootTrustStore`: upstream's
  BoringSSL `X509_verify_cert` usage with `CRL_CHECK | CRL_CHECK_ALL` at a fixed
  time, rebuilt by hand because `x509.Verify` has no CRL support and different
  usage rules. Issuers are found as `X509_check_issued` does (names,
  AKID/SKID, keyCertSign), trusted roots first; every link's signature, CA and
  path-length constraints, unhandled critical extensions and the validity of
  every certificate, the trust anchor included, are checked. Each certificate
  needs a current CRL from its issuer (the root's own for the root) that
  doesn't list it. The trust anchor's self-signature is not checked, as in
  BoringSSL; `RootTrustStore` checks the root and root CRL against Intel's
  pinned key (`IntelRootKey`).

Not yet ported: endorsements (TCB info, QE identity), the TCB status policy,
MRENCLAVE/config checks and the top-level `verify_remote_attestation`.

Tests port every upstream test of these files under its upstream name
(`sort_*`, `validate_*`, `valid_quote_from_disk`, `isv_sig_*`, `qe_sig_*`,
`qe_report_*`, `deserialize_*`, evidence and util tests,
`test_deserialization`), plus `TestIntelPCKChain`, which validates the
recorded Intel PCK chain against the recorded CRLs as `verify_certificates`
does.
