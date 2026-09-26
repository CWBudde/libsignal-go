# attest/dcap

Pure-Go port of libsignal **v0.102.2** `rust/attest/src/dcap` and
`cert_chain.rs` (go-signal PLAN.md Phase 9.2), on the standard library's
`crypto/x509` and `crypto/ecdsa`.

`VerifyRemoteAttestation(evidence, endorsements, mrenclave, advisories, now)`
is the entry point (`dcap.rs verify_remote_attestation`); it returns the
enclave's custom claims. The pieces:

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

- `ParseEndorsements`: the Open Enclave collateral blob (header, offsets,
  nine fields). TCB info and QE identity signatures are checked over the raw
  JSON bytes with the leaf keys of their issuer chains before decoding.
  `ParseTCBInfo` / `ParseEnclaveIdentity` decode the JSON as upstream's serde
  derives do, not as `encoding/json` would: exact key match, duplicate known
  keys and missing fields rejected, unknown keys ignored, no nulls for numbers
  or strings, exact hex lengths, u8/u16 ranges, and the untagged v2/v3 TCB
  layout. Stricter than serde in two corners no signed Intel collateral uses:
  structs written as JSON arrays and enum variants written as `{"Name": null}`
  are rejected.
- Attestation (`attest_impl`): expiry of the evidence and collateral (TCB
  evaluation data number ≥ `TCBEvaluationDataNumberMin` = 21), all four chains
  and both CRLs against Intel's key, the quoting enclave against the QE
  identity (Intel vendor ID, MRSIGNER, ISVPRODID, masked MISCSELECT and
  attributes, QE TCB level up to date), the report signatures, the TCB level
  lookup (first level the platform's SVNs reach; `UpToDate` or
  `SWHardeningNeeded` with advisory IDs, anything else fails), the claims hash
  and the debug flag. `VerifyRemoteAttestation` then requires every advisory
  of a hardening-needed level to be accepted and the expected MRENCLAVE.
- `SWAdvisories` and the `EnclaveID*` MRENCLAVE constants of v0.102.2
  (`constants.rs`); raft configs and SVR-specific TCB exceptions are not here.
- `AttestationMetrics`: the validity timestamps upstream reports.

Upstream's test-only acceptance of TCB evaluation data number 12 is an
unexported switch that only this package's tests turn on. The SVR2/CDS2
handshakes (Noise, raft config) are not here.

Tests port every upstream test of these files under its upstream name
(`sort_*`, `validate_*`, `valid_quote_from_disk`, `isv_sig_*`, `qe_sig_*`,
`qe_report_*`, `deserialize_*`, evidence and util tests,
`test_deserialization`), all of `endorsements.rs` and all 25 of `dcap.rs`
(the `FakeAttestation` cases re-sign the recorded blobs with test
certificates, see `fakes_test.go`; the `test_verify_remote_attestation*`
cases use the recorded CDSI handshake). `TestIntelPCKChain` validates the
recorded Intel PCK chain against the recorded CRLs as `verify_certificates`
does. Further cases cover MRENCLAVE and advisory policy, expiry boundaries,
tampered blobs and the strict JSON decoding. `TestRecordedVectors` runs every
recorded blob of upstream's `tests/data` (`cds2_test` at the `test_clock_skew`
times, `dcap_v3`, `dcap-expired`, `svr2`) with tampered quote, expiry and
wrong measurement cases, each against the outcome upstream gives.
