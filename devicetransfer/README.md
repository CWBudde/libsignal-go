# devicetransfer

Pure-Go port of libsignal **v0.102.2** `rust/device-transfer` as the bridge
calls it (`DeviceTransfer_GeneratePrivateKey`,
`DeviceTransfer_GenerateCertificate`), go-signal PLAN.md Phase 9.4.

- `GeneratePrivateKey` returns a new 4096-bit RSA key (e = 65537) in PKCS#8
  DER.
- `GenerateCertificate(privateKey, name, daysToExpire, now)` returns
  upstream's self-signed certificate, built field by field:
  - version 1 with serial number 0 and no extensions;
  - issuer and subject CN=name, O=Signal Foundation, OU=Device Transfer,
    each in its own RDN as UTF8String;
  - valid from one day before `now` until `daysToExpire` days after it, in
    UTCTime up to 2049 and GeneralizedTime from 2050;
  - signed with SHA-256.

  Upstream reads the clock itself; the Go function takes `now`.

Inputs are read as upstream reads them:

- **Keys:** the private key may be PKCS#8, PKCS#1 (RSA) or SEC 1 (EC), the
  formats BoringSSL's `d2i_AutoPrivateKey` reads.
  - RSA keys sign with `sha256WithRSAEncryption`, EC keys (P-256, P-384,
    P-521) with `ecdsa-with-SHA256`.
  - A key that does not decode gives `ErrKeyDecoding`.
  - Ed25519 and X25519 keys decode but cannot sign, so they give
    `ErrInternal`, as upstream's `InternalError` does.
- **Name:** must be 1 to 64 characters, the X.520 bound OpenSSL enforces.
  Other lengths give `ErrInternal`.
- **Validity:** `daysToExpire` above 49710 gives `ErrInternal`. Upstream
  computes `days·86400` in a u32 with overflow checks and panics there.
- **Invalid UTF-8 names:** rejected with `ErrInternal`; upstream's `String`
  parameter cannot hold them.

The tests pin all of this, and the recorded certificates in `testdata/` were
made by upstream's `create_self_signed_cert`:

- For the RSA key, the Go certificate from the same key at the same second is
  byte-identical, since RSA PKCS#1 v1.5 signatures are deterministic.
- For the EC key, the to-be-signed part is identical.

Also checked once against upstream:

- BoringSSL parsed a Go-generated key and Go certificates as upstream's
  `test_generate_and_parse` does, and used the key to sign. The
  certificates' self-signatures verified.
- The name, validity and key-format limits above are upstream's.
