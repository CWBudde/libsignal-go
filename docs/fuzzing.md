# Fuzzing

Every function in this module that parses bytes (or strings) that can come
from a peer, a server, an enclave or local storage has a native Go fuzz target
(`func FuzzXxx(f *testing.F)`). This page lists them, says how to run them, and
records the parsers deliberately left out.

## Running the fuzzers

The seed corpus of every target runs as an ordinary test, so `go test ./...`
already replays all seeds and every committed regression input under
`<pkg>/testdata/fuzz/<FuzzName>/`.

To mutate, run one target:

```sh
go test -run '^$' -fuzz '^FuzzRecv$' -fuzztime 1m ./spqr
```

or all of them with `scripts/fuzz.sh`, which discovers the targets per package
(`go test -list '^Fuzz'`) and runs each in turn:

```sh
scripts/fuzz.sh                                 # every target, 10s each
FUZZTIME=2m scripts/fuzz.sh ./attest/...        # longer, one subtree
FUZZ_FILTER='^spqr\.' scripts/fuzz.sh           # targets matching pkg.FuzzName
FUZZ_SHARD=1/4 scripts/fuzz.sh                  # every 4th target, from index 1
```

The script runs every selected target even after a failure, then lists the
failing targets and the new corpus files (the reproducers) and exits non-zero.
With `FUZZ_ARTIFACT_DIR` set it also copies the reproducers there.

Go's fuzzer stops reporting executions while it minimizes a new interesting
input (up to a minute per input), so a run that shows `0/sec` for a while is
usually minimizing, not hung. When `-fuzztime` runs out during such a
minimization, `go test` can fail with `context deadline exceeded` and no
failing input; the script retries a target once in that case instead of
reporting it.

## CI budget

`.github/workflows/fuzz.yml` runs `scripts/fuzz.sh` in four shards:

| Trigger | Budget per target | Wall time per shard (approx.) |
|---------|-------------------|-------------------------------|
| pull request, push to `main` | 10s | 4 min |
| weekly schedule (Sunday 03:00 UTC) | 2m | 40 min |
| manual dispatch | `fuzztime` input (default 2m) | |

A failing shard uploads the reproducers as the `fuzz-reproducers-shard-N`
artifact. Fix the bug, and commit the reproducer under
`<pkg>/testdata/fuzz/<FuzzName>/` so it stays a regression test.

## Writing a target

Follow the existing targets: seed from real encodings (committed vectors,
recorded blobs under `testdata`, or objects generated once before `f.Fuzz`,
never per input), add a few malformed seeds, and check more than "no panic"
where the API allows it: an accepted input must re-serialize to the same bytes
when the format is canonical, and to bytes that parse back to the same value
otherwise. Keep each iteration cheap; skip inputs whose cost is set by local
configuration rather than by the attacker (see `spqr.FuzzRecv`).

## Inventory

"Before" marks targets that existed before the 2026-09 fuzzing sweep, "new"
the ones it added. A function listed as a thin wrapper adds no parsing of its
own to the function whose target covers it.

### Wire messages and records

| Parser | Fuzz target | |
|--------|-------------|-|
| `protocol.DeserializeSignalMessage` | `protocol.FuzzDeserializeSignalMessage` | before |
| `protocol.DeserializePreKeySignalMessage` | `protocol.FuzzDeserializePreKeySignalMessage` | before |
| `protocol.DeserializeSenderKeyMessage` | `protocol.FuzzDeserializeSenderKeyMessage` | before |
| `protocol.DeserializeSenderKeyDistributionMessage` | `protocol.FuzzDeserializeSenderKeyDistributionMessage` | before |
| `protocol.DeserializeDecryptionErrorMessage` | `protocol.FuzzDeserializeDecryptionErrorMessage` | before |
| `protocol.DeserializePlaintextContent` | `protocol.FuzzDeserializePlaintextContent` | before |
| `protocol.DecryptionErrorMessageForOriginal` | `protocol.FuzzDecryptionErrorMessageForOriginal` | new |
| `protocol.ExtractDecryptionErrorMessageFromSerializedContent` | `protocol.FuzzExtractDecryptionErrorMessage` | new |
| `session.DeserializeSessionRecord` | `session.FuzzDeserializeSessionRecord` | before |
| `session.DeserializePreKeyRecord` | `session.FuzzDeserializePreKeyRecord` | new |
| `session.DeserializeSignedPreKeyRecord` | `session.FuzzDeserializeSignedPreKeyRecord` | new |
| `session.DeserializeKyberPreKeyRecord` | `session.FuzzDeserializeKyberPreKeyRecord` | new |
| `session.ProcessPreKeyBundle` | `session.FuzzProcessPreKeyBundle` | before |
| `session.Decrypt` | `session.FuzzDecrypt` | before |
| `session.SessionState.PQRatchetRecv` | thin wrapper of `spqr.Recv` (`spqr.FuzzRecv`) | new |
| `groups.DeserializeSenderKeyRecord` | `groups.FuzzDeserializeSenderKeyRecord` | before |
| `groups.ProcessSenderKeyDistributionMessage` | `groups.FuzzDeserializeSenderKeyDistributionMessage` | before |
| `groups.Decrypt` | `groups.FuzzGroupDecrypt` | before |
| `spqr.DecodeState` | `spqr.FuzzDecodeState` | before |
| `spqr.Recv` | `spqr.FuzzRecv` | new |
| `spqr.Negotiation`, `spqr.CurrentVersion` | `spqr.FuzzRecv` | new |
| SPQR v1 message codec (`deserializeMessage`) | `spqr.FuzzDeserializeMessage` | new |
| `chunked.EncoderFromProto` (SPQR state) | `chunked.FuzzEncoderFromProto` | new |
| `chunked.DecoderFromProto`, `Decoder.AddChunk`, `Decoder.DecodedMessage` | `chunked.FuzzDecoderFromProto` | new |
| `sealedsender.DeserializeUnidentifiedSenderMessageContent` | `sealedsender.FuzzDeserializeUSMC` | before |
| `sealedsender.DecryptToUSMC` (v1 and v2) | `sealedsender.FuzzDecryptToUSMC` | before |
| `sealedsender.DecryptToUSMCAndValidate` | `sealedsender.FuzzDecryptToUSMC` | new |
| `fingerprint.DeserializeScannableFingerprint` | `fingerprint.FuzzDeserializeScannableFingerprint` | before |
| `fingerprint.ScannableFingerprint.Compare` | `fingerprint.FuzzDeserializeScannableFingerprint` | before |
| `address.ParseServiceIDBinary` | `address.FuzzParseServiceIDBinary` | before |
| `address.ParseServiceIDFixedWidthBinary` | `address.FuzzParseServiceIDBinary` (17-byte path) | before |
| `address.ParseServiceIDString` | `address.FuzzParseServiceIDString` | before |
| `usernames.Parse`, `Hash`, `HashHex`, `ReserveUsernameHash` | `usernames.FuzzParse` | new |
| `usernames.FromParts`, `HashFromParts` | same validation as `Parse` (`usernames.FuzzParse`) | new |
| `usernames.ParseLinkBuffer` | `usernames.FuzzParseLinkBuffer` | new |
| `usernames.DecryptUsername` | `usernames.FuzzParseLinkBuffer` | new |
| username link payload (`decodeUsernameData`, behind the HMAC) | `usernames.FuzzDecodeUsernameData` | new |
| `accountkeys.ParseAccountEntropyPool` | `accountkeys.FuzzParseAccountEntropyPool` | new |
| `accountkeys.VerifyLocalPINHash` (PHC string) | `accountkeys.FuzzParsePHC` | new |
| `devicetransfer.GenerateCertificate` (private key DER) | `devicetransfer.FuzzGenerateCertificate` | new |

### Keys, certificates and signatures

| Parser | Fuzz target | |
|--------|-------------|-|
| `curve.DeserializePublicKey` | `curve.FuzzDeserializePublicKey` | before |
| `curve.DeserializePrivateKey` | `curve.FuzzDeserializePrivateKey` | before |
| `curve.PublicKey.VerifySignature` | `curve.FuzzVerifySignature` | before |
| `curve.NewPublicKey` | `curve.FuzzKeyPairFromPublicAndPrivate` | new |
| `curve.KeyPairFromPublicAndPrivate` | `curve.FuzzKeyPairFromPublicAndPrivate` | new |
| `kem.DeserializePublicKey` | `kem.FuzzDeserializePublicKey` | before |
| `kem.DeserializeSecretKey` | `kem.FuzzDeserializeSecretKey` | before |
| `kem.KeyPairFromPublicAndSecret` | `kem.FuzzKeyPairFromPublicAndSecret` | new |
| `identity.DeserializeKeyPair` | `identity.FuzzDeserializeKeyPair` | new |
| `identity.VerifyAlternateIdentity` | `identity.FuzzVerifyAlternateIdentity` | new |
| `sealedsender.DeserializeServerCertificate` | `sealedsender.FuzzDeserializeServerCertificate` | before |
| `sealedsender.DeserializeSenderCertificate` | `sealedsender.FuzzDeserializeSenderCertificate` | before |
| `mlkem768incr.NewEncapsulationKey768` | `mlkem768incr.FuzzNewEncapsulationKey768` | new |
| `mlkem768incr.ValidatePublicKeyParts` | `mlkem768incr.FuzzIncrementalPublicKey` | new |
| `mlkem768incr.Encapsulate1Internal`, `Encapsulate2` (peer pk1/pk2) | `mlkem768incr.FuzzIncrementalPublicKey` | new |
| `mlkem768incr.FixEncapsStateEndianness` | `mlkem768incr.FuzzEncapsState` | new |
| `mlkem768incr.DecapsulateCompressedKey` | `mlkem768incr.FuzzDecapsulateCompressedKey` | new |

### Symmetric crypto

| Parser | Fuzz target | |
|--------|-------------|-|
| `crypto.DecryptCBC` | `crypto.FuzzCBCRoundTrip` | before |
| `crypto.OpenGCM` | `crypto.FuzzGCMOpen` | before |
| `crypto.Aes256Ctr32.Process` | `crypto.FuzzCTRProcess` | before |
| `gcmsiv.Open` | `gcmsiv.FuzzOpen` | before |
| `aes256gcmsiv.Cipher.Decrypt` | thin wrapper of `gcmsiv.Open` (`gcmsiv.FuzzOpen`) | before |

### Attestation and enclave channels

| Parser | Fuzz target | |
|--------|-------------|-|
| `dcap.ParseEvidence` | `dcap.FuzzParseEvidence` | before |
| `dcap.ParseCustomClaims` | `dcap.FuzzParseEvidence` | before |
| `dcap.ParsePCKExtension` | `dcap.FuzzParseEvidence` | before |
| `dcap.ParseRevocationList` | `dcap.FuzzParseEvidence` | before |
| `dcap.ParseEndorsements` | `dcap.FuzzParseEndorsements` | before |
| `dcap.ParseTCBInfo` | `dcap.FuzzParseEndorsements` | before |
| `dcap.ParseEnclaveIdentity` | `dcap.FuzzParseEndorsements` | before |
| `dcap.ParseQuote` | `dcap.FuzzParseQuote` | new |
| `dcap.ParseQuoteSupport` | `dcap.FuzzParseQuote` | new |
| `dcap.ParseCertChainPEM` | `dcap.FuzzParseCertChainPEM` | new |
| `dcap.VerifyRemoteAttestation` | `dcap.FuzzVerifyRemoteAttestation` | new |
| `dcap.AttestationMetrics` | `dcap.FuzzVerifyRemoteAttestation` | new |
| `enclave.NewCDS2Handshake`, `NewCDS2HandshakeWithAdvisories`, `NewCDS2ClientState` (`ClientHandshakeStart`) | `enclave.FuzzCDS2Handshake` | new |
| `enclave.ExtractCDS2Metrics` | `enclave.FuzzCDS2Handshake` | new |
| `enclave.NewSGXHandshake` | `dcap.FuzzVerifyRemoteAttestation`, `enclave.FuzzCDS2Handshake` | new |
| `enclave.Handshake.Complete`, `SGXClientState.CompleteHandshake` | `enclave.FuzzHandshakeComplete` (slow: one DCAP verification per input) | new |
| `enclave.SGXClientState.EstablishedRecv` | thin wrapper of `noise.Transport.Recv` (`noise.FuzzTransportRecv`) | new |
| `hsmenclave.NewClient` | `hsmenclave.FuzzNewClient` | new |
| `hsmenclave.Client.CompleteHandshake` | `hsmenclave.FuzzCompleteHandshake` | new |
| `hsmenclave.Client.EstablishedRecv` | `hsmenclave.FuzzEstablishedRecv` | new |
| `noise.HandshakeState.ReadMessage` | `noise.FuzzReadMessage` | before |
| `noise.NewInitiator`, `noise.NewResponder` (static keys) | `noise.FuzzHandshakeKeys` | new |
| `noise.Transport.Recv` | `noise.FuzzTransportRecv` | new |

### zkgroup, zkcredential and poksho

| Parser | Fuzz target | |
|--------|-------------|-|
| `poksho.ParseProof` | `poksho.FuzzProof` | before |
| `poksho.VerifySignature` | `poksho.FuzzProof` | before |
| `poksho.Statement.VerifyProof` | `poksho.FuzzVerifyProof` | new |
| `poksho.ScalarFromCanonicalBytes`, `PointFromCanonicalBytes` | `poksho.FuzzCanonicalEncodings` | new |
| `ristrettolizard` decoding | `ristrettolizard.FuzzLizard` | before |
| `zkcredential.Parse*` (20 types: `Attribute`, `EncryptionKeyPair`, `EncryptionPublicKey`, `BlindingKeyPair`, `BlindingPublicKey`, `BlindedPoint`, `BlindedAttribute`, `Credential`, `CredentialKeyPair`, `CredentialPublicKey`, `IssuanceProof`, `BlindedIssuanceProof`, `PresentationProof`, `ServerRootKeyPair`, `ServerRootPublicKey`, `ServerDerivedKeyPair`, `ServerDerivedPublicKey`, `ClientDecryptionKey`, `EndorsementResponse`, `Endorsement`) | `compat.FuzzZKCredentialEncoding` | before |
| `zkgroup.Parse*` for `ServerPublicParams`, `GroupSecretParams`, `GroupPublicParams`, `UUIDCiphertext`, `ProfileKeyCiphertext`, `ProfileKeyCredentialRequestContext`, `ProfileKeyCredentialRequest`, `ExpiringProfileKeyCredentialResponse`, `ExpiringProfileKeyCredential`, `ProfileKeyCredentialPresentation`, `AuthCredentialWithPniResponse`, `AuthCredentialWithPni`, `AuthCredentialPresentation` (13) | `zkgroup.FuzzAPIEncoding` | before |
| `zkgroup.GroupSecretParams.DecryptBlob` | `zkgroup.FuzzAPIEncoding` | before |
| `zkgroup.Parse*` for `GroupSendEndorsementsResponse`, `GroupSendEndorsement`, `GroupSendToken`, `GroupSendFullToken` (4) | `zkgroup.FuzzGroupSendEncoding` | before |
| `zkgroup.ServerPublicParams.VerifySignature` | thin wrapper of `poksho.VerifySignature` (`poksho.FuzzProof`) | before |
| `zkcrypto.Parse*` for `UID`, `ProfileKey`, `ProfileKeyCommitment`, `ProfileKeyCommitmentWithNonce`, `UIDKeyPair`, `ProfileKeyKeyPair`, `UIDCiphertext`, `ProfileKeyCiphertext` (8) | `zkcrypto.FuzzEncodings` | before |
| `zkcrypto.Parse*` for `CredentialPublicKey`, `CredentialKeyPair`, `Credential`, `BlindedCredential`, `BlindedCredentialWithNonce`, `Receipt`, `ReceiptRequestKeyPair`, `ReceiptRequestPublicKey`, `ReceiptRequestCiphertext`, `ReceiptRequestCiphertextWithNonce`, `ProfileRequestKeyPair`, `ProfileRequestPublicKey`, `ProfileRequestCiphertext`, `ProfileRequestCiphertextWithNonce`, `ProfileRequestProof`, `ProfileIssuanceProof`, `ReceiptIssuanceProof`, `ProfilePresentationProof`, `ProfilePresentationProofV1`, `ProfilePresentationProofV2`, `ReceiptPresentationProof`, `SignatureKeyPair`, `SignaturePublicKey` (23) | `compat.FuzzLegacyCredentialEncodings` | before |
| `zkcrypto.SignaturePublicKey.Verify` | thin wrapper of `poksho.VerifySignature` (`poksho.FuzzProof`) | before |

### Summary

161 inventory entries (one per table row, except that each type of a
`Parse*` family counts once): 114 were covered before, 47 are covered by the
35 targets added now (and one extended target), for 74 fuzz targets in all.
Nothing is left MISSING.

## Deliberately not fuzzed

| Function | Why |
|----------|-----|
| `ratchet.NewChainKey`, `NewRootKey`, `NewMessageKeys`, `NewMessageKeyGeneratorFromSeed`, `DeriveInitialKeys`, `PQXDHSecret` | take derived key material, not encoded input; they only check lengths |
| `crypto.NewAES256CTR32`, `aes256gcmsiv.New`, `crypto.HKDF*`, `crypto.HMACSHA256` | key or KDF input, length checks only |
| `mlkem768incr.NewDecapsulationKey768`, `GenerateIncrementalKey` | expand a 64-byte seed; every seed is valid |
| `poksho.ScalarFromUniformBytes`, `PointFromUniformBytes`, `ristrettolizard.Map`/`Encode` | hash or map fixed-size input; every input is valid |
| `zkcredential.ServerDerivedKeyPair.VerifyToken` | server side; a constant-time comparison of opaque bytes |
| `session.MessageDecryptSignal`, `MessageDecryptPreKey` | take already parsed messages (their parsers are fuzzed above); the decrypt state machine is exercised by `session.FuzzDecrypt`. A pre-key decrypt fuzzer needs a fresh store per input and is a follow-up |
| `enclave.ClaimsFromCustom` | takes the claims map of a verified attestation, not bytes |
| `internal/upstream.Load` | reads the embedded, committed manifest |
| `messagebackup`, `svr`, `svrb`, `proofreport` | report-only packages without parsers |
| `stores/inmem` | in-memory stores; they hold records, the record parsers are fuzzed |

## Findings

- 2026-09: `spqr.FuzzRecv` found that a stored SPQR state whose chunk decoder
  claims fewer points than the header (or ct2) needs made `Recv` panic with a
  slice bound out of range, instead of returning an error
  (`recvHdrChunk`, `recvCt2ChunkEkSent`). Only a corrupted stored state
  reaches it; a peer's message alone cannot. `Recv` now returns
  `ErrInvalidState` there; the reproducer is
  `spqr/testdata/fuzz/FuzzRecv/67ff4125e1b28fca`.
