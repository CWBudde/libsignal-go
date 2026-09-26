// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package compat

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	z "github.com/cwbudde/libsignal-go/zkgroup/zkcrypto"
	"os"
	"testing"
)

type legacyEncoding interface{ Bytes() []byte }
type legacyParser struct {
	field string
	parse func([]byte) (legacyEncoding, error)
}

var legacyParsers = []legacyParser{
	{"key_auth", func(b []byte) (legacyEncoding, error) { return z.ParseCredentialKeyPair(z.AuthCredentialKind, b) }},
	{"key_auth_pni", func(b []byte) (legacyEncoding, error) {
		return z.ParseCredentialKeyPair(z.AuthWithPNICredentialKind, b)
	}},
	{"key_profile", func(b []byte) (legacyEncoding, error) { return z.ParseCredentialKeyPair(z.ProfileCredentialKind, b) }},
	{"key_expiring", func(b []byte) (legacyEncoding, error) {
		return z.ParseCredentialKeyPair(z.ExpiringProfileCredentialKind, b)
	}},
	{"key_receipt", func(b []byte) (legacyEncoding, error) { return z.ParseCredentialKeyPair(z.ReceiptCredentialKind, b) }},
	{"key_pni", func(b []byte) (legacyEncoding, error) { return z.ParseCredentialKeyPair(z.PNICredentialKind, b) }},
	{"public_expiring", func(b []byte) (legacyEncoding, error) { return z.ParseCredentialPublicKey(b) }},
	{"signing_key", func(b []byte) (legacyEncoding, error) { return z.ParseSignatureKeyPair(b) }},
	{"signing_public", func(b []byte) (legacyEncoding, error) { return z.ParseSignaturePublicKey(b) }},
	{"request_key", func(b []byte) (legacyEncoding, error) { return z.ParseProfileRequestKeyPair(b) }},
	{"request_public", func(b []byte) (legacyEncoding, error) { return z.ParseProfileRequestPublicKey(b) }},
	{"request", func(b []byte) (legacyEncoding, error) { return z.ParseProfileRequestCiphertext(b) }},
	{"request_with_nonce", func(b []byte) (legacyEncoding, error) { return z.ParseProfileRequestCiphertextWithNonce(b) }},
	{"request_proof", func(b []byte) (legacyEncoding, error) { return z.ParseProfileRequestProof(b) }},
	{"blinded", func(b []byte) (legacyEncoding, error) { return z.ParseBlindedCredential(b) }},
	{"blinded_with_nonce", func(b []byte) (legacyEncoding, error) { return z.ParseBlindedCredentialWithNonce(b) }},
	{"issuance_proof", func(b []byte) (legacyEncoding, error) { return z.ParseProfileIssuanceProof(b) }},
	{"credential", func(b []byte) (legacyEncoding, error) { return z.ParseCredential(b) }},
	{"presentation", func(b []byte) (legacyEncoding, error) { return z.ParseProfilePresentationProof(b) }},
	{"receipt_request_key", func(b []byte) (legacyEncoding, error) { return z.ParseReceiptRequestKeyPair(b) }},
	{"receipt_request_public", func(b []byte) (legacyEncoding, error) { return z.ParseReceiptRequestPublicKey(b) }},
	{"receipt_request", func(b []byte) (legacyEncoding, error) { return z.ParseReceiptRequestCiphertext(b) }},
	{"receipt_request_with_nonce", func(b []byte) (legacyEncoding, error) { return z.ParseReceiptRequestCiphertextWithNonce(b) }},
	{"receipt_issuance", func(b []byte) (legacyEncoding, error) { return z.ParseReceiptIssuanceProof(b) }},
	{"receipt_presentation", func(b []byte) (legacyEncoding, error) { return z.ParseReceiptPresentationProof(b) }},
	{"receipt", func(b []byte) (legacyEncoding, error) { return z.ParseReceipt(b) }},
	{"presentation", func(b []byte) (legacyEncoding, error) { return z.ParseProfilePresentationProofV1(b) }},
	{"presentation", func(b []byte) (legacyEncoding, error) { return z.ParseProfilePresentationProofV2(b) }},
}

func TestZKGroupCredentialEncodings(t *testing.T) {
	cases := loadLegacy(t).Cases
	for _, parser := range legacyParsers {
		for _, c := range cases {
			original := zkBytes(t, c.Result[parser.field])
			input := bytes.Clone(original)
			parsed, e := parser.parse(input)
			legacyCheck(t, e)
			if !bytes.Equal(parsed.Bytes(), original) {
				t.Fatalf("%s roundtrip mismatch", parser.field)
			}
			clear(input)
			encoded := parsed.Bytes()
			encoded[0] ^= 1
			if !bytes.Equal(parsed.Bytes(), original) {
				t.Fatalf("%s aliases input/output", parser.field)
			}
		}
		b := zkBytes(t, cases[0].Result[parser.field])
		for i := range len(b) {
			if _, e := parser.parse(b[:i]); e == nil {
				t.Fatalf("%s accepted prefix %d", parser.field, i)
			}
		}
		if _, e := parser.parse(append(b, 0)); e == nil {
			t.Fatalf("%s accepted trailing byte", parser.field)
		}
	}
	// Proof Vec fields are opaque at deserialization. Huge length prefixes must
	// fail without allocating, while empty/noncanonical inner proofs parse and
	// are rejected at verification (matching upstream serde).
	for _, typ := range []struct {
		parse  func([]byte) (legacyEncoding, error)
		points int
	}{
		{func(b []byte) (legacyEncoding, error) { return z.ParseProfileRequestProof(b) }, 0},
		{func(b []byte) (legacyEncoding, error) { return z.ParseProfileIssuanceProof(b) }, 0},
		{func(b []byte) (legacyEncoding, error) { return z.ParseProfilePresentationProof(b) }, 8},
		{func(b []byte) (legacyEncoding, error) { return z.ParseReceiptIssuanceProof(b) }, 0},
		{func(b []byte) (legacyEncoding, error) { return z.ParseReceiptPresentationProof(b) }, 5},
	} {
		empty := make([]byte, typ.points*32+8)
		v, e := typ.parse(empty)
		legacyCheck(t, e)
		if !bytes.Equal(v.Bytes(), empty) {
			t.Fatal("opaque empty proof changed")
		}
		binary.LittleEndian.PutUint64(empty[typ.points*32:], ^uint64(0))
		if _, e := typ.parse(empty); e == nil {
			t.Fatal("accepted overflowing proof length")
		}
	}
	// Scalars use canonical encodings, including historically unused scalars.
	for _, field := range []string{"key_auth", "key_auth_pni", "key_profile", "key_expiring", "key_receipt", "key_pni", "signing_key", "request_key", "request_with_nonce", "blinded", "blinded_with_nonce", "credential", "receipt_request_key", "receipt_request_with_nonce"} {
		for _, parser := range legacyParsers {
			if parser.field != field {
				continue
			}
			b := zkBytes(t, cases[0].Result[field])
			copy(b[:32], bytes.Repeat([]byte{255}, 32))
			if _, e := parser.parse(b); e == nil {
				t.Fatalf("%s accepted noncanonical scalar", field)
			}
		}
	}
}
func FuzzLegacyCredentialEncodings(f *testing.F) {
	raw, e := os.ReadFile("vectors/zkgroup-credentials.json")
	if e != nil {
		f.Fatal(e)
	}
	var v legacyVectors
	if e = json.Unmarshal(raw, &v); e != nil {
		f.Fatal(e)
	}
	for i, p := range legacyParsers {
		f.Add(uint8(i), []byte{}) //nolint:gosec // G115: fixed table has fewer than 256 parsers.
		b, e := hex.DecodeString(v.Cases[0].Result[p.field])
		if e != nil {
			f.Fatal(e)
		}
		f.Add(uint8(i), b) //nolint:gosec // G115: fixed table has fewer than 256 parsers.
	}
	f.Fuzz(func(t *testing.T, index uint8, b []byte) {
		p := legacyParsers[int(index)%len(legacyParsers)]
		value, e := p.parse(b)
		if e != nil {
			return
		}
		if !bytes.Equal(value.Bytes(), b) {
			t.Fatalf("%s encoding changed", p.field)
		}
	})
}
