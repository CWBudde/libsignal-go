// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package compat

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	z "github.com/cwbudde/libsignal-go/zkcredential"
	"os"
	"testing"
)

type genericCodec struct {
	field string
	parse func([]byte) ([]byte, error)
}

func genericCodecs() []genericCodec {
	d := z.NewDomain("Compat_ZKCredential_A")
	return []genericCodec{
		{"key", func(b []byte) ([]byte, error) {
			v, e := z.ParseCredentialKeyPair(z.StandardMode, b)
			if e != nil {
				return nil, e
			}
			return v.Bytes(), nil
		}},
		{"public_key", func(b []byte) ([]byte, error) {
			v, e := z.ParseCredentialPublicKey(b)
			if e != nil {
				return nil, e
			}
			return v.Bytes(), nil
		}},
		{"enc_key0", func(b []byte) ([]byte, error) {
			v, e := z.ParseEncryptionKeyPair(d, b)
			if e != nil {
				return nil, e
			}
			return v.Bytes(), nil
		}},
		{"enc_public0", func(b []byte) ([]byte, error) {
			v, e := z.ParseEncryptionPublicKey(d, b)
			if e != nil {
				return nil, e
			}
			return v.Bytes(), nil
		}},
		{"attr0", func(b []byte) ([]byte, error) {
			v, e := z.ParseAttribute(b)
			if e != nil {
				return nil, e
			}
			return v.Bytes(), nil
		}},
		{"blinding_key", func(b []byte) ([]byte, error) {
			v, e := z.ParseBlindingKeyPair(b)
			if e != nil {
				return nil, e
			}
			return v.Bytes(), nil
		}},
		{"blinding_public", func(b []byte) ([]byte, error) {
			v, e := z.ParseBlindingPublicKey(b)
			if e != nil {
				return nil, e
			}
			return v.Bytes(), nil
		}},
		{"blind0", func(b []byte) ([]byte, error) {
			v, e := z.ParseBlindedAttribute(b)
			if e != nil {
				return nil, e
			}
			return v.Bytes(), nil
		}},
		{"revealed_blind0", func(b []byte) ([]byte, error) {
			v, e := z.ParseBlindedPoint(b)
			if e != nil {
				return nil, e
			}
			return v.Bytes(), nil
		}},
		{"credential", func(b []byte) ([]byte, error) {
			v, e := z.ParseCredential(b)
			if e != nil {
				return nil, e
			}
			return v.Bytes(), nil
		}},
		{"issuance", func(b []byte) ([]byte, error) {
			v, e := z.ParseIssuanceProof(b)
			if e != nil {
				return nil, e
			}
			return v.Bytes(), nil
		}},
		{"issuance", func(b []byte) ([]byte, error) {
			v, e := z.ParseBlindedIssuanceProof(b)
			if e != nil {
				return nil, e
			}
			return v.Bytes(), nil
		}},
		{"presentation", func(b []byte) ([]byte, error) {
			v, e := z.ParsePresentationProof(b)
			if e != nil {
				return nil, e
			}
			return v.Bytes(), nil
		}},
		{"root", func(b []byte) ([]byte, error) {
			v, e := z.ParseServerRootKeyPair(b)
			if e != nil {
				return nil, e
			}
			return v.Bytes(), nil
		}},
		{"root_public", func(b []byte) ([]byte, error) {
			v, e := z.ParseServerRootPublicKey(b)
			if e != nil {
				return nil, e
			}
			return v.Bytes(), nil
		}},
		{"derived", func(b []byte) ([]byte, error) {
			v, e := z.ParseServerDerivedKeyPair(b)
			if e != nil {
				return nil, e
			}
			return v.Bytes(), nil
		}},
		{"derived_public", func(b []byte) ([]byte, error) {
			v, e := z.ParseServerDerivedPublicKey(b)
			if e != nil {
				return nil, e
			}
			return v.Bytes(), nil
		}},
		{"client", func(b []byte) ([]byte, error) {
			v, e := z.ParseClientDecryptionKey(b)
			if e != nil {
				return nil, e
			}
			return v.Bytes(), nil
		}},
		{"endorsement_response", func(b []byte) ([]byte, error) {
			v, e := z.ParseEndorsementResponse(b)
			if e != nil {
				return nil, e
			}
			return v.Bytes(), nil
		}},
		{"combined", func(b []byte) ([]byte, error) {
			v, e := z.ParseEndorsement(b)
			if e != nil {
				return nil, e
			}
			return v.Bytes(), nil
		}},
	}
}
func TestZKCredentialEncoding(t *testing.T) {
	codecs := genericCodecs()
	for _, c := range loadGeneric(t).Cases {
		for i, codec := range codecs {
			if i == 10 && c.Params.blinded() || i == 11 && !c.Params.blinded() {
				continue
			}
			value, ok := c.Result[codec.field]
			if !ok {
				continue
			}
			raw := zkBytes(t, value)
			encoded, e := codec.parse(raw)
			legacyCheck(t, e)
			if !bytes.Equal(raw, encoded) {
				t.Fatalf("%s round trip", codec.field)
			}
			for n := 0; n < len(raw); n++ {
				if _, e := codec.parse(raw[:n]); e == nil {
					t.Fatalf("%s accepted prefix %d", codec.field, n)
				}
			}
			if _, e := codec.parse(append(bytes.Clone(raw), 0)); e == nil {
				t.Fatalf("%s accepted trailing data", codec.field)
			}
		}
	}
}
func FuzzZKCredentialEncoding(f *testing.F) {
	raw, e := os.ReadFile("vectors/zkcredential.json")
	if e != nil {
		f.Fatal(e)
	}
	var vs genericVectors
	if e = json.Unmarshal(raw, &vs); e != nil {
		f.Fatal(e)
	}
	codecs := genericCodecs()
	for _, c := range vs.Cases {
		for i, codec := range codecs {
			if value, ok := c.Result[codec.field]; ok {
				b, e := hex.DecodeString(value)
				if e != nil {
					f.Fatal(e)
				}
				f.Add(uint8(i), b)
			}
		}
	}
	f.Fuzz(func(t *testing.T, kind uint8, b []byte) {
		codec := codecs[int(kind)%len(codecs)]
		encoded, e := codec.parse(b)
		if e == nil && !bytes.Equal(b, encoded) {
			t.Fatalf("%s changed encoding", codec.field)
		}
	})
}
