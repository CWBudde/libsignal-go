// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package dcap_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"maps"
	"testing"

	"github.com/cwbudde/libsignal-go/attest/dcap"
)

// Ports of evidence.rs's tests.

func TestEvidenceFromBytes(t *testing.T) {
	data := readTestdata(t, "dcap.evidence")
	pkey, err := hex.DecodeString(string(readTestdata(t, "dcap.pubkey")))
	if err != nil {
		t.Fatal(err)
	}
	e, err := dcap.ParseEvidence(data)
	if err != nil {
		t.Fatalf("should parse: %v", err)
	}
	if !bytes.Equal(e.Claims.Map["pk"], pkey) {
		t.Fatalf("pk claim %x", e.Claims.Map["pk"])
	}
	want, _ := hex.DecodeString("337ac97ce088a132daeb1308ea3159f807de4a827e875b2c90ce21bf4751196f")
	if got := e.Quote.Body.ReportBody().MREnclave(); !bytes.Equal(got[:], want) {
		t.Fatalf("mrenclave %x", got)
	}
	// The report data commits to the claims (dcap.rs verify_claims_hash).
	h := e.Claims.DataSHA256()
	rd := e.Quote.Body.ReportBody().ReportData()
	if !bytes.Equal(h[:], rd[:32]) || h == sha256.Sum256(nil) {
		t.Fatal("claims hash does not match the report data")
	}
	if _, err := dcap.ParseEvidence(append(data, 0)); err == nil {
		t.Fatal("trailing byte accepted")
	}
}

type claim struct {
	name  string
	value []byte
}

func testClaims() []claim {
	return []claim{{"first_claim", []byte("foo")}, {"SECOND CLAIM", []byte("bar")}, {"🥉 Claim", []byte("baz")}}
}

func serializeClaims(claims []claim) []byte {
	b := binary.LittleEndian.AppendUint64(nil, 1)
	b = binary.LittleEndian.AppendUint64(b, uint64(len(claims)))
	for _, c := range claims {
		b = binary.LittleEndian.AppendUint64(b, uint64(len(c.name)))
		b = binary.LittleEndian.AppendUint64(b, uint64(len(c.value)))
		b = append(b, c.name...)
		b = append(b, c.value...)
	}
	return b
}

func claimMap(claims []claim) map[string][]byte {
	m := map[string][]byte{}
	for _, c := range claims {
		m[c.name] = c.value
	}
	return m
}

func TestCustomClaims(t *testing.T) {
	eq := func(a, b map[string][]byte) bool { return maps.EqualFunc(a, b, bytes.Equal) }
	t.Run("custom_claims", func(t *testing.T) {
		c, err := dcap.ParseCustomClaims(serializeClaims(testClaims()))
		if err != nil || !eq(c.Map, claimMap(testClaims())) {
			t.Fatalf("%v, %v", c, err)
		}
	})
	t.Run("null_terminated_claims", func(t *testing.T) {
		var nulled []claim
		for _, c := range testClaims() {
			nulled = append(nulled, claim{c.name + "\x00", c.value})
		}
		c, err := dcap.ParseCustomClaims(serializeClaims(nulled))
		if err != nil || !eq(c.Map, claimMap(testClaims())) {
			t.Fatalf("%v, %v", c, err)
		}
	})
	t.Run("underflow_claims", func(t *testing.T) {
		b := binary.LittleEndian.AppendUint64(nil, 1)
		b = binary.LittleEndian.AppendUint64(b, 1)
		if _, err := dcap.ParseCustomClaims(b); !errors.Is(err, dcap.ErrMalformed) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("empty_claims", func(t *testing.T) {
		c, err := dcap.ParseCustomClaims(serializeClaims(nil))
		if err != nil || len(c.Map) != 0 {
			t.Fatalf("%v, %v", c, err)
		}
	})
	t.Run("limits", func(t *testing.T) {
		bad := [][]byte{
			serializeClaims(testClaims())[:20],
			append(serializeClaims(testClaims()), 0),
			func() []byte { b := serializeClaims(nil); b[0] = 2; return b }(),
			func() []byte { b := serializeClaims(nil); b[8] = 1; b[9] = 1; return b }(), // 257 claims
			serializeClaims([]claim{{string(bytes.Repeat([]byte("n"), 1025)), nil}}),
			serializeClaims([]claim{{"x", make([]byte, 1024*1024+1)}}),
			serializeClaims([]claim{{"\xff", nil}}),
		}
		for i, b := range bad {
			if _, err := dcap.ParseCustomClaims(b); err == nil {
				t.Errorf("case %d accepted", i)
			}
		}
	})
}

// Ports of util.rs's tests.
func TestUtil(t *testing.T) {
	t.Run("test_strip_trailing_null_byte", func(t *testing.T) {
		for _, tc := range [][2][]byte{{{2, 0}, {2}}, {{3}, {3}}, {{}, {}}} {
			if got := dcap.StripTrailingNull(tc[0]); !bytes.Equal(got, tc[1]) {
				t.Errorf("%v -> %v", tc[0], got)
			}
		}
	})
	t.Run("test_read_from_bytes", func(t *testing.T) {
		a, b, c, rest, ok := dcap.ReadU64U32U16([]byte{1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 3, 0})
		if !ok || a != 1 || b != 2 || c != 3 || len(rest) != 0 {
			t.Fatal(a, b, c, rest, ok)
		}
		if _, _, _, _, ok := dcap.ReadU64U32U16(make([]byte, 13)); ok {
			t.Fatal("short input accepted")
		}
	})
	t.Run("test_read_bytes", func(t *testing.T) {
		front, rest, ok := dcap.ReadBytes([]byte{0, 1, 2, 3, 4, 5}, 2)
		if !ok || !bytes.Equal(front, []byte{0, 1}) || !bytes.Equal(rest, []byte{2, 3, 4, 5}) {
			t.Fatal(front, rest, ok)
		}
		if _, _, ok := dcap.ReadBytes([]byte{1}, 2); ok {
			t.Fatal("underflow accepted")
		}
	})
}

func FuzzParseEvidence(f *testing.F) {
	f.Add(readTestdata(f, "dcap.evidence"))
	f.Add(serializeClaims(testClaims()))
	f.Fuzz(func(_ *testing.T, b []byte) {
		if e, err := dcap.ParseEvidence(b); err == nil {
			_ = e.Quote.Support.VerifyQEReport()
		}
		_, _ = dcap.ParseCustomClaims(b)
		_, _ = dcap.ParsePCKExtension(b)
		_, _ = dcap.ParseRevocationList(b)
	})
}
