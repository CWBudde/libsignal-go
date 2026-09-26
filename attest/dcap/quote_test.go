// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package dcap_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cwbudde/libsignal-go/attest/dcap"
)

// Ports of sgx_quote.rs's tests.

func quoteBytes(t testing.TB) []byte { return readTestdata(t, "dcap.evidence") }

// quoteSupportBytes returns the signature data: {QuoteBody, length (4), support}.
func quoteSupportBytes(t testing.TB) []byte {
	b := quoteBytes(t)[dcap.QuoteBodySize:]
	n := binary.LittleEndian.Uint32(b)
	return append([]byte(nil), b[4:4+n]...)
}

func parseQuote(t testing.TB, b []byte) *dcap.Quote {
	t.Helper()
	q, _, err := dcap.ParseQuote(b)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func leafKey(t testing.TB, s *dcap.QuoteSupport) *ecdsa.PublicKey {
	t.Helper()
	k, err := s.PCKCertChain.LeafPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestValidQuoteFromDisk(t *testing.T) {
	q := parseQuote(t, quoteBytes(t))
	if err := q.Support.VerifySignature(leafKey(t, &q.Support)); err != nil {
		t.Fatalf("QE report should be signed by pck cert: %v", err)
	}
	if err := q.Support.VerifyQEReport(); err != nil {
		t.Fatalf("QE report should be valid: %v", err)
	}
	ak, err := q.Support.AttestKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := q.VerifySignature(ak); err != nil {
		t.Fatalf("ISV report should be signed with attest key: %v", err)
	}
}

type failInfo int

const (
	success failInfo = iota
	failQE
	failISV
)

func verifyQuote(t *testing.T, mutate func(*dcap.Quote)) failInfo {
	t.Helper()
	q := parseQuote(t, quoteBytes(t))
	mutate(q)
	if q.Support.VerifySignature(leafKey(t, &q.Support)) != nil {
		return failQE
	}
	ak, err := q.Support.AttestKey()
	if err != nil {
		t.Fatal(err)
	}
	if q.VerifySignature(ak) != nil {
		return failISV
	}
	return success
}

// rawSignature signs "test" with a fresh key, as upstream's
// EcdsaSig::sign("test", key), as raw r‖s.
func rawSignature(t *testing.T) [64]byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("test"))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	var sig [64]byte
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig
}

func TestQuoteSignatures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, *dcap.Quote)
		want   failInfo
	}{
		{"unmodified", func(*testing.T, *dcap.Quote) {}, success},
		{"isv_sig_bad_body", func(_ *testing.T, q *dcap.Quote) { q.Body[4]++ }, failISV}, // reserved[0]
		{"isv_sig_bad_mrenclave", func(_ *testing.T, q *dcap.Quote) { q.Body[48+64]++ }, failISV},
		{"isv_sig_bad_sig", func(t *testing.T, q *dcap.Quote) { q.Support.ISVSignature = rawSignature(t) }, failISV},
		{"qe_sig_bad_report", func(_ *testing.T, q *dcap.Quote) { q.Support.QEReportBody[320]++ }, failQE},
		{"qe_sig_bad_sig", func(t *testing.T, q *dcap.Quote) { q.Support.QEReportSignature = rawSignature(t) }, failQE},
		{"qe_sig_bad_signer", func(t *testing.T, q *dcap.Quote) {
			q.Support.PCKCertChain = mustChain(t, testChain(t, 2))
		}, failQE},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := verifyQuote(t, func(q *dcap.Quote) { tc.mutate(t, q) }); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func parseSupport(t *testing.T, b []byte) *dcap.QuoteSupport {
	t.Helper()
	s, _, err := dcap.ParseQuoteSupport(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestQEReport(t *testing.T) {
	t.Run("qe_report_bad_attest_key", func(t *testing.T) {
		s := parseSupport(t, quoteSupportBytes(t))
		s.AttestPubKey[0]++
		if !errors.Is(s.VerifyQEReport(), dcap.ErrQEReport) {
			t.Fatal("accepted")
		}
	})
	t.Run("qe_report_bad_report", func(t *testing.T) {
		s := parseSupport(t, quoteSupportBytes(t))
		s.QEReportBody[320]++
		if !errors.Is(s.VerifyQEReport(), dcap.ErrQEReport) {
			t.Fatal("accepted")
		}
	})
	t.Run("qe_report_bad_padding", func(t *testing.T) {
		s := parseSupport(t, quoteSupportBytes(t))
		s.QEReportBody[320+63]++
		if !errors.Is(s.VerifyQEReport(), dcap.ErrQEReport) {
			t.Fatal("accepted")
		}
	})
	t.Run("qe_report_bad_auth_data", func(t *testing.T) {
		b := quoteSupportBytes(t)
		b[578]++ // the auth data follows SgxEcdsaSignatureHeader
		s := parseSupport(t, b)
		if err := s.VerifySignature(leafKey(t, s)); err != nil {
			t.Fatalf("signature should still work: %v", err)
		}
		if !errors.Is(s.VerifyQEReport(), dcap.ErrQEReport) {
			t.Fatal("report accepted")
		}
	})
}

func TestQuoteDeserialize(t *testing.T) {
	t.Run("deserialize_bad_version", func(t *testing.T) {
		q := quoteBytes(t)
		if q[0] != 3 || q[1] != 0 {
			t.Fatalf("version bytes %x", q[:2])
		}
		q[0]++
		if _, _, err := dcap.ParseQuote(q); !errors.Is(err, dcap.ErrUnsupported) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("deserialize_bad_sign_type", func(t *testing.T) {
		q := quoteBytes(t)
		q[2]++
		if _, _, err := dcap.ParseQuote(q); !errors.Is(err, dcap.ErrUnsupported) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("deserialize_underflow", func(t *testing.T) {
		q := quoteBytes(t)
		for _, n := range []int{dcap.QuoteBodySize - 1, dcap.QuoteBodySize, dcap.QuoteBodySize + 4, len(q) - 2000} {
			if _, _, err := dcap.ParseQuote(q[:n]); err == nil {
				t.Fatalf("%d bytes: accepted", n)
			}
		}
	})
	t.Run("deserialize_unsupported_key_type", func(t *testing.T) {
		s := quoteSupportBytes(t)
		authSize := int(binary.LittleEndian.Uint16(s[576:]))
		s[578+authSize]++ // {header, auth_data, key type, ...}
		// Upstream feeds this to SgxQuote::read, which fails on the version.
		if _, _, err := dcap.ParseQuote(s); err == nil {
			t.Fatal("ParseQuote accepted support bytes")
		}
		if _, _, err := dcap.ParseQuoteSupport(s); !errors.Is(err, dcap.ErrUnsupported) {
			t.Fatalf("ParseQuoteSupport: %v", err)
		}
	})
}

func TestReportBodyFields(t *testing.T) {
	q := parseQuote(t, quoteBytes(t))
	rb := q.Body.ReportBody()
	if rb.HasFlag(dcap.FlagDebug) || !rb.HasFlag(dcap.FlagInited|dcap.FlagMode64Bit) {
		t.Errorf("attributes %x", rb.Attributes())
	}
	if q.Body.Version() != 3 || q.Body.SignType() != 2 {
		t.Errorf("version %d, sign type %d", q.Body.Version(), q.Body.SignType())
	}
	// Intel's QE vendor ID (dcap.rs INTEL_QE_VENDOR_ID).
	want := [16]byte{0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07}
	if q.Body.QEVendorID() != want {
		t.Errorf("QE vendor ID %x", q.Body.QEVendorID())
	}
}
