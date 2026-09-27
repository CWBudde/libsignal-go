// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package dcap_test

import (
	"bytes"
	"testing"

	"github.com/cwbudde/libsignal-go/attest/dcap"
)

// pemChain returns the PEM certificate blocks embedded in b, from the first
// BEGIN to the last END line, or nil.
func pemChain(b []byte) []byte {
	begin := bytes.Index(b, []byte("-----BEGIN CERTIFICATE-----"))
	end := bytes.LastIndex(b, []byte("-----END CERTIFICATE-----"))
	if begin < 0 || end < begin {
		return nil
	}
	return b[begin : end+len("-----END CERTIFICATE-----\n")]
}

// FuzzParseQuote parses arbitrary bytes as an SGX quote and, separately, as
// the quote's signature data. Neither may panic; the accessors and signature
// checks of an accepted quote must not panic either.
func FuzzParseQuote(f *testing.F) {
	for _, name := range []string{"dcap.evidence", "dcap_v3.evidence", "cds2_test.evidence"} {
		b := readTestdata(f, name)
		f.Add(b)
		if len(b) > dcap.QuoteBodySize+4 {
			f.Add(b[dcap.QuoteBodySize+4:]) // the signature data on its own
		}
	}
	f.Add([]byte{})
	f.Add(make([]byte, dcap.QuoteBodySize+4))

	f.Fuzz(func(_ *testing.T, b []byte) {
		if q, _, err := dcap.ParseQuote(b); err == nil {
			rb := q.Body.ReportBody()
			_, _, _ = rb.MREnclave(), rb.ReportData(), rb.ISVSVN()
			_ = q.Support.VerifyQEReport()
			if pub, err := q.Support.AttestKey(); err == nil {
				_ = q.VerifySignature(pub)
			}
		}
		if s, _, err := dcap.ParseQuoteSupport(b); err == nil {
			_ = s.VerifyQEReport()
		}
	})
}

// FuzzParseCertChainPEM parses arbitrary bytes as a PEM certificate chain,
// the form the quote and the endorsements carry the Intel chains in. It must
// never panic, and an accepted chain's accessors must not panic.
func FuzzParseCertChainPEM(f *testing.F) {
	for _, name := range []string{"dcap.evidence", "dcap.endorsements"} {
		if pem := pemChain(readTestdata(f, name)); pem != nil {
			f.Add(pem)
		}
	}
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"))
	f.Add([]byte{})

	f.Fuzz(func(_ *testing.T, b []byte) {
		c, err := dcap.ParseCertChainPEM(b)
		if err != nil {
			return
		}
		_, _ = c.Leaf(), c.Root()
		_, _ = c.LeafPublicKey()
		_ = c.ValidAt(c.Leaf().NotBefore)
	})
}

// FuzzVerifyRemoteAttestation runs the full DCAP verification on arbitrary
// evidence and endorsements, against the recorded CDSI enclave and time. It
// must never panic, and the untouched recording must still verify.
func FuzzVerifyRemoteAttestation(f *testing.F) {
	h := loadCDSI(f)
	f.Add(h.evidence, h.endorsements)
	f.Add(readTestdata(f, "dcap.evidence"), readTestdata(f, "dcap.endorsements"))
	f.Add(h.evidence, []byte{})
	f.Add([]byte{}, h.endorsements)

	f.Fuzz(func(t *testing.T, evidence, endorsements []byte) {
		_, err := dcap.VerifyRemoteAttestation(evidence, endorsements, h.mrenclave, h.advisories, h.now)
		if err != nil && bytes.Equal(evidence, h.evidence) && bytes.Equal(endorsements, h.endorsements) {
			t.Fatalf("recorded attestation no longer verifies: %v", err)
		}
		_, _ = dcap.AttestationMetrics(evidence, endorsements)
	})
}
