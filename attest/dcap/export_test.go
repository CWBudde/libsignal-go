// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package dcap

import (
	"crypto/x509"

	"github.com/cwbudde/libsignal-go/attest/internal/testhook"
)

// SortChain exposes upstream's CertChain::sort.
func SortChain(certs []*x509.Certificate) error { return sortChain(certs) }

// StripTrailingNull exposes util::strip_trailing_null_byte.
func StripTrailingNull(b []byte) []byte { return stripTrailingNull(b) }

// ReadBytes exposes util::read_bytes, returning the front and the rest.
func ReadBytes(b []byte, n int) (front, rest []byte, ok bool) {
	r := reader{b}
	front, ok = r.bytes(n)
	return front, r.b, ok
}

// ReadU64U32U16 exposes the little-endian readers (util::read_from_bytes).
func ReadU64U32U16(b []byte) (a uint64, c uint32, d uint16, rest []byte, ok bool) {
	r := reader{b}
	a, ok1 := r.u64()
	c, ok2 := r.u32()
	d, ok3 := r.u16()
	return a, c, d, r.b, ok1 && ok2 && ok3
}

// UnsortedChain builds a chain without sorting (upstream's CertChain { certs }).
func UnsortedChain(certs []*x509.Certificate) *CertChain { return &CertChain{certs: certs} }

// Attest exposes attest (dcap.rs attest_impl) with a chosen root key.
var Attest = attest

// CheckPolicy exposes the MRENCLAVE and advisory checks of
// VerifyRemoteAttestation.
func (a *Attestation) CheckPolicy(mrenclave [32]byte, acceptable []string) (map[string][]byte, error) {
	return a.check(mrenclave, acceptable)
}

// Report body and quote layout offsets.
const (
	RBMiscSelect          = rbMiscSelect
	RBAttributes          = rbAttributes
	RBMRSigner            = rbMRSigner
	RBISVSVN              = rbISVSVN
	RBReportData          = rbReportData
	QuoteReportBodyOffset = 48
	QuoteQEVendorIDOffset = 12
)

// VeryExpiredTestEvalNumberDefault is the exception's setting before this
// file turned it on: its production value. Upstream accepts the very
// expired test evaluation number in every cfg(test) build; so do this
// package's tests.
var VeryExpiredTestEvalNumberDefault = testhook.SetAcceptVeryExpiredEvalNumber(true)

// SetAcceptVeryExpiredTestEvalNumber switches that test-only exception and
// returns the previous setting. Tests using it must not run in parallel.
func SetAcceptVeryExpiredTestEvalNumber(on bool) (was bool) {
	return testhook.SetAcceptVeryExpiredEvalNumber(on)
}
