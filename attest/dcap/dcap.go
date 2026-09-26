// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package dcap parses and verifies Intel SGX DCAP attestation evidence,
// ported from rust/attest/src/dcap and cert_chain.rs at libsignal v0.102.2.
//
// VerifyRemoteAttestation is the entry point. It covers the evidence (the
// v3 quote with its report bodies, ECDSA signatures and QE report, the Open
// Enclave custom claims, the SGX PCK certificate extension), the
// endorsements (TCB info, QE identity, CRLs and their issuer chains),
// certificate chains validated with CRLs against Intel's pinned SGX root
// key, the TCB status policy, and the caller's MRENCLAVE and advisory
// policy. Everything here handles public data; nothing needs constant-time
// treatment.
package dcap

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// Errors. Parse and verification failures wrap one of these.
var (
	ErrMalformed    = errors.New("dcap: malformed data")
	ErrUnsupported  = errors.New("dcap: unsupported format")
	ErrSignature    = errors.New("dcap: signature verification failed")
	ErrQEReport     = errors.New("dcap: invalid quoting enclave report")
	ErrCertChain    = errors.New("dcap: invalid certificate chain")
	ErrRevoked      = errors.New("dcap: certificate revoked")
	ErrCRL          = errors.New("dcap: invalid or missing CRL")
	ErrUntrustedKey = errors.New("dcap: not signed by the trusted root key")

	ErrExpired       = errors.New("dcap: attestation expired")
	ErrEnclaveSource = errors.New("dcap: quoting enclave not trusted")
	ErrTCB           = errors.New("dcap: platform TCB not trusted")
	ErrClaims        = errors.New("dcap: custom claims do not match the report")
	ErrDebug         = errors.New("dcap: debug enclave")
	ErrMREnclave     = errors.New("dcap: unexpected MRENCLAVE")
	ErrAdvisory      = errors.New("dcap: unaccepted security advisory")
)

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
}

// verifyRawSignature checks a raw r‖s P-256 ECDSA signature over
// SHA-256(data), as upstream's EcdsaSigned::verify_signature does.
func verifyRawSignature(pub *ecdsa.PublicKey, data []byte, sig *[64]byte) error {
	h := sha256.Sum256(data)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, h[:], r, s) {
		return fmt.Errorf("%w: data did not match signature", ErrSignature)
	}
	return nil
}

// reader consumes a byte slice from the front (upstream util.rs).
type reader struct{ b []byte }

func (r *reader) bytes(n int) ([]byte, bool) {
	if n < 0 || len(r.b) < n {
		return nil, false
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out, true
}

func (r *reader) u16() (uint16, bool) {
	b, ok := r.bytes(2)
	if !ok {
		return 0, false
	}
	return uint16(b[0]) | uint16(b[1])<<8, true
}

func (r *reader) u32() (uint32, bool) {
	b, ok := r.bytes(4)
	if !ok {
		return 0, false
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24, true
}

func (r *reader) u64() (uint64, bool) {
	lo, ok1 := r.u32()
	hi, ok2 := r.u32()
	return uint64(lo) | uint64(hi)<<32, ok1 && ok2
}

// stripTrailingNull removes one trailing zero byte, if present.
func stripTrailingNull(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == 0 {
		return b[:n-1]
	}
	return b
}
