// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package zkgroup implements the client group and profile APIs of libsignal
// v0.102.2. Use constructors or parsers; zero values are not initialized.
// Parsers validate structure, not authenticity. Receive methods verify issuance.
package zkgroup

import (
	"encoding/binary"
	"errors"
	"github.com/cwbudde/libsignal-go/poksho"
	"github.com/gtank/ristretto255"
)

var (
	// ErrEncoding indicates malformed, noncanonical or unsupported API bytes.
	ErrEncoding = errors.New("zkgroup: invalid API encoding")
	// ErrVerification indicates failed authentication or a credential policy violation.
	ErrVerification = errors.New("zkgroup: API verification failed")
)

// SecondsPerDay is the upstream credential day length in seconds.
const SecondsPerDay uint64 = 86400

type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if n < 0 || n > len(r.b) {
		r.err = ErrEncoding
		return make([]byte, n)
	}
	b := r.b[:n]
	r.b = r.b[n:]
	return b
}
func (r *reader) version(v byte) {
	if r.take(1)[0] != v {
		r.err = ErrEncoding
	}
}
func (r *reader) done() error {
	if r.err != nil || len(r.b) != 0 {
		return ErrEncoding
	}
	return nil
}
func read[T any](r *reader, n int, parse func([]byte) (T, error)) T {
	v, e := parse(r.take(n))
	if e != nil {
		r.err = ErrEncoding
	}
	return v
}
func point(b []byte) (*ristretto255.Element, error) {
	return ristretto255.NewIdentityElement().SetCanonicalBytes(b)
}
func seeded(label string, b []byte) *poksho.ShoHmacSha256 {
	s := poksho.NewShoHmacSha256([]byte(label))
	s.AbsorbAndRatchet(b)
	return s
}
func join(version byte, parts ...[]byte) []byte {
	b := []byte{version}
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}
func timestamp(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }
