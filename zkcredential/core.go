// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package zkcredential implements attribute-based anonymous credentials and
// endorsements compatible with rust/zkcredential at libsignal v0.102.2.
// Callers supply fresh, cryptographically secure randomness for every issuance
// and presentation. This package implements cryptography, not redemption policy.
package zkcredential

import (
	"encoding/binary"
	"errors"
	"strconv"

	"github.com/cwbudde/libsignal-go/poksho"
	"github.com/gtank/ristretto255"
)

var (
	// ErrEncoding indicates a noncanonical or incorrectly sized encoding.
	ErrEncoding = errors.New("zkcredential: invalid encoding")
	// ErrVerification indicates an invalid proof, token, or ciphertext.
	ErrVerification = errors.New("zkcredential: verification failed")
	// ErrArguments indicates an unsupported mode, arity, or inconsistent domain.
	ErrArguments = errors.New("zkcredential: invalid arguments")
)

// Mode selects credential arity separation and presentation authentication.
// A server key must always be used in the same mode, including after loading it.
// Mode is supplied out of band and is not part of the upstream wire encoding.
type Mode uint8

const (
	// StandardMode binds arity and authenticates all presentation inputs.
	StandardMode Mode = iota
	// LegacyMode is only for existing credentials requiring upstream compatibility.
	LegacyMode
)

func (m Mode) valid() bool { return m == StandardMode || m == LegacyMode }

type scalar = ristretto255.Scalar
type point = ristretto255.Element

func zero() *point                   { return ristretto255.NewIdentityElement() }
func add(a, b *point) *point         { return zero().Add(a, b) }
func sub(a, b *point) *point         { return zero().Subtract(a, b) }
func neg(a *point) *point            { return zero().Negate(a) }
func mul(s *scalar, p *point) *point { return zero().ScalarMult(s, p) }
func base(s *scalar) *point          { return zero().ScalarBaseMult(s) }
func smul(a, b *scalar) *scalar      { return ristretto255.NewScalar().Multiply(a, b) }
func sneg(a *scalar) *scalar         { return ristretto255.NewScalar().Negate(a) }
func sinv(a *scalar) *scalar         { return ristretto255.NewScalar().Invert(a) }
func sget(sho poksho.SHO) *scalar {
	s, e := poksho.ScalarFromUniformBytes(sho.SqueezeAndRatchet(64))
	if e != nil {
		panic(e)
	}
	return s
}
func pget(sho poksho.SHO) *point {
	p, e := poksho.PointFromUniformBytes(sho.SqueezeAndRatchet(64))
	if e != nil {
		panic(e)
	}
	return p
}
func seeded(label string, randomness [32]byte) *poksho.ShoHmacSha256 {
	s := poksho.NewShoHmacSha256([]byte(label))
	s.AbsorbAndRatchet(randomness[:])
	return s
}
func random32(sho poksho.SHO) [32]byte { return [32]byte(sho.SqueezeAndRatchet(32)) }
func name(prefix string, i int) string { return prefix + strconv.Itoa(i) }
func equation(s *poksho.Statement, lhs string, terms ...poksho.Term) {
	if e := s.Add(lhs, terms); e != nil {
		panic(e)
	}
}
func term(s, p string) poksho.Term { return poksho.Term{Scalar: s, Point: p} }
func proofOK(e error) error {
	if e != nil {
		return ErrVerification
	}
	return nil
}
func pointCopy(p *point) *point { return zero().Set(p) }

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
func (r *reader) scalar() *scalar {
	s, e := ristretto255.NewScalar().SetCanonicalBytes(r.take(32))
	if e != nil {
		r.err = ErrEncoding
		return ristretto255.NewScalar()
	}
	return s
}
func (r *reader) point() *point {
	p, e := zero().SetCanonicalBytes(r.take(32))
	if e != nil {
		r.err = ErrEncoding
		return zero()
	}
	return p
}
func (r *reader) vector() []byte {
	n := binary.LittleEndian.Uint64(r.take(8))
	if n > uint64(len(r.b)) {
		r.err = ErrEncoding
		return nil
	}
	return append([]byte(nil), r.take(int(n))...) //nolint:gosec // n is bounded by the int-sized input above.
}
func (r *reader) done() error {
	if r.err != nil || len(r.b) != 0 {
		return ErrEncoding
	}
	return nil
}
func vector(b, v []byte) []byte {
	b = binary.LittleEndian.AppendUint64(b, uint64(len(v)))
	return append(b, v...)
}
func pointsBytes(ps ...*point) []byte {
	var b []byte
	for _, p := range ps {
		b = append(b, p.Bytes()...)
	}
	return b
}
func clonePoints(ps []*point) []*point {
	out := make([]*point, len(ps))
	for i, p := range ps {
		out[i] = pointCopy(p)
	}
	return out
}
