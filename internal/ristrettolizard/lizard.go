// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package ristrettolizard implements Signal's reversible Ristretto encodings.
// The inverse map is ported from curve25519-dalek 5.0.0's lizard module;
// see LICENSE.dalek for its license. Field operations use edwards25519/field.
package ristrettolizard

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"

	"filippo.io/edwards25519/field"
	"github.com/gtank/ristretto255"
)

// Map maps one 32-byte string using Ristretto Elligator. MAP(0) is the
// identity, so the standard 64-byte map with a zero second half is exactly
// the single Elligator map. The field input's high bit is ignored.
func Map(input [32]byte) *ristretto255.Element {
	var wide [64]byte
	copy(wide[:32], input[:])
	p, _ := ristretto255.NewIdentityElement().SetUniformBytes(wide[:])
	return p
}

// Encode reversibly encodes a UUID, with SHA-256 redundancy (Lizard).
func Encode(input [16]byte) *ristretto255.Element {
	b := sha256.Sum256(input[:])
	copy(b[8:24], input[:])
	b[0] &= 254
	b[31] &= 63
	return Map(b)
}

// Candidate is a possible positive Elligator preimage. Valid is a constant-
// time choice (0 or 1). Bytes must not be used without checking Valid.
type Candidate struct {
	Bytes [32]byte
	Valid int
}

// Decode checks all eight positive inverse candidates without early exits.
func Decode(p *ristretto255.Element) ([16]byte, bool) {
	var result [16]byte
	found := 0
	for _, c := range Inverse(p) {
		expected := sha256.Sum256(c.Bytes[8:24])
		copy(expected[8:24], c.Bytes[8:24])
		expected[0] &= 254
		expected[31] &= 63
		ok := c.Valid & subtle.ConstantTimeCompare(expected[:], c.Bytes[:])
		subtle.ConstantTimeCopy(ok, result[:], c.Bytes[8:24])
		found += ok
	}
	return result, found == 1
}

func add(a, b *field.Element) *field.Element { return new(field.Element).Add(a, b) }
func sub(a, b *field.Element) *field.Element { return new(field.Element).Subtract(a, b) }
func mul(a, b *field.Element) *field.Element { return new(field.Element).Multiply(a, b) }
func neg(a *field.Element) *field.Element    { return new(field.Element).Negate(a) }
func sq(a *field.Element) *field.Element     { return new(field.Element).Square(a) }
func inv(a *field.Element) *field.Element    { return new(field.Element).Invert(a) }

var (
	zero = new(field.Element)
	one  = new(field.Element).One()
	// d = -121665 / 121666 mod (2^255 - 19).
	d                = mul(neg(small(121665)), inv(small(121666)))
	sqrtM1           = fieldBytes([32]byte{0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f, 0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b})
	invSqrtAMinusD   = sqrtRatio(one, sub(neg(one), d))
	minusDoubleInv   = neg(add(invSqrtAMinusD, invSqrtAMinusD))
	minusIDoubleInv  = mul(minusDoubleInv, sqrtM1)
	minusInvOnePlusD = neg(sqrtRatio(one, add(one, d)))
	sqrtID           = sqrtRatio(mul(sqrtM1, d), one)
	dPlusOverMinus   = mul(add(d, one), inv(sub(d, one)))
)

func fieldBytes(b [32]byte) *field.Element {
	f, _ := new(field.Element).SetBytes(b[:])
	return f
}
func small(n uint64) *field.Element {
	var b [32]byte
	binary.LittleEndian.PutUint64(b[:8], n)
	return fieldBytes(b)
}
func sqrtRatio(a, b *field.Element) *field.Element {
	r, _ := new(field.Element).SqrtRatio(a, b)
	return r
}

// coordinates decodes a *known valid* Ristretto point to an affine Edwards
// representative, using RFC 9496 section 4.3.1. No unsafe access to the
// ristretto255 implementation is needed. All operations are constant time.
func coordinates(p *ristretto255.Element) (x, y *field.Element) {
	s, _ := new(field.Element).SetBytes(p.Bytes())
	u1, u2 := sub(one, sq(s)), add(one, sq(s))
	v := sub(neg(mul(d, sq(u1))), sq(u2))
	i := sqrtRatio(one, mul(v, sq(u2)))
	dx := mul(i, u2)
	dy := mul(mul(i, dx), v)
	x = new(field.Element).Absolute(mul(add(s, s), dx))
	y = mul(u1, dy)
	return x, y
}

type jacobi struct{ s, t *field.Element }

// Inverse returns all eight positive inverse candidates. Candidate order is
// based on the canonical Edwards representative, and need not match the order
// of a noncanonical internal Rust representative. The valid set is identical.
func Inverse(p *ristretto255.Element) [8]Candidate {
	x, y := coordinates(p)
	y2 := sq(y)
	z2MinusY2 := sub(one, y2)
	gamma := sqrtRatio(one, mul(mul(sq(y2), sq(x)), z2MinusY2))
	den := mul(gamma, y2)
	sx, spx := mul(den, sub(one, y)), mul(den, add(one, y))
	s0, s1 := mul(sx, x), mul(neg(spx), x)
	t0, t1 := mul(minusDoubleInv, sx), mul(minusDoubleInv, spx)
	den = mul(mul(neg(z2MinusY2), minusInvOnePlusD), gamma)
	sy, spy := mul(den, sub(sqrtM1, x)), mul(den, add(sqrtM1, x))
	s2, s3 := mul(sy, y), mul(neg(spy), y)
	tmp := mul(minusDoubleInv, sqrtM1)
	t2, t3 := mul(tmp, sy), mul(tmp, spy)
	special := x.Equal(zero) | y.Equal(zero)
	t0.Select(one, t0, special)
	t1.Select(one, t1, special)
	t2.Select(minusIDoubleInv, t2, special)
	t3.Select(minusIDoubleInv, t3, special)
	s2.Select(one, s2, special)
	s3.Select(neg(one), s3, special)
	var result [8]Candidate
	for i, j := range [4]jacobi{{s0, t0}, {s1, t1}, {s2, t2}, {s3, t3}} {
		result[2*i] = j.inverse()
		result[2*i+1] = (jacobi{neg(j.s), neg(j.t)}).inverse()
	}
	return result
}

func (j jacobi) inverse() Candidate {
	sZero := j.s.Equal(zero)
	out := new(field.Element).Select(sqrtID, zero, j.t.Equal(one))
	a := mul(add(j.t, one), dPlusOverMinus)
	s2 := sq(j.s)
	y, square := new(field.Element).SqrtRatio(one, mul(sub(sq(s2), sq(a)), sqrtM1))
	pm := new(field.Element).Select(neg(s2), s2, j.s.IsNegative())
	x := new(field.Element).Absolute(mul(add(a, pm), y))
	out.Select(x, out, (1-sZero)&square)
	var c Candidate
	copy(c.Bytes[:], out.Bytes())
	c.Valid = sZero | square
	return c
}
