// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package mlkem768incr

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"testing"
)

// The references below are the straightforward (branching) forms of the
// constant-time helpers. The tests pin the constant-time versions to them;
// whether the compiled code branches is checked by reading the disassembly
// (docs/constant-time.md, CT-01), which output tests cannot do.

func referenceToBalanced(c fieldElement) int16 {
	v := int16(c)
	if int(c) > (q-1)/2 {
		v -= q
	}
	return v
}

func referenceFromBalanced(v int16) fieldElement {
	r := int32(v) % q
	if r < 0 {
		r += q
	}
	return fieldElement(r)
}

// referenceFixEncapsStateEndianness follows SPQR's rule directly: the first
// coefficient of e₂ that is not 0 or -1 decides.
func referenceFixEncapsStateEndianness(state []byte) []byte {
	out := bytes.Clone(state)
	for i := k * rawPolyI16Size; i < EncapsStateSize-messageSize; i += 2 {
		switch int16(binary.LittleEndian.Uint16(state[i : i+2])) {
		case 0, -1:
			continue
		case 0x0100, 0x0200, -0x0101:
			for j := 0; j < EncapsStateSize-messageSize; j += 2 {
				out[j], out[j+1] = out[j+1], out[j]
			}
		}
		return out
	}
	return out
}

func TestToBalancedAllInputs(t *testing.T) {
	for c := range fieldElement(q) {
		if got, want := toBalanced(c), referenceToBalanced(c); got != want {
			t.Fatalf("toBalanced(%d) = %d, want %d", c, got, want)
		}
	}
}

func TestFromBalancedAllInputs(t *testing.T) {
	for i := range 1 << 16 {
		v := int16(uint16(i))
		if got, want := fromBalanced(v), referenceFromBalanced(v); got != want {
			t.Fatalf("fromBalanced(%d) = %d, want %d", v, got, want)
		}
	}
}

// TestFixEncapsStateEndiannessDecisions puts every decisive value class at every
// e₂ position, behind ambiguous 0/-1 coefficients and ahead of arbitrary ones
// (including unexpected values), and compares with the reference.
func TestFixEncapsStateEndiannessDecisions(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	classes := []int16{
		1, 2, -2, // correct encoding: keep
		0x0100, 0x0200, -0x0101, // swapped encoding: flip
		3, -3, 0x1234, 0x0300, -0x0201, // unexpected: keep
	}
	tail := []int16{0, -1, 1, 2, -2, 0x0100, 0x0200, -0x0101, 7, 0x7fff}
	e2Start := k * rawPolyI16Size
	check := func(t *testing.T, state []byte) {
		t.Helper()
		in := bytes.Clone(state)
		got, err := FixEncapsStateEndianness(state)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(state, in) {
			t.Fatal("the input state was modified")
		}
		if want := referenceFixEncapsStateEndianness(state); !bytes.Equal(got, want) {
			t.Fatal("result differs from the reference")
		}
		if !bytes.Equal(got[EncapsStateSize-messageSize:], state[EncapsStateSize-messageSize:]) {
			t.Fatal("the trailing message changed")
		}
	}
	newState := func() []byte {
		s := make([]byte, EncapsStateSize)
		for i := range s {
			s[i] = byte(rng.Uint32())
		}
		return s
	}
	put := func(s []byte, pos int, v int16) {
		binary.LittleEndian.PutUint16(s[e2Start+2*pos:], uint16(v))
	}

	for pos := range n {
		for _, v := range classes {
			s := newState()
			for j := range pos {
				put(s, j, int16(-(rng.IntN(2)))) // 0 or -1
			}
			put(s, pos, v)
			for j := pos + 1; j < n; j++ {
				put(s, j, tail[rng.IntN(len(tail))])
			}
			check(t, s)
		}
	}

	// No decisive coefficient at all: kept as is.
	s := newState()
	for j := range n {
		put(s, j, int16(-(rng.IntN(2))))
	}
	check(t, s)
	got, err := FixEncapsStateEndianness(s)
	if err != nil || !bytes.Equal(got, s) {
		t.Fatal("an all-ambiguous state was changed")
	}
}
