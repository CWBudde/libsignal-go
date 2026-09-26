// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package poksho implements libsignal's Ristretto Schnorr proof system and SHO
// hash constructions, compatible with rust/poksho at libsignal v0.102.2.
package poksho

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"hash"
)

// SHO is the stateful absorb/ratchet/squeeze interface used by poksho. Squeezing
// while absorbing panics: callers must explicitly ratchet first, as in Rust.
// Instances are mutable and must not be used concurrently or copied by value.
type SHO interface {
	Absorb([]byte)
	Ratchet()
	AbsorbAndRatchet([]byte)
	SqueezeAndRatchet(int) []byte
	SqueezeAndRatchetInto([]byte)
}

// ShoHmacSha256 is the HMAC-SHA256 SHO construction. Use its constructor.
type ShoHmacSha256 struct{ sho }

// ShoSha256 is the SHA256 SHO construction. Use its constructor.
type ShoSha256 struct{ sho }

// NewShoHmacSha256 initializes a domain-separated SHO state.
func NewShoHmacSha256(label []byte) *ShoHmacSha256 {
	s := &ShoHmacSha256{sho: sho{hmac: true}}
	s.AbsorbAndRatchet(label)
	return s
}

// NewShoSha256 initializes a domain-separated SHO state.
func NewShoSha256(label []byte) *ShoSha256 {
	s := &ShoSha256{}
	s.AbsorbAndRatchet(label)
	return s
}

// Clone returns an independent copy, including any partially absorbed input.
func (s *ShoHmacSha256) Clone() *ShoHmacSha256 { return &ShoHmacSha256{sho: s.clone()} }

// Clone returns an independent copy, including any partially absorbed input.
func (s *ShoSha256) Clone() *ShoSha256 { return &ShoSha256{sho: s.clone()} }

type sho struct {
	cv        [32]byte
	hasher    hash.Hash
	absorbing bool
	hmac      bool
}

func (s *sho) clone() sho {
	out := *s
	if s.hasher != nil {
		// Go 1.26's SHA256 and HMAC(SHA256) support hash.Cloner. No
		// transcript buffering or unsafe access to hash internals is necessary.
		cloned, err := s.hasher.(hash.Cloner).Clone()
		if err != nil {
			panic(err)
		}
		out.hasher = cloned
	}
	return out
}

// Absorb appends input, entering absorbing mode even for an empty slice.
func (s *sho) Absorb(input []byte) {
	if !s.absorbing {
		if s.hmac {
			s.hasher = hmac.New(sha256.New, s.cv[:])
		} else {
			s.hasher = sha256.New()
			_, _ = s.hasher.Write(make([]byte, 64))
			_, _ = s.hasher.Write(s.cv[:])
		}
		s.absorbing = true
	}
	_, _ = s.hasher.Write(input)
}

// Ratchet finishes absorption. Repeated calls without absorption are no-ops.
func (s *sho) Ratchet() {
	if !s.absorbing {
		return
	}
	if s.hmac {
		_, _ = s.hasher.Write([]byte{0})
		copy(s.cv[:], s.hasher.Sum(nil))
	} else {
		s.cv = sha256.Sum256(s.hasher.Sum(nil))
	}
	s.hasher = nil
	s.absorbing = false
}

// AbsorbAndRatchet absorbs input and finishes the absorption step.
func (s *sho) AbsorbAndRatchet(input []byte) { s.Absorb(input); s.Ratchet() }

// SqueezeAndRatchet returns output and updates the state, even for length zero.
func (s *sho) SqueezeAndRatchet(n int) []byte {
	if n < 0 {
		panic("poksho: negative output length")
	}
	out := make([]byte, n)
	s.SqueezeAndRatchetInto(out)
	return out
}

// SqueezeAndRatchetInto writes output and updates the state, even for empty out.
func (s *sho) SqueezeAndRatchetInto(out []byte) {
	if s.absorbing {
		panic("poksho: squeeze before ratchet")
	}
	size := len(out)
	for i := uint64(0); len(out) > 0; i++ {
		block := s.output(i, 1)
		n := copy(out, block[:])
		out = out[n:]
	}
	s.cv = s.output(uint64(size), 2)
}

func (s *sho) output(counter uint64, domain byte) [32]byte {
	var h hash.Hash
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], counter)
	if s.hmac {
		h = hmac.New(sha256.New, s.cv[:])
		_, _ = h.Write(encoded[:])
		_, _ = h.Write([]byte{domain})
	} else {
		h = sha256.New()
		var prefix [64]byte
		prefix[63] = domain
		_, _ = h.Write(prefix[:])
		_, _ = h.Write(s.cv[:])
		_, _ = h.Write(encoded[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
