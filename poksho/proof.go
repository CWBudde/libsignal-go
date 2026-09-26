// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package poksho

import (
	"errors"
	"fmt"

	"github.com/gtank/ristretto255"
)

// Errors distinguish malformed inputs from invalid proofs and faulty creation.
var (
	ErrBadArgs                   = errors.New("poksho: bad arguments")
	ErrWrongNumberOfScalarArgs   = fmt.Errorf("%w: wrong number of scalars", ErrBadArgs)
	ErrWrongNumberOfPointArgs    = fmt.Errorf("%w: wrong number of points", ErrBadArgs)
	ErrMissingScalarArg          = fmt.Errorf("%w: missing scalar", ErrBadArgs)
	ErrMissingPointArg           = fmt.Errorf("%w: missing point", ErrBadArgs)
	ErrInvalidProof              = errors.New("poksho: invalid proof encoding")
	ErrVerification              = errors.New("poksho: verification failed")
	ErrProofCreationVerification = errors.New("poksho: proof creation verification failed")
)

// ScalarFromCanonicalBytes decodes a canonical 32-byte little-endian scalar.
func ScalarFromCanonicalBytes(b []byte) (*ristretto255.Scalar, error) {
	s, err := ristretto255.NewScalar().SetCanonicalBytes(b)
	if err != nil {
		return nil, fmt.Errorf("%w: scalar encoding", ErrBadArgs)
	}
	return s, nil
}

// ScalarFromUniformBytes reduces a 64-byte little-endian integer modulo the order.
func ScalarFromUniformBytes(b []byte) (*ristretto255.Scalar, error) {
	s, err := ristretto255.NewScalar().SetUniformBytes(b)
	if err != nil {
		return nil, fmt.Errorf("%w: wide scalar encoding", ErrBadArgs)
	}
	return s, nil
}

// PointFromCanonicalBytes decodes a canonical 32-byte Ristretto encoding.
func PointFromCanonicalBytes(b []byte) (*ristretto255.Element, error) {
	p, err := ristretto255.NewIdentityElement().SetCanonicalBytes(b)
	if err != nil {
		return nil, fmt.Errorf("%w: point encoding", ErrBadArgs)
	}
	return p, nil
}

// Proof holds a challenge and one response per witness. Its encoding is the
// concatenation of canonical 32-byte scalars, without a length prefix.
type Proof struct {
	challenge *ristretto255.Scalar
	response  []*ristretto255.Scalar
}

// ParseProof parses an untrusted proof. Rust permits 1..256 response scalars.
// Parsing checks public encodings and is not constant time.
func ParseProof(b []byte) (*Proof, error) {
	if len(b) < 64 || len(b) > 32*257 || len(b)%32 != 0 {
		return nil, ErrInvalidProof
	}
	scalars := make([]*ristretto255.Scalar, len(b)/32)
	for i := range scalars {
		s, err := ScalarFromCanonicalBytes(b[i*32 : (i+1)*32])
		if err != nil {
			return nil, ErrInvalidProof
		}
		scalars[i] = s
	}
	return &Proof{challenge: scalars[0], response: scalars[1:]}, nil
}

// Bytes returns the canonical encoding in fresh storage. A zero Proof has no
// encoding and returns nil; it cannot be verified.
func (p *Proof) Bytes() []byte {
	if p == nil || p.challenge == nil {
		return nil
	}
	b := append([]byte(nil), p.challenge.Bytes()...)
	for _, s := range p.response {
		b = append(b, s.Bytes()...)
	}
	return b
}

// PointFromUniformBytes maps 64 uniform bytes to a Ristretto point.
func PointFromUniformBytes(b []byte) (*ristretto255.Element, error) {
	p, err := ristretto255.NewIdentityElement().SetUniformBytes(b)
	if err != nil {
		return nil, fmt.Errorf("%w: uniform point encoding", ErrBadArgs)
	}
	return p, nil
}
