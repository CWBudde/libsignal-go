// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package poksho

import (
	"errors"
	"fmt"
	"slices"

	"github.com/gtank/ristretto255"
)

// ScalarArgs assigns witnesses by name. Values must be non-nil.
type ScalarArgs map[string]*ristretto255.Scalar

// PointArgs assigns points by name. G is implicit and must not be supplied.
type PointArgs map[string]*ristretto255.Element

// Term identifies a scalar times a point on an equation's right-hand side.
type Term struct{ Scalar, Point string }

type equation struct {
	lhs string
	rhs []Term
}

// Statement is an ordered set of linear Ristretto equations. The zero value is
// ready for Add. Do not mutate a statement or its arguments during Prove/Verify.
type Statement struct {
	equations []equation
	scalars   []string
	points    []string // excludes the implicit G at index zero
}

// NewStatement returns an empty statement.
func NewStatement() *Statement { return &Statement{} }

// Add adds lhs = sum(rhs). Names receive indices in first-occurrence order.
// It validates all limits before changing the statement. Usable upstream
// statements have at most 255 equations, terms per equation, scalars, and
// points (including G); Rust's serializer panics at 256 scalars or points.
func (s *Statement) Add(lhs string, rhs []Term) error {
	if lhs == "" || len(rhs) == 0 || len(rhs) > 255 || len(s.equations) >= 255 {
		return ErrBadArgs
	}
	scalars, points := slices.Clone(s.scalars), slices.Clone(s.points)
	add := func(names *[]string, name string) {
		if !slices.Contains(*names, name) {
			*names = append(*names, name)
		}
	}
	if lhs != "G" {
		add(&points, lhs)
	}
	for _, term := range rhs {
		if term.Scalar == "" || term.Point == "" {
			return ErrBadArgs
		}
		add(&scalars, term.Scalar)
		if term.Point != "G" {
			add(&points, term.Point)
		}
	}
	if len(scalars) > 255 || len(points) > 254 {
		return ErrBadArgs
	}
	s.scalars, s.points = scalars, points
	s.equations = append(s.equations, equation{lhs, slices.Clone(rhs)})
	return nil
}

// Bytes returns the upstream statement description (indices, not names).
func (s *Statement) Bytes() []byte {
	// All counts/indices are bounded by Add before conversion to byte.
	b := []byte{byte(len(s.equations))} //nolint:gosec // G115: Add bounds count to 255.
	for _, e := range s.equations {
		b = append(b, s.pointIndex(e.lhs), byte(len(e.rhs))) //nolint:gosec // G115: Add bounds terms to 255.
		for _, t := range e.rhs {
			b = append(b, byte(slices.Index(s.scalars, t.Scalar)), s.pointIndex(t.Point)) //nolint:gosec // G115: Add bounds index to 254.
		}
	}
	return b
}

func (s *Statement) pointIndex(name string) byte {
	if name == "G" {
		return 0
	}
	return byte(slices.Index(s.points, name) + 1) //nolint:gosec // G115: Add bounds index to 254.
}

func (s *Statement) sortScalars(args ScalarArgs) ([]*ristretto255.Scalar, error) {
	if len(args) != len(s.scalars) {
		return nil, ErrWrongNumberOfScalarArgs
	}
	out := make([]*ristretto255.Scalar, len(s.scalars))
	for i, name := range s.scalars {
		a := args[name]
		if a == nil {
			return nil, fmt.Errorf("%w: %s", ErrMissingScalarArg, name)
		}
		out[i] = ristretto255.NewScalar().Set(a)
	}
	return out, nil
}

func (s *Statement) sortPoints(args PointArgs) ([]*ristretto255.Element, error) {
	if len(args) != len(s.points) {
		return nil, ErrWrongNumberOfPointArgs
	}
	out := make([]*ristretto255.Element, 1, len(s.points)+1)
	out[0] = ristretto255.NewGeneratorElement()
	for _, name := range s.points {
		a := args[name]
		if a == nil {
			return nil, fmt.Errorf("%w: %s", ErrMissingPointArg, name)
		}
		out = append(out, ristretto255.NewIdentityElement().Set(a))
	}
	return out, nil
}

func (s *Statement) transcript(points []*ristretto255.Element) *ShoHmacSha256 {
	sho := NewShoHmacSha256([]byte("POKSHO_Ristretto_SHOHMACSHA256"))
	sho.Absorb(s.Bytes())
	// The implicit base point is also absorbed, matching statement.rs.
	for _, p := range points {
		sho.Absorb(p.Bytes())
	}
	sho.Ratchet()
	return sho
}

func squeezeScalar(sho *ShoHmacSha256) *ristretto255.Scalar {
	s, err := ScalarFromUniformBytes(sho.SqueezeAndRatchet(64))
	if err != nil {
		panic(err)
	} // fixed 64-byte output
	return s
}

// Prove creates a deterministic proof, then verifies it before returning it.
// randomness should be 32 fresh random bytes supplied by the caller.
func (s *Statement) Prove(args ScalarArgs, pointArgs PointArgs, message []byte, randomness [32]byte) ([]byte, error) {
	if len(s.equations) == 0 {
		return nil, ErrBadArgs
	}
	witness, err := s.sortScalars(args)
	if err != nil {
		return nil, err
	}
	points, err := s.sortPoints(pointArgs)
	if err != nil {
		return nil, err
	}
	sho := s.transcript(points)
	nonceSHO := sho.Clone()
	nonceSHO.Absorb(randomness[:])
	for _, a := range witness {
		nonceSHO.Absorb(a.Bytes())
	}
	nonceSHO.Ratchet()
	nonceSHO.AbsorbAndRatchet(message)
	// One squeeze for the entire vector: separate squeezes ratchet differently.
	raw := nonceSHO.SqueezeAndRatchet(len(witness) * 64)
	nonce := make([]*ristretto255.Scalar, len(witness))
	for i := range nonce {
		nonce[i], err = ScalarFromUniformBytes(raw[i*64 : (i+1)*64])
		if err != nil {
			panic(err)
		}
	}
	clear(raw)
	for _, p := range s.homomorphism(nonce, points, nil) {
		sho.Absorb(p.Bytes())
	}
	sho.AbsorbAndRatchet(message)
	challenge := squeezeScalar(sho)
	response := make([]*ristretto255.Scalar, len(witness))
	for i := range response {
		response[i] = ristretto255.NewScalar().Multiply(witness[i], challenge)
		response[i].Add(response[i], nonce[i])
	}
	proof := (&Proof{challenge: challenge, response: response}).Bytes()
	if err := s.VerifyProof(proof, pointArgs, message); err != nil {
		if errors.Is(err, ErrVerification) {
			return nil, ErrProofCreationVerification
		}
		return nil, err
	}
	return proof, nil
}

// VerifyProof verifies an untrusted proof against the statement and message.
func (s *Statement) VerifyProof(b []byte, args PointArgs, message []byte) error {
	proof, err := ParseProof(b)
	if err != nil || len(proof.response) != len(s.scalars) {
		return ErrVerification
	}
	points, err := s.sortPoints(args)
	if err != nil {
		return err
	}
	sho := s.transcript(points)
	for _, p := range s.homomorphism(proof.response, points, proof.challenge) {
		sho.Absorb(p.Bytes())
	}
	sho.AbsorbAndRatchet(message)
	if squeezeScalar(sho).Equal(proof.challenge) != 1 {
		return ErrVerification
	}
	return nil
}

func (s *Statement) homomorphism(scalars []*ristretto255.Scalar, points []*ristretto255.Element, challenge *ristretto255.Scalar) []*ristretto255.Element {
	out := make([]*ristretto255.Element, len(s.equations))
	for i, e := range s.equations {
		ss := make([]*ristretto255.Scalar, 0, len(e.rhs)+1)
		ps := make([]*ristretto255.Element, 0, len(e.rhs)+1)
		for _, term := range e.rhs {
			ss = append(ss, scalars[slices.Index(s.scalars, term.Scalar)])
			ps = append(ps, points[s.pointIndex(term.Point)])
		}
		if challenge != nil {
			ss = append(ss, ristretto255.NewScalar().Negate(challenge))
			ps = append(ps, points[s.pointIndex(e.lhs)])
		}
		// Points may be secret too. Never replace with VarTimeMultiScalarMult.
		out[i] = ristretto255.NewIdentityElement().MultiScalarMult(ss, ps)
	}
	return out
}

func signatureStatement() *Statement {
	s := NewStatement()
	if err := s.Add("public_key", []Term{{"private_key", "G"}}); err != nil {
		panic(err)
	}
	return s
}

// Sign creates a poksho Schnorr signature (not XEdDSA).
func Sign(privateKey *ristretto255.Scalar, publicKey *ristretto255.Element, message []byte, randomness [32]byte) ([]byte, error) {
	return signatureStatement().Prove(ScalarArgs{"private_key": privateKey}, PointArgs{"public_key": publicKey}, message, randomness)
}

// VerifySignature verifies a poksho Schnorr signature (not XEdDSA).
func VerifySignature(signature []byte, publicKey *ristretto255.Element, message []byte) error {
	return signatureStatement().VerifyProof(signature, PointArgs{"public_key": publicKey}, message)
}
