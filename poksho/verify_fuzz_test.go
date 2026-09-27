// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package poksho_test

import (
	"bytes"
	"testing"

	"github.com/cwbudde/libsignal-go/poksho"
	"github.com/gtank/ristretto255"
)

// FuzzVerifyProof verifies arbitrary proof bytes against a fixed two-term
// statement, the path every zkgroup presentation takes. It must never panic,
// and the only proof accepted for the statement is the honest one (proofs are
// deterministic given the randomness, and a second one would be a forgery).
func FuzzVerifyProof(f *testing.F) {
	s := poksho.NewStatement()
	if err := s.Add("A", []poksho.Term{{Scalar: "a", Point: "G"}, {Scalar: "b", Point: "H"}}); err != nil {
		f.Fatal(err)
	}
	a, b := scalar(17), scalar(23)
	h := ristretto255.NewIdentityElement().ScalarBaseMult(scalar(5))
	pa := poksho.PointArgs{
		"A": ristretto255.NewIdentityElement().Add(
			ristretto255.NewIdentityElement().ScalarBaseMult(a),
			ristretto255.NewIdentityElement().ScalarMult(b, h)),
		"H": h,
	}
	msg := []byte("fuzz message")
	proof, err := s.Prove(poksho.ScalarArgs{"a": a, "b": b}, pa, msg, [32]byte{9})
	if err != nil {
		f.Fatal(err)
	}
	if err := s.VerifyProof(proof, pa, msg); err != nil {
		f.Fatalf("honest proof rejected: %v", err)
	}
	f.Add(proof)
	f.Add(proof[:32])
	f.Add(append(bytes.Clone(proof), 0))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, p []byte) {
		if err := s.VerifyProof(p, pa, msg); err == nil && !bytes.Equal(p, proof) {
			t.Fatalf("accepted a proof other than the honest one: %x", p)
		}
	})
}

// FuzzCanonicalEncodings parses arbitrary bytes as a canonical scalar and a
// canonical Ristretto point. Neither may panic, and accepted values must
// encode back to the input.
func FuzzCanonicalEncodings(f *testing.F) {
	f.Add(scalar(1).Bytes())
	f.Add(ristretto255.NewGeneratorElement().Bytes())
	f.Add(bytes.Repeat([]byte{0xFF}, 32))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		if s, err := poksho.ScalarFromCanonicalBytes(b); err == nil && !bytes.Equal(s.Bytes(), b) {
			t.Fatal("scalar encoding is not canonical")
		}
		if p, err := poksho.PointFromCanonicalBytes(b); err == nil && !bytes.Equal(p.Bytes(), b) {
			t.Fatal("point encoding is not canonical")
		}
	})
}
