// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package poksho_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/cwbudde/libsignal-go/poksho"
	"github.com/gtank/ristretto255"
)

func scalar(n byte) *ristretto255.Scalar {
	var b [32]byte
	b[0] = n
	s, err := poksho.ScalarFromCanonicalBytes(b[:])
	if err != nil {
		panic(err)
	}
	return s
}
func signature(t *testing.T) (*poksho.Statement, poksho.ScalarArgs, poksho.PointArgs, []byte) {
	t.Helper()
	s := poksho.NewStatement()
	if err := s.Add("A", []poksho.Term{{Scalar: "a", Point: "G"}}); err != nil {
		t.Fatal(err)
	}
	a := scalar(17)
	p := ristretto255.NewIdentityElement().ScalarBaseMult(a)
	sa, pa := poksho.ScalarArgs{"a": a}, poksho.PointArgs{"A": p}
	proof, err := s.Prove(sa, pa, []byte("message"), [32]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	return s, sa, pa, proof
}

func TestUpstreamSignature(t *testing.T) {
	var wide [64]byte
	var randomness [32]byte
	message := make([]byte, 100)
	for i := range wide {
		wide[i] = byte(i)
	}
	for i := range randomness {
		randomness[i] = byte(i)
	}
	for i := range message {
		message[i] = byte(i)
	}
	a, err := poksho.ScalarFromUniformBytes(wide[:])
	if err != nil {
		t.Fatal(err)
	}
	public := ristretto255.NewIdentityElement().ScalarBaseMult(a)
	proof, err := poksho.Sign(a, public, message, randomness)
	if err != nil {
		t.Fatal(err)
	}
	// rust/poksho/src/sign.rs::test_signature at v0.102.2.
	const want = "a08f6b34a282dd4c7cfc40b918f224a6b631ca5f6480a10b42bd1408602a7e008a23a1e32479befb5e26b9f0f4fe0e9e9e9ec9afad269143acb03a22c6364f03"
	if hex.EncodeToString(proof) != want {
		t.Fatalf("signature = %x", proof)
	}
	if err := poksho.VerifySignature(proof, public, message); err != nil {
		t.Fatal(err)
	}
}

func TestProofRejection(t *testing.T) {
	s, sa, pa, proof := signature(t)
	msg := []byte("message")
	invalid := [][]byte{nil, {}, proof[:32], proof[:63], append(bytes.Clone(proof), 0), append(bytes.Clone(proof), make([]byte, 32)...), make([]byte, 32*258)}
	for i := range proof {
		b := bytes.Clone(proof)
		b[i] ^= 128
		invalid = append(invalid, b)
	}
	for i, b := range invalid {
		if err := s.VerifyProof(b, pa, msg); !errors.Is(err, poksho.ErrVerification) {
			t.Fatalf("case %d: %v", i, err)
		}
	}
	if err := s.VerifyProof(proof, pa, []byte("other")); !errors.Is(err, poksho.ErrVerification) {
		t.Fatal(err)
	}
	wrong := poksho.PointArgs{"A": ristretto255.NewGeneratorElement()}
	if err := s.VerifyProof(proof, wrong, msg); !errors.Is(err, poksho.ErrVerification) {
		t.Fatal(err)
	}
	if _, err := s.Prove(sa, wrong, msg, [32]byte{}); !errors.Is(err, poksho.ErrProofCreationVerification) {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		sa   poksho.ScalarArgs
		pa   poksho.PointArgs
		want error
	}{
		{nil, pa, poksho.ErrWrongNumberOfScalarArgs},
		{poksho.ScalarArgs{"x": sa["a"]}, pa, poksho.ErrMissingScalarArg},
		{poksho.ScalarArgs{"a": nil}, pa, poksho.ErrMissingScalarArg},
		{sa, nil, poksho.ErrWrongNumberOfPointArgs},
		{sa, poksho.PointArgs{"X": pa["A"]}, poksho.ErrMissingPointArg},
		{sa, poksho.PointArgs{"A": nil}, poksho.ErrMissingPointArg},
		{sa, poksho.PointArgs{"A": pa["A"], "G": ristretto255.NewGeneratorElement()}, poksho.ErrWrongNumberOfPointArgs},
	} {
		if _, err := s.Prove(tc.sa, tc.pa, msg, [32]byte{}); !errors.Is(err, tc.want) {
			t.Fatalf("got %v want %v", err, tc.want)
		}
	}
	other := poksho.NewStatement()
	if err := other.Add("A", []poksho.Term{{Scalar: "a", Point: "G"}, {Scalar: "a", Point: "G"}}); err != nil {
		t.Fatal(err)
	}
	if err := other.VerifyProof(proof, pa, msg); !errors.Is(err, poksho.ErrVerification) {
		t.Fatal(err)
	}
	if _, err := new(poksho.Statement).Prove(nil, nil, nil, [32]byte{}); !errors.Is(err, poksho.ErrBadArgs) {
		t.Fatal(err)
	}
}

func TestProofEncoding(t *testing.T) {
	for _, n := range []int{1, 2, 255, 256} {
		b := make([]byte, 32*(n+1))
		p, err := poksho.ParseProof(b)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(p.Bytes(), b) {
			t.Fatal("encoding changed")
		}
	}
	for _, n := range []int{0, 1, 31, 32, 33, 63, 65, 32 * 258} {
		if _, err := poksho.ParseProof(make([]byte, n)); !errors.Is(err, poksho.ErrInvalidProof) {
			t.Fatalf("length %d: %v", n, err)
		}
	}
	order, _ := hex.DecodeString("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
	for _, offset := range []int{0, 32} {
		b := make([]byte, 64)
		copy(b[offset:], order)
		if _, err := poksho.ParseProof(b); !errors.Is(err, poksho.ErrInvalidProof) {
			t.Fatal(err)
		}
	}
	var zero poksho.Proof
	if zero.Bytes() != nil {
		t.Fatal("zero proof encoded")
	}
}

func TestStatementBuilder(t *testing.T) {
	var s poksho.Statement
	terms := []poksho.Term{{Scalar: "a", Point: "G"}}
	if err := s.Add("A", terms); err != nil {
		t.Fatal(err)
	}
	terms[0].Scalar = "changed"
	if got := s.Bytes(); !bytes.Equal(got, []byte{1, 1, 1, 0, 0}) {
		t.Fatalf("description %x", got)
	}
	before := s.Bytes()
	for _, tc := range []struct {
		lhs string
		rhs []poksho.Term
	}{
		{"", terms}, {"B", nil}, {"B", []poksho.Term{{Scalar: "new", Point: "H"}, {Scalar: "", Point: "G"}}},
		{"B", []poksho.Term{{Scalar: "new", Point: ""}}}, {"B", make([]poksho.Term, 256)},
	} {
		if err := s.Add(tc.lhs, tc.rhs); !errors.Is(err, poksho.ErrBadArgs) {
			t.Fatal(err)
		}
		if !bytes.Equal(before, s.Bytes()) {
			t.Fatal("failed Add mutated statement")
		}
	}
	if err := s.Add("B", []poksho.Term{{Scalar: "a", Point: "H"}}); err != nil {
		t.Fatal(err)
	}
	if got := s.Bytes(); !bytes.Equal(got, []byte{2, 1, 1, 0, 0, 2, 1, 0, 3}) {
		t.Fatalf("description %x", got)
	}
	// Name changes alone preserve the indexed relation; equation order does not.
	renamed := poksho.NewStatement()
	for _, e := range []struct{ lhs, point string }{{"X", "G"}, {"Y", "Z"}} {
		if err := renamed.Add(e.lhs, []poksho.Term{{Scalar: "x", Point: e.point}}); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(s.Bytes(), renamed.Bytes()) {
		t.Fatal("names affect description")
	}
}

func TestStatementLimits(t *testing.T) {
	for _, kind := range []string{"equations", "scalars", "points", "terms"} {
		t.Run(kind, func(t *testing.T) {
			s := poksho.NewStatement()
			rhs := []poksho.Term{{Scalar: "a", Point: "G"}}
			switch kind {
			case "equations":
				for range 255 {
					if err := s.Add("A", rhs); err != nil {
						t.Fatal(err)
					}
				}
			case "scalars":
				rhs = nil
				for i := range 255 {
					rhs = append(rhs, poksho.Term{Scalar: fmt.Sprint(i), Point: "G"})
				}
				if err := s.Add("A", rhs); err != nil {
					t.Fatal(err)
				}
				rhs = []poksho.Term{{Scalar: "extra", Point: "G"}}
			case "points":
				rhs = nil
				for i := range 253 {
					rhs = append(rhs, poksho.Term{Scalar: "a", Point: fmt.Sprint(i)})
				}
				if err := s.Add("A", rhs); err != nil {
					t.Fatal(err)
				}
				rhs = []poksho.Term{{Scalar: "a", Point: "extra"}}
			case "terms":
				rhs = nil
				for range 255 {
					rhs = append(rhs, poksho.Term{Scalar: "a", Point: "G"})
				}
				if err := s.Add("A", rhs); err != nil {
					t.Fatal(err)
				}
				rhs = append(rhs, rhs[0])
			}
			before := s.Bytes()
			if err := s.Add("A", rhs); !errors.Is(err, poksho.ErrBadArgs) {
				t.Fatal(err)
			}
			if !bytes.Equal(before, s.Bytes()) {
				t.Fatal("failed limit check changed statement")
			}
		})
	}
}

func TestInputOwnershipAndDeterminism(t *testing.T) {
	s, sa, pa, proof := signature(t)
	a, p := bytes.Clone(sa["a"].Bytes()), bytes.Clone(pa["A"].Bytes())
	for range 2 {
		got, err := s.Prove(sa, pa, []byte("message"), [32]byte{9})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, proof) {
			t.Fatal("not deterministic")
		}
	}
	if !bytes.Equal(a, sa["a"].Bytes()) || !bytes.Equal(p, pa["A"].Bytes()) {
		t.Fatal("mutated arguments")
	}
	changed, err := s.Prove(sa, pa, []byte("message"), [32]byte{10})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(proof, changed) {
		t.Fatal("randomness ignored")
	}
}

func TestSHOState(t *testing.T) {
	for _, variant := range []string{"hmac", "sha"} {
		t.Run(variant, func(t *testing.T) {
			newSHO := func() poksho.SHO {
				if variant == "hmac" {
					return poksho.NewShoHmacSha256([]byte("label"))
				}
				return poksho.NewShoSha256([]byte("label"))
			}
			clone := func(s poksho.SHO) poksho.SHO {
				switch s := s.(type) {
				case *poksho.ShoHmacSha256:
					return s.Clone()
				case *poksho.ShoSha256:
					return s.Clone()
				default:
					panic("type")
				}
			}
			a, b := newSHO(), newSHO()
			a.Absorb([]byte("abc"))
			a.Absorb([]byte("def"))
			a.Ratchet()
			b.AbsorbAndRatchet([]byte("abcdef"))
			b.Ratchet()
			b.Ratchet()
			if !bytes.Equal(a.SqueezeAndRatchet(65), b.SqueezeAndRatchet(65)) {
				t.Fatal("split absorption or repeated ratchet")
			}
			for _, absorbing := range []bool{false, true} {
				original := newSHO()
				if absorbing {
					original.Absorb([]byte("partial"))
				}
				left, right := clone(original), clone(original)
				left.AbsorbAndRatchet([]byte("left"))
				right.AbsorbAndRatchet([]byte("right"))
				original.AbsorbAndRatchet([]byte("left"))
				l, r := left.SqueezeAndRatchet(65), right.SqueezeAndRatchet(65)
				if bytes.Equal(l, r) || !bytes.Equal(l, original.SqueezeAndRatchet(65)) {
					t.Fatal("clone aliases state")
				}
			}
			a, b = newSHO(), newSHO()
			a.SqueezeAndRatchet(0)
			if bytes.Equal(a.SqueezeAndRatchet(32), b.SqueezeAndRatchet(32)) {
				t.Fatal("empty squeeze did not ratchet")
			}
			a, b = newSHO(), newSHO()
			a.AbsorbAndRatchet(nil)
			if bytes.Equal(a.SqueezeAndRatchet(32), b.SqueezeAndRatchet(32)) {
				t.Fatal("empty absorb did not ratchet")
			}
			for _, n := range []int{0, 1, 31, 32, 33, 63, 64, 65} {
				a, b = newSHO(), newSHO()
				out := make([]byte, n)
				a.SqueezeAndRatchetInto(out)
				if !bytes.Equal(out, b.SqueezeAndRatchet(n)) {
					t.Fatal("into mismatch")
				}
			}
			t.Run("squeeze while absorbing", func(t *testing.T) {
				defer func() {
					if recover() == nil {
						t.Fatal("expected misuse panic")
					}
				}()
				a := newSHO()
				a.Absorb(nil)
				a.SqueezeAndRatchet(0)
			})
		})
	}
}

func TestConversionRejectsBadInput(t *testing.T) {
	for _, b := range [][]byte{nil, make([]byte, 31), make([]byte, 33), bytes.Repeat([]byte{255}, 32)} {
		if _, err := poksho.ScalarFromCanonicalBytes(b); !errors.Is(err, poksho.ErrBadArgs) {
			t.Fatal(err)
		}
		if _, err := poksho.PointFromCanonicalBytes(b); !errors.Is(err, poksho.ErrBadArgs) {
			t.Fatal(err)
		}
	}
	for _, n := range []int{0, 32, 63, 65} {
		if _, err := poksho.ScalarFromUniformBytes(make([]byte, n)); !errors.Is(err, poksho.ErrBadArgs) {
			t.Fatal(err)
		}
		if _, err := poksho.PointFromUniformBytes(make([]byte, n)); !errors.Is(err, poksho.ErrBadArgs) {
			t.Fatal(err)
		}
	}
}

func FuzzProof(f *testing.F) {
	f.Add(make([]byte, 64))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{255}, 96))
	f.Fuzz(func(t *testing.T, b []byte) {
		parsed, err := poksho.ParseProof(b)
		if err == nil && !bytes.Equal(parsed.Bytes(), b) {
			t.Fatal("noncanonical round trip")
		}
		_ = poksho.VerifySignature(b, ristretto255.NewGeneratorElement(), []byte("fuzz"))
	})
}
