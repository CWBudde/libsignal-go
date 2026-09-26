// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package compat

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/cwbudde/libsignal-go/poksho"
	"github.com/gtank/ristretto255"
)

type pokshoParams struct {
	Variant string `json:"variant"`
	Label   string `json:"label"`
	Ops     []struct {
		Op     string `json:"op"`
		Input  string `json:"input"`
		Length int    `json:"length"`
	} `json:"ops"`
	Equations []struct {
		LHS   string `json:"lhs"`
		Terms []struct {
			Scalar string `json:"scalar"`
			Point  string `json:"point"`
		} `json:"terms"`
	} `json:"equations"`
	Scalars    map[string]string `json:"scalars"`
	Points     map[string]string `json:"points"`
	Scalar     string            `json:"scalar"`
	Point      string            `json:"point"`
	Message    string            `json:"message"`
	Randomness string            `json:"randomness"`
	Proof      string            `json:"proof"`
}
type pokshoResult struct {
	Proof    string   `json:"proof"`
	Outputs  []string `json:"outputs"`
	Verified bool     `json:"verified"`
}
type pokshoVector struct {
	Method string       `json:"method"`
	Params pokshoParams `json:"params"`
	Result pokshoResult `json:"result"`
}
type pokshoBatch struct {
	UpstreamTag string         `json:"upstream_tag"`
	Cases       []pokshoVector `json:"cases"`
	Conversions []struct {
		Uniform, Scalar   string
		BasepointMultiple string `json:"basepoint_multiple"`
		UniformPoint      string `json:"uniform_point"`
	} `json:"conversions"`
}

func loadPoksho(t *testing.T) pokshoBatch {
	t.Helper()
	b, err := os.ReadFile("vectors/poksho.json")
	if err != nil {
		t.Fatal(err)
	}
	var batch pokshoBatch
	if err := json.Unmarshal(b, &batch); err != nil {
		t.Fatal(err)
	}
	if batch.UpstreamTag != "v0.102.2" || len(batch.Cases) < 40 || len(batch.Conversions) < 16 {
		t.Fatal("incomplete poksho vectors")
	}
	return batch
}
func pokshoHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func pokshoScalar(t *testing.T, s string) *ristretto255.Scalar {
	t.Helper()
	v, err := poksho.ScalarFromCanonicalBytes(pokshoHex(t, s))
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func pokshoPoint(t *testing.T, s string) *ristretto255.Element {
	t.Helper()
	v, err := poksho.PointFromCanonicalBytes(pokshoHex(t, s))
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func pokshoStatement(t *testing.T, p pokshoParams) (*poksho.Statement, poksho.ScalarArgs, poksho.PointArgs) {
	t.Helper()
	s := poksho.NewStatement()
	sa, pa := poksho.ScalarArgs{}, poksho.PointArgs{}
	for _, e := range p.Equations {
		terms := make([]poksho.Term, 0, len(e.Terms))
		for _, term := range e.Terms {
			terms = append(terms, poksho.Term{Scalar: term.Scalar, Point: term.Point})
		}
		if err := s.Add(e.LHS, terms); err != nil {
			t.Fatal(err)
		}
	}
	for name, v := range p.Scalars {
		sa[name] = pokshoScalar(t, v)
	}
	for name, v := range p.Points {
		pa[name] = pokshoPoint(t, v)
	}
	return s, sa, pa
}
func runPoksho(t *testing.T, method string, p pokshoParams) pokshoResult {
	t.Helper()
	result := pokshoResult{}
	switch method {
	case "poksho.sho":
		var s poksho.SHO
		if p.Variant == "hmac" {
			s = poksho.NewShoHmacSha256(pokshoHex(t, p.Label))
		} else {
			s = poksho.NewShoSha256(pokshoHex(t, p.Label))
		}
		for _, op := range p.Ops {
			switch op.Op {
			case "absorb":
				s.Absorb(pokshoHex(t, op.Input))
			case "ratchet":
				s.Ratchet()
			case "absorb_and_ratchet":
				s.AbsorbAndRatchet(pokshoHex(t, op.Input))
			case "squeeze":
				result.Outputs = append(result.Outputs, hex.EncodeToString(s.SqueezeAndRatchet(op.Length)))
			case "clone":
				switch v := s.(type) {
				case *poksho.ShoHmacSha256:
					s = v.Clone()
				case *poksho.ShoSha256:
					s = v.Clone()
				}
			default:
				t.Fatal("unknown SHO operation")
			}
		}
	case "poksho.sign", "poksho.prove":
		random := pokshoHex(t, p.Randomness)
		if len(random) != 32 {
			t.Fatal("randomness length")
		}
		var proof []byte
		var err error
		if method == "poksho.sign" {
			proof, err = poksho.Sign(pokshoScalar(t, p.Scalar), pokshoPoint(t, p.Point), pokshoHex(t, p.Message), [32]byte(random))
		} else {
			s, sa, pa := pokshoStatement(t, p)
			proof, err = s.Prove(sa, pa, pokshoHex(t, p.Message), [32]byte(random))
		}
		if err != nil {
			t.Fatal(err)
		}
		result.Proof = hex.EncodeToString(proof)
	case "poksho.verify_signature":
		result.Verified = poksho.VerifySignature(pokshoHex(t, p.Proof), pokshoPoint(t, p.Point), pokshoHex(t, p.Message)) == nil
	case "poksho.verify":
		s, _, pa := pokshoStatement(t, p)
		result.Verified = s.VerifyProof(pokshoHex(t, p.Proof), pa, pokshoHex(t, p.Message)) == nil
	default:
		t.Fatalf("unknown method %s", method)
	}
	return result
}

func TestPokshoVectors(t *testing.T) {
	batch := loadPoksho(t)
	for i, c := range batch.Cases {
		t.Run(fmt.Sprintf("%s/%d", c.Method, i), func(t *testing.T) {
			got := runPoksho(t, c.Method, c.Params)
			if !reflect.DeepEqual(got, c.Result) {
				t.Fatalf("got %+v want %+v", got, c.Result)
			}
			if c.Method != "poksho.sho" {
				method := "poksho.verify"
				if c.Method == "poksho.sign" {
					method = "poksho.verify_signature"
				}
				c.Params.Proof = c.Result.Proof
				if !runPoksho(t, method, c.Params).Verified {
					t.Fatal("Rust vector did not verify")
				}
				parsed, err := poksho.ParseProof(pokshoHex(t, c.Result.Proof))
				if err != nil {
					t.Fatal(err)
				}
				if hex.EncodeToString(parsed.Bytes()) != c.Result.Proof {
					t.Fatal("proof round trip")
				}
			}
		})
	}
	for _, c := range batch.Conversions {
		uniform := pokshoHex(t, c.Uniform)
		scalar, err := poksho.ScalarFromUniformBytes(uniform)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(scalar.Bytes(), pokshoHex(t, c.Scalar)) {
			t.Fatal("scalar reduction")
		}
		if scalar.Equal(pokshoScalar(t, c.Scalar)) != 1 {
			t.Fatal("scalar parsing")
		}
		p := ristretto255.NewIdentityElement().ScalarBaseMult(scalar)
		if !bytes.Equal(p.Bytes(), pokshoHex(t, c.BasepointMultiple)) || p.Equal(pokshoPoint(t, c.BasepointMultiple)) != 1 {
			t.Fatal("point conversion")
		}
		p, err = poksho.PointFromUniformBytes(uniform)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(p.Bytes(), pokshoHex(t, c.UniformPoint)) {
			t.Fatal("uniform point mapping")
		}
	}
}
