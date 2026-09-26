// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build interop

package compat

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"testing"
)

func callPoksho(t *testing.T, h *harness, method string, p pokshoParams) pokshoResult {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var params map[string]any
	if err := json.Unmarshal(b, &params); err != nil {
		t.Fatal(err)
	}
	resp := h.call(method, params)
	if !resp.Ok {
		t.Fatalf("%s: %s", method, resp.Error)
	}
	var result pokshoResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestPokshoInterop(t *testing.T) {
	h := newHarness(t)
	for i, c := range loadPoksho(t).Cases {
		t.Run(fmt.Sprintf("%s/%d", c.Method, i), func(t *testing.T) {
			if c.Method == "poksho.sho" {
				if got := callPoksho(t, h, c.Method, c.Params); !reflect.DeepEqual(got, runPoksho(t, c.Method, c.Params)) {
					t.Fatal("SHO mismatch")
				}
				return
			}
			// Fresh live transcript, not just verification of the committed fixtures.
			var random [32]byte
			var message [51]byte
			if _, err := rand.Read(random[:]); err != nil {
				t.Fatal(err)
			}
			if _, err := rand.Read(message[:]); err != nil {
				t.Fatal(err)
			}
			p := c.Params
			p.Randomness = hex.EncodeToString(random[:])
			p.Message = hex.EncodeToString(message[:])
			goProof := runPoksho(t, c.Method, p).Proof
			rustProof := callPoksho(t, h, c.Method, p).Proof
			if goProof != rustProof {
				t.Fatal("deterministic proof bytes differ")
			}
			verify := "poksho.verify"
			if c.Method == "poksho.sign" {
				verify = "poksho.verify_signature"
			}
			p.Proof = goProof
			if !callPoksho(t, h, verify, p).Verified {
				t.Fatal("Rust rejected Go proof")
			}
			p.Proof = rustProof
			if !runPoksho(t, verify, p).Verified {
				t.Fatal("Go rejected Rust proof")
			}
			originalMessage := p.Message
			p.Message = "00" + p.Message
			if callPoksho(t, h, verify, p).Verified || runPoksho(t, verify, p).Verified {
				t.Fatal("accepted changed message")
			}
			p.Message = originalMessage
			b := pokshoHex(t, rustProof)
			corrupt := bytes.Clone(b)
			corrupt[len(corrupt)-1] ^= 128
			noncanonical := bytes.Clone(b)
			for j := range 32 {
				noncanonical[j] = 255
			}
			for _, bad := range [][]byte{nil, b[:len(b)-1], append(bytes.Clone(b), make([]byte, 32)...), corrupt, noncanonical, make([]byte, 32*258)} {
				p.Proof = hex.EncodeToString(bad)
				if callPoksho(t, h, verify, p).Verified || runPoksho(t, verify, p).Verified {
					t.Fatal("accepted malformed proof")
				}
			}
		})
	}
}

func TestPokshoVectorRegeneration(t *testing.T) {
	bin := os.Getenv("COMPAT_HARNESS_BIN")
	if bin == "" {
		t.Skip("COMPAT_HARNESS_BIN unset")
	}
	want, err := os.ReadFile("vectors/poksho.json")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		// Operator-supplied harness, same contract as newHarness.
		got, err := exec.Command(bin, "gen-vectors", "poksho").Output() //nolint:gosec // G204: intentional test harness execution.
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("regenerated poksho vectors differ from committed bytes")
		}
	}
}

func TestPokshoHarnessRejectsBadRequests(t *testing.T) {
	h := newHarness(t)
	for _, req := range []struct {
		method string
		params map[string]any
	}{
		{"poksho.unknown", nil},
		{"poksho.sho", map[string]any{"variant": "hmac", "label": "", "ops": []any{map[string]any{"op": "absorb", "input": ""}, map[string]any{"op": "squeeze", "length": 1}}}},
		{"poksho.prove", map[string]any{"equations": []any{map[string]any{"lhs": "A", "terms": []any{}}}}},
		{"poksho.verify_signature", map[string]any{"point": "ff", "proof": "", "message": ""}},
	} {
		if resp := h.call(req.method, req.params); resp.Ok {
			t.Fatal("accepted bad request")
		}
	}
	if resp := h.call("ping", nil); !resp.Ok {
		t.Fatal("harness did not survive bad requests")
	}
}
