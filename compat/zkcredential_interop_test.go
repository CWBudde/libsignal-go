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
	"maps"
	"os"
	"os/exec"
	"reflect"
	"testing"
)

func genericRPC(p genericParams, a map[string]string) map[string]any {
	return map[string]any{"seed": p.Seed, "label": p.Label, "message": p.Message, "public": p.Public, "hidden": p.Hidden, "clear": p.Clear, "revealed": p.Revealed, "same": p.Same, "unverified": p.Unverified, "legacy": p.Legacy, "artifacts": a}
}
func compareGenericVerification(t *testing.T, h *harness, p genericParams, a map[string]string, rejected ...string) {
	t.Helper()
	got := verifyGeneric(t, p, a)
	want := zkCall[map[string]bool](t, h, "zkcredential.verify", genericRPC(p, a))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Go=%v Rust=%v", got, want)
	}
	if len(rejected) == 0 {
		for n, ok := range got {
			if !ok {
				t.Fatalf("rejected %s", n)
			}
		}
	}
	for _, n := range rejected {
		if got[n] {
			t.Fatalf("accepted tampered %s", n)
		}
	}
}
func TestZKCredentialInterop(t *testing.T) {
	h := newHarness(t)
	cases := loadGeneric(t).Cases
	for i, c := range cases {
		p := c.Params
		if i%2 == 0 {
			var entropy [96]byte
			_, e := rand.Read(entropy[:])
			legacyCheck(t, e)
			p.Seed = hex.EncodeToString(entropy[:32])
			p.Public = hex.EncodeToString(entropy[32:64])
			p.Message = hex.EncodeToString(entropy[64:])
			p.Label = hex.EncodeToString(entropy[16:48])
		}
		rust := zkCall[map[string]string](t, h, "zkcredential", genericRPC(p, nil))
		got := runGeneric(t, p)
		if !reflect.DeepEqual(got, rust) {
			t.Fatalf("case %d differs", i)
		}
		compareGenericVerification(t, h, p, got)
		for n, ok := range verifyGeneric(t, p, rust) {
			if !ok {
				t.Fatalf("rejected Rust %s", n)
			}
		}
	}
}
func TestZKCredentialRejectionInterop(t *testing.T) {
	h := newHarness(t)
	cases := loadGeneric(t).Cases
	for _, idx := range []int{0, 8, 12, 16, 20, 24, 26, 34, 38, 42, 46, 50} {
		c := cases[idx]
		p, a := c.Params, c.Result
		fields := map[string]string{"key": "presentation", "public_key": "issuance", "issuance": "issuance", "presentation": "presentation", "derived_public": "endorsement", "endorsement_response": "endorsement", "endorsement_hidden": "endorsement", "derived": "token", "endorsement_plain": "token", "token": "token"}
		for i := range p.Hidden {
			fields[genericName("cipher", i)] = "presentation"
			if i < p.Clear {
				fields[genericName("attr", i)] = "issuance"
			} else {
				fields[genericName("blind", i)] = "issuance"
			}
		}
		for i := range p.Revealed {
			fields[genericName("revealed", i)] = "presentation"
			fields[genericName("revealed_blind", i)] = "issuance"
		}
		if p.Hidden > 0 && !p.Unverified {
			fields["enc_public0"] = "presentation"
		}
		if p.blinded() {
			fields["blinding_key"] = "issuance"
		}
		for field, op := range fields {
			changed := maps.Clone(a)
			b := zkBytes(t, a[field])
			offset := len(b) - 1
			if field == "derived" || field == "public_key" {
				offset = 0
			}
			if field == "key" {
				offset = 96
			} // x0; w and wprime are not used by the presentation verifier.
			b[offset] ^= 1
			changed[field] = hex.EncodeToString(b)
			t.Run(fmt.Sprintf("case%d/%s", idx, field), func(t *testing.T) { compareGenericVerification(t, h, p, changed, op) })
		}
		for field, op := range map[string]string{"issuance": "issuance", "presentation": "presentation", "endorsement_response": "endorsement"} {
			raw := zkBytes(t, a[field])
			for _, bad := range [][]byte{nil, raw[:len(raw)-1], append(bytes.Clone(raw), 0), bytes.Repeat([]byte{255}, len(raw)), bytes.Repeat([]byte{255}, 8)} {
				changed := maps.Clone(a)
				changed[field] = hex.EncodeToString(bad)
				t.Run(fmt.Sprintf("case%d/%s", idx, field), func(t *testing.T) { compareGenericVerification(t, h, p, changed, op) })
			}
		}
		for _, field := range []string{"label", "message", "public"} {
			changed := p
			switch field {
			case "label":
				changed.Label += "00"
			case "message":
				changed.Message += "00"
			case "public":
				changed.Public += "00"
			}
			compareGenericVerification(t, h, changed, a, "issuance", "presentation")
		}
		if p.Hidden > 0 {
			changed := p
			changed.Legacy = !p.Legacy
			compareGenericVerification(t, h, changed, a, "presentation")
		}
	}
	for _, p := range []map[string]any{nil, {"seed": "00"}} {
		if h.call("zkcredential", p).Ok {
			t.Fatal("accepted malformed params")
		}
	}
	if !h.call("ping", nil).Ok {
		t.Fatal("harness did not survive")
	}
}
func TestZKCredentialVectorRegeneration(t *testing.T) {
	bin := os.Getenv("COMPAT_HARNESS_BIN")
	if bin == "" {
		t.Skip("COMPAT_HARNESS_BIN unset")
	}
	want, e := os.ReadFile("vectors/zkcredential.json")
	legacyCheck(t, e)
	for range 2 {
		got, e := exec.Command(bin, "gen-vectors", "zkcredential").Output() //nolint:gosec // G204: operator-supplied compatibility harness.
		legacyCheck(t, e)
		if !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(want)) {
			var v genericVectors
			legacyCheck(t, json.Unmarshal(got, &v))
			t.Fatal("regenerated bytes differ")
		}
	}
}

// Legacy mode authenticates the sum of encryption public keys. Standard mode
// additionally binds each key in order, preventing substitutions with the same sum.
func TestZKCredentialPublicKeyBinding(t *testing.T) {
	h := newHarness(t)
	cases := loadGeneric(t).Cases
	for _, idx := range []int{14, 40} {
		c := cases[idx]
		changed := maps.Clone(c.Result)
		changed["enc_public0"], changed["enc_public1"] = changed["enc_public1"], changed["enc_public0"]
		if c.Params.Legacy {
			compareGenericVerification(t, h, c.Params, changed)
		} else {
			compareGenericVerification(t, h, c.Params, changed, "presentation")
		}
	}
}
