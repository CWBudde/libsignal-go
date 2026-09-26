// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build interop

package compat

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"maps"
	"os"
	"os/exec"
	"reflect"
	"testing"
)

func legacyRPC(p legacyParams, a map[string]string) map[string]any {
	return map[string]any{"seed": p.Seed, "uuid": p.UUID, "profile_key": p.ProfileKey, "serial": p.Serial, "message": p.Message, "timestamp": p.Timestamp, "level": p.Level, "artifacts": a}
}
func compareLegacyVerification(t *testing.T, h *harness, p legacyParams, a map[string]string, wantRejected ...string) {
	t.Helper()
	goResult := verifyLegacy(t, p, a)
	rust := zkCall[map[string]bool](t, h, "zkgroup.credentials.verify", legacyRPC(p, a))
	if !reflect.DeepEqual(goResult, rust) {
		t.Fatalf("verification differs: Go=%v Rust=%v", goResult, rust)
	}
	if len(wantRejected) == 0 {
		for name, ok := range rust {
			if !ok {
				t.Fatalf("rejected %s", name)
			}
		}
	}
	for _, name := range wantRejected {
		if rust[name] {
			t.Fatalf("accepted tampered %s", name)
		}
	}
}
func TestZKGroupCredentialInterop(t *testing.T) {
	h := newHarness(t)
	cases := loadLegacy(t).Cases
	for i := range 40 {
		p := cases[i%len(cases)].Params
		if i >= len(cases) {
			var b [96]byte
			if _, e := rand.Read(b[:]); e != nil {
				t.Fatal(e)
			}
			p.Seed = hex.EncodeToString(b[:32])
			p.UUID = hex.EncodeToString(b[32:48])
			p.ProfileKey = hex.EncodeToString(b[48:80])
			p.Serial = hex.EncodeToString(b[80:])
			p.Message = hex.EncodeToString(b[:])
		}
		rust := zkCall[map[string]string](t, h, "zkgroup.credentials", legacyRPC(p, nil))
		goResult := runLegacy(t, p)
		for name, want := range rust {
			if goResult[name] != want {
				t.Fatalf("case %d: live %s mismatch", i, name)
			}
		}
		compareLegacyVerification(t, h, p, goResult)
		for name, ok := range verifyLegacy(t, p, rust) {
			if !ok {
				t.Fatalf("Go rejected live Rust %s", name)
			}
		}
	}
}
func TestZKGroupCredentialRejectionInterop(t *testing.T) {
	h := newHarness(t)
	cases := loadLegacy(t).Cases
	p, a := cases[3].Params, cases[3].Result
	for field, proof := range map[string]string{
		"signature": "signature", "signing_public": "signature",
		"request_proof": "request", "request_public": "request", "request": "request", "commitment": "request",
		"issuance_proof": "issuance", "public_expiring": "issuance", "blinded": "issuance",
		"presentation": "presentation", "uid_ciphertext": "presentation", "profile_ciphertext": "presentation", "uid_public": "presentation", "profile_enc_public": "presentation", "key_expiring": "presentation",
		"receipt_issuance": "receipt_issuance", "receipt_request_public": "receipt_issuance", "receipt_request": "receipt_issuance", "receipt_blinded": "receipt_issuance", "public_receipt": "receipt_issuance",
		"receipt_presentation": "receipt_presentation", "key_receipt": "receipt_presentation",
	} {
		t.Run(field, func(t *testing.T) {
			changed := maps.Clone(a)
			changed[field] = cases[4].Result[field] // well-formed, unrelated artifact
			compareLegacyVerification(t, h, p, changed, proof)
			raw := zkBytes(t, a[field])
			raw[len(raw)-1] ^= 1
			changed[field] = hex.EncodeToString(raw)
			compareLegacyVerification(t, h, p, changed, proof)
		})
	}
	for field, proof := range map[string]string{"signature": "signature", "request_proof": "request", "issuance_proof": "issuance", "presentation": "presentation", "receipt_issuance": "receipt_issuance", "receipt_presentation": "receipt_presentation"} {
		raw := zkBytes(t, a[field])
		for _, bad := range [][]byte{nil, raw[:len(raw)-1], bytes.Repeat([]byte{255}, len(raw)), make([]byte, 8), bytes.Repeat([]byte{255}, 8)} {
			changed := maps.Clone(a)
			changed[field] = hex.EncodeToString(bad)
			compareLegacyVerification(t, h, p, changed, proof)
		}
	}
	changed := p
	changed.Timestamp ^= 1
	compareLegacyVerification(t, h, changed, a, "issuance", "presentation", "receipt_issuance", "receipt_presentation")
	changed = p
	changed.UUID = cases[4].Params.UUID
	compareLegacyVerification(t, h, changed, a, "issuance")
	changed = p
	changed.Serial = cases[4].Params.Serial
	compareLegacyVerification(t, h, changed, a, "receipt_presentation")
	changed = p
	changed.Level ^= 1
	compareLegacyVerification(t, h, changed, a, "receipt_issuance", "receipt_presentation")
	changed = p
	changed.Message = cases[4].Params.Message
	compareLegacyVerification(t, h, changed, a, "signature")
	for _, params := range []map[string]any{nil, {"seed": "00"}} {
		if h.call("zkgroup.credentials", params).Ok {
			t.Fatal("accepted malformed request")
		}
	}
	if !h.call("ping", nil).Ok {
		t.Fatal("harness did not survive malformed requests")
	}
}
func TestZKGroupCredentialVectorRegeneration(t *testing.T) {
	bin := os.Getenv("COMPAT_HARNESS_BIN")
	if bin == "" {
		t.Skip("COMPAT_HARNESS_BIN unset")
	}
	want, e := os.ReadFile("vectors/zkgroup-credentials.json")
	legacyCheck(t, e)
	for range 2 {
		got, e := exec.Command(bin, "gen-vectors", "zkgroup-credentials").Output() //nolint:gosec // G204: operator-supplied compatibility harness.
		legacyCheck(t, e)
		if !bytes.Equal(got, want) {
			t.Fatal("credential vectors drifted")
		}
	}
}

// The pinned Rust deserialize_in_place does not check end-of-input, despite
// configuring reject_trailing_bytes. Go deliberately retains the package's
// exact-length boundary. Record this difference rather than hiding it in the oracle.
func TestZKGroupCredentialTrailingDataPolicy(t *testing.T) {
	h := newHarness(t)
	c := loadLegacy(t).Cases[3]
	for field, proof := range map[string]string{"request_proof": "request", "issuance_proof": "issuance", "presentation": "presentation", "receipt_issuance": "receipt_issuance", "receipt_presentation": "receipt_presentation"} {
		a := maps.Clone(c.Result)
		a[field] = hex.EncodeToString(append(zkBytes(t, a[field]), 0))
		rust := zkCall[map[string]bool](t, h, "zkgroup.credentials.verify", legacyRPC(c.Params, a))
		if !rust[proof] || verifyLegacy(t, c.Params, a)[proof] {
			t.Fatalf("trailing-data boundary changed for %s", field)
		}
	}
}
