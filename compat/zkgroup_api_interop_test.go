// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build interop

package compat

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"maps"
	"os"
	"os/exec"
	"reflect"
	"testing"
)

func apiRPC(p apiParams, a map[string]string) map[string]any {
	b, _ := json.Marshal(p)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	out["artifacts"] = a
	return out
}
func compareAPI(t *testing.T, h *harness, p apiParams, a map[string]string, rejected ...string) {
	t.Helper()
	goResult := verifyAPI(t, p, a)
	rust := zkCall[map[string]bool](t, h, "zkgroup.api.verify", apiRPC(p, a))
	if !reflect.DeepEqual(goResult, rust) {
		t.Fatalf("verification differs: Go=%v Rust=%v", goResult, rust)
	}
	if len(rejected) == 0 {
		for k, v := range rust {
			if !v {
				t.Fatalf("rejected %s", k)
			}
		}
	}
	for _, k := range rejected {
		if rust[k] {
			t.Fatalf("accepted altered %s", k)
		}
	}
}
func TestZKGroupAPIInterop(t *testing.T) {
	h := newHarness(t)
	cases := loadAPI(t)
	for i := range 32 {
		p := cases[i%len(cases)].Params
		if i >= len(cases) {
			fresh := func(n int) string {
				b := make([]byte, n)
				_, e := rand.Read(b)
				legacyCheck(t, e)
				return hex.EncodeToString(b)
			}
			p.Seed = fresh(32)
			p.Randomness = fresh(32)
			p.MasterKey = fresh(32)
			p.ACI = fresh(16)
			p.PNI = fresh(16)
			p.ProfileKey = fresh(32)
			p.Message = fresh(i)
		}
		rust := zkCall[map[string]string](t, h, "zkgroup.api", apiRPC(p, nil))
		got := runAPI(t, p)
		for k, v := range rust {
			if got[k] != v {
				t.Fatalf("case %d: %s mismatch", i, k)
			}
		}
		compareAPI(t, h, p, got)
		for k, v := range verifyAPI(t, p, rust) {
			if !v {
				t.Fatalf("Go rejected Rust %s", k)
			}
		}
	}
}
func TestZKGroupAPIRejectionInterop(t *testing.T) {
	h := newHarness(t)
	cases := loadAPI(t)
	p, a := cases[2].Params, cases[2].Result
	for field, checks := range map[string][]string{"signature": {"signature"}, "blob": {"blob"}, "aci_ciphertext": {"uid"}, "profile_ciphertext": {"profile_key"}, "context": {"profile_receive"}, "profile_response": {"profile_receive"}, "profile_presentation": {"profile_presentation"}, "auth_response": {"auth_receive"}, "auth_presentation": {"auth_presentation"}} {
		t.Run(field, func(t *testing.T) {
			changed := maps.Clone(a)
			changed[field] = cases[3].Result[field]
			compareAPI(t, h, p, changed, checks...)
			raw := zkBytes(t, a[field])
			offset := len(raw) / 2
			raw[offset] ^= 1
			changed[field] = hex.EncodeToString(raw)
			compareAPI(t, h, p, changed, checks...)
			// The oracle guards Rust's historical empty-presentation indexing panic.
			changed[field] = hex.EncodeToString(raw[:1])
			compareAPI(t, h, p, changed, checks...)
			changed[field] = ""
			compareAPI(t, h, p, changed, checks...)
		})
	}
	changed := p
	changed.Seed = cases[3].Params.Seed
	compareAPI(t, h, changed, a, "signature", "profile_receive", "auth_receive", "profile_presentation", "auth_presentation")
	changed = p
	changed.MasterKey = cases[3].Params.MasterKey
	compareAPI(t, h, changed, a, "profile_presentation", "auth_presentation", "uid", "profile_key", "blob")
	changed = p
	changed.ACI = cases[3].Params.ACI
	compareAPI(t, h, changed, a, "auth_receive", "uid", "profile_key")
	changed = p
	changed.PNI = cases[3].Params.PNI
	compareAPI(t, h, changed, a, "auth_receive")
	changed = p
	changed.Redemption++
	compareAPI(t, h, changed, a, "auth_receive")
	for _, now := range []uint64{p.Expiration, p.Expiration - 1, p.Expiration - 86400 + 1, p.Expiration - 8*86400, ^uint64(0)} {
		changed = p
		changed.Now = now
		compareAPI(t, h, changed, a, "profile_receive")
	}
	for _, now := range []uint64{p.Redemption - 86400 - 1, p.Redemption + 2*86400 + 1} {
		changed = p
		changed.Now = now
		compareAPI(t, h, changed, a, "auth_presentation")
	}
}
func TestZKGroupAPIVectorRegeneration(t *testing.T) {
	bin := os.Getenv("COMPAT_HARNESS_BIN")
	if bin == "" {
		t.Skip("COMPAT_HARNESS_BIN unset")
	}
	want, e := os.ReadFile("vectors/zkgroup-api.json")
	legacyCheck(t, e)
	for range 2 {
		got, e := exec.Command(bin, "gen-vectors", "zkgroup-api").Output() //nolint:gosec // G204: operator-supplied compatibility harness.
		legacyCheck(t, e)
		if !bytes.Equal(got, want) {
			t.Fatal("API vectors drifted")
		}
	}
}

// Rust deserialize_in_place accepts trailing API bytes despite reject_trailing_bytes.
// Keep Go's strict boundary explicit instead of weakening parsers to match it.
func TestZKGroupAPITrailingDataPolicy(t *testing.T) {
	h := newHarness(t)
	c := loadAPI(t)[0]
	for field, result := range map[string]string{"context": "profile_receive", "profile_response": "profile_receive", "auth_response": "auth_receive", "profile_presentation": "profile_presentation", "auth_presentation": "auth_presentation"} {
		a := maps.Clone(c.Result)
		a[field] = hex.EncodeToString(append(zkBytes(t, a[field]), 0))
		rust := zkCall[map[string]bool](t, h, "zkgroup.api.verify", apiRPC(c.Params, a))
		if !rust[result] || verifyAPI(t, c.Params, a)[result] {
			t.Fatalf("trailing-data policy changed for %s", field)
		}
	}
}
