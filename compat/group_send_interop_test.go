// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build interop

package compat

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"testing"
)

func groupSendRPC(p groupSendParams, a groupSendResult) map[string]any {
	b, _ := json.Marshal(p)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	out["artifacts"] = a
	return out
}
func TestGroupSendInterop(t *testing.T) {
	h := newHarness(t)
	for _, c := range loadGroupSend(t) {
		for randomize := range 2 {
			p := c.Params
			if randomize == 1 {
				fresh := func(n int) string {
					b := make([]byte, n)
					_, e := rand.Read(b)
					legacyCheck(t, e)
					return hex.EncodeToString(b)
				}
				p.Seed, p.Randomness, p.MasterKey = fresh(32), fresh(32), fresh(32)
				p.Members = slices.Clone(p.Members)
				for i, id := range p.Members {
					p.Members[i] = id[:2] + fresh(16)
				}
			}
			rust := zkCall[groupSendResult](t, h, "zkgroup.group_send", groupSendRPC(p, groupSendResult{}))
			got := runGroupSend(t, p)
			if !reflect.DeepEqual(got, rust) {
				t.Fatal("Rust/Go artifacts differ")
			}
			verify := zkCall[map[string]bool](t, h, "zkgroup.group_send.verify", groupSendRPC(p, got))
			if !verify["receive"] || !verify["token"] {
				t.Fatalf("Rust rejected Go: %v", verify)
			}
			for k, v := range verifyGroupSend(t, p, rust) {
				if !v {
					t.Fatalf("Go rejected Rust %s", k)
				}
			}
		}
	}
}
func TestGroupSendRejectionInterop(t *testing.T) {
	h := newHarness(t)
	c := loadGroupSend(t)[3]
	compare := func(p groupSendParams, a groupSendResult, want map[string]bool) {
		t.Helper()
		goResult := verifyGroupSend(t, p, a)
		rust := zkCall[map[string]bool](t, h, "zkgroup.group_send.verify", groupSendRPC(p, a))
		if !reflect.DeepEqual(goResult, rust) || !reflect.DeepEqual(rust, want) {
			t.Fatalf("Go=%v Rust=%v want=%v", goResult, rust, want)
		}
	}
	for _, now := range []uint64{c.Params.Expiration - 7*86400 - 1, c.Params.Expiration - 7*86400, c.Params.Expiration - 7200, c.Params.Expiration - 7199, c.Params.Expiration, c.Params.Expiration + 1, ^uint64(0)} {
		p := c.Params
		p.Now = now
		compare(p, c.Result, map[string]bool{"receive": now <= p.Expiration-7200 && now >= p.Expiration-7*86400, "token": now <= p.Expiration})
	}
	for _, field := range []string{"response", "token"} {
		for _, mode := range []string{"flip", "truncate", "empty"} {
			a := c.Result
			value := a.Response
			if field == "token" {
				value = a.FullToken
			}
			b := zkBytes(t, value)
			switch mode {
			case "flip":
				b[len(b)/2] ^= 1
			case "truncate":
				b = b[:1]
			case "empty":
				b = nil
			}
			if field == "token" {
				a.FullToken = hex.EncodeToString(b)
			} else {
				a.Response = hex.EncodeToString(b)
			}
			compare(c.Params, a, map[string]bool{"receive": field != "response", "token": field != "token"})
		}
	}
	p := c.Params
	p.Seed = loadGroupSend(t)[4].Params.Seed
	compare(p, c.Result, map[string]bool{"receive": false, "token": false})
	p = c.Params
	p.MasterKey = loadGroupSend(t)[4].Params.MasterKey
	compare(p, c.Result, map[string]bool{"receive": false, "token": true})
	p = c.Params
	p.Members = slices.Clone(p.Members)
	p.Members[1] = p.Members[2]
	compare(p, c.Result, map[string]bool{"receive": false, "token": false})
	p = c.Params
	p.Members = slices.Clone(p.Members)
	slices.Reverse(p.Members[1:])
	compare(p, c.Result, map[string]bool{"receive": true, "token": true})
	// ACI/PNI kind is part of the signed attribute, even for an identical UUID.
	p = c.Params
	p.Members = slices.Clone(p.Members)
	p.Members[1] = "00" + p.Members[1][2:]
	compare(p, c.Result, map[string]bool{"receive": false, "token": false})
	// Changing the day-aligned expiration invalidates both the proof and the token.
	a := c.Result
	for _, delta := range []byte{1, 128} {
		response := zkBytes(t, c.Result.Response)
		response[len(response)-8] ^= delta
		a.Response = hex.EncodeToString(response)
		token := zkBytes(t, c.Result.FullToken)
		token[len(token)-8] ^= delta
		a.FullToken = hex.EncodeToString(token)
		compare(c.Params, a, map[string]bool{"receive": false, "token": false})
	}
}
func TestGroupSendVectorRegeneration(t *testing.T) {
	bin := os.Getenv("COMPAT_HARNESS_BIN")
	if bin == "" {
		t.Skip("COMPAT_HARNESS_BIN unset")
	}
	want, e := os.ReadFile("vectors/group-send.json")
	legacyCheck(t, e)
	for range 2 {
		got, e := exec.Command(bin, "gen-vectors", "group-send").Output() //nolint:gosec // G204: operator-supplied compatibility harness.
		legacyCheck(t, e)
		if !bytes.Equal(got, want) {
			t.Fatal("group send vectors drifted")
		}
	}
}
