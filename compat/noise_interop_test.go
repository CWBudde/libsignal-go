// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build interop

package compat

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/cwbudde/libsignal-go/noise"
)

type noiseRPCResult struct {
	Message0      string   `json:"message0"`
	Message1      string   `json:"message1"`
	Payload0      string   `json:"payload0"`
	Payload1      string   `json:"payload1"`
	HandshakeHash string   `json:"handshake_hash"`
	Inbound       []string `json:"inbound"`
	Outbound      []string `json:"outbound"`
}

// callNoise returns the result, or the harness's error message when ok is false.
func callNoise(t *testing.T, h *harness, method string, params map[string]any) (noiseRPCResult, string) {
	t.Helper()
	resp := h.call(method, params)
	if !resp.Ok {
		return noiseRPCResult{}, resp.Error
	}
	var r noiseRPCResult
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		t.Fatal(err)
	}
	return r, ""
}

func mustNoise(t *testing.T, h *harness, method string, params map[string]any) noiseRPCResult {
	t.Helper()
	r, errMsg := callNoise(t, h, method, params)
	if errMsg != "" {
		t.Fatalf("%s: %s", method, errMsg)
	}
	return r
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func hexAll(items [][]byte) []string {
	out := make([]string, len(items))
	for i, b := range items {
		out[i] = hex.EncodeToString(b)
	}
	return out
}

// transportMessages returns fresh plaintexts: an empty one, short ones and
// one that spans two Noise messages.
func transportMessages(t *testing.T) [][]byte {
	t.Helper()
	return [][]byte{nil, randBytes(t, 1), randBytes(t, 300), randBytes(t, noise.MaxPayloadSize+100)}
}

func flip(b []byte, i int) []byte {
	b = bytes.Clone(b)
	b[i] ^= 1
	return b
}

// TestNoiseInterop runs fresh handshakes between Go and snow (the harness
// replays its side from a seed on each call), in both roles and for both
// patterns, then exchanges transport messages in both directions.
func TestNoiseInterop(t *testing.T) {
	h := newHarness(t)
	for _, pattern := range []string{"NK", "NKhfs"} {
		p := noisePattern(t, pattern)
		for round := range 4 {
			t.Run(fmt.Sprintf("%s/go-initiator/%d", pattern, round), func(t *testing.T) {
				goInitiator(t, h, pattern, p)
			})
			t.Run(fmt.Sprintf("%s/go-responder/%d", pattern, round), func(t *testing.T) {
				goResponder(t, h, pattern, p)
			})
		}
		t.Run(pattern+"/rejects", func(t *testing.T) { noiseRejects(t, h, pattern, p) })
	}
}

func goInitiator(t *testing.T, h *harness, pattern string, p noise.Pattern) {
	static, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ini, err := noise.NewInitiator(p, static.PublicKey().Bytes(), nil)
	if err != nil {
		t.Fatal(err)
	}
	payload0, payload1 := randBytes(t, 17), randBytes(t, 23)
	m0, err := ini.WriteMessage(payload0)
	if err != nil {
		t.Fatal(err)
	}
	params := map[string]any{
		"pattern":        pattern,
		"static_private": hex.EncodeToString(static.Bytes()),
		"seed":           hex.EncodeToString(randBytes(t, 32)),
		"message0":       hex.EncodeToString(m0),
		"payload1":       hex.EncodeToString(payload1),
	}
	first := mustNoise(t, h, "noise.responder", params)
	if first.Payload0 != hex.EncodeToString(payload0) {
		t.Fatal("snow read a different payload 0")
	}
	got1, err := ini.ReadMessage(unhex(t, first.Message1))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got1, payload1) {
		t.Fatal("payload 1 differs")
	}
	tr, err := ini.Transport()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(tr.HandshakeHash()) != first.HandshakeHash {
		t.Fatal("handshake hash differs")
	}

	toRust, fromRust := transportMessages(t), transportMessages(t)
	var inbound [][]byte
	for _, pt := range toRust {
		ct, err := tr.Send(pt)
		if err != nil {
			t.Fatal(err)
		}
		inbound = append(inbound, ct)
	}
	params["inbound"], params["outbound"] = hexAll(inbound), hexAll(fromRust)
	second := mustNoise(t, h, "noise.responder", params)
	if second.Message1 != first.Message1 {
		t.Fatal("harness replay is not deterministic")
	}
	checkExchange(t, tr, toRust, fromRust, second)
}

func goResponder(t *testing.T, h *harness, pattern string, p noise.Pattern) {
	static, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	res, err := noise.NewResponder(p, static.Bytes(), nil)
	if err != nil {
		t.Fatal(err)
	}
	payload0, payload1 := randBytes(t, 5), randBytes(t, 0)
	params := map[string]any{
		"pattern":       pattern,
		"remote_static": hex.EncodeToString(static.PublicKey().Bytes()),
		"seed":          hex.EncodeToString(randBytes(t, 32)),
		"payload0":      hex.EncodeToString(payload0),
	}
	first := mustNoise(t, h, "noise.initiator", params)
	got0, err := res.ReadMessage(unhex(t, first.Message0))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got0, payload0) {
		t.Fatal("payload 0 differs")
	}
	m1, err := res.WriteMessage(payload1)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := res.Transport()
	if err != nil {
		t.Fatal(err)
	}

	toRust, fromRust := transportMessages(t), transportMessages(t)
	var inbound [][]byte
	for _, pt := range toRust {
		ct, err := tr.Send(pt)
		if err != nil {
			t.Fatal(err)
		}
		inbound = append(inbound, ct)
	}
	params["message1"] = hex.EncodeToString(m1)
	params["inbound"], params["outbound"] = hexAll(inbound), hexAll(fromRust)
	second := mustNoise(t, h, "noise.initiator", params)
	if second.Message0 != first.Message0 {
		t.Fatal("harness replay is not deterministic")
	}
	if second.Payload1 != hex.EncodeToString(payload1) {
		t.Fatal("snow read a different payload 1")
	}
	if hex.EncodeToString(tr.HandshakeHash()) != second.HandshakeHash {
		t.Fatal("handshake hash differs")
	}
	checkExchange(t, tr, toRust, fromRust, second)
}

// checkExchange compares what snow decrypted with what Go sent, and decrypts
// what snow sent.
func checkExchange(t *testing.T, tr *noise.Transport, toRust, fromRust [][]byte, r noiseRPCResult) {
	t.Helper()
	if len(r.Inbound) != len(toRust) || len(r.Outbound) != len(fromRust) {
		t.Fatalf("harness returned %d/%d messages", len(r.Inbound), len(r.Outbound))
	}
	for i, pt := range toRust {
		if r.Inbound[i] != hex.EncodeToString(pt) {
			t.Fatalf("snow decrypted message %d differently", i)
		}
	}
	for i, ct := range r.Outbound {
		pt, err := tr.Recv(unhex(t, ct))
		if err != nil {
			t.Fatalf("message %d from snow: %v", i, err)
		}
		if !bytes.Equal(pt, fromRust[i]) {
			t.Fatalf("message %d from snow differs", i)
		}
	}
}

// noiseRejects checks that each side rejects the other's tampered or
// truncated messages and a wrong static key.
func noiseRejects(t *testing.T, h *harness, pattern string, p noise.Pattern) {
	static, _ := ecdh.X25519().GenerateKey(rand.Reader)
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	seed := hex.EncodeToString(randBytes(t, 32))

	// Go initiator → snow responder. The initiator's randomness is fixed, so
	// newInitiator rebuilds the same one for each check.
	goRandom := randBytes(t, 32+64)
	newInitiator := func() (*noise.HandshakeState, []byte) {
		ini, err := noise.NewInitiator(p, static.PublicKey().Bytes(), bytes.NewReader(goRandom))
		if err != nil {
			t.Fatal(err)
		}
		m0, err := ini.WriteMessage(nil)
		if err != nil {
			t.Fatal(err)
		}
		return ini, m0
	}
	_, m0 := newInitiator()
	respond := func(key *ecdh.PrivateKey, msg []byte) string {
		_, errMsg := callNoise(t, h, "noise.responder", map[string]any{
			"pattern": pattern, "static_private": hex.EncodeToString(key.Bytes()),
			"seed": seed, "message0": hex.EncodeToString(msg), "payload1": "",
		})
		return errMsg
	}
	if respond(other, m0) == "" {
		t.Error("snow accepted message 0 for another static key")
	}
	for _, i := range []int{0, 40, len(m0) - 1} {
		if respond(static, flip(m0, i)) == "" {
			t.Errorf("snow accepted message 0 with byte %d flipped", i)
		}
	}
	if respond(static, m0[:len(m0)-1]) == "" {
		t.Error("snow accepted a truncated message 0")
	}
	ok := mustNoise(t, h, "noise.responder", map[string]any{
		"pattern": pattern, "static_private": hex.EncodeToString(static.Bytes()),
		"seed": seed, "message0": hex.EncodeToString(m0), "payload1": "",
	})
	m1 := unhex(t, ok.Message1)
	// For NKhfs, byte 40 lies in ekem1; the truncation cuts into the tag.
	for _, bad := range [][]byte{flip(m1, 0), flip(m1, 40), flip(m1, len(m1)-1), m1[:len(m1)-1]} {
		ini, _ := newInitiator()
		if _, err := ini.ReadMessage(bad); err == nil {
			t.Error("Go accepted a tampered message 1 from snow")
		}
	}
	ini, _ := newInitiator()
	if _, err := ini.ReadMessage(m1); err != nil {
		t.Fatalf("untampered message 1: %v", err)
	}

	// snow initiator → Go responder.
	params := map[string]any{
		"pattern": pattern, "remote_static": hex.EncodeToString(static.PublicKey().Bytes()),
		"seed": seed, "payload0": "",
	}
	r0 := unhex(t, mustNoise(t, h, "noise.initiator", params).Message0)
	for _, bad := range [][]byte{flip(r0, 0), flip(r0, 40), flip(r0, len(r0)-1), r0[:len(r0)-1]} {
		res, _ := noise.NewResponder(p, static.Bytes(), nil)
		if _, err := res.ReadMessage(bad); err == nil {
			t.Error("Go accepted a tampered message 0 from snow")
		}
	}
	res, _ := noise.NewResponder(p, static.Bytes(), nil)
	if _, err := res.ReadMessage(r0); err != nil {
		t.Fatal(err)
	}
	g1, err := res.WriteMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{flip(g1, 0), flip(g1, 40), flip(g1, len(g1)-1), g1[:len(g1)-1]} {
		params["message1"] = hex.EncodeToString(bad)
		if _, errMsg := callNoise(t, h, "noise.initiator", params); errMsg == "" {
			t.Error("snow accepted a tampered message 1 from Go")
		}
	}
	params["message1"] = hex.EncodeToString(g1)
	mustNoise(t, h, "noise.initiator", params)
}

// TestNoiseVectorRegeneration checks that the generator is deterministic and
// matches the committed fixture.
func TestNoiseVectorRegeneration(t *testing.T) {
	bin := os.Getenv("COMPAT_HARNESS_BIN")
	if bin == "" {
		t.Skip("COMPAT_HARNESS_BIN unset")
	}
	want, err := os.ReadFile("vectors/noise.json")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		// Operator-supplied harness, same contract as newHarness.
		got, err := exec.Command(bin, "gen-vectors", "noise").Output() //nolint:gosec // G204: intentional test harness execution.
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("regenerated noise vectors differ from committed bytes")
		}
	}
}
