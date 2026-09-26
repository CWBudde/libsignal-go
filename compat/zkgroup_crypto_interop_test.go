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
	"testing"

	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/internal/ristrettolizard"
	"github.com/cwbudde/libsignal-go/zkgroup/zkcrypto"
	"github.com/gtank/ristretto255"
)

func zkCall[T any](t *testing.T, h *harness, method string, p map[string]any) T {
	t.Helper()
	r := h.call(method, p)
	if !r.Ok {
		t.Fatalf("%s: %s", method, r.Error)
	}
	var result T
	if err := json.Unmarshal(r.Result, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

type zkDecryption struct {
	Verified  bool   `json:"verified"`
	Plaintext string `json:"plaintext"`
}

func TestZKGroupCryptoInterop(t *testing.T) {
	h := newHarness(t)
	cases := loadZK(t).Cases
	for i := range 64 {
		p := cases[i%len(cases)].Params
		if i >= len(cases) {
			var b [80]byte
			if _, err := rand.Read(b[:]); err != nil {
				t.Fatal(err)
			}
			p.Seed = hex.EncodeToString(b[:32])
			p.UUID = hex.EncodeToString(b[32:48])
			p.ProfileKey = hex.EncodeToString(b[48:])
		}
		rust := zkCall[zkResult](t, h, "zkgroup.crypto", map[string]any{
			"seed": p.Seed, "uuid": p.UUID, "profile_key": p.ProfileKey, "pni": p.PNI, "timestamp": p.Timestamp,
		})
		goResult := runZK(t, p)
		if !reflect.DeepEqual(rust, goResult) {
			t.Fatalf("case %d differs from live Rust", i)
		}
		uidKey, profileKey := zkKeys(t, p.Seed)
		uuid := [16]byte(zkBytes(t, p.UUID))
		id := address.NewACI(uuid)
		if p.PNI {
			id = address.NewPNI(uuid)
		}
		params := map[string]any{"seed": p.Seed, "uuid": p.UUID, "ciphertext": goResult.UIDCiphertext}
		got := zkCall[zkDecryption](t, h, "zkgroup.decrypt_uid", params)
		if !got.Verified || got.Plaintext != hex.EncodeToString(id.ServiceIDBinary()) {
			t.Fatal("Rust rejected Go UID ciphertext")
		}
		uidCipher, err := zkcrypto.ParseUIDCiphertext(zkBytes(t, rust.UIDCiphertext))
		if err != nil {
			t.Fatal(err)
		}
		if got, err := uidKey.Decrypt(uidCipher); err != nil || got != id {
			t.Fatal("Go rejected Rust UID ciphertext")
		}
		params["ciphertext"] = goResult.ProfileCiphertext
		got = zkCall[zkDecryption](t, h, "zkgroup.decrypt_profile", params)
		if got.Verified != rust.ProfileDecrypts || (got.Verified && got.Plaintext != p.ProfileKey) {
			t.Fatal("Rust/Go profile decryption disagreement")
		}
		profileCipher, err := zkcrypto.ParseProfileKeyCiphertext(zkBytes(t, rust.ProfileCiphertext))
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := profileKey.Decrypt(profileCipher, uuid)
		if (err == nil) != got.Verified || (err == nil && hex.EncodeToString(decoded[:]) != p.ProfileKey) {
			t.Fatal("Go/Rust profile decryption disagreement")
		}

		// Binding to UUID and group key, with valid encodings throughout.
		wrongUUID := uuid
		wrongUUID[0] ^= 1
		params["uuid"] = hex.EncodeToString(wrongUUID[:])
		if zkCall[zkDecryption](t, h, "zkgroup.decrypt_profile", params).Verified {
			t.Fatal("Rust accepted wrong UUID")
		}
		if _, err := profileKey.Decrypt(profileCipher, wrongUUID); err == nil {
			t.Fatal("Go accepted wrong UUID")
		}
		params["uuid"] = p.UUID
		seed := zkBytes(t, p.Seed)
		seed[0] ^= 1
		params["seed"] = hex.EncodeToString(seed)
		wrongUIDKey, wrongProfileKey := zkKeys(t, hex.EncodeToString(seed))
		if zkCall[zkDecryption](t, h, "zkgroup.decrypt_profile", params).Verified {
			t.Fatal("Rust accepted wrong group key")
		}
		if _, err := wrongProfileKey.Decrypt(profileCipher, uuid); err == nil {
			t.Fatal("Go accepted wrong profile group key")
		}
		params["ciphertext"] = goResult.UIDCiphertext
		if zkCall[zkDecryption](t, h, "zkgroup.decrypt_uid", params).Verified {
			t.Fatal("Rust accepted wrong UID group key")
		}
		if _, err := wrongUIDKey.Decrypt(uidCipher); err == nil {
			t.Fatal("Go accepted wrong UID group key")
		}
	}
}

func TestZKGroupCryptoRejectsMalformed(t *testing.T) {
	h := newHarness(t)
	p := loadZK(t).Cases[9].Params
	uKey, pKey := zkKeys(t, p.Seed)
	uuid := [16]byte(zkBytes(t, p.UUID))
	for _, bad := range [][]byte{
		nil, make([]byte, 63), make([]byte, 65), bytes.Repeat([]byte{255}, 64), make([]byte, 64),
		append(ristretto255.NewGeneratorElement().Bytes(), make([]byte, 32)...),
		append(make([]byte, 32), ristretto255.NewGeneratorElement().Bytes()...),
	} {
		params := map[string]any{"seed": p.Seed, "uuid": p.UUID, "ciphertext": hex.EncodeToString(bad)}
		for _, method := range []string{"zkgroup.decrypt_uid", "zkgroup.decrypt_profile"} {
			if zkCall[zkDecryption](t, h, method, params).Verified {
				t.Fatal("Rust accepted bad ciphertext")
			}
		}
		if c, err := zkcrypto.ParseUIDCiphertext(bad); err == nil {
			if _, err := uKey.Decrypt(c); err == nil {
				t.Fatal("Go accepted bad UID ciphertext")
			}
		}
		if c, err := zkcrypto.ParseProfileKeyCiphertext(bad); err == nil {
			if _, err := pKey.Decrypt(c, uuid); err == nil {
				t.Fatal("Go accepted bad profile ciphertext")
			}
		}
	}
	for _, params := range []map[string]any{nil, {"seed": "00"}, {"seed": p.Seed, "uuid": "00"}} {
		if h.call("zkgroup.crypto", params).Ok {
			t.Fatal("Rust accepted malformed request")
		}
	}
	if !h.call("ping", nil).Ok {
		t.Fatal("harness failed after malformed input")
	}
}

func TestZKGroupInverseInterop(t *testing.T) {
	h := newHarness(t)
	for range 32 {
		var b [64]byte
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatal(err)
		}
		point, err := ristretto255.NewIdentityElement().SetUniformBytes(b[:])
		if err != nil {
			t.Fatal(err)
		}
		result := zkCall[zkResult](t, h, "zkgroup.inverse", map[string]any{"point": hex.EncodeToString(point.Bytes())})
		for i, c := range ristrettolizard.Inverse(point) {
			if (c.Valid == 1) != (result.Inverse[i] != nil) {
				t.Fatal("inverse validity mismatch")
			}
			if c.Valid == 1 && hex.EncodeToString(c.Bytes[:]) != *result.Inverse[i] {
				t.Fatal("inverse bytes mismatch")
			}
		}
	}
}

func TestZKGroupCryptoVectorRegeneration(t *testing.T) {
	bin := os.Getenv("COMPAT_HARNESS_BIN")
	if bin == "" {
		t.Skip("COMPAT_HARNESS_BIN unset")
	}
	want, err := os.ReadFile("vectors/zkgroup-crypto.json")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		got, err := exec.Command(bin, "gen-vectors", "zkgroup-crypto").Output() //nolint:gosec // G204: operator-supplied test harness, as in newHarness.
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("regenerated zkgroup vectors differ")
		}
	}
}
