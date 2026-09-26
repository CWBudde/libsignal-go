// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package zkgroup_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/internal/crypto/gcmsiv"
	"github.com/cwbudde/libsignal-go/internal/zkgroupserver"
	"github.com/cwbudde/libsignal-go/zkgroup"
	"os"
	"testing"
)

func check(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}

type serializable interface{ Bytes() []byte }

func parse[T serializable](fn func([]byte) (T, error)) func([]byte) ([]byte, error) {
	return func(b []byte) ([]byte, error) {
		v, e := fn(b)
		if e != nil {
			return nil, e
		}
		return v.Bytes(), nil
	}
}
func parsers() map[string]func([]byte) ([]byte, error) {
	return map[string]func([]byte) ([]byte, error){
		"server": parse(zkgroup.ParseServerPublicParams), "group": parse(zkgroup.ParseGroupSecretParams), "group_public": parse(zkgroup.ParseGroupPublicParams), "aci_ciphertext": parse(zkgroup.ParseUUIDCiphertext), "profile_ciphertext": parse(zkgroup.ParseProfileKeyCiphertext), "context": parse(zkgroup.ParseProfileKeyCredentialRequestContext), "request": parse(zkgroup.ParseProfileKeyCredentialRequest), "profile_response": parse(zkgroup.ParseExpiringProfileKeyCredentialResponse), "profile_credential": parse(zkgroup.ParseExpiringProfileKeyCredential), "profile_presentation": parse(zkgroup.ParseProfileKeyCredentialPresentation), "auth_response": parse(zkgroup.ParseAuthCredentialWithPniResponse), "auth_credential": parse(zkgroup.ParseAuthCredentialWithPni), "auth_presentation": parse(zkgroup.ParseAuthCredentialPresentation)}
}
func fixtures(t testing.TB) map[string][]byte {
	t.Helper()
	b, e := os.ReadFile("../compat/vectors/zkgroup-api.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Cases []struct {
			Result map[string]string `json:"result"`
		} `json:"cases"`
	}
	if e = json.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
	out := map[string][]byte{}
	for k, s := range v.Cases[0].Result {
		out[k], e = hex.DecodeString(s)
		if e != nil {
			t.Fatal(e)
		}
	}
	return out
}
func TestEncoding(t *testing.T) {
	f := fixtures(t)
	for name, parser := range parsers() {
		t.Run(name, func(t *testing.T) {
			b := f[name]
			out, e := parser(b)
			check(t, e)
			if !bytes.Equal(out, b) {
				t.Fatal("serialization changed")
			}
			for _, bad := range [][]byte{nil, {}, b[:len(b)-1], append(bytes.Clone(b), 0), bytes.Repeat([]byte{255}, len(b))} {
				if _, e = parser(bad); e == nil {
					t.Fatalf("accepted malformed encoding: %d", len(bad))
				}
			}
			bad := bytes.Clone(b)
			bad[0] = 255
			if _, e = parser(bad); e == nil {
				t.Fatal("accepted wrong version")
			}
		})
	}
	p := f["profile_presentation"]
	for _, v := range []byte{0, 1, 2, 3} {
		b := bytes.Clone(p)
		b[0] = v
		if v < 2 {
			b = b[:len(b)-8]
		}
		parsed, e := zkgroup.ParseProfileKeyCredentialPresentation(b)
		check(t, e)
		if !bytes.Equal(parsed.UUIDCiphertext().Bytes(), f["aci_ciphertext"]) {
			t.Fatal("legacy UID extraction")
		}
		if !bytes.Equal(parsed.ProfileKeyCiphertext().Bytes(), f["profile_ciphertext"]) {
			t.Fatal("legacy profile extraction")
		}
	}
}
func TestCredentialPolicies(t *testing.T) {
	s, e := zkgroupserver.Generate([32]byte{1})
	check(t, e)
	key := zkgroup.ProfileKey{4}
	aci, pni := [16]byte{2}, [16]byte{3}
	r := [32]byte{9}
	day := uint64(20000) * zkgroup.SecondsPerDay
	c, e := s.Public().CreateProfileKeyCredentialRequestContext(r, aci, key)
	check(t, e)
	for _, offset := range []uint64{0, 1, 86400 - 1, 86400, 7 * 86400, 8*86400 - 1, 8 * 86400} {
		expiration := day + offset
		response, e := s.IssueProfile(r, c.Request(), aci, key.Commitment(aci), expiration)
		check(t, e)
		_, e = s.Public().ReceiveExpiringProfileKeyCredential(c, response, day)
		want := offset == 86400 || offset == 7*86400
		if (e == nil) != want {
			t.Errorf("offset %d: %v", offset, e)
		}
	}
	// Integer-day truncation intentionally accepts 7 days plus a partial day.
	response, e := s.IssueProfile(r, c.Request(), aci, key.Commitment(aci), day+8*86400)
	check(t, e)
	_, e = s.Public().ReceiveExpiringProfileKeyCredential(c, response, day+1)
	check(t, e)
	_, e = s.IssueProfile(r, c.Request(), aci, zkgroup.ProfileKey{5}.Commitment(aci), day+86400)
	if e == nil {
		t.Fatal("accepted wrong commitment")
	}
	for _, redemption := range []uint64{day, day + 1, ^uint64(0)} {
		response, e := s.IssueAuth(r, aci, pni, redemption)
		check(t, e)
		_, e = s.Public().ReceiveAuthCredentialWithPni(aci, pni, redemption, response)
		if (e == nil) != (redemption == day) {
			t.Errorf("redemption %d: %v", redemption, e)
		}
	}
}
func TestGroupEncryption(t *testing.T) {
	g := zkgroup.GenerateGroupSecretParams([32]byte{})
	other := zkgroup.GenerateGroupSecretParams([32]byte{1})
	aci := [16]byte{2}
	for _, id := range []address.ServiceID{address.NewACI(aci), address.NewPNI(aci)} {
		c := g.EncryptServiceID(id)
		got, e := g.DecryptServiceID(c)
		check(t, e)
		if got != id {
			t.Fatal("identity kind lost")
		}
		if _, e = other.DecryptServiceID(c); e == nil {
			t.Fatal("wrong group key accepted")
		}
	}
	for _, padding := range []uint32{0, 8} {
		b, e := g.EncryptBlob([32]byte{}, []byte("secret team"), padding)
		check(t, e)
		p, e := g.DecryptBlob(b)
		check(t, e)
		if string(p) != "secret team" {
			t.Fatal("blob")
		}
		if _, e = other.DecryptBlob(b); e == nil {
			t.Fatal("wrong blob key accepted")
		}
		b[0] ^= 1
		if _, e = g.DecryptBlob(b); e == nil {
			t.Fatal("altered blob accepted")
		}
	}
}
func FuzzAPIEncoding(f *testing.F) {
	for _, b := range fixtures(f) {
		f.Add(b)
	}
	f.Add([]byte{})
	ps := parsers()
	g := zkgroup.GenerateGroupSecretParams([32]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, p := range ps {
			out, e := p(b)
			if e == nil && !bytes.Equal(out, b) {
				t.Fatal("noncanonical parse")
			}
		}
		_, _ = g.DecryptBlob(b)
	})
}

func TestBlobPaddingValidation(t *testing.T) {
	g := zkgroup.GenerateGroupSecretParams([32]byte{})
	blobKey := g.Bytes()[65:97]
	nonce := make([]byte, 12)
	for _, plaintext := range [][]byte{nil, {0, 0, 0}, {0, 0, 0, 1}, {255, 255, 255, 255}} {
		encrypted, e := gcmsiv.Seal(blobKey, nonce, plaintext, nil)
		check(t, e)
		blob := append(append(encrypted, nonce...), 0)
		if _, e = g.DecryptBlob(blob); e == nil {
			t.Fatal("accepted malformed authenticated padding")
		}
	}
	// Upstream ignores the reserved byte and does not require zero padding bytes.
	encrypted, e := gcmsiv.Seal(blobKey, nonce, []byte{0, 0, 0, 1, 'a', 99}, nil)
	check(t, e)
	blob := append(append(encrypted, nonce...), 255)
	plaintext, e := g.DecryptBlob(blob)
	check(t, e)
	if string(plaintext) != "a" {
		t.Fatal("upstream padding behavior changed")
	}
}
