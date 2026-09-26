// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package zkcrypto_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/poksho"
	"github.com/cwbudde/libsignal-go/zkgroup/zkcrypto"
	"github.com/gtank/ristretto255"
)

func keys(seed byte) (zkcrypto.UIDKeyPair, zkcrypto.ProfileKeyKeyPair) {
	s := poksho.NewShoHmacSha256([]byte("Test_Phase82"))
	s.AbsorbAndRatchet([]byte{seed})
	return zkcrypto.DeriveUIDKeyPair(s), zkcrypto.DeriveProfileKeyKeyPair(s)
}

func TestEncryption(t *testing.T) {
	uKey, pKey := keys(0)
	wrongUIDKey, wrongProfileKey := keys(1)
	for i := range 64 {
		key := sha256.Sum256([]byte{byte(i)})
		uuid := [16]byte(key[:16])
		aci, pni := address.NewACI(uuid), address.NewPNI(uuid)
		u, p := zkcrypto.NewUID(aci), zkcrypto.NewUID(pni)
		up, pp := u.Points(), p.Points()
		if up[0].Equal(pp[0]) == 1 || up[1].Equal(pp[1]) != 1 {
			t.Fatal("service-ID kind domain separation")
		}
		up[0].Set(ristretto255.NewIdentityElement())
		if bytes.Equal(u.Bytes()[16:48], make([]byte, 32)) {
			t.Fatal("point accessor aliases UID")
		}
		for _, id := range []address.ServiceID{aci, pni} {
			ct := uKey.Encrypt(zkcrypto.NewUID(id))
			got, err := uKey.Decrypt(ct)
			if err != nil || got != id {
				t.Fatalf("UID roundtrip: %v %v", got, err)
			}
			if _, err := wrongUIDKey.Decrypt(ct); !errors.Is(err, zkcrypto.ErrVerification) {
				t.Fatal("wrong UID key accepted")
			}
		}
		attribute := zkcrypto.NewProfileKey(key, uuid)
		points := attribute.Points()
		points[0].Set(ristretto255.NewIdentityElement())
		if bytes.Equal(attribute.Bytes()[32:64], make([]byte, 32)) {
			t.Fatal("point accessor aliases profile")
		}
		ct := pKey.Encrypt(attribute)
		got, err := pKey.Decrypt(ct, uuid)
		if err != nil || got != key {
			t.Fatalf("profile roundtrip: %x %v", got, err)
		}
		if _, err := wrongProfileKey.Decrypt(ct, uuid); !errors.Is(err, zkcrypto.ErrVerification) {
			t.Fatal("wrong profile key accepted")
		}
		uuid[0] ^= 1
		if _, err := pKey.Decrypt(ct, uuid); !errors.Is(err, zkcrypto.ErrVerification) {
			t.Fatal("wrong UUID accepted")
		}
	}
}

func TestRejectInvalidCiphertexts(t *testing.T) {
	uKey, pKey := keys(0)
	for _, b := range [][]byte{
		make([]byte, 64),
		append(ristretto255.NewGeneratorElement().Bytes(), make([]byte, 32)...),
		append(make([]byte, 32), ristretto255.NewGeneratorElement().Bytes()...),
	} {
		u, err := zkcrypto.ParseUIDCiphertext(b)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := uKey.Decrypt(u); !errors.Is(err, zkcrypto.ErrVerification) {
			t.Fatal("invalid UID accepted")
		}
		p, err := zkcrypto.ParseProfileKeyCiphertext(b)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pKey.Decrypt(p, [16]byte{}); !errors.Is(err, zkcrypto.ErrVerification) {
			t.Fatal("invalid profile accepted")
		}
	}
}

func TestProfileKeyIdentityEncoding(t *testing.T) {
	_, k := keys(0)
	// The pinned upstream rejects profile keys whose masked map is the identity:
	// the inverse has duplicate valid candidates and decryption requires exactly
	// one matching candidate. Preserve this edge behavior, including all-zero.
	for bits := byte(0); bits < 8; bits++ {
		var key [32]byte
		key[0] = (bits >> 2) & 1
		key[31] = ((bits>>1)&1)<<7 | (bits&1)<<6
		ct := k.Encrypt(zkcrypto.NewProfileKey(key, [16]byte{}))
		if _, err := k.Decrypt(ct, [16]byte{}); !errors.Is(err, zkcrypto.ErrVerification) {
			t.Fatal("accepted ambiguous identity encoding")
		}
	}
}

type encoding interface{ Bytes() []byte }
type codec struct {
	name          string
	value         encoding
	parse         func([]byte) (encoding, error)
	scalarOffsets []int
}

func adapter[T encoding](parse func([]byte) (T, error)) func([]byte) (encoding, error) {
	return func(b []byte) (encoding, error) { return parse(b) }
}

func codecs() []codec {
	u, p := keys(0)
	uuid := [16]byte{1}
	uid := zkcrypto.NewUID(address.NewPNI(uuid))
	key := sha256.Sum256([]byte("test"))
	profile := zkcrypto.NewProfileKey(key, uuid)
	c := zkcrypto.NewProfileKeyCommitment(key, uuid)
	return []codec{
		{"uid", uid, adapter(zkcrypto.ParseUID), nil},
		{"profile", profile, adapter(zkcrypto.ParseProfileKey), nil},
		{"uid-key", u, adapter(zkcrypto.ParseUIDKeyPair), []int{0, 32}},
		{"profile-key", p, adapter(zkcrypto.ParseProfileKeyKeyPair), []int{0, 32}},
		{"uid-ciphertext", u.Encrypt(uid), adapter(zkcrypto.ParseUIDCiphertext), nil},
		{"profile-ciphertext", p.Encrypt(profile), adapter(zkcrypto.ParseProfileKeyCiphertext), nil},
		{"commitment", c.Public(), adapter(zkcrypto.ParseProfileKeyCommitment), nil},
		{"commitment-with-nonce", c, adapter(zkcrypto.ParseProfileKeyCommitmentWithNonce), []int{96}},
	}
}

func TestEncodings(t *testing.T) {
	for _, c := range codecs() {
		t.Run(c.name, func(t *testing.T) {
			b := c.value.Bytes()
			parsed, err := c.parse(b)
			if err != nil || !bytes.Equal(parsed.Bytes(), b) {
				t.Fatalf("roundtrip: %v", err)
			}
			b[0] ^= 1
			if bytes.Equal(parsed.Bytes(), b) || bytes.Equal(c.value.Bytes(), b) {
				t.Fatal("serialization aliases storage")
			}
			b = c.value.Bytes()
			for _, bad := range [][]byte{nil, b[:len(b)-1], append(bytes.Clone(b), 0), bytes.Repeat([]byte{255}, len(b))} {
				if _, err := c.parse(bad); !errors.Is(err, zkcrypto.ErrEncoding) {
					t.Fatalf("accepted malformed encoding of size %d", len(bad))
				}
			}
			for _, offset := range c.scalarOffsets {
				bad := bytes.Clone(b)
				// The group order is not a canonical scalar.
				copy(bad[offset:offset+32], []byte{237, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16})
				if _, err := c.parse(bad); !errors.Is(err, zkcrypto.ErrEncoding) {
					t.Fatal("accepted noncanonical scalar")
				}
			}
		})
	}
	u, p := keys(0)
	if !bytes.Equal(u.PublicKeyBytes(), u.Bytes()[64:]) || !bytes.Equal(p.PublicKeyBytes(), p.Bytes()[64:]) {
		t.Fatal("public key bytes")
	}
	c := zkcrypto.NewProfileKeyCommitment([32]byte{1}, [16]byte{2})
	want := c.Bytes()
	c.Nonce().Set(ristretto255.NewScalar())
	if !bytes.Equal(c.Bytes(), want) {
		t.Fatal("nonce accessor aliases secret")
	}
}

func FuzzEncodings(f *testing.F) {
	cs := codecs()
	for _, c := range cs {
		f.Add(c.value.Bytes())
	}
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, c := range cs {
			if value, err := c.parse(b); err == nil && !bytes.Equal(value.Bytes(), b) {
				t.Fatal("noncanonical roundtrip")
			}
		}
	})
}
