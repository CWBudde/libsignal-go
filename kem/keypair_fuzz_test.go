// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package kem

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// FuzzKeyPairFromPublicAndSecret parses arbitrary bytes as a stored KEM key
// pair (wire-form public and secret keys, whose types must match). Nothing may
// panic, and an accepted pair must re-serialize to what parses back to it.
func FuzzKeyPairFromPublicAndSecret(f *testing.F) {
	kp, err := GenerateKeyPair(KeyTypeKyber1024, rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(kp.PublicKey.Serialize(), kp.SecretKey.Serialize())
	f.Add(kp.PublicKey.Serialize(), []byte{byte(KeyTypeMLKEM1024)})
	f.Add([]byte{byte(KeyTypeKyber1024)}, kp.SecretKey.Serialize())
	f.Add([]byte{}, []byte{})

	f.Fuzz(func(t *testing.T, pub, sec []byte) {
		pair, err := KeyPairFromPublicAndSecret(pub, sec)
		if err != nil {
			return
		}
		again, err := KeyPairFromPublicAndSecret(pair.PublicKey.Serialize(), pair.SecretKey.Serialize())
		if err != nil {
			t.Fatalf("re-parse: %v", err)
		}
		if !again.PublicKey.Equal(pair.PublicKey) || !bytes.Equal(again.SecretKey.Serialize(), pair.SecretKey.Serialize()) {
			t.Fatal("key pair changed in the round trip")
		}
	})
}
