// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package curve

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// FuzzKeyPairFromPublicAndPrivate parses arbitrary bytes as a stored key pair
// (wire-form public key plus raw private key) and as a raw 32-byte public key.
// Nothing may panic, and accepted keys must re-serialize to what parses back
// to the same keys.
func FuzzKeyPairFromPublicAndPrivate(f *testing.F) {
	kp, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(kp.PublicKey.Serialize(), kp.PrivateKey.Serialize())
	f.Add(kp.PublicKey.Serialize()[1:], []byte{})
	f.Add([]byte{0x05}, bytes.Repeat([]byte{0xFF}, PrivateKeyLength))
	f.Add([]byte{}, []byte{})

	f.Fuzz(func(t *testing.T, pub, priv []byte) {
		if pk, err := NewPublicKey(pub); err == nil {
			if !bytes.Equal(pk.Serialize()[1:], pub) {
				t.Fatal("raw public key does not round-trip")
			}
		}
		pair, err := KeyPairFromPublicAndPrivate(pub, priv)
		if err != nil {
			return
		}
		again, err := KeyPairFromPublicAndPrivate(pair.PublicKey.Serialize(), pair.PrivateKey.Serialize())
		if err != nil {
			t.Fatalf("re-parse: %v", err)
		}
		if !again.PublicKey.Equal(pair.PublicKey) || !bytes.Equal(again.PrivateKey.Serialize(), pair.PrivateKey.Serialize()) {
			t.Fatal("key pair changed in the round trip")
		}
	})
}
