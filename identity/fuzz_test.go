// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package identity_test

import (
	"bytes"
	cryptorand "crypto/rand"
	"testing"

	"github.com/cwbudde/libsignal-go/curve"
	"github.com/cwbudde/libsignal-go/identity"
)

func fuzzKeyPair(f *testing.F) curve.KeyPair {
	f.Helper()
	kp, err := curve.GenerateKeyPair(cryptorand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	return kp
}

// FuzzDeserializeKeyPair parses arbitrary bytes as a stored identity key pair.
// It must never panic, and an accepted pair must survive a serialize/parse
// round trip unchanged. (The protobuf encoding itself is not canonical, and a
// public key may carry trailing bytes, so the input bytes are not compared.)
func FuzzDeserializeKeyPair(f *testing.F) {
	f.Add(identity.SerializeKeyPair(fuzzKeyPair(f)))
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0x01, 0x05})
	f.Add([]byte{0x0a, 0x21, 0x05})

	f.Fuzz(func(t *testing.T, b []byte) {
		kp, err := identity.DeserializeKeyPair(b)
		if err != nil {
			return
		}
		back, err := identity.DeserializeKeyPair(identity.SerializeKeyPair(kp))
		if err != nil {
			t.Fatalf("re-parse: %v", err)
		}
		if !back.PublicKey.Equal(kp.PublicKey) || !bytes.Equal(back.PrivateKey.Serialize(), kp.PrivateKey.Serialize()) {
			t.Fatal("key pair changed in the round trip")
		}
	})
}

// FuzzVerifyAlternateIdentity checks that verifying an arbitrary signature over
// a PNI identity key never panics, and that only the real signature verifies.
func FuzzVerifyAlternateIdentity(f *testing.F) {
	aci, pni := fuzzKeyPair(f), fuzzKeyPair(f)
	sig, err := identity.SignAlternateIdentity(aci.PrivateKey, pni.PublicKey, cryptorand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sig)
	f.Add([]byte{})
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, s []byte) {
		if identity.VerifyAlternateIdentity(aci.PublicKey, pni.PublicKey, s) && !bytes.Equal(s, sig) {
			// XEdDSA signatures are randomized, but a second valid one for
			// the same message from a fuzzer would be a forgery.
			t.Fatalf("forged alternate-identity signature %x", s)
		}
	})
}
