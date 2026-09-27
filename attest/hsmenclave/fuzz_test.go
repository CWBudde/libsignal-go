// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package hsmenclave_test

import (
	"bytes"
	"crypto/ecdh"
	"testing"

	"github.com/cwbudde/libsignal-go/attest/hsmenclave"
	"github.com/cwbudde/libsignal-go/noise"
)

// hsmKey is the HSM's static key for the fuzzers; any 32 bytes are a valid
// X25519 private key, so no key generation runs per input.
var hsmKey = bytes.Repeat([]byte{0x31}, 32)

func hsmPublic(t testing.TB) []byte {
	t.Helper()
	k, err := ecdh.X25519().NewPrivateKey(hsmKey)
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().Bytes()
}

// FuzzNewClient starts a client from arbitrary trusted key and code hash
// bytes. It must never panic, and an accepted client must offer an initial
// request.
func FuzzNewClient(f *testing.F) {
	f.Add(hsmPublic(f), bytes.Repeat([]byte{1}, hsmenclave.CodeHashSize))
	f.Add(hsmPublic(f), bytes.Repeat([]byte{1}, 2*hsmenclave.CodeHashSize+1))
	f.Add([]byte{}, []byte{})

	f.Fuzz(func(t *testing.T, pub, hashes []byte) {
		c, err := hsmenclave.NewClient(pub, hashes)
		if err != nil {
			return
		}
		if _, err := c.InitialRequest(); err != nil {
			t.Fatal(err)
		}
	})
}

// FuzzCompleteHandshake answers a fresh client's handshake with arbitrary
// bytes. Nothing may panic, and a failed handshake must leave the client
// unusable.
func FuzzCompleteHandshake(f *testing.F) {
	f.Add(make([]byte, 32+noise.TagSize))
	f.Add(make([]byte, 32+hsmenclave.CodeHashSize+noise.TagSize))
	f.Add([]byte{})
	pub := hsmPublic(f)
	trusted := bytes.Repeat([]byte{1}, hsmenclave.CodeHashSize)

	f.Fuzz(func(t *testing.T, reply []byte) {
		c, err := hsmenclave.NewClient(pub, trusted)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.CompleteHandshake(reply); err != nil {
			if _, err := c.EstablishedRecv(reply); err == nil {
				t.Fatal("client usable after a failed handshake")
			}
		}
	})
}

// FuzzEstablishedRecv decrypts arbitrary bytes on a freshly established HSM
// channel. It must never panic.
func FuzzEstablishedRecv(f *testing.F) {
	f.Add(make([]byte, noise.TagSize))
	f.Add(make([]byte, 64))
	f.Add([]byte{})
	pub := hsmPublic(f)
	trusted := bytes.Repeat([]byte{1}, hsmenclave.CodeHashSize)

	f.Fuzz(func(t *testing.T, ct []byte) {
		c, err := hsmenclave.NewClient(pub, trusted)
		if err != nil {
			t.Fatal(err)
		}
		initial, err := c.InitialRequest()
		if err != nil {
			t.Fatal(err)
		}
		hs, err := noise.NewResponder(noise.NK, hsmKey, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := hs.ReadMessage(initial); err != nil {
			t.Fatal(err)
		}
		reply, err := hs.WriteMessage(trusted)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.CompleteHandshake(reply); err != nil {
			t.Fatal(err)
		}
		_, _ = c.EstablishedRecv(ct)
	})
}
