// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package noise_test

import (
	"bytes"
	"crypto/ecdh"
	"testing"

	"github.com/cwbudde/libsignal-go/noise"
)

// constReader returns the same byte forever, so ephemeral keys, and with them
// the whole handshake, are reproducible.
type constReader byte

func (r constReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}

// fixedStatic is the responder's static X25519 key pair for the Transport
// fuzzer; any 32 bytes are a valid X25519 private key.
var fixedStatic = bytes.Repeat([]byte{0x42}, 32)

// deterministicTransports runs an NK handshake with fixed keys and returns the
// initiator's and responder's transports. The same call always yields the
// same channel keys, so ciphertexts from one call decrypt in another.
func deterministicTransports(t testing.TB) (ti, tr *noise.Transport) {
	t.Helper()
	r, err := noise.NewResponder(noise.NK, fixedStatic, constReader(0x07))
	if err != nil {
		t.Fatal(err)
	}
	k, err := ecdh.X25519().NewPrivateKey(fixedStatic)
	if err != nil {
		t.Fatal(err)
	}
	pub := k.PublicKey().Bytes()
	i, err := noise.NewInitiator(noise.NK, pub, constReader(0x09))
	if err != nil {
		t.Fatal(err)
	}
	m0, err := i.WriteMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.ReadMessage(m0); err != nil {
		t.Fatal(err)
	}
	m1, err := r.WriteMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = i.ReadMessage(m1); err != nil {
		t.Fatal(err)
	}
	if ti, err = i.Transport(); err != nil {
		t.Fatal(err)
	}
	if tr, err = r.Transport(); err != nil {
		t.Fatal(err)
	}
	return ti, tr
}

// FuzzTransportRecv decrypts arbitrary bytes on a fresh established channel.
// It must never panic, and whatever decrypts must be exactly what the peer's
// Send produces for that plaintext (Send and Recv split the same way).
func FuzzTransportRecv(f *testing.F) {
	for _, pt := range [][]byte{[]byte("hello enclave"), {}, bytes.Repeat([]byte{1}, noise.MaxPayloadSize+10)} {
		ti, _ := deterministicTransports(f)
		ct, err := ti.Send(pt)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(ct)
		// The seeds must decrypt on a fresh channel, or determinism broke.
		if _, tr := deterministicTransports(f); len(ct) > 0 {
			if _, err := tr.Recv(ct); err != nil {
				f.Fatalf("seed does not decrypt on a fresh channel: %v", err)
			}
		}
	}
	f.Add(make([]byte, noise.TagSize))

	f.Fuzz(func(t *testing.T, ct []byte) {
		ti, tr := deterministicTransports(t)
		pt, err := tr.Recv(ct)
		if err != nil {
			return
		}
		again, err := ti.Send(pt)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(again, ct) {
			t.Fatal("decrypted message does not re-encrypt to its ciphertext")
		}
	})
}

// FuzzHandshakeKeys starts handshakes with arbitrary static keys, as a client
// does with an enclave key taken from attestation claims. Neither constructor
// may panic.
func FuzzHandshakeKeys(f *testing.F) {
	f.Add(uint8(noise.NK), fixedStatic)
	f.Add(uint8(noise.NKhfs), fixedStatic)
	f.Add(uint8(noise.NKhfs), make([]byte, 31))
	f.Add(uint8(0), []byte{})

	f.Fuzz(func(_ *testing.T, p uint8, key []byte) {
		if i, err := noise.NewInitiator(noise.Pattern(p), key, constReader(1)); err == nil {
			_, _ = i.WriteMessage(nil)
		}
		if r, err := noise.NewResponder(noise.Pattern(p), key, constReader(2)); err == nil {
			_, _ = r.ReadMessage(key)
		}
	})
}
