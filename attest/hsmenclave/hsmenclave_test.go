// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package hsmenclave_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"slices"
	"testing"

	"github.com/cwbudde/libsignal-go/attest/hsmenclave"
	"github.com/cwbudde/libsignal-go/noise"
)

func newKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func hashes(n int) [][]byte {
	hs := make([][]byte, n)
	for i := range hs {
		hs[i] = bytes.Repeat([]byte{byte(i + 1)}, hsmenclave.CodeHashSize)
	}
	return hs
}

func wantErr(t *testing.T, err error, targets ...error) {
	t.Helper()
	for _, target := range targets {
		if !errors.Is(err, target) {
			t.Fatalf("err = %v, want %v", err, target)
		}
	}
}

// server is the HSM side: it reads the client's initial request, checks
// that it carries the trusted code hashes, and answers with codeHash.
func server(t *testing.T, key *ecdh.PrivateKey, initial, wantHashes, codeHash []byte) ([]byte, *noise.Transport) {
	t.Helper()
	hs, err := noise.NewResponder(noise.NK, key.Bytes(), nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := hs.ReadMessage(initial)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, wantHashes) {
		t.Fatalf("initial request payload = %x, want the code hashes %x", payload, wantHashes)
	}
	reply, err := hs.WriteMessage(codeHash)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := hs.Transport()
	if err != nil {
		t.Fatal(err)
	}
	return reply, tr
}

// TestClient covers the bridge's HsmEnclaveClient from the initial request
// to messages both ways, with each trusted hash as the server's.
func TestClient(t *testing.T) {
	key := newKey(t)
	trusted := slices.Concat(hashes(3)...)
	for i, codeHash := range hashes(3) {
		c, err := hsmenclave.NewClient(key.PublicKey().Bytes(), trusted)
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.EstablishedSend([]byte{1})
		wantErr(t, err, hsmenclave.ErrInvalidState)
		_, err = c.EstablishedRecv([]byte{1})
		wantErr(t, err, hsmenclave.ErrInvalidState)

		initial, err := c.InitialRequest()
		if err != nil {
			t.Fatal(err)
		}
		// e, then the encrypted hashes and their tag.
		if want := 32 + len(trusted) + 16; len(initial) != want {
			t.Fatalf("initial request is %d bytes, want %d", len(initial), want)
		}
		reply, srv := server(t, key, initial, trusted, codeHash)
		if err := c.CompleteHandshake(reply); err != nil {
			t.Fatalf("hash %d: %v", i, err)
		}

		_, err = c.InitialRequest()
		wantErr(t, err, hsmenclave.ErrInvalidState)
		wantErr(t, c.CompleteHandshake(reply), hsmenclave.ErrInvalidState)

		// Long enough to take two Noise messages.
		long := bytes.Repeat([]byte("hsm!"), noise.MaxPayloadSize/2)
		ct, err := c.EstablishedSend(long)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := srv.Recv(ct); err != nil || !bytes.Equal(got, long) {
			t.Fatalf("server received %d bytes, %v", len(got), err)
		}
		ct, err = srv.Send([]byte("reply"))
		if err != nil {
			t.Fatal(err)
		}
		if got, err := c.EstablishedRecv(ct); err != nil || string(got) != "reply" {
			t.Fatalf("client received %q, %v", got, err)
		}
		_, err = c.EstablishedRecv(ct) // replayed: wrong nonce
		wantErr(t, err, hsmenclave.ErrCommunication, noise.ErrDecrypt)
	}
}

// TestClientRejectsCodeHash checks hsm_enclave.rs complete: the server's
// payload must be exactly one trusted code hash. Upstream reads it into a
// 32-byte buffer, so a longer one fails in snow as a decryption error.
func TestClientRejectsCodeHash(t *testing.T) {
	key := newKey(t)
	trusted := slices.Concat(hashes(2)...)
	for _, tc := range []struct {
		name    string
		payload []byte
		wantErr []error
	}{
		{"untrusted", bytes.Repeat([]byte{9}, 32), []error{hsmenclave.ErrTrustedCode}},
		{"empty", nil, []error{hsmenclave.ErrTrustedCode}},
		{"short", hashes(1)[0][:31], []error{hsmenclave.ErrTrustedCode}},
		{"long", append(bytes.Clone(hashes(1)[0]), 0), []error{hsmenclave.ErrHandshake, noise.ErrDecrypt}},
		{"two hashes", trusted, []error{hsmenclave.ErrHandshake, noise.ErrDecrypt}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := hsmenclave.NewClient(key.PublicKey().Bytes(), trusted)
			if err != nil {
				t.Fatal(err)
			}
			initial, err := c.InitialRequest()
			if err != nil {
				t.Fatal(err)
			}
			reply, _ := server(t, key, initial, trusted, tc.payload)
			wantErr(t, c.CompleteHandshake(reply), tc.wantErr...)
			_, err = c.EstablishedSend([]byte{1})
			wantErr(t, err, hsmenclave.ErrInvalidState)
			wantErr(t, c.CompleteHandshake(reply), hsmenclave.ErrInvalidState)
		})
	}
}

// TestClientFailedHandshake checks replies that are not a Noise message for
// this handshake. Each leaves the client unusable, as the bridge does.
func TestClientFailedHandshake(t *testing.T) {
	key := newKey(t)
	trusted := hashes(1)[0]
	c, err := hsmenclave.NewClient(key.PublicKey().Bytes(), trusted)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := c.InitialRequest()
	if err != nil {
		t.Fatal(err)
	}
	good, _ := server(t, key, initial, trusted, trusted)

	tampered := bytes.Clone(good)
	tampered[len(tampered)-1] ^= 1
	for _, tc := range []struct {
		name  string
		reply []byte
	}{
		{"empty", nil},
		{"truncated", good[:len(good)-1]},
		{"tampered", tampered},
		{"garbage", bytes.Repeat([]byte{0x42}, len(good))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := hsmenclave.NewClient(key.PublicKey().Bytes(), trusted)
			if err != nil {
				t.Fatal(err)
			}
			wantErr(t, c.CompleteHandshake(tc.reply), hsmenclave.ErrHandshake)
			wantErr(t, c.CompleteHandshake(good), hsmenclave.ErrInvalidState)
			_, err = c.InitialRequest()
			wantErr(t, err, hsmenclave.ErrInvalidState)
		})
	}
}

// TestClientWrongServerKey checks that a server without the trusted key
// cannot read the initial request.
func TestClientWrongServerKey(t *testing.T) {
	c, err := hsmenclave.NewClient(newKey(t).PublicKey().Bytes(), hashes(1)[0])
	if err != nil {
		t.Fatal(err)
	}
	initial, err := c.InitialRequest()
	if err != nil {
		t.Fatal(err)
	}
	hs, err := noise.NewResponder(noise.NK, newKey(t).Bytes(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hs.ReadMessage(initial); !errors.Is(err, noise.ErrDecrypt) {
		t.Fatalf("err = %v, want %v", err, noise.ErrDecrypt)
	}
}

// TestNewClientInputs checks the bridge's HsmEnclaveClient::new checks.
func TestNewClientInputs(t *testing.T) {
	pub := newKey(t).PublicKey().Bytes()
	hash := hashes(1)[0]
	for _, tc := range []struct {
		name         string
		pub, hashes  []byte
		wantErr      error
		wantPayloads int
	}{
		{"short key", pub[:31], hash, hsmenclave.ErrInvalidPublicKey, 0},
		{"long key", append(bytes.Clone(pub), 0), hash, hsmenclave.ErrInvalidPublicKey, 0},
		{"no key", nil, hash, hsmenclave.ErrInvalidPublicKey, 0},
		{"no hashes", pub, nil, hsmenclave.ErrInvalidCodeHash, 0},
		{"partial hash", pub, hash[:31], hsmenclave.ErrInvalidCodeHash, 0},
		{"hash and a byte", pub, append(bytes.Clone(hash), 0), hsmenclave.ErrInvalidCodeHash, 0},
		{"one hash", pub, hash, nil, 1},
		{"four hashes", pub, slices.Concat(hashes(4)...), nil, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := hsmenclave.NewClient(tc.pub, tc.hashes)
			if tc.wantErr != nil {
				wantErr(t, err, tc.wantErr)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			initial, err := c.InitialRequest()
			if err != nil {
				t.Fatal(err)
			}
			if want := 48 + tc.wantPayloads*hsmenclave.CodeHashSize; len(initial) != want {
				t.Fatalf("initial request is %d bytes, want %d", len(initial), want)
			}
		})
	}
}

// TestNewClientCopiesInputs checks that later changes to the caller's
// slices do not change the trusted hashes.
func TestNewClientCopiesInputs(t *testing.T) {
	key := newKey(t)
	trusted := hashes(1)[0]
	c, err := hsmenclave.NewClient(key.PublicKey().Bytes(), trusted)
	if err != nil {
		t.Fatal(err)
	}
	orig := bytes.Clone(trusted)
	initial, err := c.InitialRequest()
	if err != nil {
		t.Fatal(err)
	}
	initial[0] ^= 1 // the returned request is a copy too
	trusted[0] ^= 1
	initial, err = c.InitialRequest()
	if err != nil {
		t.Fatal(err)
	}
	reply, _ := server(t, key, initial, orig, orig)
	if err := c.CompleteHandshake(reply); err != nil {
		t.Fatal(err)
	}
}
