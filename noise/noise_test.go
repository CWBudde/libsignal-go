// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package noise_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/cwbudde/libsignal-go/noise"
)

var patterns = []noise.Pattern{noise.NK, noise.NKhfs}

func staticKey(t testing.TB) (priv, pub []byte) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k.Bytes(), k.PublicKey().Bytes()
}

// handshake runs both messages and returns the two transports.
func handshake(t *testing.T, p noise.Pattern, payload0, payload1 []byte) (ti, tr *noise.Transport) {
	t.Helper()
	priv, pub := staticKey(t)
	i, err := noise.NewInitiator(p, pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := noise.NewResponder(p, priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	m0, err := i.WriteMessage(payload0)
	if err != nil {
		t.Fatal(err)
	}
	got0, err := r.ReadMessage(m0)
	if err != nil {
		t.Fatal(err)
	}
	m1, err := r.WriteMessage(payload1)
	if err != nil {
		t.Fatal(err)
	}
	got1, err := i.ReadMessage(m1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got0, payload0) || !bytes.Equal(got1, payload1) {
		t.Fatal("handshake payload mismatch")
	}
	if !i.Finished() || !r.Finished() {
		t.Fatal("handshake not finished")
	}
	if ti, err = i.Transport(); err != nil {
		t.Fatal(err)
	}
	if tr, err = r.Transport(); err != nil {
		t.Fatal(err)
	}
	return ti, tr
}

func TestPatternNames(t *testing.T) {
	if got := noise.NK.Name(); got != "Noise_NK_25519_ChaChaPoly_SHA256" {
		t.Errorf("NK = %q", got)
	}
	if got := noise.NKhfs.Name(); got != "Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256" {
		t.Errorf("NKhfs = %q", got)
	}
}

func TestHandshakeAndTransport(t *testing.T) {
	long := make([]byte, 2*noise.MaxPayloadSize+7)
	if _, err := rand.Read(long); err != nil {
		t.Fatal(err)
	}
	for _, p := range patterns {
		t.Run(p.Name(), func(t *testing.T) {
			ti, tr := handshake(t, p, []byte("hello"), []byte("enclave"))
			if !bytes.Equal(ti.HandshakeHash(), tr.HandshakeHash()) || len(ti.HandshakeHash()) != 32 {
				t.Fatal("handshake hash mismatch")
			}
			for _, msg := range [][]byte{nil, []byte("x"), long} {
				for _, dir := range [][2]*noise.Transport{{ti, tr}, {tr, ti}} {
					ct, err := dir[0].Send(msg)
					if err != nil {
						t.Fatal(err)
					}
					chunks := (len(msg) + noise.MaxPayloadSize - 1) / noise.MaxPayloadSize
					if len(ct) != len(msg)+chunks*noise.TagSize {
						t.Fatalf("ciphertext length %d for %d bytes", len(ct), len(msg))
					}
					pt, err := dir[1].Recv(ct)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(pt, msg) {
						t.Fatal("transport mismatch")
					}
				}
			}
		})
	}
}

// The sizes libsignal allocates for the initial request
// (NOISE_HANDSHAKE_OVERHEAD = 64 + 1568 for NKhfs).
func TestMessageSizes(t *testing.T) {
	for _, tc := range []struct {
		p    noise.Pattern
		size int
	}{{noise.NK, 48}, {noise.NKhfs, 1632}} {
		priv, pub := staticKey(t)
		i, _ := noise.NewInitiator(tc.p, pub, nil)
		r, _ := noise.NewResponder(tc.p, priv, nil)
		m0, err := i.WriteMessage(nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.ReadMessage(m0); err != nil {
			t.Fatal(err)
		}
		m1, err := r.WriteMessage(nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(m0) != tc.size || len(m1) != tc.size {
			t.Errorf("%s: sizes %d, %d; want %d", tc.p.Name(), len(m0), len(m1), tc.size)
		}
	}
}

func TestDeterministic(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32+64)
	_, pub := staticKey(t)
	for _, p := range patterns {
		var msgs [2][]byte
		for k := range msgs {
			i, err := noise.NewInitiator(p, pub, bytes.NewReader(seed))
			if err != nil {
				t.Fatal(err)
			}
			if msgs[k], err = i.WriteMessage([]byte("p")); err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(msgs[0], msgs[1]) {
			t.Errorf("%s: same randomness, different messages", p.Name())
		}
	}
}

func TestRandomnessFailure(t *testing.T) {
	_, pub := staticKey(t)
	i, _ := noise.NewInitiator(noise.NKhfs, pub, bytes.NewReader(make([]byte, 40))) // e, but not e1
	if _, err := i.WriteMessage(nil); !errors.Is(err, noise.ErrRandom) {
		t.Fatalf("err = %v", err)
	}
	if _, err := i.WriteMessage(nil); !errors.Is(err, noise.ErrFailed) {
		t.Fatalf("after failure: err = %v", err)
	}
}

func TestWrongStaticKey(t *testing.T) {
	for _, p := range patterns {
		_, pub := staticKey(t)
		other, _ := staticKey(t)
		i, _ := noise.NewInitiator(p, pub, nil)
		r, _ := noise.NewResponder(p, other, nil)
		m0, _ := i.WriteMessage(nil)
		if _, err := r.ReadMessage(m0); !errors.Is(err, noise.ErrDecrypt) {
			t.Errorf("%s: err = %v", p.Name(), err)
		}
	}
}

// Flipping any byte of either handshake message makes the reader fail, and
// a failed handshake stays failed.
func TestTamperedHandshake(t *testing.T) {
	for _, p := range patterns {
		priv, pub := staticKey(t)
		i, _ := noise.NewInitiator(p, pub, nil)
		m0, _ := i.WriteMessage([]byte("payload"))
		for _, pos := range []int{0, 31, 32, len(m0) - 17, len(m0) - 1} {
			bad := bytes.Clone(m0)
			bad[pos] ^= 1
			r, _ := noise.NewResponder(p, priv, nil)
			if _, err := r.ReadMessage(bad); err == nil {
				t.Errorf("%s: message 0 byte %d: accepted", p.Name(), pos)
			}
		}
		for _, pos := range []int{0, 32, 47, -1} {
			i, _ := noise.NewInitiator(p, pub, nil)
			r, _ := noise.NewResponder(p, priv, nil)
			m0, _ := i.WriteMessage(nil)
			if _, err := r.ReadMessage(m0); err != nil {
				t.Fatal(err)
			}
			m1, _ := r.WriteMessage(nil)
			if pos < 0 {
				pos = len(m1) - 1
			}
			bad := bytes.Clone(m1)
			bad[pos] ^= 0x80
			if _, err := i.ReadMessage(bad); err == nil {
				t.Errorf("%s: message 1 byte %d: accepted", p.Name(), pos)
			}
			if _, err := i.ReadMessage(m1); !errors.Is(err, noise.ErrFailed) {
				t.Errorf("%s: retry after failure: err = %v", p.Name(), err)
			}
			if _, err := i.Transport(); !errors.Is(err, noise.ErrFailed) {
				t.Errorf("%s: transport after failure: err = %v", p.Name(), err)
			}
		}
	}
}

func TestMessageBounds(t *testing.T) {
	for _, p := range patterns {
		priv, pub := staticKey(t)
		i, _ := noise.NewInitiator(p, pub, nil)
		if _, err := i.WriteMessage(make([]byte, noise.MaxMessageSize)); !errors.Is(err, noise.ErrMessageSize) {
			t.Errorf("%s: oversized payload: err = %v", p.Name(), err)
		}
		// A size error before any token is written leaves the state usable.
		m0, err := i.WriteMessage(nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, msg := range [][]byte{m0[:len(m0)-1], make([]byte, noise.MaxMessageSize+1)} {
			r, _ := noise.NewResponder(p, priv, nil)
			if _, err := r.ReadMessage(msg); !errors.Is(err, noise.ErrMessageSize) {
				t.Errorf("%s: %d-byte message: err = %v", p.Name(), len(msg), err)
			}
		}
	}
}

func TestTurns(t *testing.T) {
	priv, pub := staticKey(t)
	i, _ := noise.NewInitiator(noise.NK, pub, nil)
	r, _ := noise.NewResponder(noise.NK, priv, nil)
	if _, err := i.ReadMessage(make([]byte, 48)); !errors.Is(err, noise.ErrNotYourTurn) {
		t.Errorf("initiator read first: %v", err)
	}
	if _, err := r.WriteMessage(nil); !errors.Is(err, noise.ErrNotYourTurn) {
		t.Errorf("responder write first: %v", err)
	}
	if _, err := i.Transport(); !errors.Is(err, noise.ErrHandshakePending) {
		t.Errorf("early transport: %v", err)
	}
	m0, _ := i.WriteMessage(nil)
	if _, err := i.WriteMessage(nil); !errors.Is(err, noise.ErrNotYourTurn) {
		t.Errorf("initiator writes twice: %v", err)
	}
	if _, err := r.ReadMessage(m0); err != nil {
		t.Fatal(err)
	}
	m1, _ := r.WriteMessage(nil)
	if _, err := i.ReadMessage(m1); err != nil {
		t.Fatal(err)
	}
	if _, err := i.WriteMessage(nil); !errors.Is(err, noise.ErrHandshakeDone) {
		t.Errorf("write after finish: %v", err)
	}
	if _, err := i.Transport(); err != nil {
		t.Fatal(err)
	}
	if _, err := i.Transport(); !errors.Is(err, noise.ErrFailed) {
		t.Errorf("second transport: %v", err)
	}
}

func TestInvalidInputs(t *testing.T) {
	if _, err := noise.NewInitiator(0, make([]byte, 32), nil); !errors.Is(err, noise.ErrInvalidPattern) {
		t.Errorf("pattern 0: %v", err)
	}
	if _, err := noise.NewResponder(3, make([]byte, 32), nil); !errors.Is(err, noise.ErrInvalidPattern) {
		t.Errorf("pattern 3: %v", err)
	}
	if _, err := noise.NewInitiator(noise.NK, make([]byte, 31), nil); !errors.Is(err, noise.ErrInvalidKey) {
		t.Errorf("short public key: %v", err)
	}
	if _, err := noise.NewResponder(noise.NK, make([]byte, 33), nil); !errors.Is(err, noise.ErrInvalidKey) {
		t.Errorf("long private key: %v", err)
	}
	// A low-order responder key makes es all zero, which is rejected.
	i, _ := noise.NewInitiator(noise.NK, make([]byte, 32), nil)
	if _, err := i.WriteMessage(nil); !errors.Is(err, noise.ErrInvalidKey) {
		t.Errorf("low-order static key: %v", err)
	}
}

func TestTransportTampering(t *testing.T) {
	ti, tr := handshake(t, noise.NKhfs, nil, nil)
	ct, _ := ti.Send([]byte("secret"))
	bad := bytes.Clone(ct)
	bad[0] ^= 1
	if _, err := tr.Recv(bad); !errors.Is(err, noise.ErrDecrypt) {
		t.Fatalf("tampered: %v", err)
	}
	if _, err := tr.Recv(ct[:noise.TagSize-1]); !errors.Is(err, noise.ErrDecrypt) {
		t.Fatalf("short: %v", err)
	}
	// A failed Recv doesn't consume the nonce.
	if pt, err := tr.Recv(ct); err != nil || string(pt) != "secret" {
		t.Fatalf("after failures: %q, %v", pt, err)
	}
	// Replays fail: the nonce has moved on.
	if _, err := tr.Recv(ct); !errors.Is(err, noise.ErrDecrypt) {
		t.Fatalf("replay: %v", err)
	}
}

func FuzzReadMessage(f *testing.F) {
	priv, pub := staticKey(f)
	for _, p := range patterns {
		i, _ := noise.NewInitiator(p, pub, nil)
		m0, _ := i.WriteMessage([]byte("seed"))
		f.Add(uint8(p), m0)
	}
	f.Fuzz(func(t *testing.T, p uint8, msg []byte) {
		pat := noise.Pattern(p%2 + 1)
		r, err := noise.NewResponder(pat, priv, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = r.ReadMessage(msg)
		i, err := noise.NewInitiator(pat, pub, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := i.WriteMessage(nil); err != nil {
			t.Fatal(err)
		}
		_, _ = i.ReadMessage(msg)
	})
}
