// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package compat

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/cwbudde/libsignal-go/noise"
)

type noiseExchange struct {
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
}

type noiseCase struct {
	Pattern                string          `json:"pattern"`
	ResponderStaticPrivate string          `json:"responder_static_private"`
	ResponderStaticPublic  string          `json:"responder_static_public"`
	InitiatorRandom        string          `json:"initiator_random"`
	ResponderRandom        string          `json:"responder_random"`
	Payload0               string          `json:"payload0"`
	Payload1               string          `json:"payload1"`
	Message0               string          `json:"message0"`
	Message1               string          `json:"message1"`
	HandshakeHash          string          `json:"handshake_hash"`
	InitiatorToResponder   []noiseExchange `json:"initiator_to_responder"`
	ResponderToInitiator   []noiseExchange `json:"responder_to_initiator"`
}

func noisePattern(t *testing.T, name string) noise.Pattern {
	t.Helper()
	switch name {
	case "NK":
		return noise.NK
	case "NKhfs":
		return noise.NKhfs
	}
	t.Fatalf("unknown pattern %q", name)
	return 0
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestNoiseVectors replays snow's handshakes: the Go initiator, fed the
// randomness snow drew, reproduces message 0, reads message 1 and every
// transport message byte for byte. The Go responder reads message 0 and, for
// NK, reproduces message 1 as well; NKhfs's message 1 depends on randomized
// ML-KEM encapsulation, which the noise package's own known-answer test
// derandomizes.
func TestNoiseVectors(t *testing.T) {
	var batch struct {
		Snow  string      `json:"snow"`
		Cases []noiseCase `json:"cases"`
	}
	loadVectors(t, "noise", &batch)
	if batch.Snow != "0.10.0" || len(batch.Cases) == 0 {
		t.Fatalf("unexpected batch: snow %q, %d cases", batch.Snow, len(batch.Cases))
	}
	for i, c := range batch.Cases {
		t.Run(fmt.Sprintf("%s/%d", c.Pattern, i), func(t *testing.T) {
			p := noisePattern(t, c.Pattern)

			// Initiator.
			rnd := bytes.NewReader(unhex(t, c.InitiatorRandom))
			ini, err := noise.NewInitiator(p, unhex(t, c.ResponderStaticPublic), rnd)
			if err != nil {
				t.Fatal(err)
			}
			m0, err := ini.WriteMessage(unhex(t, c.Payload0))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(m0, unhex(t, c.Message0)) {
				t.Fatal("message 0 differs from snow")
			}
			if rnd.Len() != 0 {
				t.Fatalf("initiator left %d random bytes unused", rnd.Len())
			}
			p1, err := ini.ReadMessage(unhex(t, c.Message1))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(p1, unhex(t, c.Payload1)) {
				t.Fatal("payload 1 differs")
			}
			ti, err := ini.Transport()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ti.HandshakeHash(), unhex(t, c.HandshakeHash)) {
				t.Fatal("handshake hash differs")
			}
			for _, x := range c.InitiatorToResponder {
				ct, err := ti.Send(unhex(t, x.Plaintext))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(ct, unhex(t, x.Ciphertext)) {
					t.Fatal("initiator ciphertext differs")
				}
			}
			for _, x := range c.ResponderToInitiator {
				pt, err := ti.Recv(unhex(t, x.Ciphertext))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(pt, unhex(t, x.Plaintext)) {
					t.Fatal("initiator plaintext differs")
				}
			}

			// Responder.
			rnd = bytes.NewReader(unhex(t, c.ResponderRandom))
			res, err := noise.NewResponder(p, unhex(t, c.ResponderStaticPrivate), rnd)
			if err != nil {
				t.Fatal(err)
			}
			p0, err := res.ReadMessage(unhex(t, c.Message0))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(p0, unhex(t, c.Payload0)) {
				t.Fatal("payload 0 differs")
			}
			if p != noise.NK {
				return
			}
			m1, err := res.WriteMessage(unhex(t, c.Payload1))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(m1, unhex(t, c.Message1)) {
				t.Fatal("message 1 differs from snow")
			}
			tr, err := res.Transport()
			if err != nil {
				t.Fatal(err)
			}
			for _, x := range c.ResponderToInitiator {
				ct, err := tr.Send(unhex(t, x.Plaintext))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(ct, unhex(t, x.Ciphertext)) {
					t.Fatal("responder ciphertext differs")
				}
			}
		})
	}
}
