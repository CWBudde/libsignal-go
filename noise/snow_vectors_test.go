// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package noise_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/cwbudde/libsignal-go/noise"
)

// TestSnowResponderKAT checks the responder side of compat/vectors/noise.json
// byte for byte, including NKhfs, whose ekem1 needs the derandomized
// encapsulation hook. compat's TestNoiseVectors covers the initiator.
func TestSnowResponderKAT(t *testing.T) {
	data, err := os.ReadFile("../compat/vectors/noise.json")
	if err != nil {
		t.Fatal(err)
	}
	var batch struct {
		Cases []struct {
			Pattern                string `json:"pattern"`
			ResponderStaticPrivate string `json:"responder_static_private"`
			ResponderRandom        string `json:"responder_random"`
			Message0               string `json:"message0"`
			Payload1               string `json:"payload1"`
			Message1               string `json:"message1"`
			HandshakeHash          string `json:"handshake_hash"`
			ResponderToInitiator   []struct {
				Plaintext  string `json:"plaintext"`
				Ciphertext string `json:"ciphertext"`
			} `json:"responder_to_initiator"`
			InitiatorToResponder []struct {
				Plaintext  string `json:"plaintext"`
				Ciphertext string `json:"ciphertext"`
			} `json:"initiator_to_responder"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &batch); err != nil {
		t.Fatal(err)
	}
	unhex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	hfs := 0
	for _, c := range batch.Cases {
		p := noise.NK
		if c.Pattern == "NKhfs" {
			p = noise.NKhfs
			hfs++
		}
		rnd := bytes.NewReader(unhex(c.ResponderRandom))
		r, err := noise.NewResponder(p, unhex(c.ResponderStaticPrivate), rnd)
		if err != nil {
			t.Fatal(err)
		}
		noise.Derandomize(r)
		if _, err := r.ReadMessage(unhex(c.Message0)); err != nil {
			t.Fatal(err)
		}
		m1, err := r.WriteMessage(unhex(c.Payload1))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(m1, unhex(c.Message1)) {
			t.Fatalf("%s: message 1 differs from snow", c.Pattern)
		}
		if rnd.Len() != 0 {
			t.Fatalf("%s: %d random bytes unused", c.Pattern, rnd.Len())
		}
		tr, err := r.Transport()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(tr.HandshakeHash(), unhex(c.HandshakeHash)) {
			t.Fatalf("%s: handshake hash differs", c.Pattern)
		}
		for _, x := range c.InitiatorToResponder {
			pt, err := tr.Recv(unhex(x.Ciphertext))
			if err != nil || !bytes.Equal(pt, unhex(x.Plaintext)) {
				t.Fatalf("%s: recv: %v", c.Pattern, err)
			}
		}
		for _, x := range c.ResponderToInitiator {
			ct, err := tr.Send(unhex(x.Plaintext))
			if err != nil || !bytes.Equal(ct, unhex(x.Ciphertext)) {
				t.Fatalf("%s: send differs: %v", c.Pattern, err)
			}
		}
	}
	if hfs == 0 {
		t.Fatal("no NKhfs cases")
	}
}
