// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package enclave_test

import (
	"bytes"
	"testing"

	"github.com/cwbudde/libsignal-go/attest/enclave"
	"github.com/cwbudde/libsignal-go/noise"
)

// FuzzCDS2Handshake parses arbitrary bytes as a CDSI attestation message (a
// ClientHandshakeStart protobuf) and attests it against the recorded enclave
// and time. Nothing may panic, and the recorded message must still attest.
func FuzzCDS2Handshake(f *testing.F) {
	c := loadCDSI(f)
	f.Add(c.msg)
	f.Add([]byte{})
	f.Add([]byte{0x12, 0x00, 0x1a, 0x00})
	f.Add([]byte{0x10, 0x01})

	f.Fuzz(func(t *testing.T, msg []byte) {
		h, err := enclave.NewCDS2HandshakeWithAdvisories(c.mrenclave, msg, c.now, c.advisories)
		if err != nil {
			if bytes.Equal(msg, c.msg) {
				t.Fatalf("recorded attestation rejected: %v", err)
			}
		} else {
			_ = h.InitialRequest()
			_ = h.Claims()
		}
		_, _ = enclave.ExtractCDS2Metrics(msg)
	})
}

// FuzzHandshakeComplete completes an attested Noise handshake with an
// arbitrary enclave reply, through SGXClientState as the bridge does. Every
// input needs a fresh handshake (it is single-use), and building one runs the
// full DCAP verification of the recording, so this target is slow (tens of
// milliseconds per input); the Noise parsing itself is fuzzed faster by
// noise.FuzzReadMessage. Nothing may panic.
func FuzzHandshakeComplete(f *testing.F) {
	f.Add(make([]byte, 32+noise.TagSize))
	f.Add(bytes.Repeat([]byte{0xFF}, 32+noise.TagSize))
	f.Add(make([]byte, 32))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, reply []byte) {
		s := enclave.NewSGXClientState(handshakeFromTestsData(t))
		err := s.CompleteHandshake(reply)
		if err == nil && len(reply) < 32+noise.TagSize {
			t.Fatalf("accepted a %d-byte reply", len(reply))
		}
		if err := s.CompleteHandshake(reply); err == nil {
			t.Fatal("a completed or failed handshake was used again")
		}
		_, _ = s.EstablishedRecv(reply)
	})
}
