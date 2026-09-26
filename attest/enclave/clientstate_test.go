// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package enclave_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cwbudde/libsignal-go/attest/enclave"
	"github.com/cwbudde/libsignal-go/noise"
)

// respond runs the enclave side of an NK handshake with the cds2_test key
// and returns its reply payload-free, or with payload when given.
func respond(t *testing.T, initial, payload []byte) ([]byte, *noise.Transport) {
	t.Helper()
	server, err := noise.NewResponder(noise.NK, privateKey(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.ReadMessage(initial); err != nil {
		t.Fatal(err)
	}
	reply, err := server.WriteMessage(payload)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := server.Transport()
	if err != nil {
		t.Fatal(err)
	}
	return reply, tr
}

func wantErr(t *testing.T, err error, targets ...error) {
	t.Helper()
	for _, target := range targets {
		if !errors.Is(err, target) {
			t.Fatalf("err = %v, want %v", err, target)
		}
	}
}

// TestSGXClientState covers the bridge's SgxClientState state machine.
func TestSGXClientState(t *testing.T) {
	s := enclave.NewSGXClientState(handshakeFromTestsData(t))

	_, err := s.EstablishedSend([]byte{1})
	wantErr(t, err, enclave.ErrInvalidState)
	_, err = s.EstablishedRecv([]byte{1})
	wantErr(t, err, enclave.ErrInvalidState)

	initial, err := s.InitialRequest()
	if err != nil {
		t.Fatal(err)
	}
	reply, server := respond(t, initial, nil)
	if err := s.CompleteHandshake(reply); err != nil {
		t.Fatal(err)
	}

	_, err = s.InitialRequest()
	wantErr(t, err, enclave.ErrInvalidState)
	wantErr(t, s.CompleteHandshake(reply), enclave.ErrInvalidState)

	// Long enough to take two Noise messages.
	long := bytes.Repeat([]byte("cdsi"), noise.MaxPayloadSize/2)
	ct, err := s.EstablishedSend(long)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := server.Recv(ct); err != nil || !bytes.Equal(got, long) {
		t.Fatalf("server received %d bytes, %v", len(got), err)
	}
	ct, err = server.Send([]byte("reply"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.EstablishedRecv(ct); err != nil || string(got) != "reply" {
		t.Fatalf("client received %q, %v", got, err)
	}
	ct, err = server.Send([]byte("tampered"))
	if err != nil {
		t.Fatal(err)
	}
	ct[0] ^= 1
	_, err = s.EstablishedRecv(ct)
	wantErr(t, err, enclave.ErrNoise, noise.ErrDecrypt)
}

// TestSGXClientStateFailedHandshake checks that a failed CompleteHandshake
// leaves the state unusable (SgxClientState::InvalidConnectionState).
func TestSGXClientStateFailedHandshake(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply func(t *testing.T, initial []byte) []byte
	}{
		{"garbage", func(*testing.T, []byte) []byte { return make([]byte, 48) }},
		{"truncated", func(t *testing.T, initial []byte) []byte {
			reply, _ := respond(t, initial, nil)
			return reply[:47]
		}},
		// upstream reads the reply into an empty buffer: snow::Error::Decrypt
		{"payload", func(t *testing.T, initial []byte) []byte {
			reply, _ := respond(t, initial, []byte{1})
			return reply
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := enclave.NewSGXClientState(handshakeFromTestsData(t))
			initial, err := s.InitialRequest()
			if err != nil {
				t.Fatal(err)
			}
			wantErr(t, s.CompleteHandshake(tc.reply(t, initial)), enclave.ErrNoiseHandshake)
			_, err = s.InitialRequest()
			wantErr(t, err, enclave.ErrInvalidState)
			wantErr(t, s.CompleteHandshake(nil), enclave.ErrInvalidState)
			_, err = s.EstablishedSend(nil)
			wantErr(t, err, enclave.ErrInvalidState)
			_, err = s.EstablishedRecv(nil)
			wantErr(t, err, enclave.ErrInvalidState)
		})
	}
}

// TestCDS2ClientState covers Cds2ClientState_New on the recorded CDSI
// attestation.
func TestCDS2ClientState(t *testing.T) {
	c := loadCDSI(t)
	s, err := enclave.NewCDS2ClientState(c.mrenclave, c.msg, c.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.InitialRequest(); err != nil {
		t.Fatal(err)
	}
	if _, err := enclave.NewCDS2ClientState(c.mrenclave, c.msg, c.now.AddDate(2, 0, 0)); !errors.Is(err, enclave.ErrAttestation) {
		t.Fatalf("err = %v, want %v", err, enclave.ErrAttestation)
	}
	if _, err := enclave.NewCDS2ClientState(c.mrenclave, []byte{0xff}, c.now); !errors.Is(err, enclave.ErrAttestationData) {
		t.Fatalf("err = %v, want %v", err, enclave.ErrAttestationData)
	}
}
