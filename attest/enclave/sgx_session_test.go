// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package enclave_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/cwbudde/libsignal-go/attest/dcap"
	"github.com/cwbudde/libsignal-go/attest/enclave"
	"github.com/cwbudde/libsignal-go/attest/internal/testhook"
	"github.com/cwbudde/libsignal-go/noise"
)

// TestClockSkew ports sgx_session.rs test_clock_skew: the session checks
// the attestation a day ahead of the given time.
func TestClockSkew(t *testing.T) {
	validEnd := validStart.Add(30 * 24 * time.Hour)
	for _, tc := range []struct {
		name string
		at   time.Time
		want error // nil: accepted
	}{
		{"slightly_earlier", validStart.Add(-enclave.SkewAdjustment), nil},
		{"more_than_skew_before", validStart.Add(-enclave.SkewAdjustment - time.Second), dcap.ErrCRL},
		{"within_a_day_of_expiry", validEnd.Add(-enclave.SkewAdjustment), dcap.ErrExpired},
		{"earlier_than_that", validEnd.Add(-enclave.SkewAdjustment - time.Second), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sgxHandshake(t, tc.at)
			if tc.want == nil {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, enclave.ErrAttestation) || !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v and %v", err, enclave.ErrAttestation, tc.want)
			}
		})
	}
}

// TestHappyPath ports sgx_session.rs test_happy_path: a responder with the
// enclave's private key completes the handshake and both sides exchange
// messages.
func TestHappyPath(t *testing.T) {
	server, err := noise.NewResponder(noise.NK, privateKey(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	establishment := handshakeFromTestsData(t)

	payload, err := server.ReadMessage(establishment.InitialRequest())
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 0 {
		t.Fatalf("initial request payload = %x, want empty", payload)
	}
	message, err := server.WriteMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(message) != 48 || !server.Finished() {
		t.Fatalf("reply %d bytes, finished %v; want 48, true", len(message), server.Finished())
	}
	serverTransport, err := server.Transport()
	if err != nil {
		t.Fatal(err)
	}

	conn, err := establishment.Complete(message)
	if err != nil {
		t.Fatal(err)
	}

	svrCli, err := serverTransport.Send([]byte{7, 8, 9})
	if err != nil {
		t.Fatal(err)
	}
	if len(svrCli) != 19 {
		t.Fatalf("server message %d bytes, want 19", len(svrCli))
	}
	if got, err := conn.Recv(svrCli); err != nil || !bytes.Equal(got, []byte{7, 8, 9}) {
		t.Fatalf("client received %x, %v", got, err)
	}

	cliSvr, err := conn.Send([]byte{0xa, 0xb, 0xc})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := serverTransport.Recv(cliSvr); err != nil || !bytes.Equal(got, []byte{0xa, 0xb, 0xc}) {
		t.Fatalf("server received %x, %v", got, err)
	}
}

// assertResponderRejects checks that a responder with key cannot read the
// client's initial request.
func assertResponderRejects(t *testing.T, key []byte) {
	t.Helper()
	server, err := noise.NewResponder(noise.NK, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	establishment := handshakeFromTestsData(t)
	if _, err := server.ReadMessage(establishment.InitialRequest()); !errors.Is(err, noise.ErrDecrypt) {
		t.Fatalf("err = %v, want %v", err, noise.ErrDecrypt)
	}
}

// TestMismatchedKeys ports sgx_session.rs test_mismatched_keys: a valid
// but different key.
func TestMismatchedKeys(t *testing.T) {
	bad := bytes.Repeat([]byte{1}, 32)
	bad[0] &= 0xf8
	bad[31] = bad[31]&0x7f | 0x40
	assertResponderRejects(t, bad)
}

// TestInvalidPrivateKey ports sgx_session.rs test_invalid_private_key: an
// unclamped key.
func TestInvalidPrivateKey(t *testing.T) {
	assertResponderRejects(t, bytes.Repeat([]byte{1}, 32))
}

// TestSGXHandshakeInputs covers Handshake::for_sgx's input checks and the
// claims it passes on.
func TestSGXHandshakeInputs(t *testing.T) {
	mr := hexFile(t, "cds2_test.mrenclave")
	ev, en := readTestdata(t, "cds2_test.evidence"), readTestdata(t, "cds2_test.endorsements")
	for _, tc := range []struct {
		name                   string
		mrenclave, evidence, e []byte
		want                   error
	}{
		{"empty_evidence", mr, nil, en, enclave.ErrAttestationData},
		{"empty_endorsements", mr, ev, nil, enclave.ErrAttestationData},
		{"short_mrenclave", mr[:31], ev, en, enclave.ErrAttestationData},
		{"long_mrenclave", append(bytes.Clone(mr), 0), ev, en, enclave.ErrAttestationData},
		{"wrong_mrenclave", make([]byte, 32), ev, en, dcap.ErrMREnclave},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := enclave.NewSGXHandshake(tc.mrenclave, tc.evidence, tc.e, nil, testsDataTime, enclave.PreQuantum)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}

	h := handshakeFromTestsData(t)
	if !bytes.Equal(h.Claims().PublicKey, publicKey(t)) {
		t.Fatalf("pk claim = %x, want %x", h.Claims().PublicKey, publicKey(t))
	}
	if n := len(h.InitialRequest()); n != noise.KeySize+noise.TagSize {
		t.Fatalf("NK initial request %d bytes, want %d", n, noise.KeySize+noise.TagSize)
	}
	if _, err := enclave.NewSGXHandshake(mr, ev, en, nil, testsDataTime, 0); err == nil {
		t.Fatal("handshake type 0 accepted")
	}
}

// TestClaimsFromCustom covers Claims::from_custom_claims.
func TestClaimsFromCustom(t *testing.T) {
	if _, err := enclave.ClaimsFromCustom(map[string][]byte{"config": {1}}); !errors.Is(err, enclave.ErrAttestationData) {
		t.Fatalf("err = %v, want %v", err, enclave.ErrAttestationData)
	}
	in := map[string][]byte{"pk": {1, 2}, "config": {3}}
	c, err := enclave.ClaimsFromCustom(in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.PublicKey, []byte{1, 2}) || len(c.Custom) != 1 || !bytes.Equal(c.Custom["config"], []byte{3}) {
		t.Fatalf("claims = %+v", c)
	}
	if len(in) != 2 {
		t.Fatal("input claims modified")
	}
}

// TestVeryExpiredEvalNumberDefault checks that the test-only exception the
// cds2_test blob needs is off outside tests, and that the blob fails
// without it.
func TestVeryExpiredEvalNumberDefault(t *testing.T) {
	if enclave.VeryExpiredTestEvalNumberDefault {
		t.Fatal("test-only evaluation number exception is on outside tests")
	}
	was := testhook.SetAcceptVeryExpiredEvalNumber(false)
	t.Cleanup(func() { testhook.SetAcceptVeryExpiredEvalNumber(was) })
	if _, err := sgxHandshake(t, testsDataTime); !errors.Is(err, dcap.ErrExpired) {
		t.Fatalf("err = %v, want %v", err, dcap.ErrExpired)
	}
}
