// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package enclave opens a Noise channel to a remote SGX enclave whose
// attestation names the enclave's public key, as libsignal v0.102.2
// rust/attest/src/enclave.rs, sgx_session.rs and cds2.rs do, plus the
// bridge's SgxClientState (bridge/shared/types/src/sgx_session.rs).
//
// A caller receives the enclave's attestation, builds a Handshake from it
// (NewCDS2Handshake), sends InitialRequest, and completes the handshake with
// the enclave's reply to get a Noise transport. SGXClientState wraps these
// steps in the state machine libsignal's apps call.
package enclave

import (
	"errors"
	"fmt"

	"github.com/cwbudde/libsignal-go/noise"
)

// Errors, one per variant of enclave.rs Error. Attestation failures wrap
// the dcap error, Noise failures the noise error.
var (
	ErrAttestation     = errors.New("enclave: failure to attest remote enclave")
	ErrAttestationData = errors.New("enclave: attestation data invalid")
	ErrNoiseHandshake  = errors.New("enclave: failure to complete Noise handshake to the enclave")
	ErrNoise           = errors.New("enclave: failure to communicate on established Noise channel to the enclave")
	ErrInvalidState    = errors.New("enclave: invalid bridge state")
)

func dataErr(reason string) error { return fmt.Errorf("%w: %s", ErrAttestationData, reason) }

// HandshakeType selects the Noise pattern (enclave.rs HandshakeType).
type HandshakeType uint8

const (
	// PreQuantum is Noise_NK_25519_ChaChaPoly_SHA256.
	PreQuantum HandshakeType = iota + 1
	// PostQuantum is Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256.
	PostQuantum
)

func (t HandshakeType) pattern() (noise.Pattern, error) {
	switch t {
	case PreQuantum:
		return noise.NK, nil
	case PostQuantum:
		return noise.NKhfs, nil
	default:
		return 0, fmt.Errorf("%w: handshake type %d", noise.ErrInvalidPattern, t)
	}
}

// Claims are an attested enclave's claims (enclave.rs Claims).
type Claims struct {
	// PublicKey is the enclave's static X25519 key, the "pk" claim.
	PublicKey []byte
	// Custom holds the other claims. SVR2's "config" and "minimum_limits"
	// stay undecoded: they matter only for the raft validation of SVR2,
	// which is not ported.
	Custom map[string][]byte
}

// ClaimsFromCustom takes the "pk" claim out of claims
// (Claims::from_custom_claims). claims is not modified.
func ClaimsFromCustom(claims map[string][]byte) (*Claims, error) {
	pk, ok := claims["pk"]
	if !ok {
		return nil, dataErr("pk field is missing from the claims")
	}
	c := &Claims{PublicKey: pk, Custom: make(map[string][]byte, len(claims)-1)}
	for k, v := range claims {
		if k != "pk" {
			c.Custom[k] = v
		}
	}
	return c, nil
}

// Handshake is the client side of the Noise handshake with an attested
// enclave (enclave.rs Handshake). It is not safe for concurrent use.
type Handshake struct {
	hs             *noise.HandshakeState
	initialRequest []byte
	claims         *Claims
}

// newHandshake starts a handshake to the enclave key in claims and writes
// the initial request, which carries no payload (Handshake::with_claims).
func newHandshake(claims *Claims, typ HandshakeType) (*Handshake, error) {
	p, err := typ.pattern()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoiseHandshake, err)
	}
	hs, err := noise.NewInitiator(p, claims.PublicKey, nil)
	if err != nil {
		// Only the key can be wrong here, which is not a Noise fault.
		return nil, dataErr("invalid public key")
	}
	msg, err := hs.WriteMessage(nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoiseHandshake, err)
	}
	return &Handshake{hs: hs, initialRequest: msg, claims: claims}, nil
}

// InitialRequest returns the client's first handshake message.
func (h *Handshake) InitialRequest() []byte { return append([]byte(nil), h.initialRequest...) }

// Claims returns the enclave's attested claims.
func (h *Handshake) Claims() *Claims { return h.claims }

// Complete reads the enclave's handshake reply and returns the established
// channel. The reply must carry no payload: upstream reads it into an empty
// buffer, which snow rejects as a decryption failure. The handshake cannot
// be used again, whatever the outcome.
func (h *Handshake) Complete(received []byte) (*noise.Transport, error) {
	payload, err := h.hs.ReadMessage(received)
	if err == nil && len(payload) > 0 {
		err = fmt.Errorf("%w: unexpected handshake payload", noise.ErrDecrypt)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoiseHandshake, err)
	}
	t, err := h.hs.Transport()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoiseHandshake, err)
	}
	return t, nil
}
