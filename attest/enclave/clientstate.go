// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package enclave

import (
	"fmt"
	"time"

	"github.com/cwbudde/libsignal-go/noise"
)

// SGXClientState is the bridge's SgxClientState: a handshake until
// CompleteHandshake succeeds, a channel afterwards, and unusable once
// CompleteHandshake has failed. A call in the wrong state returns
// ErrInvalidState. It is not safe for concurrent use.
type SGXClientState struct {
	handshake *Handshake
	conn      *noise.Transport
}

// NewSGXClientState wraps a handshake (SgxClientState::new).
func NewSGXClientState(h *Handshake) *SGXClientState { return &SGXClientState{handshake: h} }

// NewCDS2ClientState starts a handshake with a CDSI enclave
// (Cds2ClientState_New).
func NewCDS2ClientState(mrenclave, attestationMsg []byte, now time.Time) (*SGXClientState, error) {
	h, err := NewCDS2Handshake(mrenclave, attestationMsg, now)
	if err != nil {
		return nil, err
	}
	return NewSGXClientState(h), nil
}

// InitialRequest returns the handshake's first message while the handshake
// is pending.
func (s *SGXClientState) InitialRequest() ([]byte, error) {
	if s.handshake == nil {
		return nil, ErrInvalidState
	}
	return s.handshake.InitialRequest(), nil
}

// CompleteHandshake completes the handshake with the enclave's reply. On
// failure the state becomes unusable.
func (s *SGXClientState) CompleteHandshake(received []byte) error {
	h := s.handshake
	if h == nil {
		return ErrInvalidState
	}
	s.handshake = nil
	conn, err := h.Complete(received)
	if err != nil {
		return err
	}
	s.conn = conn
	return nil
}

// EstablishedSend encrypts plaintext on the established channel.
func (s *SGXClientState) EstablishedSend(plaintext []byte) ([]byte, error) {
	if s.conn == nil {
		return nil, ErrInvalidState
	}
	ct, err := s.conn.Send(plaintext)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoise, err)
	}
	return ct, nil
}

// EstablishedRecv decrypts ciphertext received on the established channel.
func (s *SGXClientState) EstablishedRecv(ciphertext []byte) ([]byte, error) {
	if s.conn == nil {
		return nil, ErrInvalidState
	}
	pt, err := s.conn.Recv(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoise, err)
	}
	return pt, nil
}
