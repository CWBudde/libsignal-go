// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package hsmenclave opens a Noise channel to trusted code running in an
// HSM, as libsignal v0.102.2 rust/attest/src/hsm_enclave.rs does, wrapped in
// the bridge's HsmEnclaveClient (bridge/shared/types/src/hsm_enclave.rs).
//
// The client knows the HSM's static X25519 key and the hashes of the code it
// trusts. Its initial NK handshake message carries the trusted hashes; the
// HSM answers with the hash of the code it runs, which must be one of them.
package hsmenclave

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/cwbudde/libsignal-go/noise"
)

const (
	// CodeHashSize is the size of a code hash (hsm_enclave.rs CODE_HASH_SIZE).
	CodeHashSize = 32
	// PublicKeySize is the size of the HSM's public key (PUB_KEY_SIZE).
	PublicKeySize = 32
)

// Errors, one per variant of hsm_enclave.rs Error. Handshake and
// communication failures wrap the noise error.
var (
	ErrCommunication    = errors.New("hsmenclave: error in communication to HSM")
	ErrHandshake        = errors.New("hsmenclave: error in handshake to HSM")
	ErrTrustedCode      = errors.New("hsmenclave: trusted HSM process does not match trusted code hash")
	ErrInvalidPublicKey = errors.New("hsmenclave: invalid public key, must be 32 bytes")
	ErrInvalidCodeHash  = errors.New("hsmenclave: invalid code hashes, must be >0 hashes, each exactly 32 bytes")
	ErrInvalidState     = errors.New("hsmenclave: invalid bridge state")
)

// Client is the bridge's HsmEnclaveClient: a handshake until
// CompleteHandshake succeeds, a channel afterwards, and unusable once
// CompleteHandshake has failed. A call in the wrong state returns
// ErrInvalidState. It is not safe for concurrent use.
type Client struct {
	hs             *noise.HandshakeState
	initialRequest []byte
	trusted        []byte // concatenated code hashes
	conn           *noise.Transport
}

// NewClient starts a handshake with the HSM whose static key is
// trustedPublicKey. trustedCodeHashes is one or more concatenated 32-byte
// code hashes (HsmEnclaveClient::new, ClientConnectionEstablishment::new).
func NewClient(trustedPublicKey, trustedCodeHashes []byte) (*Client, error) {
	if len(trustedPublicKey) != PublicKeySize {
		return nil, ErrInvalidPublicKey
	}
	if len(trustedCodeHashes) == 0 || len(trustedCodeHashes)%CodeHashSize != 0 {
		return nil, ErrInvalidCodeHash
	}
	hs, err := noise.NewInitiator(noise.NK, trustedPublicKey, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	trusted := bytes.Clone(trustedCodeHashes)
	msg, err := hs.WriteMessage(trusted)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	return &Client{hs: hs, initialRequest: msg, trusted: trusted}, nil
}

// InitialRequest returns the handshake's first message while the handshake
// is pending.
func (c *Client) InitialRequest() ([]byte, error) {
	if c.hs == nil {
		return nil, ErrInvalidState
	}
	return bytes.Clone(c.initialRequest), nil
}

// CompleteHandshake reads the HSM's reply, whose payload must be exactly one
// of the trusted code hashes: a shorter or untrusted one fails with
// ErrTrustedCode, a longer one with ErrHandshake, as upstream's do. On
// failure the client becomes unusable.
func (c *Client) CompleteHandshake(received []byte) error {
	hs := c.hs
	if hs == nil {
		return ErrInvalidState
	}
	c.hs, c.initialRequest = nil, nil
	codeHash, err := hs.ReadMessage(received)
	if err == nil && len(codeHash) > CodeHashSize {
		// Upstream reads the payload into a 32-byte buffer, which snow
		// rejects as a decryption failure.
		err = fmt.Errorf("%w: handshake payload longer than a code hash", noise.ErrDecrypt)
	}
	if err != nil {
		return fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	if !c.trusts(codeHash) {
		return ErrTrustedCode
	}
	conn, err := hs.Transport()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrHandshake, err)
	}
	c.conn = conn
	return nil
}

func (c *Client) trusts(codeHash []byte) bool {
	for h := range slices.Chunk(c.trusted, CodeHashSize) {
		if bytes.Equal(h, codeHash) {
			return true
		}
	}
	return false
}

// EstablishedSend encrypts plaintext on the established channel.
func (c *Client) EstablishedSend(plaintext []byte) ([]byte, error) {
	if c.conn == nil {
		return nil, ErrInvalidState
	}
	ct, err := c.conn.Send(plaintext)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCommunication, err)
	}
	return ct, nil
}

// EstablishedRecv decrypts ciphertext received on the established channel.
func (c *Client) EstablishedRecv(ciphertext []byte) ([]byte, error) {
	if c.conn == nil {
		return nil, ErrInvalidState
	}
	pt, err := c.conn.Recv(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCommunication, err)
	}
	return pt, nil
}
