// Copyright 2020-2024 Signal Messenger, LLC.
// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package zkgroup

import (
	"bytes"
	"github.com/cwbudde/libsignal-go/zkcredential"
	"github.com/cwbudde/libsignal-go/zkgroup/zkcrypto"
)

// NotarySignature is a 64-byte server signature.
type NotarySignature [64]byte

// ServerPublicParams includes the historical fields retained by the wire format.
type ServerPublicParams struct {
	encoded      []byte
	signature    zkcrypto.SignaturePublicKey
	profile      zkcrypto.CredentialPublicKey
	generic      *zkcredential.CredentialPublicKey
	endorsements *zkcredential.ServerRootPublicKey
}

// ParseServerPublicParams validates the exact encoding without authenticating its contents.
func ParseServerPublicParams(b []byte) (*ServerPublicParams, error) {
	if len(b) != 673 {
		return nil, ErrEncoding
	}
	r := reader{b: b}
	r.version(0)
	read(&r, 64, zkcrypto.ParseCredentialPublicKey)
	read(&r, 64, zkcrypto.ParseCredentialPublicKey)
	s := &ServerPublicParams{signature: read(&r, 32, zkcrypto.ParseSignaturePublicKey)}
	read(&r, 64, zkcrypto.ParseCredentialPublicKey)
	read(&r, 64, zkcrypto.ParseCredentialPublicKey)
	s.profile = read(&r, 64, zkcrypto.ParseCredentialPublicKey)
	read(&r, 64, zkcrypto.ParseCredentialPublicKey)
	s.generic = read(&r, 224, zkcredential.ParseCredentialPublicKey)
	s.endorsements = read(&r, 32, zkcredential.ParseServerRootPublicKey)
	if e := r.done(); e != nil {
		return nil, e
	}
	s.encoded = bytes.Clone(b)
	return s, nil
}

// Bytes returns an independent canonical encoding; secret objects must not be logged.
func (s *ServerPublicParams) Bytes() []byte { return bytes.Clone(s.encoded) }

// VerifySignature authenticates a notary signature and its message.
func (s *ServerPublicParams) VerifySignature(message []byte, signature NotarySignature) error {
	if e := s.signature.Verify(message, signature[:]); e != nil {
		return ErrVerification
	}
	return nil
}
