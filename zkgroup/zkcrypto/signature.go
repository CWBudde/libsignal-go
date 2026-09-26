// Copyright 2020-2022 Signal Messenger, LLC.
// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package zkcrypto

import (
	"github.com/cwbudde/libsignal-go/poksho"
	"github.com/gtank/ristretto255"
)

// SignatureKeyPair is the server's poksho signing key (not XEdDSA).
// Use its generator or parser; the zero value is not initialized.
type SignatureKeyPair struct {
	secret *ristretto255.Scalar
	public SignaturePublicKey
}

// SignaturePublicKey verifies server signatures.
type SignaturePublicKey struct{ point *ristretto255.Element }

// GenerateSignatureKeyPair consumes one scalar squeeze.
func GenerateSignatureKeyPair(s poksho.SHO) SignatureKeyPair {
	x := scalar(s)
	return SignatureKeyPair{x, SignaturePublicKey{baseMult(x)}}
}

// Public returns the immutable public key.
func (k SignatureKeyPair) Public() SignaturePublicKey { return k.public }

// Bytes returns the private scalar and public point (64 bytes).
func (k SignatureKeyPair) Bytes() []byte { return append(k.secret.Bytes(), k.public.Bytes()...) }

// Bytes returns the compressed point (32 bytes).
func (k SignaturePublicKey) Bytes() []byte { return k.point.Bytes() }

// ParseSignatureKeyPair checks canonical encoding like serde, without recomputing the public key.
func ParseSignatureKeyPair(b []byte) (SignatureKeyPair, error) {
	if len(b) != 64 {
		return SignatureKeyPair{}, ErrEncoding
	}
	r := fixedReader{b: b}
	k := SignatureKeyPair{r.scalar(), SignaturePublicKey{r.point()}}
	return k, r.err
}

// ParseSignaturePublicKey validates a public key encoding.
func ParseSignaturePublicKey(b []byte) (SignaturePublicKey, error) {
	p, e := decodePoints(b, 1)
	if e != nil {
		return SignaturePublicKey{}, e
	}
	return SignaturePublicKey{p[0]}, nil
}

// Sign consumes a 32-byte randomness squeeze and returns a 64-byte signature.
// It self-verifies and rejects an inconsistent parsed key pair.
func (k SignatureKeyPair) Sign(message []byte, s poksho.SHO) ([]byte, error) {
	signature, err := poksho.Sign(k.secret, k.public.point, message, [32]byte(s.SqueezeAndRatchet(32)))
	if err != nil {
		return nil, ErrVerification
	}
	return signature, nil
}

// Verify checks the signature and message, returning ErrVerification on failure.
func (k SignaturePublicKey) Verify(message, signature []byte) error {
	if err := poksho.VerifySignature(signature, k.point, message); err != nil {
		return ErrVerification
	}
	return nil
}
