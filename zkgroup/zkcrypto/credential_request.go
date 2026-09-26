// Copyright 2020-2022 Signal Messenger, LLC.
// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package zkcrypto

import (
	"github.com/cwbudde/libsignal-go/poksho"
	"github.com/gtank/ristretto255"
)

// ProfileRequestKeyPair is the client blinding key. Use its generator/parser.
type ProfileRequestKeyPair struct {
	secret *ristretto255.Scalar
	public ProfileRequestPublicKey
}

// ProfileRequestPublicKey is the client's public blinding point.
type ProfileRequestPublicKey struct{ y *ristretto255.Element }

// ProfileRequestCiphertext encrypts the private credential attributes.
type ProfileRequestCiphertext struct{ d1, d2, e1, e2 *ristretto255.Element }

// ProfileRequestCiphertextWithNonce retains the private encryption nonces.
type ProfileRequestCiphertextWithNonce struct {
	r1, r2     *ristretto255.Scalar
	ciphertext ProfileRequestCiphertext
}

// GenerateProfileRequestKeyPair consumes a scalar squeeze from s.
func GenerateProfileRequestKeyPair(s poksho.SHO) ProfileRequestKeyPair {
	y := scalar(s)
	return ProfileRequestKeyPair{y, ProfileRequestPublicKey{baseMult(y)}}
}

// Public returns the public blinding key.
func (k ProfileRequestKeyPair) Public() ProfileRequestPublicKey { return k.public }

// Public omits the secret nonces.
func (c ProfileRequestCiphertextWithNonce) Public() ProfileRequestCiphertext { return c.ciphertext }

// Bytes returns the canonical 32-byte point.
func (k ProfileRequestPublicKey) Bytes() []byte { return k.y.Bytes() }

// Bytes returns the secret scalar and public point (64 bytes).
func (k ProfileRequestKeyPair) Bytes() []byte { return append(k.secret.Bytes(), k.public.Bytes()...) }

// Bytes returns the ciphertext's canonical points.
func (c ProfileRequestCiphertext) Bytes() []byte { return encodePoints(c.d1, c.d2, c.e1, c.e2) }

// Bytes returns secret nonces followed by ciphertext points.
func (c ProfileRequestCiphertextWithNonce) Bytes() []byte {
	b := c.r1.Bytes()
	b = append(b, c.r2.Bytes()...)
	return append(b, c.ciphertext.Bytes()...)
}

// ParseProfileRequestKeyPair checks canonical encodings, without recomputing the public key.
func ParseProfileRequestKeyPair(b []byte) (ProfileRequestKeyPair, error) {
	if len(b) != 64 {
		return ProfileRequestKeyPair{}, ErrEncoding
	}
	r := fixedReader{b: b}
	k := ProfileRequestKeyPair{r.scalar(), ProfileRequestPublicKey{r.point()}}
	return k, r.err
}

// ParseProfileRequestPublicKey checks length and canonical encoding.
func ParseProfileRequestPublicKey(b []byte) (ProfileRequestPublicKey, error) {
	p, e := decodePoints(b, 1)
	if e != nil {
		return ProfileRequestPublicKey{}, e
	}
	return ProfileRequestPublicKey{p[0]}, nil
}

// ParseProfileRequestCiphertext checks length and canonical encodings.
func ParseProfileRequestCiphertext(b []byte) (ProfileRequestCiphertext, error) {
	p, e := decodePoints(b, 4)
	if e != nil {
		return ProfileRequestCiphertext{}, e
	}
	return ProfileRequestCiphertext{p[0], p[1], p[2], p[3]}, nil
}

// ParseProfileRequestCiphertextWithNonce parses the client's private encoding.
func ParseProfileRequestCiphertextWithNonce(b []byte) (ProfileRequestCiphertextWithNonce, error) {
	if len(b) != 192 {
		return ProfileRequestCiphertextWithNonce{}, ErrEncoding
	}
	r := fixedReader{b: b}
	c := ProfileRequestCiphertextWithNonce{r.scalar(), r.scalar(), ProfileRequestCiphertext{r.point(), r.point(), r.point(), r.point()}}
	return c, r.err
}

// Unblind recovers a credential. The caller MUST verify the issuance proof
// before accepting it; this subtraction alone provides no authentication.
func (k ProfileRequestKeyPair) Unblind(c BlindedCredential) Credential {
	return Credential{c.t, c.u, sub(c.s2, mult(k.secret, c.s1))}
}

// ReceiptRequestKeyPair is the client blinding key. Use its generator/parser.
type ReceiptRequestKeyPair struct {
	secret *ristretto255.Scalar
	public ReceiptRequestPublicKey
}

// ReceiptRequestPublicKey is the client's public blinding point.
type ReceiptRequestPublicKey struct{ y *ristretto255.Element }

// ReceiptRequestCiphertext encrypts the private credential attributes.
type ReceiptRequestCiphertext struct{ d1, d2 *ristretto255.Element }

// ReceiptRequestCiphertextWithNonce retains the private encryption nonces.
type ReceiptRequestCiphertextWithNonce struct {
	r1         *ristretto255.Scalar
	ciphertext ReceiptRequestCiphertext
}

// GenerateReceiptRequestKeyPair consumes a scalar squeeze from s.
func GenerateReceiptRequestKeyPair(s poksho.SHO) ReceiptRequestKeyPair {
	y := scalar(s)
	return ReceiptRequestKeyPair{y, ReceiptRequestPublicKey{baseMult(y)}}
}

// Public returns the public blinding key.
func (k ReceiptRequestKeyPair) Public() ReceiptRequestPublicKey { return k.public }

// Public omits the secret nonces.
func (c ReceiptRequestCiphertextWithNonce) Public() ReceiptRequestCiphertext { return c.ciphertext }

// Bytes returns the canonical 32-byte point.
func (k ReceiptRequestPublicKey) Bytes() []byte { return k.y.Bytes() }

// Bytes returns the secret scalar and public point (64 bytes).
func (k ReceiptRequestKeyPair) Bytes() []byte { return append(k.secret.Bytes(), k.public.Bytes()...) }

// Bytes returns the ciphertext's canonical points.
func (c ReceiptRequestCiphertext) Bytes() []byte { return encodePoints(c.d1, c.d2) }

// Bytes returns secret nonces followed by ciphertext points.
func (c ReceiptRequestCiphertextWithNonce) Bytes() []byte {
	b := c.r1.Bytes()
	return append(b, c.ciphertext.Bytes()...)
}

// ParseReceiptRequestKeyPair checks canonical encodings, without recomputing the public key.
func ParseReceiptRequestKeyPair(b []byte) (ReceiptRequestKeyPair, error) {
	if len(b) != 64 {
		return ReceiptRequestKeyPair{}, ErrEncoding
	}
	r := fixedReader{b: b}
	k := ReceiptRequestKeyPair{r.scalar(), ReceiptRequestPublicKey{r.point()}}
	return k, r.err
}

// ParseReceiptRequestPublicKey checks length and canonical encoding.
func ParseReceiptRequestPublicKey(b []byte) (ReceiptRequestPublicKey, error) {
	p, e := decodePoints(b, 1)
	if e != nil {
		return ReceiptRequestPublicKey{}, e
	}
	return ReceiptRequestPublicKey{p[0]}, nil
}

// ParseReceiptRequestCiphertext checks length and canonical encodings.
func ParseReceiptRequestCiphertext(b []byte) (ReceiptRequestCiphertext, error) {
	p, e := decodePoints(b, 2)
	if e != nil {
		return ReceiptRequestCiphertext{}, e
	}
	return ReceiptRequestCiphertext{p[0], p[1]}, nil
}

// ParseReceiptRequestCiphertextWithNonce parses the client's private encoding.
func ParseReceiptRequestCiphertextWithNonce(b []byte) (ReceiptRequestCiphertextWithNonce, error) {
	if len(b) != 96 {
		return ReceiptRequestCiphertextWithNonce{}, ErrEncoding
	}
	r := fixedReader{b: b}
	c := ReceiptRequestCiphertextWithNonce{r.scalar(), ReceiptRequestCiphertext{r.point(), r.point()}}
	return c, r.err
}

// Unblind recovers a credential. The caller MUST verify the issuance proof
// before accepting it; this subtraction alone provides no authentication.
func (k ReceiptRequestKeyPair) Unblind(c BlindedCredential) Credential {
	return Credential{c.t, c.u, sub(c.s2, mult(k.secret, c.s1))}
}

// Encrypt blinds both profile-key points using independent nonces.
func (k ProfileRequestKeyPair) Encrypt(p ProfileKey, s poksho.SHO) ProfileRequestCiphertextWithNonce {
	r1, r2 := scalar(s), scalar(s)
	return ProfileRequestCiphertextWithNonce{r1, r2, ProfileRequestCiphertext{baseMult(r1), sum(mult(r1, k.public.y), p.m3), baseMult(r2), sum(mult(r2, k.public.y), p.m4)}}
}

// Encrypt blinds the private receipt serial.
func (k ReceiptRequestKeyPair) Encrypt(serial [16]byte, s poksho.SHO) ReceiptRequestCiphertextWithNonce {
	r := scalar(s)
	return ReceiptRequestCiphertextWithNonce{r, ReceiptRequestCiphertext{baseMult(r), sum(mult(r, k.public.y), receiptSerialPoint(serial))}}
}
