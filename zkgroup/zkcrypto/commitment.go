// Copyright 2020 Signal Messenger, LLC.
// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package zkcrypto

import "github.com/gtank/ristretto255"

var commitmentGenerators = func() [3]*ristretto255.Element {
	s := sho("Signal_ZKGroup_20200424_Constant_ProfileKeyCommitment_SystemParams_Generate", nil)
	return [3]*ristretto255.Element{point(s), point(s), point(s)}
}()

// CommitmentSystemParams returns the serialized, deterministically derived
// generator points (96 bytes). It matches upstream's hardcoded parameters.
func CommitmentSystemParams() []byte { return encodePoints(commitmentGenerators[:]...) }

// ProfileKeyCommitment holds three public points. Use its constructor/parser.
type ProfileKeyCommitment struct{ j1, j2, j3 *ristretto255.Element }

// ProfileKeyCommitmentWithNonce also retains the secret scalar needed for
// credential request proofs. Its Bytes encoding must be kept confidential.
type ProfileKeyCommitmentWithNonce struct {
	commitment ProfileKeyCommitment
	nonce      *ristretto255.Scalar
}

// NewProfileKeyCommitment deterministically commits to the key and UUID.
func NewProfileKeyCommitment(key [32]byte, uuid [16]byte) ProfileKeyCommitmentWithNonce {
	p := NewProfileKey(key, uuid)
	b := profileInput(key, uuid)
	nonce := scalar(sho("Signal_ZKGroup_20200424_ProfileKeyAndUid_ProfileKeyCommitment_Calcj3", b[:]))
	return ProfileKeyCommitmentWithNonce{ProfileKeyCommitment{
		sum(mult(nonce, commitmentGenerators[0]), p.m3),
		sum(mult(nonce, commitmentGenerators[1]), p.m4),
		mult(nonce, commitmentGenerators[2]),
	}, nonce}
}

// Public returns the public commitment; its methods do not mutate it.
func (c ProfileKeyCommitmentWithNonce) Public() ProfileKeyCommitment { return c.commitment }

// Nonce returns a copy of the secret scalar.
func (c ProfileKeyCommitmentWithNonce) Nonce() *ristretto255.Scalar {
	return ristretto255.NewScalar().Set(c.nonce)
}

// Bytes serializes J1, J2, J3 and the secret nonce (128 bytes).
func (c ProfileKeyCommitmentWithNonce) Bytes() []byte {
	return append(c.commitment.Bytes(), c.nonce.Bytes()...)
}

// Bytes serializes J1, J2 and J3 (96 bytes).
func (c ProfileKeyCommitment) Bytes() []byte { return encodePoints(c.j1, c.j2, c.j3) }

// ParseProfileKeyCommitment checks length and canonical point encodings.
func ParseProfileKeyCommitment(b []byte) (ProfileKeyCommitment, error) {
	p, err := decodePoints(b, 3)
	if err != nil {
		return ProfileKeyCommitment{}, err
	}
	return ProfileKeyCommitment{p[0], p[1], p[2]}, nil
}

// ParseProfileKeyCommitmentWithNonce checks canonical encodings, as in Rust.
func ParseProfileKeyCommitmentWithNonce(b []byte) (ProfileKeyCommitmentWithNonce, error) {
	if len(b) != 128 {
		return ProfileKeyCommitmentWithNonce{}, ErrEncoding
	}
	c, err := ParseProfileKeyCommitment(b[:96])
	if err != nil {
		return ProfileKeyCommitmentWithNonce{}, err
	}
	n, err := ristretto255.NewScalar().SetCanonicalBytes(b[96:])
	if err != nil {
		return ProfileKeyCommitmentWithNonce{}, ErrEncoding
	}
	return ProfileKeyCommitmentWithNonce{c, n}, nil
}
