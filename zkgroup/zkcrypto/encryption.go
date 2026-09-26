// Copyright 2020-2023 Signal Messenger, LLC.
// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package zkcrypto

import (
	"crypto/subtle"

	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/internal/ristrettolizard"
	"github.com/cwbudde/libsignal-go/poksho"
	"github.com/gtank/ristretto255"
)

var (
	uidGenerators     = generators("Signal_ZKGroup_20200424_Constant_UidEncryption_SystemParams_Generate")
	profileGenerators = generators("Signal_ZKGroup_20200424_Constant_ProfileKeyEncryption_SystemParams_Generate")
)

func generators(label string) [2]*ristretto255.Element {
	s := sho(label, nil)
	return [2]*ristretto255.Element{point(s), point(s)}
}

// UIDEncryptionSystemParams returns the two serialized UID generators.
func UIDEncryptionSystemParams() []byte { return encodePoints(uidGenerators[:]...) }

// ProfileKeyEncryptionSystemParams returns the two profile-key generators.
func ProfileKeyEncryptionSystemParams() []byte { return encodePoints(profileGenerators[:]...) }

type keyPair struct {
	a1, a2 *ristretto255.Scalar
	public *ristretto255.Element
}
type ciphertext struct{ e1, e2 *ristretto255.Element }

// UIDKeyPair encrypts service IDs. Use DeriveUIDKeyPair or ParseUIDKeyPair;
// the zero value is not initialized. This type is distinct from profile keys.
type UIDKeyPair struct{ keyPair }

// ProfileKeyKeyPair encrypts profile keys. Use its derivation or parser.
type ProfileKeyKeyPair struct{ keyPair }

// UIDCiphertext is a pair of points encrypting a service ID.
type UIDCiphertext struct{ ciphertext }

// ProfileKeyCiphertext is a pair of points encrypting a profile key.
type ProfileKeyCiphertext struct{ ciphertext }

func derive(s poksho.SHO, g [2]*ristretto255.Element) keyPair {
	a1, a2 := scalar(s), scalar(s)
	return keyPair{a1, a2, sum(mult(a1, g[0]), mult(a2, g[1]))}
}

// DeriveUIDKeyPair consumes two 64-byte scalar squeezes from the caller's SHO.
// This permits the exact shared transcript used by GroupSecretParams.
func DeriveUIDKeyPair(s poksho.SHO) UIDKeyPair { return UIDKeyPair{derive(s, uidGenerators)} }

// DeriveProfileKeyKeyPair consumes two scalar squeezes from the caller's SHO.
func DeriveProfileKeyKeyPair(s poksho.SHO) ProfileKeyKeyPair {
	return ProfileKeyKeyPair{derive(s, profileGenerators)}
}

// Bytes serializes both secret scalars and the public key (96 bytes).
func (k keyPair) Bytes() []byte {
	return append(append(k.a1.Bytes(), k.a2.Bytes()...), k.public.Bytes()...)
}

// PublicKeyBytes returns the compressed public key (32 bytes).
func (k keyPair) PublicKeyBytes() []byte { return k.public.Bytes() }

// Bytes serializes the two ciphertext points (64 bytes).
func (c ciphertext) Bytes() []byte { return encodePoints(c.e1, c.e2) }

func parseKey(b []byte) (keyPair, error) {
	if len(b) != 96 {
		return keyPair{}, ErrEncoding
	}
	a1, err := ristretto255.NewScalar().SetCanonicalBytes(b[:32])
	if err != nil {
		return keyPair{}, ErrEncoding
	}
	a2, err := ristretto255.NewScalar().SetCanonicalBytes(b[32:64])
	if err != nil {
		return keyPair{}, ErrEncoding
	}
	p, err := decodePoints(b[64:], 1)
	if err != nil {
		return keyPair{}, err
	}
	return keyPair{a1, a2, p[0]}, nil
}

// ParseUIDKeyPair checks the canonical encodings of a stored key pair, as
// upstream serde does. It does not recompute the redundant public key.
func ParseUIDKeyPair(b []byte) (UIDKeyPair, error) {
	k, err := parseKey(b)
	return UIDKeyPair{k}, err
}

// ParseProfileKeyKeyPair parses a stored key pair, like upstream serde.
func ParseProfileKeyKeyPair(b []byte) (ProfileKeyKeyPair, error) {
	k, err := parseKey(b)
	return ProfileKeyKeyPair{k}, err
}

// ParseUIDCiphertext rejects wrong lengths and noncanonical Ristretto points.
func ParseUIDCiphertext(b []byte) (UIDCiphertext, error) {
	p, err := decodePoints(b, 2)
	if err != nil {
		return UIDCiphertext{}, err
	}
	return UIDCiphertext{ciphertext{p[0], p[1]}}, nil
}

// ParseProfileKeyCiphertext rejects wrong lengths and noncanonical points.
func ParseProfileKeyCiphertext(b []byte) (ProfileKeyCiphertext, error) {
	p, err := decodePoints(b, 2)
	if err != nil {
		return ProfileKeyCiphertext{}, err
	}
	return ProfileKeyCiphertext{ciphertext{p[0], p[1]}}, nil
}

func (k keyPair) encrypt(m1, m2 *ristretto255.Element) ciphertext {
	e1 := mult(k.a1, m1)
	return ciphertext{e1, sum(mult(k.a2, e1), m2)}
}

// Encrypt deterministically encrypts a UID attribute.
func (k UIDKeyPair) Encrypt(uid UID) UIDCiphertext { return UIDCiphertext{k.encrypt(uid.m1, uid.m2)} }

// Encrypt deterministically encrypts a profile-key attribute.
func (k ProfileKeyKeyPair) Encrypt(p ProfileKey) ProfileKeyCiphertext {
	return ProfileKeyCiphertext{k.encrypt(p.m3, p.m4)}
}

func (k keyPair) decrypt(c ciphertext) (*ristretto255.Element, *ristretto255.Element, error) {
	// Upstream rejects E1 = G explicitly. This depends on public ciphertext.
	if c.e1.Equal(ristretto255.NewGeneratorElement()) == 1 {
		return nil, nil, ErrVerification
	}
	m2 := ristretto255.NewIdentityElement().Subtract(c.e2, mult(k.a2, c.e1))
	m1 := mult(ristretto255.NewScalar().Invert(k.a1), c.e1)
	return m1, m2, nil
}

// Decrypt authenticates both the recovered UUID and its ACI/PNI kind. Both
// kinds are checked before selection; failure does not disclose a partial UUID.
func (k UIDKeyPair) Decrypt(c UIDCiphertext) (address.ServiceID, error) {
	m1, m2, err := k.decrypt(c.ciphertext)
	if err != nil {
		return address.ServiceID{}, err
	}
	uuid, ok := ristrettolizard.Decode(m2)
	if !ok {
		return address.ServiceID{}, ErrVerification
	}
	aci, pni := address.NewACI(uuid), address.NewPNI(uuid)
	isACI, isPNI := uidM1(aci).Equal(m1), uidM1(pni).Equal(m1)
	if isACI+isPNI != 1 {
		return address.ServiceID{}, ErrVerification
	}
	return [2]address.ServiceID{aci, pni}[isPNI], nil
}

// Decrypt authenticates the key and UUID. It checks all eight positive
// Elligator candidates and all eight combinations of the omitted bits, even
// for invalid candidates. Exactly one valid match is required.
func (k ProfileKeyKeyPair) Decrypt(c ProfileKeyCiphertext, uuid [16]byte) ([32]byte, error) {
	m3, m4, err := k.decrypt(c.ciphertext)
	if err != nil {
		return [32]byte{}, err
	}
	var result [32]byte
	found := 0
	for _, candidate := range ristrettolizard.Inverse(m4) {
		for bits := byte(0); bits < 8; bits++ {
			p := candidate.Bytes
			p[0] |= (bits >> 2) & 1
			p[31] |= ((bits >> 1) & 1) << 7
			p[31] |= (bits & 1) << 6
			match := profileM3(p, uuid).Equal(m3) & candidate.Valid
			subtle.ConstantTimeCopy(match, result[:], p[:])
			found += match
		}
	}
	if found != 1 {
		return [32]byte{}, ErrVerification
	}
	return result, nil
}
