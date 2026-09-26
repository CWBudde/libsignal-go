// Copyright 2020 Signal Messenger, LLC.
// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package zkcrypto implements the attribute encryption and legacy credential
// primitives of libsignal v0.102.2. These are crypto-layer encodings, without
// the reserved version byte used by zkgroup's higher-level API types.
package zkcrypto

import (
	"encoding/binary"
	"errors"

	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/internal/ristrettolizard"
	"github.com/cwbudde/libsignal-go/poksho"
	"github.com/gtank/ristretto255"
)

// ErrEncoding indicates an invalid length or noncanonical scalar/point.
var ErrEncoding = errors.New("zkgroup: invalid encoding")

// ErrVerification indicates a failed ciphertext, signature or credential proof check.
var ErrVerification = errors.New("zkgroup: verification failed")

func sho(label string, input []byte) *poksho.ShoHmacSha256 {
	s := poksho.NewShoHmacSha256([]byte(label))
	s.AbsorbAndRatchet(input)
	return s
}

func point(s poksho.SHO) *ristretto255.Element {
	p, _ := ristretto255.NewIdentityElement().SetUniformBytes(s.SqueezeAndRatchet(64))
	return p
}

func scalar(s poksho.SHO) *ristretto255.Scalar {
	r, _ := ristretto255.NewScalar().SetUniformBytes(s.SqueezeAndRatchet(64))
	return r
}

func singlePoint(s poksho.SHO) *ristretto255.Element {
	return ristrettolizard.Map([32]byte(s.SqueezeAndRatchet(32)))
}

func mult(s *ristretto255.Scalar, p *ristretto255.Element) *ristretto255.Element {
	return ristretto255.NewIdentityElement().ScalarMult(s, p)
}

func sum(a, b *ristretto255.Element) *ristretto255.Element {
	return ristretto255.NewIdentityElement().Add(a, b)
}

func encodePoints(points ...*ristretto255.Element) []byte {
	b := make([]byte, 0, 32*len(points))
	for _, p := range points {
		b = append(b, p.Bytes()...)
	}
	return b
}

func decodePoints(b []byte, count int) ([]*ristretto255.Element, error) {
	if len(b) != count*32 {
		return nil, ErrEncoding
	}
	p := make([]*ristretto255.Element, count)
	for i := range p {
		var err error
		p[i], err = ristretto255.NewIdentityElement().SetCanonicalBytes(b[32*i : 32*(i+1)])
		if err != nil {
			return nil, ErrEncoding
		}
	}
	return p, nil
}

// UID is the UUID plus the two points used in a credential. Use NewUID or
// ParseUID; the zero value is not initialized. Methods return independent data.
type UID struct {
	raw    [16]byte
	m1, m2 *ristretto255.Element
}

// NewUID binds both the service-ID kind and UUID into M1. M2 reversibly encodes
// the UUID; ACI and PNI of the same UUID deliberately share M2, but not M1.
func NewUID(id address.ServiceID) UID {
	raw := id.RawUUID()
	return UID{raw, uidM1(id), ristrettolizard.Encode(raw)}
}

func uidM1(id address.ServiceID) *ristretto255.Element {
	return point(sho("Signal_ZKGroup_20200424_UID_CalcM1", id.ServiceIDBinary()))
}

// Bytes serializes the stored UUID and both points (80 bytes).
func (u UID) Bytes() []byte {
	return append(append([]byte(nil), u.raw[:]...), encodePoints(u.m1, u.m2)...)
}

// Points returns the two attribute points in independent storage.
func (u UID) Points() [2]*ristretto255.Element {
	return [2]*ristretto255.Element{ristretto255.NewIdentityElement().Set(u.m1), ristretto255.NewIdentityElement().Set(u.m2)}
}

// ParseUID parses a stored attribute, like upstream serde. It checks canonical
// encodings, not consistency of the redundant UUID (historically unused).
func ParseUID(b []byte) (UID, error) {
	if len(b) != 80 {
		return UID{}, ErrEncoding
	}
	p, err := decodePoints(b[16:], 2)
	if err != nil {
		return UID{}, err
	}
	return UID{[16]byte(b[:16]), p[0], p[1]}, nil
}

// ProfileKey is a profile key and its UUID-bound attribute points. Use
// NewProfileKey or ParseProfileKey; the zero value is not initialized.
type ProfileKey struct {
	raw    [32]byte
	m3, m4 *ristretto255.Element
}

// NewProfileKey constructs the credential attribute, preserving all 256 key
// bits: three bits omitted by the reversible map are authenticated by M3.
func NewProfileKey(key [32]byte, uuid [16]byte) ProfileKey {
	masked := key
	masked[0] &= 254
	masked[31] &= 63
	return ProfileKey{key, profileM3(key, uuid), ristrettolizard.Map(masked)}
}

func profileInput(key [32]byte, uuid [16]byte) [48]byte {
	var b [48]byte
	copy(b[:32], key[:])
	copy(b[32:], uuid[:])
	return b
}

func profileM3(key [32]byte, uuid [16]byte) *ristretto255.Element {
	b := profileInput(key, uuid)
	return singlePoint(sho("Signal_ZKGroup_20200424_ProfileKeyAndUid_ProfileKey_CalcM3", b[:]))
}

// Bytes serializes the raw key followed by M3 and M4 (96 bytes).
func (p ProfileKey) Bytes() []byte {
	return append(append([]byte(nil), p.raw[:]...), encodePoints(p.m3, p.m4)...)
}

// Points returns the two attribute points in independent storage.
func (p ProfileKey) Points() [2]*ristretto255.Element {
	return [2]*ristretto255.Element{ristretto255.NewIdentityElement().Set(p.m3), ristretto255.NewIdentityElement().Set(p.m4)}
}

// ParseProfileKey parses a stored attribute. Like upstream serde, it validates
// canonical encodings only; it cannot authenticate M3 without the UUID.
func ParseProfileKey(b []byte) (ProfileKey, error) {
	if len(b) != 96 {
		return ProfileKey{}, ErrEncoding
	}
	p, err := decodePoints(b[32:], 2)
	if err != nil {
		return ProfileKey{}, err
	}
	return ProfileKey{[32]byte(b[:32]), p[0], p[1]}, nil
}

// TimestampScalar maps an unsigned Unix timestamp to the legacy credential
// scalar. Its transcript uses big endian; TimestampBytes uses little endian.
func TimestampScalar(seconds uint64) *ristretto255.Scalar {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], seconds)
	return scalar(sho("Signal_ZKGroup_20220524_Timestamp_Calc_m", b[:]))
}

// TimestampBytes serializes a TimestampStruct as upstream bincode does.
func TimestampBytes(seconds uint64) []byte {
	return binary.LittleEndian.AppendUint64(nil, seconds)
}
