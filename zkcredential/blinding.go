// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package zkcredential

import (
	"github.com/cwbudde/libsignal-go/poksho"
	"github.com/gtank/ristretto255"
)

// BlindingKeyPair hides attributes from the issuing server. Generate a fresh key
// for each request. Only its scalar is serialized, as in upstream.
type BlindingKeyPair struct {
	y      *scalar
	public *BlindingPublicKey
}

// BlindingPublicKey allows a server to issue blinded credentials.
type BlindingPublicKey struct{ y *point }

// BlindedPoint is a single blinded point without its secret nonce.
type BlindedPoint struct{ d1, d2 *point }

// BlindedPointWithNonce retains a secret nonce for application request proofs.
// It intentionally has no serialization method; send Public instead.
type BlindedPointWithNonce struct {
	public *BlindedPoint
	nonce  *scalar
}

// BlindedAttribute is a pair of blinded points without their secret nonces.
type BlindedAttribute struct{ points [2]*BlindedPoint }

// BlindedAttributeWithNonce retains nonces for an application request proof.
type BlindedAttributeWithNonce struct{ points [2]*BlindedPointWithNonce }

// GenerateBlindingKeyPair consumes one scalar squeeze.
func GenerateBlindingKeyPair(sho poksho.SHO) *BlindingKeyPair {
	s := sget(sho)
	return &BlindingKeyPair{s, &BlindingPublicKey{base(s)}}
}

// Public returns the immutable public key.
func (k *BlindingKeyPair) Public() *BlindingPublicKey { return k.public }

// PrivateScalar returns an independent scalar for application request proofs.
func (k *BlindingKeyPair) PrivateScalar() *ristretto255.Scalar { return new(scalar).Set(k.y) }

// Point returns an independent point for application request proofs.
func (k *BlindingPublicKey) Point() *ristretto255.Element { return pointCopy(k.y) }

// Bytes serializes the secret scalar.
func (k *BlindingKeyPair) Bytes() []byte { return k.y.Bytes() }

// Bytes serializes the public point.
func (k *BlindingPublicKey) Bytes() []byte { return k.y.Bytes() }

// ParseBlindingKeyPair parses the private scalar and derives the public key.
func ParseBlindingKeyPair(b []byte) (*BlindingKeyPair, error) {
	r := reader{b: b}
	s := r.scalar()
	return &BlindingKeyPair{s, &BlindingPublicKey{base(s)}}, r.done()
}

// ParseBlindingPublicKey parses a canonical point.
func ParseBlindingPublicKey(b []byte) (*BlindingPublicKey, error) {
	r := reader{b: b}
	k := &BlindingPublicKey{r.point()}
	return k, r.done()
}

// Blind blinds a single revealed attribute, retaining its nonce for request proofs.
func (k *BlindingKeyPair) Blind(p *ristretto255.Element, sho poksho.SHO) *BlindedPointWithNonce {
	s := sget(sho)
	return &BlindedPointWithNonce{&BlindedPoint{base(s), add(mul(s, k.public.y), p)}, s}
}

// Encrypt blinds both points of a hidden attribute.
func (k *BlindingKeyPair) Encrypt(a *Attribute, sho poksho.SHO) *BlindedAttributeWithNonce {
	return &BlindedAttributeWithNonce{[2]*BlindedPointWithNonce{k.Blind(a.p[0], sho), k.Blind(a.p[1], sho)}}
}

// Public discards the secret nonce from the returned representation.
func (p *BlindedPointWithNonce) Public() *BlindedPoint { return p.public }

// Nonce returns an independent scalar for an application request proof.
func (p *BlindedPointWithNonce) Nonce() *ristretto255.Scalar { return new(scalar).Set(p.nonce) }

// Public discards both secret nonces from the returned representation.
func (p *BlindedAttributeWithNonce) Public() *BlindedAttribute {
	return &BlindedAttribute{[2]*BlindedPoint{p.points[0].public, p.points[1].public}}
}

// Points returns the nonce-bearing components for request proofs.
func (p *BlindedAttributeWithNonce) Points() [2]*BlindedPointWithNonce { return p.points }

// Points returns independent D1, D2 values.
func (p *BlindedPoint) Points() [2]*ristretto255.Element {
	return [2]*point{pointCopy(p.d1), pointCopy(p.d2)}
}

// Points returns the two immutable blinded points.
func (p *BlindedAttribute) Points() [2]*BlindedPoint { return p.points }

// Bytes returns two canonical compressed points.
func (p *BlindedPoint) Bytes() []byte { return pointsBytes(p.d1, p.d2) }

// Bytes returns the two blinded point encodings.
func (p *BlindedAttribute) Bytes() []byte { return append(p.points[0].Bytes(), p.points[1].Bytes()...) }

// ParseBlindedPoint parses two canonical points.
func ParseBlindedPoint(b []byte) (*BlindedPoint, error) {
	r := reader{b: b}
	p := &BlindedPoint{r.point(), r.point()}
	return p, r.done()
}

// ParseBlindedAttribute parses two blinded points.
func ParseBlindedAttribute(b []byte) (*BlindedAttribute, error) {
	r := reader{b: b}
	p := &BlindedAttribute{[2]*BlindedPoint{{r.point(), r.point()}, {r.point(), r.point()}}}
	return p, r.done()
}
