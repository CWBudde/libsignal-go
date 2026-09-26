// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package zkcredential

import (
	"github.com/cwbudde/libsignal-go/poksho"
	"github.com/gtank/ristretto255"
)

// Attribute is a pair of points. Accessors return independent copies.
// The first plaintext point should be hash-derived; the second may encode data.
type Attribute struct{ p [2]*point }

// NewAttribute snapshots two points supplied by a higher-level attribute codec.
func NewAttribute(first, second *ristretto255.Element) *Attribute {
	return &Attribute{[2]*point{pointCopy(first), pointCopy(second)}}
}

// Points returns independent copies of the attribute points.
func (a *Attribute) Points() [2]*ristretto255.Element {
	return [2]*point{pointCopy(a.p[0]), pointCopy(a.p[1])}
}

// Bytes returns the two compressed points.
func (a *Attribute) Bytes() []byte { return pointsBytes(a.p[:]...) }

// ParseAttribute reads two canonical Ristretto points.
func ParseAttribute(b []byte) (*Attribute, error) {
	r := reader{b: b}
	a := &Attribute{[2]*point{r.point(), r.point()}}
	return a, r.done()
}

// Domain binds encryption keys to an ID and two generator points. IDs must be
// unique within a protocol. The domain is not serialized in keys or ciphertexts.
type Domain struct {
	id string
	g  [2]*point
}

// NewDomain derives the upstream default generators for id.
func NewDomain(id string) *Domain {
	s := poksho.NewShoHmacSha256([]byte("Signal_ZKCredential_Domain_20231011"))
	s.AbsorbAndRatchet([]byte(id))
	return NewDomainWithGenerators(id, pget(s), pget(s))
}

// NewDomainWithGenerators supports existing protocol-specific generators.
func NewDomainWithGenerators(id string, first, second *ristretto255.Element) *Domain {
	return &Domain{id, [2]*point{pointCopy(first), pointCopy(second)}}
}

// ID returns the domain identifier.
func (d *Domain) ID() string { return d.id }

// Generators returns independent copies of the generator points.
func (d *Domain) Generators() [2]*ristretto255.Element {
	return [2]*point{pointCopy(d.g[0]), pointCopy(d.g[1])}
}
func sameDomain(a, b *Domain) bool {
	return a.id == b.id && a.g[0].Equal(b.g[0]) == 1 && a.g[1].Equal(b.g[1]) == 1
}

// EncryptionKeyPair encrypts attributes in a specific domain. Use a constructor.
type EncryptionKeyPair struct {
	a1, a2 *scalar
	public *EncryptionPublicKey
}

// EncryptionPublicKey authenticates the key used to encrypt attributes.
type EncryptionPublicKey struct {
	domain *Domain
	a      *point
}

// DeriveEncryptionKeyPair consumes two scalar squeezes from sho.
func DeriveEncryptionKeyPair(d *Domain, sho poksho.SHO) *EncryptionKeyPair {
	return encryptionKey(d, sget(sho), sget(sho))
}
func encryptionKey(d *Domain, a1, a2 *scalar) *EncryptionKeyPair {
	return &EncryptionKeyPair{a1, a2, &EncryptionPublicKey{d, add(mul(a1, d.g[0]), mul(a2, d.g[1]))}}
}

// InverseEncryptionKeyPair constructs an inverse transform in a distinct domain.
func InverseEncryptionKeyPair(d *Domain, k *EncryptionKeyPair) (*EncryptionKeyPair, error) {
	if d.id == k.public.domain.id {
		return nil, ErrArguments
	}
	return encryptionKey(d, sinv(k.a1), sneg(smul(k.a1, k.a2))), nil
}

// Public returns the immutable public key.
func (k *EncryptionKeyPair) Public() *EncryptionPublicKey { return k.public }

// Bytes returns a1, a2 and the compressed public key.
func (k *EncryptionKeyPair) Bytes() []byte {
	b := append(k.a1.Bytes(), k.a2.Bytes()...)
	return append(b, k.public.Bytes()...)
}

// Bytes returns the compressed public key.
func (k *EncryptionPublicKey) Bytes() []byte { return k.a.Bytes() }

// ParseEncryptionKeyPair reads the upstream encoding in domain d.
func ParseEncryptionKeyPair(d *Domain, b []byte) (*EncryptionKeyPair, error) {
	r := reader{b: b}
	k := &EncryptionKeyPair{r.scalar(), r.scalar(), &EncryptionPublicKey{d, r.point()}}
	return k, r.done()
}

// ParseEncryptionPublicKey reads a compressed public key in domain d.
func ParseEncryptionPublicKey(d *Domain, b []byte) (*EncryptionPublicKey, error) {
	r := reader{b: b}
	k := &EncryptionPublicKey{d, r.point()}
	return k, r.done()
}

// Encrypt applies the domain's homomorphic encryption transform. The returned
// attribute is a ciphertext, to be passed to a presentation verifier.
func (k *EncryptionKeyPair) Encrypt(a *Attribute) *Attribute {
	e1 := mul(k.a1, a.p[0])
	return NewAttribute(e1, add(mul(k.a2, e1), a.p[1]))
}

// DecryptToSecondPoint recovers an UNAUTHENTICATED plaintext point. The caller
// must decode it, re-encode the first point and check its encryption against the
// ciphertext's first point. Merely calling this method does not verify a value.
func (k *EncryptionKeyPair) DecryptToSecondPoint(a *Attribute) (*ristretto255.Element, error) {
	if a.p[0].Equal(ristretto255.NewGeneratorElement()) == 1 {
		return nil, ErrVerification
	}
	return sub(a.p[1], mul(k.a2, a.p[0])), nil
}
