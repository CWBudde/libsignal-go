// Copyright 2020-2022 Signal Messenger, LLC.
// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package zkcrypto

import (
	"encoding/binary"

	"github.com/cwbudde/libsignal-go/poksho"
	"github.com/gtank/ristretto255"
)

type credentialParams struct {
	w, wp, x0, x1 *ristretto255.Element
	y             [6]*ristretto255.Element
	m             [5]*ristretto255.Element
	v, z          *ristretto255.Element
}

var credentialGenerators = func() credentialParams {
	s := sho("Signal_ZKGroup_20200424_Constant_Credentials_SystemParams_Generate", nil)
	p := credentialParams{w: point(s), wp: point(s), x0: point(s), x1: point(s)}
	for i := range 4 {
		p.y[i] = point(s)
	}
	for i := range 4 {
		p.m[i] = point(s)
	}
	p.v, p.z = point(s), point(s)
	p.y[4], p.y[5], p.m[4] = point(s), point(s), point(s)
	return p
}()

// CredentialSystemParams returns the pinned legacy KVAC generators (544 bytes).
func CredentialSystemParams() []byte {
	p := credentialGenerators
	b := encodePoints(p.w, p.wp, p.x0, p.x1)
	b = append(b, encodePoints(p.y[:]...)...)
	b = append(b, encodePoints(p.m[:]...)...)
	return append(b, encodePoints(p.v, p.z)...)
}

// CredentialKind determines the attribute count and historical storage layout.
// The kind is external context and is not included in the serialized key.
type CredentialKind uint8

const (
	// AuthCredentialKind retains the unused legacy three-attribute key.
	AuthCredentialKind CredentialKind = iota + 1
	// AuthWithPNICredentialKind retains the unused legacy five-attribute key.
	AuthWithPNICredentialKind
	// ProfileCredentialKind retains the unused legacy four-attribute key.
	ProfileCredentialKind
	// ExpiringProfileCredentialKind is the active five-attribute profile system.
	ExpiringProfileCredentialKind
	// ReceiptCredentialKind is the active two-attribute receipt system.
	ReceiptCredentialKind
	// PNICredentialKind retains the unused legacy six-attribute key.
	PNICredentialKind
)

func (k CredentialKind) counts() (int, int) {
	switch k {
	case AuthCredentialKind:
		return 3, 4
	case AuthWithPNICredentialKind, ExpiringProfileCredentialKind:
		return 5, 5
	case ProfileCredentialKind:
		return 4, 4
	case ReceiptCredentialKind:
		return 2, 4
	case PNICredentialKind:
		return 6, 6
	default:
		return 0, 0
	}
}

// CredentialPublicKey is the two-point public KVAC key. Use a constructor/parser.
type CredentialPublicKey struct{ cw, i *ristretto255.Element }

// CredentialKeyPair is a legacy KVAC key. Use GenerateCredentialKeyPair or its
// parser; the zero value is not initialized. Methods never mutate stored keys.
type CredentialKeyPair struct {
	kind   CredentialKind
	w, wp  *ristretto255.Scalar
	wPoint *ristretto255.Element
	x0, x1 *ristretto255.Scalar
	y      []*ristretto255.Scalar
	public CredentialPublicKey
}

// GenerateCredentialKeyPair consumes the exact upstream SHO transcript,
// including unused stored scalars in the historical auth and receipt layouts.
func GenerateCredentialKeyPair(kind CredentialKind, s poksho.SHO) (CredentialKeyPair, error) {
	n, storage := kind.counts()
	if n == 0 {
		return CredentialKeyPair{}, ErrEncoding
	}
	p := credentialGenerators
	k := CredentialKeyPair{kind: kind, w: scalar(s)}
	k.wPoint = mult(k.w, p.w)
	k.wp, k.x0, k.x1 = scalar(s), scalar(s), scalar(s)
	k.y = make([]*ristretto255.Scalar, storage)
	for i := range k.y {
		k.y[i] = scalar(s)
	}
	k.public.cw = sum(k.wPoint, mult(k.wp, p.wp))
	k.public.i = sub(sub(p.v, mult(k.x0, p.x0)), mult(k.x1, p.x1))
	for i := range n {
		k.public.i = sub(k.public.i, mult(k.y[i], p.y[i]))
	}
	return k, nil
}

// Kind returns the key's externally selected credential system.
func (k CredentialKeyPair) Kind() CredentialKind { return k.kind }

// Public returns the immutable public key.
func (k CredentialKeyPair) Public() CredentialPublicKey { return k.public }

// Bytes serializes C_W and I (64 bytes).
func (k CredentialPublicKey) Bytes() []byte { return encodePoints(k.cw, k.i) }

// Bytes serializes the secret key, including historical redundant fields.
func (k CredentialKeyPair) Bytes() []byte {
	b := append(k.w.Bytes(), k.wp.Bytes()...)
	b = append(b, k.wPoint.Bytes()...)
	b = append(b, k.x0.Bytes()...)
	b = append(b, k.x1.Bytes()...)
	for _, y := range k.y {
		b = append(b, y.Bytes()...)
	}
	return append(b, k.public.Bytes()...)
}

// ParseCredentialPublicKey validates exact length and canonical points.
func ParseCredentialPublicKey(b []byte) (CredentialPublicKey, error) {
	p, e := decodePoints(b, 2)
	if e != nil {
		return CredentialPublicKey{}, e
	}
	return CredentialPublicKey{p[0], p[1]}, nil
}

// ParseCredentialKeyPair matches upstream serde: it checks canonical encodings
// but does not recompute redundant W, C_W or I. The caller selects the kind.
func ParseCredentialKeyPair(kind CredentialKind, b []byte) (CredentialKeyPair, error) {
	_, n := kind.counts()
	if n == 0 || len(b) != (7+n)*32 {
		return CredentialKeyPair{}, ErrEncoding
	}
	r := fixedReader{b: b}
	k := CredentialKeyPair{kind: kind, w: r.scalar(), wp: r.scalar(), wPoint: r.point(), x0: r.scalar(), x1: r.scalar()}
	k.y = make([]*ristretto255.Scalar, n)
	for i := range k.y {
		k.y[i] = r.scalar()
	}
	k.public = CredentialPublicKey{r.point(), r.point()}
	return k, r.err
}

// Credential is a (t,U,V) KVAC. Its system is supplied by the key and proof.
// Unblinding alone does not authenticate a credential: verify issuance first.
type Credential struct {
	t    *ristretto255.Scalar
	u, v *ristretto255.Element
}

// BlindedCredential contains (t,U,S1,S2) shared with a requesting client.
type BlindedCredential struct {
	t         *ristretto255.Scalar
	u, s1, s2 *ristretto255.Element
}

// BlindedCredentialWithNonce retains the issuer's secret rerandomization scalar.
type BlindedCredentialWithNonce struct {
	nonce   *ristretto255.Scalar
	blinded BlindedCredential
}

// Public omits the secret nonce.
func (c BlindedCredentialWithNonce) Public() BlindedCredential { return c.blinded }

// Bytes returns the upstream 96-byte encoding.
func (c Credential) Bytes() []byte { return append(c.t.Bytes(), encodePoints(c.u, c.v)...) }

// Bytes returns the upstream 128-byte encoding.
func (c BlindedCredential) Bytes() []byte {
	return append(c.t.Bytes(), encodePoints(c.u, c.s1, c.s2)...)
}

// Bytes returns the secret 160-byte encoding.
func (c BlindedCredentialWithNonce) Bytes() []byte {
	return append(c.nonce.Bytes(), c.blinded.Bytes()...)
}

// ParseCredential parses canonical scalars and points.
func ParseCredential(b []byte) (Credential, error) {
	if len(b) != 96 {
		return Credential{}, ErrEncoding
	}
	r := fixedReader{b: b}
	c := Credential{r.scalar(), r.point(), r.point()}
	return c, r.err
}

// ParseBlindedCredential parses canonical scalars and points.
func ParseBlindedCredential(b []byte) (BlindedCredential, error) {
	if len(b) != 128 {
		return BlindedCredential{}, ErrEncoding
	}
	r := fixedReader{b: b}
	c := BlindedCredential{r.scalar(), r.point(), r.point(), r.point()}
	return c, r.err
}

// ParseBlindedCredentialWithNonce parses the issuer's secret encoding.
func ParseBlindedCredentialWithNonce(b []byte) (BlindedCredentialWithNonce, error) {
	if len(b) != 160 {
		return BlindedCredentialWithNonce{}, ErrEncoding
	}
	r := fixedReader{b: b}
	c := BlindedCredentialWithNonce{r.scalar(), BlindedCredential{r.scalar(), r.point(), r.point(), r.point()}}
	return c, r.err
}

func (k CredentialKeyPair) core(m []*ristretto255.Element, s poksho.SHO) Credential {
	t, u := scalar(s), point(s)
	x := ristretto255.NewScalar().Add(k.x0, ristretto255.NewScalar().Multiply(k.x1, t))
	v := sum(k.wPoint, mult(x, u))
	for i, p := range m {
		v = sum(v, mult(k.y[i], p))
	}
	return Credential{t, u, v}
}

// IssueProfile blinds a profile credential. Verify the request proof before
// calling this method. Expiration policy belongs to the higher-level API.
func (k CredentialKeyPair) IssueProfile(uid UID, public ProfileRequestPublicKey, request ProfileRequestCiphertext, expiration uint64, s poksho.SHO) (BlindedCredentialWithNonce, error) {
	if k.kind != ExpiringProfileCredentialKind {
		return BlindedCredentialWithNonce{}, ErrVerification
	}
	c := k.core([]*ristretto255.Element{uid.m1, uid.m2}, s)
	c.v = sum(c.v, mult(k.y[4], mult(TimestampScalar(expiration), credentialGenerators.m[4])))
	r := scalar(s)
	s1 := sum(sum(baseMult(r), mult(k.y[2], request.d1)), mult(k.y[3], request.e1))
	s2 := sum(sum(sum(mult(r, public.y), c.v), mult(k.y[2], request.d2)), mult(k.y[3], request.e2))
	return BlindedCredentialWithNonce{r, BlindedCredential{c.t, c.u, s1, s2}}, nil
}

// Receipt describes the serial and public metadata attested by a receipt KVAC.
// Clients must validate expiration and level against their expected values.
type Receipt struct {
	Serial            [16]byte
	Expiration, Level uint64
}

// ReceiptScalar hashes the expiration and level in big-endian order.
func ReceiptScalar(expiration, level uint64) *ristretto255.Scalar {
	b := binary.BigEndian.AppendUint64(nil, expiration)
	b = binary.BigEndian.AppendUint64(b, level)
	return scalar(sho("Signal_ZKGroup_20210919_Receipt_CalcM1", b))
}
func receiptSerialPoint(serial [16]byte) *ristretto255.Element {
	var b [32]byte
	copy(b[:], serial[:])
	s, _ := ristretto255.NewScalar().SetCanonicalBytes(b[:])
	return mult(s, credentialGenerators.m[1])
}
func (r Receipt) points() []*ristretto255.Element {
	return []*ristretto255.Element{mult(ReceiptScalar(r.Expiration, r.Level), credentialGenerators.m[0]), receiptSerialPoint(r.Serial)}
}

// Bytes returns serial followed by little-endian expiration and level.
func (r Receipt) Bytes() []byte {
	b := append([]byte(nil), r.Serial[:]...)
	b = binary.LittleEndian.AppendUint64(b, r.Expiration)
	return binary.LittleEndian.AppendUint64(b, r.Level)
}

// ParseReceipt parses the fixed-size receipt attribute encoding.
func ParseReceipt(b []byte) (Receipt, error) {
	if len(b) != 32 {
		return Receipt{}, ErrEncoding
	}
	return Receipt{[16]byte(b[:16]), binary.LittleEndian.Uint64(b[16:24]), binary.LittleEndian.Uint64(b[24:])}, nil
}

// IssueReceipt blinds a receipt credential for the supplied metadata.
func (k CredentialKeyPair) IssueReceipt(public ReceiptRequestPublicKey, request ReceiptRequestCiphertext, expiration, level uint64, s poksho.SHO) (BlindedCredentialWithNonce, error) {
	if k.kind != ReceiptCredentialKind {
		return BlindedCredentialWithNonce{}, ErrVerification
	}
	c := k.core([]*ristretto255.Element{mult(ReceiptScalar(expiration, level), credentialGenerators.m[0])}, s)
	r := scalar(s)
	s1 := sum(mult(k.y[1], request.d1), baseMult(r))
	s2 := sum(mult(k.y[1], request.d2), sum(mult(r, public.y), c.v))
	return BlindedCredentialWithNonce{r, BlindedCredential{c.t, c.u, s1, s2}}, nil
}

func sub(a, b *ristretto255.Element) *ristretto255.Element {
	return ristretto255.NewIdentityElement().Subtract(a, b)
}
func neg(a *ristretto255.Element) *ristretto255.Element {
	return ristretto255.NewIdentityElement().Negate(a)
}
func baseMult(s *ristretto255.Scalar) *ristretto255.Element {
	return ristretto255.NewIdentityElement().ScalarBaseMult(s)
}

// fixedReader is used only after validating an exact, fixed encoding length.
type fixedReader struct {
	b   []byte
	err error
}

func (r *fixedReader) scalar() *ristretto255.Scalar {
	s, e := ristretto255.NewScalar().SetCanonicalBytes(r.b[:32])
	r.b = r.b[32:]
	if e != nil {
		r.err = ErrEncoding
	}
	return s
}
func (r *fixedReader) point() *ristretto255.Element {
	p, e := ristretto255.NewIdentityElement().SetCanonicalBytes(r.b[:32])
	r.b = r.b[32:]
	if e != nil {
		r.err = ErrEncoding
	}
	return p
}
