// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package zkcredential

import (
	"encoding/binary"
	"github.com/cwbudde/libsignal-go/poksho"
)

// PublicAttribute hashes a protocol-specific value into the public transcript.
// Implementations must use unambiguous encodings and consistent ratchet boundaries.
type PublicAttribute interface{ HashInto(poksho.SHO) }

// PublicBytes is a byte-string public attribute; integers should be big endian.
type PublicBytes []byte

// HashInto absorbs and ratchets one public byte-string attribute.
func (a PublicBytes) HashInto(s poksho.SHO) { s.AbsorbAndRatchet(a) }

// PublicUint32 hashes an unsigned integer in upstream big-endian form.
type PublicUint32 uint32

// HashInto absorbs and ratchets the four-byte integer.
func (a PublicUint32) HashInto(s poksho.SHO) {
	s.AbsorbAndRatchet(binary.BigEndian.AppendUint32(nil, uint32(a)))
}

// PublicUint64 hashes an unsigned integer in upstream big-endian form.
type PublicUint64 uint64

// HashInto absorbs and ratchets the eight-byte integer.
func (a PublicUint64) HashInto(s poksho.SHO) {
	s.AbsorbAndRatchet(binary.BigEndian.AppendUint64(nil, uint64(a)))
}

// IssuanceBuilder accumulates attributes in order. Blinded attributes must come
// last. Builders are mutable and must not be used concurrently. Errors persist
// until Issue or Verify, so invalid additions cannot silently change a statement.
type IssuanceBuilder struct {
	public  *poksho.ShoHmacSha256
	ms      []*point
	blind   []*BlindedPoint
	message []byte
	err     error
}

// NewIssuanceBuilder binds a mandatory credential label and an optional proof
// message. The message is not part of the resulting credential.
func NewIssuanceBuilder(label, message []byte) *IssuanceBuilder {
	return &IssuanceBuilder{public: poksho.NewShoHmacSha256(label), ms: []*point{zero()}, message: append([]byte(nil), message...)}
}

// AddPublicAttribute absorbs a public attribute. It must precede blinded attributes.
func (b *IssuanceBuilder) AddPublicAttribute(a PublicAttribute) *IssuanceBuilder {
	if len(b.blind) > 0 {
		b.err = ErrArguments
		return b
	}
	a.HashInto(b.public)
	b.public.Ratchet()
	return b
}

// AddAttribute appends two cleartext attribute points.
func (b *IssuanceBuilder) AddAttribute(a *Attribute) *IssuanceBuilder {
	if len(b.blind) > 0 || len(b.ms)+2 > maxPoints {
		b.err = ErrArguments
		return b
	}
	b.ms = append(b.ms, clonePoints(a.p[:])...)
	return b
}

// AddBlindedAttribute appends two blinded points. The issuer must validate any
// application-specific request proof before calling IssueBlinded.
func (b *IssuanceBuilder) AddBlindedAttribute(a *BlindedAttribute) *IssuanceBuilder {
	b.AddBlindedRevealedAttribute(a.points[0])
	return b.AddBlindedRevealedAttribute(a.points[1])
}

// AddBlindedRevealedAttribute appends a single point hidden during issuance but
// revealed to the verifying server during presentation.
func (b *IssuanceBuilder) AddBlindedRevealedAttribute(a *BlindedPoint) *IssuanceBuilder {
	if len(b.ms)+len(b.blind) >= maxPoints {
		b.err = ErrArguments
		return b
	}
	b.blind = append(b.blind, a)
	return b
}
func (b *IssuanceBuilder) ready(blind bool) error {
	if b.err != nil {
		return b.err
	}
	n := len(b.ms) + len(b.blind)
	if n < 2 || n > maxPoints || (len(b.blind) > 0) != blind {
		return ErrArguments
	}
	return nil
}
func (b *IssuanceBuilder) attrs() []*point {
	ms := clonePoints(b.ms)
	ms[0] = pget(b.public.Clone())
	return ms
}
func (b *IssuanceBuilder) statement() *poksho.Statement {
	n := len(b.ms) + len(b.blind)
	st := poksho.NewStatement()
	equation(st, "C_W", term("w", "G_w"), term("wprime", "G_wprime"))
	terms := []poksho.Term{term("x0", "G_x0"), term("x1", "G_x1")}
	for i := range n {
		terms = append(terms, term(name("y", i), name("G_y", i)))
	}
	equation(st, "G_V-I", terms...)
	v := []poksho.Term{term("w", "G_w"), term("x0", "U"), term("x1", "tU")}
	for i := range b.ms {
		v = append(v, term(name("y", i), name("M", i)))
	}
	if len(b.blind) == 0 {
		equation(st, "V", v...)
		return st
	}
	var s1 []poksho.Term
	for i := len(b.ms); i < n; i++ {
		s1 = append(s1, term(name("y", i), name("D1_", i)))
	}
	s1 = append(s1, term("rprime", "G"))
	equation(st, "S1", s1...)
	s2 := append([]poksho.Term{term("rprime", "Y")}, v...)
	for i := len(b.ms); i < n; i++ {
		s2 = append(s2, term(name("y", i), name("D2_", i)))
	}
	equation(st, "S2", s2...)
	return st
}
func (b *IssuanceBuilder) scalarArgs(k *CredentialKeyPair) poksho.ScalarArgs {
	n := len(b.ms) + len(b.blind)
	a := poksho.ScalarArgs{"w": k.w, "wprime": k.wp, "x0": k.x0, "x1": k.x1}
	for i := range n {
		a[name("y", i)] = k.y[i]
	}
	a["y0"] = k.y0(n)
	return a
}
func (b *IssuanceBuilder) pointArgs(k *CredentialPublicKey, ms []*point, c *Credential, blindKey *BlindingPublicKey, s1, s2 *point) poksho.PointArgs {
	n := len(ms) + len(b.blind)
	a := poksho.PointArgs{"C_W": k.cw, "G_w": system.w, "G_wprime": system.wp, "G_V-I": sub(system.v, k.i[n-2]), "G_x0": system.x0, "G_x1": system.x1, "U": c.u, "tU": mul(c.t, c.u)}
	for i := range n {
		a[name("G_y", i)] = system.y[i]
	}
	for i, m := range ms {
		a[name("M", i)] = m
	}
	if blindKey == nil {
		a["V"] = c.v
		return a
	}
	a["Y"], a["S1"], a["S2"] = blindKey.y, s1, s2
	for j, p := range b.blind {
		i := j + len(ms)
		a[name("D1_", i)], a[name("D2_", i)] = p.d1, p.d2
	}
	return a
}

// IssuanceProof contains a credential and its issuance proof.
type IssuanceProof struct {
	credential *Credential
	proof      []byte
}

// Issue creates a credential and proof. Every call needs fresh random bytes.
func (b *IssuanceBuilder) Issue(k *CredentialKeyPair, randomness [32]byte) (*IssuanceProof, error) {
	if e := b.ready(false); e != nil {
		return nil, e
	}
	ms := b.attrs()
	sho := seeded("Signal_ZKCredential_Issuance_20230410", randomness)
	c := k.credential(ms, len(ms), sho)
	p, e := b.statement().Prove(b.scalarArgs(k), b.pointArgs(k.public, ms, c, nil, nil, nil), b.message, random32(sho))
	if e != nil {
		return nil, proofOK(e)
	}
	return &IssuanceProof{c, p}, nil
}

// Verify authenticates an issuance proof and extracts the credential.
func (b *IssuanceBuilder) Verify(k *CredentialPublicKey, p *IssuanceProof) (*Credential, error) {
	if e := b.ready(false); e != nil {
		return nil, e
	}
	if e := b.statement().VerifyProof(p.proof, b.pointArgs(k, b.attrs(), p.credential, nil, nil, nil), b.message); e != nil {
		return nil, ErrVerification
	}
	return p.credential, nil
}

// Bytes returns the upstream credential and length-prefixed proof encoding.
func (p *IssuanceProof) Bytes() []byte { return vector(p.credential.Bytes(), p.proof) }

// ParseIssuanceProof parses without authenticating. Call Verify before use.
func ParseIssuanceProof(b []byte) (*IssuanceProof, error) {
	r := reader{b: b}
	p := &IssuanceProof{&Credential{r.scalar(), r.point(), r.point()}, nil}
	p.proof = r.vector()
	return p, r.done()
}

// BlindedIssuanceProof contains an encrypted credential and its proof.
type BlindedIssuanceProof struct {
	t         *scalar
	u, s1, s2 *point
	proof     []byte
}

// IssueBlinded issues a credential over cleartext and blinded attributes.
// The caller is responsible for any application-specific request proof.
func (b *IssuanceBuilder) IssueBlinded(k *CredentialKeyPair, bk *BlindingPublicKey, randomness [32]byte) (*BlindedIssuanceProof, error) {
	if e := b.ready(true); e != nil {
		return nil, e
	}
	ms := b.attrs()
	sho := seeded("Signal_ZKCredential_BlindIssuance_20230410", randomness)
	rp := sget(sho)
	s1 := base(rp)
	for j, p := range b.blind {
		s1 = add(s1, mul(k.y[len(ms)+j], p.d1))
	}
	c := k.credential(ms, len(ms)+len(b.blind), sho)
	s2 := add(mul(rp, bk.y), c.v)
	for j, p := range b.blind {
		s2 = add(s2, mul(k.y[len(ms)+j], p.d2))
	}
	a := b.scalarArgs(k)
	a["rprime"] = rp
	p, e := b.statement().Prove(a, b.pointArgs(k.public, ms, c, bk, s1, s2), b.message, random32(sho))
	if e != nil {
		return nil, proofOK(e)
	}
	return &BlindedIssuanceProof{c.t, c.u, s1, s2, p}, nil
}

// VerifyBlinded authenticates an issuance proof before unblinding its credential.
func (b *IssuanceBuilder) VerifyBlinded(k *CredentialPublicKey, bk *BlindingKeyPair, p *BlindedIssuanceProof) (*Credential, error) {
	if e := b.ready(true); e != nil {
		return nil, e
	}
	c := &Credential{p.t, p.u, nil}
	if e := b.statement().VerifyProof(p.proof, b.pointArgs(k, b.attrs(), c, bk.public, p.s1, p.s2), b.message); e != nil {
		return nil, ErrVerification
	}
	c.v = sub(p.s2, mul(bk.y, p.s1))
	return c, nil
}

// Bytes returns the upstream blinded credential and proof encoding.
func (p *BlindedIssuanceProof) Bytes() []byte {
	return vector(append(p.t.Bytes(), pointsBytes(p.u, p.s1, p.s2)...), p.proof)
}

// ParseBlindedIssuanceProof parses without authenticating.
func ParseBlindedIssuanceProof(b []byte) (*BlindedIssuanceProof, error) {
	r := reader{b: b}
	p := &BlindedIssuanceProof{r.scalar(), r.point(), r.point(), r.point(), nil}
	p.proof = r.vector()
	return p, r.done()
}
