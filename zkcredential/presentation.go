// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package zkcredential

import (
	"encoding/binary"
	"github.com/cwbudde/libsignal-go/poksho"
	"github.com/gtank/ristretto255"
	"math"
)

type presentationKey struct {
	id      string
	public  *EncryptionPublicKey
	private *EncryptionKeyPair
}
type attributeRef struct{ key, first, second int }
type presentationCore struct {
	keys    []presentationKey
	refs    []attributeRef
	ms      []*point
	message []byte
	err     error
}

func newPresentationCore(message []byte) presentationCore {
	return presentationCore{ms: []*point{zero()}, message: append([]byte(nil), message...)}
}
func (c *presentationCore) append(ms []*point, key *presentationKey) {
	if len(c.ms)+len(ms) > maxPoints {
		c.err = ErrArguments
		return
	}
	ki := -1
	if key != nil {
		for i, k := range c.keys {
			if k.id != key.id {
				continue
			}
			ki = i
			if (k.public == nil) != (key.public == nil) {
				c.err = ErrArguments
				return
			}
			if k.public != nil && (!sameDomain(k.public.domain, key.public.domain) || k.public.a.Equal(key.public.a) != 1) {
				c.err = ErrArguments
				return
			}
			break
		}
		if ki < 0 {
			ki = len(c.keys)
			c.keys = append(c.keys, *key)
		}
	}
	first := len(c.ms)
	c.ms = append(c.ms, clonePoints(ms)...)
	c.refs = append(c.refs, attributeRef{ki, first, len(c.ms) - 1})
}
func (c *presentationCore) ready() error {
	if c.err != nil {
		return c.err
	}
	if len(c.ms) < 2 || len(c.ms) > maxPoints || uint64(len(c.message)) > math.MaxUint32 {
		return ErrArguments
	}
	return nil
}
func (c *presentationCore) statement() *poksho.Statement {
	st := poksho.NewStatement()
	equation(st, "Z", term("z", "I"))
	equation(st, "C_x1", term("t", "C_x0"), term("z0", "G_x0"), term("z", "G_x1"))
	var sum []poksho.Term
	for _, k := range c.keys {
		a1 := "a1_" + k.id
		equation(st, "0", term("z1_"+k.id, "I"), term(a1, "Z"))
		if k.public != nil {
			sum = append(sum, term(a1, "G_a1_"+k.id), term("a2_"+k.id, "G_a2_"+k.id))
		}
	}
	if len(sum) > 0 {
		equation(st, "sum(A)", sum...)
	}
	for _, a := range c.refs {
		i, j := a.first, a.second
		if a.key < 0 {
			equation(st, name("C_y", i), term("z", name("G_y", i)))
			continue
		}
		id := c.keys[a.key].id
		equation(st, name("E_A", i), term("a1_"+id, name("C_y", i)), term("z1_"+id, name("G_y", i)))
		equation(st, name("C_y", j)+"-"+name("E_A", j), term("z", name("G_y", j)), term("a2_"+id, name("-E_A", i)))
	}
	equation(st, "C_y0", term("z", "G_y0"))
	return st
}
func (c *presentationCore) args(i *point, p *PresentationProof) poksho.PointArgs {
	a := poksho.PointArgs{"I": i, "C_x0": p.x0, "C_x1": p.x1, "G_x0": system.x0, "G_x1": system.x1, "C_y0": p.y[0]}
	if len(c.keys) > 0 {
		a["0"] = zero()
		sum := zero()
		for _, k := range c.keys {
			if k.public == nil {
				continue
			}
			a["G_a1_"+k.id] = k.public.domain.g[0]
			a["G_a2_"+k.id] = k.public.domain.g[1]
			sum = add(sum, k.public.a)
		}
		// Preserve upstream rejection when verified public keys sum to identity.
		if sum.Equal(zero()) != 1 {
			a["sum(A)"] = sum
		}
	}
	for j := range c.ms {
		a[name("G_y", j)] = system.y[j]
	}
	return a
}
func (c *presentationCore) messageFor(mode Mode, extra []*point) []byte {
	if mode == LegacyMode {
		return c.message
	}
	b := binary.BigEndian.AppendUint32(nil, uint32(len(c.message))) //nolint:gosec // ready bounds length to uint32.
	b = append(b, c.message...)
	for _, k := range c.keys {
		if k.public != nil {
			b = append(b, k.public.a.Bytes()...)
		}
	}
	b = append(b, pointsBytes(extra...)...)
	if len(b) == 4 {
		return nil
	}
	return b
}
func (c *presentationCore) attributeArgs(p *PresentationProof, a poksho.PointArgs, prover bool) []*point {
	var extra []*point
	for _, r := range c.refs {
		i, j := r.first, r.second
		a[name("C_y", i)] = p.y[i]
		if r.key < 0 {
			continue
		}
		e1, e2 := c.ms[i], c.ms[j]
		if prover {
			k := c.keys[r.key].private
			e1 = mul(k.a1, e1)
			e2 = add(mul(k.a2, e1), e2)
		}
		a[name("E_A", i)] = e1
		a[name("-E_A", i)] = neg(e1)
		a[name("C_y", j)+"-"+name("E_A", j)] = sub(p.y[j], e2)
		extra = append(extra, p.y[j], e2)
	}
	return extra
}

// PresentationBuilder accumulates plaintext attributes for presentation. Public
// attributes are checked by the verifier and are not added to this builder.
type PresentationBuilder struct{ core presentationCore }

// NewPresentationBuilder accepts an optional proof message. The label argument
// mirrors the verifier API; as a public attribute it is checked only by the verifier.
func NewPresentationBuilder(_ []byte, message []byte) *PresentationBuilder {
	return &PresentationBuilder{newPresentationCore(message)}
}

// AddAttribute proves encryption using the supplied domain key.
func (b *PresentationBuilder) AddAttribute(a *Attribute, k *EncryptionKeyPair) *PresentationBuilder {
	b.core.append(a.p[:], &presentationKey{k.public.domain.id, k.public, k})
	return b
}

// AddAttributeWithoutVerifiedKey proves correct encryption without authenticating
// which key performed it. The verifier must use the same domain ID.
func (b *PresentationBuilder) AddAttributeWithoutVerifiedKey(a *Attribute, k *EncryptionKeyPair) *PresentationBuilder {
	b.core.append(a.p[:], &presentationKey{k.public.domain.id, nil, k})
	return b
}

// AddRevealedAttribute reserves one point for an attribute the verifier supplies.
func (b *PresentationBuilder) AddRevealedAttribute() *PresentationBuilder {
	b.core.append([]*point{zero()}, nil)
	return b
}

// Present generates a fresh unlinkable presentation. The selected mode must
// match the server key's mode. Every call needs fresh random bytes.
func (b *PresentationBuilder) Present(mode Mode, k *CredentialPublicKey, credential *Credential, randomness [32]byte) (*PresentationProof, error) {
	c := &b.core
	if !mode.valid() {
		return nil, ErrArguments
	}
	if e := c.ready(); e != nil {
		return nil, e
	}
	sho := seeded("Signal_ZKCredential_Presentation_20230410", randomness)
	z := sget(sho)
	p := &PresentationProof{x0: add(mul(z, system.x0), credential.u), x1: add(mul(z, system.x1), mul(credential.t, credential.u)), v: add(mul(z, system.v), credential.v)}
	for j, m := range c.ms {
		p.y = append(p.y, add(mul(z, system.y[j]), m))
	}
	i := k.i[len(c.ms)-2]
	a := c.args(i, p)
	a["Z"] = mul(z, i)
	extra := c.attributeArgs(p, a, true)
	s := poksho.ScalarArgs{"z": z, "t": credential.t, "z0": sneg(smul(z, credential.t))}
	for _, k := range c.keys {
		s["a1_"+k.id] = k.private.a1
		s["a2_"+k.id] = k.private.a2
		s["z1_"+k.id] = sneg(smul(z, k.private.a1))
	}
	var e error
	p.proof, e = c.statement().Prove(s, a, c.messageFor(mode, extra), random32(sho))
	if e != nil {
		return nil, proofOK(e)
	}
	return p, nil
}

// PresentationVerifier accumulates public attributes, ciphertexts and revealed
// attributes in the same order used at issuance and presentation.
type PresentationVerifier struct {
	core   presentationCore
	public *poksho.ShoHmacSha256
}

// NewPresentationVerifier binds the credential label and optional proof message.
func NewPresentationVerifier(label, message []byte) *PresentationVerifier {
	return &PresentationVerifier{newPresentationCore(message), poksho.NewShoHmacSha256(label)}
}

// AddPublicAttribute adds an order-sensitive public attribute.
func (b *PresentationVerifier) AddPublicAttribute(a PublicAttribute) *PresentationVerifier {
	a.HashInto(b.public)
	b.public.Ratchet()
	return b
}

// AddAttribute binds a ciphertext to the expected encryption domain and public key.
func (b *PresentationVerifier) AddAttribute(a *Attribute, k *EncryptionPublicKey) *PresentationVerifier {
	b.core.append(a.p[:], &presentationKey{k.domain.id, k, nil})
	return b
}

// AddAttributeWithoutVerifiedKey checks encryption but not the encryption key's identity.
func (b *PresentationVerifier) AddAttributeWithoutVerifiedKey(a *Attribute, id string) *PresentationVerifier {
	b.core.append(a.p[:], &presentationKey{id, nil, nil})
	return b
}

// AddRevealedAttribute adds an unencrypted point that was blinded during issuance.
func (b *PresentationVerifier) AddRevealedAttribute(p *ristretto255.Element) *PresentationVerifier {
	b.core.append([]*point{p}, nil)
	return b
}

// Verify checks a presentation using the issuing/verifying server's private key.
func (b *PresentationVerifier) Verify(k *CredentialKeyPair, p *PresentationProof) error {
	c := &b.core
	if e := c.ready(); e != nil {
		return e
	}
	if len(p.y) != len(c.ms) {
		return ErrVerification
	}
	y0 := k.y0(len(p.y))
	z := sub(sub(sub(p.v, k.W), mul(k.x0, p.x0)), mul(k.x1, p.x1))
	for i, cy := range p.y {
		y := k.y[i]
		if i == 0 {
			y = y0
		}
		z = sub(z, mul(y, cy))
	}
	z = sub(z, mul(y0, pget(b.public.Clone())))
	for _, r := range c.refs {
		if r.key < 0 {
			z = sub(z, mul(k.y[r.first], c.ms[r.first]))
		}
	}
	a := c.args(k.public.i[len(c.ms)-2], p)
	extra := c.attributeArgs(p, a, false)
	a["Z"] = z
	return proofOK(c.statement().VerifyProof(p.proof, a, c.messageFor(k.mode, extra)))
}

// PresentationProof is a randomized credential presentation.
type PresentationProof struct {
	x0, x1, v *point
	y         []*point
	proof     []byte
}

// Bytes serializes commitments and the length-prefixed proof.
func (p *PresentationProof) Bytes() []byte {
	b := pointsBytes(p.x0, p.x1, p.v)
	b = binary.LittleEndian.AppendUint64(b, uint64(len(p.y)))
	b = append(b, pointsBytes(p.y...)...)
	return vector(b, p.proof)
}

// ParsePresentationProof validates canonical points and limits the commitment
// vector to the seven points supported by this protocol, before allocating.
func ParsePresentationProof(b []byte) (*PresentationProof, error) {
	r := reader{b: b}
	p := &PresentationProof{x0: r.point(), x1: r.point(), v: r.point()}
	n := binary.LittleEndian.Uint64(r.take(8))
	if n > maxPoints || n > uint64(len(r.b)/32) {
		return nil, ErrEncoding
	}
	for range n {
		p.y = append(p.y, r.point())
	}
	p.proof = r.vector()
	return p, r.done()
}
