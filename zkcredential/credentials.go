// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package zkcredential

import (
	"encoding/binary"
	"github.com/cwbudde/libsignal-go/poksho"
)

const maxPoints = 7

var system = func() struct {
	w, wp, x0, x1, v, z *point
	y                   [maxPoints]*point
} {
	s := poksho.NewShoSha256([]byte("Signal_ZKCredential_ConstantSystemParams_generate_20230410"))
	var p struct {
		w, wp, x0, x1, v, z *point
		y                   [maxPoints]*point
	}
	p.w, p.wp, p.x0, p.x1, p.v, p.z = pget(s), pget(s), pget(s), pget(s), pget(s), pget(s)
	for i := range p.y {
		p.y[i] = pget(s)
	}
	return p
}()

// SystemParametersBytes returns the fixed upstream generator encoding.
func SystemParametersBytes() []byte {
	b := pointsBytes(system.w, system.wp, system.x0, system.x1, system.v, system.z)
	return append(b, pointsBytes(system.y[:]...)...)
}

// Credential is a server MAC, obtained by verifying an issuance proof.
type Credential struct {
	t    *scalar
	u, v *point
}

// Bytes returns the canonical upstream credential encoding.
func (c *Credential) Bytes() []byte { return append(c.t.Bytes(), pointsBytes(c.u, c.v)...) }

// ParseCredential reads an already trusted credential from storage. Parsing does
// not authenticate issuance; use IssuanceBuilder.Verify for received proofs.
func ParseCredential(b []byte) (*Credential, error) {
	r := reader{b: b}
	c := &Credential{r.scalar(), r.point(), r.point()}
	return c, r.done()
}

// CredentialKeyPair is an immutable issuing/verifying server key.
type CredentialKeyPair struct {
	mode   Mode
	w, wp  *scalar
	W      *point
	x0, x1 *scalar
	y      [maxPoints]*scalar
	public *CredentialPublicKey
}

// CredentialPublicKey allows clients to verify issuance and create presentations.
type CredentialPublicKey struct {
	cw *point
	i  [maxPoints - 1]*point
}

// GenerateCredentialKeyPair derives a server key in the selected mode.
func GenerateCredentialKeyPair(mode Mode, randomness [32]byte) (*CredentialKeyPair, error) {
	if !mode.valid() {
		return nil, ErrArguments
	}
	s := seeded("Signal_ZKCredential_CredentialPrivateKey_generate_20230410", randomness)
	k := &CredentialKeyPair{mode: mode}
	k.w = sget(s)
	k.W = mul(k.w, system.w)
	k.wp = sget(s)
	k.x0 = sget(s)
	k.x1 = sget(s)
	for i := range k.y {
		k.y[i] = sget(s)
	}
	k.derivePublic()
	return k, nil
}
func (k *CredentialKeyPair) y0(n int) *scalar {
	if k.mode == LegacyMode || n == 2 {
		return k.y[0]
	}
	s := poksho.NewShoHmacSha256([]byte("Signal_ZKCredential_SlotZeroBlinding_20260805"))
	s.AbsorbAndRatchet(k.y[0].Bytes())
	s.AbsorbAndRatchet(binary.BigEndian.AppendUint64(nil, uint64(n))) //nolint:gosec // Callers bound arity to 2..7.
	return sget(s)
}
func (k *CredentialKeyPair) derivePublic() {
	p := &CredentialPublicKey{cw: add(k.W, mul(k.wp, system.wp))}
	partial := sub(sub(system.v, mul(k.x0, system.x0)), mul(k.x1, system.x1))
	for i := 1; i < maxPoints; i++ {
		partial = sub(partial, mul(k.y[i], system.y[i]))
		p.i[i-1] = sub(partial, mul(k.y0(i+1), system.y[0]))
	}
	k.public = p
}

// Public returns the immutable public key.
func (k *CredentialKeyPair) Public() *CredentialPublicKey { return k.public }

// Mode returns the selected compatibility mode.
func (k *CredentialKeyPair) Mode() Mode { return k.mode }

// Bytes serializes private key material; it does not include the mode.
func (k *CredentialKeyPair) Bytes() []byte {
	b := append(k.w.Bytes(), k.wp.Bytes()...)
	b = append(b, k.W.Bytes()...)
	b = append(b, k.x0.Bytes()...)
	b = append(b, k.x1.Bytes()...)
	for _, y := range k.y {
		b = append(b, y.Bytes()...)
	}
	return b
}

// Bytes serializes the public commitment and arity-specific I ladder.
func (k *CredentialPublicKey) Bytes() []byte { return append(k.cw.Bytes(), pointsBytes(k.i[:]...)...) }

// ParseCredentialKeyPair restores a key in its original mode. Changing the mode
// of existing key material can invalidate the standard mode's security guarantees.
func ParseCredentialKeyPair(mode Mode, b []byte) (*CredentialKeyPair, error) {
	if !mode.valid() {
		return nil, ErrArguments
	}
	r := reader{b: b}
	k := &CredentialKeyPair{mode: mode, w: r.scalar(), wp: r.scalar(), W: r.point(), x0: r.scalar(), x1: r.scalar()}
	for i := range k.y {
		k.y[i] = r.scalar()
	}
	if e := r.done(); e != nil {
		return nil, e
	}
	k.derivePublic()
	return k, nil
}

// ParseCredentialPublicKey reads all supported arities.
func ParseCredentialPublicKey(b []byte) (*CredentialPublicKey, error) {
	r := reader{b: b}
	k := &CredentialPublicKey{cw: r.point()}
	for i := range k.i {
		k.i[i] = r.point()
	}
	return k, r.done()
}
func (k *CredentialKeyPair) credential(ms []*point, n int, sho poksho.SHO) *Credential {
	t, u := sget(sho), pget(sho)
	v := add(k.W, mul(ristrettoScalarAdd(k.x0, smul(k.x1, t)), u))
	for i, m := range ms {
		y := k.y[i]
		if i == 0 {
			y = k.y0(n)
		}
		v = add(v, mul(y, m))
	}
	return &Credential{t, u, v}
}
func ristrettoScalarAdd(a, b *scalar) *scalar { return new(scalar).Add(a, b) }
