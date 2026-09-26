// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package compat

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/cwbudde/libsignal-go/poksho"
	z "github.com/cwbudde/libsignal-go/zkcredential"
	"github.com/gtank/ristretto255"
	"os"
	"reflect"
	"testing"
)

type genericParams struct {
	Seed       string `json:"seed"`
	Label      string `json:"label"`
	Message    string `json:"message"`
	Public     string `json:"public"`
	Hidden     int    `json:"hidden"`
	Clear      int    `json:"clear"`
	Revealed   int    `json:"revealed"`
	Same       bool   `json:"same"`
	Unverified bool   `json:"unverified"`
	Legacy     bool   `json:"legacy"`
}

func (p genericParams) mode() z.Mode {
	if p.Legacy {
		return z.LegacyMode
	}
	return z.StandardMode
}
func (p genericParams) blinded() bool { return p.Hidden != p.Clear || p.Revealed > 0 }

type genericVectors struct {
	UpstreamTag string `json:"upstream_tag"`
	Cases       []struct {
		Params genericParams     `json:"params"`
		Result map[string]string `json:"result"`
	} `json:"cases"`
}

func loadGeneric(t *testing.T) genericVectors {
	t.Helper()
	b, e := os.ReadFile("vectors/zkcredential.json")
	legacyCheck(t, e)
	var v genericVectors
	legacyCheck(t, json.Unmarshal(b, &v))
	if v.UpstreamTag != "v0.102.2" || len(v.Cases) != 52 {
		t.Fatal("unexpected metadata")
	}
	return v
}
func genericGet[T any](t *testing.T, v T, e error) T { t.Helper(); legacyCheck(t, e); return v }
func genericPoint(t *testing.T, s poksho.SHO) *ristretto255.Element {
	t.Helper()
	p, e := poksho.PointFromUniformBytes(s.SqueezeAndRatchet(64))
	return genericGet(t, p, e)
}
func genericName(s string, i int) string { return fmt.Sprintf("%s%d", s, i) }
func genericDomain(i int) *z.Domain {
	if i == 0 {
		return z.NewDomain("Compat_ZKCredential_A")
	}
	return z.NewDomain("Compat_ZKCredential_B")
}
func genericIndex(p genericParams, i int) int {
	if p.Same {
		return 0
	}
	return i % 2
}
func genericTag(t *testing.T, p genericParams) poksho.SHO {
	t.Helper()
	s := poksho.NewShoHmacSha256([]byte("Compat_ZKCredential_EndorsementTag"))
	s.AbsorbAndRatchet(zkBytes(t, p.Public))
	return s
}
func encodeGenericPoints(ps []*ristretto255.Element) []byte {
	b := binary.LittleEndian.AppendUint64(nil, uint64(len(ps)))
	for _, p := range ps {
		b = append(b, p.Bytes()...)
	}
	return b
}
func decodeGenericPoints(b []byte) ([]*ristretto255.Element, error) {
	if len(b) < 8 {
		return nil, z.ErrEncoding
	}
	n := binary.LittleEndian.Uint64(b[:8])
	if n != uint64((len(b)-8)/32) || (len(b)-8)%32 != 0 {
		return nil, z.ErrEncoding
	}
	var ps []*ristretto255.Element
	for i := 8; i < len(b); i += 32 {
		p, e := ristretto255.NewIdentityElement().SetCanonicalBytes(b[i : i+32])
		if e != nil {
			return nil, e
		}
		ps = append(ps, p)
	}
	return ps, nil
}
func runGeneric(t *testing.T, p genericParams) map[string]string {
	t.Helper()
	out := map[string]string{}
	put := func(n string, b []byte) { out[n] = hex.EncodeToString(b) }
	s := poksho.NewShoHmacSha256([]byte("Compat_ZKCredential_Flow"))
	seed := [32]byte(zkBytes(t, p.Seed))
	s.AbsorbAndRatchet(seed[:])
	k, e := z.GenerateCredentialKeyPair(p.mode(), seed)
	legacyCheck(t, e)
	put("key", k.Bytes())
	put("public_key", k.Public().Bytes())
	keys := [2]*z.EncryptionKeyPair{z.DeriveEncryptionKeyPair(genericDomain(0), s), z.DeriveEncryptionKeyPair(genericDomain(1), s)}
	for i, k := range keys {
		put(genericName("enc_key", i), k.Bytes())
		put(genericName("enc_public", i), k.Public().Bytes())
		g := genericDomain(i).Generators()
		put(genericName("domain", i), append(g[0].Bytes(), g[1].Bytes()...))
	}
	inv, e := z.InverseEncryptionKeyPair(z.NewDomain("Compat_ZKCredential_Inverse"), keys[0])
	legacyCheck(t, e)
	put("inverse_key", inv.Bytes())
	var attrs []*z.Attribute
	for i := range p.Hidden {
		a := z.NewAttribute(genericPoint(t, s), genericPoint(t, s))
		attrs = append(attrs, a)
		put(genericName("attr", i), a.Bytes())
		put(genericName("cipher", i), keys[genericIndex(p, i)].Encrypt(a).Bytes())
	}
	var revealed []*ristretto255.Element
	for i := range p.Revealed {
		a := genericPoint(t, s)
		revealed = append(revealed, a)
		put(genericName("revealed", i), a.Bytes())
	}
	bk := z.GenerateBlindingKeyPair(s)
	put("blinding_key", bk.Bytes())
	put("blinding_public", bk.Public().Bytes())
	b := z.NewIssuanceBuilder(zkBytes(t, p.Label), zkBytes(t, p.Message)).AddPublicAttribute(z.PublicBytes(zkBytes(t, p.Public)))
	for i, a := range attrs {
		if i < p.Clear {
			b.AddAttribute(a)
			continue
		}
		blind := bk.Encrypt(a, s)
		put(genericName("blind", i), blind.Public().Bytes())
		ns := blind.Points()
		put(genericName("nonce", i), append(ns[0].Nonce().Bytes(), ns[1].Nonce().Bytes()...))
		b.AddBlindedAttribute(blind.Public())
	}
	for i, a := range revealed {
		blind := bk.Blind(a, s)
		put(genericName("revealed_blind", i), blind.Public().Bytes())
		put(genericName("revealed_nonce", i), blind.Nonce().Bytes())
		b.AddBlindedRevealedAttribute(blind.Public())
	}
	random := [32]byte(s.SqueezeAndRatchet(32))
	var cred *z.Credential
	if p.blinded() {
		proof, e := b.IssueBlinded(k, bk.Public(), random)
		legacyCheck(t, e)
		put("issuance", proof.Bytes())
		cred, e = b.VerifyBlinded(k.Public(), bk, proof)
		legacyCheck(t, e)
	} else {
		proof, e := b.Issue(k, random)
		legacyCheck(t, e)
		put("issuance", proof.Bytes())
		cred, e = b.Verify(k.Public(), proof)
		legacyCheck(t, e)
	}
	put("credential", cred.Bytes())
	pb := z.NewPresentationBuilder(zkBytes(t, p.Label), zkBytes(t, p.Message))
	for i, a := range attrs {
		if p.Unverified {
			pb.AddAttributeWithoutVerifiedKey(a, keys[genericIndex(p, i)])
		} else {
			pb.AddAttribute(a, keys[genericIndex(p, i)])
		}
	}
	for range revealed {
		pb.AddRevealedAttribute()
	}
	proof, e := pb.Present(p.mode(), k.Public(), cred, [32]byte(s.SqueezeAndRatchet(32)))
	legacyCheck(t, e)
	put("presentation", proof.Bytes())
	root := z.GenerateServerRootKeyPair(seed)
	derived := root.DeriveKey(genericTag(t, p))
	put("root", root.Bytes())
	put("root_public", root.Public().Bytes())
	put("derived", derived.Bytes())
	put("derived_public", root.Public().DeriveKey(genericTag(t, p)).Bytes())
	client := z.ClientDecryptionKeyForAttribute(keys[0])
	put("client", client.Bytes())
	var plain, hidden []*ristretto255.Element
	for range p.Hidden + p.Revealed + 1 {
		a := genericPoint(t, s)
		plain = append(plain, a)
		hidden = append(hidden, keys[0].Encrypt(z.NewAttribute(a, a)).Points()[0])
	}
	put("endorsement_plain", encodeGenericPoints(plain))
	put("endorsement_hidden", encodeGenericPoints(hidden))
	resp, e := z.IssueEndorsements(hidden, derived, [32]byte(s.SqueezeAndRatchet(32)))
	legacyCheck(t, e)
	put("endorsement_response", resp.Bytes())
	es, e := resp.Receive(hidden, derived.Public())
	legacyCheck(t, e)
	for i, e := range es {
		put(genericName("endorsement", i), e.Bytes())
	}
	combined := z.CombineEndorsements(es...)
	put("combined", combined.Bytes())
	removed := combined.Remove(es[0])
	put("removed", removed.Bytes())
	tok := combined.Token(client)
	put("token", tok[:])
	tok = removed.Token(client)
	put("removed_token", tok[:])
	put("sho_tail", s.SqueezeAndRatchet(32))
	return out
}
func genericIssuance(t *testing.T, p genericParams, a map[string]string) (*z.IssuanceBuilder, error) {
	t.Helper()
	raw := func(n string) []byte { return zkBytes(t, a[n]) }
	b := z.NewIssuanceBuilder(zkBytes(t, p.Label), zkBytes(t, p.Message)).AddPublicAttribute(z.PublicBytes(zkBytes(t, p.Public)))
	for i := range p.Hidden {
		if i < p.Clear {
			x, e := z.ParseAttribute(raw(genericName("attr", i)))
			if e != nil {
				return nil, e
			}
			b.AddAttribute(x)
		} else {
			x, e := z.ParseBlindedAttribute(raw(genericName("blind", i)))
			if e != nil {
				return nil, e
			}
			b.AddBlindedAttribute(x)
		}
	}
	for i := range p.Revealed {
		x, e := z.ParseBlindedPoint(raw(genericName("revealed_blind", i)))
		if e != nil {
			return nil, e
		}
		b.AddBlindedRevealedAttribute(x)
	}
	return b, nil
}
func verifyGeneric(t *testing.T, p genericParams, a map[string]string) map[string]bool {
	t.Helper()
	raw := func(n string) []byte { return zkBytes(t, a[n]) }
	out := map[string]bool{}
	out["issuance"] = func() bool {
		k, e := z.ParseCredentialPublicKey(raw("public_key"))
		if e != nil {
			return false
		}
		b, e := genericIssuance(t, p, a)
		if e != nil {
			return false
		}
		if p.blinded() {
			bk, e := z.ParseBlindingKeyPair(raw("blinding_key"))
			if e != nil {
				return false
			}
			proof, e := z.ParseBlindedIssuanceProof(raw("issuance"))
			if e != nil {
				return false
			}
			_, e = b.VerifyBlinded(k, bk, proof)
			return e == nil
		}
		proof, e := z.ParseIssuanceProof(raw("issuance"))
		if e != nil {
			return false
		}
		_, e = b.Verify(k, proof)
		return e == nil
	}()
	out["presentation"] = func() bool {
		k, e := z.ParseCredentialKeyPair(p.mode(), raw("key"))
		if e != nil {
			return false
		}
		proof, e := z.ParsePresentationProof(raw("presentation"))
		if e != nil {
			return false
		}
		v := z.NewPresentationVerifier(zkBytes(t, p.Label), zkBytes(t, p.Message)).AddPublicAttribute(z.PublicBytes(zkBytes(t, p.Public)))
		for i := range p.Hidden {
			ct, e := z.ParseAttribute(raw(genericName("cipher", i)))
			if e != nil {
				return false
			}
			idx := genericIndex(p, i)
			if p.Unverified {
				v.AddAttributeWithoutVerifiedKey(ct, genericDomain(idx).ID())
			} else {
				ek, e := z.ParseEncryptionPublicKey(genericDomain(idx), raw(genericName("enc_public", idx)))
				if e != nil {
					return false
				}
				v.AddAttribute(ct, ek)
			}
		}
		for i := range p.Revealed {
			pt, e := ristretto255.NewIdentityElement().SetCanonicalBytes(raw(genericName("revealed", i)))
			if e != nil {
				return false
			}
			v.AddRevealedAttribute(pt)
		}
		return v.Verify(k, proof) == nil
	}()
	out["endorsement"] = func() bool {
		k, e := z.ParseServerDerivedPublicKey(raw("derived_public"))
		if e != nil {
			return false
		}
		r, e := z.ParseEndorsementResponse(raw("endorsement_response"))
		if e != nil {
			return false
		}
		ps, e := decodeGenericPoints(raw("endorsement_hidden"))
		if e != nil {
			return false
		}
		_, e = r.Receive(ps, k)
		return e == nil
	}()
	out["token"] = func() bool {
		k, e := z.ParseServerDerivedKeyPair(raw("derived"))
		if e != nil {
			return false
		}
		ps, e := decodeGenericPoints(raw("endorsement_plain"))
		if e != nil {
			return false
		}
		sum := ristretto255.NewIdentityElement()
		for _, p := range ps {
			sum.Add(sum, p)
		}
		return k.VerifyToken(sum, raw("token")) == nil
	}()
	return out
}
func TestZKCredentialVectors(t *testing.T) {
	for i, c := range loadGeneric(t).Cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			got := runGeneric(t, c.Params)
			if !reflect.DeepEqual(got, c.Result) {
				for k, v := range c.Result {
					if got[k] != v {
						t.Errorf("%s mismatch\nGo: %s\nRust: %s", k, got[k], v)
					}
				}
				if len(got) != len(c.Result) {
					t.Errorf("field count %d != %d", len(got), len(c.Result))
				}
			}
			for op, ok := range verifyGeneric(t, c.Params, c.Result) {
				if !ok {
					t.Errorf("rejected Rust %s", op)
				}
			}
		})
	}
}
