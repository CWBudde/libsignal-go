// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package zkcredential_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"github.com/cwbudde/libsignal-go/poksho"
	z "github.com/cwbudde/libsignal-go/zkcredential"
	"github.com/gtank/ristretto255"
	"testing"
)

func check(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func requireError(t *testing.T, e, want error) {
	t.Helper()
	if !errors.Is(e, want) {
		t.Fatalf("got %v, want %v", e, want)
	}
}
func point(t *testing.T, s poksho.SHO) *ristretto255.Element {
	t.Helper()
	p, e := poksho.PointFromUniformBytes(s.SqueezeAndRatchet(64))
	check(t, e)
	return p
}
func TestBuilderArguments(t *testing.T) {
	k, e := z.GenerateCredentialKeyPair(z.StandardMode, [32]byte{1})
	check(t, e)
	s := poksho.NewShoHmacSha256([]byte("test"))
	a := z.NewAttribute(point(t, s), point(t, s))
	ek := z.DeriveEncryptionKeyPair(z.NewDomain("one"), s)
	bk := z.GenerateBlindingKeyPair(s)
	_, e = z.GenerateCredentialKeyPair(255, [32]byte{})
	requireError(t, e, z.ErrArguments)
	_, e = z.ParseCredentialKeyPair(255, k.Bytes())
	requireError(t, e, z.ErrArguments)
	for _, b := range []*z.IssuanceBuilder{z.NewIssuanceBuilder(nil, nil), z.NewIssuanceBuilder(nil, nil).AddAttribute(a).AddAttribute(a).AddAttribute(a).AddAttribute(a), z.NewIssuanceBuilder(nil, nil).AddBlindedAttribute(bk.Encrypt(a, s).Public()).AddAttribute(a), z.NewIssuanceBuilder(nil, nil).AddBlindedAttribute(bk.Encrypt(a, s).Public()).AddPublicAttribute(z.PublicBytes{1})} {
		_, e = b.Issue(k, [32]byte{})
		requireError(t, e, z.ErrArguments)
	}
	b := z.NewIssuanceBuilder([]byte("label"), nil).AddAttribute(a)
	issuance, e := b.Issue(k, [32]byte{2})
	check(t, e)
	credential, e := b.Verify(k.Public(), issuance)
	check(t, e)
	_, e = b.IssueBlinded(k, bk.Public(), [32]byte{})
	requireError(t, e, z.ErrArguments)
	for _, pb := range []*z.PresentationBuilder{z.NewPresentationBuilder(nil, nil), z.NewPresentationBuilder(nil, nil).AddAttribute(a, ek).AddAttribute(a, ek).AddAttribute(a, ek).AddAttribute(a, ek), z.NewPresentationBuilder(nil, nil).AddAttribute(a, ek).AddAttributeWithoutVerifiedKey(a, ek), z.NewPresentationBuilder(nil, nil).AddAttribute(a, ek).AddAttribute(a, z.DeriveEncryptionKeyPair(z.NewDomain("one"), s))} {
		_, e = pb.Present(z.StandardMode, k.Public(), credential, [32]byte{})
		requireError(t, e, z.ErrArguments)
	}
	_, e = z.NewPresentationBuilder(nil, nil).AddAttribute(a, ek).Present(255, k.Public(), credential, [32]byte{})
	requireError(t, e, z.ErrArguments)
	_, e = z.InverseEncryptionKeyPair(z.NewDomain("one"), ek)
	requireError(t, e, z.ErrArguments)
}
func TestAttributeInverseAndOwnership(t *testing.T) {
	s := poksho.NewShoHmacSha256([]byte("test"))
	first, second := point(t, s), point(t, s)
	a := z.NewAttribute(first, second)
	want := a.Bytes()
	first.Add(first, second)
	if !bytes.Equal(a.Bytes(), want) {
		t.Fatal("attribute aliases input")
	}
	ps := a.Points()
	ps[0].Add(ps[0], ps[1])
	if !bytes.Equal(a.Bytes(), want) {
		t.Fatal("attribute aliases output")
	}
	k := z.DeriveEncryptionKeyPair(z.NewDomain("enc"), s)
	inverse, e := z.InverseEncryptionKeyPair(z.NewDomain("inverse"), k)
	check(t, e)
	cipher := k.Encrypt(a)
	if !bytes.Equal(inverse.Encrypt(cipher).Bytes(), want) {
		t.Fatal("inverse did not recover plaintext")
	}
	m2, e := k.DecryptToSecondPoint(cipher)
	check(t, e)
	if m2.Equal(a.Points()[1]) != 1 {
		t.Fatal("M2 mismatch")
	}
	_, e = k.DecryptToSecondPoint(z.NewAttribute(ristretto255.NewGeneratorElement(), second))
	requireError(t, e, z.ErrVerification)
	encoded := k.Bytes()
	restored, e := z.ParseEncryptionKeyPair(z.NewDomain("enc"), encoded)
	check(t, e)
	encoded[0] ^= 1
	if !bytes.Equal(restored.Bytes(), k.Bytes()) {
		t.Fatal("parser aliases input")
	}
	out := restored.Bytes()
	out[0] ^= 1
	if !bytes.Equal(restored.Bytes(), k.Bytes()) {
		t.Fatal("Bytes aliases storage")
	}
}
func TestEndorsementEdges(t *testing.T) {
	root := z.GenerateServerRootKeyPair([32]byte{1})
	k := root.DeriveKey(poksho.NewShoHmacSha256([]byte("tag")))
	_, e := z.IssueEndorsements(nil, k, [32]byte{})
	requireError(t, e, z.ErrArguments)
	s := poksho.NewShoHmacSha256([]byte("test"))
	a := point(t, s)
	key := z.DeriveEncryptionKeyPair(z.NewDomain("enc"), s)
	hidden := key.Encrypt(z.NewAttribute(a, a)).Points()[0]
	r, e := z.IssueEndorsements([]*ristretto255.Element{hidden}, k, [32]byte{2})
	check(t, e)
	_, e = r.Receive(nil, k.Public())
	requireError(t, e, z.ErrVerification)
	received, e := r.Receive([]*ristretto255.Element{hidden}, k.Public())
	check(t, e)
	token := received[0].Token(z.ClientDecryptionKeyForAttribute(key))
	check(t, k.VerifyToken(a, token[:]))
	requireError(t, k.VerifyToken(a, token[:15]), z.ErrVerification)
	identity := z.CombineEndorsements(received[0]).Remove(received[0])
	if !bytes.Equal(identity.Bytes(), make([]byte, 32)) {
		t.Fatal("remove did not recover identity")
	}
	zero := z.CombineEndorsements()
	if !bytes.Equal(zero.Bytes(), identity.Bytes()) {
		t.Fatal("empty combine")
	}
	doubled := z.CombineEndorsements(received[0], received[0])
	token = doubled.Token(z.ClientDecryptionKeyForAttribute(key))
	requireError(t, k.VerifyToken(a, token[:]), z.ErrVerification)
	check(t, k.VerifyToken(ristretto255.NewIdentityElement().Add(a, a), token[:]))
	different := root.DeriveKey(poksho.NewShoHmacSha256([]byte("other tag")))
	_, e = r.Receive([]*ristretto255.Element{hidden}, different.Public())
	requireError(t, e, z.ErrVerification)
}

func TestModeAndPublicAttributeEncoding(t *testing.T) {
	standard, e := z.GenerateCredentialKeyPair(z.StandardMode, [32]byte{3})
	check(t, e)
	legacy, e := z.GenerateCredentialKeyPair(z.LegacyMode, [32]byte{3})
	check(t, e)
	if !bytes.Equal(standard.Bytes(), legacy.Bytes()) {
		t.Fatal("mode changed private material")
	}
	a, b := standard.Public().Bytes(), legacy.Public().Bytes()
	if !bytes.Equal(a[:64], b[:64]) {
		t.Fatal("two-point migration compatibility changed")
	}
	for i := 64; i < len(a); i += 32 {
		if bytes.Equal(a[i:i+32], b[i:i+32]) {
			t.Fatal("arity separation missing")
		}
	}
	for _, pair := range [][2]z.PublicAttribute{{z.PublicUint32(0x01020304), z.PublicBytes{1, 2, 3, 4}}, {z.PublicUint64(0x0102030405060708), z.PublicBytes{1, 2, 3, 4, 5, 6, 7, 8}}} {
		x, y := poksho.NewShoHmacSha256(nil), poksho.NewShoHmacSha256(nil)
		pair[0].HashInto(x)
		pair[1].HashInto(y)
		if !bytes.Equal(x.SqueezeAndRatchet(32), y.SqueezeAndRatchet(32)) {
			t.Fatal("public integer encoding")
		}
	}
}

func TestInconsistentKeysFailProofCreation(t *testing.T) {
	s := poksho.NewShoHmacSha256([]byte("test"))
	a := z.NewAttribute(point(t, s), point(t, s))
	key, e := z.GenerateCredentialKeyPair(z.StandardMode, [32]byte{1})
	check(t, e)
	bad := key.Bytes()
	bad[0] ^= 1
	corrupt, e := z.ParseCredentialKeyPair(z.StandardMode, bad)
	check(t, e)
	b := z.NewIssuanceBuilder(nil, nil).AddAttribute(a)
	_, e = b.Issue(corrupt, [32]byte{2})
	requireError(t, e, z.ErrVerification)
	issuance, e := b.Issue(key, [32]byte{2})
	check(t, e)
	credential, e := b.Verify(key.Public(), issuance)
	check(t, e)
	enc := z.DeriveEncryptionKeyPair(z.NewDomain("enc"), s)
	bad = enc.Bytes()
	copy(bad[64:], ristretto255.NewGeneratorElement().Bytes())
	badEnc, e := z.ParseEncryptionKeyPair(z.NewDomain("enc"), bad)
	check(t, e)
	_, e = z.NewPresentationBuilder(nil, nil).AddAttribute(a, badEnc).Present(z.StandardMode, key.Public(), credential, [32]byte{3})
	requireError(t, e, z.ErrVerification)
	zeroKey, e := z.ParseEncryptionKeyPair(z.NewDomain("zero"), make([]byte, 96))
	check(t, e)
	_, e = z.NewPresentationBuilder(nil, nil).AddAttribute(a, zeroKey).Present(z.StandardMode, key.Public(), credential, [32]byte{3})
	requireError(t, e, z.ErrVerification)
	root := z.GenerateServerRootKeyPair([32]byte{1})
	derived := root.DeriveKey(poksho.NewShoHmacSha256([]byte("tag")))
	bad = derived.Bytes()
	copy(bad[32:], ristretto255.NewGeneratorElement().Bytes())
	badDerived, e := z.ParseServerDerivedKeyPair(bad)
	check(t, e)
	_, e = z.IssueEndorsements([]*ristretto255.Element{point(t, s)}, badDerived, [32]byte{4})
	requireError(t, e, z.ErrVerification)
}

func TestSystemParameters(t *testing.T) {
	if hex.EncodeToString(z.SystemParametersBytes()) != "589c8718e8263a53a78932b6212a46e7fd52de3ad157b5bb277dba494cfd3471d4cc5f90685952917b33366efcce0512a1f8d70f974758266cb04fc424346d37b20f49cb2a081c94b1771fd8c172ae21785c61ea2c7e31947ce351e7b5ff07028c5329beb87b317ffcd981e440819d91136c988d6d9fbea4a87e55ed24a5993aa02f688ab1d3bd19056f94c8a44b8faddfa3c9c79c95ad44311a7bf00e5e862ec2c399f0d689dfb8c2dc0d7caba32afcf58cf0d85f78195a0b5ab732f565595492cfd982321d1f9be4b21fe6a0214306023d6a05d0d23f67ddc1c0400e5e0a5e92d17595131b7a095e740b884b8c9bb0226a39cfd027c769c4f4677c51f21b24da81fb2bd1356a9d0650f6a63fcc90d93bd74a954ba6f75f0e9fca47a6d21734bce7b28f06b76ef2c44d20a07026534e586eb8e1038874a93e44de362ce7bc0844bffc88e390c62519e281aa6fd53ff9ddd1d9ba303cf70004278ea2ae66ce05a2749d29eba56f3efe99e42902825c473dfc3c154c3762d2e76bd103f629d250b2d9d5c243a4cf8f3be21a84f153f44e2733a105cf780a20f03d84fe1ebbeb0e" {
		t.Fatal("upstream system parameter mismatch")
	}
}
