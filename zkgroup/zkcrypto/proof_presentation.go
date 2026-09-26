// Copyright 2020-2022 Signal Messenger, LLC.
// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package zkcrypto

import (
	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/poksho"
	"github.com/gtank/ristretto255"
)

func negProduct(a, b *ristretto255.Scalar) *ristretto255.Scalar {
	return ristretto255.NewScalar().Negate(ristretto255.NewScalar().Multiply(a, b))
}

// NewProfilePresentationProof proves possession of an expiring profile KVAC
// while hiding the ACI and profile key behind group ciphertexts. Supply fresh
// randomness through s. An invalid credential is rejected by server verification.
func NewProfilePresentationProof(uk UIDKeyPair, pk ProfileKeyKeyPair, server CredentialPublicKey, c Credential, uc UIDCiphertext, pc ProfileKeyCiphertext, aci [16]byte, key [32]byte, s poksho.SHO) (ProfilePresentationProof, error) {
	g := credentialGenerators
	u, p := NewUID(address.NewACI(aci)), NewProfileKey(key, aci)
	z := scalar(s)
	points := []*ristretto255.Element{
		sum(mult(z, g.x0), c.u), sum(mult(z, g.x1), mult(c.t, c.u)),
		sum(mult(z, g.y[0]), u.m1), sum(mult(z, g.y[1]), u.m2),
		sum(mult(z, g.y[2]), p.m3), sum(mult(z, g.y[3]), p.m4),
		mult(z, g.y[4]), sum(mult(z, g.v), c.v),
	}
	w := poksho.ScalarArgs{"z": z, "t": c.t, "z0": negProduct(z, c.t), "a1": uk.a1, "a2": uk.a2, "b1": pk.a1, "b2": pk.a2, "z1": negProduct(z, uk.a1), "z2": negProduct(z, pk.a1)}
	args := profilePresentationPoints(points, mult(z, server.i), server.i, uk.public, pk.public, uc, pc)
	proof, e := prove(profilePresentationProofStatement(), w, args, s)
	return ProfilePresentationProof{proofData{points, proof}}, e
}

func profilePresentationPoints(c []*ristretto255.Element, z, i, a, b *ristretto255.Element, uc UIDCiphertext, pc ProfileKeyCiphertext) poksho.PointArgs {
	g := credentialGenerators
	return poksho.PointArgs{
		"Z": z, "I": i, "C_x0": c[0], "C_x1": c[1], "G_x0": g.x0, "G_x1": g.x1,
		"A+B": sum(a, b), "G_a1": uidGenerators[0], "G_a2": uidGenerators[1], "G_b1": profileGenerators[0], "G_b2": profileGenerators[1],
		"C_y2-E_A2": sub(c[3], uc.e2), "G_y2": g.y[1], "-E_A1": neg(uc.e1), "E_A1": uc.e1, "C_y1": c[2], "G_y1": g.y[0],
		"C_y4-E_B2": sub(c[5], pc.e2), "G_y4": g.y[3], "-E_B1": neg(pc.e1), "E_B1": pc.e1, "C_y3": c[4], "G_y3": g.y[2],
		"0": ristretto255.NewIdentityElement(), "C_y5": c[6], "G_y5": g.y[4],
	}
}

// Verify checks the presentation using the server's private KVAC key and the
// group's two compressed encryption public keys. It binds the ciphertexts and
// expiration; wall-clock and permitted-expiration checks belong to the API.
func (p ProfilePresentationProof) Verify(k CredentialKeyPair, uc UIDCiphertext, uidPublic []byte, pc ProfileKeyCiphertext, profilePublic []byte, expiration uint64) error {
	if k.kind != ExpiringProfileCredentialKind || len(p.points) != 8 {
		return ErrVerification
	}
	a, e := decodePoints(uidPublic, 1)
	if e != nil {
		return ErrVerification
	}
	b, e := decodePoints(profilePublic, 1)
	if e != nil {
		return ErrVerification
	}
	c := p.points
	z := sub(sub(sub(c[7], k.wPoint), mult(k.x0, c[0])), mult(k.x1, c[1]))
	for i := range 4 {
		z = sub(z, mult(k.y[i], c[i+2]))
	}
	m5 := mult(TimestampScalar(expiration), credentialGenerators.m[4])
	z = sub(z, mult(k.y[4], sum(c[6], m5)))
	return verify(profilePresentationProofStatement(), p.proof, profilePresentationPoints(c, z, k.public.i, a[0], b[0], uc, pc))
}

// NewReceiptPresentationProof proves possession of a receipt KVAC. Its metadata
// is supplied separately to Verify. Use fresh randomness for each presentation.
func NewReceiptPresentationProof(k CredentialPublicKey, c Credential, s poksho.SHO) (ReceiptPresentationProof, error) {
	g := credentialGenerators
	z := scalar(s)
	points := []*ristretto255.Element{sum(mult(z, g.x0), c.u), sum(mult(z, g.x1), mult(c.t, c.u)), mult(z, g.y[0]), mult(z, g.y[1]), sum(mult(z, g.v), c.v)}
	w := poksho.ScalarArgs{"z": z, "t": c.t, "-zt": negProduct(z, c.t)}
	proof, e := prove(receiptPresentationProofStatement(), w, receiptPresentationPoints(points, mult(z, k.i), k.i), s)
	return ReceiptPresentationProof{proofData{points, proof}}, e
}
func receiptPresentationPoints(c []*ristretto255.Element, z, i *ristretto255.Element) poksho.PointArgs {
	g := credentialGenerators
	return poksho.PointArgs{"Z": z, "I": i, "C_x0": c[0], "C_x1": c[1], "C_y1": c[2], "C_y2": c[3], "G_x0": g.x0, "G_x1": g.x1, "G_y1": g.y[0], "G_y2": g.y[1]}
}

// Verify authenticates the receipt serial, expiration and level under the
// server's private key. It does not enforce expiry or prevent double spending.
func (p ReceiptPresentationProof) Verify(k CredentialKeyPair, r Receipt) error {
	if k.kind != ReceiptCredentialKind || len(p.points) != 5 {
		return ErrVerification
	}
	c, m := p.points, r.points()
	z := sub(sub(sub(c[4], k.wPoint), mult(k.x0, c[0])), mult(k.x1, c[1]))
	for i := range 2 {
		z = sub(z, mult(k.y[i], sum(c[i+2], m[i])))
	}
	return verify(receiptPresentationProofStatement(), p.proof, receiptPresentationPoints(c, z, k.public.i))
}
