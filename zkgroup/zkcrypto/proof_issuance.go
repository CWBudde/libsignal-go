// Copyright 2020-2022 Signal Messenger, LLC.
// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package zkcrypto

import (
	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/poksho"
)

func requestPoints(k ProfileRequestPublicKey, c ProfileRequestCiphertext, j ProfileKeyCommitment) poksho.PointArgs {
	g := commitmentGenerators
	return poksho.PointArgs{"Y": k.y, "D1": c.d1, "E1": c.e1, "J3": j.j3, "G_j3": g[2], "D2-J1": sub(c.d2, j.j1), "-G_j1": neg(g[0]), "E2-J2": sub(c.e2, j.j2), "-G_j2": neg(g[1])}
}

// NewProfileRequestProof proves that the encrypted attributes match the public
// commitment, using the client's secret blinding key and nonces.
func NewProfileRequestProof(k ProfileRequestKeyPair, c ProfileRequestCiphertextWithNonce, j ProfileKeyCommitmentWithNonce, s poksho.SHO) (ProfileRequestProof, error) {
	w := poksho.ScalarArgs{"y": k.secret, "r1": c.r1, "r2": c.r2, "j3": j.nonce}
	b, e := prove(profileRequestProofStatement(), w, requestPoints(k.Public(), c.Public(), j.Public()), s)
	return ProfileRequestProof{proofData{proof: b}}, e
}

// Verify authenticates the request against a previously obtained commitment.
func (p ProfileRequestProof) Verify(k ProfileRequestPublicKey, c ProfileRequestCiphertext, j ProfileKeyCommitment) error {
	return verify(profileRequestProofStatement(), p.proof, requestPoints(k, c, j))
}

var credentialYNames = [...]string{"y1", "y2", "y3", "y4", "y5", "y6"}
var credentialGYNames = [...]string{"G_y1", "G_y2", "G_y3", "G_y4", "G_y5", "G_y6"}

func issuanceWitness(k CredentialKeyPair, c BlindedCredentialWithNonce, n int) poksho.ScalarArgs {
	w := poksho.ScalarArgs{"w": k.w, "wprime": k.wp, "x0": k.x0, "x1": k.x1, "rprime": c.nonce}
	for i := range n {
		w[credentialYNames[i]] = k.y[i]
	}
	return w
}
func issuancePoints(k CredentialPublicKey, c BlindedCredential, n int) poksho.PointArgs {
	g := credentialGenerators
	p := poksho.PointArgs{"C_W": k.cw, "G_w": g.w, "G_wprime": g.wp, "G_V-I": sub(g.v, k.i), "G_x0": g.x0, "G_x1": g.x1, "S1": c.s1, "S2": c.s2, "U": c.u, "tU": mult(c.t, c.u)}
	for i := range n {
		p[credentialGYNames[i]] = g.y[i]
	}
	return p
}
func profileIssuancePoints(k CredentialPublicKey, r ProfileRequestPublicKey, c ProfileRequestCiphertext, b BlindedCredential, u UID, expiration uint64) poksho.PointArgs {
	p := issuancePoints(k, b, 5)
	p["Y"], p["D1"], p["D2"], p["E1"], p["E2"] = r.y, c.d1, c.d2, c.e1, c.e2
	p["M1"], p["M2"], p["M5"] = u.m1, u.m2, mult(TimestampScalar(expiration), credentialGenerators.m[4])
	return p
}

// NewProfileIssuanceProof proves correct blinded issuance under the server key.
func NewProfileIssuanceProof(k CredentialKeyPair, r ProfileRequestPublicKey, c ProfileRequestCiphertext, b BlindedCredentialWithNonce, u UID, expiration uint64, s poksho.SHO) (ProfileIssuanceProof, error) {
	if k.kind != ExpiringProfileCredentialKind {
		return ProfileIssuanceProof{}, ErrVerification
	}
	proof, e := prove(profileIssuanceProofStatement(), issuanceWitness(k, b, 5), profileIssuancePoints(k.Public(), r, c, b.Public(), u, expiration), s)
	return ProfileIssuanceProof{proofData{proof: proof}}, e
}

// Verify binds issuance to the client's request, ACI and expiration time.
// This checks the cryptographic statement, not wall-clock validity.
func (p ProfileIssuanceProof) Verify(k CredentialPublicKey, r ProfileRequestPublicKey, aci [16]byte, c ProfileRequestCiphertext, b BlindedCredential, expiration uint64) error {
	return verify(profileIssuanceProofStatement(), p.proof, profileIssuancePoints(k, r, c, b, NewUID(address.NewACI(aci)), expiration))
}
func receiptIssuancePoints(k CredentialPublicKey, r ReceiptRequestPublicKey, c ReceiptRequestCiphertext, b BlindedCredential, expiration, level uint64) poksho.PointArgs {
	p := issuancePoints(k, b, 2)
	p["Y"], p["D1"], p["D2"] = r.y, c.d1, c.d2
	p["M1"] = mult(ReceiptScalar(expiration, level), credentialGenerators.m[0])
	return p
}

// NewReceiptIssuanceProof proves correct blinded receipt issuance.
func NewReceiptIssuanceProof(k CredentialKeyPair, r ReceiptRequestPublicKey, c ReceiptRequestCiphertext, b BlindedCredentialWithNonce, expiration, level uint64, s poksho.SHO) (ReceiptIssuanceProof, error) {
	if k.kind != ReceiptCredentialKind {
		return ReceiptIssuanceProof{}, ErrVerification
	}
	proof, e := prove(receiptIssuanceProofStatement(), issuanceWitness(k, b, 2), receiptIssuancePoints(k.Public(), r, c, b.Public(), expiration, level), s)
	return ReceiptIssuanceProof{proofData{proof: proof}}, e
}

// Verify binds receipt issuance to the request, expiration and level.
func (p ReceiptIssuanceProof) Verify(k CredentialPublicKey, r ReceiptRequestPublicKey, c ReceiptRequestCiphertext, b BlindedCredential, receipt Receipt) error {
	return verify(receiptIssuanceProofStatement(), p.proof, receiptIssuancePoints(k, r, c, b, receipt.Expiration, receipt.Level))
}
