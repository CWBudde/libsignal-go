// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package zkcrypto_test

import (
	"errors"
	"testing"

	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/poksho"
	z "github.com/cwbudde/libsignal-go/zkgroup/zkcrypto"
)

func credentialSHO() *poksho.ShoHmacSha256 {
	s := poksho.NewShoHmacSha256([]byte("Credential unit test"))
	s.AbsorbAndRatchet([]byte("test randomness"))
	return s
}
func TestCredentialKindSeparation(t *testing.T) {
	s := credentialSHO()
	for _, kind := range []z.CredentialKind{0, 255} {
		if _, e := z.GenerateCredentialKeyPair(kind, s); !errors.Is(e, z.ErrEncoding) {
			t.Fatal("invalid kind accepted")
		}
		if _, e := z.ParseCredentialKeyPair(kind, make([]byte, 352)); !errors.Is(e, z.ErrEncoding) {
			t.Fatal("invalid kind parsed")
		}
	}
	for _, kind := range []z.CredentialKind{z.AuthCredentialKind, z.AuthWithPNICredentialKind, z.ProfileCredentialKind, z.ExpiringProfileCredentialKind, z.ReceiptCredentialKind, z.PNICredentialKind} {
		k, e := z.GenerateCredentialKeyPair(kind, s)
		if e != nil {
			t.Fatal(e)
		}
		if k.Kind() != kind {
			t.Fatal("kind lost")
		}
		if kind != z.ExpiringProfileCredentialKind {
			if _, e = k.IssueProfile(z.UID{}, z.ProfileRequestPublicKey{}, z.ProfileRequestCiphertext{}, 0, s); !errors.Is(e, z.ErrVerification) {
				t.Fatal("wrong kind issued profile")
			}
			if _, e = z.NewProfileIssuanceProof(k, z.ProfileRequestPublicKey{}, z.ProfileRequestCiphertext{}, z.BlindedCredentialWithNonce{}, z.UID{}, 0, s); !errors.Is(e, z.ErrVerification) {
				t.Fatal("wrong kind proved issuance")
			}
			if e = (z.ProfilePresentationProof{}).Verify(k, z.UIDCiphertext{}, nil, z.ProfileKeyCiphertext{}, nil, 0); !errors.Is(e, z.ErrVerification) {
				t.Fatal("wrong kind verified profile")
			}
		}
		if kind != z.ReceiptCredentialKind {
			if _, e = k.IssueReceipt(z.ReceiptRequestPublicKey{}, z.ReceiptRequestCiphertext{}, 0, 0, s); !errors.Is(e, z.ErrVerification) {
				t.Fatal("wrong kind issued receipt")
			}
			if _, e = z.NewReceiptIssuanceProof(k, z.ReceiptRequestPublicKey{}, z.ReceiptRequestCiphertext{}, z.BlindedCredentialWithNonce{}, 0, 0, s); !errors.Is(e, z.ErrVerification) {
				t.Fatal("wrong kind proved receipt issuance")
			}
			if e = (z.ReceiptPresentationProof{}).Verify(k, z.Receipt{}); !errors.Is(e, z.ErrVerification) {
				t.Fatal("wrong kind verified receipt")
			}
		}
	}
}
func TestCredentialProofCreationRejectsInconsistentSecrets(t *testing.T) {
	s := credentialSHO()
	key := z.GenerateSignatureKeyPair(s)
	other := z.GenerateSignatureKeyPair(s)
	b := key.Bytes()
	copy(b[32:], other.Public().Bytes())
	inconsistent, e := z.ParseSignatureKeyPair(b)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = inconsistent.Sign([]byte("message"), s); !errors.Is(e, z.ErrVerification) {
		t.Fatal("signed with inconsistent public key")
	}
	uuid := [16]byte{42}
	raw := [32]byte{99}
	profile := z.NewProfileKey(raw, uuid)
	requestKey := z.GenerateProfileRequestKeyPair(s)
	request := requestKey.Encrypt(profile, s)
	wrong := z.NewProfileKeyCommitment([32]byte{100}, uuid)
	if _, e = z.NewProfileRequestProof(requestKey, request, wrong, s); !errors.Is(e, z.ErrVerification) {
		t.Fatal("proved request with wrong commitment")
	}
	server, e := z.GenerateCredentialKeyPair(z.ExpiringProfileCredentialKind, s)
	if e != nil {
		t.Fatal(e)
	}
	uid := z.NewUID(address.NewACI(uuid))
	blinded, e := server.IssueProfile(uid, requestKey.Public(), request.Public(), 100, s)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = z.NewProfileIssuanceProof(server, requestKey.Public(), request.Public(), blinded, uid, 101, s); !errors.Is(e, z.ErrVerification) {
		t.Fatal("proved inconsistent expiration")
	}
	receiptKey := z.GenerateReceiptRequestKeyPair(s)
	receiptRequest := receiptKey.Encrypt(uuid, s)
	rs, e := z.GenerateCredentialKeyPair(z.ReceiptCredentialKind, s)
	if e != nil {
		t.Fatal(e)
	}
	rb, e := rs.IssueReceipt(receiptKey.Public(), receiptRequest.Public(), 100, 5, s)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = z.NewReceiptIssuanceProof(rs, receiptKey.Public(), receiptRequest.Public(), rb, 100, 6, s); !errors.Is(e, z.ErrVerification) {
		t.Fatal("proved inconsistent level")
	}
	// Unblinding is intentionally not authentication. A well-formed altered KVAC
	// can produce a proof, but the server must reject the resulting presentation.
	credential := requestKey.Unblind(blinded.Public())
	encoded := credential.Bytes()
	clear(encoded[64:])
	altered, e := z.ParseCredential(encoded)
	if e != nil {
		t.Fatal(e)
	}
	uk, pk := z.DeriveUIDKeyPair(s), z.DeriveProfileKeyKeyPair(s)
	uc, pc := uk.Encrypt(uid), pk.Encrypt(profile)
	presentation, e := z.NewProfilePresentationProof(uk, pk, server.Public(), altered, uc, pc, uuid, raw, s)
	if e != nil {
		t.Fatal(e)
	}
	if e = presentation.Verify(server, uc, uk.PublicKeyBytes(), pc, pk.PublicKeyBytes(), 100); !errors.Is(e, z.ErrVerification) {
		t.Fatal("accepted corrupted credential")
	}
	// Malformed encryption public keys are rejected before proof arithmetic.
	if e = presentation.Verify(server, uc, nil, pc, pk.PublicKeyBytes(), 100); !errors.Is(e, z.ErrVerification) {
		t.Fatal("accepted malformed UID key")
	}
	if e = presentation.Verify(server, uc, uk.PublicKeyBytes(), pc, nil, 100); !errors.Is(e, z.ErrVerification) {
		t.Fatal("accepted malformed profile key")
	}
}
