// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package compat

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/poksho"
	z "github.com/cwbudde/libsignal-go/zkgroup/zkcrypto"
)

type legacyParams struct {
	Seed       string `json:"seed"`
	UUID       string `json:"uuid"`
	ProfileKey string `json:"profile_key"`
	Serial     string `json:"serial"`
	Message    string `json:"message"`
	Timestamp  uint64 `json:"timestamp"`
	Level      uint64 `json:"level"`
}
type legacyVectors struct {
	UpstreamTag string `json:"upstream_tag"`
	System      string `json:"system"`
	Cases       []struct {
		Params legacyParams      `json:"params"`
		Result map[string]string `json:"result"`
	} `json:"cases"`
}

func loadLegacy(t *testing.T) legacyVectors {
	t.Helper()
	b, e := os.ReadFile("vectors/zkgroup-credentials.json")
	legacyCheck(t, e)
	var v legacyVectors
	legacyCheck(t, json.Unmarshal(b, &v))
	if v.UpstreamTag != "v0.102.2" || len(v.Cases) != 24 {
		t.Fatal("unexpected credential vector metadata")
	}
	return v
}
func legacyCheck(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func runLegacy(t *testing.T, p legacyParams) map[string]string {
	t.Helper()
	out := map[string]string{}
	put := func(name string, b []byte) { out[name] = hex.EncodeToString(b) }
	s := poksho.NewShoHmacSha256([]byte("Compat_ZKGroup_Credentials"))
	s.AbsorbAndRatchet(zkBytes(t, p.Seed))
	names := []string{"key_auth", "key_auth_pni", "key_profile", "key_expiring", "key_receipt", "key_pni"}
	kinds := []z.CredentialKind{z.AuthCredentialKind, z.AuthWithPNICredentialKind, z.ProfileCredentialKind, z.ExpiringProfileCredentialKind, z.ReceiptCredentialKind, z.PNICredentialKind}
	keys := make([]z.CredentialKeyPair, len(names))
	for i, name := range names {
		k, e := z.GenerateCredentialKeyPair(kinds[i], s)
		legacyCheck(t, e)
		keys[i] = k
		put(name, k.Bytes())
	}
	server, rs := keys[3], keys[4]
	put("public_expiring", server.Public().Bytes())
	put("public_receipt", rs.Public().Bytes())
	signing := z.GenerateSignatureKeyPair(s)
	put("signing_key", signing.Bytes())
	put("signing_public", signing.Public().Bytes())
	sig, e := signing.Sign(zkBytes(t, p.Message), s)
	legacyCheck(t, e)
	put("signature", sig)
	uuid, key, serial := [16]byte(zkBytes(t, p.UUID)), [32]byte(zkBytes(t, p.ProfileKey)), [16]byte(zkBytes(t, p.Serial))
	uid, profile := z.NewUID(address.NewACI(uuid)), z.NewProfileKey(key, uuid)
	commitment := z.NewProfileKeyCommitment(key, uuid)
	put("commitment", commitment.Public().Bytes())
	requestKey := z.GenerateProfileRequestKeyPair(s)
	request := requestKey.Encrypt(profile, s)
	put("request_key", requestKey.Bytes())
	put("request_public", requestKey.Public().Bytes())
	put("request_with_nonce", request.Bytes())
	put("request", request.Public().Bytes())
	requestProof, e := z.NewProfileRequestProof(requestKey, request, commitment, s)
	legacyCheck(t, e)
	put("request_proof", requestProof.Bytes())
	blinded, e := server.IssueProfile(uid, requestKey.Public(), request.Public(), p.Timestamp, s)
	legacyCheck(t, e)
	put("blinded_with_nonce", blinded.Bytes())
	put("blinded", blinded.Public().Bytes())
	issuance, e := z.NewProfileIssuanceProof(server, requestKey.Public(), request.Public(), blinded, uid, p.Timestamp, s)
	legacyCheck(t, e)
	put("issuance_proof", issuance.Bytes())
	credential := requestKey.Unblind(blinded.Public())
	put("credential", credential.Bytes())
	uk, pk := z.DeriveUIDKeyPair(s), z.DeriveProfileKeyKeyPair(s)
	put("uid_key", uk.Bytes())
	put("profile_enc_key", pk.Bytes())
	put("uid_public", uk.PublicKeyBytes())
	put("profile_enc_public", pk.PublicKeyBytes())
	uc, pc := uk.Encrypt(uid), pk.Encrypt(profile)
	put("uid_ciphertext", uc.Bytes())
	put("profile_ciphertext", pc.Bytes())
	presentation, e := z.NewProfilePresentationProof(uk, pk, server.Public(), credential, uc, pc, uuid, key, s)
	legacyCheck(t, e)
	put("presentation", presentation.Bytes())
	rk := z.GenerateReceiptRequestKeyPair(s)
	rc := rk.Encrypt(serial, s)
	put("receipt_request_key", rk.Bytes())
	put("receipt_request_public", rk.Public().Bytes())
	put("receipt_request_with_nonce", rc.Bytes())
	put("receipt_request", rc.Public().Bytes())
	rb, e := rs.IssueReceipt(rk.Public(), rc.Public(), p.Timestamp, p.Level, s)
	legacyCheck(t, e)
	put("receipt_blinded_with_nonce", rb.Bytes())
	put("receipt_blinded", rb.Public().Bytes())
	ri, e := z.NewReceiptIssuanceProof(rs, rk.Public(), rc.Public(), rb, p.Timestamp, p.Level, s)
	legacyCheck(t, e)
	put("receipt_issuance", ri.Bytes())
	rcred := rk.Unblind(rb.Public())
	put("receipt_credential", rcred.Bytes())
	rp, e := z.NewReceiptPresentationProof(rs.Public(), rcred, s)
	legacyCheck(t, e)
	put("receipt_presentation", rp.Bytes())
	receipt := z.Receipt{Serial: serial, Expiration: p.Timestamp, Level: p.Level}
	put("receipt", receipt.Bytes())
	put("receipt_scalar", z.ReceiptScalar(p.Timestamp, p.Level).Bytes())
	put("transcript_tail", s.SqueezeAndRatchet(32))
	return out
}
func TestZKGroupCredentialVectors(t *testing.T) {
	v := loadLegacy(t)
	if hex.EncodeToString(z.CredentialSystemParams()) != v.System {
		t.Fatal("credential system mismatch")
	}
	for i, c := range v.Cases {
		got := runLegacy(t, c.Params)
		if len(got) != len(c.Result) {
			t.Fatal("artifact count mismatch")
		}
		for name, want := range c.Result {
			if got[name] != want {
				t.Fatalf("case %d %s mismatch\ngot %s\nwant %s", i, name, got[name], want)
			}
		}
		for name, ok := range verifyLegacy(t, c.Params, c.Result) {
			if !ok {
				t.Fatalf("case %d: rejected Rust %s", i, name)
			}
		}
	}
}

func verifyLegacy(t *testing.T, p legacyParams, a map[string]string) map[string]bool {
	t.Helper()
	uuid, serial := [16]byte(zkBytes(t, p.UUID)), [16]byte(zkBytes(t, p.Serial))
	receipt := z.Receipt{Serial: serial, Expiration: p.Timestamp, Level: p.Level}
	result := map[string]bool{}
	result["signature"] = func() bool {
		k, e := z.ParseSignaturePublicKey(zkBytes(t, a["signing_public"]))
		if e != nil {
			return false
		}
		return k.Verify(zkBytes(t, p.Message), zkBytes(t, a["signature"])) == nil
	}()
	result["request"] = func() bool {
		proof, e := z.ParseProfileRequestProof(zkBytes(t, a["request_proof"]))
		if e != nil {
			return false
		}
		k, e := z.ParseProfileRequestPublicKey(zkBytes(t, a["request_public"]))
		if e != nil {
			return false
		}
		c, e := z.ParseProfileRequestCiphertext(zkBytes(t, a["request"]))
		if e != nil {
			return false
		}
		j, e := z.ParseProfileKeyCommitment(zkBytes(t, a["commitment"]))
		if e != nil {
			return false
		}
		return proof.Verify(k, c, j) == nil
	}()
	result["issuance"] = func() bool {
		proof, e := z.ParseProfileIssuanceProof(zkBytes(t, a["issuance_proof"]))
		if e != nil {
			return false
		}
		k, e := z.ParseCredentialPublicKey(zkBytes(t, a["public_expiring"]))
		if e != nil {
			return false
		}
		r, e := z.ParseProfileRequestPublicKey(zkBytes(t, a["request_public"]))
		if e != nil {
			return false
		}
		c, e := z.ParseProfileRequestCiphertext(zkBytes(t, a["request"]))
		if e != nil {
			return false
		}
		b, e := z.ParseBlindedCredential(zkBytes(t, a["blinded"]))
		if e != nil {
			return false
		}
		return proof.Verify(k, r, uuid, c, b, p.Timestamp) == nil
	}()
	result["presentation"] = func() bool {
		proof, e := z.ParseProfilePresentationProof(zkBytes(t, a["presentation"]))
		if e != nil {
			return false
		}
		k, e := z.ParseCredentialKeyPair(z.ExpiringProfileCredentialKind, zkBytes(t, a["key_expiring"]))
		if e != nil {
			return false
		}
		uc, e := z.ParseUIDCiphertext(zkBytes(t, a["uid_ciphertext"]))
		if e != nil {
			return false
		}
		pc, e := z.ParseProfileKeyCiphertext(zkBytes(t, a["profile_ciphertext"]))
		if e != nil {
			return false
		}
		return proof.Verify(k, uc, zkBytes(t, a["uid_public"]), pc, zkBytes(t, a["profile_enc_public"]), p.Timestamp) == nil
	}()
	result["receipt_issuance"] = func() bool {
		proof, e := z.ParseReceiptIssuanceProof(zkBytes(t, a["receipt_issuance"]))
		if e != nil {
			return false
		}
		k, e := z.ParseCredentialPublicKey(zkBytes(t, a["public_receipt"]))
		if e != nil {
			return false
		}
		r, e := z.ParseReceiptRequestPublicKey(zkBytes(t, a["receipt_request_public"]))
		if e != nil {
			return false
		}
		c, e := z.ParseReceiptRequestCiphertext(zkBytes(t, a["receipt_request"]))
		if e != nil {
			return false
		}
		b, e := z.ParseBlindedCredential(zkBytes(t, a["receipt_blinded"]))
		if e != nil {
			return false
		}
		return proof.Verify(k, r, c, b, receipt) == nil
	}()
	result["receipt_presentation"] = func() bool {
		proof, e := z.ParseReceiptPresentationProof(zkBytes(t, a["receipt_presentation"]))
		if e != nil {
			return false
		}
		k, e := z.ParseCredentialKeyPair(z.ReceiptCredentialKind, zkBytes(t, a["key_receipt"]))
		if e != nil {
			return false
		}
		return proof.Verify(k, receipt) == nil
	}()
	return result
}
