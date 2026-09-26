// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package compat

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/internal/ristrettolizard"
	"github.com/cwbudde/libsignal-go/poksho"
	"github.com/cwbudde/libsignal-go/zkgroup/zkcrypto"
)

type zkParams struct {
	Seed       string `json:"seed"`
	UUID       string `json:"uuid"`
	ProfileKey string `json:"profile_key"`
	PNI        bool   `json:"pni"`
	Timestamp  uint64 `json:"timestamp"`
}

type zkResult struct {
	UID                 string    `json:"uid"`
	Profile             string    `json:"profile"`
	UIDKey              string    `json:"uid_key"`
	ProfileKeyPair      string    `json:"profile_key_pair"`
	UIDCiphertext       string    `json:"uid_ciphertext"`
	ProfileCiphertext   string    `json:"profile_ciphertext"`
	ProfileDecrypts     bool      `json:"profile_decrypts"`
	Commitment          string    `json:"commitment"`
	CommitmentWithNonce string    `json:"commitment_with_nonce"`
	TimestampBytes      string    `json:"timestamp_bytes"`
	TimestampScalar     string    `json:"timestamp_scalar"`
	Map                 string    `json:"map"`
	Inverse             []*string `json:"inverse"`
}

type zkVectors struct {
	UpstreamTag      string `json:"upstream_tag"`
	UIDSystem        string `json:"uid_system"`
	ProfileSystem    string `json:"profile_system"`
	CommitmentSystem string `json:"commitment_system"`
	Cases            []struct {
		Params zkParams `json:"params"`
		Result zkResult `json:"result"`
	} `json:"cases"`
}

func loadZK(t *testing.T) zkVectors {
	t.Helper()
	b, err := os.ReadFile("vectors/zkgroup-crypto.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors zkVectors
	if err := json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.UpstreamTag != "v0.102.2" || len(vectors.Cases) < 40 {
		t.Fatal("unexpected zkgroup vector metadata")
	}
	return vectors
}

func zkBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func zkKeys(t *testing.T, seed string) (zkcrypto.UIDKeyPair, zkcrypto.ProfileKeyKeyPair) {
	t.Helper()
	s := poksho.NewShoHmacSha256([]byte("Signal_ZKGroup_20200424_GroupMasterKey_GroupSecretParams_DeriveFromMasterKey"))
	s.AbsorbAndRatchet(zkBytes(t, seed))
	s.SqueezeAndRatchet(32) // group ID
	s.SqueezeAndRatchet(32) // blob key; separate ratchet is part of the transcript
	return zkcrypto.DeriveUIDKeyPair(s), zkcrypto.DeriveProfileKeyKeyPair(s)
}

func runZK(t *testing.T, p zkParams) zkResult {
	t.Helper()
	uuid, key := [16]byte(zkBytes(t, p.UUID)), [32]byte(zkBytes(t, p.ProfileKey))
	id := address.NewACI(uuid)
	if p.PNI {
		id = address.NewPNI(uuid)
	}
	uid, profile := zkcrypto.NewUID(id), zkcrypto.NewProfileKey(key, uuid)
	uKey, pKey := zkKeys(t, p.Seed)
	uCipher, pCipher := uKey.Encrypt(uid), pKey.Encrypt(profile)
	if got, err := uKey.Decrypt(uCipher); err != nil || got != id {
		t.Fatalf("UID decrypt: %v %v", got, err)
	}
	decrypted, decryptErr := pKey.Decrypt(pCipher, uuid)
	if decryptErr == nil && decrypted != key {
		t.Fatalf("profile decrypt: %x", decrypted)
	}
	commitment := zkcrypto.NewProfileKeyCommitment(key, uuid)
	point := ristrettolizard.Map(key)
	inverses := make([]*string, 8)
	for i, c := range ristrettolizard.Inverse(point) {
		if c.Valid == 1 {
			s := hex.EncodeToString(c.Bytes[:])
			inverses[i] = &s
		}
	}
	return zkResult{
		UID: hex.EncodeToString(uid.Bytes()), Profile: hex.EncodeToString(profile.Bytes()),
		UIDKey: hex.EncodeToString(uKey.Bytes()), ProfileKeyPair: hex.EncodeToString(pKey.Bytes()),
		UIDCiphertext: hex.EncodeToString(uCipher.Bytes()), ProfileCiphertext: hex.EncodeToString(pCipher.Bytes()),
		Commitment: hex.EncodeToString(commitment.Public().Bytes()), CommitmentWithNonce: hex.EncodeToString(commitment.Bytes()),
		TimestampBytes: hex.EncodeToString(zkcrypto.TimestampBytes(p.Timestamp)), TimestampScalar: hex.EncodeToString(zkcrypto.TimestampScalar(p.Timestamp).Bytes()),
		Map: hex.EncodeToString(point.Bytes()), Inverse: inverses, ProfileDecrypts: decryptErr == nil,
	}
}

func TestZKGroupCryptoVectors(t *testing.T) {
	v := loadZK(t)
	for _, pair := range []struct {
		want string
		got  []byte
	}{
		{v.UIDSystem, zkcrypto.UIDEncryptionSystemParams()},
		{v.ProfileSystem, zkcrypto.ProfileKeyEncryptionSystemParams()},
		{v.CommitmentSystem, zkcrypto.CommitmentSystemParams()},
	} {
		if hex.EncodeToString(pair.got) != pair.want {
			t.Fatal("system parameter mismatch")
		}
	}
	for i, c := range v.Cases {
		got := runZK(t, c.Params)
		if !reflect.DeepEqual(got, c.Result) {
			t.Fatalf("case %d mismatch\ngot: %+v\nwant: %+v", i, got, c.Result)
		}
	}
}
