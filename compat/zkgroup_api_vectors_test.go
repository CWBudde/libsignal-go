// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package compat

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/internal/zkgroupserver"
	"github.com/cwbudde/libsignal-go/zkgroup"
	"os"
	"reflect"
	"testing"
)

type apiParams struct {
	Seed       string `json:"seed"`
	Randomness string `json:"randomness"`
	MasterKey  string `json:"master_key"`
	ACI        string `json:"aci"`
	PNI        string `json:"pni"`
	ProfileKey string `json:"profile_key"`
	Message    string `json:"message"`
	Padding    uint32 `json:"padding"`
	Now        uint64 `json:"now"`
	Redemption uint64 `json:"redemption"`
	Expiration uint64 `json:"expiration"`
}
type apiCase struct {
	Params apiParams         `json:"params"`
	Result map[string]string `json:"result"`
}

func loadAPI(t *testing.T) []apiCase {
	t.Helper()
	b, e := os.ReadFile("vectors/zkgroup-api.json")
	legacyCheck(t, e)
	var v struct {
		Cases []apiCase `json:"cases"`
	}
	legacyCheck(t, json.Unmarshal(b, &v))
	return v.Cases
}
func runAPI(t *testing.T, p apiParams) map[string]string {
	t.Helper()
	raw := func(s string) []byte { return zkBytes(t, s) }
	seed, r := [32]byte(raw(p.Seed)), [32]byte(raw(p.Randomness))
	aci, pni := [16]byte(raw(p.ACI)), [16]byte(raw(p.PNI))
	key := zkgroup.ProfileKey(raw(p.ProfileKey))
	server, e := zkgroupserver.Generate(seed)
	legacyCheck(t, e)
	public := server.Public()
	group := zkgroup.DeriveGroupSecretParams(zkgroup.GroupMasterKey(raw(p.MasterKey)))
	signature, e := server.Sign(r, raw(p.Message))
	legacyCheck(t, e)
	blob, e := group.EncryptBlob(r, raw(p.Message), p.Padding)
	legacyCheck(t, e)
	context, e := public.CreateProfileKeyCredentialRequestContext(r, aci, key)
	legacyCheck(t, e)
	request := context.Request()
	response, e := server.IssueProfile(r, request, aci, key.Commitment(aci), p.Expiration)
	legacyCheck(t, e)
	credential, e := public.ReceiveExpiringProfileKeyCredential(context, response, p.Now)
	legacyCheck(t, e)
	presentation, e := public.CreateExpiringProfileKeyCredentialPresentation(r, group, credential)
	legacyCheck(t, e)
	authResponse, e := server.IssueAuth(r, aci, pni, p.Redemption)
	legacyCheck(t, e)
	authCredential, e := public.ReceiveAuthCredentialWithPni(aci, pni, p.Redemption, authResponse)
	legacyCheck(t, e)
	authPresentation, e := public.CreateAuthCredentialPresentation(r, group, authCredential)
	legacyCheck(t, e)
	id := group.Public().Identifier()
	commitment := key.Commitment(aci)
	version := key.Version(aci)
	access := key.AccessKey()
	values := map[string][]byte{"server": public.Bytes(), "signature": signature[:], "group": group.Bytes(), "generated_group": zkgroup.GenerateGroupSecretParams(r).Bytes(), "group_public": group.Public().Bytes(), "group_id": id[:], "aci_ciphertext": group.EncryptServiceID(address.NewACI(aci)).Bytes(), "pni_ciphertext": group.EncryptServiceID(address.NewPNI(pni)).Bytes(), "profile_ciphertext": group.EncryptProfileKey(key, aci).Bytes(), "blob": blob, "commitment": commitment[:], "version": version[:], "access_key": access[:], "context": context.Bytes(), "request": request.Bytes(), "profile_response": response.Bytes(), "profile_credential": credential.Bytes(), "profile_presentation": presentation.Bytes(), "auth_response": authResponse.Bytes(), "auth_credential": authCredential.Bytes(), "auth_presentation": authPresentation.Bytes()}
	out := map[string]string{}
	for k, v := range values {
		out[k] = hex.EncodeToString(v)
	}
	return out
}
func verifyAPI(t *testing.T, p apiParams, a map[string]string) map[string]bool {
	t.Helper()
	raw := func(s string) []byte { return zkBytes(t, s) }
	get := func(s string) []byte { return raw(a[s]) }
	server, e := zkgroupserver.Generate([32]byte(raw(p.Seed)))
	legacyCheck(t, e)
	public := server.Public()
	group := zkgroup.DeriveGroupSecretParams(zkgroup.GroupMasterKey(raw(p.MasterKey)))
	aci, pni := [16]byte(raw(p.ACI)), [16]byte(raw(p.PNI))
	out := map[string]bool{}
	sig := get("signature")
	out["signature"] = len(sig) == 64 && public.VerifySignature(raw(p.Message), zkgroup.NotarySignature(sig)) == nil
	presentation, e := zkgroup.ParseProfileKeyCredentialPresentation(get("profile_presentation"))
	out["profile_presentation"] = e == nil && server.VerifyProfile(group.Public(), presentation, p.Now) == nil
	auth, e := zkgroup.ParseAuthCredentialPresentation(get("auth_presentation"))
	out["auth_presentation"] = e == nil && server.VerifyAuth(group.Public(), auth, p.Now) == nil
	context, e := zkgroup.ParseProfileKeyCredentialRequestContext(get("context"))
	response, er := zkgroup.ParseExpiringProfileKeyCredentialResponse(get("profile_response"))
	out["profile_receive"] = false
	if e == nil && er == nil {
		_, e = public.ReceiveExpiringProfileKeyCredential(context, response, p.Now)
		out["profile_receive"] = e == nil
	}
	ar, e := zkgroup.ParseAuthCredentialWithPniResponse(get("auth_response"))
	out["auth_receive"] = false
	if e == nil {
		_, e = public.ReceiveAuthCredentialWithPni(aci, pni, p.Redemption, ar)
		out["auth_receive"] = e == nil
	}
	u, e := zkgroup.ParseUUIDCiphertext(get("aci_ciphertext"))
	out["uid"] = false
	if e == nil {
		id, er := group.DecryptServiceID(u)
		out["uid"] = er == nil && id == address.NewACI(aci)
	}
	c, e := zkgroup.ParseProfileKeyCiphertext(get("profile_ciphertext"))
	out["profile_key"] = false
	if e == nil {
		k, er := group.DecryptProfileKey(c, aci)
		out["profile_key"] = er == nil && bytes.Equal(k[:], raw(p.ProfileKey))
	}
	b, e := group.DecryptBlob(get("blob"))
	out["blob"] = e == nil && bytes.Equal(b, raw(p.Message))
	return out
}
func TestZKGroupAPIVectors(t *testing.T) {
	for _, c := range loadAPI(t) {
		got := runAPI(t, c.Params)
		if !reflect.DeepEqual(got, c.Result) {
			for k, v := range c.Result {
				if got[k] != v {
					t.Errorf("%s mismatch\ngot %s\nwant %s", k, got[k], v)
				}
			}
			t.FailNow()
		}
		for k, v := range verifyAPI(t, c.Params, c.Result) {
			if !v {
				t.Errorf("rejected %s", k)
			}
		}
	}
}
