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
	"github.com/cwbudde/libsignal-go/internal/zkgroupserver"
	"github.com/cwbudde/libsignal-go/zkgroup"
)

type groupSendParams struct {
	Seed       string   `json:"seed"`
	Randomness string   `json:"randomness"`
	MasterKey  string   `json:"master_key"`
	Members    []string `json:"members"`
	Now        uint64   `json:"now"`
	Expiration uint64   `json:"expiration"`
}
type groupSendResult struct {
	Server       string   `json:"server"`
	Response     string   `json:"response"`
	Ciphertexts  []string `json:"ciphertexts"`
	Endorsements []string `json:"endorsements"`
	Combined     string   `json:"combined"`
	Removed      string   `json:"removed"`
	Empty        string   `json:"empty"`
	Token        string   `json:"token"`
	FullToken    string   `json:"full_token"`
}
type groupSendCase struct {
	Params groupSendParams `json:"params"`
	Result groupSendResult `json:"result"`
}

func loadGroupSend(t *testing.T) []groupSendCase {
	t.Helper()
	b, e := os.ReadFile("vectors/group-send.json")
	legacyCheck(t, e)
	var data struct {
		Cases []groupSendCase `json:"cases"`
	}
	legacyCheck(t, json.Unmarshal(b, &data))
	return data.Cases
}
func groupSendInputs(t *testing.T, p groupSendParams) (*zkgroupserver.Server, *zkgroup.GroupSecretParams, []address.ServiceID) {
	t.Helper()
	server, e := zkgroupserver.Generate([32]byte(zkBytes(t, p.Seed)))
	legacyCheck(t, e)
	group := zkgroup.DeriveGroupSecretParams(zkgroup.GroupMasterKey(zkBytes(t, p.MasterKey)))
	members := make([]address.ServiceID, len(p.Members))
	for i, id := range p.Members {
		members[i], e = address.ParseServiceIDFixedWidthBinary([17]byte(zkBytes(t, id)))
		legacyCheck(t, e)
	}
	return server, group, members
}
func runGroupSend(t *testing.T, p groupSendParams) groupSendResult {
	t.Helper()
	server, group, members := groupSendInputs(t, p)
	ciphertexts := make([]zkgroup.UUIDCiphertext, len(members))
	result := groupSendResult{Server: hex.EncodeToString(server.Public().Bytes()), Ciphertexts: make([]string, len(members)), Endorsements: make([]string, len(members))}
	for i, id := range members {
		ciphertexts[i] = group.EncryptServiceID(id)
		result.Ciphertexts[i] = hex.EncodeToString(ciphertexts[i].Bytes())
	}
	response, e := server.IssueEndorsements(ciphertexts, p.Expiration, [32]byte(zkBytes(t, p.Randomness)))
	legacyCheck(t, e)
	result.Response = hex.EncodeToString(response.Bytes())
	received, e := response.ReceiveWithServiceIDs(members, p.Now, group, server.Public())
	legacyCheck(t, e)
	fromCiphertexts, e := response.ReceiveWithCiphertexts(ciphertexts, p.Now, server.Public())
	legacyCheck(t, e)
	for i, end := range received {
		result.Endorsements[i] = hex.EncodeToString(end.Bytes())
		if !reflect.DeepEqual(end.Bytes(), fromCiphertexts[i].Bytes()) {
			t.Fatal("ciphertext receipt differs")
		}
	}
	combined := zkgroup.CombineGroupSendEndorsements(received[1:]...)
	result.Combined = hex.EncodeToString(combined.Bytes())
	result.Removed = hex.EncodeToString(zkgroup.CombineGroupSendEndorsements(received...).Remove(received[0]).Bytes())
	result.Empty = hex.EncodeToString(zkgroup.CombineGroupSendEndorsements().Bytes())
	token := combined.ToToken(group)
	result.Token = hex.EncodeToString(token.Bytes())
	full := token.ToFullToken(p.Expiration)
	result.FullToken = hex.EncodeToString(full.Bytes())
	legacyCheck(t, server.VerifyGroupSendToken(full, members[1:], p.Now))
	return result
}
func verifyGroupSend(t *testing.T, p groupSendParams, a groupSendResult) map[string]bool {
	t.Helper()
	server, group, members := groupSendInputs(t, p)
	response, e := zkgroup.ParseGroupSendEndorsementsResponse(zkBytes(t, a.Response))
	if e == nil {
		_, e = response.ReceiveWithServiceIDs(members, p.Now, group, server.Public())
	}
	out := map[string]bool{"receive": e == nil}
	token, e := zkgroup.ParseGroupSendFullToken(zkBytes(t, a.FullToken))
	if e == nil {
		e = server.VerifyGroupSendToken(token, members[1:], p.Now)
	}
	out["token"] = e == nil
	return out
}
func TestGroupSendVectors(t *testing.T) {
	for i, c := range loadGroupSend(t) {
		got := runGroupSend(t, c.Params)
		if !reflect.DeepEqual(got, c.Result) {
			t.Fatalf("case %d differs from Rust\nGo=%+v\nRust=%+v", i, got, c.Result)
		}
		for k, valid := range verifyGroupSend(t, c.Params, c.Result) {
			if !valid {
				t.Fatalf("case %d rejected Rust %s", i, k)
			}
		}
	}
}
