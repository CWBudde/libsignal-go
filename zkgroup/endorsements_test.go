// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package zkgroup_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/internal/zkgroupserver"
	"github.com/cwbudde/libsignal-go/zkgroup"
)

func TestGroupSendPolicies(t *testing.T) {
	server, e := zkgroupserver.Generate([32]byte{1})
	if e != nil {
		t.Fatal(e)
	}
	group := zkgroup.DeriveGroupSecretParams(zkgroup.GroupMasterKey{2})
	ids := []address.ServiceID{address.NewACI([16]byte{3}), address.NewPNI([16]byte{3})}
	ciphertexts := []zkgroup.UUIDCiphertext{group.EncryptServiceID(ids[0]), group.EncryptServiceID(ids[1])}
	const expiration = 20000 * 86400
	for _, expiry := range []uint64{expiration, expiration + 1, 0, ^uint64(0)} {
		response, e := server.IssueEndorsements(ciphertexts, expiry, [32]byte{4})
		if e != nil {
			t.Fatal(e)
		}
		_, e = response.ReceiveWithServiceIDs(ids, expiration-86400, group, server.Public())
		if (e == nil) != (expiry == expiration) {
			t.Fatalf("expiry %d: %v", expiry, e)
		}
	}
	response, e := server.IssueEndorsements(ciphertexts, expiration, [32]byte{4})
	if e != nil {
		t.Fatal(e)
	}
	for _, ids := range [][]address.ServiceID{nil, ids[:1], {ids[0], ids[0]}} {
		if _, e = response.ReceiveWithServiceIDs(ids, expiration-86400, group, server.Public()); !errors.Is(e, zkgroup.ErrVerification) {
			t.Fatalf("wrong members: %v", e)
		}
	}
	received, e := response.ReceiveWithServiceIDs(ids, expiration-86400, group, server.Public())
	if e != nil {
		t.Fatal(e)
	}
	combined := zkgroup.CombineGroupSendEndorsements(received...)
	token := combined.Remove(received[0]).ToToken(group).ToFullToken(expiration)
	if e = server.VerifyGroupSendToken(token, ids[1:], expiration); e != nil {
		t.Fatal(e)
	}
	if e = server.VerifyGroupSendToken(token, ids[1:], expiration+1); e == nil {
		t.Fatal("accepted expired token")
	}
	if e = server.VerifyGroupSendToken(token, ids, expiration); e == nil {
		t.Fatal("accepted wrong recipient set")
	}
	if e = server.VerifyGroupSendToken(combined.Remove(received[0]).Remove(received[0]).ToToken(group).ToFullToken(expiration), ids[1:], expiration); e == nil {
		t.Fatal("accepted excess removal")
	}
	if e = server.VerifyGroupSendToken(zkgroup.CombineGroupSendEndorsements(received[1], received[1]).ToToken(group).ToFullToken(expiration), ids[1:], expiration); e == nil {
		t.Fatal("duplicates lost multiplicity")
	}
	// An empty response is structurally valid but must reject receipt without panicking.
	empty, e := zkgroup.ParseGroupSendEndorsementsResponse(binary.LittleEndian.AppendUint64(make([]byte, 17), expiration))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = empty.ReceiveWithServiceIDs(nil, expiration-86400, group, server.Public()); e == nil {
		t.Fatal("accepted empty response")
	}
}
func TestGroupSendEncodings(t *testing.T) {
	server, e := zkgroupserver.Generate([32]byte{1})
	if e != nil {
		t.Fatal(e)
	}
	group := zkgroup.DeriveGroupSecretParams(zkgroup.GroupMasterKey{2})
	response, e := server.IssueEndorsements([]zkgroup.UUIDCiphertext{group.EncryptServiceID(address.NewACI([16]byte{3}))}, 20000*86400, [32]byte{4})
	if e != nil {
		t.Fatal(e)
	}
	endorsement := zkgroup.CombineGroupSendEndorsements()
	token := endorsement.ToToken(group)
	cases := []struct {
		data  []byte
		parse func([]byte) ([]byte, error)
	}{
		{response.Bytes(), func(b []byte) ([]byte, error) {
			v, e := zkgroup.ParseGroupSendEndorsementsResponse(b)
			if e != nil {
				return nil, e
			}
			return v.Bytes(), nil
		}},
		{endorsement.Bytes(), func(b []byte) ([]byte, error) {
			v, e := zkgroup.ParseGroupSendEndorsement(b)
			if e != nil {
				return nil, e
			}
			return v.Bytes(), nil
		}},
		{token.Bytes(), func(b []byte) ([]byte, error) {
			v, e := zkgroup.ParseGroupSendToken(b)
			if e != nil {
				return nil, e
			}
			return v.Bytes(), nil
		}},
		{token.ToFullToken(20000 * 86400).Bytes(), func(b []byte) ([]byte, error) {
			v, e := zkgroup.ParseGroupSendFullToken(b)
			if e != nil {
				return nil, e
			}
			return v.Bytes(), nil
		}},
	}
	for _, c := range cases {
		got, e := c.parse(c.data)
		if e != nil || !bytes.Equal(got, c.data) {
			t.Fatal("roundtrip", e)
		}
		for i := range len(c.data) {
			if _, e = c.parse(c.data[:i]); e == nil {
				t.Fatalf("accepted truncated %d/%d", i, len(c.data))
			}
		}
		b := append(bytes.Clone(c.data), 0)
		if _, e = c.parse(b); e == nil {
			t.Fatal("accepted trailing data")
		}
		b = bytes.Clone(c.data)
		b[0] = 1
		if _, e = c.parse(b); e == nil {
			t.Fatal("accepted version")
		}
	}
	b := bytes.Repeat([]byte{255}, 33)
	b[0] = 0
	if _, e := zkgroup.ParseGroupSendEndorsement(b); e == nil {
		t.Fatal("accepted noncanonical point")
	}
	// Rust token parsers accept arbitrary opaque lengths; verification rejects them.
	short, e := zkgroup.ParseGroupSendToken(make([]byte, 9))
	if e != nil {
		t.Fatal(e)
	}
	if e = server.VerifyGroupSendToken(short.ToFullToken(20000*86400), nil, 0); e == nil {
		t.Fatal("accepted empty bearer")
	}
}
func FuzzGroupSendEncoding(f *testing.F) {
	f.Add(make([]byte, 33))
	f.Add(make([]byte, 25))
	f.Add(make([]byte, 9))
	f.Add([]byte{255})
	f.Fuzz(func(t *testing.T, b []byte) {
		check := func(got []byte, e error) {
			if e == nil && !bytes.Equal(got, b) {
				t.Fatal("noncanonical roundtrip")
			}
		}
		if v, e := zkgroup.ParseGroupSendEndorsementsResponse(b); e == nil {
			check(v.Bytes(), e)
		}
		if v, e := zkgroup.ParseGroupSendEndorsement(b); e == nil {
			check(v.Bytes(), e)
		}
		if v, e := zkgroup.ParseGroupSendToken(b); e == nil {
			check(v.Bytes(), e)
		}
		if v, e := zkgroup.ParseGroupSendFullToken(b); e == nil {
			check(v.Bytes(), e)
		}
	})
}
