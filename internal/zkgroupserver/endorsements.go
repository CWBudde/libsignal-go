// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package zkgroupserver

import (
	"bytes"
	"encoding/binary"
	"slices"

	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/poksho"
	"github.com/cwbudde/libsignal-go/zkcredential"
	"github.com/cwbudde/libsignal-go/zkgroup"
	"github.com/cwbudde/libsignal-go/zkgroup/zkcrypto"
	"github.com/gtank/ristretto255"
)

func (s *Server) endorsementKey(expiration uint64) *zkcredential.ServerDerivedKeyPair {
	sho := poksho.NewShoHmacSha256([]byte("20240215_Signal_GroupSendEndorsement"))
	sho.AbsorbAndRatchet(binary.BigEndian.AppendUint64(nil, expiration))
	return s.endorsements.DeriveKey(sho)
}

// IssueEndorsements creates a test response from encrypted group members.
func (s *Server) IssueEndorsements(members []zkgroup.UUIDCiphertext, expiration uint64, randomness [32]byte) (*zkgroup.GroupSendEndorsementsResponse, error) {
	type entry struct {
		point *ristretto255.Element
		key   []byte
	}
	entries := make([]entry, len(members))
	for i, c := range members {
		p, e := ristretto255.NewIdentityElement().SetCanonicalBytes(c.Bytes()[1:33])
		if e != nil {
			return nil, e
		}
		entries[i] = entry{p, ristretto255.NewIdentityElement().Add(p, p).Bytes()}
	}
	slices.SortFunc(entries, func(a, b entry) int { return bytes.Compare(a.key, b.key) })
	points := make([]*ristretto255.Element, len(entries))
	for i, e := range entries {
		points[i] = e.point
	}
	response, e := zkcredential.IssueEndorsements(points, s.endorsementKey(expiration), randomness)
	if e != nil {
		return nil, e
	}
	return zkgroup.ParseGroupSendEndorsementsResponse(binary.LittleEndian.AppendUint64(append([]byte{0}, response.Bytes()...), expiration))
}

// VerifyGroupSendToken authenticates a bearer token, its exact recipient set and
// expiry. As in Rust, the expiration instant itself is accepted.
func (s *Server) VerifyGroupSendToken(token *zkgroup.GroupSendFullToken, members []address.ServiceID, now uint64) error {
	if now > token.Expiration() {
		return zkgroup.ErrVerification
	}
	sum := ristretto255.NewIdentityElement()
	for _, id := range members {
		sum.Add(sum, zkcrypto.NewUID(id).Points()[0])
	}
	b := token.Bytes()
	return s.endorsementKey(token.Expiration()).VerifyToken(sum, b[9:len(b)-8])
}
