// Copyright 2024 Signal Messenger, LLC.
// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package zkgroup

import (
	"bytes"
	"encoding/binary"
	"slices"

	"github.com/cwbudde/libsignal-go/address"
	"github.com/cwbudde/libsignal-go/zkcredential"
	"github.com/gtank/ristretto255"
)

// GroupSendEndorsementsResponse contains a batch of endorsements and its expiry.
// Parsing alone does not authenticate the response; use ReceiveWithServiceIDs or
// ReceiveWithCiphertexts before storing endorsements.
type GroupSendEndorsementsResponse struct {
	inner      *zkcredential.EndorsementResponse
	expiration uint64
}

// GroupSendEndorsement authorizes a member or combined set of members. Only
// combine or remove endorsements from the same issuance. These operations
// preserve multiplicity: repeated inputs do not deduplicate.
type GroupSendEndorsement struct{ inner *zkcredential.Endorsement }

// GroupSendToken is a bearer token without its issuance expiration.
// Its bytes are sensitive and must not be logged.
type GroupSendToken struct{ raw []byte }

// GroupSendFullToken is a bearer token with its issuance expiration.
// Its bytes are sensitive and must not be logged.
type GroupSendFullToken struct {
	raw        []byte
	expiration uint64
}

// ParseGroupSendEndorsementsResponse validates a complete bounded encoding.
// Compressed endorsement points are validated during receipt, as in Rust.
func ParseGroupSendEndorsementsResponse(b []byte) (*GroupSendEndorsementsResponse, error) {
	if len(b) < 25 || b[0] != 0 {
		return nil, ErrEncoding
	}
	inner, e := zkcredential.ParseEndorsementResponse(b[1 : len(b)-8])
	if e != nil {
		return nil, ErrEncoding
	}
	return &GroupSendEndorsementsResponse{inner, timestamp(b[len(b)-8:])}, nil
}

// Bytes returns an independent serialized response.
func (r *GroupSendEndorsementsResponse) Bytes() []byte {
	return binary.LittleEndian.AppendUint64(join(0, r.inner.Bytes()), r.expiration)
}

// Expiration returns the Unix timestamp shared by all endorsements in the batch.
func (r *GroupSendEndorsementsResponse) Expiration() uint64 { return r.expiration }

// ReceiveWithServiceIDs verifies issuance for all members, including the local
// user, and returns endorsements in the supplied member order. now is Unix time.
// Expiry must be day-aligned and between two hours and seven days away, inclusive.
func (r *GroupSendEndorsementsResponse) ReceiveWithServiceIDs(members []address.ServiceID, now uint64, group *GroupSecretParams, server *ServerPublicParams) ([]*GroupSendEndorsement, error) {
	ciphertexts := make([]UUIDCiphertext, len(members))
	for i, id := range members {
		ciphertexts[i] = group.EncryptServiceID(id)
	}
	return r.ReceiveWithCiphertexts(ciphertexts, now, server)
}

// ReceiveWithCiphertexts verifies issuance using existing member ciphertexts.
// Its result follows the supplied order, independent of server ordering.
func (r *GroupSendEndorsementsResponse) ReceiveWithCiphertexts(members []UUIDCiphertext, now uint64, server *ServerPublicParams) ([]*GroupSendEndorsement, error) {
	if r.expiration%SecondsPerDay != 0 || r.expiration < now || r.expiration-now < 2*3600 || r.expiration-now > 7*SecondsPerDay {
		return nil, ErrVerification
	}
	type indexedPoint struct {
		index int
		point *ristretto255.Element
		key   []byte
	}
	points := make([]indexedPoint, len(members))
	for i, member := range members {
		p, e := point(member.inner.Bytes()[:32])
		if e != nil {
			return nil, ErrEncoding
		}
		points[i] = indexedPoint{i, p, ristretto255.NewIdentityElement().Add(p, p).Bytes()}
	}
	// The protocol sorts by the compressed DOUBLE of each ciphertext's first point.
	slices.SortFunc(points, func(a, b indexedPoint) int { return bytes.Compare(a.key, b.key) })
	sorted := make([]*ristretto255.Element, len(points))
	for i, p := range points {
		sorted[i] = p.point
	}
	tag := binary.BigEndian.AppendUint64(nil, r.expiration)
	key := server.endorsements.DeriveKey(seeded("20240215_Signal_GroupSendEndorsement", tag))
	received, e := r.inner.Receive(sorted, key)
	if e != nil {
		return nil, ErrVerification
	}
	out := make([]*GroupSendEndorsement, len(received))
	for i, endorsement := range received {
		out[points[i].index] = &GroupSendEndorsement{endorsement}
	}
	return out, nil
}

// ParseGroupSendEndorsement parses a stored canonical endorsement point.
// Parsing does not verify that it was issued by the expected server.
func ParseGroupSendEndorsement(b []byte) (*GroupSendEndorsement, error) {
	if len(b) != 33 || b[0] != 0 {
		return nil, ErrEncoding
	}
	inner, e := zkcredential.ParseEndorsement(b[1:])
	if e != nil {
		return nil, ErrEncoding
	}
	return &GroupSendEndorsement{inner}, nil
}

// Bytes returns an independent serialized endorsement.
func (e *GroupSendEndorsement) Bytes() []byte { return join(0, e.inner.Bytes()) }

// CombineGroupSendEndorsements adds endorsements from the same issuance.
// An empty input produces the identity endorsement, matching Rust.
func CombineGroupSendEndorsements(endorsements ...*GroupSendEndorsement) *GroupSendEndorsement {
	inner := make([]*zkcredential.Endorsement, len(endorsements))
	for i, e := range endorsements {
		inner[i] = e.inner
	}
	return &GroupSendEndorsement{zkcredential.CombineEndorsements(inner...)}
}

// Remove subtracts endorsements previously included in this endorsement.
func (e *GroupSendEndorsement) Remove(other *GroupSendEndorsement) *GroupSendEndorsement {
	return &GroupSendEndorsement{e.inner.Remove(other.inner)}
}

// ToToken converts an authenticated endorsement into a bearer token.
func (e *GroupSendEndorsement) ToToken(group *GroupSecretParams) *GroupSendToken {
	// The parsed/derived UID key uses the same canonical scalar layout.
	scalar, err := ristretto255.NewScalar().SetCanonicalBytes(group.uid.Bytes()[:32])
	if err != nil {
		panic("zkgroup: uninitialized group secret parameters")
	}
	raw := e.inner.Token(zkcredential.ClientDecryptionKeyFromScalar(scalar))
	return &GroupSendToken{raw[:]}
}

// ToFullToken attaches the original issuance expiration to a bearer token.
// It does not validate expiry or authenticate the token; the server does so.
func (t *GroupSendToken) ToFullToken(expiration uint64) *GroupSendFullToken {
	return &GroupSendFullToken{bytes.Clone(t.raw), expiration}
}

// Bytes returns an independent encoding containing the bearer token.
func (t *GroupSendToken) Bytes() []byte {
	return append(binary.LittleEndian.AppendUint64([]byte{0}, uint64(len(t.raw))), t.raw...)
}

// Bytes returns an independent encoding containing the bearer token and expiry.
func (t *GroupSendFullToken) Bytes() []byte {
	return binary.LittleEndian.AppendUint64((&GroupSendToken{t.raw}).Bytes(), t.expiration)
}

// Expiration returns the token's Unix expiration timestamp.
func (t *GroupSendFullToken) Expiration() uint64 { return t.expiration }

// ParseGroupSendToken validates framing. As in Rust, arbitrary token lengths
// parse; only an authentic 16-byte token can pass server verification.
func ParseGroupSendToken(b []byte) (*GroupSendToken, error) {
	if len(b) < 9 || b[0] != 0 || binary.LittleEndian.Uint64(b[1:9]) != uint64(len(b)-9) { //nolint:gosec // len(b) >= 9 is checked before subtracting.
		return nil, ErrEncoding
	}
	return &GroupSendToken{bytes.Clone(b[9:])}, nil
}

// ParseGroupSendFullToken validates exact framing without authenticating a token.
func ParseGroupSendFullToken(b []byte) (*GroupSendFullToken, error) {
	if len(b) < 17 {
		return nil, ErrEncoding
	}
	t, e := ParseGroupSendToken(b[:len(b)-8])
	if e != nil {
		return nil, e
	}
	return t.ToFullToken(timestamp(b[len(b)-8:])), nil
}
