// Copyright 2020-2022 Signal Messenger, LLC.
// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package zkcrypto

import (
	"encoding/binary"

	"github.com/cwbudde/libsignal-go/poksho"
	"github.com/gtank/ristretto255"
)

type proofData struct {
	points []*ristretto255.Element
	proof  []byte
}

// Bytes encodes commitment points and a bincode length-prefixed poksho proof.
func (p proofData) Bytes() []byte {
	b := encodePoints(p.points...)
	b = binary.LittleEndian.AppendUint64(b, uint64(len(p.proof)))
	return append(b, p.proof...)
}
func parseProofData(b []byte, n int) (proofData, error) {
	offset := 32 * n
	if len(b) < offset+8 {
		return proofData{}, ErrEncoding
	}
	length := binary.LittleEndian.Uint64(b[offset : offset+8])
	if length != uint64(len(b)-offset-8) { //nolint:gosec // G115: the preceding length check guarantees a nonnegative remainder.
		return proofData{}, ErrEncoding
	}
	points, err := decodePoints(b[:offset], n)
	if err != nil {
		return proofData{}, err
	}
	// Like serde, parsing a Vec does not validate the inner proof. Verification does.
	return proofData{points, append([]byte(nil), b[offset+8:]...)}, nil
}
func prove(s *poksho.Statement, w poksho.ScalarArgs, p poksho.PointArgs, r poksho.SHO) ([]byte, error) {
	b, err := s.Prove(w, p, nil, [32]byte(r.SqueezeAndRatchet(32)))
	if err != nil {
		return nil, ErrVerification
	}
	return b, nil
}
func verify(s *poksho.Statement, b []byte, p poksho.PointArgs) error {
	if err := s.VerifyProof(b, p, nil); err != nil {
		return ErrVerification
	}
	return nil
}

// ProfileRequestProof holds an immutable credential proof. Use its constructor/parser.
type ProfileRequestProof struct{ proofData }

// ParseProfileRequestProof checks the outer encoding; Verify checks the inner proof.
func ParseProfileRequestProof(b []byte) (ProfileRequestProof, error) {
	p, e := parseProofData(b, 0)
	return ProfileRequestProof{p}, e
}

// ProfileIssuanceProof holds an immutable credential proof. Use its constructor/parser.
type ProfileIssuanceProof struct{ proofData }

// ParseProfileIssuanceProof checks the outer encoding; Verify checks the inner proof.
func ParseProfileIssuanceProof(b []byte) (ProfileIssuanceProof, error) {
	p, e := parseProofData(b, 0)
	return ProfileIssuanceProof{p}, e
}

// ReceiptIssuanceProof holds an immutable credential proof. Use its constructor/parser.
type ReceiptIssuanceProof struct{ proofData }

// ParseReceiptIssuanceProof checks the outer encoding; Verify checks the inner proof.
func ParseReceiptIssuanceProof(b []byte) (ReceiptIssuanceProof, error) {
	p, e := parseProofData(b, 0)
	return ReceiptIssuanceProof{p}, e
}

// ProfilePresentationProof holds an immutable credential proof. Use its constructor/parser.
type ProfilePresentationProof struct{ proofData }

// ParseProfilePresentationProof checks the outer encoding; Verify checks the inner proof.
func ParseProfilePresentationProof(b []byte) (ProfilePresentationProof, error) {
	p, e := parseProofData(b, 8)
	return ProfilePresentationProof{p}, e
}

// ReceiptPresentationProof holds an immutable credential proof. Use its constructor/parser.
type ReceiptPresentationProof struct{ proofData }

// ParseReceiptPresentationProof checks the outer encoding; Verify checks the inner proof.
func ParseReceiptPresentationProof(b []byte) (ReceiptPresentationProof, error) {
	p, e := parseProofData(b, 5)
	return ReceiptPresentationProof{p}, e
}

// ProfilePresentationProofV1 is a deprecated deserialize-only proof; it cannot be verified.
type ProfilePresentationProofV1 struct{ proofData }

// ParseProfilePresentationProofV1 preserves a deprecated proof without verification.
func ParseProfilePresentationProofV1(b []byte) (ProfilePresentationProofV1, error) {
	p, e := parseProofData(b, 8)
	return ProfilePresentationProofV1{p}, e
}

// ProfilePresentationProofV2 is a deprecated deserialize-only proof; it cannot be verified.
type ProfilePresentationProofV2 struct{ proofData }

// ParseProfilePresentationProofV2 preserves a deprecated proof without verification.
func ParseProfilePresentationProofV2(b []byte) (ProfilePresentationProofV2, error) {
	p, e := parseProofData(b, 8)
	return ProfilePresentationProofV2{p}, e
}
