// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package enclave

import (
	"fmt"
	"time"

	"github.com/cwbudde/libsignal-go/attest/dcap"
)

// SkewAdjustment is added to the current time before the attestation's
// validity is checked, to allow for clients whose clock runs slow
// (sgx_session.rs SKEW_ADJUSTMENT).
const SkewAdjustment = 24 * time.Hour

// NewSGXHandshake verifies an SGX DCAP attestation of the enclave with
// MRENCLAVE mrenclave at now + SkewAdjustment and starts a handshake to the
// public key it attests (Handshake::for_sgx). The raft config of SVR2 is
// not validated.
func NewSGXHandshake(mrenclave, evidence, endorsements []byte, advisories []string, now time.Time, typ HandshakeType) (*Handshake, error) {
	if len(evidence) == 0 {
		return nil, dataErr("Evidence does not fit expected format")
	}
	if len(endorsements) == 0 {
		return nil, dataErr("Endorsement does not fit expected format")
	}
	if len(mrenclave) != 32 {
		return nil, dataErr("MREnclave value does not fit expected format")
	}
	claims, err := dcap.VerifyRemoteAttestation(evidence, endorsements, [32]byte(mrenclave), advisories, now.Add(SkewAdjustment))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAttestation, err)
	}
	c, err := ClaimsFromCustom(claims)
	if err != nil {
		return nil, err
	}
	return newHandshake(c, typ)
}
