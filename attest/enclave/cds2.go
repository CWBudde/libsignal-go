// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package enclave

import (
	"fmt"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/cwbudde/libsignal-go/attest/dcap"
)

// NewCDS2Handshake starts a post-quantum handshake with a contact discovery
// (CDSI) enclave from its attestation message, accepting the advisories
// known to be mitigated in that enclave (cds2.rs new_handshake).
func NewCDS2Handshake(mrenclave, attestationMsg []byte, now time.Time) (*Handshake, error) {
	return NewCDS2HandshakeWithAdvisories(mrenclave, attestationMsg, now, dcap.SWAdvisories(mrenclave))
}

// NewCDS2HandshakeWithAdvisories is NewCDS2Handshake with the acceptable
// advisories given (cds2.rs new_handshake_with_advisories).
func NewCDS2HandshakeWithAdvisories(mrenclave, attestationMsg []byte, now time.Time, advisories []string) (*Handshake, error) {
	evidence, endorsement, err := decodeHandshakeStart(attestationMsg)
	if err != nil {
		return nil, err
	}
	return NewSGXHandshake(mrenclave, evidence, endorsement, advisories, now, PostQuantum)
}

// ExtractCDS2Metrics returns the attestation metrics of a CDSI attestation
// message (cds2.rs extract_metrics).
func ExtractCDS2Metrics(attestationMsg []byte) (map[string]int64, error) {
	evidence, endorsement, err := decodeHandshakeStart(attestationMsg)
	if err != nil {
		return nil, err
	}
	m, err := dcap.AttestationMetrics(evidence, endorsement)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAttestation, err)
	}
	return m, nil
}

// Field numbers of org.signal.cds2.ClientHandshakeStart (proto/cds2.proto).
const (
	fieldPubkey      = 1
	fieldEvidence    = 2
	fieldEndorsement = 3
)

// decodeHandshakeStart decodes a ClientHandshakeStart as prost does: a
// repeated field keeps its last value, unknown fields are skipped, and a
// known field with another wire type is an error.
func decodeHandshakeStart(b []byte) (evidence, endorsement []byte, err error) {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, nil, decodeErr(n)
		}
		b = b[n:]
		switch num {
		case fieldPubkey, fieldEvidence, fieldEndorsement:
			if typ != protowire.BytesType {
				return nil, nil, dataErr(fmt.Sprintf("ClientHandshakeStart field %d: invalid wire type %d", num, typ))
			}
			v, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return nil, nil, decodeErr(n)
			}
			switch num {
			case fieldEvidence:
				evidence = v
			case fieldEndorsement:
				endorsement = v
			}
			b = b[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return nil, nil, decodeErr(n)
			}
			b = b[n:]
		}
	}
	return evidence, endorsement, nil
}

func decodeErr(n int) error {
	return fmt.Errorf("%w: ClientHandshakeStart: %w", ErrAttestationData, protowire.ParseError(n))
}
