// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package enclave_test

import (
	"errors"
	"reflect"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/cwbudde/libsignal-go/attest/dcap"
	"github.com/cwbudde/libsignal-go/attest/enclave"
	"github.com/cwbudde/libsignal-go/noise"
)

// TestAttestCDS2 ports cds2.rs attest_cds2.
func TestAttestCDS2(t *testing.T) {
	c := loadCDSI(t)
	h, err := enclave.NewCDS2HandshakeWithAdvisories(c.mrenclave, c.msg, c.now, c.advisories)
	if err != nil {
		t.Fatal(err)
	}
	// CDS2 is post-quantum: e, the encrypted ML-KEM key and the payload tag
	// (client_connection.rs NOISE_HANDSHAKE_OVERHEAD).
	if n, want := len(h.InitialRequest()), 64+noise.KEMPublicKeySize; n != want {
		t.Fatalf("initial request %d bytes, want %d", n, want)
	}
	if !reflect.DeepEqual(h.Claims().PublicKey, readTestdata(t, "cdsi.pubkey")) {
		t.Fatalf("pk claim = %x", h.Claims().PublicKey)
	}
}

// TestCDS2Handshake covers new_handshake, which takes the advisories of
// the enclave from util.rs get_sw_advisories. The recorded enclave is
// CDSI staging.
func TestCDS2Handshake(t *testing.T) {
	c := loadCDSI(t)
	if _, err := enclave.NewCDS2Handshake(c.mrenclave, c.msg, c.now); err != nil {
		t.Fatal(err)
	}
	// Without the advisories the enclave mitigates, it is rejected.
	if _, err := enclave.NewCDS2HandshakeWithAdvisories(c.mrenclave, c.msg, c.now, nil); !errors.Is(err, dcap.ErrAdvisory) {
		t.Fatalf("err = %v, want %v", err, dcap.ErrAdvisory)
	}
}

// TestExtractCDS2Metrics covers cds2.rs extract_metrics.
func TestExtractCDS2Metrics(t *testing.T) {
	c := loadCDSI(t)
	got, err := enclave.ExtractCDS2Metrics(c.msg)
	if err != nil {
		t.Fatal(err)
	}
	h := decodeStart(t, c.msg)
	want, err := dcap.AttestationMetrics(h[2], h[3])
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || !reflect.DeepEqual(got, want) {
		t.Fatalf("metrics = %v, want %v", got, want)
	}
	if _, err := enclave.ExtractCDS2Metrics([]byte{0x12}); !errors.Is(err, enclave.ErrAttestationData) {
		t.Fatalf("err = %v, want %v", err, enclave.ErrAttestationData)
	}
	if _, err := enclave.ExtractCDS2Metrics(nil); !errors.Is(err, enclave.ErrAttestation) {
		t.Fatalf("err = %v, want %v", err, enclave.ErrAttestation)
	}
}

// decodeStart returns the bytes fields of a ClientHandshakeStart.
func decodeStart(t *testing.T, msg []byte) map[protowire.Number][]byte {
	t.Helper()
	fields := map[protowire.Number][]byte{}
	for len(msg) > 0 {
		num, _, n := protowire.ConsumeTag(msg)
		msg = msg[n:]
		v, m := protowire.ConsumeBytes(msg)
		if n < 0 || m < 0 {
			t.Fatal("malformed ClientHandshakeStart")
		}
		fields[num], msg = v, msg[m:]
	}
	return fields
}

// TestClientHandshakeStartDecoding covers the prost decoding of the
// attestation message.
func TestClientHandshakeStartDecoding(t *testing.T) {
	c := loadCDSI(t)
	f := decodeStart(t, c.msg)
	bytesField := func(b []byte, num protowire.Number, v []byte) []byte {
		b = protowire.AppendTag(b, num, protowire.BytesType)
		return protowire.AppendBytes(b, v)
	}
	var valid []byte
	valid = bytesField(valid, 2, f[2])
	valid = bytesField(valid, 3, f[3])

	var extras []byte
	extras = bytesField(extras, 2, []byte("overwritten"))
	extras = bytesField(extras, 1, []byte("test-only pubkey, ignored"))
	extras = protowire.AppendTag(extras, 9, protowire.VarintType)
	extras = protowire.AppendVarint(extras, 300)
	extras = protowire.AppendTag(extras, 10, protowire.StartGroupType)
	extras = protowire.AppendTag(extras, 10, protowire.EndGroupType)
	extras = append(extras, valid...)

	// Read as bytes, varint 0 would be an empty evidence that the valid
	// field after it overwrites; prost rejects the wire type instead.
	wrongType := protowire.AppendTag(nil, 2, protowire.VarintType)
	wrongType = protowire.AppendVarint(wrongType, 0)

	for _, tc := range []struct {
		name string
		msg  []byte
		want error // nil: accepted
	}{
		{"recorded", c.msg, nil},
		{"minimal", valid, nil},
		{"last_value_wins_unknown_skipped", extras, nil},
		{"known_field_wrong_wire_type", append(wrongType, valid...), enclave.ErrAttestationData},
		{"truncated", c.msg[:len(c.msg)-1], enclave.ErrAttestationData},
		{"unmatched_end_group", append(protowire.AppendTag(nil, 10, protowire.EndGroupType), valid...), enclave.ErrAttestationData},
		{"field_number_zero", append([]byte{0x02, 0x00}, valid...), enclave.ErrAttestationData},
		{"empty", nil, enclave.ErrAttestationData},
		{"no_endorsement", bytesField(nil, 2, f[2]), enclave.ErrAttestationData},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := enclave.NewCDS2HandshakeWithAdvisories(c.mrenclave, tc.msg, c.now, c.advisories)
			if tc.want == nil {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}
