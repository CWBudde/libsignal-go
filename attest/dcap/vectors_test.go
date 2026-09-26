// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package dcap_test

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/cwbudde/libsignal-go/attest/dcap"
)

// skewAdjustment is sgx_session.rs SKEW_ADJUSTMENT: the session attests at
// the current time plus one day.
const skewAdjustment = 24 * time.Hour

// cds2TestValidStart is sgx_session.rs testutil::valid_start, when the
// cds2_test PCK CRL becomes valid; the collateral lasts 30 days.
var cds2TestValidStart = time.Unix(1655846111, 0)

// recordedVector is one recorded attestation with the outcome upstream
// gives for it.
type recordedVector struct {
	name                   string
	evidence, endorsements []byte
	mrenclave              [32]byte
	advisories             []string
	now                    time.Time
	pk                     []byte // expected pk claim; nil when rejected
	err                    error  // expected sentinel; nil when accepted
}

func hexFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := hex.DecodeString(string(bytes.TrimSpace(readTestdata(t, name))))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return b
}

func tamperQuote(evidence []byte) []byte {
	ev := bytes.Clone(evidence)
	ev[dcap.QuoteReportBodyOffset+64]++
	return ev
}

// recordedVectors lists every recorded blob of upstream's tests/data as
// positive and negative vectors. The expected outcomes are those of
// upstream's dcap::verify_remote_attestation with the test-util feature, run
// on the same inputs (testdata/README.md).
func recordedVectors(t *testing.T) []recordedVector {
	t.Helper()
	var wrong [32]byte

	// cds2_test: sgx_session.rs test_clock_skew. The session attests at
	// time + skewAdjustment, so its four times become these.
	cds2Ev, cds2En := readTestdata(t, "cds2_test.evidence"), readTestdata(t, "cds2_test.endorsements")
	cds2MR := [32]byte(hexFile(t, "cds2_test.mrenclave"))
	priv, err := ecdh.X25519().NewPrivateKey(hexFile(t, "cds2_test.privatekey"))
	if err != nil {
		t.Fatal(err)
	}
	cds2PK := priv.PublicKey().Bytes() // the K of the NK handshake
	cds2End := cds2TestValidStart.Add(30 * 24 * time.Hour)
	cds2 := func(name string, clock time.Time, pk []byte, err error) recordedVector {
		return recordedVector{
			name: "cds2_test/" + name, evidence: cds2Ev, endorsements: cds2En,
			mrenclave: cds2MR, now: clock.Add(skewAdjustment), pk: pk, err: err,
		}
	}

	// dcap_v3 and dcap-expired have no upstream test.
	v3Ev, v3En := readTestdata(t, "dcap_v3.evidence"), readTestdata(t, "dcap_v3.endorsements")
	v3MR := [32]byte(mustHex(t, "e5eaa62da3514e8b37ccabddb87e52e7f319ccf5120a13f9e1b42b87ec9dd3dd"))
	v3PK := hexFile(t, "dcap_v3.pubkey")
	v3NextUpdate := time.Date(2022, 8, 14, 2, 31, 29, 0, time.UTC) // earliest nextUpdate

	// svr2: svr2.rs attest_svr2, attestation half (the raft config check is
	// not DCAP).
	svr2 := loadHandshake(t, "svr2")
	svr2PK := readTestdata(t, "svr2.pubkey")

	return []recordedVector{
		cds2("valid_start", cds2TestValidStart.Add(-skewAdjustment), cds2PK, nil),
		cds2("before_valid_start", cds2TestValidStart.Add(-skewAdjustment-time.Second), nil, dcap.ErrCRL),
		cds2("valid_end", cds2End.Add(-skewAdjustment), nil, dcap.ErrExpired),
		cds2("before_valid_end", cds2End.Add(-skewAdjustment-time.Second), cds2PK, nil),
		{
			name: "cds2_test/tampered_quote", evidence: tamperQuote(cds2Ev), endorsements: cds2En,
			mrenclave: cds2MR, now: cds2TestValidStart, err: dcap.ErrSignature,
		},
		{
			name: "cds2_test/wrong_measurement", evidence: cds2Ev, endorsements: cds2En,
			mrenclave: wrong, now: cds2TestValidStart, err: dcap.ErrMREnclave,
		},

		{
			name: "dcap_v3/in_window", evidence: v3Ev, endorsements: v3En,
			mrenclave: v3MR, now: time.Date(2022, 7, 20, 0, 0, 0, 0, time.UTC), pk: v3PK,
		},
		{
			name: "dcap_v3/next_update", evidence: v3Ev, endorsements: v3En,
			mrenclave: v3MR, now: v3NextUpdate, pk: v3PK,
		},
		{
			name: "dcap_v3/after_next_update", evidence: v3Ev, endorsements: v3En,
			mrenclave: v3MR, now: v3NextUpdate.Add(time.Second), err: dcap.ErrExpired,
		},
		{
			name: "dcap_v3/at_issue_date", evidence: v3Ev, endorsements: v3En,
			mrenclave: v3MR, now: time.Date(2022, 7, 15, 2, 31, 29, 0, time.UTC), err: dcap.ErrCRL,
		},
		{
			name: "dcap_v3/tampered_quote", evidence: tamperQuote(v3Ev), endorsements: v3En,
			mrenclave: v3MR, now: v3NextUpdate, err: dcap.ErrSignature,
		},
		{
			name: "dcap_v3/wrong_measurement", evidence: v3Ev, endorsements: v3En,
			mrenclave: wrong, now: v3NextUpdate, err: dcap.ErrMREnclave,
		},

		// The PCK CRL field is not DER, so upstream rejects the collateral
		// while parsing it, before any expiry check.
		{
			name: "dcap-expired/malformed_crl", evidence: readTestdata(t, "dcap-expired.evidence"),
			endorsements: readTestdata(t, "dcap-expired.endorsements"),
			now:          time.Date(2021, 5, 1, 0, 0, 0, 0, time.UTC), err: dcap.ErrMalformed,
		},

		{
			name: "svr2/attest_svr2", evidence: svr2.evidence, endorsements: svr2.endorsements,
			mrenclave: svr2.mrenclave, advisories: svr2.advisories, now: svr2.now, pk: svr2PK,
		},
		{
			name: "svr2/no_advisories", evidence: svr2.evidence, endorsements: svr2.endorsements,
			mrenclave: svr2.mrenclave, now: svr2.now, err: dcap.ErrAdvisory,
		},
		{
			name: "svr2/expired", evidence: svr2.evidence, endorsements: svr2.endorsements,
			mrenclave: svr2.mrenclave, advisories: svr2.advisories,
			now: svr2.now.AddDate(2, 0, 0), err: dcap.ErrExpired,
		},
		{
			name: "svr2/tampered_quote", evidence: tamperQuote(svr2.evidence), endorsements: svr2.endorsements,
			mrenclave: svr2.mrenclave, advisories: svr2.advisories, now: svr2.now, err: dcap.ErrSignature,
		},
		{
			name: "svr2/wrong_measurement", evidence: svr2.evidence, endorsements: svr2.endorsements,
			mrenclave: cds2MR, advisories: svr2.advisories, now: svr2.now, err: dcap.ErrMREnclave,
		},
	}
}

// TestRecordedVectors checks every recorded blob against upstream's
// outcome.
func TestRecordedVectors(t *testing.T) {
	for _, v := range recordedVectors(t) {
		t.Run(v.name, func(t *testing.T) {
			claims, err := dcap.VerifyRemoteAttestation(v.evidence, v.endorsements, v.mrenclave, v.advisories, v.now)
			if v.err != nil {
				if !errors.Is(err, v.err) {
					t.Fatalf("err = %v, want %v", err, v.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(claims["pk"], v.pk) {
				t.Fatalf("pk claim = %x, want %x", claims["pk"], v.pk)
			}
		})
	}
}

// TestVeryExpiredEvalNumber checks that the recorded blobs with TCB
// evaluation data number 12 attest only under the test-only exception, as
// upstream's do only with cfg(test) or the test-util feature. It switches
// package state, so it must not run in parallel.
func TestVeryExpiredEvalNumber(t *testing.T) {
	if dcap.VeryExpiredTestEvalNumberDefault {
		t.Fatal("test-only evaluation number exception is on outside tests")
	}
	was := dcap.SetAcceptVeryExpiredTestEvalNumber(false)
	t.Cleanup(func() { dcap.SetAcceptVeryExpiredTestEvalNumber(was) })
	for _, v := range recordedVectors(t) {
		if v.err != nil {
			continue
		}
		t.Run(v.name, func(t *testing.T) {
			_, err := dcap.VerifyRemoteAttestation(v.evidence, v.endorsements, v.mrenclave, v.advisories, v.now)
			switch v.name {
			case "svr2/attest_svr2": // evaluation data number ≥ 21
				if err != nil {
					t.Fatal(err)
				}
			default:
				if !errors.Is(err, dcap.ErrExpired) {
					t.Fatalf("err = %v, want %v", err, dcap.ErrExpired)
				}
			}
		})
	}
	en, err := dcap.ParseEndorsements(readTestdata(t, "cds2_test.endorsements"))
	if err != nil {
		t.Fatal(err)
	}
	if en.TCBInfo.TCBEvaluationDataNumber != 12 || en.QEIdentity.TCBEvaluationDataNumber != 12 {
		t.Fatalf("evaluation data numbers %d, %d, want 12",
			en.TCBInfo.TCBEvaluationDataNumber, en.QEIdentity.TCBEvaluationDataNumber)
	}
	at := cds2TestValidStart
	if en.TCBInfo.ValidAt(at) || en.QEIdentity.ValidAt(at) {
		t.Fatal("evaluation data number 12 accepted with the exception off")
	}
	dcap.SetAcceptVeryExpiredTestEvalNumber(true)
	if !en.TCBInfo.ValidAt(at) || !en.QEIdentity.ValidAt(at) {
		t.Fatal("evaluation data number 12 rejected with the exception on")
	}
}
