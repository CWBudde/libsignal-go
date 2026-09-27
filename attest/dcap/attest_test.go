// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package dcap_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/cwbudde/libsignal-go/attest/dcap"
)

// TestAttest ports the FakeAttestation tests of dcap.rs: each case changes
// the evidence or endorsements before they are re-signed.
func TestAttest(t *testing.T) {
	type check func(t *testing.T, a *dcap.Attestation, err error)
	ok := func(t *testing.T, _ *dcap.Attestation, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("attest: %v", err)
		}
	}
	fails := func(want error) check {
		return func(t *testing.T, _ *dcap.Attestation, err error) {
			t.Helper()
			if !errors.Is(err, want) {
				t.Fatalf("attest: got %v, want %v", err, want)
			}
		}
	}
	qeLevels := func(levels ...dcap.QETCBLevel) []dcap.QETCBLevel { return levels }
	setQEISVSVN := func(f *fakeAttestation, v uint16) {
		binary.LittleEndian.PutUint16(f.qeReport()[dcap.RBISVSVN:], v)
	}
	level := func(version dcap.TCBInfoVersion, comp0 uint8, status dcap.TCBStatus, ids ...string) dcap.TCBLevel {
		l := dcap.TCBLevel{Version: version, Status: status, AdvisoryIDs: append([]string{}, ids...)}
		l.Components[0] = comp0
		return l
	}
	for _, tc := range []struct {
		name   string
		modify func(t *testing.T, f *fakeAttestation)
		check  check
	}{
		{"unmodified", func(*testing.T, *fakeAttestation) {}, ok},
		{"debug_flag", func(_ *testing.T, f *fakeAttestation) {
			f.isvReport()[dcap.RBAttributes] |= 0x2
		}, fails(dcap.ErrDebug)},
		{"tcb_fmspc_mismatch", func(_ *testing.T, f *fakeAttestation) {
			f.en.TCBInfo.FMSPC = [6]byte{}
		}, fails(dcap.ErrTCB)},
		{"tcb_pceid_mismatch", func(_ *testing.T, f *fakeAttestation) {
			f.en.TCBInfo.PCEID = [2]byte{0, 1}
		}, fails(dcap.ErrTCB)},
		{"bad_vendor_id", func(_ *testing.T, f *fakeAttestation) {
			clear(f.ev.Quote.Body[dcap.QuoteQEVendorIDOffset : dcap.QuoteQEVendorIDOffset+16])
		}, fails(dcap.ErrEnclaveSource)},
		{"bad_mrsigner", func(_ *testing.T, f *fakeAttestation) {
			clear(f.qeReport()[dcap.RBMRSigner : dcap.RBMRSigner+32])
		}, fails(dcap.ErrEnclaveSource)},
		{"qe_id_valid_tcb_level", func(_ *testing.T, f *fakeAttestation) {
			f.en.QEIdentity.TCBLevels = qeLevels(
				dcap.QETCBLevel{Status: dcap.QEUpToDate, ISVSVN: 4},
				dcap.QETCBLevel{Status: dcap.QEOutOfDate, ISVSVN: 2})
			setQEISVSVN(f, 5)
		}, ok},
		{"qe_id_unknown", func(_ *testing.T, f *fakeAttestation) {
			f.en.QEIdentity.TCBLevels = qeLevels(dcap.QETCBLevel{Status: dcap.QERevoked, ISVSVN: 4})
			setQEISVSVN(f, 3)
		}, fails(dcap.ErrEnclaveSource)},
		{"qe_id_outdated_tcb_level", func(_ *testing.T, f *fakeAttestation) {
			f.en.QEIdentity.TCBLevels = qeLevels(
				dcap.QETCBLevel{Status: dcap.QERevoked, ISVSVN: 4},
				dcap.QETCBLevel{Status: dcap.QEOutOfDate, ISVSVN: 0})
			setQEISVSVN(f, 1)
		}, fails(dcap.ErrEnclaveSource)},
		{"qe_id_revoked_tcb_level", func(_ *testing.T, f *fakeAttestation) {
			f.en.QEIdentity.TCBLevels = qeLevels(
				dcap.QETCBLevel{Status: dcap.QEUpToDate, ISVSVN: 4},
				dcap.QETCBLevel{Status: dcap.QERevoked, ISVSVN: 3})
			setQEISVSVN(f, 3)
		}, fails(dcap.ErrEnclaveSource)},
		{"revoked_pck", func(_ *testing.T, f *fakeAttestation) {
			f.info.pckRevoked = append(f.info.pckRevoked, serialOf(f.info.pckChain[0]))
		}, fails(dcap.ErrRevoked)},
		{"revoked_other_pck", func(_ *testing.T, f *fakeAttestation) {
			f.info.pckRevoked = append(f.info.pckRevoked, bigZero())
		}, ok},
		{"revoked_other_root", func(_ *testing.T, f *fakeAttestation) {
			f.info.rootRevoked = append(f.info.rootRevoked, bigZero())
		}, ok},
		{"revoked_tcb_signer", func(_ *testing.T, f *fakeAttestation) {
			f.info.rootRevoked = append(f.info.rootRevoked, serialOf(f.info.tcbIssuerChain[0]))
		}, fails(dcap.ErrRevoked)},
		{"revoked_qe_id_signer", func(_ *testing.T, f *fakeAttestation) {
			f.info.rootRevoked = append(f.info.rootRevoked, serialOf(f.info.qeIDIssuerChain[0]))
		}, fails(dcap.ErrRevoked)},
		{"v2_tcb_level", func(_ *testing.T, f *fakeAttestation) {
			for i := range f.en.TCBInfo.TCBLevels {
				l := &f.en.TCBInfo.TCBLevels[i]
				l.Version, l.AdvisoryIDs = dcap.TCBInfoV2, []string{}
			}
		}, ok},
		{"tcb_level_too_low_tcb_info", func(_ *testing.T, f *fakeAttestation) {
			f.en.TCBInfo.TCBEvaluationDataNumber = dcap.TCBEvaluationDataNumberMin - 1
		}, fails(dcap.ErrExpired)},
		{"tcb_level_too_low_enclave_identity", func(_ *testing.T, f *fakeAttestation) {
			f.en.QEIdentity.TCBEvaluationDataNumber = dcap.TCBEvaluationDataNumberMin - 1
		}, fails(dcap.ErrExpired)},
		{"unsupported_tcb_level", func(_ *testing.T, f *fakeAttestation) {
			f.en.TCBInfo.TCBLevels = []dcap.TCBLevel{level(dcap.TCBInfoV3, 1, dcap.TCBSWHardeningNeeded)}
			ext := f.ev.Quote.Support.PCKExtension
			ext.TCB.CompSVN, ext.TCB.PCESVN = [16]uint8{}, 0
		}, fails(dcap.ErrTCB)},
		{"sw_hardening_needed", func(_ *testing.T, f *fakeAttestation) {
			f.en.TCBInfo.TCBLevels = []dcap.TCBLevel{
				level(dcap.TCBInfoV3, 1, dcap.TCBSWHardeningNeeded, "INTEL-SA-1234"),
			}
			ext := f.ev.Quote.Support.PCKExtension
			ext.TCB.CompSVN, ext.TCB.PCESVN = [16]uint8{1}, 0
		}, func(t *testing.T, a *dcap.Attestation, err error) {
			t.Helper()
			ok(t, a, err)
			want := dcap.TCBStanding{SWHardeningNeeded: true, AdvisoryIDs: []string{"INTEL-SA-1234"}}
			if !reflect.DeepEqual(a.TCBStanding, want) {
				t.Errorf("standing = %+v, want %+v", a.TCBStanding, want)
			}
		}},
		// Beyond upstream: the remaining TCB statuses and the claims hash.
		{"tcb_level_out_of_date", func(_ *testing.T, f *fakeAttestation) {
			f.en.TCBInfo.TCBLevels = []dcap.TCBLevel{level(dcap.TCBInfoV3, 0, dcap.TCBOutOfDate)}
		}, fails(dcap.ErrTCB)},
		{"tcb_level_configuration_and_sw_hardening", func(_ *testing.T, f *fakeAttestation) {
			f.en.TCBInfo.TCBLevels = []dcap.TCBLevel{level(dcap.TCBInfoV3, 0, dcap.TCBConfigurationAndSWHardeningNeeded)}
		}, fails(dcap.ErrTCB)},
		{"tcb_level_first_match_wins", func(_ *testing.T, f *fakeAttestation) {
			f.en.TCBInfo.TCBLevels = []dcap.TCBLevel{
				level(dcap.TCBInfoV3, 0, dcap.TCBRevoked),
				level(dcap.TCBInfoV3, 0, dcap.TCBUpToDate),
			}
		}, fails(dcap.ErrTCB)},
		{"claims_hash_mismatch", func(_ *testing.T, f *fakeAttestation) {
			f.isvReport()[dcap.RBReportData]++
		}, fails(dcap.ErrClaims)},
		{"claims_hash_padding", func(_ *testing.T, f *fakeAttestation) {
			f.isvReport()[dcap.RBReportData+63] = 1
		}, fails(dcap.ErrClaims)},
		{"expired_collateral", func(_ *testing.T, f *fakeAttestation) {
			f.en.TCBInfo.NextUpdate = time.Now().Add(-time.Minute)
		}, fails(dcap.ErrExpired)},
		{"wrong_qe_identity_type", func(_ *testing.T, f *fakeAttestation) {
			f.en.QEIdentity.ID = dcap.EnclaveQVE
		}, fails(dcap.ErrEnclaveSource)},
		{"bad_isvprodid", func(_ *testing.T, f *fakeAttestation) {
			f.en.QEIdentity.ISVProdID++
		}, fails(dcap.ErrEnclaveSource)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			tc.modify(t, f)
			a, err := f.attest(t)
			tc.check(t, a, err)
		})
	}
}

// TestCheckAttributes ports check_attributes: the QE report's attributes,
// masked, must equal the QE identity's.
func TestCheckAttributes(t *testing.T) {
	fill := func(n int) (b [16]byte) {
		for i := range n {
			b[i] = byte(i)
		}
		return b
	}
	all := func(v byte) (b [16]byte) {
		for i := range b {
			b[i] = v
		}
		return b
	}
	for i, tc := range []struct {
		mask, qeID, reported [16]byte
		ok                   bool
	}{
		{all(0x00), all(0x00), all(0xFF), true},
		{all(0xFF), all(0x0F), all(0x0F), true},
		{all(0x0F), all(0x0A), all(0x7A), true},
		{all(0x07), all(0x05), all(0xFD), true},
		{all(0x77), all(0x55), all(0xDD), true},
		{all(0xFF), fill(16), fill(16), true},
		{all(0x00), all(0xFF), all(0xFF), false},
		{all(0x07), all(0x0F), all(0x0F), false},
		{all(0xF0), all(0xB0), all(0xC0), false},
		{all(0x07), all(0x0A), all(0x7A), false},
		{all(0xFD), fill(16), fill(16), false},
	} {
		f := newFake(t)
		copy(f.qeReport()[dcap.RBAttributes:], tc.reported[:])
		f.en.QEIdentity.Attributes = tc.qeID
		f.en.QEIdentity.AttributesMask = tc.mask
		if _, err := f.attest(t); (err == nil) != tc.ok {
			t.Errorf("case %d: attest = %v, want ok=%v", i, err, tc.ok)
		}
	}
}

// TestCheckMiscselect ports check_miscselct.
func TestCheckMiscselect(t *testing.T) {
	for i, tc := range []struct {
		mask, qeID, reported uint32
		ok                   bool
	}{
		{0x00000000, 0x00000000, 0xFFFFFFFF, true},
		{0x0123ABCD, 0x0123ABCD, 0xFFFFFFFF, true},
		{0xFFFFFFFF, 0x0123ABCD, 0x0123ABCD, true},
		{0x77770000, 0x55550000, 0xDDDDFFFF, true},
		{0x00000000, 0x00000001, 0x00000000, false},
		{0x000000CC, 0x000000FF, 0x000000FF, false},
		{0x000000FF, 0x000000DD, 0x000000FF, false},
		{0x070000FF, 0x000000DD, 0x070000DD, false},
	} {
		f := newFake(t)
		binary.LittleEndian.PutUint32(f.qeReport()[dcap.RBMiscSelect:], tc.reported)
		f.en.QEIdentity.MiscSelect = tc.qeID
		f.en.QEIdentity.MiscSelectMask = tc.mask
		if _, err := f.attest(t); (err == nil) != tc.ok {
			t.Errorf("case %d: attest = %v, want ok=%v", i, err, tc.ok)
		}
	}
}

// recordedHandshake is a recorded attestation (cds2/svr2
// ClientHandshakeStart fields evidence = 2, endorsement = 3) with its time,
// MRENCLAVE and accepted advisories.
type recordedHandshake struct {
	evidence, endorsements []byte
	now                    time.Time
	mrenclave              [32]byte
	advisories             []string
}

func loadCDSI(t testing.TB) recordedHandshake {
	t.Helper()
	return loadHandshake(t, "cdsi")
}

// loadHandshake reads name.handshakestart, .timestamp, .mrenclave and
// .advisories.
func loadHandshake(t testing.TB, name string) recordedHandshake {
	t.Helper()
	var h recordedHandshake
	msg := readTestdata(t, name+".handshakestart")
	for len(msg) > 0 {
		num, typ, n := protowire.ConsumeTag(msg)
		if n < 0 {
			t.Fatal(protowire.ParseError(n))
		}
		msg = msg[n:]
		if typ != protowire.BytesType {
			t.Fatalf("field %d: wire type %d", num, typ)
		}
		v, n := protowire.ConsumeBytes(msg)
		if n < 0 {
			t.Fatal(protowire.ParseError(n))
		}
		msg = msg[n:]
		switch num {
		case 2:
			h.evidence = v
		case 3:
			h.endorsements = v
		}
	}
	ts := binary.BigEndian.Uint64(readTestdata(t, name+".timestamp"))
	h.now = time.Unix(int64(ts), 0) //nolint:gosec // G115: a recorded timestamp
	h.mrenclave = [32]byte(readTestdata(t, name+".mrenclave"))
	h.advisories = strings.Split(string(readTestdata(t, name+".advisories")), "\n")
	return h
}

// TestVerifyRemoteAttestation ports the recorded-data tests of dcap.rs.
func TestVerifyRemoteAttestation(t *testing.T) {
	h := loadCDSI(t)
	pk := readTestdata(t, "cdsi.pubkey")
	verify := func(now time.Time, mrenclave [32]byte, advisories []string) (map[string][]byte, error) {
		return dcap.VerifyRemoteAttestation(h.evidence, h.endorsements, mrenclave, advisories, now)
	}
	t.Run("test_verify_remote_attestation", func(t *testing.T) {
		claims, err := verify(h.now, h.mrenclave, h.advisories)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(claims["pk"], pk) {
			t.Errorf("pk = %x, want %x", claims["pk"], pk)
		}
	})
	t.Run("test_verify_remote_attestation_accepted_sw_advisories_not_present", func(t *testing.T) {
		claims, err := verify(h.now, h.mrenclave, append(h.advisories, "INTEL-SA-1234"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(claims["pk"], pk) {
			t.Errorf("pk = %x, want %x", claims["pk"], pk)
		}
	})
	t.Run("test_verify_remote_attestation_expired_attestation", func(t *testing.T) {
		if _, err := verify(h.now.Add(2*365*24*time.Hour), h.mrenclave, h.advisories); err == nil {
			t.Fatal("expired attestation accepted")
		}
	})
	// Beyond upstream: the policy checks on real data.
	t.Run("wrong_mrenclave", func(t *testing.T) {
		other := h.mrenclave
		other[0] ^= 1
		if _, err := verify(h.now, other, h.advisories); !errors.Is(err, dcap.ErrMREnclave) {
			t.Fatalf("got %v, want ErrMREnclave", err)
		}
	})
	t.Run("advisory_not_accepted", func(t *testing.T) {
		// The platform's level needs INTEL-SA-00615 mitigated.
		if _, err := verify(h.now, h.mrenclave, []string{"INTEL-SA-00657"}); !errors.Is(err, dcap.ErrAdvisory) {
			t.Fatalf("got %v, want ErrAdvisory", err)
		}
	})
	t.Run("known_enclave_advisories", func(t *testing.T) {
		if _, err := verify(h.now, h.mrenclave, dcap.SWAdvisories(h.mrenclave[:])); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("expiry_boundary", func(t *testing.T) {
		// The collateral's earliest expiry decides; one second before it
		// the attestation holds, after it it does not.
		en, err := dcap.ParseEndorsements(h.endorsements)
		if err != nil {
			t.Fatal(err)
		}
		limit := en.TCBInfo.NextUpdate
		for _, u := range []time.Time{en.QEIdentity.NextUpdate, en.PCKIssuerCRL.CRL().NextUpdate, en.RootCRL.CRL().NextUpdate} {
			if u.Before(limit) {
				limit = u
			}
		}
		if _, err := verify(limit.Add(-time.Second), h.mrenclave, h.advisories); err != nil {
			t.Fatalf("before expiry: %v", err)
		}
		if _, err := verify(limit.Add(time.Second), h.mrenclave, h.advisories); !errors.Is(err, dcap.ErrExpired) {
			t.Fatalf("after expiry: got %v, want ErrExpired", err)
		}
	})
	t.Run("tampered", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			blob  func() ([]byte, []byte)
			match error
		}{
			{"evidence_mrenclave", func() ([]byte, []byte) {
				ev := bytes.Clone(h.evidence)
				ev[dcap.QuoteReportBodyOffset+64]++
				return ev, h.endorsements
			}, dcap.ErrSignature},
			{"endorsements_tcb_info", func() ([]byte, []byte) {
				en := bytes.Clone(h.endorsements)
				i := bytes.Index(en, []byte(`"tcbType":0`))
				en[i+len(`"tcbType":`)] = '1'
				return h.evidence, en
			}, dcap.ErrSignature},
		} {
			t.Run(tc.name, func(t *testing.T) {
				ev, en := tc.blob()
				if _, err := dcap.VerifyRemoteAttestation(ev, en, h.mrenclave, h.advisories, h.now); !errors.Is(err, tc.match) {
					t.Fatalf("got %v, want %v", err, tc.match)
				}
			})
		}
	})
}

// TestAttestationPolicy checks the advisory and MRENCLAVE policy on a
// software-hardening-needed attestation.
func TestAttestationPolicy(t *testing.T) {
	f := newFake(t)
	f.en.TCBInfo.TCBLevels = []dcap.TCBLevel{{Version: dcap.TCBInfoV3, Status: dcap.TCBSWHardeningNeeded,
		AdvisoryIDs: []string{"INTEL-SA-1", "INTEL-SA-2"}}}
	a, err := f.attest(t)
	if err != nil {
		t.Fatal(err)
	}
	mr := a.MREnclave
	for _, tc := range []struct {
		name       string
		mrenclave  [32]byte
		advisories []string
		want       error
	}{
		{"all_accepted", mr, []string{"INTEL-SA-2", "INTEL-SA-1", "INTEL-SA-3"}, nil},
		{"one_missing", mr, []string{"INTEL-SA-1"}, dcap.ErrAdvisory},
		{"none", mr, nil, dcap.ErrAdvisory},
		{"wrong_mrenclave", [32]byte{1}, []string{"INTEL-SA-1", "INTEL-SA-2"}, dcap.ErrMREnclave},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := a.CheckPolicy(tc.mrenclave, tc.advisories)
			if !errors.Is(err, tc.want) || (err == nil) != (tc.want == nil) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if err == nil && !reflect.DeepEqual(claims, a.Claims) {
				t.Error("claims not returned")
			}
		})
	}
}

// TestAttestationMetrics ports test_attestation_metrics.
func TestAttestationMetrics(t *testing.T) {
	m, err := dcap.AttestationMetrics(readTestdata(t, "dcap.evidence"), readTestdata(t, "dcap.endorsements"))
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]int64{
		"tcb_info_expiration_ts":   1676670969, // 2023-02-17 21:56:09 UTC
		"tcb_signer_not_before_ts": 1526899810, // May 21 10:50:10 2018 GMT
		"tcb_signer_not_after_ts":  1747824610, // May 21 10:50:10 2025 GMT
	} {
		if m[key] != want {
			t.Errorf("%s = %d, want %d", key, m[key], want)
		}
	}
	if len(m) != 12 {
		t.Errorf("%d metrics, want 12", len(m))
	}
}

// TestSWAdvisories checks the advisory table of constants.rs.
func TestSWAdvisories(t *testing.T) {
	common := []string{"INTEL-SA-00615", "INTEL-SA-00657"}
	for _, tc := range []struct {
		hex  string
		want []string
	}{
		{dcap.EnclaveIDCDSIProd, common},
		{dcap.EnclaveIDCDSIStaging, common},
		{dcap.EnclaveIDSVR2Prod2026Q3, common},
		{dcap.EnclaveIDSVRBStaging2026Q1, common},
		{strings.Repeat("00", 32), nil},
	} {
		got := dcap.SWAdvisories(mustHex(t, tc.hex))
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("SWAdvisories(%s) = %q, want %q", tc.hex[:8], got, tc.want)
		}
	}
	if got, want := dcap.SWAdvisories(readTestdata(t, "cdsi.mrenclave")),
		strings.Split(string(readTestdata(t, "cdsi.advisories")), "\n"); !reflect.DeepEqual(got, want) {
		t.Errorf("cdsi advisories = %q, want %q", got, want)
	}
}
