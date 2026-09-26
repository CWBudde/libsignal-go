// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package dcap_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/cwbudde/libsignal-go/attest/dcap"
)

func bigZero() *big.Int { return big.NewInt(0) }

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestEndorsements ports the endorsements.rs tests.
func TestEndorsements(t *testing.T) {
	blob := readTestdata(t, "dcap.endorsements")
	t.Run("make_endorsements_header", func(t *testing.T) {
		if v := binary.LittleEndian.Uint32(blob); v != 1 {
			t.Errorf("version %d", v)
		}
		// oe_enclave_type_t SGX
		if v := binary.LittleEndian.Uint32(blob[4:]); v != 2 {
			t.Errorf("enclave type %d", v)
		}
	})
	t.Run("make_endorsements", func(t *testing.T) {
		if _, err := dcap.ParseEndorsements(blob); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("verify_signature_chain_integrity", func(t *testing.T) {
		// Upstream's test is empty. Parsing checks both collateral
		// signatures against their chains' leaves; check the chains here.
		// The collateral itself (TCB evaluation data number 14) is too old
		// to be valid today.
		e, err := dcap.ParseEndorsements(blob)
		if err != nil {
			t.Fatal(err)
		}
		now := e.PCKIssuerCRL.CRL().ThisUpdate
		if e.ValidAt(now) || !e.TCBIssuerChain.ValidAt(now) || !e.QEIdentityIssuerChain.ValidAt(now) {
			t.Fatalf("unexpected validity at %s", now)
		}
		trusted, err := dcap.RootTrustStore(e.TCBIssuerChain.Root(), e.RootCRL, dcap.IntelRootKey(), now)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.TCBIssuerChain.Validate(trusted, nil); err != nil {
			t.Error(err)
		}
		if err := e.QEIdentityIssuerChain.Validate(trusted, nil); err != nil {
			t.Error(err)
		}
	})
	for _, tc := range []struct {
		name    string
		file    string
		version dcap.TCBInfoVersion
		ids     []string
	}{
		{"parse_tcb_info_v3", "tcb_info_v3.json", dcap.TCBInfoV3, []string{"INTEL-SA-00615", "INTEL-SA-00657"}},
		{"parse_tcb_info_v2", "tcb_info_v2.json", dcap.TCBInfoV2, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info, err := dcap.ParseTCBInfo(readTestdata(t, tc.file))
			if err != nil {
				t.Fatal(err)
			}
			if info.Version != tc.version {
				t.Errorf("version %d", info.Version)
			}
			if info.FMSPC != [6]byte(mustHex(t, "00606A000000")) {
				t.Errorf("fmspc %x", info.FMSPC)
			}
			l := info.TCBLevels[0]
			if l.Status != dcap.TCBSWHardeningNeeded {
				t.Errorf("status %s", l.Status)
			}
			if strings.Join(l.AdvisoryIDs, ",") != strings.Join(tc.ids, ",") || l.AdvisoryIDs == nil {
				t.Errorf("advisory ids %q", l.AdvisoryIDs)
			}
			if want := [16]uint8{7, 9, 3, 3, 255, 255, 1}; l.Components != want || l.PCESVN != 13 {
				t.Errorf("tcb %v/%d", l.Components, l.PCESVN)
			}
			for _, l := range info.TCBLevels {
				if l.Version != tc.version {
					t.Errorf("level layout %d", l.Version)
				}
			}
		})
	}
	t.Run("qe_identity", func(t *testing.T) {
		e, err := dcap.ParseEndorsements(blob)
		if err != nil {
			t.Fatal(err)
		}
		id := e.QEIdentity
		if id.ID != dcap.EnclaveQE || id.Version != 2 || id.ISVProdID != 1 ||
			id.MiscSelect != 0 || id.MiscSelectMask != 0xFFFFFFFF ||
			id.Attributes != [16]byte{0x11} ||
			id.AttributesMask != [16]byte(mustHex(t, "FBFFFFFFFFFFFFFF0000000000000000")) ||
			id.MRSigner != [32]byte(mustHex(t, "8C4F5775D796503E96137F77C68A829A0056AC8DED70140B081B094490C57BFF")) {
			t.Errorf("identity %+v", id)
		}
		for _, tc := range []struct {
			isvsvn uint16
			want   dcap.QETCBStatus
		}{{7, dcap.QEUpToDate}, {6, dcap.QEUpToDate}, {5, dcap.QEOutOfDate}, {3, dcap.QEOutOfDate}, {0, dcap.QERevoked}} {
			if got := id.TCBStatus(tc.isvsvn); got != tc.want {
				t.Errorf("TCBStatus(%d) = %s, want %s", tc.isvsvn, got, tc.want)
			}
		}
	})
}

// endorsementsBlob re-assembles an endorsements blob from fields.
func endorsementsBlob(fields [][]byte) []byte {
	var b []byte
	b = binary.LittleEndian.AppendUint32(b, 1)
	b = binary.LittleEndian.AppendUint32(b, 2)
	size := 4 * len(fields) // buffer_size covers the offsets and the data
	for _, f := range fields {
		size += len(f)
	}
	b = binary.LittleEndian.AppendUint32(b, uint32(size))        //nolint:gosec // G115: small test blob
	b = binary.LittleEndian.AppendUint32(b, uint32(len(fields))) //nolint:gosec // G115: nine fields
	off := 0
	for _, f := range fields {
		b = binary.LittleEndian.AppendUint32(b, uint32(off)) //nolint:gosec // G115: small test blob
		off += len(f)
	}
	for _, f := range fields {
		b = append(b, f...)
	}
	return b
}

// splitEndorsements cuts the recorded blob into its fields.
func splitEndorsements(t testing.TB, blob []byte) [][]byte {
	t.Helper()
	n := int(binary.LittleEndian.Uint32(blob[12:]))
	data := blob[16+4*n:]
	var fields [][]byte
	for i := range n {
		start := int(binary.LittleEndian.Uint32(blob[16+4*i:]))
		end := len(data)
		if i+1 < n {
			end = int(binary.LittleEndian.Uint32(blob[16+4*(i+1):]))
		}
		fields = append(fields, bytes.Clone(data[start:end]))
	}
	return fields
}

// TestParseEndorsementsRejects covers the blob layout and the signed
// collateral wrappers.
func TestParseEndorsementsRejects(t *testing.T) {
	blob := readTestdata(t, "dcap.endorsements")
	fields := splitEndorsements(t, blob)
	if !bytes.Equal(endorsementsBlob(fields), blob) {
		t.Fatal("re-assembled blob differs")
	}
	with := func(i int, v []byte) []byte {
		fs := append([][]byte(nil), fields...)
		fs[i] = v
		return endorsementsBlob(fs)
	}
	replaceIn := func(i int, old, repl string) []byte {
		if !bytes.Contains(fields[i], []byte(old)) {
			t.Fatalf("field %d lacks %q", i, old)
		}
		return with(i, bytes.Replace(fields[i], []byte(old), []byte(repl), 1))
	}
	const tcbInfo, qeID = 1, 6
	for _, tc := range []struct {
		name string
		blob []byte
		want error
	}{
		{"too_short", blob[:15], dcap.ErrMalformed},
		{"bad_version", append([]byte{2}, blob[1:]...), dcap.ErrUnsupported},
		{"bad_enclave_type", append(append(bytes.Clone(blob[:4]), 3), blob[5:]...), dcap.ErrUnsupported},
		{"too_few_fields", endorsementsBlob(fields[:8]), dcap.ErrMalformed},
		{"offsets_not_increasing", with(2, nil), dcap.ErrMalformed},
		{"no_data_after_last_offset", with(8, nil), dcap.ErrMalformed},
		{"bad_field_version", with(0, []byte{2, 0, 0, 0}), dcap.ErrUnsupported},
		{"short_field_version", with(0, []byte{1, 0, 0}), dcap.ErrMalformed},
		{"tcb_info_tampered", replaceIn(tcbInfo, `"tcbType":0`, `"tcbType":1`), dcap.ErrSignature},
		{"tcb_info_bad_signature_hex", replaceIn(tcbInfo, `"signature":"`, `"signature":"0`), dcap.ErrMalformed},
		{"tcb_info_key_case", replaceIn(tcbInfo, `"tcbInfo"`, `"tcbinfo"`), dcap.ErrMalformed},
		{"tcb_info_duplicate_key", replaceIn(tcbInfo, `{"tcbInfo":`, `{"signature":"00","tcbInfo":`), dcap.ErrMalformed},
		{"qe_identity_tampered", replaceIn(qeID, `"isvprodid":1`, `"isvprodid":2`), dcap.ErrSignature},
		{"qe_identity_missing", replaceIn(qeID, `"enclaveIdentity"`, `"enclaveIdentityX"`), dcap.ErrMalformed},
		{"trailing_json", with(tcbInfo, append(bytes.TrimRight(fields[tcbInfo], "\x00"), []byte(" {}\x00")...)), dcap.ErrMalformed},
		{"bad_crl", with(3, []byte("not a crl")), dcap.ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := dcap.ParseEndorsements(tc.blob); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	t.Run("unknown_keys_ignored", func(t *testing.T) {
		b := replaceIn(tcbInfo, `{"tcbInfo":`, `{"extra":[1,{"a":null}],"extra":2,"tcbInfo":`)
		if _, err := dcap.ParseEndorsements(b); err != nil {
			t.Fatal(err)
		}
	})
}

// TestParseTCBInfoStrict checks the serde-like decoding of the collateral
// JSON, which encoding/json alone would accept.
func TestParseTCBInfoStrict(t *testing.T) {
	good := string(readTestdata(t, "tcb_info_v3.json"))
	v2 := string(readTestdata(t, "tcb_info_v2.json"))
	comp := `{"svn":255},`
	for _, tc := range []struct {
		name, old, repl string
		base            string
		ok              bool
	}{
		{"unmodified", "", "", good, true},
		{"unknown_top_level_key", `"id":"SGX"`, `"unknown":"SGX"`, good, true},
		{"key_case", `"fmspc"`, `"FMSPC"`, good, false},
		{"duplicate_key", `"tcbType":0`, `"tcbType":0,"tcbType":0`, good, false},
		{"missing_field", `"pceId":"0000",`, ``, good, false},
		{"null_number", `"tcbType":0`, `"tcbType":null`, good, false},
		{"number_as_string", `"tcbType":0`, `"tcbType":"0"`, good, false},
		{"float_number", `"tcbType":0`, `"tcbType":0.0`, good, false},
		{"u8_overflow", `{"svn":7,`, `{"svn":256,`, good, false},
		{"negative", `"pcesvn":13`, `"pcesvn":-1`, good, false},
		{"fmspc_short", `"fmspc":"00606A000000"`, `"fmspc":"00606A0000"`, good, false},
		{"fmspc_lower_case", `"fmspc":"00606A000000"`, `"fmspc":"00606a000000"`, good, true},
		{"bad_version", `"version":3`, `"version":4`, good, false},
		{"bad_status", `"tcbStatus":"SWHardeningNeeded"`, `"tcbStatus":"swHardeningNeeded"`, good, false},
		{"bad_date", `"tcbDate":"2022-08-10T00:00:00Z"`, `"tcbDate":"2022-08-10"`, good, false},
		{"fifteen_components", comp, ``, good, false},
		{"seventeen_components", comp, comp + comp, good, false},
		{"v2_missing_component", `"sgxtcbcomp16svn":0,`, ``, v2, false},
		{"advisory_ids_absent", `,"advisoryIDs":["INTEL-SA-00615","INTEL-SA-00657"]`, ``, good, true},
		{"advisory_ids_null", `"advisoryIDs":["INTEL-SA-00615","INTEL-SA-00657"]`, `"advisoryIDs":null`, good, false},
		{"trailing_data", `]}`, `]}}`, good, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.old != "" && !strings.Contains(tc.base, tc.old) {
				t.Fatalf("fixture lacks %q", tc.old)
			}
			data := strings.Replace(tc.base, tc.old, tc.repl, 1)
			if tc.name == "trailing_data" {
				data = strings.TrimSpace(tc.base) + "}"
			}
			_, err := dcap.ParseTCBInfo([]byte(data))
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
			if err != nil && !errors.Is(err, dcap.ErrMalformed) && !errors.Is(err, dcap.ErrUnsupported) {
				t.Errorf("error %v is not a dcap error", err)
			}
		})
	}
}

// TestParseEnclaveIdentityStrict covers the QE identity JSON.
func TestParseEnclaveIdentityStrict(t *testing.T) {
	blob := readTestdata(t, "dcap.endorsements")
	f := splitEndorsements(t, blob)[6]
	start := bytes.Index(f, []byte(`{"id"`))
	end := bytes.Index(f, []byte(`,"signature"`))
	good := string(f[start:end])
	for _, tc := range []struct {
		name, old, repl string
		ok              bool
	}{
		{"unmodified", "", "", true},
		{"qve", `"id":"QE"`, `"id":"QVE"`, true},
		{"bad_id", `"id":"QE"`, `"id":"qe"`, false},
		{"miscselect_short", `"miscselect":"00000000"`, `"miscselect":"000000"`, false},
		{"mrsigner_long", `"mrsigner":"8C`, `"mrsigner":"008C`, false},
		{"qe_status_not_allowed", `"tcbStatus":"UpToDate"`, `"tcbStatus":"SWHardeningNeeded"`, false},
		{"missing_tcb_date", `"tcbDate":"2022-11-09T00:00:00Z",`, ``, false},
		{"isvsvn_missing", `"tcb":{"isvsvn":6}`, `"tcb":{}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.old != "" && !strings.Contains(good, tc.old) {
				t.Fatalf("fixture lacks %q", tc.old)
			}
			_, err := dcap.ParseEnclaveIdentity([]byte(strings.Replace(good, tc.old, tc.repl, 1)))
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func FuzzParseEndorsements(f *testing.F) {
	f.Add(readTestdata(f, "dcap.endorsements"))
	f.Add(readTestdata(f, "tcb_info_v3.json"))
	f.Add(readTestdata(f, "tcb_info_v2.json"))
	f.Fuzz(func(_ *testing.T, b []byte) {
		if e, err := dcap.ParseEndorsements(b); err == nil {
			_ = e.ValidAt(e.TCBInfo.NextUpdate)
		}
		_, _ = dcap.ParseTCBInfo(b)
		_, _ = dcap.ParseEnclaveIdentity(b)
	})
}
