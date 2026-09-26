// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package dcap_test

import (
	"encoding/asn1"
	"testing"

	"github.com/cwbudde/libsignal-go/attest/dcap"
)

// Port of sgx_x509.rs's test_deserialization.
func TestPCKExtensionDeserialization(t *testing.T) {
	ext, err := dcap.ParsePCKExtension(readTestdata(t, "sgx_x509_extension.der"))
	if err != nil {
		t.Fatal(err)
	}
	if ext.PCEID != [2]byte{0, 0} || ext.TCB.PCESVN != 11 || ext.TCB.CompSVN[0] != 4 {
		t.Fatalf("pceid %x, pcesvn %d, compsvn[0] %d", ext.PCEID, ext.TCB.PCESVN, ext.TCB.CompSVN[0])
	}
}

// The quote's PCK leaf carries the extension too.
func TestPCKExtensionOfQuote(t *testing.T) {
	q := parseQuote(t, quoteBytes(t))
	if q.Support.PCKExtension == nil || q.Support.PCKExtension.FMSPC == [6]byte{} {
		t.Fatalf("extension %+v", q.Support.PCKExtension)
	}
}

type sgxEntry struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue
}

func sgxArc(arcs ...int) asn1.ObjectIdentifier {
	return append(asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1}, arcs...)
}

func TestPCKExtensionRejects(t *testing.T) {
	der := readTestdata(t, "sgx_x509_extension.der")
	var entries []sgxEntry
	if rest, err := asn1.Unmarshal(der, &entries); err != nil || len(rest) != 0 {
		t.Fatalf("fixture: %v", err)
	}
	marshal := func(es []sgxEntry) []byte {
		b, err := asn1.Marshal(es)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if _, err := dcap.ParsePCKExtension(marshal(entries)); err != nil {
		t.Fatalf("re-encoded fixture: %v", err)
	}
	octets := func(n int) asn1.RawValue {
		b, _ := asn1.Marshal(make([]byte, n))
		var v asn1.RawValue
		_, _ = asn1.Unmarshal(b, &v)
		return v
	}
	cases := map[string][]byte{
		"trailing data": append(append([]byte(nil), der...), 0),
		"truncated":     der[:len(der)-1],
		"missing entry": marshal(entries[1:]),
		"duplicate":     marshal(append(append([]sgxEntry(nil), entries...), entries[0])),
		"unknown oid":   marshal(append(append([]sgxEntry(nil), entries...), sgxEntry{sgxArc(99), octets(1)})),
	}
	for i, e := range entries {
		if e.ID.Equal(sgxArc(1)) { // PPID must be 16 bytes
			bad := append([]sgxEntry(nil), entries...)
			bad[i].Value = octets(15)
			cases["short ppid"] = marshal(bad)
		}
	}
	for name, b := range cases {
		if _, err := dcap.ParsePCKExtension(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
