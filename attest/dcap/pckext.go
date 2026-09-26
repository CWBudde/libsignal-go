// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package dcap

import (
	"crypto/x509"
	encasn1 "encoding/asn1"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// SGXExtensionOID is the OID of the SGX extension on PCK certificates.
var SGXExtensionOID = encasn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1}

// SGXType is the SGX type recorded in the PCK certificate.
type SGXType int

// SGX types.
const (
	SGXStandard SGXType = 0
	SGXScalable SGXType = 1
)

// PCKExtension is the SGX extension of a PCK certificate (sgx_x509.rs).
// Unknown, duplicate or missing entries are errors, as upstream.
type PCKExtension struct {
	PPID               [16]byte
	TCB                PCKTCB
	PCEID              [2]byte
	FMSPC              [6]byte
	SGXType            SGXType
	PlatformInstanceID [16]byte
	Configuration      PCKConfiguration
}

// PCKTCB is the TCB entry of the SGX extension.
type PCKTCB struct {
	CompSVN [16]uint8
	PCESVN  uint16
	CPUSVN  [16]byte
}

// PCKConfiguration is the configuration entry of the SGX extension.
type PCKConfiguration struct {
	DynamicPlatform bool
	CachedKeys      bool
	SMTEnabled      bool
}

func sgxOID(arcs ...int) string {
	return append(encasn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1}, arcs...).String()
}

func pckExtensionOf(leaf *x509.Certificate) (*PCKExtension, error) {
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(SGXExtensionOID) {
			e, err := ParsePCKExtension(ext.Value)
			if err != nil {
				return nil, fmt.Errorf("SgxPckExtension: %w", err)
			}
			return e, nil
		}
	}
	return nil, malformed("PCK certificate is missing SGX extension")
}

// extValue is one parsed entry value: the ASN.1 tag and its contents.
type extValue struct {
	tag  asn1.Tag
	body cryptobyte.String
}

var errExtValue = malformed("malformed extension value in PCK certificate")

func (v extValue) octets(n int) ([]byte, error) {
	if v.tag != asn1.OCTET_STRING || len(v.body) != n {
		return nil, errExtValue
	}
	return v.body, nil
}

// integer decodes a minimally encoded, non-negative INTEGER no larger than
// limit, like the asn1 crate's u64.
func (v extValue) integer(limit uint64) (uint64, error) {
	b := []byte(v.body)
	if v.tag != asn1.INTEGER || len(b) == 0 || b[0]&0x80 != 0 ||
		(len(b) > 1 && b[0] == 0 && b[1]&0x80 == 0) {
		return 0, errExtValue
	}
	if b[0] == 0 {
		b = b[1:]
	}
	if len(b) > 8 {
		return 0, errExtValue
	}
	var n uint64
	for _, c := range b {
		n = n<<8 | uint64(c)
	}
	if n > limit {
		return 0, errExtValue
	}
	return n, nil
}

func (v extValue) boolean() (bool, error) {
	if v.tag != asn1.BOOLEAN || len(v.body) != 1 || (v.body[0] != 0 && v.body[0] != 0xff) {
		return false, errExtValue
	}
	return v.body[0] == 0xff, nil
}

// entries parses a SEQUENCE OF { OID, value } into a map, rejecting
// entries outside want and duplicates, and requiring every wanted OID.
func entries(seq cryptobyte.String, want []string) (map[string]extValue, error) {
	allowed := make(map[string]bool, len(want))
	for _, oid := range want {
		allowed[oid] = true
	}
	out := make(map[string]extValue, len(want))
	for !seq.Empty() {
		var entry cryptobyte.String
		var oid encasn1.ObjectIdentifier
		var v extValue
		if !seq.ReadASN1(&entry, asn1.SEQUENCE) ||
			!entry.ReadASN1ObjectIdentifier(&oid) ||
			!entry.ReadAnyASN1(&v.body, &v.tag) || !entry.Empty() {
			return nil, malformed("could not parse required extension from PCK certificate")
		}
		key := oid.String()
		if !allowed[key] {
			return nil, malformed("unexpected extension in PCK certificate %s", key)
		}
		if _, dup := out[key]; dup {
			return nil, malformed("duplicate extension in PCK certificate")
		}
		out[key] = v
	}
	for _, oid := range want {
		if _, ok := out[oid]; !ok {
			return nil, malformed("could not parse required extension from PCK certificate: %s", oid)
		}
	}
	return out, nil
}

// ParsePCKExtension parses the DER value of the SGX extension.
func ParsePCKExtension(der []byte) (*PCKExtension, error) {
	s := cryptobyte.String(der)
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, asn1.SEQUENCE) || !s.Empty() {
		return nil, malformed("could not parse required extension from PCK certificate")
	}
	var (
		ppid, tcb, pceid, fmspc = sgxOID(1), sgxOID(2), sgxOID(3), sgxOID(4)
		sgxType, platform, conf = sgxOID(5), sgxOID(6), sgxOID(7)
	)
	m, err := entries(seq, []string{ppid, tcb, pceid, fmspc, sgxType, platform, conf})
	if err != nil {
		return nil, err
	}
	var e PCKExtension
	fixed := []struct {
		oid string
		dst []byte
	}{{ppid, e.PPID[:]}, {pceid, e.PCEID[:]}, {fmspc, e.FMSPC[:]}, {platform, e.PlatformInstanceID[:]}}
	for _, f := range fixed {
		b, err := m[f.oid].octets(len(f.dst))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.oid, err)
		}
		copy(f.dst, b)
	}
	if e.TCB, err = parseTCB(m[tcb]); err != nil {
		return nil, fmt.Errorf("%s: %w", tcb, err)
	}
	v := m[sgxType]
	if v.tag != asn1.ENUM || len(v.body) != 1 {
		return nil, fmt.Errorf("%s: %w", sgxType, errExtValue)
	}
	if v.body[0] > 1 {
		return nil, fmt.Errorf("%s: %w", sgxType, malformed("unknown SGX type in PCK certificate"))
	}
	e.SGXType = SGXType(v.body[0])
	if e.Configuration, err = parseConfiguration(m[conf]); err != nil {
		return nil, fmt.Errorf("%s: %w", conf, err)
	}
	return &e, nil
}

func parseTCB(v extValue) (PCKTCB, error) {
	var t PCKTCB
	if v.tag != asn1.SEQUENCE {
		return t, errExtValue
	}
	want := make([]string, 0, 18)
	for i := 1; i <= 18; i++ {
		want = append(want, sgxOID(2, i))
	}
	m, err := entries(v.body, want)
	if err != nil {
		return t, err
	}
	for i := range t.CompSVN {
		n, err := m[want[i]].integer(0xff)
		if err != nil {
			return t, fmt.Errorf("%s: %w", want[i], err)
		}
		t.CompSVN[i] = uint8(n) //nolint:gosec // G115: integer checked n <= 0xff
	}
	n, err := m[want[16]].integer(0xffff)
	if err != nil {
		return t, fmt.Errorf("%s: %w", want[16], err)
	}
	t.PCESVN = uint16(n) //nolint:gosec // G115: integer checked n <= 0xffff
	cpusvn, err := m[want[17]].octets(16)
	if err != nil {
		return t, fmt.Errorf("%s: %w", want[17], err)
	}
	t.CPUSVN = [16]byte(cpusvn)
	return t, nil
}

func parseConfiguration(v extValue) (PCKConfiguration, error) {
	var c PCKConfiguration
	if v.tag != asn1.SEQUENCE {
		return c, errExtValue
	}
	want := []string{sgxOID(7, 1), sgxOID(7, 2), sgxOID(7, 3)}
	m, err := entries(v.body, want)
	if err != nil {
		return c, err
	}
	for i, dst := range []*bool{&c.DynamicPlatform, &c.CachedKeys, &c.SMTEnabled} {
		if *dst, err = m[want[i]].boolean(); err != nil {
			return c, fmt.Errorf("%s: %w", want[i], err)
		}
	}
	return c, nil
}
