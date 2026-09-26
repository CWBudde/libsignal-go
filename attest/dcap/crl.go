// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package dcap

import (
	"crypto/x509"
	encasn1 "encoding/asn1"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

var (
	oidAuthorityKeyID = encasn1.ObjectIdentifier{2, 5, 29, 35}
	oidCRLNumber      = encasn1.ObjectIdentifier{2, 5, 29, 20}
)

// RevocationList is a CRL (revocation_list.rs).
type RevocationList struct {
	crl *x509.RevocationList
}

// ParseRevocationList parses one DER CRL; bytes after it (such as a NUL
// terminator) are ignored, as with BoringSSL's d2i. Like upstream it
// requires the authority key identifier and CRL number extensions.
func ParseRevocationList(der []byte) (*RevocationList, error) {
	var elem cryptobyte.String
	s := cryptobyte.String(der)
	if !s.ReadASN1Element(&elem, 0x30) {
		return nil, malformed("CRL")
	}
	crl, err := x509.ParseRevocationList(elem)
	if err != nil {
		return nil, malformed("CRL: %v", err)
	}
	var aki, number bool
	for _, ext := range crl.Extensions {
		aki = aki || ext.Id.Equal(oidAuthorityKeyID)
		number = number || ext.Id.Equal(oidCRLNumber)
	}
	if !aki || !number {
		return nil, malformed("CRL missing required extension")
	}
	return &RevocationList{crl: crl}, nil
}

// CRL returns the parsed CRL.
func (r *RevocationList) CRL() *x509.RevocationList { return r.crl }

// ValidAt reports whether t is before the CRL's next update.
func (r *RevocationList) ValidAt(t time.Time) bool {
	return !r.crl.NextUpdate.IsZero() && t.Before(r.crl.NextUpdate)
}
