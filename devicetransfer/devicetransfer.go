// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package devicetransfer makes the key and certificate a device offers
// while transferring an account to a new device, as libsignal v0.102.2
// rust/device-transfer does through the bridge's
// DeviceTransfer_GeneratePrivateKey and DeviceTransfer_GenerateCertificate.
package devicetransfer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// KeyBits is the size of the RSA key GeneratePrivateKey makes
// (DEVICE_TRANSFER_KEY_BITS).
const KeyBits = 4096

// Errors, one per variant of device-transfer's Error.
var (
	ErrKeyDecoding = errors.New("devicetransfer: failed to decode private key")
	ErrInternal    = errors.New("devicetransfer: internal error")
)

func internalErr(reason string) error { return fmt.Errorf("%w: %s", ErrInternal, reason) }

// maxCommonName is the upper bound on the common name in characters
// (X.520 ub-common-name), which OpenSSL enforces.
const maxCommonName = 64

// maxDays is the largest validity upstream accepts: it computes
// days·86400 seconds in a u32 with overflow checks.
const maxDays = (1<<32 - 1) / (24 * 60 * 60)

var (
	oidCommonName       = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidOrganization     = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidOrganizationUnit = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidSHA256WithRSA    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidECDSAWithSHA256  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

// GeneratePrivateKey returns a new KeyBits RSA key in PKCS#8 DER
// (create_rsa_private_key with KeyFormat::Pkcs8).
func GeneratePrivateKey() ([]byte, error) {
	k, err := rsa.GenerateKey(rand.Reader, KeyBits)
	if err != nil {
		return nil, internalErr("RSA key generation failed")
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, internalErr("exporting to PKCS8 failed")
	}
	return der, nil
}

// GenerateCertificate returns a self-signed X.509 certificate in DER for
// privateKey (create_self_signed_cert). Like upstream's, it is a version 1
// certificate with serial number 0 and no extensions, issued to and by
// CN=name, O=Signal Foundation, OU=Device Transfer, signed with SHA-256,
// and valid from one day before now until daysToExpire days after now.
//
// privateKey is PKCS#8, PKCS#1 (RSA) or SEC 1 (EC) DER, as BoringSSL's
// d2i_AutoPrivateKey reads it; RSA and ECDSA keys can sign. name must be
// 1 to 64 characters of UTF-8, and daysToExpire at most 49710.
func GenerateCertificate(privateKey []byte, name string, daysToExpire uint32, now time.Time) ([]byte, error) {
	key, err := parsePrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	var sigAlg asn1.ObjectIdentifier
	switch key.(type) {
	case *rsa.PrivateKey:
		sigAlg = oidSHA256WithRSA
	case *ecdsa.PrivateKey:
		sigAlg = oidECDSAWithSHA256
	default:
		return nil, internalErr(fmt.Sprintf("creating certificate failed: cannot sign with %T", key))
	}
	if !utf8.ValidString(name) {
		return nil, internalErr("creating certificate failed: name is not UTF-8")
	}
	if n := utf8.RuneCountInString(name); n < 1 || n > maxCommonName {
		return nil, internalErr("creating certificate failed: name must be 1 to 64 characters")
	}
	if daysToExpire > maxDays {
		return nil, internalErr("creating certificate failed: validity too long")
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, internalErr("creating certificate failed: " + err.Error())
	}

	now = now.UTC().Truncate(time.Second)
	notBefore := now.Add(-24 * time.Hour)
	notAfter := now.Add(time.Duration(daysToExpire) * 24 * time.Hour)

	var tbs cryptobyte.Builder
	tbs.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		// No version field: X509Builder leaves it at v1.
		b.AddASN1Int64(0) // serial number
		addAlgorithm(b, sigAlg)
		addName(b, name) // issuer
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			addTime(b, notBefore)
			addTime(b, notAfter)
		})
		addName(b, name) // subject
		b.AddBytes(spki)
	})
	tbsDER, err := tbs.Bytes()
	if err != nil {
		return nil, internalErr("creating certificate failed: " + err.Error())
	}

	digest := sha256.Sum256(tbsDER)
	sig, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, internalErr("creating certificate failed: " + err.Error())
	}

	var cert cryptobyte.Builder
	cert.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(tbsDER)
		addAlgorithm(b, sigAlg)
		b.AddASN1BitString(sig)
	})
	der, err := cert.Bytes()
	if err != nil {
		return nil, internalErr("converting cert to DER failed")
	}
	return der, nil
}

// parsePrivateKey reads the formats d2i_AutoPrivateKey reads. A key of a
// type that cannot sign a certificate is returned, and fails later with
// ErrInternal as upstream's does.
func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
		return nil, internalErr(fmt.Sprintf("creating certificate failed: cannot sign with %T", k))
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	return nil, ErrKeyDecoding
}

// addAlgorithm writes an AlgorithmIdentifier as OpenSSL does: RSA
// signatures carry NULL parameters, ECDSA ones none.
func addAlgorithm(b *cryptobyte.Builder, oid asn1.ObjectIdentifier) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
		if oid.Equal(oidSHA256WithRSA) {
			b.AddASN1NULL()
		}
	})
}

// addName writes CN=name, O=Signal Foundation, OU=Device Transfer, each in
// its own RDN and as UTF8String (build_self_signed_name).
func addName(b *cryptobyte.Builder, name string) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, atv := range []struct {
			oid   asn1.ObjectIdentifier
			value string
		}{
			{oidCommonName, name},
			{oidOrganization, "Signal Foundation"},
			{oidOrganizationUnit, "Device Transfer"},
		} {
			b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(atv.oid)
					b.AddASN1(cbasn1.UTF8String, func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(atv.value))
					})
				})
			})
		}
	})
}

// addTime writes UTCTime for the years 1950 to 2049 and GeneralizedTime
// otherwise, as RFC 5280 and ASN1_TIME_set do.
func addTime(b *cryptobyte.Builder, t time.Time) {
	if y := t.Year(); y >= 1950 && y < 2050 {
		b.AddASN1UTCTime(t)
		return
	}
	b.AddASN1GeneralizedTime(t)
}
