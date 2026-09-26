// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package devicetransfer_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cwbudde/libsignal-go/devicetransfer"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // G304: fixed testdata file names
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parseCert(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// createdAt is when upstream made a recorded certificate: its notBefore
// plus the one day it backdates.
func createdAt(t *testing.T, der []byte) time.Time {
	t.Helper()
	return parseCert(t, der).NotBefore.Add(24 * time.Hour)
}

// TestGenerateCertificateRecorded compares certificates with ones upstream's
// create_self_signed_cert made from the same key at the same second. RSA
// PKCS#1 v1.5 signatures are deterministic, so the whole certificate must
// match; ECDSA ones are not, so there the to-be-signed part must.
func TestGenerateCertificateRecorded(t *testing.T) {
	for _, tc := range []struct {
		file, key, name string
		days            uint32
		wholeCert       bool
	}{
		{"rsa-test-10.cert", "rsa.key", "test", 10, true},
		{"rsa-utf8-36500.cert", "rsa.key", "Gerät ✓", 36500, true}, // notAfter in GeneralizedTime
		{"ec-ec-1.cert", "ec.key", "ec", 1, false},
	} {
		t.Run(tc.file, func(t *testing.T) {
			want := readTestdata(t, tc.file)
			key := readTestdata(t, tc.key)
			got, err := devicetransfer.GenerateCertificate(key, tc.name, tc.days, createdAt(t, want))
			if err != nil {
				t.Fatal(err)
			}
			if tc.wholeCert {
				if !bytes.Equal(got, want) {
					t.Fatalf("certificate differs from upstream's:\n got %x\nwant %x", got, want)
				}
				return
			}
			g, w := parseCert(t, got), parseCert(t, want)
			if !bytes.Equal(g.RawTBSCertificate, w.RawTBSCertificate) {
				t.Fatalf("to-be-signed certificate differs from upstream's:\n got %x\nwant %x",
					g.RawTBSCertificate, w.RawTBSCertificate)
			}
			if err := g.CheckSignatureFrom(g); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestGenerateCertificate checks the certificate's fields as upstream sets
// them: a v1 self-signed certificate with serial 0, valid from a day before
// now for daysToExpire days.
func TestGenerateCertificate(t *testing.T) {
	key := readTestdata(t, "rsa.key")
	now := time.Date(2026, 9, 27, 12, 34, 56, 789, time.FixedZone("CEST", 2*60*60))
	der, err := devicetransfer.GenerateCertificate(key, "device", 30, now)
	if err != nil {
		t.Fatal(err)
	}
	c := parseCert(t, der)
	if c.Version != 1 || c.SerialNumber.Sign() != 0 || len(c.Extensions) != 0 {
		t.Fatalf("version %d, serial %v, %d extensions, want 1, 0, 0", c.Version, c.SerialNumber, len(c.Extensions))
	}
	if c.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Fatalf("signature algorithm %v", c.SignatureAlgorithm)
	}
	if err := c.CheckSignatureFrom(c); err != nil {
		t.Fatal(err)
	}
	wantName := pkix.RDNSequence{
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "device"}},
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Signal Foundation"}},
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "Device Transfer"}},
	}
	for _, raw := range [][]byte{c.RawSubject, c.RawIssuer} {
		var got pkix.RDNSequence
		if _, err := asn1.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		if len(got) != len(wantName) {
			t.Fatalf("name %v, want %v", got, wantName)
		}
		for i := range got {
			if len(got[i]) != 1 || !got[i][0].Type.Equal(wantName[i][0].Type) || got[i][0].Value != wantName[i][0].Value {
				t.Fatalf("name %v, want %v", got, wantName)
			}
		}
	}
	start := time.Date(2026, 9, 26, 10, 34, 56, 0, time.UTC)
	if !c.NotBefore.Equal(start) || !c.NotAfter.Equal(start.Add(31*24*time.Hour)) {
		t.Fatalf("valid %v to %v, want %v to %v", c.NotBefore, c.NotAfter, start, start.Add(31*24*time.Hour))
	}
	priv, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.(*rsa.PrivateKey).PublicKey.Equal(c.PublicKey) {
		t.Fatal("certificate key is not the private key's")
	}
}

// TestGenerateCertificateName checks upstream's limits on the name, which
// becomes the common name: 1 to 64 characters.
func TestGenerateCertificateName(t *testing.T) {
	key := readTestdata(t, "rsa.key")
	now := time.Now()
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"", false},
		{"x", true},
		{strings.Repeat("a", 64), true},
		{strings.Repeat("a", 65), false},
		{strings.Repeat("ä", 64), true}, // characters, not bytes
		{strings.Repeat("ä", 65), false},
		{"a\tb", true},
		{"\xff", false}, // not UTF-8, which upstream's String cannot hold
	} {
		der, err := devicetransfer.GenerateCertificate(key, tc.name, 1, now)
		if !tc.ok {
			if !errors.Is(err, devicetransfer.ErrInternal) {
				t.Fatalf("name %q: err = %v, want %v", tc.name, err, devicetransfer.ErrInternal)
			}
			continue
		}
		if err != nil {
			t.Fatalf("name %q: %v", tc.name, err)
		}
		if cn := parseCert(t, der).Subject.CommonName; cn != tc.name {
			t.Fatalf("common name %q, want %q", cn, tc.name)
		}
	}
}

// TestGenerateCertificateDays checks the validity end, which upstream
// computes as days·86400 in a u32 with overflow checks.
func TestGenerateCertificateDays(t *testing.T) {
	key := readTestdata(t, "rsa.key")
	now := time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		days uint32
		ok   bool
		// wantTime is the encoded notAfter: UTCTime (tag 0x17) up to 2049,
		// GeneralizedTime (0x18) from 2050.
		wantTime string
	}{
		{0, true, "\x17\x0d260927000000Z"},
		{8496, true, "\x17\x0d491231000000Z"},
		{8497, true, "\x18\x0f20500101000000Z"},
		{49710, true, "\x18\x0f21621103000000Z"}, // the largest period that fits a u32
		{49711, false, ""},
		{1<<32 - 1, false, ""},
	} {
		der, err := devicetransfer.GenerateCertificate(key, "x", tc.days, now)
		if !tc.ok {
			if !errors.Is(err, devicetransfer.ErrInternal) {
				t.Fatalf("%d days: err = %v, want %v", tc.days, err, devicetransfer.ErrInternal)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%d days: %v", tc.days, err)
		}
		want := now.AddDate(0, 0, int(tc.days))
		if got := parseCert(t, der).NotAfter; !got.Equal(want) {
			t.Fatalf("%d days: notAfter %v, want %v", tc.days, got, want)
		}
		if !bytes.Contains(der, []byte(tc.wantTime)) {
			t.Fatalf("%d days: notAfter not encoded as %q", tc.days, tc.wantTime)
		}
	}
}

// TestGenerateCertificateKeys checks the private key formats upstream's
// PKey::private_key_from_der reads and the key types it can sign with.
func TestGenerateCertificateKeys(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8 := func(k any) []byte {
		b, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	ecKeys := map[string]*ecdsa.PrivateKey{}
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ecKeys[curve.Params().Name] = k
	}
	sec1, err := x509.MarshalECPrivateKey(ecKeys["P-256"])
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		key     []byte
		wantAlg x509.SignatureAlgorithm
		wantErr error
	}{
		{"RSA PKCS#8", pkcs8(rsaKey), x509.SHA256WithRSA, nil},
		{"RSA PKCS#1", x509.MarshalPKCS1PrivateKey(rsaKey), x509.SHA256WithRSA, nil},
		{"P-256 PKCS#8", pkcs8(ecKeys["P-256"]), x509.ECDSAWithSHA256, nil},
		{"P-384 PKCS#8", pkcs8(ecKeys["P-384"]), x509.ECDSAWithSHA256, nil},
		{"P-521 PKCS#8", pkcs8(ecKeys["P-521"]), x509.ECDSAWithSHA256, nil},
		{"P-256 SEC 1", sec1, x509.ECDSAWithSHA256, nil},
		{"Ed25519", pkcs8(edKey), 0, devicetransfer.ErrInternal},
		{"X25519", pkcs8(xKey), 0, devicetransfer.ErrInternal},
		{"empty", nil, 0, devicetransfer.ErrKeyDecoding},
		{"garbage", []byte("garbage"), 0, devicetransfer.ErrKeyDecoding},
		{"truncated", pkcs8(rsaKey)[:100], 0, devicetransfer.ErrKeyDecoding},
	} {
		t.Run(tc.name, func(t *testing.T) {
			der, err := devicetransfer.GenerateCertificate(tc.key, "k", 1, time.Now())
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			c := parseCert(t, der)
			if c.SignatureAlgorithm != tc.wantAlg {
				t.Fatalf("signature algorithm %v, want %v", c.SignatureAlgorithm, tc.wantAlg)
			}
			if err := c.CheckSignatureFrom(c); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestGeneratePrivateKey checks the bridge's DeviceTransfer_GeneratePrivateKey:
// a fresh 4096-bit RSA key in PKCS#8.
func TestGeneratePrivateKey(t *testing.T) {
	key, err := devicetransfer.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	rk, ok := priv.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("key is %T, want RSA", priv)
	}
	// DEVICE_TRANSFER_KEY_BITS, and BoringSSL's RSA_F4 exponent.
	if rk.N.BitLen() != 4096 || rk.E != 65537 || devicetransfer.KeyBits != 4096 {
		t.Fatalf("%d-bit key with e = %d, want 4096 bits and 65537", rk.N.BitLen(), rk.E)
	}
	if _, err := devicetransfer.GenerateCertificate(key, "test", 10, time.Now()); err != nil {
		t.Fatal(err)
	}
}
