// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package dcap_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cwbudde/libsignal-go/attest/dcap"
)

func readTestdata(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // G304: fixed testdata file names
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// testCert is upstream's cert_chain::testutil::TestCert.
type testCert struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func serialNumber(t testing.TB) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// newTestCert creates a CA certificate for cn, self-signed without issuer.
func newTestCert(t testing.TB, issuer *testCert, cn string) *testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serialNumber(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.AddDate(0, 0, 365),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	parent, signer := tmpl, key
	if issuer != nil {
		parent, signer = issuer.cert, issuer.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCert{key: key, cert: cert}
}

// crl is a CRL issued by c revoking serials, valid for 30 days.
func (c *testCert) crl(t testing.TB, serials ...*big.Int) *dcap.RevocationList {
	t.Helper()
	now := time.Now()
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-time.Minute),
		NextUpdate: now.AddDate(0, 0, 30),
	}
	for _, s := range serials {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries,
			x509.RevocationListEntry{SerialNumber: s, RevocationTime: now})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, c.cert, c.key)
	if err != nil {
		t.Fatal(err)
	}
	rl, err := dcap.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	return rl
}

// testChain returns n certificates ordered leaf to root, the root
// self-signed and named "0", its child "1" and so on.
func testChain(t testing.TB, n int) []*testCert {
	t.Helper()
	var vs []*testCert
	for i := range n {
		var issuer *testCert
		if len(vs) > 0 {
			issuer = vs[len(vs)-1]
		}
		vs = append(vs, newTestCert(t, issuer, string(rune('0'+i))))
	}
	for i, j := 0, len(vs)-1; i < j; i, j = i+1, j-1 {
		vs[i], vs[j] = vs[j], vs[i]
	}
	return vs
}

func certsOf(cs []*testCert) []*x509.Certificate {
	out := make([]*x509.Certificate, len(cs))
	for i, c := range cs {
		out[i] = c.cert
	}
	return out
}

func names(certs []*x509.Certificate) []string {
	out := make([]string, len(certs))
	for i, c := range certs {
		out[i] = c.Subject.CommonName
	}
	return out
}
